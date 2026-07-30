# Adaptive OS Agent 设计与实现

本文说明 Adaptive-OS-Agent 当前代码怎样发现任务、判断工作负载目标、维护一致状态，并把
结果可靠地交给 scx_adaptive。运行与配置方法见 [README.md](README.md)，内核调度实现见
[scheduler/Design.md](../scheduler/Design.md)。

## 1. 组件定位

Agent 是整个方案唯一的服务入口。它启动 scheduler child，但不参与每次调度：

~~~text
Linux /proc + sched_ext lifecycle
               |
               v
      +---------------------+
      | Discovery + Admission|<-- 本地目标识别
      +----------+----------+<-- DeepSeek process/thread
                 |             <-- BehaviorWindow
                 v
      +---------------------+       +------------------+
      | ClassificationRegistry|---->| Tool 只读服务     |
      | (唯一写者)            |       +------------------+
      +----------+----------+
                 |
                 v
      +---------------------+       +--------------------+
      | SchedulerClient     |<------| SchedulerSupervisor|
      +----------+----------+       +---------+----------+
                 |                            |
                 v                            v
          scx_adaptive control          scheduler child
~~~

Agent 负责：

- 发现普通用户态进程与线程；
- 只把安全、稳定的 SCHED_OTHER 线程准入 partial sched_ext；
- 从本地目标、DeepSeek 语义和 scheduler 行为中形成保守分类；
- 维护进程/线程的 identity、stage、desired/applied generation；
- 监督 scheduler 生命周期，并在新 epoch 上全量恢复；
- 提供只读观测接口。

Agent 不负责：

- 选择 CPU；
- 保存或移动 runnable task；
- 修改 DSQ；
- 在模型返回前暂停任务；
- 根据测试 scenario 或预先写死的应用名单分类。

## 2. 线程模型与状态所有权

### 2.1 为什么 Registry 只有一个写者

分类会同时收到四类异步输入：内核生命周期事件、远端模型返回、行为窗口和控制 ACK。
若各线程直接修改分类表，迟到响应与 PID 复用很容易造成覆盖。当前实现让主线程成为
ClassificationRegistry 的唯一写者：

~~~text
 +----------------------+   +----------------------+
 | DeepSeek worker 0    |   | DeepSeek worker 1    |
 | process-only         |   | prefer-thread       |
 +----------+-----------+   +----------+-----------+
            | proposals                | proposals
            +------------+-------------+
                         v
                 +---------------+
                 | outcome queue  |
                 +-------+-------+
                         |
 +------------------+    |    +------------------+
 | SchedulerClient  |----+----| event/control    |
 | I/O thread       |         | queue            |
 +------------------+         +--------+---------+
                                      |
 +------------------+                 |
 | Tool socket      |-----------------+
 | thread           |   read-only request
 +------------------+                 |
                                      v
                         +-----------------------+
                         | Agent main             |
                         | ClassificationRegistry |
                         | 唯一 writer            |
                         +------------+----------+
                                      |
                                      +--> immutable Tool response
~~~

worker 只返回 identity-bound proposal；SchedulerClient 只处理 frame、重连和 ACK；
ToolServer 只把请求转给主线程。所有改变都在主线程重新核对 identity 后发生。

### 2.2 固定节拍

主循环每 20 ms 醒来一次，每轮工作有明确上界：

| 工作 | 上界或周期 |
| --- | ---: |
| scheduler event | 每 tick 最多 2,048 个 |
| control action | 每 tick 最多 256 个 |
| /proc 全量 reconciliation | 默认每 10 s |
| 语义 batch 规划 | 默认每 1 s |
| scheduler snapshot 文件 | 配置后默认每 1 s |
| 单个 control ACK 等待 | 3 s |
| scheduler ready | 15 s |
| worker 退出宽限 | 2 s |

即使进程数或事件量突然增加，Agent 也不会在一轮中无限扫描。

## 3. 启动与退出

### 3.1 启动顺序

~~~text
Agent main       Supervisor       scx_adaptive       sched_ext
    |                |                 |                |
    |-- spawn ------>|                 |                |
    |                |-- child ------->|                |
    |                |                 |-- load/attach ->|
    |<---------------------- Hello(epoch) --------------|
    |                |                 |                |
    |-- wait ready --|---------------> state=enabled     |
    |-- /proc scan + admission ------------------------>|
    |-- create bounded DeepSeek workers                 |
    |<---------------- lifecycle replay ----------------|
    |---------------- Registry snapshot --------------->|
    |<---------------- final snapshot ACK ---------------|
    |                |                 |                |
    |      之后才提交增量 classification action          |
~~~

Agent 先等 scheduler Hello 和 sched_ext attach 成功，再建立初始 Registry。这样初次
准入的任务一定有可用数据面；即使尚未分类，也能立即按 Balanced 运行。

### 3.2 正常退出

收到 SIGINT 或 SIGTERM 后：

1. shutdown flag 阻止主循环继续产生新工作；
2. DeepSeek worker 最多等待 2 s；
3. Tool 与 control I/O 线程停止；
4. Supervisor 向 scheduler 发送 SIGTERM；
5. scheduler 最多获得 3 s 释放 struct_ops；
6. 只有超时后才强制结束 child。

Supervisor 的 Drop 也执行 stop，避免普通错误返回遗留 sched_ext 实例。

## 4. 进程发现与安全准入

### 4.1 /proc 读取

Discovery 扫描 /proc 的数字目录。对每个候选进程读取：

| 文件 | 用途 | 边界 |
| --- | --- | ---: |
| stat | parent、PF_KTHREAD、start_time_ticks | 精确解析 comm 后字段 |
| comm | 进程短名 | 256 bytes |
| cmdline | argv 语义 | 总计 8 KiB、最多 64 项、单项 512 bytes |
| exe | 可执行文件路径 | 1,024 bytes |
| cgroup | 服务/容器上下文 | 最多 16 行、单行 512 bytes |
| status | real UID | 只取第一个 Uid 值 |
| task/*/comm | 线程语义 | 每项 256 bytes |

PF_KTHREAD 进程直接排除；cmdline 与 exe 都缺失的进程不视为普通用户态 workload。
每 10 s 的全量扫描是恢复路径，scheduler lifecycle event 是新任务的快速路径。

### 4.2 准入判定

~~~text
 +------------------+
 | ProcessMetadata  |
 +--------+---------+
          v
 +-------------------------------+
 | PID>1 且不在排除表？          |
 +-----------+-------------------+
       否    |    是
       v     |    v
  原生调度   |  复核 process starttime
             |          |
             |       不同|相同
             |          v   v
             |      原生  枚举线程
             |                 |
             |                 v
             |       +------------------+
             |       | sched policy     |
             |       +---+----------+---+
             |           |          |
             |    RT/DL/其他     SCHED_OTHER
             |           |          |
             |           v          v
             |        原生   读 task starttime
             |                          |
             |                          v
             |                  sched_setscheduler
             |                          |
             |                   前后 starttime？
             |                      /        \
             |                   相同        改变
             |                    |            |
             |                 已准入      identity race
~~~

排除表始终包含：

- PID 1；
- Agent 自身 TGID；
- 当前 scheduler child TGID。

任何读取、身份核对或系统调用失败都只跳过当前线程，不扩大权限、不改变其原有 policy。
后续 lifecycle event 或 reconciliation 可以再次尝试。

## 5. 稳定身份

Agent 同时面对 /proc 视角和 BPF 视角，因此使用两段式绑定：

~~~text
/proc 阶段:
  ProcessInstanceKey
    tgid
    start_time_ticks

BPF 生命周期到达后:
  ProcessKey
    tgid
    process_cookie
    exec_generation

  TaskKey
    tid
    task_cookie
~~~

绑定关系保存在 process_by_instance。proposal 在发出和返回时都携带请求当时的 instance
或 cookie identity。线程 proposal 还必须匹配 owning ProcessKey。

### 5.1 exec

exec 不被当作同一个语义对象：

~~~text
 +------------------------------+
 | ProcessKey(exec_generation=N)|
 +---------------+--------------+
                 | sched_process_exec
                 v
 +------------------------------+
 | 退休旧 image 与旧 task 绑定   |
 +---------------+--------------+
                 |
                 v
 +------------------------------+
 | 同 process_cookie             |
 | exec_generation = N + 1      |
 +---------------+--------------+
                 |
                 v
             重新发现/分类
                 |
                 v
               exit
~~~

Agent 先退休旧 process image 及其 task 绑定，再为新 exec generation 读取元数据并重新
分类。旧请求、旧 action 和旧 ACK 因 generation 或 identity 不符而被丢弃。

### 5.2 scheduler 重启

BPF cookie 会随 scheduler 重启改变。Agent 在断线时暂存只有同时满足以下条件的 task
投影：

- 原记录具有 ProcessInstanceKey；
- task 具有 /proc start_time_ticks；
- 新 replay 中出现相同 instance、TID 和 task starttime。

只有三者相同才把旧语义投影绑定到新 TaskKey；否则按新任务处理。

## 6. 分类输入与隐私边界

### 6.1 本地显式目标

本地规则不依赖程序名，只有明确目标才专用化：

| 证据 | 结果 |
| --- | --- |
| latency、deadline、response-time、SLO 选项 | Latency，0.95 |
| rate/QPS/RPS 选项和 percentile/HDR/latency-report 同时存在 | Latency，0.95 |
| throughput 或 throughput-mode | Throughput，0.95 |
| 本机 bounded repeat 或 benchmark operation + work budget | Throughput，0.90 |
| 远端 endpoint 上只有 bench/check/perf、没有 SLO | Balanced，0.90 |
| 其余歧义 | 无本地 proposal，保持当前类 |

这是“明确证据快速路径”，不是应用名称白名单。

### 6.2 命令行脱敏

发送模型前，Agent 处理以下形式：

- token、password、api-key、secret、authorization 等选项的下一项；
- name=value 中的敏感 name；
- Bearer 后的值；
- Authorization header；
- sk-、ghp_、github_pat_、AKIA 等常见 secret 形状；
- scheme://user:password@host 形式的 URL。

真实 BPF cookie、PID identity、UID、API key 和测试指标不会进入 prompt。线程请求只发送
线程 comm 和已经脱敏的进程上下文。

## 7. DeepSeek 语义通道

### 7.1 请求结构

~~~text
 +----------------------+       +----------------------+
 | ProcessBatchPlan     |       | ThreadBatchPlan      |
 | <=24 items           |       | same ProcessKey      |
 +----------+-----------+       +----------+-----------+
            | p0,p1,...                    | t0,t1,...
            +---------------+--------------+
                            v
                   +----------------------+
                   | HTTPS chat/completion|
                   +----------+-----------+
                              v
                   +----------------------+
                   | strict JSON parser   |
                   +----------+-----------+
                              v
                   +----------------------+
                   | map opaque ID back   |
                   | to original identity |
                   +----------+-----------+
                              v
                   +----------------------+
                   | main thread recheck  |
                   | Registry             |
                   +----------------------+
~~~

默认配置：

| 项目 | 值 |
| --- | --- |
| endpoint | https://api.deepseek.com |
| model | deepseek-v4-flash |
| batch | 24 |
| worker | 2 |
| connect / response timeout | 5 s / 45 s |
| retry | 初次请求后最多 2 次 |
| temperature | 0 |
| thinking | disabled |
| response format | json_object |
| 最低语义置信度 | 0.60 |

两个 worker 时，worker 0 只处理 process batch，确保大量线程请求不能饿死新进程识别；
其余 worker 优先 thread，但可回退处理 process。process 和 thread queue 均为有界队列，
提交使用 try_send，满时把 batch 恢复为 Pending。

### 7.2 输出校验

模型输出只允许：

~~~json
{
  "classifications": [
    {"id": "p0", "class": "latency|balanced|throughput|unknown", "confidence": 0.0}
  ]
}
~~~

parser 拒绝 Markdown fence、未知字段、未知/重复 ID、陌生 class、NaN、无穷值和区间外
confidence。模型遗漏的合法 ID 会被显式补成 Unknown 0.0。HTTP 非成功响应只保留最多
512 个字符用于错误信息。

## 8. scheduler 行为证据

Rust scheduler 每秒把 task 运行事实聚合成 BehaviorWindow。Agent 先做质量门禁：

~~~text
quality == good
window_sequence 连续且非零
task_age >= 2 s
并且满足以下任一采样量:
  max(enqueue_count, run_count) >= 32
  wakeup_count >= 32
  runtime >= 20 ms
~~~

窗口分成小于 250 us、小于 1 ms、小于 4 ms、至少 4 ms 四个 runtime/wait 桶。

### 8.1 确定性判断

| 类别 | 必须同时满足的主要条件 |
| --- | --- |
| Latency | wakeup ≥50%，短 burst ≥70%，主动阻塞 ≥50%，slice exhaustion ≤10%，利用率 ≤50%，存在 runnable wait |
| Throughput | 长 burst ≥70%，slice exhaustion ≥50%，主动阻塞 ≤10% |
| Balanced | run ≥64，五项混合信号至少满足三项 |

Latency 与 Throughput proposal 置信度为 0.90；Balanced 为 0.70 到 0.80。bad window、
sequence gap 或 action 尚未 ACK 时会清空连续投票，不能锁定分类。

### 8.2 行为为什么不能随便创造 Latency

频繁唤醒也可能只是普通 I/O worker。行为 candidate 为 Latency 时，还必须有进程默认或
process/thread semantic 提供高置信 Latency 目标。没有目标证据时该 candidate 不参与
最终决策。Throughput 行为可以确认持续本机计算；强专用证据互相矛盾时收敛到 Balanced。

## 9. ClassificationRegistry

### 9.1 数据模型

~~~text
 +-------------------------+          1        N +----------------------+
 | ProcessRecord           |-------------------->| TaskRecord           |
 +-------------------------+                     +----------------------+
 | ProcessKey identity     |                     | TaskKey identity     |
 | ProcessInstanceKey      |                     | ProcessKey owner     |
 | metadata                |                     | effective_class      |
 | default_class           |                     | stage                |
 | inherited_from          |                     | semantic             |
 | semantic                |                     | desired_generation   |
 | desired_generation      |                     | applied_generation   |
 | applied_generation      |                     | behavior streak      |
 | tasks: Set<TaskKey>     |                     +----------------------+
 +-------------------------+

 Registry 另外维护：
   pre-cookie metadata / request
   semantic fingerprint cache
   replay projection
   pending request_id / timing
   bounded retired process/task
~~~

Registry 还保存：

- pre-cookie metadata 和 semantic request；
- semantic fingerprint cache；
- scheduler replay 投影；
- pending request_id；
- created、requested、resolved、decided、locked、applied 时间点；
- 有界 retired process/task，用于 Tool 观察刚退出对象。

### 9.2 进程继承

新进程若能以精确 ProcessInstanceKey 找到父进程，就先继承父进程 default class。子进程
获得自己的本地/语义/行为证据后解除 inherited_from。父进程稍后完成决策时，Registry
用显式 stack 向仍未独立决策的后代传播，避免递归深度失控。

### 9.3 语义融合

~~~text
 DeepSeek class/confidence
             |
             v
      +---------------------+
      | confidence >= 0.60? |
      +----------+----------+
          否     |      是
          v      |      v
       Unknown   |  有本地明确证据？
       (不改类)  |       /       \
                 |      无         有
                 |      |           |
                 |      v           v
                 |  专用>=0.90   本地同类/冲突
                 |  或行为支持?       |
                 |   /      \         |
                 | 是        否        |
                 | |         |         |
                 | v         v         v
                 | 形成 default  等待  取较低置信
                 |       \      |      /
                 |        +-----+-----+
                 |              v
                 |       行为与语义冲突？
                 |          /          \
                 |        是            否
                 |        v              v
                 |    Balanced       提交分类
~~~

语义 fingerprint cache 只复用 metadata 签名完全相同的已分类结果，并受 process
Registry 容量限制；它不按可执行文件名进行无界全局记忆。

### 9.4 task stage

协议支持以下状态图：

~~~text
                  +-----------+
                  | Inherited  |
                  +-----+-----+
                        |
              +---------+---------+
              |                   |
              v                   v
       +-------------+     +-------------+
       | Semantic    |---->| Locked      |
       | (可选协议态)|     | (正常路径)  |
       +-------------+     +------+------+
                                 |
                    一次晚到强冲突仅允许
                    专用类 -> Balanced
                                 v
                         +---------------+
                         | LockedBalanced|
                         +---------------+
~~~

当前实现中的 thread semantic proposal 先写入 Registry 证据，随后由连续 good behavior
window 决定 Locked，因此常见路径是 Inherited 直接到 Locked。若 30 s 仍没有足够强
行为，任务锁定当前 effective class，避免长期采样。

高置信相反证据默认需要 5 个连续窗口；低置信或 Unknown 需要 3 个。Locked 后 scheduler
停止该 task 的行为事件，降低 ring buffer 与用户态开销。

## 10. generation 事务

### 10.1 Registry 侧

每条 action 包含：

~~~text
request_id
scheduler_epoch
ProcessKey
可选 TaskKey
class + stage
expected_generation
new_generation = expected_generation + 1
~~~

Registry 先更新 desired class/generation，并保留 pending_request_id；applied_generation
保持不变。只有 ACK 的 request_id、identity、class、stage 与 new_generation 全部匹配，
才把 desired 标记为 applied。

### 10.2 一次增量提交

~~~text
Registry              SchedulerClient        Rust scheduler          BPF map
   |                         |                     |                    |
   |-- pending action ------>|                     |                    |
   |                         |-- framed JSON ----->|                    |
   |                         |                     | 校验 epoch/identity |
   |                         |                     | /generation CAS     |
   |                         |                     |                    |
   |                         |                     |-- write ----------->|
   |                         |                     |                    |
   |                         |                     |  Rust cache commit  |
   |                         |                     |       /       \      |
   |                         |                     |     成功       失败  |
   |<-- ACK(new_generation)-|<--------------------|       |         |      |
   | desired=applied        |                     |       |         |
   |                         |                     |       +-------->| rollback
   |<-- structured error ---|<--------------------| invalidate sync      |
~~~

若 scheduler 返回 unknown_identity，Registry 只删除精确的 task/process identity。其他
reject、timeout 或 socket 断开都会使当前同步失效，随后走全量恢复，而不是猜测远端状态。

## 11. 控制连接与全量恢复

### 11.1 wire format

Agent 与 scheduler 使用 Unix stream：

~~~text
4-byte big-endian payload length
JSON envelope:
  protocol_version
  message_type
  request_id
  scheduler_epoch
  payload
~~~

控制 frame 最大 1 MiB。FrameReader 保留半帧和连续帧，拒绝零长度、超大长度和非法 JSON。

### 11.2 reconnect

~~~text
SchedulerClient          new scheduler(epoch)             Registry
      |                         |                            |
      |-- Hello(known_epoch) -->|                            |
      |<-- epoch/rebuild -------|                            |
      |                         |-- lifecycle replay ------->|
      |                         |-- ReplayComplete ---------->|
      |                         |                            |
      |---------------- snapshot batch 0..N (<=128) -------->|
      |<--------------- ACK(final snapshot_complete) --------|
      |---------------- mark_synchronized(epoch) ----------->|
      |                         |                            |
      |          增量 request 恢复                            |
~~~

snapshot 以非零 snapshot_id 和连续 batch_index 开始，最后一批必须显式 is_last。Agent
在新 epoch 完整 ACK 前不发送普通 action。

行为窗口属于可丢 telemetry：event queue 满时可以放弃一个行为 batch；生命周期事件和
控制响应则使用带超时的阻塞发送，不能悄悄丢失。

## 12. Tool 观测面

Tool socket 默认是 /run/adaptive-os-agent-tools.sock，与控制 socket 分离。协议同样是
4-byte 长度前缀 JSON，但 frame 上限为 256 KiB。

当前只读工具：

| tool | 返回内容 |
| --- | --- |
| workload.list | live 与 bounded retired process/task 摘要 |
| workload.get | 一个精确 identity 的生命周期和元数据投影 |
| classification.get | class、stage、source、confidence、generation 与时间点 |
| scheduler.health | registry_ready、degraded、epoch 等健康状态 |
| scheduler.stats | scheduler/BPF 聚合统计 |

scheduler 类工具会即时请求 scheduler snapshot；不可用时返回结构化错误。ToolServer 不
持有可变 Registry 引用，也没有写分类或调度的接口。

## 13. 固定资源边界

| 资源 | 上限 |
| --- | ---: |
| live process / task Registry | 32,768 / 65,536 |
| pending LLM batch | 32 |
| DeepSeek batch / worker | 24 / 2，配置硬上限 128 / 8 |
| control queue / frame | 1,024 / 1 MiB |
| Registry snapshot batch | 128 item |
| Tool queue / frame | 128 / 256 KiB |
| scheduler event / control action per tick | 2,048 / 256 |

容量满时记录 dropped counter 并拒绝新记录，现有任务仍可按 BPF Balanced/default 路径运行。

## 14. 失败语义

| 失败点 | 实际处理 |
| --- | --- |
| /proc 项消失或 starttime 改变 | 视为 race，不绑定 |
| 非 SCHED_OTHER thread | 保持原 policy |
| DeepSeek queue 满 | batch 回到 Pending |
| DeepSeek timeout、HTTP、schema 错误 | 有界重试后标 Failed，行为/当前类接管 |
| 低 confidence 或 unknown | 不建立无依据专用类 |
| proposal 迟到 | instance、request_id、ProcessKey 或 TaskKey 失配即丢弃 |
| behavior sequence gap / bad quality | 清空 streak，不投票 |
| control reject 或 timeout | 使同步失效，重新 replay + snapshot |
| scheduler child 退出 | 60 s 窗口最多重启 3 次 |
| Tool client 错误 | 只影响该响应 |
| Registry 容量满 | 拒绝新记录，数据面继续 |

API key 优先从 DEEPSEEK_API_KEY 读取，也可从配置的 0600 文件读取。密钥只驻留 Agent
内存，不写入 prompt 正文、Registry、Tool、日志或测试 artifact；validate-only 不读取
密钥。

## 15. 实现不变量

1. 只有稳定的普通 SCHED_OTHER 线程能进入 partial sched_ext。
2. 新任务和所有模型失败路径都不等待远端服务。
3. ClassificationRegistry 只有 Agent 主线程写。
4. proposal 与 action 必须绑定完整任务生命期。
5. 行为 bad/gap 窗口不能改变或锁定分类。
6. 行为不能在没有目标证据时独立创建 Latency。
7. 专用类强冲突必须保守收敛到 Balanced。
8. desired generation 只有匹配 ACK 后才能成为 applied。
9. 新 scheduler epoch 必须先 lifecycle replay，再完整 snapshot。
10. Tool 面只读，所有队列、frame、batch 和 Registry 都有界。

## 16. 代码索引

| 主题 | 文件 |
| --- | --- |
| 服务入口、主循环、worker 调度 | src/main.rs |
| 配置与默认阈值 | src/config.rs、src/limits.rs |
| /proc 扫描与元数据 | src/discovery.rs、src/metadata.rs |
| SCHED_EXT 准入 | src/task_admission.rs |
| 本地与 DeepSeek process 分类 | src/process_classifier.rs、src/deepseek.rs |
| thread 分类 | src/thread_classifier.rs |
| 行为规则与 Skill 包装 | src/behavior.rs、src/skills.rs |
| Registry 状态机 | src/registry.rs |
| scheduler 控制连接 | src/scheduler_client.rs、src/local_frame.rs |
| child 监督 | src/supervisor.rs |
| 只读工具面 | src/tools.rs |

单元测试覆盖配置校验、secret 脱敏、PID/TID 复用、exec、准入竞态、严格 JSON、worker
公平性、Registry 融合与 stage、generation/ACK、重连 snapshot、Tool 只读性和 Supervisor
生命周期。
