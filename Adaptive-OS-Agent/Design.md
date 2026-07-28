# Adaptive OS Agent 当前实现设计

本文档只描述 Agent 的当前设计和实现主线：普通任务如何被发现、准入、分类、
确认并可靠地提交给 scheduler。构建命令和使用方法见 [`README.md`](README.md)，
跨组件契约见 [`../Design.md`](../Design.md)，scheduler 数据面见
[`../scheduler/Design.md`](../scheduler/Design.md)。

## 1. Agent 负责什么

```text
                               Adaptive OS Agent

 ┌────────────────────┐      ┌───────────────────────────────────────────┐
 │ Linux /proc        │─────▶│ discovery ─▶ admission ─▶ Registry        │
 │ process / thread   │      │                    │                      │
 └────────────────────┘      │                    ├─ LLM proposal        │
                             │                    ├─ behavior            │
 ┌────────────────────┐      │                    └─ generation          │
 │ scheduler events   │─────▶│                                           │
 │ lifecycle / window │      │ Registry action ─▶ SchedulerClient        │────▶ scx_adaptive
 └────────────────────┘      │                                           │
                             │ ToolServer ─▶ 主线程一致读取                │
 ┌────────────────────┐      │                                           │
 │ local test client  │─────▶│ Supervisor ─▶ scheduler 启停/恢复          │
 └────────────────────┘      └───────────────────────────────────────────┘
```

Agent 负责：

- 发现普通用户态进程和线程，建立不受 PID/TID 复用影响的身份；
- 只将稳定的普通 `SCHED_OTHER` 线程准入 partial sched_ext；
- 融合显式启动目标、LLM 语义和 scheduler 运行行为；
- 维护 process/task 分类、stage 和 desired/applied generation；
- 监管 scheduler 子进程，并提供只读观测 Tool。

Agent 不负责：

- 不选择 CPU、time slice 或 runnable task；
- 不保存调度队列，不参与每次 enqueue/dispatch；
- 不让 LLM 直接改 Registry、scheduler 或 BPF map；
- 不读测试场景名、`targets.jsonl` 或应用性能结果。

## 2. 模块与状态所有权

```text
main.rs                         Agent 主线程，唯一 Registry writer
  ├─ discovery.rs/metadata.rs    /proc 发现、有界元数据、脱敏
  ├─ task_admission.rs           SCHED_OTHER → SCHED_EXT 准入
  ├─ process/thread_classifier   本地目标与 LLM 特征投影
  ├─ deepseek.rs/skills.rs        批量 proposal-only 能力
  ├─ behavior.rs                  确定性行为窗口判定
  ├─ registry.rs                  身份、分类、generation、ACK、replay
  ├─ scheduler_client.rs          epoch、snapshot、action 和重连
  ├─ supervisor.rs                scheduler 子进程生命周期
  └─ tools.rs                     只读本地 Tool socket
```

| 执行单元 | 可修改状态 | 不允许做的事 |
| --- | --- | --- |
| Agent 主线程 | Registry 和全部分类计时 | 直接做远端 HTTP |
| LLM worker | 当前 HTTP 请求 | 修改 Registry 或 scheduler |
| SchedulerClient | socket、重连、在途请求 | 解释分类策略 |
| ToolServer | listener 和当前连接 | 直接读写 Registry |
| Supervisor | scheduler child 和重启窗口 | 修改分类 |

所有异步结果先进入有界队列，再由主线程重新核对完整身份。Registry 因此无需
内部锁，也不会被迟到 LLM 结果异步改写。

## 3. 启动、主循环与退出

### 3.1 启动时序

```text
Agent              Supervisor        scheduler/BPF       Registry/LLM
  │ parse+validate     │                   │                  │
  │ spawn child ──────▶│                   │                  │
  │                    │ load+attach ─────▶│                  │
  │ Hello / epoch ────────────────────────▶│                  │
  │ wait_ready <=15 s  │                   │                  │
  │ scan /proc + admit ordinary task ────────────────────────▶│
  │ create LLM pool unless --offline ────────────────────────▶│
  │◀─ lifecycle replay + replay complete ─────────────────────│
  │ Registry snapshot ────────────────────▶│                  │
  │◀─ snapshot ACK / synchronized ─────────│                  │
```

scheduler 子进程由 Agent 以下列参数启动：

```text
scx_adaptive --agent-pid <Agent PID> --control-socket <socket> [--debug]
```

### 3.2 20 ms 主循环

```text
scheduler liveness/restart
        │
        ├─ drain <=512 lifecycle/behavior events
        ├─ replay complete 后尝试 Registry snapshot
        ├─ apply ready LLM outcomes
        ├─ answer read-only Tool calls
        ├─ commit pending actions when synchronized
        ├─ due: /proc reconciliation (default 10 s)
        ├─ due: process/thread semantic batches (default 1 s)
        └─ due: optional scheduler snapshot file
```

生命周期事件始终先于 LLM outcome 处理，因此 exit/exec 之前发出的 proposal 不会命中
新身份。scheduler 新 epoch 必须先完成 lifecycle replay，Agent 才允许发送完整 snapshot；
snapshot 完成前不发送增量 action。

### 3.3 退出

```text
SIGINT/SIGTERM
  ─▶ 停止新语义工作
  ─▶ 有界等待 LLM workers
  ─▶ 停止 ToolServer 并删除 socket
  ─▶ 停止 SchedulerClient
  ─▶ SIGTERM scheduler，3 s 后才允许强制结束
  ─▶ scheduler detach sched_ext
```

## 4. 普通任务发现与安全准入

### 4.1 `/proc` 发现

Agent 枚举数字 `/proc/<tgid>`，排除 Agent、scheduler 和内核线程。一个进程只有在
cmdline 非空或 executable 可见时才视为 ordinary。单个可选元数据字段读取失败不会
使 Agent 退出，但进程身份无法核对时会 fail closed。

| 元数据 | 来源 | 固定上限 |
| --- | --- | ---: |
| comm | `/proc/<tgid>/comm` | 256 bytes |
| cmdline | `/proc/<tgid>/cmdline` | 总计 8,192 bytes，最多 64 项，每项 512 bytes |
| executable | `/proc/<tgid>/exe` | 1,024 bytes |
| cgroup paths | `/proc/<tgid>/cgroup` | 最多 16 行，每行 512 bytes |
| thread comm | `/proc/<tgid>/task/<tid>/comm` | 256 bytes |

发送给 LLM 之前，Agent 会脱敏常见 token/password/API key 参数、Bearer 值、带凭据 URL
以及常见密钥前缀，并在 UTF-8 字符边界处截断。

### 4.2 partial sched_ext 准入

```text
ProcessMetadata
      │
      ├─ tgid <= 1 / Agent / scheduler / non-ordinary ─▶ 不操作
      └─ 重读 process starttime 确认生命期
                    │
                    └─ 遍历当前线程
                           ├─ already SCHED_EXT ─▶ 记录
                           ├─ non-SCHED_OTHER ─▶ 跳过 RT/DL/其他策略
                           └─ SCHED_OTHER ─▶ sched_setscheduler(SCHED_EXT)
                                               └─ 再读 task starttime
```

准入在首次扫描、默认每 10 s reconciliation，以及 scheduler INIT/EXEC 通知后执行。
任何读取或系统调用失败都只跳过当前线程；调用后的身份变化记为
`identity_races`，后续由生命周期事件和 reconciliation 恢复。

## 5. 稳定身份

```text
/proc 扫描阶段                      scheduler/BPF 阶段

┌──────────────────────────┐       bind       ┌──────────────────────────┐
│ ProcessInstanceKey       │─────────────────▶│ ProcessKey               │
│ tgid + start_time_ticks  │                  │ tgid + process_cookie    │
└──────────────────────────┘                  │      + exec_generation   │
                                              └────────────┬─────────────┘
                                                           │ owns
                                                           ▼
                                                 ┌──────────────────────────┐
                                                 │ TaskKey                  │
                                                 │ tid + task_cookie        │
                                                 └──────────────────────────┘
```

- `start_time_ticks` 拒绝 PID/TID 复用；
- `process_cookie` 区分内核中不同进程生命期；
- `exec_generation` 区分同一进程的不同 executable image；
- `task_cookie` 区分同 TID 的不同线程生命期；
- `scheduler_epoch` 区分 scheduler 进程实例；
- `class_generation` 区分同一稳定身份的分类版本。

任何 proposal、action、ACK、exit 和 replay 都不只使用数字 PID/TID。exec 会创建新
`ProcessKey`，旧镜像的迟到结果无法修改新镜像。

## 6. 分类管线

### 6.1 先默认 Balanced，再融合证据

```text
新 process/task
      │
      └─ Balanced 或精确父进程/process default
               │
       ┌───────┼───────────────┐
       ▼       ▼               ▼
 本地显式目标  process/thread LLM  scheduler 行为窗口
       │       │               │
       └───────┴───────┬───────┘
                       ▼
             Registry 身份核对与融合
                       │
                       ├─ 证据一致 ─▶ 专用类
                       ├─ 专用类冲突 ─▶ Balanced
                       └─ 证据不足 ─▶ 保留当前类
```

`Balanced` 有三种来源：新任务的安全默认、无 SLO 远端 I/O 混合工作的明确结论，
以及 Latency/Throughput 强证据冲突时的保守收敛。因此“有效类别是 Balanced”
不一定意味着 LLM 已明确确认 Balanced。

### 6.2 本地显式目标

本地判定只识别与程序名称无关的明确调度目标：

| 证据 | 分类 |
| --- | --- |
| deadline/SLO/response-time/latency 参数 | Latency |
| 固定请求率 + 尾延迟报告 | Latency |
| 显式 throughput 模式 | Throughput |
| 无远端 endpoint 的本地 benchmark + 工作预算 | Throughput |
| 有时间边界与完成量计数的本地重复工作 | Throughput |
| 有远端 endpoint 且无 SLO 的 bench/check-perf | Balanced |
| 其余 | 不在本地猜测，保留默认并继续 LLM |

本地显式目标可以立即建立 process default，但不会阻止后续 LLM 语义校验。

### 6.3 LLM 语义

```text
bounded /proc metadata ─▶ redact ─▶ batch (default 24 items)
                              │
                              ▼
                     DeepSeek chat/completions
                              │ strict JSON
                              ▼
                  proposal(class, confidence)
                              │
                              ▼
                    Registry revalidation
```

当前默认模型为 `deepseek-v4-flash`，thinking 关闭、`temperature=0`、超时 45 s。模型
输出只允许 `latency|balanced|throughput|unknown` 和 `0..=1` confidence；未知字段、
重复/陌生 ID、非 JSON 包装或非法置信度全部拒绝。

- process 特征：comm、脱敏 argv、executable、cgroups；
- thread 特征：thread comm，外加所属 process 的共享上下文；
- 请求只使用 `p0/t0...` 短 ID，稳定 cookie 不离开 Agent；
- 进程默认在 scheduler 观测到且年龄达 1 s 后入批；
- thread 语义只用于长寿命进程（默认 5 s）和长寿命 task（默认 2 s）；
- 线程批次要求同一 process 至少有 2 个候选 task；
- 置信度低于 0.60 转为 Unknown；无独立证据时，专用 process default 要求 0.90；
- 请求失败或结果缺失会终止本次语义路径，不阻塞任务。

相同有界元数据的 proposal 只在当前 Agent 进程内有界复用，不写入磁盘，Agent 重启后为空。

### 6.4 scheduler 运行行为

scheduler 每秒发送 task 运行窗口：CPU 运行时间、runnable wait、sleep、enqueue/wakeup/run
次数、burst/wait 直方图、slice exhaustion、自愿阻塞和迁移。只有 `quality=good`、task 年龄
至少 2 s，并达到最低样本量的窗口才可以投票。

| 行为类 | 主要强证据 | 限制 |
| --- | --- | --- |
| Latency | 高 wakeup、短 burst、高自愿阻塞、低 slice exhaustion、低利用率、存在 wait | 不能独立创建延迟目标；process default 已是 Latency，或必须有高置信 process/thread 语义支持 |
| Throughput | 长 burst >=70%、slice exhaustion >=50%、自愿阻塞 <=10% | 可以独立证明持续计算形态 |
| Balanced | 至少 64 次 run，五个混合信号中至少命中三个 | 作为中性证据，不会撤销已有强专用锁定 |

## 7. 分类状态机与证据融合

### 7.1 语义请求状态

```text
Pending ─▶ Requested ─┬─▶ Classified(class, confidence)
                      ├─▶ Unknown
                      └─▶ Failed

只有尚未成功入队的工作才能回到 Pending。
Classified/Unknown/Failed 是当前生命期的终态。
```

### 7.2 task 已提交阶段

```text
                    thread LLM 只更新语义上下文
                                  │
                                  ▼
Inherited ─── 连续 good behavior / 30 s timeout ───▶ Locked
    │                                                       │
    └─ 跟随 process default，默认 16 ms 粗采样       └─ 终止行为采样
```

`Semantic` 阶段仍是 control/scheduler 协议支持的合法中间状态，但当前 Registry 不会仅因
thread LLM proposal 而生成 Semantic action；正常路径是 `Inherited -> Locked`。

连续证据阈值：

- 低置信/一致证据默认需要 3 个连续 good window；
- 要推翻高置信专用语义，或低置信 Balanced 候选，默认需要 5 个窗口；
- 窗口缺口、Bad quality、pending action 或 desired/applied 不一致都会清空连续证据；
- 30 s 仍未得到足够强证据时，锁定当前 effective class；
- Locked 不再采样；只有晚到的高置信专用语义与另一已锁定专用类直接冲突时，
  才允许一次收敛到 Balanced。

同一 process 中至少两个独立 Locked task 给出一致专用类，Registry 才可以形成
process behavior 候选。不一致、包含 Balanced 或与高置信 process 语义冲突时，process
default 保守为 Balanced。

## 8. Registry 与可靠提交

### 8.1 desired 与 applied

```text
Registry decision
      │
      ▼
RegistryAction
 identity + class + stage + request_id
 expected_generation + new_generation
      │
      ▼
scheduler 校验 epoch / identity / generation CAS
      │
      ├─ success ─▶ 先写 BPF task_control，再提交 Rust cache
      │                         └─ ACK(new_generation)
      │                                      └─ Agent applied = desired
      └─ reject/timeout ─▶ 保留 desired，使当前同步失效，转 snapshot 恢复
```

增量更新必须满足 `new_generation = expected_generation + 1`，并且 scheduler 当前值等于
`expected_generation`。action 的 request ID 在得到匹配 ACK 前保持不变，重试不生成新 ID。

process default action 会更新所有 `Inherited` task；task action 仅作用于精确 TaskKey。
当前 Agent 产生的 task action 都是 `Locked`。

### 8.2 scheduler 重启与 replay

```text
control disconnect / new scheduler epoch
              │
              ▼
  保留 (process instance, tid, starttime) 投影
              │
              ▼
  scheduler replay new ProcessKey/TaskKey
              │ exact /proc lifetime match
              ▼
  restore class/stage/generation as desired
              │
              ▼
  ordered Registry snapshot batches ─▶ final ACK ─▶ resume incremental action
```

snapshot 每批最多 128 个 process/task 投影，空 Registry 也会发送一个终结批次。无法与
当前 `/proc` starttime 精确匹配的旧记录不恢复。

## 9. 控制协议与只读 Tool

Agent 与 scheduler 使用 Unix stream socket，每帧为 `4-byte big-endian length + JSON`。控制帧最大
1 MiB，协议版本为 1，每个 envelope 带 request ID、scheduler epoch 和 payload length。主要消息：

```text
Agent -> scheduler: Hello / RegistrySnapshotBatch / SetProcessDefault
                    SetTaskProvisional / LockTaskClass / GetSnapshot
scheduler -> Agent: ACK / ProcessDiscovered / TaskDiscovered / ProcessExec
                    TaskExited / ProcessExited / TaskStatsBatch / ReplayComplete
```

`SetTaskProvisional` 和 Semantic stage 为协议能力；当前 Agent 正常路径不产生该 action。

Tool socket 同样使用有界长度帧，但只提供以下读操作：

| Tool | 用途 |
| --- | --- |
| `workload.list` | 有界分页列出 active/recently-exited process/task，可按 TGID 批量筛选 |
| `workload.get` | 读取一个 active 稳定身份的有界投影 |
| `classification.get` | 读取 class、stage、source、confidence、generation 和 timing |
| `scheduler.health` | 读取当前 epoch、registry-ready、degraded 和连接状态 |
| `scheduler.stats` | 读取 scheduler 与 BPF data-plane 计数 |

Tool 线程不直接读 Registry：请求进入有界队列，由 Agent 主线程在一致视图上生成回复。
`scheduler.*` 每次读取实时 scheduler snapshot，失败时返回错误，不使用过期缓存。

## 10. 有界性、密钥与失败恢复

### 10.1 关键默认值

| 项目 | 当前默认 |
| --- | ---: |
| `/proc` reconciliation | 10 s |
| behavior/semantic tick | 1 s |
| LLM batch / workers | 24 / 2（性能配置为 3 workers） |
| LLM timeout / retries | 45 s / 2（性能配置为 1） |
| process/task Registry | 32,768 / 65,536 |
| pending LLM batches | 32 |
| control queue / frame | 1,024 / 1 MiB |
| Tool queue / frame | 128 / 256 KiB |
| scheduler restart | 60 s 内最多 3 次 |

配置使用 `deny_unknown_fields`，未知 TOML 键直接拒绝。队列、Registry、帧、snapshot、retry 和最大
批量都有上限，不允许通过普通配置无界放大。

API key 优先从环境变量读取，否则从配置文件读取；密钥只存在当前进程内存，不进入
prompt、Registry、snapshot 或正常日志。测试环境还要求密钥文件权限为 `0600`。

### 10.2 失败路径

| 失败 | 结果 |
| --- | --- |
| LLM HTTP/schema 失败 | 有界重试后进入 Failed；保留当前类，未知任务仍为 Balanced |
| LLM 队列满 | 未发送批次回到 Pending，不阻塞主循环 |
| proposal 迟到 | 身份或 request state 不匹配则丢弃 |
| Registry 容量满 | 丢弃新记录并增加计数；scheduler 数据面仍以 Balanced 运行 |
| control 断开/reject/timeout | 同步失效；重连后 lifecycle replay + Registry snapshot |
| scheduler child 退出 | 在 60 s 窗口内有界重启；超限则 Agent 失败退出 |
| Tool 失败 | 返回结构化错误，Registry 不变 |

## 11. 必须保持的不变量

1. 准入与分类分离；只有普通 `SCHED_OTHER` 任务可由 Agent 切换到 `SCHED_EXT`。
2. PID 1、内核线程、Agent、scheduler 和 RT/DL 任务保持 Linux 原生调度。
3. 新任务不等 LLM；未知、超时和失败都保留可调度的 Balanced/当前类。
4. LLM 只返回 proposal，Registry 主线程是分类状态的唯一 writer。
5. 所有分类和控制操作必须绑定完整 process/task lifetime，不能只使用 PID/TID。
6. desired generation 只在决策变化时增加，applied generation 只在匹配 ACK/snapshot 后推进。
7. Bad 行为窗口、序列缺口和身份冲突不能用于锁定分类。
8. 运行时形态不能独立创造 Latency 目标；必须有独立语义证据。
9. 专用类强证据冲突时回到 Balanced，不在不确定情况下激进分类。
10. Agent 重启不保留持久化应用分类；scheduler 重启必须先 replay 和 snapshot，再恢复增量更新。

## 12. 实现验证

```text
metadata/redaction tests
          │
          ▼
LLM strict-schema + mapping tests
          │
          ▼
Registry identity/state/generation tests
          │
          ▼
SchedulerClient/Tool/Supervisor tests
          │
          ▼
6 vCPU Native/Agent VM campaign
```

当前 Agent 单元测试覆盖准入、PID/TID 复用、exec、LLM 严格输出、证据融合、连续窗口、
generation ACK、scheduler replay、Tool 只读性和有界队列。性能实验额外验证普通负载进入
sched_ext，以及 PID 1、内核任务、Agent 和 scheduler 没有进入 sched_ext。
