# Adaptive OS Agent 总体设计

本文描述当前代码实际实现的端到端架构。它回答四个问题：

1. 系统怎样认识一个新工作负载；
2. 分类结果怎样可靠地进入内核；
3. eBPF 怎样在每次唤醒和调度时使用这些结果；
4. 任一组件失效时，系统怎样继续运行或安全退出。

组件内部实现分别见：

- [Adaptive-OS-Agent/Design.md](Adaptive-OS-Agent/Design.md)：发现、分类、Registry 与控制事务；
- [scheduler/Design.md](scheduler/Design.md)：Rust 控制面、动态 policy 与 eBPF 数据面；
- [test/Design.md](test/Design.md)：Host、VM、真实负载、采集和配对分析。

## 1. 问题与核心思路

Linux 调度热路径需要微秒级、确定性和有界执行；工作负载语义识别却需要读取进程上下文，
甚至调用远端模型。项目没有把这两件事塞进同一条路径，而是把系统拆成两个时间尺度：

~~~text
+---------------------- 慢闭环：20 ms 至秒级 ----------------------+
| /proc / lifecycle                                                |
|          |                                                       |
|          v                                                       |
| 本地规则 + DeepSeek + 行为窗口 -> ClassificationRegistry         |
|                                      |                           |
|                                      v                           |
|                           class / stage / generation              |
+--------------------------------------+---------------------------+
                                       |
                                       v
                              +------------------+
                              | task_control map |
                              +--------+---------+
                                       |
                                       v
+------------------------- 快闭环：每次唤醒与 dispatch ------------+
| select_cpu -> enqueue -> BPF DSQ -> dispatch -> CPU              |
|                               |                                   |
|                               +-> 运行/排队/抢占/压力 -> 慢闭环   |
+-------------------------------------------------------------------+
~~~

这形成项目最重要的实现原则：

- LLM 只给出建议，永不参与 enqueue 或 dispatch；
- Agent 只拥有语义状态，不拥有 runnable queue；
- Rust scheduler 负责可靠控制和动态策略，不逐任务决定下一次运行；
- eBPF 独占可运行任务的数据面，因此用户态抖动不会堵住 CPU 调度；
- 任何缺失、过期或冲突的信息都收敛到 Balanced 或内核 fallback。

## 2. 整体架构

~~~text
+------------------------- Adaptive-OS-Agent -----------------------+
| 进程发现/安全准入 ----+                                          |
| 语义/行为 Skills -----+--> ClassificationRegistry (唯一写者)    |
|                                  |                 |              |
|                                  v                 +-> Tool 只读  |
|                           SchedulerClient                         |
+----------------------------------+--------------------------------+
                                   | 长度前缀 JSON / 协议 v1
+----------------------------------v--------------------------------+
|                    scx_adaptive Rust 控制面                       |
| Unix control -> identity + generation CAS -> 健康/受控 detach    |
| lifecycle/behavior Engine -> topology + PolicyController          |
+---------------------+--------------------------+------------------+
                      |                          |
       先写 BPF map， |                          | 双槽原子发布
       后写 Rust cache|                          |
+---------------------v--------------------------v------------------+
|                     sched_ext eBPF 数据面                         |
| task/process identity      task_control       cpu_policy[2]       |
|             \                  |                  /                |
|              +-------> select_cpu / enqueue <---+                 |
|                           |                                       |
|                  private/shared DSQ                               |
|                           |                                       |
|             dispatch / running / stopping                         |
+---------------------+--------------------------+------------------+
                      |                          |
              2 MiB lifecycle ring       runtime/pressure counters
                      +-------------> Rust Engine
                                        |
                                        +-- 1 s BehaviorWindow --> Agent
~~~

### 2.1 每层拥有的状态

| 层 | 权威状态 | 明确不做的事情 |
| --- | --- | --- |
| Agent | 进程元数据、语义证据、desired/applied generation | 不选 CPU，不操作 DSQ |
| Rust scheduler | BPF 身份镜像、控制事务、拓扑、policy、健康状态 | 不保存 runnable queue |
| eBPF | task/process cookie、虚拟时间、CPU 状态、DSQ、热路径统计 | 不读取 /proc，不访问网络 |
| test | VM 生命周期、原始证据、有效性、Native/Agent 配对 | 不向被测进程设置调度提示 |

这种所有权划分避免“双写”：Registry 只有 Agent 主线程写，runnable queue 只有 BPF 写，
动态 policy 只有 Rust 发布。

## 3. 一条任务怎样从出现到被调度

下面的时序图把最常见路径串起来。新任务不会等待识别完成，它先按 Balanced 运行。

~~~text
Linux/sched_ext       eBPF              Rust             Agent          DeepSeek
      |                 |                 |                 |               |
      |-- init_task --->|                 |                 |               |
      |                 | 分配 task/process cookie         |               |
      |                 |-- INIT event -->|                 |               |
      |                 |                 |-- discovered -->|               |
      |                 |                 |                 | 读 /proc       |
      |<----------------------------------------------- SCHED_OTHER 准入    |
      |                 |                 |                 |               |
      |  先按 Balanced 运行；分类不阻塞任务               |               |
      |                 |                 |                 |-- batch ------>|
      |                 |                 |                 |<-- strict JSON-|
      |                 |-- run samples ->|-- 1 s window -->|               |
      |                 |                 |                 | 融合证据       |
      |                 |                 |<-- CAS action ---|               |
      |                 |<-- task_control-| 校验 epoch/身份 |               |
      |                 |                 | 更新 Rust cache |               |
      |                 |                 |-- ACK ---------->|               |
      |                 |                 |                 | desired=applied
      |                 |                 |                 |               |
      |-- select/enqueue>| 匹配 cookie，算 request/deadline/DSQ             |
      |<-- dispatch -----|                 |                 |               |
~~~

### 3.1 为什么新任务不会卡住

首次出现时，BPF task context 和 Rust cache 都使用 Balanced。Agent 的本地规则、
DeepSeek 或行为投票可以晚到，但只会改变后续 runnable incarnation。远端请求超时、
JSON 错误、低置信或队列满都不会阻塞当前任务。

### 3.2 为什么 PID/TID 复用不会误分类

系统使用逐层增强的身份，而不是只相信数值 PID：

~~~text
Agent 初始发现:
  ProcessInstanceKey = tgid + /proc start_time_ticks

BPF/Rust 稳定进程:
  ProcessKey = tgid + process_cookie + exec_generation

BPF/Rust 稳定线程:
  TaskKey = tid + task_cookie

单次可运行实例:
  RunnableKey = TaskKey + enqueue_sequence

跨实例与跨版本:
  scheduler_epoch + class_generation
~~~

Agent 在准入系统调用前后读取 starttime；BPF 在 task_control 命中后再次比较
task_cookie、process_cookie 和 exec_generation。exec 会增加 image generation 并清空旧的
虚拟时间与分类快路径状态。由此，迟到的模型响应、控制 ACK 或生命周期事件都不能落到
复用后的任务上。

## 4. 工作负载感知闭环

分类不是“看进程名猜类别”，而是三类证据的保守融合：

~~~text
                        +------------------+
                        | 新进程: Balanced |
                        +--------+---------+
                                 |
             +-------------------+-------------------+
             |                   |                   |
             v                   v                   v
     +---------------+   +---------------+   +----------------+
     | 本地明确目标  |   | DeepSeek 语义 |   | scheduler 行为 |
     +-------+-------+   +-------+-------+   +--------+-------+
             \                   |                    /
              +------------------+-------------------+
                                 v
                        +------------------+
                        | Registry 保守融合|
                        +----+---------+---+
                             |         |
              同向强证据     |         | 歧义/低置信/冲突
                             v         v
                    Latency/Throughput Balanced
                             \         /
                              v       v
                         连续 good window
                                |
                                v
                              Locked
~~~

### 4.1 三类证据的用途

| 证据 | 实现输入 | 能解决的问题 |
| --- | --- | --- |
| 本地显式目标 | 有界 argv、comm、executable、cgroup | 快速识别 deadline、SLO、固定速率+尾延迟、明确本机批处理 |
| DeepSeek | 脱敏后的进程批次或线程 comm + 进程上下文 | 识别命令语义和父子/线程角色 |
| 行为窗口 | runtime、wait、sleep、wakeup、burst、slice exhaustion、migration | 验证任务实际是短唤醒、混合运行或持续占用 |

行为证据不能凭“频繁唤醒”独立创造 Latency 目标；专用类冲突时退回 Balanced。协议支持
Inherited、Semantic、Locked 三个 stage，当前正常线上路径为 Inherited 到 Locked；
Semantic 仍保留给兼容控制协议和状态校验。

### 4.2 分类提交不是普通赋值

Registry 同时保存 desired generation 与 scheduler 已确认的 applied generation。一次更新
必须满足：

~~~text
current_generation == expected_generation
new_generation     == expected_generation + 1
~~~

Rust 先把新值写入 BPF task_control，再更新自身 cache。第二步失败时恢复原 map value；
进程默认值影响多个 inherited task 时，任一 task 写失败会回滚此前所有写入。Agent 只有
收到匹配 request_id、identity 和 applied_generation 的 ACK 后才推进 applied 状态。

## 5. 调度数据面

### 5.1 类别与基础 request

| 类别 | 初始 request | 热路径目标 |
| --- | ---: | --- |
| Latency | 250 us | 短服务、阻塞唤醒救援、受预算抢占 |
| Balanced | 4 ms | 通用公平与 EEVDF 式虚拟截止时间 |
| Throughput | 8 ms | 保持 CPU/cache locality，空闲竞争时最长增长到 64 ms |

虚拟服务先按 Linux task weight 做反比缩放；Latency 再获得 2 倍虚拟权重。任务因睡眠或
换 CPU 获得的 credit 最多为一个 request，避免睡眠任务积累无界优势。

### 5.2 队列不是三条全局队列

当前 ABI v35 的真实队列结构如下：

~~~text
每个 CPU                         每个物理 core         每个 topology domain
+--------------------------+    +------------------+  +----------------------+
| latency_dsq(cpu)         |    | shared_latency   |  | balanced_overflow    |
|   Latency                |    | _dsq(core leader)|  | _dsq(domain)         |
|                          |    | 宽 affinity 的   |  | 宽 affinity 的       |
| task_dsq(cpu)            |    | blocked Latency  |  | ordinary Balanced    |
|   Balanced + Throughput  |    +--------+---------+  +----------+-----------+
|                          |             |                       |
| SCX_DSQ_LOCAL            |             |                       |
|   空闲 CPU 直接投递      |             |                       |
+------------+-------------+             |                       |
             +---------------------------+-----------------------+
                                         |
                                         v
                                  +---------------+
                                  | dispatch(cpu) |
                                  +---------------+
~~~

Balanced 与 Throughput 共享 normal lane，但 request、virtual deadline、CPU 复用和
Throughput epoch 不同。共享队列只处理适合迁移的宽 affinity 任务，受限 affinity 或
migration-disabled 任务始终留在合法的私有路径。

### 5.3 一次 dispatch 的优先顺序

~~~text
1. 有 Latency credit、无 normal 竞争或已消费 urgent marker:
     private/shared Latency
2. 本 CPU normal lane:
     Balanced + Throughput
3. 处理队列竞争后仍存在的 Latency
4. 有 credit 时救援远端 Latency
5. domain Balanced overflow
6. 有界 normal remote steal
7. CPU 真正空闲时最后救援 Latency
~~~

这个顺序同时满足两条要求：有可运行任务时不让 CPU 空转；存在普通任务竞争时，Latency
只能使用 credit/debt 预算和 cadence，而不是无限抢占。

## 6. 动态 topology policy

Rust 从 sysfs 发现 CPU online、core/SMT、LLC、NUMA、package、capacity 和 core type。
每个 CPU 的 policy 保存两个 Latency candidate 和两个 Normal candidate，以及预算、
抢占周期、successor lease、Balanced granularity 和跨 domain 成本。

~~~text
+------------------------- 闭环反馈 -------------------------------+
| BPF per-CPU pressure/counters                                    |
|              |                                                    |
|              v                                                    |
|       1 s observation delta -> PolicyController                  |
|                                  |                                |
|                                  v                                |
|                     写完整 inactive policy slot                   |
|                                  |                                |
|                                  v                                |
|                         原子切换 generation                        |
+----------------------------------+--------------------------------+
                                   |
                                   v
                         BPF active_policy 校验
                          /                  \
          generation 匹配且 lease 有效       过期/不完整
                     |                         |
                     v                         v
                使用新 policy           immutable fallback
                     |
                     +------> 新的 pressure/counters
~~~

policy 有两个完整 slot，Rust 每 500 ms 续租，lease 为 2 s。发布顺序是“先写完 inactive
slot 的所有 CPU，再切 generation”，因此 BPF 不会看到半张拓扑。反馈只调慢路径参数，
不会把用户态重新放进逐任务 dispatch。

## 7. 启动、重连与退出

### 7.1 正常启动

~~~text
Agent                          scheduler                         BPF
  |                                |                              |
  |-- spawn(child, Agent PID) ---->|                              |
  |                                |-- load maps/rodata ---------->|
  |                                |-- attach struct_ops --------->|
  |<-- Hello(scheduler_epoch) -----|                              |
  |<-- lifecycle replay -----------|<----- current identities -----|
  |<-- ReplayComplete -------------|                              |
  |-- RegistrySnapshotBatch 0 ---->|-- rebuild task_control ------>|
  |-- RegistrySnapshotBatch ... -->|-- rebuild task_control ------>|
  |-- final batch ---------------->|-- rebuild task_control ------>|
  |<-- ACK(snapshot_complete) ------|                              |
  |                                |                              |
  |      registry_ready=true；此后才接受增量分类                    |
~~~

在 snapshot 完成前，BPF 仍按默认 Balanced 调度；scheduler 明确拒绝增量更新，避免旧
Agent 状态和新 scheduler epoch 混合。

### 7.2 故障恢复

| 故障 | 具体实现 |
| --- | --- |
| DeepSeek timeout、HTTP 或 schema 错误 | 有界重试；失败/Unknown 保留当前类 |
| worker 或控制队列满 | 不阻塞主循环，任务保持当前类，稍后再收敛 |
| 控制 socket 断开 | BPF 数据面继续；重连后 replay + 全量 snapshot |
| scheduler child 退出 | Agent 在 60 s 滑动窗口内最多重启 3 次 |
| Agent PID 消失或复用 | scheduler 每 100 ms 核对 PID+starttime，宽限 2 s 后 detach |
| policy lease 过期 | BPF 使用加载时的不可变默认值 |
| event overflow 连续 3 个窗口 | 行为窗口标坏并受控 detach |
| task capacity 或 Engine degraded | scheduler 受控 detach |
| SIGINT/SIGTERM | 停止新工作，关闭 socket，释放 struct_ops，确认 sched_ext disabled |

所有关键资源都有固定上界，包括 Registry、BPF map、ring buffer、frame、队列、event
batch、snapshot batch、response cache、remote steal 扫描和 dispatch batch。

## 8. 为什么这套架构能形成性能优势

~~~text
                  +----------------------------+
                  | 语义区分谁怕等待、谁怕切换 |
                  +-------------+--------------+
                                |
              +-----------------v------------------+
双槽反馈 ---->| 类别化 request、placement 与预算    |
              +-----+---------------+--------------+
                    |               |
        +-----------+               +-----------------+
        |                                               |
        v                                               v
+---------------------+                         +----------------------+
| Latency 短 request  |                         | Throughput 长 epoch  |
| + 有界唤醒救援      |                         | + CPU/cache locality |
+----------+----------+                         +----------+-----------+
           |                                               |
           v                                               v
      降低交互 P99                                    控制吞吐损失

              +--------------------------------------+
              | Balanced EEVDF 式公平路径            |
              +------------------+-------------------+
                                 v
                          维持通用任务公平
~~~

优势不是来自某个固定进程名或某次随机参数，而来自架构上的组合：

1. 语义把尾延迟任务与持续任务分开；
2. BPF 在本地完成 hot path，Agent 和网络延迟不会进入调度成本；
3. Latency 只在竞争发生时消耗预算，空闲容量可以直接利用；
4. Throughput 在无竞争 epoch 增长并优先保留前一 CPU；
5. private lane 保持 locality，共享 lane 只接收可安全迁移的任务；
6. policy 用实际运行反馈调整 cadence、granularity 和候选 CPU，但有 lease/fallback 约束。

## 9. 实验怎样证明闭环有效

测试只运行 dynamic_mix：Redis、Nginx、PostgreSQL 提供 P99，FFmpeg、RocksDB、zstd
提供持续吞吐，OpenSSL 提供周期压力。Host 为 Native 和 Agent 分别创建同一模板的独立
VM overlay，固定 6 vCPU、3 GB、1 socket × 3 cores × 2 threads、CPU pin 和 3.3 GHz。

冻结版本在 campaign `20260730-144717-822781` 中的一轮完整配对结果：

| 指标 | Native | Agent | Agent 相对结果 |
| --- | ---: | ---: | ---: |
| 聚合 P99 | 3,706.5 us | 1,851.0 us | 降低 50.06% |
| 综合吞吐 | 51.211 units/s | 53.694 units/s | 提升 4.85% |
| 平均 CPU | 80.91% | 80.63% | -0.28 pp |

该轮同时验证六个目标应用、周期峰值、分类 generation、policy feedback/placement、
dispatch 健康、控制面 CPU/RSS、perf 事件和清理状态。单轮只表达这一对 VM 的观测，
不估计跨 repeat 置信区间；完整数据由每次测试生成到
test/output/performance/<timestamp>/report.md。

## 10. 跨组件不变量

1. LLM 永不进入 BPF 调度热路径。
2. PID 1、内核线程、Agent、scheduler 和非 SCHED_OTHER 任务不进入自定义数据面。
3. 新任务、缺失分类和模型失败都能立即按 Balanced 运行。
4. 分类更新必须绑定 scheduler epoch、完整身份和连续 generation。
5. task_control 事务必须先写 BPF，后写 cache；后续失败必须回滚。
6. runnable queue 只由 BPF 拥有，Rust 不发逐任务 dispatch 命令。
7. CPU 选择必须服从 online、cpus_ptr 和 migration 状态。
8. 动态 policy 必须完整双槽发布，并带 lease 与不可变 fallback。
9. 所有循环、扫描、队列、frame、map 和 cache 都有静态上界。
10. 性能结论只来自同 repeat、同配置且两侧都有效的 Native/Agent 配对。

## 11. 实现索引

| 主题 | 主要实现 |
| --- | --- |
| Agent 启动与主循环 | Adaptive-OS-Agent/src/main.rs |
| /proc 身份、脱敏、准入 | metadata.rs、discovery.rs、task_admission.rs |
| 语义与行为分类 | deepseek.rs、process_classifier.rs、thread_classifier.rs、behavior.rs |
| 分类状态和 generation | registry.rs |
| Agent/scheduler 协议 | scheduler_client.rs、scheduler/rust/src/control.rs |
| Rust identity 与事务 | engine.rs、process.rs、scheduler/rust/src/main.rs |
| topology 与动态 policy | topology.rs、policy.rs |
| BPF ABI、maps 与调度热路径 | bpf/intf.h、bpf/scx_adaptive.bpf.c |
| Host/VM/Guest 实验 | test/test_core/vm、test/test_core/benchmark |
| 真实负载 | test/image/real_workloads/aoa-real-workload |
| 离线验收与报告 | test/test_core/benchmark/analysis.py |
