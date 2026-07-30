# scx_adaptive 调度器设计与实现

本文说明当前 scheduler 的完整实现：Rust 负责加载、控制、身份和慢速 policy；eBPF
负责 sched_ext 热路径。README 只给出构建和运行命令，跨组件关系见
[根 Design.md](../Design.md)。

## 1. 设计边界

scx_adaptive 是一个 partial sched_ext 调度器，同时服务三类目标：

| 类别 | 目标 | 默认 request |
| --- | --- | ---: |
| Latency | 缩短 runnable wait 和 P99，允许受预算限制的唤醒救援 | 250 us |
| Balanced | 对未知和普通混合工作保持稳定公平 | 4 ms |
| Throughput | 减少切换，保留 cache/locality，提升持续工作完成量 | 8 ms |

Throughput request 在没有其他分类 backlog 时可按 8 -> 16 -> 32 -> 64 ms 增长；一旦
出现竞争、阻塞、exec、cancel 或 class 改变，就回到 8 ms。所有值仍受全局
min_slice/max_slice 限制。

调度器明确不做两件事：

- 不在 Rust 中保存 runnable queue 或发逐任务 dispatch 命令；
- 不把 Agent、LLM、/proc 或网络请求放进 BPF callback。

## 2. 分层和数据流

~~~text
                         +---------------------------+
                         | Agent control socket      |
                         | Hello / snapshot / CAS    |
                         +-------------+-------------+
                                       |
                                       v
+----------------------- Rust userspace ----------------------------+
| ControlHandle | SchedulerEngine | PolicyController | AgentWatch  |
|      |                |                 |                |          |
|      +---- identity/cache/generation --+                |          |
|      +---- lifecycle + behavior -------+                |          |
|      +---- topology + feedback --------+                |          |
+----------------------+-----------------+----------------+----------+
                       |                 |
              task_control map    policy slot/map
                       |                 |
+----------------------v-----------------v--------------------------+
|                         eBPF sched_ext                             |
| init_task/exec/exit -> identity + event ring                       |
| select_cpu -> enqueue -> private/shared DSQ -> dispatch             |
| running/stopping/tick -> virtual time, budget, counters             |
+----------------------+-----------------+--------------------------+
                       |
                       v
                 Linux CPU execution
~~~

Rust 与 BPF 之间唯一的二进制 ABI 是 scheduler/rust/bpf/intf.h。所有共享结构使用固定宽度
字段并有 _Static_assert；ABI 当前为 v35。

## 3. 启动与生命周期

### 3.1 loader 做什么

命令行入口在 scheduler/rust/src/main.rs：

1. 构造并校验 SchedulerConfig；
2. 从 sysfs 发现 possible/online CPU、core/SMT、LLC、NUMA、package、capacity 和
   core type；
3. 生成本次 scheduler_epoch；
4. 以 topology 和初始 PolicySnapshot 打开 skeleton；
5. 把 immutable topology、slice、Agent PID 和 policy 写入 BPF rodata/maps；
6. attach SCX_OPS_SWITCH_PARTIAL 的 struct_ops；
7. 启动 Unix control socket 与主循环。

~~~text
main
 |
 +-- validate config
 +-- CpuTopology::discover()
 +-- scheduler_epoch = random non-zero u64
 +-- PolicyController::new(generation=1)
 +-- BpfRuntime::load()
 |      +-- open object
 |      +-- fill rodata/maps
 |      +-- load verifier
 |      +-- attach struct_ops
 +-- ControlHandle::spawn()
 +-- run_scheduler()
~~~

partial 模式下，Agent 只把普通 SCHED_OTHER 线程转入自定义数据面；PID 1、内核线程、
Agent、scheduler 和其他调度策略保持 Linux 原生。BPF 在 init_task、enqueue 和
task_control 查找处再次检查 safe identity。

### 3.2 主循环

Rust 主循环的工作顺序是有意固定的：

~~~text
while sched_ext still attached:
  1. AgentWatch: 每 100 ms 检查 PID + /proc starttime
  2. policy lease: 到期则只续租当前完整 policy
  3. 若没有 replay/backlog:
       最多 pop 4096 个 BPF event -> Engine
  4. 接收 control request，按 request_id 做幂等查找
  5. 发送 lifecycle replay 或 pending event
  6. 若每 1 s 到期:
       读取 per-CPU stats/pressure
       生成 observation delta
       更新 policy 和 BehaviorWindow
  7. 没有工作时 sleep 4 ms，否则 yield
~~~

生命周期 replay 每批最多 128 条；pending control event 上限为 8,192。Engine 一旦达到
task/process capacity 或进入 degraded，主循环跳出并受控 detach。

## 4. ABI 与 BPF maps

### 4.1 固定 ABI

| 数据 | 实现约束 |
| --- | --- |
| ABI version | 35，Rust/BPF 启动时校验 |
| task_event | 88 bytes，含 task/process cookie、exec generation、enqueue sequence |
| task_control_value | 40 bytes，含 class、flags、generation 与三类 cookie |
| adaptive_policy_control | 64 bytes，含 active slot、lease、budget、cadence |
| adaptive_cpu_policy | 56 bytes，每 CPU 一行 topology/candidate |
| adaptive_cpu_state | 136 bytes，每 possible CPU 一行热状态 |
| global stats | 800 bytes，每 CPU 一份 |
| lifecycle ring | 2 MiB |
| dispatch callback batch | 最多 64 slots |

结构只追加字段，不改变既有字段的宽度和顺序。编译期静态断言阻止 Rust/BPF 看到不同
布局。

### 4.2 map 关系

~~~text
                         +----------------------+
                         | task_ctx_stor        |
                         | BPF task storage     |
                         +----------+-----------+
                                    |
                   +----------------+----------------+
                   |                                 |
                   v                                 v
        +----------------------+           +----------------------+
        | process_ctx         |           | task_control         |
        | 32768 process keys  |           | 65536 TID entries    |
        +----------------------+           +----------+-----------+
                                                       |
                                                       v
        +----------------------+           +----------------------+
        | task_events ring    |<----------| lifecycle/behavior    |
        | 2 MiB               |           | event producer        |
        +----------------------+           +----------------------+

        +----------------------+    +----------------------+
        | policy_control[1]   |    | cpu_policy[2*1024]   |
        | active selector     |    | complete policy slots|
        +----------+-----------+    +----------+-----------+
                   |                           |
                   +-------------+-------------+
                                 v
        +----------------------+    +----------------------+
        | cpu_state[1024]     |    | core_latency_state   |
        | idle/credit/queues  |    | shard claims         |
        +----------------------+    +----------------------+

        +--------------------------------------------------+
        | global_stats: PERCPU_ARRAY, no shared hot counter |
        +--------------------------------------------------+
~~~

immutable topology maps（CPU domain、core leader、core peer、leader list）由 loader 一次写入，
运行时 BPF 直接读取，不依赖可能过期的 userspace policy lease。

## 5. 身份和控制事务

### 5.1 BPF identity

~~~text
process_identity_key = tgid + leader_start_boottime
process_context      = process_cookie + exec_generation + active_threads
task_context         = task_cookie + process_cookie + exec_generation
task_control_value   = TID key + above cookies + class_generation
task_event           = above identity + enqueue_sequence
~~~

process cookie 在 init_task 为 thread group 分配，exec 增加 exec_generation，最后一个
线程 exit 时回收 process_ctx。task cookie 绑定 task storage 生命周期。

task_control 虽然以 numeric TID 为 map key，但 fast_control_for 必须同时匹配 task_cookie、
process_cookie 和 exec_generation；否则只返回 Balanced 默认值。

### 5.2 control protocol

Unix socket 默认路径是 /run/scx_adaptive.sock。协议为 v1：

~~~text
 +----------------+---------------------------------------------+
 | 4 bytes        | JSON payload                                |
 | big-endian len | version/type/request_id/epoch/payload       |
 +----------------+---------------------------------------------+
 最大 frame 1 MiB，control queue 1024，成功 response cache 4096
~~~

消息类型：

| 请求 | 作用 |
| --- | --- |
| Hello | 建立 Agent 连接，返回 scheduler_epoch 和 rebuild_required |
| RegistrySnapshotBatch | 按顺序恢复 process defaults 与 task overrides |
| SetProcessDefault | 改变一个 process image 的 inherited default |
| SetTaskProvisional | 写入 Semantic stage |
| LockTaskClass | 写入 Locked stage |
| GetSnapshot | 返回 scheduler、policy、BPF 健康快照 |

### 5.3 CAS 和回滚

一次 process/task action 的最小条件：

~~~text
engine.current_generation == expected_generation
new_generation           == expected_generation + 1
identity/process owner   完全匹配
Registry snapshot        已完成
~~~

Rust 的提交顺序是：

~~~text
Agent request
    |
    v
校验 epoch / ready / identity / generation
    |
    v
先写 task_control（process update 则逐项写 inherited tasks）
    |
    +-- 任一 BPF 写失败 --> 恢复已写项的旧 value
    |
    v
更新 SchedulerEngine cache
    |
    +-- cache 失败 --> 恢复 BPF 旧 value
    |
    v
ACK(applied_generation)
~~~

response cache 只保存成功响应；相同 request_id 搭配不同 payload 会返回
request_id_collision，而不会重放错误结果。

## 6. Registry 同步和 epoch

新连接或 scheduler 重启必须按以下顺序完成：

~~~text
Agent                         scheduler                  Engine/BPF
  |                                |                         |
  |-- Hello(known_epoch) --------->|                         |
  |<-- epoch + rebuild_required ---|                         |
  |                                |                         |
  |<-- Process/Task replay --------|-- lifecycle_notices --->|
  |<-- LifecycleReplayComplete ----|                         |
  |-- snapshot batch 0 ----------->|-- reset classifications->|
  |-- snapshot batch 1..N -------->|-- apply task_control -->|
  |<-- final snapshot_complete ----|                         |
  |                                |                         |
  |       ready=true；允许增量 action                       |
~~~

snapshot_id 必须非零，batch_index 从 0 连续递增，最后批次 is_last=true。开始 snapshot
时 scheduler 先把现有 classification reset 成 inherited Balanced；任一批次乱序或写入
失败就拒绝恢复，BPF 仍能走默认路径。

## 7. topology 与动态 policy

### 7.1 topology 建模

CpuTopology 从 /sys/devices/system/cpu 读取：

| 属性 | 来源/用途 |
| --- | --- |
| possible/online | map 范围与 hotplug 合法性 |
| physical_package_id/core_id | 物理 core leader、SMT peer |
| thread_siblings_list | smt_index 与完整 core 判断 |
| cache level/id/shared_cpu_list | LLC/domain locality |
| NUMA node、core_type | domain 和 candidate 代价 |
| cpu_capacity | 异构核上的压力归一化 |

CPU 编号保留 dense array 索引，最多支持 1,024 个 possible CPU。domain key 由
NUMA、package、LLC、core_type 组合而成。

### 7.2 PolicySnapshot

每个 CPU policy 行含：

~~~text
CPU -> domain / LLC / NUMA / package / core / SMT / capacity / core_type
    -> latency_candidate_cpu[2]
    -> normal_candidate_cpu[2]
~~~

整个快照另含：

~~~text
generation
valid_until_ns
latency_budget_percent       = 20%
preemption_interval_ns
latency_successor_lease_ns
balanced_preemption_granularity_ns
cross_domain_cost_ns         = balanced_slice * 2
domain_count
~~~

初始化 generation=1，lease=2 s，refresh=500 ms。policy generation 的奇偶选择两个 slot：
generation % 2 是 active_slot。

### 7.3 双槽发布

~~~text
                 Rust userspace                         BPF
                      |                                  |
  current slot A ---->|                                  |
                      | 写完整 slot B 的每个 CPU 行      |
                      |--------------------------------->|
                      | 写 policy_control(active_slot=B,
                      |                  generation=G+1)
                      |--------------------------------->|
                      |                                  |
                      |                         读取 active_policy
                      |                         验证 generation/flags/
                      |                         valid_until_ns
                      |                                  |
                      |<--------- 使用 G+1 或 fallback --------|
~~~

BPF 只接受 generation 匹配、POLICY_VALID 且未过期的完整快照；lease 过期时使用 attach
时写入 rodata 的 immutable 参数。Rust 每 1 s 用累计 counter 的 delta 计算观察值：

- 三类 runtime、dispatch、preemption；
- Latency budget charge 次数与 runtime；
- preemption throttle；
- Latency backlog boost；
- 每 CPU idle/running class/queued depth/credit/debt。

PolicyController 由这些事实调：

| 反馈 | 调整 |
| --- | --- |
| Latency competing service 超过预算 | 增大 preemption interval，保留下限 |
| measured Latency service 改变 | 调整 successor lease |
| Balanced 被频繁抢占 | 增大 Balanced granularity |
| Latency 被 throttle 且服务不足 | 在 bounded cap 内缩小 Balanced granularity |
| CPU pressure 变化 | 更新两个 locality-aware candidate |

只在变化超过阈值或需要续租时发布，避免每秒制造无意义 map 写入。

## 8. runnable queue 层次

当前实现不是每类一条全局队列，而是“每 CPU 私有 + 少量拓扑共享”：

~~~text
每个 CPU c
+--------------------------------------------------+
| latency_dsq(c) : private Latency                  |
| task_dsq(c)    : private Balanced + Throughput   |
| SCX_DSQ_LOCAL  : 真正 idle target 的直接投递     |
+--------------------------------------------------+
          |                         |
          |                         +------------------+
          |                                            |
每个 core leader l                                    |
+----------------------------------+                  |
| shared_latency_dsq(l)            |<-- blocked, wide affinity Latency
+----------------------------------+                  |
                                                     |
每个 domain d                                        |
+----------------------------------+                  |
| balanced_overflow_dsq(d)         |<-- non-wakeup, wide affinity Balanced
+----------------------------------+                  |
                                                     v
                                      dispatch(cpu) 本地消费/搬运
~~~

路由条件是代码中的实际条件：

| 任务 | 条件 | 目标 |
| --- | --- | --- |
| Latency | select_cpu 找到空闲且无本地 backlog | SCX_DSQ_LOCAL 直接 dispatch |
| Latency | blocked wakeup、full affinity、可迁移 | core shared latency |
| Balanced | 非 wakeup、full affinity、可迁移 | domain balanced overflow |
| 其他普通任务 | 受限 affinity 或 Throughput | owner CPU 的 vtime DSQ |

共享队列只在 owner CPU 合法且 topology/domain 校验通过时建立；migration-disabled 或
非默认 static priority 任务不会被强行搬入共享 lane。

## 9. 三条 eBPF 热路径

### 9.1 select_cpu

~~~text
select_cpu(p, prev_cpu, wake_flags)
  |
  +-- task_control 精确命中？--否--> Balanced + fallback flags
  |
  +-- Throughput 且 prev_cpu online/affinity/idle？
  |       是 -> 复用 prev_cpu
  |
  +-- scx_bpf_select_cpu_dfl()
  |       |
  |       +-- Latency: 记录 default-idle/default-busy path
  |       +-- blocked Latency 且 default busy -> policy victim candidate
  |       +-- blocked Balanced 且 default busy -> pressure candidate
  |
  +-- 结果不合法？-> prev_cpu 或 cpumask distribute
  |
  +-- Latency 命中真正 idle 且本地无队列？
  |       是 -> 直接 fast_enqueue
  |
  +-- 记录 selection path，返回 target_cpu
~~~

policy candidate 必须满足 online、cpus_ptr、core/domain 合法性和 pressure hysteresis；
默认 selector 仍是第一选择，policy 只在有明确 blocked wakeup 且默认 CPU 忙时介入。

### 9.2 enqueue

~~~text
enqueue(p)
  |
  +-- 没有 task_context / safe task？
  |       -> local-on 当前合法 CPU，否则 GLOBAL fallback
  |
  +-- 读取 selected control 或重新查 task_control
  |
  +-- begin_enqueue(): enqueue_sequence++, timestamp
  |
  +-- class_changed / woke_from_sleep / CPU changed？
  |       -> 计算 virtual time、request、request_deadline
  |
  +-- 选择队列:
  |       direct idle       -> SCX_DSQ_LOCAL_ON
  |       blocked Latency   -> shared_latency_dsq(core)
  |       ordinary Balanced -> balanced_overflow_dsq(domain)
  |       private            -> latency_dsq(cpu) 或 task_dsq(cpu)
  |
  +-- blocked Latency/Balanced 是否形成 urgent marker？
  |       -> credit/debt、cadence、victim deadline 检查
  |
  +-- idle 且非 direct？kick IDLE
      immediate preempt？kick PREEMPT
~~~

virtual deadline 由 Linux task weight 修正后的 service 计算；Latency 的 virtual service
再减半，形成更早的截止时间。睡眠 credit 只在 class change 或真实 wakeup 时补入。

### 9.3 dispatch

~~~text
dispatch(cpu)
  |
  +-- 读取 active policy，刷新 latency credit/debt
  +-- 消费 urgent marker (Latency 优先于 Balanced)
  |
  +-- private/shared Latency 有工作，且:
  |       normal 为空，或 urgent，或 credit >= latency request
  |       -> dispatch Latency
  |
  +-- credit 足够且其他 core shared Latency 有 backlog
  |       -> dispatch shared Latency
  |
  +-- 本 CPU task_dsq 有工作
  |       -> dispatch_fast_task(cpu)
  |
  +-- 处理 race 后仍有 Latency
  |       -> 再试一次 private/shared Latency
  |
  +-- 远端 Latency backlog 且 credit 足够
  |       -> core shard / bounded Latency steal
  |
  +-- domain Balanced overflow
  |
  +-- remote normal backlog
  |       -> 最多扫描 8 个 source CPU，CAS claim 后搬 1 个 task
  |
  +-- destination 真正 idle
          -> 最后 rescue shared Latency
~~~

source_can_spare 会保护两个 locality 细节：

- idle source 只有一个 Throughput task 时，先 kick source，不立即偷走；
- 非 idle source 正在运行 Latency 且只剩一个 normal successor 时，在 measured
  successor lease 内暂缓 steal。

每次 remote steal 最多扫描 8 个 CPU、移动一个 task，并用 source steal_claim 防止两个
destination 同时搬运。

## 10. 三类调度语义

### 10.1 Latency credit/debt

每个 CPU 保存 latency_credit_ns、latency_debt_ns 和 last_preemption_ns：

~~~text
空闲或普通服务让 credit 按 budget 逐步恢复
Latency 抢占/竞争服务消耗 credit
超过 credit -> debt，debt 上限 = 有限个 Latency request
credit/debt 达到边界 -> throttle 或 defer urgent wakeup
~~~

默认 budget 为 20%。若 running task 是 Throughput，还必须先运行
throughput_preemption_min_runtime_ns（默认 1 ms 上限）才能接受 Latency 抢占。这样
尾延迟路径有明显优先级，却不会把持续任务切成无数碎片。

### 10.2 Balanced preemption

Balanced blocked wakeup 只有在其 request_deadline 明显早于当前 victim deadline，且差值
超过当前 granularity 时才设置 BALANCED_RESCHED marker。tick callback 再检查：

- victim 不是 Latency；
- 已运行至少 Balanced granularity；
- victim 为 Throughput 时至少运行固定最小 slice；
- marker 仍有效。

最终由 tick 把 slice 置零，而不是在 enqueue 里直接重复 kick。

### 10.3 Throughput epoch

stopping 时计算实际 runtime：

~~~text
未完成 request 且仍 runnable 且剩余 >= min_slice
    -> 保留剩余 request/deadline
否则
    -> request 清零
    -> Throughput 且仍 runnable 时:
         无 classified backlog: request *= 2，最多 64 ms
         有 backlog: 回到 8 ms
~~~

running 时若任务移动到新 CPU，virtual time 以目标 CPU 的 clock 重新对齐，避免跨 CPU
后获得不合理的 deadline。

## 11. lifecycle、行为和统计

### 11.1 生命周期 callback

| callback | 关键动作 |
| --- | --- |
| init_task | safe task 设置 disallow；普通 task 分配 cookie、创建 task storage、发 INIT |
| process_exec tracepoint | 增加 exec_generation，清空旧 fast state，发 EXEC |
| exit_task | 清理 queue accounting、发 EXIT、删除 task_control，最后线程时回收 process_ctx |
| cpu_online/offline | 更新 online/idle、清理 urgent/credit/claim |

### 11.2 事件采样

无分类或需要高质量行为证据的任务会发 enqueue/running/stopping/cancel 事件；已 Locked
task 的 enqueue/running/stop 事件在 Engine 侧被抑制。fast event 采用时间间隔采样，
coarse observe 使用更稀疏间隔。BPF ring overflow 会增加 event_overflows；Rust 下一秒
把该窗口标坏，阻止行为投票。

stopping 还按 1/16 的 runnable incarnation 采样 pipeline：

- local normal depth；
- local + core shared Latency depth；
- ready/empty pipeline sample。

### 11.3 统计分组

global_stats 是 PERCPU_ARRAY，Rust 读取并求和，避免跨 CPU cache line 竞争。统计按下列
组别导出：

| 组 | 典型字段 |
| --- | --- |
| 基本路径 | fast enqueue/dispatch、local/direct、fallback、dispatch failure |
| locality | select migration、remote dispatch、steal attempt/claim/exhaustion |
| 抢占 | preemption、victim class、throttle、defer、immediate kick |
| Latency 预算 | charge events/runtime、backlog boost、shared/core rescue |
| Throughput | epoch continuation、service/runtime bins、topology distance |
| shared lane | Balanced/Latency enqueue、attempt、success、race failure |
| pipeline | ready/empty sample 与 normal/latency depth sum |

## 12. 健康、降级与 detach

~~~text
                    +-------------------------+
                    | scheduler running       |
                    +------------+------------+
                                 |
        +------------------------+------------------------+
        |                        |                        |
   Agent missing           Engine degraded          overflow window
   > 2 s                   capacity hit             >= 3 consecutive
        |                        |                        |
        +------------------------+------------------------+
                                 v
                    +-------------------------+
                    | stop main loop          |
                    | report exit if needed   |
                    | BpfRuntime::detach()   |
                    | ControlHandle::join()  |
                    +------------+------------+
                                 |
                                 v
                         sched_ext disabled
~~~

具体门禁：

- AgentWatch 每 100 ms 核对 PID starttime，丢失超过 2 s 才 detach；
- event overflow 连续三个 1 s window 才触发 detach；
- task capacity 或 Engine degraded 立即停止；
- policy 过期只回退 policy，不立即 detach；
- BPF 自己报告 exit reason，Rust 在 detach 前记录。

安全 fallback 分三层：

1. task_control 缺失/失配：Balanced class；
2. CPU target 不合法：当前合法 CPU 的 local DSQ，否则 GLOBAL DSQ；
3. policy 过期：attach 时 immutable 参数。

## 13. 为什么热路径适合混合任务

~~~text
语义 class
   |
   +--> Latency: 250 us + blocked wake rescue + budget/cadence
   |
   +--> Balanced: 4 ms + virtual deadline + bounded preemption
   |
   +--> Throughput: 8..64 ms + prev CPU reuse + successor protection
                         |
                         v
              每 CPU 私有 lane 保持 locality
              少量 core/domain shared lane 处理合法迁移
              BPF-only dispatch 保持确定性
~~~

该组合同时解释两类目标的取舍：Latency 获得更早的 runnable 服务，但只能在竞争预算、
victim runtime 和 cadence 允许时打断；Throughput 获得较长 epoch 与 locality，但远端
Latency backlog 有界地救援；Balanced 仍是所有未知路径的可用默认。

## 14. 实现不变量

1. BPF 是唯一 runnable queue owner。
2. safe task 与非 SCHED_OTHER task 不进入自定义 fast path。
3. task_control 必须匹配完整 task/process cookie 和 exec generation。
4. generation 只能精确加一，重复或迟到 action 必须拒绝。
5. BPF map 事务后续失败必须恢复旧值。
6. CPU 选择服从 online、cpus_ptr、migration-disabled 和 affinity。
7. Latency credit/debt、preemption cadence、Throughput min runtime 都有上限。
8. remote steal 扫描、dispatch batch、ring event 和 map capacity 都有上限。
9. policy 只从完整 inactive slot 切换，并受 generation/lease/fallback 校验。
10. Agent 消失、持续 overflow 或 degraded 时最终状态必须是 sched_ext disabled。

## 15. 代码索引

| 主题 | 文件 |
| --- | --- |
| CLI、loader、主循环、detach | rust/src/main.rs |
| 默认值与安全边界 | rust/src/config.rs |
| Unix protocol、Hello、snapshot、ACK | rust/src/control.rs |
| identity、process/task cache、stage | rust/src/identity.rs、rust/src/process.rs |
| lifecycle Engine、行为窗口 | rust/src/engine.rs、rust/src/stats.rs |
| topology | rust/src/topology.rs |
| policy 双槽与反馈 | rust/src/policy.rs |
| BPF load、map mirror、stats | rust/src/bpf.rs |
| ABI | bpf/intf.h |
| DSQ、select/enqueue/dispatch、callback | bpf/scx_adaptive.bpf.c |
