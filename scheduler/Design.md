# scx_adaptive 当前实现设计

本文档描述 2026-07-24 工作区中的实际实现。源码是最终事实来源：

- BPF 数据面：rust/bpf/scx_adaptive.bpf.c
- Rust/BPF ABI：rust/bpf/intf.h
- Rust 控制面与慢路径：rust/src
- 基准框架：../test

本文只描述已经存在且通过构建的行为，不把试验方案写成既定设计。

## 1. 目标与硬约束

scx_adaptive 的目标是在同一套调度器中同时改善两类指标：

- Latency 场景的 P99 响应时间；
- Throughput 场景的单位时间完成量；
- Mix 场景中，Latency 不能被长时间片吞吐任务饿死；
- 性能优化不能依赖无限队列、无限循环或不可恢复的用户态状态。

安全约束高于性能目标：

1. 不改变 SCHED_FIFO、SCHED_RR、SCHED_DEADLINE 等实时调度策略。
2. 不对 PF_KTHREAD、Agent 进程和 scheduler 进程执行自定义分类、CPU 放置或抢占。
3. safe task 始终进入 sched_ext 的 GLOBAL DSQ，使用 SCX_SLICE_DFL。
4. 未分类任务、状态失配和用户态故障必须存在不依赖 Agent 决策的执行路径。
5. 所有用户态命令在 BPF 中重新校验实时 identity、generation、affinity、CPU 和 slice。
6. 任一容量不变量失败时受控 detach，由内核恢复正常调度，不能带病继续。

这里的 GLOBAL 是 sched_ext 全局 DSQ，不等同于 CFS。它不执行本项目的 class EEVDF、定制放置和
Latency 抢占。Linux 的 RT/DL 调度类仍由内核更高优先级的原生调度类处理。

## 2. 总体架构

当前实现是 BPF 快路径与 Rust 慢路径并存的双数据面。

~~~text
Adaptive-OS-Agent
  process/task class + stage + generation
                     |
                     v
              task_control map
                     |
     +---------------+----------------+
     |                                |
     v                                v
有效 BPF_SCHED control            control 缺失或失配
BPF 自主快路径                     Rust 有界慢路径
     |                                |
select_cpu / class DSQ                | lifecycle event
per-CPU root EEVDF                    v
direct dispatch / steal         task EEVDF -> root EEVDF
throughput continuation         -> placement -> reservation
     |                                |
     +---------------+----------------+
                     v
            BPF 最终校验与 DSQ
                     |
                     v
                 Linux CPU

safe task / context 缺失 / 慢路径心跳失效
                     |
                     v
              SCX_DSQ_GLOBAL
~~~

职责分工如下。

| 组件 | 负责 | 不负责 |
| --- | --- | --- |
| Agent | 进程/线程语义分类、generation、一次纠正 | 直接选择 CPU、直接操作 DSQ |
| Rust | 控制协议、分类事务、生命周期观测、未分类慢路径、诊断 | 绕过 BPF 最终校验 |
| BPF | 内核事实、已分类快路径、DSQ、抢占、steal、liveness fallback | 调用模型或依赖网络 |
| 内核 | RT/DL 类、sched_ext 框架、CPU 执行、detach 后恢复 | Agent 语义分类 |

## 3. 调度对象与分类生命周期

### 3.1 稳定身份

仅使用 PID/TID 会受到复用影响，因此调度对象使用三层身份：

~~~text
ProcessKey = tgid + process_cookie + exec_generation
TaskKey    = tid + task_cookie
Runnable   = TaskKey + enqueue_sequence
~~~

- process_cookie 和 task_cookie 由 BPF 分配，零值无效；
- process map 的内核 key 是 tgid 与 group leader start_boottime；
- exec 每发生一次，exec_generation 递增并跳过零；
- 每个新的 runnable incarnation 都递增 enqueue_sequence 并跳过零；
- dispatch command 必须同时匹配上述身份和 class_generation。

### 3.2 三个 workload class

| Class | 初始请求 | 主要目标 |
| --- | ---: | --- |
| Latency | 250 us | 降低唤醒到运行的尾延迟 |
| Balanced | 4 ms | 未知和通用负载的稳定折中 |
| Throughput | 8 ms | 保持 CPU/缓存局部性并减少切换 |

Class 编号固定为 Latency=0、Balanced=1、Throughput=2。

### 3.3 分类 stage

~~~text
Inherited -> Semantic -> Locked
Inherited ------------> Locked
~~~

- Inherited：继承进程默认值；初始默认值为 Balanced、generation 为 0；
- Semantic：Agent 给出线程语义判断，仍收集运行行为；
- Locked：完成唯一一次确认或纠正，分类永久锁定；
- Locked 之后不允许再次修改。

task_control 中始终设置 BPF_SCHED。Inherited 和 Semantic 同时设置 OBSERVE；Locked 清除 OBSERVE。
因此三种 stage 都能走 BPF 快路径，但只有未锁定任务继续发送 ENQUEUE、RUNNING、STOP 等观测事件。

### 3.4 分类更新事务

进程和任务更新均使用严格的 compare-and-swap generation：

~~~text
new_generation == expected_generation + 1
current_generation == expected_generation
~~~

提交顺序固定为：

1. 校验 identity、stage 和 generation；
2. 先写 BPF task_control；
3. 再提交 Rust Engine 状态；
4. Rust 提交失败则恢复旧 BPF control；
5. 进程默认更新涉及多个 inherited task 时，任一写入失败则回滚已写项。

这个顺序保证 BPF 不会使用 Rust 尚未确认的旧 generation。

## 4. BPF 快路径

### 4.1 快路径准入

fast_control_for 必须同时满足：

- task_control 存在；
- BPF_SCHED flag 已设置，且不存在未知 flag；
- class_id 在 0..3；
- task_cookie、process_cookie、exec_generation 与 task storage 完全一致。

任何一项不满足都不会猜测分类，而是进入 Rust 慢路径。

### 4.2 select_cpu

Balanced 和 Throughput 以局部性为主：

- Throughput 先尝试原 CPU 的 idle claim；
- 然后使用内核默认 CPU 选择；
- 默认结果繁忙时，Throughput 尽量保留合法的 prev_cpu；
- Balanced 接受合法的默认选择。

Latency 以启动延迟为主：

1. 先原子 claim 一个允许的空闲 SMT CPU；
2. 再 claim 任意允许的空闲 CPU；
3. 没有空闲 CPU 时选择可抢占 victim；
4. victim 顺序是 prev_cpu 上的 Throughput、其他 Throughput、Balanced；
5. 不选择 Latency victim，不选择 safe task，不绕过 cpus_ptr。

Latency 在 select_cpu 已原子取得空闲 CPU，且该 CPU 没有 local DSQ、class DSQ、normal slot 或
urgent slot 工作时，直接完成 local DSQ 插入。这条路径省去 enqueue callback、重复 map 查询和
额外 kick。

### 4.3 enqueue 与 task EEVDF

所有 runnable 记账由 begin_enqueue 统一完成，避免快慢路径重复维护 sequence 和时间戳。

快路径为每个可能 CPU 创建三个 custom DSQ。DSQ ID 为：

~~~text
FAST_CLASS_DSQ_BASE + class_id * MAX_CPUS + cpu
~~~

task 在 class 内携带：

~~~text
vruntime
request
deadline = vruntime + request
~~~

插入使用 scx_bpf_dsq_insert_vtime。新任务或唤醒任务最多获得一个 request 的 sleep credit；
class 变化时把 source lag 限制在 source/target 各自一个 request 内再转换，不能清零历史服务来
获得无限信用。

如果 select_cpu 已确认目标 CPU 空闲且该 CPU 没有本地积压，任务直接进入 local DSQ。否则任务
进入目标 CPU 对应的 class DSQ。

### 4.4 每 CPU root EEVDF

每个 CPU 保存三个 class root entity：

~~~text
root_virtual_time_ns
root_vruntime_ns[Latency, Balanced, Throughput]
~~~

活跃 class 的 root deadline 是：

~~~text
root_vruntime + class_base_request
~~~

eligible class 中选择最早 deadline；没有 eligible class 时把 root virtual time 前移到最小
vruntime。休眠后重新活跃的 class 最多保留一个 base request 的正 lag。

root base request 固定为 0.25/4/8 ms。Latency 的短 root deadline 提供低延迟，但 EEVDF 服务记账
防止其无限占用 CPU。

### 4.5 Latency urgent lane

非 direct 的 Latency enqueue 只有在以下条件全部满足时才可 arm urgent lane：

- 目标 CPU 在线且正在运行已知普通 class；
- CPU 不 idle；
- victim 是 Balanced 或 Throughput；
- victim 已连续运行至少 250 us；
- 该 CPU 距上次快路径抢占至少 5 ms。
- urgent slot 当前为空；
- Latency root entity 没有超过 root virtual time 一个 Latency request。

成功后使用 SCX_KICK_PREEMPT。普通任务只在确有必要时使用 SCX_KICK_IDLE。select_cpu 已经直接
插入的任务不再重复 kick。

### 4.6 Throughput 自适应 epoch

Throughput 从 8 ms 开始。连续耗尽且保持 runnable 时按以下序列增长：

~~~text
8 ms -> 16 ms -> 32 ms -> 64 ms
~~~

以下情况恢复为 8 ms：

- 主动阻塞；
- dequeue/cancel；
- exec；
- class 变化；
- 系统中已有其他已分类任务排队。

提前打断且剩余时间不少于 250 us 时，保留原 deadline 和剩余 request，不把打断误判成完整 epoch。

当 dispatch 回调看到同一 Throughput prev 仍可运行，并且全局没有已分类排队任务、
同 CPU 也没有 local、class、normal 或 urgent 工作时，可直接续接下一个 epoch：

- task 必须仍在同 CPU 且 affinity 允许；
- task 必须是快路径 Throughput；
- task 必须已关闭 OBSERVE；
- control identity 和 class 必须仍有效；
- 每次续接都更新 task/class vruntime，并向 root continuation 计费；
- 上限始终是 max_slice_ns=64 ms。

这条路径减少停止、重新入队、再次 dispatch 和上下文切换，但任何本地竞争都会立即阻止续跑。

### 4.7 有界 steal

本 CPU 没有可运行 class 后才尝试 steal：

- class_queued_tasks 为零时直接跳过扫描；
- 每次最多扫描 8 个 source CPU；
- 起点由每 CPU steal_cursor 轮转；
- source 在线且 idle 时必须至少保留一个自己的 queued task；
- source 繁忙或 offline 时允许搬运其等待任务；
- 每个 source 使用原子 steal_claim，避免多个 destination 同时搬运；
- class 仍由 destination 的 root EEVDF 选择；
- 一次 dispatch 最多搬运一个 task。

所有循环由常量或 num_possible_cpus 限界，满足 BPF verifier 和运行时上限。

### 4.8 dispatch 顺序

adaptive_dispatch 的固定顺序是：

1. 如有 usersched_needed，请求运行 Rust scheduler；
2. 消费当前 CPU 的 BPF Latency urgent sentinel；
3. 在最多 64 次 verifier-bounded 循环中消费 Rust command；
4. 从当前 CPU 的三个 class DSQ 运行 root EEVDF；
5. 尝试无竞争 Throughput prev continuation；
6. 仍无本地工作时执行一次有界 steal。

## 5. Rust 慢路径

慢路径服务于尚无有效 task_control 的短暂窗口，以及需要完整用户态策略的恢复场景。它不是已锁定
任务的常规数据面。

### 5.1 task pool EEVDF

三个 class 使用同一个 EevdfPool 实现，每个 pool 有：

- eligible deadline min-heap；
- future vruntime min-heap；
- oldest-wait min-heap；
- lazy invalidation，用 identity、sequence、class、generation 和 run state 验证节点。

任务正常完成 request 后，使用 run burst EWMA 估算下一请求：

~~~text
estimate = first ? sample : (7 * old + sample) / 8
Latency headroom = 2.0
Balanced/Throughput headroom = 1.25
~~~

Rust 慢路径请求范围：

| Class | 最小 | 最大 |
| --- | ---: | ---: |
| Latency | 250 us | 250 us |
| Balanced | 500 us | 4 ms |
| Throughput | 2 ms | 8 ms |

在 slice 的 90% 前被打断时保留原 deadline 和剩余 service。

### 5.2 pool 间 RootEevdf

三个非空 task pool 是等权 root entity。Rust 创建 reservation 时立即把 planned runtime 计入 root，
STOP 再以 actual runtime 对账。这样单次 refill 不会因为尚未收到 RUNNING/STOP 而把所有 CPU
预留给同一 class。

10/50/200 ms 的 class max-wait 是异常饥饿 watchdog，不是常规静态优先级。

### 5.3 放置和慢路径抢占

Rust 放置同时考虑：

- live cached affinity，BPF 后续再次检查 cpus_ptr；
- previous CPU、逐步稳定的 home CPU 和 home LLC；
- CPU 当前 slice 的预计剩余时间；
- SMT sibling 上的 class 和工作量；
- class-specific migration hysteresis；
- 每 CPU 一个 normal slot 和一个 urgent slot。

Latency 预计超过 2 ms SLO 时，才可能在 root 选择之外申请 10% CPU-time service budget。
真正的 urgent preemption 还受到独立 2% disruption budget、victim 最小运行 250 us、重复抢占
guard 和 victim class 限制。Latency 永远不能抢占 Latency。

### 5.4 BPF 最终校验

Rust command 到达 dispatch callback 后，BPF逐项检查：

- ABI version、struct size、dispatch_id 和 flag mask；
- task/process cookie 与 exec generation；
- task 必须仍是 PendingUser；
- enqueue_sequence 与 class_generation；
- dispatch 不能重复；
- target CPU 范围、online 状态和实时 affinity；
- migration-disabled task 不能跨 CPU；
- slice 必须在 250 us..64 ms；
- normal/urgent slot 必须原子 claim 成功。

失败返回稳定 reject reason，Rust 取消 reservation；可重试的竞态重新入池。

## 6. 生命周期与状态

### 6.1 BPF task state

| 值 | 状态 | 含义 |
| ---: | --- | --- |
| 0 | Blocked | 不可运行或已取消 |
| 1 | PendingUser | 等待 Rust command |
| 2 | Staged | Rust command 已插入 local DSQ |
| 3 | Running | 正在 CPU 上运行 |
| 4 | Exited | task 生命周期结束 |
| 5 | PendingBpf | BPF class/local DSQ 拥有 runnable |

### 6.2 Rust RunState

| 状态 | 含义 |
| --- | --- |
| Blocked | 当前不可运行 |
| Queued | Rust pool 拥有 runnable |
| KernelQueued | BPF fast DSQ 拥有 runnable，Rust仅观测 |
| KernelManaged | Locked task，runnable 生命周期完全由 BPF 管理 |
| Reserved | Rust 已提交 command 并占用 slot |
| Running | RUNNING 已确认 |
| Exited | 清理中的终态 |

### 6.3 关键 callback

- init_task：分配稳定 process/task identity，非 safe task 发送 INIT；
- sched_process_exec：递增 generation，清理快路径 request，恢复 Balanced 初始状态，发送 EXEC；
- enqueue：safe/global、BPF fast、Rust slow 三选一；
- running：释放匹配 slot，更新 CPU running_class 和 vruntime，按 OBSERVE 决定是否发事件；
- stopping：记 actual runtime，保留被打断 request 或推进 Throughput epoch；
- dequeue：除 CORE_SCHED_EXEC 外取消 request，避免错误清理 core-sched 切换；
- exit_task：释放 slot、删除 task_control，最后一个线程退出时删除 process entry；
- cpu_online/offline/update_idle：立即更新 cpu_state，按规则发布 CPU_STATE。

## 7. 安全路径和故障语义

### 7.1 safe task

is_safe_task 只包含三类：

~~~text
PF_KTHREAD
task.tgid == usersched_pid
task.tgid == agent_pid
~~~

它们不查 task_control、不进入 class DSQ、不参与自定义 victim 选择。当当前 CPU 仍在线且
符合 affinity 时，fallback 直接进入该 CPU 的 local DSQ；只有本地目标无效时才进入
SCX_DSQ_GLOBAL。scheduler 自身在 usersched_needed 时仍由 dispatch callback 显式插入 GLOBAL，
避免等待自己做出的用户态决策。

### 7.2 heartbeat

Rust 在 attach 前写入 heartbeat，主循环每轮刷新；批量处理事件时每 64 个事件额外刷新。fresh 条件：

~~~text
last != 0
now >= last
now - last <= 250 ms
~~~

已有有效 task_control 的快路径不依赖 Rust heartbeat。未分类慢路径发现 heartbeat stale 时：

1. 当前 task 进入 GLOBAL；
2. stale_heartbeat_fallbacks 加一；
3. 只触发一次 scx_bpf_error，请求 sched_ext ejection。

### 7.3 event overflow

- 慢路径 ENQUEUE 无法写 event queue 时，当前 task 立即进入 GLOBAL；
- 快路径观测事件写入失败时，调度继续，窗口被标记为不完整；
- Rust 每秒检查 event_overflows；
- 连续三个窗口发生 overflow 时受控 detach。

### 7.4 其他 detach 条件

- Agent 进程退出并超过 2 s grace；
- Engine 达到不可维持的不变量或容量上限；
- BPF/struct_ops 报告退出；
- SIGINT/SIGTERM；
- 持续事件丢失。

detach 先停止主循环，再释放 struct_ops link 和 control socket。link 释放后由内核接管公平调度。

## 8. ABI v6

rust/bpf/intf.h 是 Rust 与 BPF 的唯一二进制契约。所有结构固定宽度、自然对齐，只允许通过提升
ABI version 做兼容性变更。

| 结构 | 大小 |
| --- | ---: |
| task_event | 96 bytes |
| dispatch_command | 72 bytes |
| task_control_value | 40 bytes |
| adaptive_cpu_state | 96 bytes |
| adaptive_global_stats | 208 bytes |

关键容量：

| 常量 | 值 |
| --- | ---: |
| SCX_ADAPTIVE_ABI_VERSION | 6 |
| SCX_ADAPTIVE_MAX_CPUS | 1024 |
| event queue | 16384 |
| command queue | 16384 |
| max dispatch batch | 64 |

### 8.1 event kind

| Kind | 编号 |
| --- | ---: |
| INIT | 1 |
| EXEC | 2 |
| ENQUEUE | 3 |
| CANCEL | 4 |
| RUNNING | 5 |
| STOP | 6 |
| EXIT | 7 |
| CPU_STATE | 8 |
| COMMAND_REJECT | 9 |

Event flags 包含 RUNNABLE、CPU_ONLINE、CPU_IDLE、WAKEUP、BPF_SCHEDULED。

### 8.2 command reject reason

| 编号 | 原因 |
| ---: | --- |
| 1 | TASK_GONE |
| 2 | IDENTITY |
| 3 | NOT_PENDING |
| 4 | SEQUENCE |
| 5 | CLASS_GENERATION |
| 6 | CPU_OFFLINE |
| 7 | AFFINITY |
| 8 | TARGET_SLOT_BUSY |
| 9 | SLICE |
| 10 | DUPLICATE_DISPATCH |
| 11 | MIGRATION_DISABLED |
| 12 | FLAGS |

## 9. BPF maps

| Map | 类型 | 容量 | 用途 |
| --- | --- | ---: | --- |
| task_ctx_stor | TASK_STORAGE | task lifetime | BPF task 状态 |
| process_ctx | HASH | 32768 | process cookie、exec generation、线程数 |
| task_events | QUEUE | 16384 | BPF 到 Rust 生命周期/诊断 |
| dispatch_commands | QUEUE | 16384 | Rust 到 BPF command |
| task_control | HASH | 65536 | class、stage flags、generation |
| class_state | ARRAY | 3 | class global virtual time |
| cpu_state | ARRAY | 1024 | slot、idle、root、steal 状态 |
| heartbeat | ARRAY | 1 | Rust monotonic heartbeat |
| global_stats | PERCPU_ARRAY | 每 CPU 1 项 | 无共享 cache-line 的数据面统计 |

Rust 读取 global_stats 时对计数器做 saturating sum，对 max_normal_staged_depth 取最大值。

## 10. 默认配置

配置在打开 BPF object 前校验，attach 后不可变。

| 配置 | 默认值 |
| --- | ---: |
| latency_slice_ns | 250,000 |
| balanced_slice_ns | 4,000,000 |
| throughput_slice_ns | 8,000,000 |
| min_slice_ns | 250,000 |
| max_slice_ns | 64,000,000 |
| dispatch_batch_limit | 64 |
| placement_scan_limit | 8 |
| preemption_min_runtime_ns | 250,000 |
| latency_target_ns | 2,000,000 |
| latency_guarantee_percent | 10 |
| preemption_budget_percent | 5 |
| heartbeat_timeout | 250 ms |
| poll_interval | 1 ms |
| latency_max_wait_ns | 10,000,000 |
| balanced_max_wait_ns | 50,000,000 |
| throughput_max_wait_ns | 200,000,000 |
| max_tasks | 65,536 |
| max_pool_nodes | 524,288 |
| max_reservations | 4,096 |
| control_queue_capacity | 1,024 |
| max_control_frame_bytes | 1,048,576 |
| max_snapshot_items | 256 |
| response_cache_capacity | 4,096 |
| agent_exit_grace | 2 s |

BPF 内部额外常量：

| 常量 | 值 |
| --- | ---: |
| FAST_STEAL_SCAN_LIMIT | 8 CPUs |
| CPU_STATE_EVENT_INTERVAL_NS | 1,000,000 |
| FAST_CLASS_DSQ_BASE | 0x10000 |

struct_ops flags 为 SCX_OPS_ENQ_LAST 与 SCX_OPS_KEEP_BUILTIN_IDLE。

## 11. Agent 控制协议

控制 socket 默认是 /run/scx_adaptive.sock。协议版本为 1，使用 4-byte network-order 长度前缀加
JSON envelope。control thread 只负责 framing、校验和有界转发，SchedulerEngine 仍由 main thread
单 owner。

请求类型：

- Hello；
- RegistrySnapshotBatch；
- SetProcessDefault；
- SetTaskProvisional；
- LockTaskClass；
- GetSnapshot。

每次 scheduler 启动生成非零 scheduler_epoch。除 Hello 外，请求必须匹配 epoch。Hello 后先按稳定
顺序 replay live process/task，再发送 LifecycleReplayComplete。Registry snapshot 必须从 batch 0
开始、batch 连续且 snapshot_id 非零。

成功响应按 request_id 缓存在有界 response cache 中。相同 request_id 与相同 payload 重放原响应；
相同 request_id 携带不同 payload 返回 request_id_collision。

## 12. 性能优化对应关系

| 优化 | 主要收益 | 保护条件 |
| --- | --- | --- |
| Latency idle direct dispatch | 减少 wakeup 到 local DSQ 的路径长度 | 原子 idle claim 且 CPU 无本地积压 |
| 已分类 BPF fast path | 移除每次运行的 Rust round trip | 完整 task_control identity/generation |
| Locked 事件抑制 | 降低 queue、usersched 和 JSON 观测开销 | 仅 Locked；生命周期事件仍保留 |
| CPU_STATE 1 ms 合并 | 减少 idle churn | map 状态立即更新，hotplug/必要唤醒不合并 |
| Throughput 8..64 ms epoch | 降低切换与重新入队开销 | 全局无分类排队竞争、上限 64 ms、阻塞即复位 |
| prev continuation | 避免完整 dispatch cycle | Locked Throughput 且全局/本地均无其他工作 |
| fallback 本地化 | 降低未分类与 safe task 的迁移/控制面开销 | CPU 在线且 affinity 允许，否则 GLOBAL |
| 快路径抢占限流 | 避免短 victim 和连续 IPI 抖动 | victim >=250 us，每 CPU 间隔 >=5 ms |
| 有界 rotating steal | 改善负载不均 | 8 CPU 上限、source claim、保留 source 工作 |
| PERCPU stats | 消除全局统计 cache-line 竞争 | Rust 聚合并饱和计数 |
| 单次 stats lookup 记 enqueue | 缩短热路径 | 仅合并相同生命周期的计数 |
| 条件 kick | 避免无效 IPI | direct 不 kick；仅 urgent/非运行任务 kick |

## 13. 诊断指标

GetSnapshot 同时返回 Rust SchedulerStats 和聚合后的 BPF DataPlaneStats。性能路径重点观察：

- fast_path_enqueues；
- fast_path_dispatches 与 fast_path_dispatches_by_class；
- fast_path_direct_dispatches；
- fast_path_prev_continuations；
- fast_path_empty_steal_skips；
- fast_path_steal_attempts、remote_steals、claim_conflicts；
- fast_path_dispatch_failures；
- fast_path_events_suppressed；
- cpu_state_events_suppressed；
- fast_path_preemptions；
- fast_path_preemption_throttles；
- fallback_dispatches、stale_heartbeat_fallbacks、event_overflows；
- commands_rejected 与 identity/slot reject。

fallback_dispatches 包含 PF_KTHREAD、Agent、scheduler 等预期 safe-task 插入，不能单独视为
故障；它可能进入 local 或 GLOBAL DSQ。liveness 应结合 stale_heartbeat_fallbacks、
event_overflows 和 detach 状态判断。

出现以下组合时需要停止调参并先排查正确性：

- event_overflows 持续增加；
- stale_heartbeat_fallbacks 在稳定运行时增加；
- identity_rejects 非零且增长；
- fast_path_dispatch_failures 与 dispatches 同量级；
- Latency victim 发生自抢占；
- max_normal_staged_depth 超过 1；
- 分类覆盖率或 generation 应用率不是 100%。

## 14. 当前性能证据与验收规则

`20260725-120702-620116` 是当前代码的单轮全场景候选结果。Guest 独占 3 个物理核、
6 个 SMT 线程，每个 run 预热 20 s、测量 60 s；6/6 run 有效。这些数据用于迭代取舍，
不构成正式置信区间。

| 场景 | Native | Agent | Agent 相对 Native |
| --- | ---: | ---: | ---: |
| latency P99 | 2,074.713 us | 21,996.078 us | 低 960.20% |
| throughput | 1,073.059 units/s | 977.614 units/s | 低 8.89% |
| mix P99 | 7,679.252 us | 25,406.212 us | 低 230.84% |
| mix throughput | 13.102 units/s | 12.908 units/s | 低 1.47% |

与同一天的优化前单轮基线 `single-round-20260724-222443` 相比：

- 纯 Throughput 相对 Native 的差距从 20.24% 收窄到 8.89%；
- Mix P99 从 287,953.686 us 降到 25,406.212 us，约降低 91.18%；
- Mix P99/Native 比值从约 37.22 倍降到 3.31 倍；
- Mix 的 scheduler CPU 从约 15.01 s 降到 6.42 s，events 从约 190 万降到 137 万，
  CPU migration 从约 44.1 万降到 18.5 万；
- 纯 Latency 仍为最大缺口，当前 P99 约为 Native 的 10.60 倍，不能被 Mix 改善掩盖。

独立纯 Throughput 复验 `20260725-120145-308125` 中，fallback 本地化将 CPU migration 从
130,134 降到 49,055，scheduler CPU 从 3.94 s 降到 1.95 s，同时将相对 Native 的差距从
9.78% 收窄到 8.53%。

分类 snapshot 是测量期内的时点观测，可能早于异步 LLM 批次提交；因此必须与最终 class
dispatch 计数、Locked 行为纠错和 scheduler log 一起解读，不能把早期 snapshot 当成全程分类。

后续候选必须继续运行默认三轮 paired campaign，并同时满足：

1. 所有 Native/Agent paired run 有效；
2. 分类覆盖率、正确率和 generation 应用率为 100%；
3. latency P99 相对优化前实现有正向中位改善；
4. throughput ops/s 相对优化前实现有正向中位改善；
5. mix P99 不出现统计显著退化；
6. deadline miss、event overflow、fallback 和 reject 无正确性回归；
7. verifier smoke、Rust 测试、Python benchmark 测试全部通过。

性能是硬件、内核、负载和分类共同作用的结果，因此代码不能诚实地“保证任意环境必然提升”。
本项目用相同镜像、独占 CPU、paired 顺序、重复实验和置信区间把提升变成可验证的验收条件。

## 15. 构建、校验与基准

在仓库根目录执行：

~~~bash
cargo fmt --manifest-path scheduler/rust/Cargo.toml --all -- --check
cargo build --manifest-path scheduler/rust/Cargo.toml --release --locked
cargo clippy --manifest-path scheduler/rust/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path scheduler/rust/Cargo.toml --locked
scheduler/rust/target/release/scx_adaptive --validate-only
python3 -m unittest discover -s test/tests -v
~~~

单轮迭代：

~~~bash
python3 test/scripts/benchmark.py --single-round
~~~

正式三轮：

~~~bash
python3 test/scripts/benchmark.py
~~~

报告必须同时检查 report.md、preflight.json、每个 run 的 benchmark-summary.json 和
scheduler-snapshot.json。外部分类服务失败导致的错误 class 不能用于判断调度器性能。

## 16. 源码导航

| 文件 | 职责 |
| --- | --- |
| rust/bpf/intf.h | ABI v6、event/command/control/stats |
| rust/bpf/scx_adaptive.bpf.c | callbacks、快路径 EEVDF、steal、fallback |
| rust/src/main.rs | attach、主循环、事务协调、detach |
| rust/src/bpf.rs | skeleton、map/queue I/O、PERCPU stats 聚合 |
| rust/src/wire.rs | ABI 解码、reject、command 序列化 |
| rust/src/engine.rs | 生命周期、慢路径 refill、reservation、rollback |
| rust/src/eevdf.rs | root EEVDF 和 lag 算术 |
| rust/src/pool/mod.rs | 三个共享实现的 task EEVDF pool |
| rust/src/placement.rs | topology/SMT/locality 放置 |
| rust/src/admission.rs | Latency service 与 preemption token budget |
| rust/src/process.rs | class cache、stage、generation |
| rust/src/control.rs | 有界 Unix socket 协议 |
| rust/src/topology.rs | CPU/core/LLC 发现和 affinity |
| rust/src/stats.rs | Rust 决策计数与行为窗口 |

scheduler/scx 是锁定的上游 sched_ext 构建与兼容依赖，不承载本项目调度策略。

## 17. 修改时必须保持的不变量

1. safe task 判定和 usersched 显式 GLOBAL 逃生路径不能因性能调参被旁路。
2. Latency victim 只能是 Balanced 或 Throughput。
3. direct dispatch 必须先成功 claim idle CPU，并确认没有本地工作。
4. Throughput epoch/continuation 必须在存在任何全局已分类排队竞争时停止增长。
5. 所有 slice 必须位于 250 us..64 ms。
6. 所有 BPF 扫描、repeat 和 map 容量必须有静态上界。
7. normal/urgent lane 每 CPU 各最多一个 reservation。
8. class 变化必须保留有界 lag，不能清零服务历史。
9. interrupted request 必须保留剩余 service 和原 deadline。
10. 控制更新必须 BPF-first，并具备 Rust 失败回滚。
11. ABI 结构变化必须同步 version、static_assert、Rust bindgen 使用方、collector 和测试。
12. 任何性能结论必须区分单轮迭代结果与正式重复实验。
