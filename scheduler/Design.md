# scx_adaptive 当前实现设计

本文描述 2026-07-28 工作区中的实际实现。源码是最终事实来源：

- BPF 数据面：`rust/bpf/scx_adaptive.bpf.c`
- Rust/BPF ABI：`rust/bpf/intf.h`
- Rust 控制面：`rust/src`
- 性能协议：`../test`

## 1. 目标与边界

一个 `scx_adaptive` 同时调度 Latency、Balanced 和 Throughput 普通任务，目标是：

1. Balanced 达到或超过相同机器上的 Linux EEVDF；
2. Latency 降低尾延迟；
3. Throughput 提高单位时间完成量；
4. Mix 中三类目标同时可用，任何一类都不能无限侵占 CPU；
5. 算法不依赖测试应用名称，所有循环、map 和状态都有静态上界；
6. 用户态失效时普通任务仍能执行，受保护任务始终保持原生调度。

性能结论只能来自同镜像、同 CPU、同时间窗的 Native/Agent 配对实验，不能由代码结构直接推断。

### 1.1 当前支持基线

```text
正式 Guest   openEuler 24.03 LTS-SP4 / x86_64 / 6.6.0-scx
sched_ext 库  scx_cargo 1.0.25 / scx_utils 1.0.25 / scx_stats 1.0.20
锁定工具链  clang/LLVM 17.0.6 / rustc+cargo 1.96.0
BPF ABI     v8
```

构建包装器会依次寻找 Clang 20..16；Clang 16 可用于当前本地构建，但会提示推荐
17 以上。完整基线和镜像哈希位于 [`versions.lock`](versions.lock)。策略不按应用名称分支，
但能否加载 sched_ext 仍取决于目标内核、BTF 和 BPF kfunc 兼容性。

## 2. 单数据面架构

```text
                    低频控制路径：不参与每次 dispatch

 ┌────────────────────┐      ┌────────────────────┐      ┌────────────────────┐
 │ Adaptive-OS-Agent  │      │ Rust control plane │      │ task_control map   │
 │ class/stage/gen    │─────▶│ identity/CAS/ACK   │─────▶│ exact lifetime     │
 └────────────────────┘      └──────────┬─────────┘      └──────────┬─────────┘
                                              │ lifecycle/window          │ lookup
                                              ▲                           ▼
                    高频数据路径：全部在 BPF

 ┌────────────────────┐      ┌────────────────────┐      ┌────────────────────┐
 │ Linux runnable task│─────▶│ select_cpu/enqueue │─────▶│ per-CPU class DSQ  │
 └────────────────────┘      └────────────────────┘      └──────────┬─────────┘
                                                                         │ root EEVDF
                                                                         ▼
                                                               local DSQ ─▶ Linux CPU
```

一次 runnable 事件不会上送 Rust 等待决策：

```text
control 精确匹配？
   ├─ 是 ─▶ 使用 class/generation/observe flags
   └─ 否 ─▶ 当场使用 Balanced + 粗采样
                 │
                 ▼
        选 CPU ─▶ 写 vtime DSQ ─▶ dispatch
```

| 组件 | 负责 | 不负责 |
| --- | --- | --- |
| Agent | 普通任务准入、进程/线程分类、generation | CPU 选择、DSQ |
| Rust | 控制协议、分类事务、稳定身份、行为窗口、detach | runnable 调度算法 |
| BPF | CPU 选择、virtual time、DSQ、抢占、steal、fallback | 模型和网络 |
| Linux | RT/DL、sched_ext 框架、partial 切换、detach 恢复 | 语义分类 |

不存在 Rust 慢路径调度。task_control 缺失、失配或尚未生成时，BPF 直接使用可观测的 Balanced
默认值，因此不会等待 Agent 或 Rust 做出每次 runnable 决策。

## 3. 任务范围与系统安全

### 3.1 partial admission

struct_ops 使用 `SCX_OPS_SWITCH_PARTIAL`。Agent 对 `/proc` 做有界周期性 reconciliation，并在
INIT/EXEC 生命周期通知后及时补充准入：

- 只处理普通用户态进程；
- 只把当前策略为 `SCHED_OTHER` 的线程切换为 `SCHED_EXT`；
- PID 1、Agent、scheduler、内核线程和非普通策略保持原生；
- TID 和 start time 在系统调用前后都复核，竞态记入 `identity_races`；
- 创建/退出竞态由生命周期事件和周期 reconciliation 恢复。

```text
Linux 原生策略
      │
      ├─ PID 1 / kernel / Agent / scheduler ─────▶ 保持原生
      ├─ SCHED_FIFO/RR/DEADLINE/其他非 OTHER ─▶ 保持原生
      └─ ordinary SCHED_OTHER
                    │ Agent sched_setscheduler(SCHED_EXT)
                    ▼
             scx_adaptive BPF
                    │ is_safe_task() 再检查
                    ├─ protected ▶ local/GLOBAL fallback，保证可运行
                    └─ ordinary  ▶ 三类数据面
```

BPF 的 `is_safe_task()` 再次拒绝 PID 1、`PF_KTHREAD`、Agent TGID 和 scheduler TGID。
`init_task` 对 attach 前已存在的受保护任务设置 `scx.disallow`；enqueue 中仍保留 local/GLOBAL
fallback，作为异常进入 BPF 时不依赖用户态的可运行性保护。正常安全不变量仍由
partial admission 保证：受保护任务根本不进入自定义数据面。

### 3.2 故障恢复

以下情况触发受控 detach：

- Agent 身份消失超过 2 秒 grace；
- 连续三个一秒窗口出现 BPF event overflow；
- Rust 活跃身份达到 `max_tasks`；
- BPF/struct_ops 报告退出；
- SIGINT 或 SIGTERM。

detach 释放 struct_ops link。普通 `SCHED_EXT` 任务由内核恢复，受保护任务此前从未进入自定义数据面。

```text
running
  │
  ├─ Agent identity 连续消失 >= 2 s ─┐
  ├─ event overflow 连续 3 个窗口 ───├─▶ controlled detach
  ├─ userspace task capacity hit/degraded ───┤        │
  ├─ BPF exit / SIGINT / SIGTERM ───────┘        ▼
  └─ 短时 control 断开 ─▶ 数据面继续，重连时 replay + snapshot
                                                    Linux 接管 SCHED_EXT task
```

## 4. 身份与分类事务

### 4.1 稳定身份

~~~text
ProcessKey = tgid + process_cookie + exec_generation
TaskKey    = tid + task_cookie
Runnable   = TaskKey + enqueue_sequence
~~~

- cookie 由 BPF 单调分配，零值无效；
- process map 的 kernel key 同时包含 TGID 和 group leader start time；
- exec_generation 和 enqueue_sequence 递增时跳过零；
- task_control 同时匹配 task/process cookie 与 exec_generation，TID 复用不会命中旧分类。

### 4.2 class 与 stage

| Class | 基础 request | 目标 |
| --- | ---: | --- |
| Latency | 250 us | 降低 runnable wait 和尾延迟 |
| Balanced | 4 ms | 通用公平性与稳定吞吐 |
| Throughput | 8 ms | 降低切换并保持局部性 |

Class 编号固定为 0、1、2。分类 stage 为：

~~~text
Inherited -> Semantic -> Locked
Inherited ------------> Locked
~~~

- Inherited 使用当前 process default；新未知 process 是 Balanced/generation 0，使用 16 ms 粗采样；
- Semantic 使用 4 ms 行为采样；
- Locked 不再发送 ENQUEUE/RUNNING/STOP 行为事件；
- Locked 专用类只允许一次保守冲突收敛到 Balanced。

当前 Agent 不会仅因 thread LLM proposal 就发送 Semantic 更新；正常线上 task 是
`Inherited -> Locked`。Semantic 仍是 ABI/control 状态机支持的合法中间阶段，用于完整协议
兼容性和恢复校验。

### 4.3 更新事务

增量更新必须满足：

~~~text
current_generation == expected_generation
new_generation == expected_generation + 1
~~~

提交顺序为校验身份和 stage、写 BPF task_control、提交 Rust cache。任何后续失败都会恢复旧
task_control。进程默认更新涉及多个 inherited task 时逐项写入，任一失败回滚此前写入。

scheduler 每次启动生成非零 epoch。Agent 通过 Hello 和有序 RegistrySnapshotBatch 恢复已有分类；
live process/task replay 完成后发送 `LifecycleReplayComplete`。响应按 request_id 在有界 cache 中幂等重放。

## 5. BPF 调度算法

### 5.1 默认 Balanced 与控制查找

`select_cpu` 和 `enqueue` 都从以下默认值开始：

~~~text
class = Balanced
flags = BPF_SCHED | OBSERVE | COARSE_OBSERVE
~~~

只有 task_control 的 flag、class、task cookie、process cookie 和 exec generation 全部有效时才覆盖
默认值。无效控制不是错误路径，也不会唤醒 Rust 做调度决定。

### 5.2 CPU-owned class DSQ

每个 possible CPU 有三个 virtual-time DSQ：

~~~text
FAST_CLASS_DSQ_BASE + class_id * MAX_CPUS + cpu
~~~

队列的实际布局是：

```text
                         task-level EEVDF order

 CPU 0   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
         │ Latency DSQ │ │ Balanced DSQ│ │Throughput DSQ│
         └─────────────┘ └─────────────┘ └─────────────┘

 CPU 1   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
         │ Latency DSQ │ │ Balanced DSQ│ │Throughput DSQ│
         └─────────────┘ └─────────────┘ └─────────────┘
           ... 每个 possible CPU 各自三条队列 ...

 全局   ┌──────────────────────┐
        │ Latency overflow DSQ │  目标 CPU 已有 Latency 积压，或 overflow 已活跃时使用
        └──────────────────────┘
```

这不是“三条全局任务队列”。全局状态只有：

- `class_state[3].virtual_time_ns`：三个 class 的 task-level virtual-time 基准；
- `class_queued_tasks`：自定义 class DSQ 中等待任务的原子计数，只用于快速判断是否值得 steal/增长 epoch；
- `specialized_tasks`：存活非 Balanced 任务数，用于切换 Balanced-only 与 mixed-class 路径。

每 CPU 的 `root_virtual_time_ns` 和三个 `root_vruntime_ns` 均在 `cpu_state[cpu]`中，不在全局
共用。task 自身保存 `vruntime`、`request_ns` 和 `request_deadline_ns`，使用
`scx_bpf_dsq_insert_vtime` 排队。实际服务通过 Linux task weight 换算为 virtual service，
因此 nice 权重仍参与同 class 公平性。

新任务和睡眠唤醒最多获得一个 request 的负 lag。class 转换把 source lag 限制在 source 和 target
各自一个 request 内，不能通过改 class 清零历史服务。

Balanced-only 时 `specialized_tasks == 0`，dispatch 直接移动本 CPU Balanced DSQ，跳过三类 root
选择。这是当前恢复 Balanced 基线的低开销路径。

### 5.3 per-CPU root EEVDF

存在专用类时，每 CPU 维护：

~~~text
root_virtual_time_ns
root_vruntime_ns[Latency, Balanced, Throughput]
~~~

活跃 class 的 deadline 为 `root_vruntime + class_request`。先选择 eligible 中最早 deadline；没有
eligible entity 时把 virtual time 前移到最小 vruntime。重新活跃的 class 最多保留一个 request
的 credit。

Latency backlog 超过一个任务时，root request 从 250 us 临时缩短为 227,273 ns；积压消失后恢复。
该加权有界，仍对 root vruntime 计费。

### 5.4 select_cpu

Balanced 和 Throughput 使用 sched_ext 的默认 CPU selector；Throughput 在 previous CPU 空闲且合法时
优先原地复用。全忙时不在 BPF 中逐 CPU 累加精确队列长度，避免热路径开销和 verifier 状态爆炸。

Latency 顺序为：

1. 原子取得 previous CPU 上空闲 SMT sibling；
2. 取得任意允许的空闲 CPU；
3. previous CPU 正在运行 Latency 且本地无 Latency 排队时，保留 previous CPU 但不抢占；
4. 否则优先可抢占的 previous CPU，再选 Throughput victim，最后选 Balanced victim；
5. 所有分支都不跨越实时 `p->cpus_ptr`。

空闲目标没有 local/class 积压时，Latency 在 select_cpu 直接插入 local DSQ，省去后续 dispatch。

```text
                    select_cpu
                        │
       ┌────────────────┼────────────────┐
       ▼                ▼                ▼
   Latency             Balanced          Throughput
       │                │                │
 idle SMT sibling     kernel default     previous CPU idle？
       │             selector             │
 any idle CPU             │          yes ──▶ previous CPU
       │               allowed fallback    └─ no ─▶ kernel default
 previous Latency CPU or non-Latency victim
       │
 allowed fallback

所有分支最终都必须在当下 p->cpus_ptr 中。
```

### 5.5 Latency 抢占

只有以下条件全部成立才设置 urgent sentinel 并 `SCX_KICK_PREEMPT`：

- victim 是 Balanced 或 Throughput，不是 Latency；
- victim 已运行至少 250 us；
- 同 CPU 距上次抢占至少 2.5 ms；
- urgent sentinel 当前为空；
- Latency root entity 没有领先超过一个 request；
- CPU 在线、非 idle 且 affinity 允许。

这限制了 IPI、短任务打断和连续抢占造成的吞吐退化。

### 5.6 Throughput epoch

Throughput 从 8 ms 开始，在无竞争、持续 runnable 时增长：

~~~text
8 ms -> 16 ms -> 32 ms -> 64 ms
~~~

阻塞、cancel、exec、class 变化或出现其他 class 排队都会恢复 8 ms。提前打断且剩余 request 至少
250 us 时保留剩余服务与原 deadline。

Locked Throughput 在本地和全局都没有竞争时可以续接 prev，不经过完整 dequeue/dispatch cycle；
每次续接仍更新 task/class/root virtual time，且上限保持 64 ms。

### 5.7 有界 steal

本 CPU 没有任务时才尝试 remote steal：

- 全局 custom-DSQ 计数为零时直接跳过；
- 每次最多扫描 8 个 source CPU；
- 起点由 per-CPU cursor 轮转；
- source 使用原子 claim，避免多个 destination 同时搬运；
- 一次 dispatch 最多搬运一个 task；
- 离线 source 可直接搬运；空闲 source 在队列不超过 2 时保留本地工作；
- 正在运行非 Latency 任务的 source 可借出后继任务。

Latency overflow 头部最多扫描 8 项。所有 BPF 循环由常量或 `num_possible_cpus <= 1024` 限界。

### 5.8 dispatch 总决策图

```text
adaptive_dispatch(cpu, prev)
        │
        ├─ urgent sentinel 已置位？
        │       └─是─▶ 先移入一个 Latency task ─▶ return
        │
        ├─ specialized_tasks == 0？
        │       └─是─▶ 直接搬本 CPU Balanced DSQ
        │                    └─空─▶ 最多扫描 8 个 CPU steal ─▶ return
        │
        └─ mixed-class
                │
                ├─ per-CPU root EEVDF 选 class
                │       ├─成功─▶ 搬一个 task ─▶ return
                │       └─失败─▶ 排除该 class，最多重试三类
                │
                ├─ Locked Throughput prev 且全局无等待？
                │       └─是─▶ 续接 8/16/32/64 ms epoch ─▶ return
                │
                └─ 最多扫描 8 个 CPU steal
```

## 6. Rust 控制面与行为观测

```text
BPF ringbuf
   │
   ├─ INIT / EXEC / EXIT ──▶ 稳定身份与 lifecycle notice
   │
   └─ ENQUEUE / RUNNING / STOP / CANCEL
                    │
                    ▼
            BehaviorAccumulator
                    │ 1 s snapshot
                    ├─ 序列/时间完整 ─▶ Good window ─▶ Agent 可投票
                    └─ 溢出/缺口/矛盾 ─▶ Bad window  ─▶ Agent 必须丢弃
```

`SchedulerEngine` 只保存：

- process default 和 task class/stage/generation；
- TaskKey/ProcessKey 生命周期和反向索引；
- 最近 enqueue/running 状态；
- 每任务一秒行为累计窗口；
- stale、capacity、bad-window 和 degraded 计数。

它不保存 runnable heap、root EEVDF、CPU placement、reservation、preemption budget 或 dispatch ID。

Inherited/Semantic task 的每组采样包含 ENQUEUE、RUNNING、STOP/CANCEL。窗口输出 runtime、runnable
wait、sleep、run burst、slice exhaustion、voluntary block、migration 和 previous-CPU hit。时间倒退、
顺序冲突或 ring overflow 会把窗口标为 Bad，Agent 不用 Bad 窗口锁定分类。

INIT、EXEC 和 EXIT 使用强制 ring wakeup；高频行为事件不强制唤醒，Rust 最多每 1 ms poll 一次。

## 7. ABI v8 与 maps

`rust/bpf/intf.h` 是唯一二进制契约。结构变化必须提升 ABI version 并同步 static_assert、bindgen、
Rust decoder、collector 和测试。

```text
                       写者                 读者
task_ctx_stor          BPF task callbacks       BPF
process_ctx            BPF lifecycle            BPF
task_events            BPF                      Rust ring consumer
task_control           Rust control transaction BPF select/enqueue/continue
class_state            BPF                      BPF task EEVDF
cpu_state              BPF                      BPF root/idle/steal/preempt
global_stats           each BPF CPU             Rust aggregate/Agent Tool
```

| 结构 | 大小 |
| --- | ---: |
| task_event | 88 bytes |
| task_control_value | 40 bytes |
| adaptive_cpu_state | 80 bytes |
| adaptive_global_stats | 152 bytes |

Event kind 只有 INIT=1、EXEC=2、ENQUEUE=3、CANCEL=4、RUNNING=5、STOP=6、EXIT=7。
Event flag 只有 RUNNABLE 和 WAKEUP。不存在 command queue、COMMAND_REJECT、CPU_STATE event 或 heartbeat map。

| Map | 类型 | 容量/大小 | 用途 |
| --- | --- | ---: | --- |
| task_ctx_stor | TASK_STORAGE | task lifetime | BPF 调度状态 |
| process_ctx | HASH | 32,768 | process cookie/exec generation |
| task_events | RINGBUF | 2 MiB | 生命周期与采样行为 |
| task_control | HASH | 65,536 | class/generation/observe flags |
| class_state | ARRAY | 3 | class global virtual time |
| cpu_state | ARRAY | 1,024 | idle/root/steal/urgent 状态 |
| global_stats | PERCPU_ARRAY | 每 CPU 1 项 | 无共享写竞争诊断 |

## 8. 默认配置

| 配置 | 默认值 |
| --- | ---: |
| latency_slice_ns | 250,000 |
| balanced_slice_ns | 4,000,000 |
| throughput_slice_ns | 8,000,000 |
| min_slice_ns | 250,000 |
| max_slice_ns | 64,000,000 |
| preemption_min_runtime_ns | 250,000 |
| latency_guarantee_percent | 10 |
| preemption_budget_percent | 10 |
| poll_interval | 1 ms |
| max_tasks | 65,536 |
| control_queue_capacity | 1,024 |
| max_control_frame_bytes | 1 MiB |
| max_snapshot_items | 256 |
| response_cache_capacity | 4,096 |
| agent_exit_grace | 2 s |

BPF 内部扫描上限为 8 个 source CPU 和 8 个 Latency task；struct_ops dispatch batch 上限为 64。

## 9. 诊断指标

Rust 控制面：

- `events_processed`、`stale_events`；
- `task_capacity_hits`、`bad_behavior_windows`、`degraded_transitions`。

BPF 数据面：

- `fast_path_enqueues`、`fast_path_dispatches` 和按 class dispatch；
- local、remote steal、claim conflict、empty-steal skip；
- direct dispatch、Throughput continuation；
- Latency preemption、throttle、backlog boost；
- event overflow、fallback、dispatch failure、suppressed events。

`fallback_dispatches` 包含保护路径，不能单独视为故障。正式 run 必须要求 event overflow、capacity hit
和 degraded transition 为零，并结合 sched_ext admission 观测确认普通任务为 1、受保护角色为 0。

## 10. 当前性能证据

2026-07-27 最近一次有效 Balanced 单轮基线：

| 场景 | Native | Agent | Agent 相对 Native |
| --- | ---: | ---: | ---: |
| balanced | 38,189.196 units/s | 35,445.303 units/s | -7.18% |

该单轮结果已覆盖当前控制面瘦身、partial admission 和 BPF verifier 修复，只证明仍有 Balanced 差距，
不构成正式统计结论。随后把全局队列计数改为 per-CPU 计数的候选得到 Native 38,368.251、Agent
35,291.914（-8.02%），IPC、cache miss 和控制面 CPU 均未改善，因此已完整撤销。旧 Latency、
Throughput、Mix 结果来自更早算法，不能代表当前源码。

候选保留门槛：

1. verifier/load、安全 admission、Agent detach 全部通过；
2. Native/Agent 同 repeat 配对且两边 run 均有效；
3. Balanced 单轮先明显改善当前保留实现的 -7.18% 差距，再用三轮置信区间确认；
4. Latency、Throughput 和 Mix 必须重新测试，不能用 Balanced 结果外推；
5. event overflow、capacity、degraded、分类覆盖和 generation 应用无回归；
6. 任何应用名称都不能进入 scheduler policy。

最终目标是多场景、多 CPU 拓扑上的统计改善，不承诺任意硬件和负载必然优于内核。

## 11. 源码导航

| 文件 | 职责 |
| --- | --- |
| rust/bpf/intf.h | ABI v8 event/control/stats |
| rust/bpf/scx_adaptive.bpf.c | 唯一调度数据面 |
| rust/src/main.rs | attach、控制事务、主循环、detach |
| rust/src/bpf.rs | skeleton、map/ring I/O、PERCPU 聚合 |
| rust/src/wire.rs | event 解码和 task_control 转换 |
| rust/src/engine.rs | 身份、分类 cache、行为窗口 |
| rust/src/process.rs | class stage/generation |
| rust/src/control.rs | 有界 Unix socket 协议 |
| rust/src/topology.rs | possible/online CPU |
| rust/src/stats.rs | 控制面计数与行为结构 |
| rust/build.rs | scx_cargo 构建、BPF skeleton 和 bindgen 生成入口 |
| rust/tools/bpf-clang | 有界选择 Clang 20..16 的本地构建包装器 |

sched_ext 构建和加载兼容层来自 `Cargo.lock` 精确校验的官方
`scx_cargo`、`scx_utils` crate，不提供或承载本项目调度策略。

## 12. 必须保持的不变量

1. 只有明确准入的普通 SCHED_OTHER task 进入 sched_ext。
2. PID 1、kernel、Agent、scheduler 和 RT/DL task 保持原生。
3. control 缺失或失配必须立即落到 Balanced，不等待 Rust。
4. Latency victim 只能是 Balanced 或 Throughput。
5. Throughput continuation 必须在出现竞争时停止。
6. 所有 slice 保持在 250 us..64 ms。
7. class 变化保留有界 lag，不能清零服务历史。
8. 所有 BPF 扫描和 map 都有静态上界。
9. 控制更新必须 BPF-first 且可回滚。
10. Bad 行为窗口不能用于锁定分类。
11. ABI 变化必须同步所有生成物、消费者和测试。
12. 单轮结果只能筛选候选，正式结论必须使用重复配对与置信区间。

## 13. 构建与基准

以 `scheduler/rust` 为工作目录：

~~~bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
target/release/scx_adaptive --validate-only
~~~

以仓库根目录为工作目录：

~~~bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/tests -v
python3 test/scripts/benchmark.py all --dry-run
~~~

~~~bash
python3 test/scripts/benchmark.py balanced --single-round
python3 test/scripts/benchmark.py balanced
python3 test/scripts/benchmark.py all
~~~
