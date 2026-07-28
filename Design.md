# Adaptive OS Agent 跨组件设计

本文从全局说明语义分类如何变成一次安全的 Linux 调度决策。组件内部细节见：

- [`Adaptive-OS-Agent/Design.md`](Adaptive-OS-Agent/Design.md)：发现、LLM、Registry 和控制一致性；
- [`scheduler/Design.md`](scheduler/Design.md)：partial admission、三类 BPF 调度和 Rust 控制面；
- [`test/Design.md`](test/Design.md)：VM 实验、负载、采集、有效性和统计。

## 1. 系统总图

```text
                         低频语义平面：秒级

  ┌──────────────┐    ┌──────────────────┐     ┌──────────────────┐
  │ Linux /proc  │───▶│ 发现、限长、脱敏    │───▶ │                  │
  └──────────────┘    └──────────────────┘     │ Classification   │
                                               │ Registry         │
  ┌──────────────┐    bounded batch/proposal   │                  │
  │ DeepSeek     │◀───────────────────────────▶│ process + task   │
  │ v4-flash     │                             │ class state      │
  └──────────────┘                             └────────┬─────────┘
                                                        │ class action
                                                        │ identity + generation
                                                        ▼
                         高频策略平面：微秒～毫秒级

  ┌──────────────────┐   lifecycle / behavior   ┌──────────────────────┐
  │                  │─────────────────────────▶│ Rust control plane   │
  │ eBPF data plane  │                          │ identity + class tx  │
  │                  │◀─────────────────────────│ observation + detach │
  └────────┬─────────┘      task_control map    └──────────────────────┘
           │ CPU / EEVDF / DSQ
           ▼
  ┌──────────────────┐          ┌────────────────────────────────────┐
  │ local / fallback │─────────▶│ Linux runnable tasks               │
  │ DSQ              │          │ Latency / Balanced / Throughput    │
  └──────────────────┘          └────────────────────────────────────┘

                         只读实验与观测平面

  ┌──────────────────────────────────────────────────────────────────┐
  │ test harness ── Tool / proc / perf ──▶ raw data ──▶ paired report│
  └──────────────────────────────────────────────────────────────────┘
```

核心思路是把两个时间尺度拆开：

```text
“这个任务是什么？”                               “现在应该怎样运行它？”
        │                                             │
        ▼                                             ▼
┌──────────────────┐                         ┌────────────────────┐
│ Agent + LLM      │                         │ Rust + eBPF        │
│ 秒级、可失败       │─── class / generation ─▶│ 本地、有界、可校验    │
└──────────────────┘                         └────────────────────┘
        │                                             │
        └── 失败时保持 Balanced ──────────────────────┘
```

LLM 不进入 dispatch 热路径。新 task 不等待分类，立即使用 `Balanced` 或已知 process default。

## 2. 模块边界

```text
┌──────────────────────┐
│ Adaptive-OS-Agent    │  拥有准入、语义和分类状态
│                      │
│ discovery/admission  │  不选择 runnable task
│ LLM / Registry / Tool│  不选择 CPU 和 slice
└──────────┬───────────┘
           │ control socket
           ▼
┌──────────────────────┐
│ Rust scheduler       │  拥有控制与观测状态
│                      │
│ identity / class tx  │  不保存 runnable queue
│ behavior / recovery  │  不选择 CPU 或 dispatch
└──────────┬───────────┘
           │ fixed ABI queues + maps
           ▼
┌──────────────────────┐
│ eBPF data plane      │  拥有实时调度状态
│                      │
│ CPU / virtual time   │  不扫描 /proc
│ DSQ / steal / preempt│  不执行远端 I/O
└──────────────────────┘
```

| 组件 | 权威状态 | 主要输出 |
| --- | --- | --- |
| Agent | 普通任务准入、process/task 语义、stage、desired/applied generation | `sched_setscheduler(SCHED_EXT)`、分类 action、Registry snapshot |
| Rust scheduler | task 生命周期、分类镜像、generation、行为窗口 | `task_control` 更新、生命周期 replay、健康快照 |
| eBPF | cookie、enqueue sequence、CPU/affinity、virtual time、DSQ | 调度决策、生命周期与采样行为事件 |
| test | `RunSpec`、VM 生命周期、原始数据、有效性 | Native/Agent 配对报告 |

### 2.1 哪些任务进入 scx_adaptive

```text
Linux task
   │
   ├─ PID 1 / kernel thread / Agent / scheduler ────▶ Linux 原生
   ├─ RT / DL / 其他非 SCHED_OTHER 策略 ───▶ Linux 原生
   └─ ordinary SCHED_OTHER
             │ Agent 核对 process+task lifetime
             ▼
          SCHED_EXT ─▶ scx_adaptive
```

Agent 不需要用户为每个线程手工写名单：它通过 `/proc` 周期 reconciliation 和 scheduler
INIT/EXEC 生命周期通知发现普通任务，动态新线程在后续扫描/事件中补齐。

每份状态只有一个 writer。Agent 收到匹配 ACK 后才推进 `applied_generation`；scheduler
把 generation 写入 BPF 成功后才提交 Rust class cache。

## 3. 核心身份与数据结构

### 3.1 身份逐层收紧

```text
┌──────────────────────────────┐
│ ProcessInstanceKey           │  /proc 扫描阶段
│ tgid + start_time_ticks      │  防 PID 复用
└──────────────┬───────────────┘
               │ scheduler 生命周期事件完成绑定
               ▼
┌──────────────────────────────┐
│ ProcessKey                   │  一个进程镜像
│ tgid + process_cookie        │
│      + exec_generation       │  防 PID 复用和 exec
└──────────────┬───────────────┘
               │ 1 process : N tasks
               ▼
┌──────────────────────────────┐
│ TaskKey                      │  一个线程生命周期
│ tid + task_cookie            │  防 TID 复用
└──────────────┬───────────────┘
               │ 每次 ENQUEUE 递增
               ▼
┌──────────────────────────────┐
│ RunnableKey                  │  一次 runnable 实例
│ TaskKey + enqueue_sequence   │  关联一组采样行为事件
└──────────────────────────────┘
```

两个额外版本号保护跨组件状态：

```text
scheduler_epoch    = scheduler 进程实例版本；重启后旧请求/ACK 全部失效
class_generation   = 精确 process/task 的分类版本；new 必须等于 expected + 1
```

### 3.2 数据从 Agent 走到内核

```text
┌─────────────────────┐
│ ProcessRecord       │
│ TaskRecord          │  Agent 权威分类
└──────────┬──────────┘
           │ RegistryAction
           │ identity + class + stage + generation
           ▼
┌─────────────────────┐
│ ProcessDefaultCache │
│ TaskClassCache      │  scheduler 分类镜像
└──────────┬──────────┘
           │ 原子分类事务
           ▼
┌─────────────────────┐
│ task_control map    │  identity + class + stage
│                     │  generation + observe flags
└──────────┬──────────┘
           │ enqueue 时校验；失配即 Balanced
           ▼
┌─────────────────────┐
│ BPF task context    │  vruntime + request + deadline
│ per-CPU class DSQ   │  CPU-owned EEVDF queues
└─────────────────────┘
```

这条链路中不存在“只凭 PID/TID 修改调度状态”的操作。

## 4. 启动到首次 dispatch

```text
 Agent                     Rust scheduler             eBPF                 Linux task
   │                              │                      │                       │
   │── spawn scx_adaptive ───────▶│                      │                       │
   │                              │── load + attach ────▶│                       │
   │                              │   new epoch          │                       │
   │── Hello ────────────────────▶│                      │                       │
   │── /proc scan + ordinary admission ─────────────────────────────────────────────▶│
   │◀── process/task replay ──────│◀── live identities ─ │                       │
   │◀── replay complete ──────────│                      │                       │
   │── Registry snapshot 0..N ───▶│── mirror generation▶ │                       │
   │◀── final snapshot ACK ───────│                      │                       │
   │                              │                      │◀── INIT / ENQUEUE ────│
   │                              │◀── event + cookie ───│                       │
   │                              │                      │   select CPU/class    │
   │                              │                      │   EEVDF + local DSQ ─▶│
   │                              │◀── RUNNING / STOP ───│                       │
```

snapshot 未完成前，scheduler 拒绝增量分类更新；task 仍可按 `Balanced` 调度。首次
dispatch 与 LLM 是否完成无关。

## 5. 分类如何改变调度

### 5.1 三类策略映射

```text
                      Agent 输出 class
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ Latency         │ │ Balanced        │ │ Throughput      │
│ short response  │ │ safe default    │ │ sustained CPU   │
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
         ▼                   ▼                   ▼
  EEVDF 250 us         EEVDF 4 ms          EEVDF 8 ms
  short deadline       medium deadline      long deadline
  delay-sensitive CPU  balanced CPU         locality-first CPU
```

每个 possible CPU 都有三个 class virtual-time DSQ。Balanced-only 时直接移动本 CPU 的
Balanced DSQ；出现专用类后，per-CPU Root EEVDF 在活跃 class 之间选择：

```text
CPU 0: [Latency DSQ] [Balanced DSQ] [Throughput DSQ] ─┐
CPU 1: [Latency DSQ] [Balanced DSQ] [Throughput DSQ] ─┤─▶ 各 CPU 本地 dispatch
 ...                                                    ─┘

global class_state[3]       = task-level virtual-time 基准，不存放 runnable task
per-CPU cpu_state[cpu]      = root virtual time / idle / steal / preempt
global Latency overflow DSQ = 一条有界的共享溢出通道
```

因此当前实现不是“三条全局任务队列”；只有 class virtual-time 基准、队列计数和
Latency overflow 是全局共享状态。

```text
eligible class = class_vruntime <= root_virtual_time
deadline       = class_vruntime + class_request
selection      = earliest eligible deadline
```

空 class 自动借出容量，重新活跃时最多保留一个 request 的 credit。task 内部使用带 Linux weight
换算的 virtual service；Throughput request 可在无竞争时从 8 ms 有界增长到 64 ms。

### 5.2 语义状态与 Task 提交阶段

```text
LLM 请求状态（Agent 内部）

Pending ─▶ Requested ─┬─▶ Classified(class, confidence)
                      ├─▶ Unknown
                      └─▶ Failed

Task 已提交阶段（Agent → scheduler → BPF）

Inherited ── 连续 good behavior window / timeout ──▶ Locked
    │                                                   │
    └─ 跟随 process default，仍可调度                    └─ 停止行为采样
```

当前 Agent 的正常 task 路径是 `Inherited -> Locked`。线程 LLM 只提供语义上下文，
不会单独把 task 提交为 `Semantic`；该阶段仍保留在协议和 scheduler 状态机中。
Locked 任务不再采样，但晚到的高置信专用语义与已锁定的另一专用类直接冲突时，
允许一次保守收敛到 `Balanced`。

模型 `Unknown`、低置信度或请求失败只影响语义覆盖率，不会阻塞调度。

### 5.3 Action 与 ACK

```text
┌───────────────────────────────────────────────────────────────┐
│ RegistryAction                                                │
│ stable identity | class | stage | request_id                  │
│ expected_generation | new_generation (= expected + 1)         │
└──────────────────────────────┬────────────────────────────────┘
                               ▼
           ┌──────────────────────────────────────┐
           │ scheduler 校验 epoch / identity / CAS│
           └───────────────────┬──────────────────┘
                               ▼
           ┌──────────────────────────────────────┐
           │ 先写 BPF task_control，再写 Rust cache│
           └──────────────┬───────────────┬───────┘
                          │ success       │ failure
                          ▼               ▼
                 ACK(new_generation)   rollback + reject
                          │               │
                          ▼               ▼
                 Agent 标记 applied     保留 desired，重新同步
```

## 6. BPF 热路径的有界决策

```text
┌──────────────────────────────────────────────────────────────┐
│ select_cpu                                                   │
│ 1. 从 Balanced 默认值开始，匹配 task_control 后覆盖 class        │
│ 2. 只在实时 p->cpus_ptr 内选择 previous / idle / victim CPU    │
│ 3. Latency 直接 local dispatch 和抢占均受预算限制                │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│ enqueue / dispatch                                           │
│ 1. 更新 task 和 class virtual service                         │
│ 2. 插入目标 CPU 的 class vtime DSQ                             │
│ 3. Balanced fast path 或 per-CPU Root EEVDF 选择 class        │
│ 4. 本地为空时至多扫描 8 个 CPU，一次至多 steal 一个 task           │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
                         CPU local DSQ
```

CPU online、实时 affinity 和 migration 状态都在 BPF 决策点读取；所有扫描和 map 都有静态上界。
每次 runnable 决策不跨用户态，因此控制面延迟不会形成调度闭环。

## 7. 故障与恢复

```text
LLM 失败 ───────────────────────▶ 保持 Balanced / 当前 class
control 断开 ───────────────────▶ 丢弃旧 epoch 响应，重连后 replay + snapshot
scheduler 退出 ─────────────────▶ Agent 在 60 s 窗口内最多重启 3 次
BPF event 短时溢出 ─────────────▶ 调度继续，行为窗口标记 Bad
连续溢出 / 容量不可恢复 ────────▶ scheduler degraded，受控 detach
Agent 身份消失超过 grace ───────▶ scheduler 受控 detach
```

```text
新 scheduler epoch
       │
       ▼
生命周期回放 ──▶ replay complete ──▶ Registry snapshot ──▶ 恢复增量 action
```

Agent 与 userspace scheduler 自身不准入 `SCHED_EXT`，始终由 Linux 原生调度器运行。

## 8. 控制、观测与安全

```text
┌────────────────────────────────────┐
│ Agent <-> scheduler control        │
│ 4-byte length + JSON envelope      │
│ version / type / request / epoch   │
│ payload_length / bounded payload   │
└────────────────────────────────────┘

┌────────────────────────────────────┐
│ Test -> Agent Tool                 │
│ workload / classification / health │
│ stats；只读，不改变运行状态            │
└────────────────────────────────────┘
```

- 密钥只来自环境变量或 `0600` 文件，不进入 prompt、日志或 snapshot；
- `/proc` 数据先限长和脱敏；
- LLM 只看到 batch 内短 ID，响应必须满足严格 JSON schema；
- Registry、task、queue、frame、snapshot 和 retry 都有固定上限。

## 9. 验证路径

```text
┌─────────────────┐    ┌──────────────────┐    ┌──────────────────────┐
│ Agent unit tests│───▶│ scheduler tests  │───▶│ 6 vCPU VM campaign   │
│ schema/state/ACK│    │ BPF/control/ABI  │    │ Native vs Agent pair │
└─────────────────┘    └──────────────────┘    └──────────────────────┘
```

正式性能结论只使用同一 `scenario/repeat` 的有效 Native/Agent 配对。分类快照报告覆盖率、
正确率和 generation 应用率，但分类内容本身不作为性能 run 有效性门禁。

## 10. 当前完成度与性能边界

```text
任务发现/准入       已实现 + 单元/虚拟机验证
LLM + 行为分类       已实现；已有场景分类里程碑
三类 BPF 调度         已实现
Balanced 性能           当前有效单轮仍比 Native 低 7.18%
Latency/Throughput/Mix   需在当前 scheduler 上重新执行三轮正式配对
```

因此当前文档中的调度策略是已实现事实，但“整体性能显著优于 Linux”仍是待验收目标，
不是已证明结论。具体原始基线和候选保留规则见
[`scheduler/Design.md`](scheduler/Design.md)。
