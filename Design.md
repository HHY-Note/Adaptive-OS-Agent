# Adaptive OS Agent 跨组件设计

本文从全局说明语义分类如何变成一次安全的 Linux 调度决策。组件内部细节见：

- [`Adaptive-OS-Agent/Design.md`](Adaptive-OS-Agent/Design.md)：发现、LLM、Registry 和控制一致性；
- [`scheduler/Design.md`](scheduler/Design.md)：三类调度、CPU placement、reservation 和 BPF；
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
  │                  │─────────────────────────▶│ Rust SchedulerEngine │
  │ eBPF data plane  │                          │                      │
  │                  │◀─────────────────────────│ pool + fairness      │
  └────────┬─────────┘    dispatch proposal     │ placement + reserve  │
           │                                    └──────────────────────┘
           │ 内核实时校验
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

LLM 不进入 dispatch 热路径。新 task 不等待分类，立即使用 `Balanced`。

## 2. 模块边界

```text
┌──────────────────────┐
│ Adaptive-OS-Agent    │  拥有语义和分类状态
│                      │
│ discovery / LLM      │  不选择 runnable task
│ Registry / Tool      │  不选择 CPU 和 slice
└──────────┬───────────┘
           │ control socket
           ▼
┌──────────────────────┐
│ Rust scheduler       │  拥有调度策略状态
│                      │
│ task state / pools   │  不扫描 /proc
│ fairness / placement │  不调用 LLM
└──────────┬───────────┘
           │ fixed ABI queues + maps
           ▼
┌──────────────────────┐
│ eBPF data plane      │  拥有内核实时事实
│                      │
│ cookie / affinity    │  不实现复杂策略
│ validation / DSQ     │  不执行远端 I/O
└──────────────────────┘
```

| 组件 | 权威状态 | 主要输出 |
| --- | --- | --- |
| Agent | process/task 语义、stage、desired/applied generation | 分类 action、Registry snapshot |
| Rust scheduler | task 生命周期、三类 pool、公平账本、CPU、reservation | dispatch proposal、行为窗口 |
| eBPF | cookie、enqueue sequence、实时 CPU/affinity、DSQ 状态 | 生命周期事件、accept/reject |
| test | `RunSpec`、VM 生命周期、原始数据、有效性 | Native/Agent 配对报告 |

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
│ TaskKey + enqueue_sequence   │  防旧 dispatch 命中新一轮 runnable
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
           │ 生成 lazy node
           ▼
┌─────────────────────┐
│ PoolNode            │  task + enqueue_sequence
│                     │  class + class_generation
└──────────┬──────────┘
           │ 选择 task 和 CPU
           ▼
┌─────────────────────┐
│ Reservation         │  dispatch_id + target_cpu
│                     │  planned_slice + class
└──────────┬──────────┘
           │ 序列化
           ▼
┌─────────────────────┐
│ dispatch_command    │  BPF 再核对全部身份和 generation
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
   │◀── process/task replay ──────│◀── live identities ─ │                       │
   │◀── replay complete ──────────│                      │                       │
   │── Registry snapshot 0..N ───▶│── mirror generation▶ │                       │
   │◀── final snapshot ACK ───────│                      │                       │
   │                              │                      │◀── INIT / ENQUEUE ────│
   │                              │◀── event + cookie ───│                       │
   │                              │   pool/root EEVDF/CPU│                       │
   │                              │── dispatch proposal ▶│                       │
   │                              │                      │── live validation     │
   │                              │                      │── local DSQ ─────────▶│
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
   EEVDF 1 ms          EEVDF 4 ms          EEVDF 8 ms
  short deadline       medium deadline      long deadline
  delay-sensitive CPU  balanced CPU         locality-first CPU
```

三个 pool 内部复用同一个 EEVDF；跨 pool 再运行一层等权 Root EEVDF：

```text
effective_vruntime = actual_service + reserved_runtime
eligible pool       = effective_vruntime <= root_virtual_time
selection           = earliest virtual deadline
```

空 pool 自动借出容量，重新活跃时最多保留一个 request 的 lag。max-wait watchdog 只处理异常饥饿。

### 5.2 Task 分类阶段

```text
                            thread LLM
                    ┌────────────────────────┐
                    │                        ▼
┌──────────────┐    │                 ┌──────────────┐
│ Inherited    │────┘                 │ Semantic     │
│ process 默认  │                      │ 可修正一次    │
└──────┬───────┘                      └──────┬───────┘
       │ behavior 直接定案                   │ behavior 确认/修正
       └──────────────────┬──────────────────┘
                          ▼
                   ┌──────────────┐
                   │ Locked       │
                   │ 最终，不再改   │
                   └──────────────┘
```

模型 `Unknown`、低置信度或请求失败只影响语义覆盖率，不会生成无法验证的更新。

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

## 6. Dispatch 的最后一道校验

```text
┌──────────────────────┐
│ Rust proposal        │
│ task/process cookie  │
│ exec/enqueue/class   │
│ target CPU + slice   │
└──────────┬───────────┘
           ▼
┌──────────────────────────────────────────────────────────────┐
│ BPF 最终校验                                                  │
│ 1. task 仍存在且 cookie / exec generation 相同                 │
│ 2. task 仍是本 enqueue_sequence 的 pending runnable           │
│ 3. task_control 中 class_generation 相同                      │
│ 4. CPU online 且实时 cpus_ptr 允许                             │
│ 5. 非 migration-disabled 冲突                                 │
│ 6. slice 在边界内，staged slot 可被原子占用                      │
└───────────────────────┬──────────────────────┬───────────────┘
                        │ accept               │ reject
                        ▼                      ▼
                target CPU local DSQ   Rust rollback / requeue
```

因此 task exit、CPU hotplug、affinity 修改、migration-disabled 和分类更新不需要跨用户态/
内核的全局锁。

## 7. 故障与恢复

```text
LLM 失败 ───────────────────────▶ 保持 Balanced / 当前 class
control 断开 ───────────────────▶ 丢弃旧 epoch 响应，重连后 replay + snapshot
scheduler 退出 ─────────────────▶ Agent 在 60 s 窗口内最多重启 3 次
BPF event 短时溢出 ─────────────▶ 当前 task fallback，行为窗口标记 Bad
连续溢出 / 容量不可恢复 ────────▶ scheduler degraded，受控 detach
heartbeat 过期 / Agent 消失 ────▶ kernel fallback，随后 sched_ext detach
```

```text
新 scheduler epoch
       │
       ▼
生命周期回放 ──▶ replay complete ──▶ Registry snapshot ──▶ 恢复增量 action
```

Agent 与 userspace scheduler 自身位于 BPF safe path，不依赖普通用户态调度决策才能获得 CPU。

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
│ schema/state/ACK│    │ pools/BPF/control│    │ Native vs Agent pair │
└─────────────────┘    └──────────────────┘    └──────────────────────┘
```

正式性能结论只使用同一 `scenario/repeat` 的有效 Native/Agent 配对。分类快照报告覆盖率、
正确率和 generation 应用率，但分类内容本身不作为性能 run 有效性门禁。
