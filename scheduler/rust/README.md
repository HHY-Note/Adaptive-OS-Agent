# scx_adaptive Rust 子工程

本目录同时包含 scheduler 的 Rust 控制面和 BPF 数据面。Rust 负责加载、身份、控制事务、
拓扑 policy、诊断与 detach；所有 runnable 调度决策都由 scx_adaptive.bpf.c 完成。

~~~text
Adaptive OS Agent
       |
       | protocol v1: Hello / snapshot / CAS action
       v
control.rs -> main.rs -> engine.rs -> bpf.rs -> task_control
                 |
                 +-> topology.rs -> policy.rs -> 双槽 policy maps
                 |
                 +<- ring buffer <- scx_adaptive.bpf.c
~~~

## 模块职责

| 文件 | 当前职责 |
| --- | --- |
| src/main.rs | attach、4 ms 事件循环、控制请求、Agent watchdog、detach |
| src/control.rs | 有界 Unix socket、长度帧、协议 v1、幂等响应 |
| src/engine.rs | ProcessKey/TaskKey、分类 cache、行为窗口和容量状态 |
| src/process.rs | Inherited/Semantic/Locked 状态转移与 generation |
| src/policy.rs | topology/feedback policy、500 ms refresh、2 s lease |
| src/topology.rs | possible/online CPU、core/SMT/LLC/NUMA/package/capacity |
| src/bpf.rs | skeleton、rodata、map 更新、per-CPU stats 聚合 |
| src/stats.rs | 一秒行为窗口和用户态计数 |
| src/wire.rs | v35 BPF event 转换与 ABI 校验 |
| bpf/intf.h | Rust/BPF 唯一二进制 ABI，当前版本 v35 |
| bpf/scx_adaptive.bpf.c | 唯一 runnable 调度数据面 |

Rust 不持有 global 或 per-CPU runnable queue，也不发送 dispatch 命令。

## 控制与恢复

scheduler 每次启动生成非零 epoch。Agent 连接后先发送 Hello，scheduler 回放当前
process/task 生命周期；Agent 再发送按序 RegistrySnapshotBatch。最终批次 ACK 前，
增量 SetProcessDefault、SetTaskProvisional 和 LockTaskClass 会被拒绝，但 BPF 仍可按
Balanced 默认类调度。

增量分类满足：

~~~text
current_generation == expected_generation
new_generation     == expected_generation + 1
~~~

Rust 先写 task_control map，再提交 Engine cache；后一步失败则恢复旧 map value。控制
帧最大 1 MiB，queue 1,024，单 snapshot 批次最多 256 项，成功响应 cache 4,096 条。

## 动态 policy

PolicyController 维护两份完整 CPU policy slot。发布时先写 inactive slot 的全部 CPU，
最后原子切换 policy_control；BPF 只接受 generation 匹配且 lease 未过期的快照。

- lease：2 s；
- refresh：500 ms；
- 每 CPU：2 个 Latency candidate、2 个 Normal candidate；
- 输入：class runtime/dispatch/preemption、budget charge 和每 CPU pressure；
- 输出：placement、Latency budget/cadence/successor lease、Balanced 抢占粒度、
  cross-domain cost。

policy 失效时 BPF 使用 attach 时写入 rodata 的不可变默认值。

## BPF ABI 与队列

ABI v35 固定 task_event、task_control_value、policy control、CPU policy、CPU state
和 per-CPU stats 的字段与结构大小。核心 maps：

| map | 类型 | 作用 |
| --- | --- | --- |
| task_ctx_stor | TASK_STORAGE | task cookie、vruntime、request、enqueue sequence |
| process_ctx | HASH，32,768 | process cookie 与 exec generation |
| task_control | HASH，65,536 | class、stage flags、identity、generation |
| task_events | RINGBUF，2 MiB | lifecycle 与有界行为采样 |
| policy_control | ARRAY，1 | 当前 generation、slot、lease |
| cpu_policy | ARRAY，2 x 1,024 | 双槽 topology 与 candidate |
| cpu_state | ARRAY，1,024 | online/idle、budget、queue、runtime |
| core_latency_state | ARRAY，1,024 | per-core Latency shard 状态 |
| global_stats | PERCPU_ARRAY | 热路径诊断计数 |

每 CPU 建立 latency_dsq 和合并的 task_dsq；共享通道只有 per-core Latency shard 与
per-domain Balanced overflow。

## 默认参数

| 参数 | 默认值 |
| --- | ---: |
| Latency request | 250 us |
| Balanced request | 4 ms |
| Throughput base request | 8 ms |
| request 上下界 | 250 us / 64 ms |
| Latency budget | 20% |
| event poll | 4 ms |
| max live task | 65,536 |
| Agent grace | 2 s |

## 构建

本目录的 .cargo/config.toml 把 BPF 编译器指向 tools/bpf-clang。正式基线是
Rust 1.96、Clang/LLVM 17，完整版本见 ../versions.lock。

~~~bash
cd scheduler/rust
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
target/release/scx_adaptive --validate-only
~~~

正常运行由 Adaptive OS Agent 传入 --agent-pid 与 --control-socket。完整算法和安全
不变量见 [scheduler/Design.md](../Design.md)。
