# scx_adaptive Scheduler

本目录实现项目自研的 sched_ext scheduler。Agent 只提交 Latency、Balanced、Throughput 分类和
generation；scheduler 负责内核调度、故障回退和诊断。

当前实现采用双路径：

~~~text
有效 task_control
      |
      v
BPF 快路径
  per-CPU/class virtual-deadline DSQ
  per-CPU root EEVDF
  latency direct dispatch / bounded preemption
  throughput bounded epoch / continuation
  bounded rotating steal

control 缺失或 generation 失配
      |
      v
Rust 慢路径
  task EEVDF -> root EEVDF -> topology placement
  reservation -> BPF final validation
~~~

完整算法、状态、ABI 和安全不变量见 [Design.md](Design.md)。

## 性能路径

- 已分类任务在 BPF 中直接调度，不为每个 runnable 周期等待 Rust；
- Latency 优先原子取得空闲 CPU，无本地积压时直接进入 local DSQ；
- Throughput 从 8 ms 开始，在无竞争时按 8/16/32/64 ms 有界增长；
- Locked task 关闭逐任务观测事件，CPU_STATE 事件最多每 1 ms 发布一次；
- global_stats 使用 PERCPU_ARRAY，Rust 读取时聚合；
- 本地无任务时最多扫描 8 个 source CPU，并用 source claim 串行化 steal。

任何本地竞争都会终止 Throughput continuation。Latency 只允许抢占 Balanced/Throughput，
不允许抢占 Latency。

## 安全边界

以下任务不进入自定义 class、放置或抢占逻辑：

- PF_KTHREAD；
- scheduler 所在 TGID；
- Agent 所在 TGID。

它们直接进入 sched_ext GLOBAL DSQ。GLOBAL 不等同于 CFS，但不执行本项目的 class policy。
Linux RT/DL 调度类仍由内核原生高优先级调度类处理。

未分类慢路径的 heartbeat 超过 250 ms 时，当前任务进入 GLOBAL，并触发一次受控 sched_ext
ejection。event overflow、容量不变量失败、Agent 退出或进程信号也会导致受控 detach。

## 目录

~~~text
scheduler/
├── Design.md                     当前实现的完整设计
├── README.md                     本页
├── versions.lock                 上游依赖版本锁
├── rust/
│   ├── bpf/
│   │   ├── intf.h                ABI v6
│   │   └── scx_adaptive.bpf.c    callbacks 与 BPF 快路径
│   ├── src/
│   │   ├── main.rs               attach、主循环、控制事务
│   │   ├── engine.rs             生命周期与 Rust 慢路径
│   │   ├── eevdf.rs              root EEVDF
│   │   ├── pool/mod.rs           task EEVDF pools
│   │   ├── placement.rs          topology/SMT 放置
│   │   ├── admission.rs          SLO 与抢占预算
│   │   ├── bpf.rs                skeleton、maps、stats 聚合
│   │   ├── wire.rs               ABI 转换
│   │   ├── process.rs            class stage/generation
│   │   ├── control.rs            Agent socket
│   │   └── stats.rs              诊断与行为窗口
│   └── README.md
└── scx/                           锁定的上游兼容依赖
~~~

scheduler/scx 不承载本项目调度策略。

## 构建与检查

在仓库根目录执行：

~~~bash
cargo fmt --manifest-path scheduler/rust/Cargo.toml --all -- --check
cargo build --manifest-path scheduler/rust/Cargo.toml --release --locked
cargo clippy --manifest-path scheduler/rust/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path scheduler/rust/Cargo.toml --locked
scheduler/rust/target/release/scx_adaptive --validate-only
python3 -m unittest discover -s test/tests -v
~~~

基准入口：

~~~bash
python3 test/scripts/benchmark.py --single-round
python3 test/scripts/benchmark.py
~~~

单轮用于迭代，默认三轮 paired campaign 才用于正式结论。测试说明见
[test/README.md](../test/README.md)，Agent 说明见
[Adaptive-OS-Agent/README.md](../Adaptive-OS-Agent/README.md)。
