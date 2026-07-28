# scx_adaptive Scheduler

`scx_adaptive` 是项目自研的单一 sched_ext scheduler。Agent 负责识别
Latency、Balanced、Throughput 及其 generation；BPF 是普通任务唯一的调度数据面；Rust 只维护
分类事务、稳定身份、行为观测、诊断与可恢复生命周期。

```text
ordinary SCHED_OTHER task                 Agent class/stage/generation
          │                                         │
          ▼                                         ▼
 Agent partial admission                 Rust BPF-first transaction
          │                                         │
          ▼                                         ▼
 ┌────────────────────────────────────────────────────────────┐
 │ BPF: task_control lookup ─▶ select_cpu ─▶ per-CPU class DSQ│
 │      │                                    │                │
 │      └─ missing/mismatch ─▶ Balanced      └─ root EEVDF    │
 └───────────────────────────────────────────────┬────────────┘
                                                 ▼
                                           local DSQ / CPU
```

Rust 不选择 CPU、不保存 runnable queue，也不产生 dispatch 命令。

完整算法、ABI、安全边界和验收规则见 [Design.md](Design.md)。

## 性能路径

- task_control 缺失或失配时默认使用 Balanced，任务不等待用户态；
- 每个 possible CPU 各有 Latency/Balanced/Throughput 三条 DSQ，不是三条全局任务队列；
- Balanced-only 运行时跳过三类 root 选择，直接消费本 CPU Balanced DSQ；
- Latency 优先取得空闲 CPU，必要时按最小运行时间和速率限制抢占非 Latency；
- Throughput 从 8 ms 开始，无竞争时有界增长到 64 ms；
- 本 CPU 无任务时最多扫描 8 个 source CPU；
- Inherited/Semantic 行为事件采样，Locked 任务关闭调度事件；
- global_stats 使用 PERCPU_ARRAY，避免热路径共享统计 cache line。

## 安全边界

调度器使用 `SCX_OPS_SWITCH_PARTIAL`。Agent 只把普通 `SCHED_OTHER` 任务显式切换到
`SCHED_EXT`，以下任务保持 Linux 原生调度：

- PID 1；
- `PF_KTHREAD`；
- Agent；
- scheduler；
- RT/DL 或其他非 `SCHED_OTHER` 任务。

BPF 在 `init_task` 和每次 enqueue 中重复检查 PID 1、内核线程、Agent 和 scheduler，作为第二道
保护。Agent 退出、持续事件溢出、身份容量耗尽、BPF 错误或进程信号都会触发受控 detach。

## 目录

~~~text
scheduler/
|-- Design.md
|-- README.md
|-- versions.lock
`-- rust/
    |-- .cargo/config.toml        scheduler BPF 编译器配置
    |-- bpf/
    |   |-- intf.h                 ABI v8
    |   `-- scx_adaptive.bpf.c     唯一调度数据面
    |-- src/
    |   |-- main.rs                attach、控制事务、detach
    |   |-- engine.rs              身份、分类缓存、行为观测
    |   |-- bpf.rs                 skeleton、maps、stats
    |   |-- wire.rs                event/control ABI
    |   |-- process.rs             class stage/generation
    |   |-- control.rs             Agent socket
    |   |-- topology.rs            possible/online CPU
    |   `-- stats.rs               诊断与行为窗口
    |-- tools/bpf-clang            选择 Clang 20..16
    `-- README.md
~~~

sched_ext 构建和加载兼容层使用 `Cargo.lock` 精确校验的官方
`scx_cargo`、`scx_utils` crate；项目目录不包含上游 scheduler 源码。

正式目标是 openEuler 24.03 LTS-SP4 x86_64 的 `6.6.0-scx` 内核，锁定工具链为
Clang/LLVM 17 和 Rust 1.96。完整版本与镜像哈希见 [`versions.lock`](versions.lock)。

## 构建与检查

在 `scheduler/rust` 目录执行 scheduler 检查：

~~~bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
target/release/scx_adaptive --validate-only
~~~

回到仓库根目录检查测试编排：

~~~bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/tests -v
python3 test/scripts/benchmark.py all --dry-run
~~~

单轮配对只用于迭代，正式结论必须使用三轮 campaign：

~~~bash
python3 test/scripts/benchmark.py balanced --single-round
python3 test/scripts/benchmark.py balanced
~~~
