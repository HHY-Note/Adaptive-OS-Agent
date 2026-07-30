# scx_adaptive Scheduler

scx_adaptive 是本项目的 sched_ext 数据面。Adaptive OS Agent 负责普通任务的准入、
语义分类和 generation；Rust scheduler 负责身份、控制事务、拓扑和动态 policy；
BPF 负责每一次 runnable 任务的 CPU 选择、排队、dispatch 和抢占。

~~~text
Agent: /proc + 语义 + 行为窗口
              |
              | class / stage / generation
              v
Rust: Hello / replay / CAS / policy lease
              |
              v
BPF: select_cpu -> enqueue -> DSQ -> dispatch -> Linux CPU
~~~

Rust 不保存 runnable 队列，也不在每次 dispatch 时等待 Agent。task_control 缺失、
身份失配或 policy lease 过期时，BPF 立即使用有界的 Balanced/fallback 路径。

## 当前数据面

每个 possible CPU 创建两条私有 deadline 队列：

~~~text
latency_dsq(cpu) : Latency
task_dsq(cpu)    : Balanced + Throughput，按 virtual deadline 排序
~~~

为处理宽 affinity 的可迁移工作，另外创建：

- 每个物理核心 leader 一个 shared Latency DSQ，承接 blocked Latency wakeup；
- 每个调度 domain 一个 Balanced overflow DSQ，承接 wide-affinity 的普通 Balanced enqueue。

因此不存在三条全局 class 队列；Balanced 和 Throughput 共享 normal lane，class request、
virtual service、budget 和 locality 决定顺序。Balanced-only 时会跳过 mixed-class root
选择，直接消费本 CPU normal lane。

## 安全边界

调度器使用 SCX_OPS_SWITCH_PARTIAL。Agent 只准入普通 SCHED_OTHER 线程；以下任务保持
Linux 原生路径：

- PID 1、PF_KTHREAD、Agent 和 scheduler；
- SCHED_FIFO、SCHED_RR、SCHED_DEADLINE 及其他非 SCHED_OTHER 策略；
- 任何身份或 affinity 校验失败的任务。

BPF 在 init_task 和 enqueue 中再次检查受保护身份，并保留 local/GLOBAL fallback。
Agent 消失超过 2 秒、连续 3 个一秒窗口发生 ring overflow、用户态容量耗尽、BPF 报错或
收到退出信号时，scheduler 受控 detach。

## 命令行

~~~text
scx_adaptive [--agent-pid PID] [--control-socket PATH] [--debug] [--validate-only]
~~~

正常部署由 Agent 启动：

~~~bash
sudo Adaptive-OS-Agent/target/release/adaptive-os-agent \
  --config Adaptive-OS-Agent/configs/agent.example.toml \
  --scheduler-bin scheduler/rust/target/release/scx_adaptive
~~~

直接启动 scheduler 只适合协议和内核诊断，必须显式提供 Agent PID 与控制 socket。

## 构建与检查

目标 Guest 是 openEuler 24.03 LTS-SP4 x86_64、6.6.0-scx。锁定的 Rust、Clang、
libbpf 和 sched_ext crate 版本见 versions.lock；BPF/Rust 共享 ABI 版本为 v35。

~~~bash
cd scheduler/rust
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
target/release/scx_adaptive --validate-only
cd ../..
~~~

tools/bpf-clang 优先选择 Clang 20、19、18、17，Clang 16 仅作为兼容回退；提交和
正式实验使用锁定的 Clang/LLVM 17。

## 诊断

Rust 周期性读取 per-CPU global_stats、cpu_state 和 policy 状态，并通过 Agent 的
scheduler.stats / scheduler.health Tool 暴露：

- event overflow、fallback、dispatch failure；
- 各 class dispatch、remote steal、迁移 locality；
- Latency budget charge、抢占 throttle/defer 和 backlog boost；
- shared Latency/Balanced 队列使用情况；
- policy generation、lease、反馈更新和 placement 更新；
- scheduler epoch、registry-ready、degraded 和 live task 数。

统计使用 PERCPU_ARRAY，读取时由 Rust 汇总；它们用于解释实验结果，不会改变热路径决策。

## 源码导航

~~~text
scheduler/
|-- Design.md                  完整架构、算法和不变量
|-- versions.lock              Guest/工具链/镜像基线
+-- rust/
    |-- bpf/intf.h             Rust/BPF v35 固定 ABI
    |-- bpf/scx_adaptive.bpf.c BPF sched_ext 数据面
    |-- src/main.rs            attach、事件循环、detach
    |-- src/control.rs         Unix 控制协议、replay、ACK
    |-- src/engine.rs          identity、class cache、行为窗口
    |-- src/policy.rs          双槽动态 policy controller
    |-- src/bpf.rs             skeleton、maps、统计
    |-- src/topology.rs        CPU/core/LLC/NUMA 拓扑
    +-- src/identity.rs        ProcessKey/TaskKey/RunnableKey
~~~

## 与性能测试的关系

测试入口只保留 dynamic_mix。它在同一套 6 vCPU Guest 中同时启动 Redis、Nginx、
PostgreSQL、FFmpeg、RocksDB、zstd 和周期性 OpenSSL；Host 侧随机化 Native/Agent
顺序，Guest 侧不设置 affinity、nice 或 cgroup。完整命令和数据口径见
[根 README](../README.md)、[test/README.md](../test/README.md) 与
[test/Design.md](../test/Design.md)。

~~~bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/tests -v
python3 test/scripts/benchmark.py dynamic_mix --dry-run
python3 test/scripts/benchmark.py dynamic_mix --single-round
~~~
