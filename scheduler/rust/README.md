# scx_adaptive Rust 子工程

Rust 是控制状态的单 owner，也是未分类代际的有界慢路径；已分类任务的常规 runnable 调度由
BPF 快路径完成。Agent 更新 class/generation 后，Rust 先写 task_control map，再提交 Engine；
失败时恢复旧 control。

## 模块关系

~~~text
main.rs
  +-- control.rs       Agent epoch、Registry、幂等响应
  +-- bpf.rs           attach、maps/queues、PERCPU stats 聚合
  +-- wire.rs          ABI event/command 转换
  +-- engine.rs        生命周期、慢路径 refill、reservation/rollback
       +-- eevdf.rs    root EEVDF 与 lag 算术
       +-- pool/       task EEVDF 和 oldest-wait index
       +-- placement.rs topology、SMT、locality、normal/urgent lane
       +-- admission.rs Latency service 与 preemption budget
       +-- process.rs  class stage 与 generation
       +-- stats.rs    行为窗口和决策计数

bpf/intf.h             ABI v6
bpf/scx_adaptive.bpf.c 已分类快路径、最终校验、GLOBAL fallback
~~~

Inherited/Semantic task 在 BPF 调度的同时发送观测事件；Locked task 关闭逐任务事件并进入
KernelManaged 状态。task_control 缺失或 identity/generation 失配时，BPF 才发送需要 Rust
决策的 ENQUEUE。

## 本地检查

在本目录执行：

~~~bash
cargo fmt --all -- --check
cargo build --release --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
target/release/scx_adaptive --validate-only
~~~

正常部署需要 Agent 传入 --agent-pid 和 --control-socket。完整数据面、安全边界、ABI、配置和
性能验收规则见 [../Design.md](../Design.md)。
