# scx_adaptive Rust 子工程

Rust 是 scheduler 的有界控制面，不是第二套调度器。普通任务的 CPU 选择、虚拟时间、DSQ、抢占和
steal 全部在 BPF 中完成；Rust 即使暂时没有处理事件，未分类普通任务也会继续按 Balanced 运行。

## 模块关系

```text
                         main.rs
                            │
       ┌────────────────────┼────────────────────┐
       ▼                    ▼                    ▼
 control.rs             engine.rs              bpf.rs
 epoch/snapshot/ACK     identity/behavior      attach/maps/ring
       │                    │                    │
       ├─ process.rs        ├─ stats.rs          ├─ wire.rs
       └─ topology.rs       └─ lifecycle cache   └─ ABI conversion
                                                        │
                         ┌──────────────────────────────┴────────────┐
                         │ bpf/intf.h: ABI v8                        │
                         │ bpf/scx_adaptive.bpf.c: 唯一调度数据面      │
                         └───────────────────────────────────────────┘
```

分类更新采用 BPF-first 事务：先写 `task_control` map，再提交 Engine 缓存；Engine 提交失败时恢复
旧 map 值。Inherited 和 Semantic 任务发送采样行为事件，Locked 任务只保留 INIT/EXEC/EXIT
生命周期事件。当前 Agent 的正常 task 分类路径是 `Inherited -> Locked`；Semantic 为协议
支持的中间阶段。

`class_state[3]` 是全局 task-level virtual-time 基准，而每 CPU 的 root virtual time 在
`cpu_state[cpu]` 中。可运行任务本身分布在每 CPU 的三条 class DSQ 中，Rust 不持有全局
或 per-CPU runnable queue。

## 本地检查

从 `scheduler/rust` 目录构建时，本目录的 [`.cargo/config.toml`](.cargo/config.toml) 会把 BPF 编译器指向
[`tools/bpf-clang`](tools/bpf-clang)；包装器
优先使用 Clang 20..17，并为本地兼容接受 Clang 16。正式锁定基线仍是 Clang/LLVM 17。

~~~bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
target/release/scx_adaptive --validate-only
~~~

正常部署需要 Agent 传入 `--agent-pid` 和 `--control-socket`。完整设计见
[../Design.md](../Design.md)。
