# Adaptive OS Agent

`Adaptive-OS-Agent` 是项目的普通任务准入、语义分类和调度控制层。它从
Linux `/proc` 和 `scx_adaptive` 生命周期事件中建立稳定的进程/线程身份，只将
普通 `SCHED_OTHER` 线程准入 partial sched_ext，再融合显式启动目标、LLM 语义和
scheduler 运行时行为，最后通过带 generation 的事务把分类提交给 scheduler。

```text
 /proc 普通任务              DeepSeek 批量语义          scheduler 行为窗口
        │                         │                         │
        ├─ 安全准入 SCHED_EXT      │                         │
        │                         ▼                         ▼
        └─ 有界元数据 ─────▶ ClassificationRegistry ◀─连续 good window
                                      │
                                      └─ class + generation ─▶ scx_adaptive
```

Agent 不参与每次 dispatch，LLM 也不在调度热路径上。新任务立即以
`Balanced` 或已知进程默认类运行；远端请求失败时保留当前类，未分类任务继续
使用 `Balanced`。

- 跨组件数据流：[`../Design.md`](../Design.md)
- Agent 内部设计：[`Design.md`](Design.md)
- scheduler 设计：[`../scheduler/Design.md`](../scheduler/Design.md)

## 构建与检查

```bash
cargo build --manifest-path Adaptive-OS-Agent/Cargo.toml --release --locked
cargo test --manifest-path Adaptive-OS-Agent/Cargo.toml --locked
cargo clippy --manifest-path Adaptive-OS-Agent/Cargo.toml \
  --all-targets --locked -- -D warnings
```

只校验配置，不读取密钥、不启动 scheduler：

```bash
Adaptive-OS-Agent/target/release/adaptive-os-agent \
  --config Adaptive-OS-Agent/configs/agent.example.toml \
  --validate-only
```

## 配置与密钥

最小配置见 [`configs/agent.example.toml`](configs/agent.example.toml)。未显式填写的
字段使用经过校验的默认值：

- 模型：`deepseek-v4-flash`；
- thinking：关闭；
- 批大小：24 个进程或线程；
- 并发 worker：2（性能实验配置为 3）；
- 请求超时：45 秒；
- 最低接受置信度：0.60。

在线运行时优先读取环境变量 `DEEPSEEK_API_KEY`。也可在配置中指定
`deepseek.api_key_file`，文件内容为：

```text
DEEPSEEK_API_KEY=
```

密钥文件应保持 `0600` 权限，且不应进入版本库、日志、LLM 请求正文或
scheduler snapshot。

## 运行

正式运行由 Agent 启动并监管 scheduler：

```bash
sudo Adaptive-OS-Agent/target/release/adaptive-os-agent \
  --config Adaptive-OS-Agent/configs/agent.example.toml \
  --scheduler-bin scheduler/rust/target/release/scx_adaptive
```

常用选项：

| 选项 | 作用 |
| --- | --- |
| `--offline` | 不访问远端模型；`Balanced` 默认、本地显式目标和行为修正仍然工作 |
| `--snapshot-file PATH` | 周期性原子写入 scheduler 诊断快照 |
| `--debug` | 开启 Agent 和 scheduler 子进程的调试日志 |
| `--validate-only` | 只校验配置 |

Agent 收到 `SIGINT` 或 `SIGTERM` 后，先停止分类 worker 和本地 Tool，再停止
scheduler。scheduler 会 detach sched_ext；只有在有界宽限内无法退出时才强制终止。

## 运行时结构

```text
                               唯一可写分类状态
                                      │
 /proc 发现/准入 ──────────▶ Registry ◀── proposal ── LLM worker pool
 scheduler lifecycle/window ───▶    │
                                           ├─ action/generation ─▶ SchedulerClient
 read-only Tool socket ──▶ Agent 主线程 ─┘
```

`ClassificationRegistry` 只由 Agent 主线程修改。LLM worker 只返回 proposal，
SchedulerClient I/O 线程只负责帧和重连，Tool 线程只负责本地请求转发。
这个单写者结构使分类状态转移、generation 和 ACK 容易校验。

## 本地 Tool

Agent 在 Unix socket 上提供有界、只读的查询接口：

| Tool | 用途 |
| --- | --- |
| `workload.list` | 分页列出 Registry 中的进程或线程身份 |
| `workload.get` | 读取单个稳定身份的有界元数据 |
| `classification.get` | 读取 class、stage、source、confidence 和 generation |
| `scheduler.health` | 读取 scheduler 连接与退化状态 |
| `scheduler.stats` | 读取 scheduler 和 BPF 计数器 |

Tool 不能改变 Registry 或调度器状态。性能测试使用它在测量开始约 5 s 后采集
一次分类快照。

## 目录

| 路径 | 职责 |
| --- | --- |
| `src/main.rs` | 进程入口、主循环、批调度和提交 |
| `src/registry.rs` | 权威分类状态机、generation、ACK 和重放 |
| `src/deepseek.rs` | 有界 HTTP 请求、严格 JSON schema 和重试 |
| `src/discovery.rs`, `src/metadata.rs` | `/proc` 发现、身份核对、元数据有界化与脱敏 |
| `src/task_admission.rs` | 仅把稳定的普通 `SCHED_OTHER` 线程切换为 `SCHED_EXT` |
| `src/*_classifier.rs`, `src/behavior.rs` | 进程、线程和行为 proposal |
| `src/scheduler_client.rs` | 控制协议、epoch、重连和响应匹配 |
| `src/supervisor.rs` | scheduler 子进程启停、attach 验证和有界重启 |
| `src/tools.rs` | 只读 Tool socket |
