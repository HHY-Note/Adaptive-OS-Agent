# Adaptive OS Agent

Adaptive-OS-Agent 是项目唯一的服务入口。它启动并监管 scx_adaptive，发现普通进程，
执行安全准入，融合本地目标、DeepSeek 语义和 scheduler 行为窗口，再把带稳定身份与
generation 的分类事务提交给 scheduler。

~~~text
/proc discovery -> SCHED_OTHER admission -> ClassificationRegistry
                          ^                       ^
                          |                       |
                 scheduler lifecycle      local / LLM / behavior
                                                  |
                                                  v
                           generation action -> scx_adaptive
~~~

Agent 不选择 CPU、不保存 runnable queue，也不参与每次 dispatch。新任务立即使用
Balanced 或精确 process default；远端请求失败时保留当前类，不会暂停调度。

完整内部状态机见 [Design.md](Design.md)，跨组件设计见 [根 Design.md](../Design.md)。

## 构建与测试

~~~bash
cargo build --manifest-path Adaptive-OS-Agent/Cargo.toml --release --locked
cargo test --manifest-path Adaptive-OS-Agent/Cargo.toml --locked
cargo clippy --manifest-path Adaptive-OS-Agent/Cargo.toml \
  --all-targets --locked -- -D warnings
~~~

只验证 TOML，不读取密钥、不启动 scheduler：

~~~bash
Adaptive-OS-Agent/target/release/adaptive-os-agent \
  --config Adaptive-OS-Agent/configs/agent.example.toml \
  --validate-only
~~~

## 配置

最小配置位于 configs/agent.example.toml。未写字段采用源码默认值：

| 项目 | 默认值 |
| --- | --- |
| scheduler socket | /run/scx_adaptive.sock |
| Tool socket | /run/adaptive-os-agent-tools.sock |
| /proc reconciliation | 10 s |
| behavior / semantic tick | 1 s |
| DeepSeek endpoint | https://api.deepseek.com |
| model | deepseek-v4-flash |
| batch / workers | 24 / 2 |
| connect / response timeout | 5 s / 45 s |
| retries | 2 |
| minimum confidence | 0.60 |

在线模式优先读取 DEEPSEEK_API_KEY 环境变量，也可由 deepseek.api_key_file 指向
只包含 DEEPSEEK_API_KEY=... 的 0600 文件。密钥不会进入 prompt、日志、Registry、
scheduler snapshot 或性能 artifact。

比赛性能配置位于 test/configs/agent.performance.toml：使用 3 个 worker、1 次 retry，
密钥上传到 Guest 的 /run/aoa-secrets/deepseek.env。

## 运行

~~~bash
sudo Adaptive-OS-Agent/target/release/adaptive-os-agent \
  --config Adaptive-OS-Agent/configs/agent.example.toml \
  --scheduler-bin scheduler/rust/target/release/scx_adaptive
~~~

全部 CLI：

| 选项 | 行为 |
| --- | --- |
| --config PATH | 读取严格 TOML，未知字段直接拒绝 |
| --scheduler-bin PATH | 指定由 Agent 启动的 scheduler，默认 scx_adaptive |
| --offline | 禁用远端语义；本地目标、行为确认和 Balanced 默认仍工作 |
| --snapshot-file PATH | 每个 behavior tick 原子更新 scheduler JSON snapshot |
| --debug | 同时开启 Agent 和 scheduler child 的调试日志 |
| --validate-only | 只校验配置 |

启动时 Agent 等待 scheduler Hello 和 /sys/kernel/sched_ext/state，最长 15 秒。scheduler
异常退出时，60 秒窗口内最多重启 3 次；每次新 epoch 都先完成 lifecycle replay 和完整
Registry snapshot，再恢复增量提交。

退出顺序为停止新语义工作、最多等待 worker 2 秒、停止 Tool/控制连接、向 scheduler
发送 SIGTERM，并给 scheduler 3 秒完成 detach；超时后才强制结束 child。

## 分类边界

Agent 只准入普通 SCHED_OTHER 线程，并排除：

- PID 1、内核线程；
- Agent 与其 scheduler child；
- RT/DL 和其他非 SCHED_OTHER 策略；
- 无法在系统调用前后复核 tgid/tid/starttime 的生命期。

分类使用 ProcessInstanceKey、ProcessKey、TaskKey、scheduler epoch 和 class generation，
不会仅凭可复用 PID/TID 更新状态。LLM 只返回 proposal；ClassificationRegistry 主线程
是分类状态的唯一 writer。

## 有界运行时

| 资源 | 固定上限 |
| --- | ---: |
| Registry process / task | 32,768 / 65,536 |
| pending LLM batch | 32 |
| scheduler control queue / frame | 1,024 / 1 MiB |
| Registry snapshot batch | 128 |
| Tool queue / frame | 128 / 256 KiB |
| scheduler event / tick | 2,048 |
| control action / tick | 256 |
| Tool reply timeout | 4 s |

Agent 主循环休眠周期为 20 ms。worker、SchedulerClient 和 ToolServer 只能通过有界队列
返回结果，必须由主线程重新核对完整身份后才能影响 Registry。

## 只读 Tool

Tool socket 使用 4-byte network-order 长度前缀加 JSON frame，提供：

| Tool | 返回内容 |
| --- | --- |
| workload.list | 分页列出 active/recently-exited process/task |
| workload.get | 查询一个稳定身份的有界元数据 |
| classification.get | class、stage、source、confidence、generation、timing |
| scheduler.health | epoch、registry-ready、连接和 degraded 状态 |
| scheduler.stats | Rust policy、scheduler 与 BPF 数据面计数 |

Tool 不能修改 Registry、调用模型或下发调度控制。性能测试只通过它读取分类与健康证据。

## 源码导航

~~~text
src/main.rs                 服务入口、20 ms owner loop、提交
src/config.rs               严格配置与默认值
src/limits.rs               所有固定运行时上限
src/discovery.rs            /proc process 扫描
src/metadata.rs             生命期复核、元数据界限和脱敏
src/task_admission.rs       SCHED_OTHER -> SCHED_EXT
src/registry.rs             分类状态、generation、ACK、恢复
src/deepseek.rs             HTTPS、严格 JSON schema、有界重试
src/process_classifier.rs   process 特征投影
src/thread_classifier.rs    thread 特征投影
src/behavior.rs             确定性行为 proposal
src/scheduler_client.rs     epoch、snapshot、action、重连
src/supervisor.rs           scheduler child 与 attach 监管
src/tools.rs                有界只读 Tool socket
~~~

新机器安装、CPU 隔离、频率锁定和 dynamic_mix 的完整运行命令见
[根 README](../README.md)。
