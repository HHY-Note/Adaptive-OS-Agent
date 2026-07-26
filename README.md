# Adaptive OS Agent

本项目由三个协同但可独立构建的部分组成：

- `Adaptive-OS-Agent` 从真实 `/proc` 发现进程和线程，融合当前启动目标、LLM 语义和运行时行为，并维护权威分类状态。
- `scheduler/rust/scx_adaptive` 根据 `Latency`、`Balanced`、`Throughput` 三类状态选择任务、CPU 和时间片，eBPF 数据面负责校验并执行调度命令。
- `test` 在 6 vCPU 虚拟机中，用固化到 qcow2 镜像的真实应用对 Linux 原生调度器和 Agent 做配对实验。

跨组件设计见 [`Design.md`](Design.md)，Agent 细节见 [`Adaptive-OS-Agent/Design.md`](Adaptive-OS-Agent/Design.md)，scheduler 细节见 [`scheduler/Design.md`](scheduler/Design.md)，镜像和实验协议见 [`test/Design.md`](test/Design.md)。

## 目录

```text
Adaptive-OS-Agent/
  configs/agent.example.toml     最小运行配置
  configs/deepseek.env           本机 API key，已被 git 忽略
  src/                           发现、分类、Registry、监管和只读 Tool
scheduler/
  rust/                          scx_adaptive Rust 策略层和 eBPF 数据面
  scx/                           锁定的上游 sched-ext 构建依赖
  versions.lock                 上游、目标环境和工具链版本基线
test/
  config.yaml                   3 物理核/6 vCPU 正式性能矩阵
  image/real_workloads/          镜像安装器、启动服务和指标汇总器
  scripts/benchmark.py          latency/throughput/mix 实验入口
  scripts/build_workload_image.py  独立候选镜像构建器
  guest_tools/                  Guest 只读采集器
  test_core/                    配置、VM 编排、有效性检查和统计分析
  tests/                        性能链路本地回归测试
```

`target/`、`test/output/`、`test/.local/` 和 `__pycache__/` 是本机构建或运行数据，不属于源码。

## 安全边界

真实负载调度器只启动普通用户态应用，不设置 CPU affinity、nice、实时策略、cgroup 或任何 scheduler 参数。它不会主动选择、迁移或修改 Agent、scheduler 和内核线程。Guest 采集器只读 `/proc` 和 Agent Tool；Agent 退出后，测试必须确认 `/sys/kernel/sched_ext/state` 恢复为 `disabled`，否则该 run 无效。

每个测试 run 都从只读模板创建临时 qcow2 overlay。无论成功、失败或超时，runner 都会销毁并 undefine domain，再删除 overlay。

## 构建

```bash
cargo build --manifest-path Adaptive-OS-Agent/Cargo.toml --release --locked
cargo build --manifest-path scheduler/rust/Cargo.toml --release --locked
```

本地回归：

```bash
cargo test --manifest-path Adaptive-OS-Agent/Cargo.toml --locked
cargo clippy --manifest-path Adaptive-OS-Agent/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path scheduler/rust/Cargo.toml --locked
cargo clippy --manifest-path scheduler/rust/Cargo.toml --all-targets --locked -- -D warnings
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/tests -v
```

## Agent 密钥

在线分类优先读取环境变量 `DEEPSEEK_API_KEY`，未设置时读取已生成并忽略的 `Adaptive-OS-Agent/configs/deepseek.env`：

```text
DEEPSEEK_API_KEY=
```

文件权限必须为 `0600`。密钥不会进入日志、LLM 请求正文、scheduler snapshot 或测试结果；发送给模型的命令行会先脱敏。

## 运行 Agent

正式入口由 Agent 启动并监管 scheduler：

```bash
sudo Adaptive-OS-Agent/target/release/adaptive-os-agent \
  --config Adaptive-OS-Agent/configs/agent.example.toml \
  --scheduler-bin scheduler/rust/target/release/scx_adaptive
```

新任务先使用中性的 `Balanced`。当前启动命令中的显式 SLO/批处理目标、LLM 语义和 scheduler 行为窗口并行提供证据；`Balanced` 不会压制一致的 `Latency`/`Throughput` 证据，专用类型冲突则保守回到 `Balanced`。Agent 不读写持久化应用分类档案；进程内精确元数据缓存只在本次 Agent 生命期内有效。LLM 超时、失败或返回 `Unknown` 不会阻塞调度。`SIGINT` 或 `SIGTERM` 会触发 Agent 停止 scheduler，scheduler 随后 detach sched_ext。确定性离线诊断可以添加 `--offline`。

## 真实负载镜像

正式模板固定在 `/var/lib/libvirt/images/aoa-lab/template.qcow2`。镜像内包含 Redis、Memcached、Nginx、PostgreSQL/pgbench、FFmpeg、RocksDB `db_bench`、zstd、OpenSSL、ImageMagick、etcd 和 NATS，并固化小型数据集与 `aoa-real-workload-autostart.service`。

libvirt 通过 SMBIOS serial 选择场景，服务开机后启动对应 server、准备数据并等待统一测量门。具体应用集合写死在镜像内脚本中，Host 不上传或编译负载程序。

| 场景 | 应用构成 | 比较指标 |
| --- | --- | --- |
| `latency` | Redis、Memcached、Nginx、PostgreSQL，加 zstd 后台压力 | 四个应用 P99 的几何平均，越低越好 |
| `throughput` | Redis、FFmpeg、RocksDB、zstd、OpenSSL、ImageMagick | 有效应用速率的几何平均，越高越好 |
| `mix` | Redis、Nginx、PostgreSQL、FFmpeg、RocksDB、zstd、ImageMagick、etcd、NATS | P99 与吞吐几何平均必须同时改善 |

镜像构建器始终先生成独立候选文件，不会在安装过程中修改正式模板：

```bash
python3 test/scripts/build_workload_image.py \
  --base-image /path/to/clean-template.qcow2 \
  --output /tmp/aoa-real-workloads-template.qcow2
qemu-img check /tmp/aoa-real-workloads-template.qcow2
```

固定版本和 SHA-256 位于 `test/image/real_workloads/versions.env`。详细构建、验证和替换流程见 [`test/README.md`](test/README.md)。

## 性能实验

先检查 Host 和运行计划：

```bash
python3 test/scripts/check_env.py
python3 test/scripts/benchmark.py latency --dry-run
python3 test/scripts/benchmark.py throughput --dry-run
python3 test/scripts/benchmark.py mix --dry-run
```

只需用第一个参数选择一种场景；省略或传 `all` 会运行三种场景。正式执行每种场景包含 Native/Agent 两个变体和 3 次重复：

```bash
python3 test/scripts/benchmark.py latency
python3 test/scripts/benchmark.py throughput
python3 test/scripts/benchmark.py mix
python3 test/scripts/benchmark.py all
```

调度方案迭代使用一次配对，不替代三轮正式统计：

```bash
python3 test/scripts/benchmark.py mix --single-round
```

2026-07-26 的分类里程碑单轮验收中，Mix 和 Throughput 的进程/线程、根任务与运行时加权准确率均为 100%；Latency 的根任务、已解析任务、活跃任务与运行时加权准确率也均为 100%。对应报告目录为 `20260726-123509-125295`、`20260726-123923-141354` 和 `20260726-124803-054361`。这些是分类验收与调度迭代信号，不替代三轮配对统计。

正式配置为 20 秒预热、60 秒测量和 3 秒冷却。Guest 固定为 `1 socket x 3 cores x 2 threads`；vCPU 固定到 Host CPU `6-11`，QEMU emulator 和 Host IRQ 使用 `0-5`。有效 run 才进入同 repeat 的 Native/Agent 配对统计，并报告中位数和 bootstrap 95% 区间。

已有 campaign 可以离线重新分析：

```bash
python3 test/scripts/benchmark.py \
  --analyze-only test/output/performance/<timestamp>
```

结果目录包含原始 JSON/JSONL/CSV、逐 run `benchmark-summary.json`、`summary.csv`、`comparison.json` 和 `report.md`。
