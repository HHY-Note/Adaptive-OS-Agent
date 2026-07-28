# Adaptive OS Agent

本项目由三个协同但可独立构建的部分组成：

- `Adaptive-OS-Agent` 从真实 `/proc` 发现进程和线程，只准入普通 `SCHED_OTHER` 任务，融合当前启动目标、LLM 语义和运行时行为，并维护权威分类状态。
- `scheduler/rust` 中的 `scx_adaptive` 由 eBPF 数据面直接调度 `Latency`、`Balanced`、`Throughput`，Rust 只维护分类事务、生命周期、观测与恢复。
- `test` 在 6 vCPU 虚拟机中，用固化到 qcow2 镜像的真实应用对 Linux 原生调度器和 Agent 做配对实验。

```text
/proc + scheduler behavior ─▶ Agent Registry ─▶ class/generation
                                  │                     │
                                  └─ DeepSeek proposal  ▼
                                                   Rust control
                                                        │ task_control
                                                        ▼
Linux ordinary task ─▶ partial sched_ext ─▶ BPF per-CPU class DSQ ─▶ CPU

test harness ─▶ Native/Agent 独立 VM ─▶ proc + perf + app metrics ─▶ paired report
```

跨组件设计见 [`Design.md`](Design.md)，Agent 细节见 [`Adaptive-OS-Agent/Design.md`](Adaptive-OS-Agent/Design.md)，scheduler 细节见 [`scheduler/Design.md`](scheduler/Design.md)，镜像和实验协议见 [`test/Design.md`](test/Design.md)。

## 目录

```text
Adaptive-OS-Agent/
  configs/agent.example.toml     最小运行配置
  configs/deepseek.env           本机按需创建的 API key，被 git 忽略
  src/                           发现、分类、Registry、监管和只读 Tool
scheduler/
  rust/                          scx_adaptive Rust 控制面和 eBPF 数据面
  versions.lock                 兼容依赖、目标环境和工具链版本基线
test/
  config.yaml                   3 物理核/6 vCPU 正式性能矩阵
  image/build_workload_image.py 仅用于维护固化模板，正常测试不调用
  image/real_workloads/          镜像安装器、启动服务和指标汇总器
  scripts/benchmark.py          latency/throughput/balanced/mix 实验入口
  guest_tools/                  Guest 只读采集器
  test_core/                    配置、VM 编排、有效性检查和统计分析
  tests/test_benchmark.py       不启动 VM 的性能链路回归测试
```

`target/`、`test/output/`、`test/.local/` 和 `__pycache__/` 是本机构建或运行数据，不属于源码。

## 安全边界

真实负载启动器只创建普通用户态应用，不设置 CPU affinity、nice、实时策略、cgroup 或 scheduler 参数。Agent 只把普通 `SCHED_OTHER` 线程准入 `SCHED_EXT`；PID 1、内核线程、Agent、scheduler 和 RT/DL 任务保持原生。Guest 采集器只读 `/proc` 和 Agent Tool；Agent 退出后，测试必须确认 `/sys/kernel/sched_ext/state` 恢复为 `disabled`，否则该 run 无效。

每个测试 run 都从只读模板创建临时 qcow2 overlay。无论成功、失败或超时，runner 都会销毁并 undefine domain，再删除 overlay。

## 构建

正式运行基线为 openEuler 24.03 LTS-SP4 x86_64 和 `6.6.0-scx` Guest 内核；锁定的
sched_ext crate、Clang/LLVM、Rust 和镜像哈希见 [`scheduler/versions.lock`](scheduler/versions.lock)。

```bash
cargo build --manifest-path Adaptive-OS-Agent/Cargo.toml --release --locked
cargo --config scheduler/rust/.cargo/config.toml \
  build --manifest-path scheduler/rust/Cargo.toml --release --locked
```

本地回归：

```bash
cargo test --manifest-path Adaptive-OS-Agent/Cargo.toml --locked
cargo clippy --manifest-path Adaptive-OS-Agent/Cargo.toml --all-targets --locked -- -D warnings
cargo --config scheduler/rust/.cargo/config.toml \
  test --manifest-path scheduler/rust/Cargo.toml --locked
cargo --config scheduler/rust/.cargo/config.toml \
  clippy --manifest-path scheduler/rust/Cargo.toml --all-targets --locked -- -D warnings
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/tests -v
python3 test/scripts/benchmark.py all --dry-run
```

## Agent 密钥

在线分类优先读取环境变量 `DEEPSEEK_API_KEY`，未设置时读取本机按需创建且被 Git 忽略的
`Adaptive-OS-Agent/configs/deepseek.env`：

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

新任务先使用中性的 `Balanced`。当前启动命令中的显式目标和进程完整元数据上的高置信 LLM 目标可建立进程默认，并按精确父子生命期传给短子任务；低置信进程 proposal 与所有线程 proposal 都等待 scheduler 连续行为确认，专用类型冲突保守回到 `Balanced`。Agent 不读写持久化应用分类档案；进程内精确元数据缓存只在本次 Agent 生命期内有效，且仍遵守相同置信规则。LLM 超时、失败或返回 `Unknown` 不会阻塞调度。`SIGINT` 或 `SIGTERM` 会触发 Agent 停止 scheduler，scheduler 随后 detach sched_ext。确定性离线诊断可以添加 `--offline`。

## 真实负载镜像

正式模板固定在 `/var/lib/libvirt/images/aoa-lab/template.qcow2`。镜像内包含 Redis、Memcached、Nginx、PostgreSQL/pgbench、FFmpeg、RocksDB `db_bench`、zstd、OpenSSL、ImageMagick、etcd 和 NATS，并固化小型数据集与 `aoa-real-workload-autostart.service`。

libvirt 通过 SMBIOS serial 选择场景，服务开机后启动对应 server、准备数据并等待统一测量门。具体应用集合写死在镜像内脚本中，Host 不上传或编译负载程序。

| 场景 | 应用构成 | 比较指标 |
| --- | --- | --- |
| `latency` | Redis、Memcached、Nginx、PostgreSQL，加 zstd 后台压力 | 四个应用 P99 的几何平均，越低越好 |
| `throughput` | Redis、FFmpeg、RocksDB、zstd、OpenSSL、ImageMagick | 有效应用速率的几何平均，越高越好 |
| `balanced` | 无 SLO 的 Redis、Memcached、PostgreSQL、NATS 普通远程工作 | 四个应用速率的几何平均，越高越好 |
| `mix` | Redis、Nginx、PostgreSQL、FFmpeg、RocksDB、zstd、ImageMagick、etcd、NATS | P99、吞吐与 Balanced 速率必须同时改善 |

固定版本和 SHA-256 位于 `test/image/real_workloads/versions.env`。正常测试只读取正式模板，不修改模板内容。

## 性能实验

先检查 Host 和运行计划：

```bash
python3 test/scripts/check_env.py
python3 test/scripts/benchmark.py latency --dry-run
python3 test/scripts/benchmark.py throughput --dry-run
python3 test/scripts/benchmark.py balanced --dry-run
python3 test/scripts/benchmark.py mix --dry-run
```

只需用第一个参数选择一种场景；省略或传 `all` 会运行四种场景。正式执行每种场景包含 Native/Agent 两个变体和 3 次重复：

```bash
python3 test/scripts/benchmark.py latency
python3 test/scripts/benchmark.py throughput
python3 test/scripts/benchmark.py balanced
python3 test/scripts/benchmark.py mix
python3 test/scripts/benchmark.py all
```

调度方案迭代使用一次配对，不替代三轮正式统计：

```bash
python3 test/scripts/benchmark.py mix --single-round
```

2026-07-26 的分类里程碑单轮验收中，Mix 和 Throughput 的进程/线程、根任务与运行时加权准确率均为 100%；Latency 的根任务、已解析任务、活跃任务与运行时加权准确率也均为 100%。原始运行产物写入被 Git 忽略的 `test/output/`，这些数据只用于分类验收与调度迭代，不替代三轮配对统计。

当前直接可比的 Balanced 单轮 60 秒结果为 Native `38,189.196`、Agent `35,445.303`，Agent 落后 `7.18%`。该结果是阶段基线，不是最终性能声明；最新 Balanced 重构后的 Latency、Throughput 和 Mix 必须重新执行三轮配对后才能用于比赛结论。

正式配置为 20 秒预热、60 秒测量和 3 秒冷却。Guest 固定为 `1 socket x 3 cores x 2 threads`；vCPU 固定到 Host CPU `6-11`，QEMU emulator 和 Host IRQ 使用 `0-5`。有效 run 才进入同 repeat 的 Native/Agent 配对统计，并报告中位数和 bootstrap 95% 区间。

已有 campaign 可以离线重新分析：

```bash
python3 test/scripts/benchmark.py \
  --analyze-only test/output/performance/<timestamp>
```

结果目录包含原始 JSON/JSONL/CSV、逐 run `benchmark-summary.json`、`summary.csv`、`comparison.json` 和 `report.md`。
