# 真实应用性能测试

`test/` 在相同的 6 vCPU 虚拟机环境中比较 Linux 原生调度器和 Adaptive OS Agent。测试负载不是 Host 临时生成的程序，而是预先固化到 qcow2 模板中的真实应用。测试时只需传入 `latency`、`throughput` 或 `mix`。

详细协议和实现边界见 [`Design.md`](Design.md)。

## 目录

```text
test/
├── config.yaml
├── configs/agent.performance.toml
├── image/real_workloads/
│   ├── install.sh
│   ├── versions.env
│   ├── aoa-real-workload
│   ├── aoa-real-workload-autostart.service
│   ├── summarize_workloads.py
│   └── redis/nginx 配置与静态数据
├── scripts/
│   ├── benchmark.py
│   ├── build_workload_image.py
│   ├── check_env.py
│   ├── cpu_isolation.sh
│   ├── set_cpu_frequency.sh
│   └── restore_cpu_frequency.sh
├── guest_tools/benchmark_collector.py
├── test_core/
└── tests/test_benchmark.py
```

## 固化应用

模板路径由 `config.yaml` 唯一指定，当前为：

```text
/var/lib/libvirt/images/aoa-lab/template.qcow2
```

镜像包含以下应用和工具：

- Redis 7.2、Memcached 1.6、Nginx 1.24、PostgreSQL/pgbench 15；
- FFmpeg、RocksDB `db_bench` 8.5.4、zstd、OpenSSL、ImageMagick；
- etcd 3.4、NATS server 2.14.3、NATS CLI 0.4.0；
- memtier_benchmark 2.5.1 和固定提交的 wrk2。

第三方源码版本和 SHA-256 全部固定在 `image/real_workloads/versions.env`。构建结束会清除下载缓存、包缓存和中间目标，并执行 `fstrim`，因此磁盘压力来自运行数据，不来自无关构建垃圾。

PostgreSQL 的 pgbench scale 4 数据库已固化。Redis、Memcached 的 20,000 个键以及 RocksDB 的 200,000 条 256-byte 数据在每次 run 的临时 overlay 中准备，不污染只读模板。

## 四种场景

应用集合写死在 `image/real_workloads/aoa-real-workload`，不在 Host 配置中重复维护。

表中的角色描述带显式目标的 client/job。没有进程级 SLO 或本机批处理目标的 server 组件统一按 `balanced` 观测，不从场景名称推导生产分类。

| 场景 | latency 角色 | throughput 角色 | balanced 角色 |
| --- | --- | --- | --- |
| `latency` | Redis、Memcached、Nginx、PostgreSQL | zstd-background | 无 |
| `throughput` | 无 | Redis、FFmpeg、RocksDB、zstd、OpenSSL、ImageMagick | 无 |
| `balanced` | 无 | 无 | Redis、Memcached、PostgreSQL、NATS |
| `mix` | Redis、Nginx、PostgreSQL | FFmpeg、RocksDB、zstd、ImageMagick | etcd、NATS |

在 6 vCPU Guest 中，压力预算为 `vcpus - 1 = 5`，客户端线程数为 `ceil(5 / 2) = 3`。这里的“预留一个 latency CPU”只是并发需求预算，不设置 affinity，也不把任何 CPU 从内核或 scheduler 手中隔离。正式 Host 的物理核隔离由独立的 Host 准备脚本完成。

## 安全约束

负载启动器只创建普通用户态进程，明确不执行以下操作：

- 不设置 affinity、nice、实时调度策略或 cgroup；
- 不修改 sched_ext、sysctl、IRQ 或 CPU online 状态；
- 不枚举并操作 Agent、scheduler 或内核线程；
- 不在正式模板上保存运行结果。

Agent/scheduler 仍由现有测试协议启动和停止。collector 只读目标进程及其动态后代的 `/proc` 数据和 Agent Tool socket。每个 Agent run 结束必须确认 sched_ext 为 `disabled`。

## 构建镜像

完整构建在一次性 overlay 中进行。Guest 正常关机、应用验证通过并执行 TRIM 后，overlay 才会转换成无 backing file 的独立候选镜像：

```bash
python3 test/scripts/build_workload_image.py \
  --base-image /path/to/clean-template.qcow2 \
  --output /tmp/aoa-real-workloads-template.qcow2
```

如网络受限，可提前准备 `memtier.tar.gz`、`wrk2.tar.gz`、`nats-server.tar.gz`、`nats.zip` 和 `rocksdb.tar.gz`，再传入：

```bash
python3 test/scripts/build_workload_image.py \
  --base-image /path/to/clean-template.qcow2 \
  --download-cache /path/to/cache \
  --output /tmp/aoa-real-workloads-template.qcow2
```

缓存仍会逐个校验 SHA-256。候选镜像至少完成以下检查后才能替换模板：

```bash
qemu-img info --output=json /tmp/aoa-real-workloads-template.qcow2
qemu-img check /tmp/aoa-real-workloads-template.qcow2
```

`backing-filename` 必须为空，四种 Native 烟测和至少一次 Agent 安全启停测试必须通过。替换使用同目录临时名称加原子 `mv`，替换完成后删除候选硬链接和旧构建目录；不要在运行中的 domain 上替换镜像。

只更新候选镜像内的启动脚本和配置时，可以执行：

```bash
python3 test/scripts/build_workload_image.py \
  --compact-existing /tmp/aoa-real-workloads-template.qcow2 \
  --refresh-runtime
```

该模式会直接修改指定的独立候选文件，因此不得指向正在使用的正式模板。

## CPU 准备

Host 的完整物理核分配为：

| 用途 | Host 物理核 | Host 逻辑 CPU |
| --- | --- | --- |
| Linux、QEMU emulator、IRQ | 0、1、2 | `0-5` |
| Guest vCPU | 3、4、5 | `6-11` |

Guest 拓扑固定为 `1 socket x 3 cores x 2 threads`。首次启用隔离并重启：

```bash
sudo test/scripts/cpu_isolation.sh enable
sudo reboot
```

每次 campaign 前固定频率，结束后恢复：

```bash
sudo test/scripts/set_cpu_frequency.sh
sudo test/scripts/restore_cpu_frequency.sh
```

环境预检会验证 KVM、libvirt network、模板、密钥、构建产物、完整物理核分区、隔离参数和 CPU frequency policy：

```bash
python3 test/scripts/check_env.py
```

## 运行

查看一种场景的确定性计划：

```bash
python3 test/scripts/benchmark.py latency --dry-run
python3 test/scripts/benchmark.py throughput --dry-run
python3 test/scripts/benchmark.py balanced --dry-run
python3 test/scripts/benchmark.py mix --dry-run
```

执行时只需传入测试类型：

```bash
python3 test/scripts/benchmark.py latency
python3 test/scripts/benchmark.py throughput
python3 test/scripts/benchmark.py balanced
python3 test/scripts/benchmark.py mix
```

省略参数或使用 `all` 会运行全部场景。正式模式每个场景运行 `2 variants x 3 repeats`；`all` 共 24 个独立 VM run。调度方案迭代可用一次 Native/Agent 配对：

```bash
python3 test/scripts/benchmark.py mix --single-round
```

单轮结果只用于实现验证，不能替代三轮正式统计。

## 测量协议

libvirt 用 SMBIOS serial `aoa-profile-{scenario}` 选择镜像内场景。service 开机后启动对应 server、准备数据并发布 `SERVERS_READY`，然后等待 Host/Guest 测试脚本写入统一时间窗。

正式配置为 20 秒预热、60 秒测量、3 秒冷却。测量阶段重新创建所有 client 进程并记录根 PID 与 start ticks；collector 动态发现后代进程和线程。Native 和 Agent 使用同一套镜像、数据、应用参数和测量边界。

P99 指标来自 memtier、wrk2 和 pgbench。吞吐来自应用原生结果或有明确定义的 work-units/elapsed。不同应用量纲不直接相加：场景汇总采用各应用正值指标的几何平均。

## 有效性门槛

以下任一条件失败，run 都保留证据但不进入配对结论：

- live domain 的 vCPU pin、emulator pin、拓扑、SMBIOS profile 或 discard 配置不匹配；
- Guest 不是 6 个在线 CPU、3 个 core、每 core 2 threads；
- service 未启用、场景不匹配、应用退出失败或耗时无效；
- 场景角色数量、P99 数量、吞吐数量或压力预算不满足约束；
- collector 未覆盖全部应用、未观察到线程或发生超时；
- `perf stat` 缺少要求事件；
- Native 测量期间 sched_ext 不是 `disabled`；
- Agent 缺少分类快照、scheduler epoch 改变、心跳回退、registry 未就绪或 degraded；
- Agent 结束后 sched_ext 没有恢复为 `disabled`；
- domain 或临时 overlay 清理失败。

## 输出

```text
test/output/performance/<timestamp>/
├── campaign.json
├── preflight.json
├── comparison.json
├── summary.csv
├── report.md
└── runs/<sequence>__r<repeat>__<scenario>__<variant>/
    ├── result.json
    ├── benchmark-summary.json
    ├── domain.xml
    ├── run_guest.sh
    ├── scheduler.stdout
    ├── scheduler.stderr
    └── benchmark/
        ├── environment.json
        ├── perf-stat.csv
        ├── validation.json
        ├── real-workloads/
        │   ├── pressure-plan.json
        │   ├── targets.jsonl
        │   └── apps/<name>/metrics.json
        └── observations/
```

`report.md` 比较同一场景、同一 repeat 的有效 Native/Agent 配对。延迟改善按数值下降计算，吞吐改善按数值上升计算，并给出中位数和 bootstrap 95% 区间。

本地回归：

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/tests -v
```
