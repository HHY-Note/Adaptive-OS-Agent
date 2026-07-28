# 真实应用性能实验设计

## 1. 目标

测试系统回答一个明确问题：在相同硬件、相同镜像、相同应用参数和相同测量窗口中，
Adaptive OS Agent 能否降低 Latency 应用的 P99、提高 Throughput 应用的完成量，
并保持/改善 Balanced 普通工作；在 Mix 中三类指标是否能同时成立。

设计目标：

1. 使用常见真实应用，不使用自研循环作为主要被测负载；
2. 三类场景由一个参数选择，应用集合只有一处权威定义；
3. Native 与 Agent 运行在独立、干净、配置相同的 VM overlay 中；
4. P99 和吞吐来自应用原生输出，原始结果可复核；
5. 任一环境、采集、scheduler 或清理异常都会使 run 无效；
6. 负载系统不主动调度 Agent、scheduler 或内核线程。

不把一次短烟测当作性能提升证据。正式结论必须来自三轮配对实验及置信区间。

## 2. 总体结构

```text
Host benchmark.py
  │
  ├─ load/validate config.yaml
  ├─ build Agent + scx_adaptive
  ├─ Host preflight
  └─ for each randomized paired run
       │
       ├─ create qcow2 overlay from read-only template
       ├─ generate libvirt XML
       │    └─ SMBIOS serial = aoa-profile-{latency|throughput|balanced|mix}
       ├─ boot and validate live domain
       ├─ upload generated Guest script + collector
       │    └─ Agent 变体再上传 Agent/scheduler/config/secret
       └─ run one Guest script
            │
            ├─ image service starts servers and prepares data
            ├─ Native check or Agent + scheduler startup
            ├─ common warmup
            ├─ common measurement window
            │    ├─ real applications
            │    ├─ read-only collector
            │    └─ perf stat
            ├─ artifact validation
            └─ stop Agent and require sched_ext=disabled
       │
       ├─ download /bench_out (SSH tar stream; SCP fallback)
       └─ destroy domain, undefine domain, remove overlay
```

应用二进制、配置、数据基线和 dispatcher 都在模板中。Host 不上传负载源码，也不在 Guest 中临时编译 workload。

## 3. 配置与不可变条件

正式配置只有 `test/config.yaml`。`load_performance()` 会拒绝未知字段，并强制以下约束：

- 恰好 6 vCPU；
- `1 socket x 3 cores x 2 threads`；
- Host governor 为 `performance`；
- 变体恰好为 `native` 和 `agent`；
- Native 引用 builtin scheduler，Agent 引用在线 Agent scheduler；
- 正式重复数至少为 3；
- workload kind 必须为 `baked-real-apps`；
- service、结果目录、ready/window/targets 路径必须为合法绝对路径。

`RunSpec.benchmark` 使用 schema 3，记录 scenario、variant、repeat、时间窗、perf 事件和 collector payload。应用定义不进入 `RunSpec`，避免 Host 与镜像各维护一份列表。

## 4. 虚拟机隔离

正式 Host 有 6 个物理核、12 个 SMT 线程：

| 角色 | Host CPU |
| --- | --- |
| Host、QEMU emulator、IRQ | `0-5` |
| 六个 Guest vCPU | `6-11` |

vCPU 0..5 依次 pin 到 CPU 6..11，emulator pin 到 0..5。CPU 模式为 `host-passthrough`，要求 `topoext`。磁盘使用 `cache=none`、`discard=unmap` 和 `detect_zeroes=unmap`。

每个 run 创建独立 overlay。正式模板为只读输入：

```text
/var/lib/libvirt/images/aoa-lab/template.qcow2
```

live domain 启动后，runner 再从 libvirt 实际 XML 验证 vCPU pin、emulator pin、拓扑、required features、SMBIOS serial 和 discard。只验证生成前 XML 不足以证明 libvirt 实际接受了配置。

### 4.1 正常测试与镜像维护的边界

```text
正常 benchmark
  read-only template ─▶ 每 run 创建 overlay ─▶ 启动场景 ─▶ 删除 overlay
          │
          └─ 不调用镜像构建器，不修改 template

镜像维护（仅应用/版本变更时）
  clean base ─▶ disposable build overlay ─▶ Guest install + verify
             ─▶ shutdown ─▶ qemu-img flatten ─▶ candidate image
```

`image/build_workload_image.py` 只是固化模板的维护工具。它永不直接挂载或修改正式模板，
只有 Guest 正常关机、安装验证全部通过后才把临时 overlay 转换成独立 candidate。
日常 `benchmark.py` 不导入、不执行该工具，参赛者正常测试时无需手工运行它。

## 5. 场景选择

libvirt 把 scenario 写入 SMBIOS system serial：

```text
latency    -> aoa-profile-latency
throughput -> aoa-profile-throughput
balanced   -> aoa-profile-balanced
mix        -> aoa-profile-mix
```

`aoa-real-workload-autostart.service` 在 multi-user target 启动，执行：

```text
/usr/local/sbin/aoa-real-workload --from-dmi
```

未知 serial 时 dispatcher 保持空闲并正常退出。这样普通启动该模板不会误触发压力测试。

service 为 `Type=oneshot`、`TimeoutStartSec=infinity`、`KillMode=control-group`。它先启动所需 server、准备数据、发布 `SERVERS_READY`，然后等待测试脚本提供 ready file 和时间窗。开机阶段不会把 client 的启动时间混入正式测量。

server 进程本身没有显式 SLO 或本机批处理目标，因此分类真值统一为 `balanced`；场景中的 latency/throughput 角色只属于携带该目标的 client/job。这样同一服务二进制不会因测试场景名称获得生产系统不可见的标签。

```text
SMBIOS scenario ─▶ 镜像 dispatcher 选择应用组合
                                   │
                                   ├─ targets.jsonl role ─▶ 仅 collector/准确率真值
                                   └─ process /proc ────▶ Agent 真实输入

Agent 不读 scenario、targets.jsonl 或 metrics.json。
```

## 6. 应用集合

### 6.1 latency

| 名称 | 工具 | 角色 | 主要指标 |
| --- | --- | --- | --- |
| redis | Redis + memtier | latency | p99 ms、ops/s |
| memcached | Memcached + memtier | latency | p99 ms、ops/s |
| nginx | Nginx + wrk2 | latency | p99 ms、requests/s |
| postgresql | PostgreSQL + pgbench | latency | transaction p99 ms、tps |
| zstd-background | zstd | throughput | iterations/s |

### 6.2 throughput

| 名称 | 工具 | 角色 | 主要指标 |
| --- | --- | --- | --- |
| redis-sentinel | Redis + memtier | latency | p99 ms、ops/s |
| ffmpeg | 1080p60 synthetic transcode | throughput | iterations/s |
| rocksdb | readrandomwriterandom | throughput | ops/s |
| zstd | LLVM shared library compression | throughput | iterations/s |
| openssl | AES-256-GCM EVP speed（16 KiB block） | throughput | bytes/s |
| imagemagick | fractal/blur/resize pipeline | throughput | iterations/s |

### 6.3 balanced

Redis/Memcached memtier 与 PostgreSQL pgbench 不设置请求率、延迟百分位、deadline 或 SLO；NATS 连续发布固定消息批次。四项工作都只有普通远程服务目标，不携带 latency 或本机批处理目标，并分别输出 ops/s、tps 和 messages/s。

### 6.4 mix

`redis`、`nginx`、`postgresql` 为 latency；`ffmpeg`、`rocksdb`、`zstd`、`imagemagick` 为 throughput；`etcd check perf` 和 NATS publish 为 balanced。

NATS 连续执行固定 100,000-message 批次，直到阶段窗口结束，再输出总消息 work units。etcd 在每个阶段开始前只删除自己的 `/etcdctl-check-perf/` 前缀；其固定时长检查用于施压，NATS rate 作为 mix 中的 Balanced 性能门禁。

## 7. 压力缩放

dispatcher 从 `_NPROCESSORS_ONLN` 读取 vCPU 数：

```text
pressure_cpu_budget = max(1, vcpus - 1)
client_threads      = ceil(pressure_cpu_budget / 2)
clients_per_thread  = client_threads * 2
```

6 vCPU 时得到 5、3、6。请求速率按 `pressure_cpu_budget / 5` 缩放。

`reserved_latency_cpu=1` 只记录“不要让并发需求吃满全部 vCPU”的压力预算，不执行 affinity、cpuset 或 CPU hotplug。最终 CPU 选择仍完全属于被测内核调度器。

## 8. 运行时安全边界

`aoa-real-workload` 明确不调用以下接口：

- `taskset`、`sched_setaffinity`；
- `nice`、`chrt`、`sched_setscheduler`；
- cgroup/cpuset；
- sched_ext、BPF、sysctl 或 CPU online 控制；
- 针对 Agent、scheduler 或内核线程的 PID 操作。

dispatcher 只保存自己启动的 server/job PID，并在 service 退出时终止自己的子任务。systemd 的 control-group kill 是最后的 Guest 内部清理边界。

Host 的 vCPU pin 是虚拟机实验环境控制，不是 Guest 内 workload 的任务调度策略。

## 9. 阶段协议

正式时间参数：

```text
VM warmup       2 s
Agent warmup    3 s (Agent only)
workload warmup 20 s
measurement     60 s
cooldown         3 s
```

关键顺序：

```text
service: servers/data ─ SERVERS_READY ─ wait
Guest:   environment ─ scheduler start ─ write window + READY
service: warmup jobs ─ measured jobs ─ MEASUREMENT_STARTED ─ COMPLETE
Guest:                  collector + perf ────────────────┘
```

预热任务结束后会删除其 app 结果。测量阶段重新启动所有 client，将根 PID、start ticks、名称和角色写入 `targets.jsonl`。`measurement-window.json` 使用 `CLOCK_MONOTONIC` 纳秒时间戳，Host 分析只接受该窗口内的数据。

Agent 分类快照由 collector 在测量开始约 5 秒后通过只读 Tool 获取。快照失败会使 Agent run 无效，但不会暂停 workload。

## 10. 采集器

`guest_tools/benchmark_collector.py` 以 `targets.jsonl` 为根集合。每个采样周期：

1. 用 `/proc/<pid>/stat` 校验 start ticks，避免 PID reuse；
2. 扫描 PPID 关系，找到每个根进程的动态后代；
3. 枚举 `/proc/<pid>/task` 中的线程；
4. 读取 schedstat、CPU ticks、RSS 和进程身份；
5. Agent 模式额外读取 scheduler stats 与一次分类快照。

应用可以 fork、exec 或动态创建线程，不需要预先写死线程数量。采集器不写 `/proc`、不发送调度命令。

```text
                        测量窗口内的三条数据链

targets.jsonl ─▶ /proc task/process + /proc/stat + CPU topology ─▶ JSONL
      │
      ├─ Agent Tool socket ─▶ classification snapshot + scheduler stats ─▶ JSON/JSONL
      │
      └─ 应用原生 stdout/JSON/log ─▶ summarize_workloads.py ─▶ metrics.json

Guest 全局 perf stat -a ─▶ perf-stat.csv
```

通用 collector 由 Host 每 run 通过 SCP 上传；负载二进制、配置和数据已在镜像中，
不会每轮上传。run 结束后 Host 优先通过 SSH tar stream 回收 `/bench_out`，探测或传输
失败时退回 `scp -r`。

主要输出：

```text
observations/cpu-stats.jsonl
observations/task-schedstat.jsonl
observations/process-stats.jsonl
observations/scheduler-stats.jsonl       Agent only
observations/classification-snapshot.json Agent only
observations/collector-errors.jsonl
observations/collector-summary.json
```

调度数据采集不按应用名称分支。更换陌生 Linux 应用时，只要启动器把根 PID、
start ticks、显示名称和验收角色写入 `targets.jsonl`，后代与线程由 collector 自动发现。
陌生应用的业务 P99/吞吐格式则需在下一节的指标归一化层增加解析，不需要改 scheduler。

## 11. 应用指标

`summarize_workloads.py` 为每个应用生成 schema 1 的 `metrics.json`：

```json
{
  "name": "nginx",
  "role": "latency",
  "exit_code": 0,
  "elapsed_seconds": 60.0,
  "p99_ms": 3.2,
  "throughput_per_second": 5998.0,
  "work_units": null,
  "completed": true
}
```

解析规则使用结构化 JSON 或应用稳定输出格式：

- memtier：`ALL STATS/Totals` 的 `p99.00` 与 `Ops/sec`；
- wrk2：latency percentile 和 `Requests/sec`；
- pgbench：transaction log 的 P99 与 `tps`；
- RocksDB：取有效正值 `ops/sec`，不把初始化的零速率当结果；
- OpenSSL：解析单一 16 KiB block 的 AES-256-GCM aggregate bytes/s；
- loop workload/NATS：`work_units / elapsed_seconds`。

退出码 `0` 为自然完成，`124` 为被统一测量窗口正常终止；其他退出码失败。耗时文件从最后一个合法数值解析，兼容 GNU time 对非零退出的诊断行。

## 12. 有效性检查

Guest validation 使用 schema 2。最低应用角色数量：

| 场景 | latency | throughput | balanced |
| --- | ---: | ---: | ---: |
| latency | 4 | 1 | 0 |
| throughput | 1 | 5 | 0 |
| balanced | 0 | 0 | 4 |
| mix | 3 | 4 | 2 |

latency/mix 至少两个 latency 应用必须有 P99；throughput/mix 至少两个 throughput 应用必须有正确定义的 rate；balanced 的四个应用及 mix 中的 NATS 必须有 rate。每个 metrics 应用必须至少有一个 target 根；清单可额外包含为这些应用提供服务的组件，collector 必须覆盖完整清单。

Agent run 还必须满足：

- 分类快照 schema 正确；
- 测量期 scheduler epoch 唯一；
- 无持续 event overflow 或控制面 degraded；
- 最终 snapshot `registry_ready=true` 且 `degraded=false`；
- 停止 Agent 后 sched_ext 为 `disabled`。

Host analysis 进一步拒绝 event overflow、capacity hit 和 degraded transition，并验证要求的 perf events。

## 13. 汇总与比较

单 run 分析使用 schema 4。

latency 汇总：

```text
p99_latency_geomean_us = geometric_mean(each latency application's P99 in us)
```

throughput 汇总：

```text
throughput_geomean_per_second = geometric_mean(each positive throughput rate)
```

Balanced 汇总同样对各普通应用的正 rate 计算 `balanced_geomean_per_second`。不同应用单位不能相加，几何平均用于表达相对整体变化；报告同时保留每个应用原始指标、median 和 worst。`mix` 必须同时报告 P99、throughput 和 Balanced 三项，不允许用某一类收益掩盖另一类回退。

campaign 只配对相同 scenario、相同 repeat 的 Native/Agent 有效 run。延迟改善方向为下降，吞吐改善方向为上升。正式三轮报告中位数、配对改善和 bootstrap 95% 区间；`single-round` 只作为实现迭代证据。

## 14. 输出与清理

```text
campaign/
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
    └── benchmark/
        ├── validation.json
        ├── perf-stat.csv
        ├── real-workloads/apps/<name>/
        └── observations/
```

runner 的 `finally` 路径总是尝试 destroy、undefine，并在确认 domain 不存在后删除 runtime overlay。清理失败会覆盖原 PASS 状态，使 run 无效。正式模板始终保留在固定位置，run 数据只存在于临时 overlay 和 Host 输出目录。

## 15. 操作入口

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/tests -v
python3 test/scripts/check_env.py
python3 test/scripts/benchmark.py latency --dry-run
python3 test/scripts/benchmark.py throughput --single-round
python3 test/scripts/benchmark.py mix
python3 test/scripts/benchmark.py all
```

离线重算已有结果：

```bash
python3 test/scripts/benchmark.py \
  --analyze-only test/output/performance/<timestamp>
```
