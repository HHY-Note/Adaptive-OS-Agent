# 动态混合真实应用性能测试

`test/` 在同一套 openEuler 虚拟机环境中，对 Linux Native 调度器和
Adaptive OS Agent 做 repeat 配对比较。性能入口只保留一个：

```text
dynamic_mix
```

该场景同时包含交互服务、持续计算任务和周期性压力，直接观察 Agent 是否能降低
P99，并把吞吐代价控制在可接受范围。每次测试完成后自动生成
output/performance/<timestamp>/report.md；完整实验约束见 Design.md。

```text
benchmark.py -> read-only template + per-run overlay -> openEuler VM
      |                                                |
      |-- randomized Native/Agent pair                 |-- real applications
      |-- environment and image preflight              |-- collector + perf
      `-- validation and paired analysis <-------------'-- native metrics
```

## 负载组成

应用集合只在 `image/real_workloads/aoa-real-workload` 中定义。Host 不根据场景
重复拼装负载，也不把应用真值提供给 Agent。

| 组成 | 应用 | 业务指标 |
| --- | --- | --- |
| 交互延迟 | Redis、Nginx、PostgreSQL | P99 latency |
| 持续吞吐 | FFmpeg、RocksDB、zstd | iterations/s 或 ops/s |
| 周期压力 | OpenSSL AES-256-GCM，3 workers | 2 s active / 10 s period |

在 6 vCPU Guest 中，请求率和并发按 `vcpus - 1` 的压力预算缩放。该预算只决定
工作量，不设置 affinity、cpuset、nice 或实时调度策略。CPU 选择始终由被测内核
调度器完成。

每个 run 都写出并验证负载合同：

- 平均 CPU 必须在 70% 到 90%；
- 测量窗口必须包含至少 4 个 `>=95%` CPU 采样；
- 必须完成至少 5 次周期压力；
- FFmpeg、RocksDB、zstd 必须覆盖至少 90% 的测量窗口；
- 三项延迟应用和三项持续吞吐应用都必须产出有效原生指标。

## 固定实验环境

| 项目 | 配置 |
| --- | --- |
| Guest OS | openEuler 24.03 LTS-SP4 x86_64 |
| Guest kernel | 6.6.0-scx |
| Guest CPU | 1 socket x 3 cores x 2 SMT threads |
| Guest vCPU pin | Host CPU 6-11 |
| QEMU emulator pin | Host CPU 0-5 |
| CPU governor | performance |
| workload warmup | 20 s |
| measurement | 60 s |
| current submission | 1 Native/Agent pair |
| optional repeat profile | 3 pairs |

模板镜像路径由 `config.yaml` 唯一指定。正常测试只读模板，并为每个 run 创建临时
qcow2 overlay；测试结束后删除 overlay，不修改模板。

## 运行

先执行只读环境检查：

```bash
python3 test/scripts/check_env.py
```

查看当前单轮的确定性执行计划：

```bash
python3 test/scripts/benchmark.py dynamic_mix --single-round --dry-run
```

当前提交运行一组完整配对：

```bash
python3 test/scripts/benchmark.py dynamic_mix --single-round
```

需要补充跨 repeat 离散程度时，可选运行 config.yaml 保留的 3-pair profile：

```bash
python3 test/scripts/benchmark.py dynamic_mix --dry-run
python3 test/scripts/benchmark.py dynamic_mix
```

单轮包含一个 Native run 和一个 Agent run。两侧都通过环境、负载合同、应用指标、
perf、Agent 健康与清理门禁后，才生成对比结论；CLI 不接受其他性能场景。

重新分析已有 campaign，不启动虚拟机：

```bash
python3 test/scripts/benchmark.py \
  --analyze-only test/output/performance/<timestamp>
```

## 测量与配对

Native 和 Agent 使用相同只读模板、应用参数、vCPU 拓扑和测量时长，但运行在各自
独立的 overlay 中。每个 repeat 内两种变体相邻执行，顺序由固定 seed 随机化。

指标口径：

- 聚合 P99：Redis、Nginx、PostgreSQL P99 微秒值的几何平均，越低越好；
- 综合吞吐：FFmpeg、RocksDB、zstd 原生速率的几何平均，越高越好；
- 配对改善：只比较相同 repeat 的 Native 与 Agent；
- 单轮报告：直接给出同一配对改善，不伪造跨 repeat 置信区间；
- 多 repeat 报告：给出配对改善中位数及 bootstrap 95% CI；
- 应用级报告：逐项保留应用自身单位，不直接相加。

Agent run 还会记录分类时间线、策略更新、fast-path 调度计数、异常计数、控制面 CPU
和 RSS。分类准确率按时间线对应的 schedstat 运行时间加权，避免用单个瞬时快照代表
整个测量窗口。

## 有效性门槛

以下任一条件失败，该 run 保留原始证据，但不进入性能结论：

- KVM、libvirt、模板 SHA-256、CPU 分区或频率预检失败；
- live domain 的 pin、拓扑、SMBIOS profile 或磁盘参数不匹配；
- Guest CPU 拓扑、workload service 或测量窗口不正确；
- 应用退出异常、缺少 P99/吞吐指标或负载合同未通过；
- collector 未覆盖目标应用，或 perf 必需事件缺失；
- Native 测量期间 sched_ext 不是 disabled；
- Agent 缺少 scheduler 数据，或出现 event overflow、capacity hit、degraded；
- Agent/scheduler 误调度受保护任务，或结束后 sched_ext 未恢复；
- domain、overlay 或临时资源清理失败。

## 输出

```text
test/output/performance/<timestamp>/
|-- campaign.json
|-- preflight.json
|-- comparison.json
|-- summary.csv
|-- report.md
`-- runs/<sequence>__r<repeat>__dynamic_mix__<variant>/
    |-- result.json
    |-- benchmark-summary.json
    |-- domain.xml
    |-- run_guest.sh
    `-- benchmark/
        |-- environment.json
        |-- validation.json
        |-- perf-stat.csv
        |-- real-workloads/
        `-- observations/
```

`report.md` 包含总体性能、六个应用逐项结果、实测 CPU/突发证据、分类闭环、
调度健康、控制面开销和复现环境。`comparison.json` 保存同一信息的结构化版本。

## 本地回归

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/tests -v
bash -n test/image/real_workloads/aoa-real-workload
python3 test/scripts/benchmark.py dynamic_mix --single-round --dry-run
```

测试启动器不设置 Guest 内任务 affinity、nice、实时策略或 cgroup，也不修改
sched_ext、sysctl、IRQ 或 CPU online 状态。
