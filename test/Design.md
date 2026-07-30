# 性能测试设计与实现

本文说明测试程序怎样在 Host 上创建隔离的 libvirt VM，怎样在 Guest 内启动
dynamic_mix 真实应用，怎样同时采集 Native/Agent 证据，最后怎样判定一次 run 是否
有效并生成报告。操作命令见 [README.md](README.md)；项目总体闭环见
[根 Design.md](../Design.md)。

## 1. 测试回答的问题

测试只保留一个性能入口：dynamic_mix。它把三种调度压力放在同一个可重复窗口：

~~~text
                 +----------------------------------+
                 | dynamic_mix                      |
                 +----------------+-----------------+
                                  |
          +-----------------------+-----------------------+
          |                       |                       |
          v                       v                       v
   Redis/Nginx/PostgreSQL   FFmpeg/RocksDB/zstd     周期 OpenSSL
       P99 目标                  吞吐目标             burst 证据
~~~

结论不是只看一个总分，而是同时展示：

- 三个 latency 应用的逐项 P99 与几何平均；
- 三个 continuous throughput 应用的逐项速率与几何平均；
- CPU 利用率区间、峰值采样、burst 数和持续任务覆盖；
- Agent 分类、generation、policy、dispatch、fallback、overflow 和 degraded；
- perf 事件、schedstat、核间忙碌度、控制面 CPU/RSS；
- 模板、payload、Guest 内核和拓扑的复现信息。

## 2. Host、VM、Guest 三层边界

~~~text
+============================= Host =============================+
| benchmark.py                                                   |
|  config/parser -> RunSpec -> preflight -> runner -> analysis   |
|                                                               |
| 物理 CPU 0-5: Linux/QEMU emulator/IRQ                         |
| 物理 CPU 6-11: Guest vCPU (6 条，完整 3 个 SMT core)           |
|                                                               |
| qemu-img overlay -> virsh define/start -> SSH/SCP             |
+----------------------------+----------------------------------+
                             |
                             v
+============================= Guest ============================+
| 6 vCPU, 3 GiB, 1 socket x 3 cores x 2 threads                  |
| SMBIOS serial: aoa-profile-dynamic_mix                        |
| systemd workload service + run_guest.sh                       |
|                                                               |
| Native: sched_ext 必须 disabled                               |
| Agent : adaptive-os-agent -> scx_adaptive -> sched_ext enabled |
|                                                               |
| collector + perf + application-native summarizer              |
+----------------------------+----------------------------------+
                             |
                             v
+=========================== Host output ========================+
| result.json / domain.xml / guest stdout                         |
| benchmark/observations/*.jsonl                                 |
| benchmark-summary.json                                         |
| comparison.json / summary.csv / report.md                      |
+=================================================================+
~~~

Host 只负责生命周期和证据搬运；Guest 才运行被测 scheduler 与真实应用。dispatcher 不
设置 affinity、nice、chrt、cgroup、BPF 或 sysctl，避免测试脚本替被测方案“调参”。

## 3. 配置如何变成一次 RunSpec

### 3.1 入口

benchmark.py 的执行顺序：

~~~text
命令行 dynamic_mix [--single-round] [--dry-run]
          |
          v
load_config(test/config.yaml)
          |
          v
load_performance()
  - 只接受 dynamic_mix
  - variants 必须恰好 native + agent
  - machine 必须 6 vCPU / 1x3x2 / performance governor
          |
          v
campaign_schedule(seed)
  - 每个 repeat 内随机 Native/Agent 顺序
  - 保持同 repeat 的一对
          |
          v
build_spec()
  - machine / scheduler / workload / benchmark / libvirt
          |
          v
cargo build --release --locked (scheduler + Agent)
          |
          v
template + Host + payload preflight
~~~

当前提交的主入口是 single-round：每个命令只生成一个 Native 和一个 Agent VM。配置中的
formal profile 仍保留 3 个 repeat，用于需要离散程度时的补充实验。

### 3.2 固定机器参数

| 项目 | 当前值 |
| --- | --- |
| Guest memory | 3 GiB |
| Guest vCPU | 6 |
| Guest topology | 1 socket × 3 cores × 2 threads |
| vCPU pin | Host CPU 6-11，一一对应 |
| QEMU emulator | Host CPU 0-5 |
| CPU mode | host-passthrough |
| required feature | topoext |
| frequency | performance，min=max 3,300,000 kHz |
| VM warmup | 2 s |
| workload warmup | 20 s |
| measured window | 60 s |
| cooldown | 3 s |
| perf events | task-clock、context-switches、cpu-migrations、page-faults、cycles、instructions、cache-references、cache-misses |

## 4. Host 预检：先证明环境，再启动 VM

预检是只读的；失败时 benchmark.py 在创建 campaign 目录前退出，不修改 GRUB、CPU
频率、隔离状态或 libvirt 配置。

### 4.1 基础依赖与模板

检查：

~~~text
 /dev/kvm 可读写
 virsh qemu-img ssh scp tar cpupower 均存在
 qemu:///system 可连接
 default network active
 无残留 test-* domain
 runtime_dir 存在且为空，或父目录可创建
 template.qcow2 存在且 regular/read-only
 scheduler/versions.lock 中的 target.template_sha256 与实际 hash 相同
 benchmark payload、Agent binary、scheduler binary、secret file 都存在
 secret file mode 不允许 group/world access
~~~

模板 hash 读取前后同时检查 device/inode/size/mtime/ctime，防止“计算 hash 的同时镜像
被替换”。每次 run 使用该只读模板的 backing file，不直接写模板。

### 4.2 CPU 分区与频率

~~~text
物理 Host（示例 12 SMT threads）

CPU 0  1  2  3  4  5  |  CPU 6  7  8  9  10 11
      Host/QEMU/IRQ    |       Guest vCPU 0..5
      三个完整 core    |       三个完整 core

内核启动参数必须表达：
  isolated=6-11
  nohz_full=6-11
  rcu_nocbs=6-11
  irqaffinity=0-5
~~~

预检逐项读取：

- online CPU 必须恰好由 Guest pin 集合与 emulator 集合覆盖；
- 两集合不得重叠，且各自拥有完整 SMT core；
- Guest core 不得与 emulator core 共享；
- /sys/devices/system/cpu/isolated 与 nohz_full 必须覆盖 6-11，不能出现额外隔离核；
- rcu_nocbs 必须覆盖 Guest，irqaffinity 只能落在 Host 集合；
- 每个参与 CPU 的 scaling_governor、scaling_min_freq、scaling_max_freq 必须分别为
  performance、3300000、3300000。

设置与恢复由外部脚本完成，测试模块只检查：

~~~bash
sudo test/scripts/set_cpu_frequency.sh
python3 test/scripts/check_env.py
sudo test/scripts/restore_cpu_frequency.sh
~~~

## 5. Host 创建一台 VM 的完整生命周期

这是测试的核心实现。每个 Native 或 Agent variant 都独立走一遍，不复用运行中的 Guest。

### 5.1 建立 run 目录和名称

runner.run_one 首先建立空的 run_dir，并根据绝对路径 hash 生成 8 位 unique suffix：

~~~text
test/output/performance/<campaign>/runs/
  001__r01__dynamic_mix__native/
  002__r01__dynamic_mix__agent/

runtime_dir = /tmp/aoa-test-runs/<libvirt-domain>
overlay     = runtime_dir/disk.qcow2
guest script= run_dir/run_guest.sh
domain XML  = run_dir/domain.xml
~~~

domain 名称被清洗为 [a-z0-9-_]，最长 63 字符，避免 libvirt 名称和不同 run 冲突。

### 5.2 创建 qcow2 overlay

Host 执行等价于：

~~~text
qemu-img create -f qcow2 -F qcow2
  -b /var/lib/libvirt/images/aoa-lab/template.qcow2
  /tmp/aoa-test-runs/<domain>/disk.qcow2
~~~

overlay.parent 在创建前建立；Guest 的 systemd、数据库、结果和临时写入全部落到
overlay，template 始终只读。一个 run 一个 overlay 使 Native/Agent 的写时状态互不污染。

### 5.3 生成 libvirt XML

domain.build_domain_xml 生成以下结构：

~~~text
<domain type="kvm">
  <memory unit="MiB">3072</memory>
  <currentMemory unit="MiB">3072</currentMemory>
  <vcpu placement="static">6</vcpu>
  <cputune>
    vcpupin 0 -> 6 ... vcpupin 5 -> 11
    emulatorpin -> 0-5
  </cputune>
  <os><type arch="x86_64">hvm</type><boot dev="hd"/></os>
  <sysinfo type="smbios">
    serial = aoa-profile-dynamic_mix
  </sysinfo>
  <cpu mode="host-passthrough" check="none">
    topology sockets=1 cores=3 threads=2
    <feature policy="require" name="topoext"/>
  </cpu>
  <disk type="file" device="disk">
    qcow2, virtio(vda), cache=none,
    discard=unmap, detect_zeroes=unmap
  </disk>
  <interface network="default" model="virtio"/>
  <serial/><console/><rng backend="/dev/urandom"/>
</domain>
~~~

SMBIOS serial 是 Guest 选择 workload profile 的唯一信号；它不会通过命令行参数污染
应用。disk driver 的 cache/discard/detect_zeroes 也在 live XML 中重新校验。

### 5.4 define、start、校验 live XML

~~~text
run_one
  |
  +-- virsh define run_dir/domain.xml
  +-- virsh start <domain>
  +-- virsh dumpxml <domain>
          |
          +-- vcpupin 是否为 {0:6,1:7,...,5:11}
          +-- emulatorpin 是否为 0-5
          +-- topology 是否为 1x3x2
          +-- required CPU feature 是否存在
          +-- SMBIOS serial 是否为 aoa-profile-dynamic_mix
          +-- disk discard 是否为 unmap
~~~

只有 live XML 与 RunSpec 完全一致才继续。这样能发现 libvirt 接受 XML 但实际没有应用
pin/topology 的情况。

### 5.5 DHCP 与 SSH

wait_for_ssh 每 2 s 重试，直到 boot_timeout（默认 90 s）：

~~~text
virsh domifaddr <domain> --source lease
             |
             v
       取得 Guest IP
             |
             v
ssh -i test/.local/ssh/test_ed25519
    -o BatchMode=yes -o StrictHostKeyChecking=no
    root@<ip> true
~~~

单次 sshd 启动慢只记住 last_error 并继续重试；总期限到达才报告 BootTimeout。SCP 使用
大写 -P 指定端口，避免和 ssh 的 -p 混淆。

### 5.6 上传 payload 与运行脚本

Host 上传内容分两组：

| 组 | 内容 |
| --- | --- |
| scheduler payload | Agent release、scheduler release、Agent TOML |
| benchmark payload | benchmark_collector.py、dispatcher、summarizer |
| secret | deepseek.env，目标路径 mode 600，父目录 mode 700 |
| run script | 根据 RunSpec 动态生成的 /tmp/test-run.sh |

每个 payload 在 result.json 记录 source、target 和 SHA-256。上传后执行 chmod/install，
再通过 SSH 启动 /tmp/test-run.sh。

### 5.7 失败也必须清理

无论失败发生在 overlay、boot、upload、Guest run、download 还是分析前，finally 都执行：

~~~text
virsh destroy <domain>       (忽略已退出)
virsh undefine <domain>
virsh list --all --name       (确认 domain 不再存在)
remove runtime_dir/overlay
写 result.json:
  status / failed_phase / error / returncode / timestamps
~~~

domain 仍存在或 runtime_dir 删除失败会把 run 标为 FAIL。原始 run_dir 不删除，便于定位
失败原因。

## 6. Guest 脚本：Native 与 Agent 的唯一区别

### 6.1 启动检查

Guest 脚本先停止自启动 workload service，清理上一次的 marker，然后安装本次 dispatcher
和 summarizer。它读取：

~~~text
/sys/kernel/sched_ext/state
/sys/kernel/sched_ext/root/ops
~~~

Native 分支要求 state=disabled；Agent 分支同时要求 scheduler PID 存活、state=enabled，
且 ops 名称匹配 scx_adaptive（允许内核后缀）。

Agent 命令等价于：

~~~text
/opt/Adaptive-OS-Agent/adaptive-os-agent
  --config /opt/Adaptive-OS-Agent/configs/agent.performance.toml
  --scheduler-bin /opt/Adaptive-OS-Agent/scx_adaptive
  --snapshot-file /bench_out/scheduler-snapshot.json
~~~

等待 scheduler 20 s，Agent warmup 3 s；停止时发送 TERM，最多等待 60 s，最后检查
sched_ext 已恢复 disabled。

### 6.2 Guest 环境校验

Guest 内嵌 Python 校验器写 environment.json 并检查：

- online CPU 数为 6；
- 当前进程 affinity 覆盖全部 online CPU；
- topology 为 1 socket、3 core、每 core 2 threads；
- DMI serial 等于 aoa-profile-dynamic_mix；
- workload systemd service 已 enabled；
- 记录 uname、os-release、kernel cmdline、workload version、perf version。

校验失败不会进入 measured window。

## 7. dynamic_mix 负载实现

### 7.1 dispatcher 初始化

aoa-real-workload 由 systemd service 运行，profile 由 DMI serial 选择：

~~~text
aoa-profile-dynamic_mix
          |
          v
锁文件 /run/aoa-real-workload.lock
          |
          v
VCPUS = getconf _NPROCESSORS_ONLN = 6
PRESSURE_CPUS = VCPUS - 1 = 5
CLIENT_THREADS = (PRESSURE_CPUS + 1) / 2 = 3
CLIENTS = CLIENT_THREADS * 2 = 6
          |
          v
启动服务端 -> 准备 Redis/RocksDB 数据 -> SERVERS_READY
~~~

服务端进程以普通 userspace 身份启动：

- Redis 监听 16379；
- Nginx 监听 18080；
- PostgreSQL 监听 15432。

### 7.2 六个目标应用和一个辅助压力源

| 应用 | 角色 | 真实命令/参数 | 结果字段 |
| --- | --- | --- | --- |
| Redis + memtier | latency | rate 1000，ratio 1:9，256-byte data | p99_ms |
| Nginx + wrk2 | latency | rate 1800，latency mode | p99_ms |
| PostgreSQL + pgbench | latency | rate 90，20 ms latency limit | p99_ms |
| FFmpeg | throughput | 1920x1080@60，MPEG-4，完整 iteration | throughput_per_second |
| RocksDB | throughput | readrandomwriterandom，200000 rows | throughput_per_second |
| zstd | throughput | LLVM shared library corpus，持续压缩 | throughput_per_second |
| OpenSSL | auxiliary | 3 workers，active 2 s / period 10 s | burst timeline |

客户端速率由 scaled_rate(base) 计算：

~~~text
rate = max(1, base * PRESSURE_CPUS / 5)
~~~

6 vCPU 时正好得到表中的 1000、1800、90。RocksDB、zstd、OpenSSL 按 pressure CPU 数
逐级启用；当前 5 个 pressure CPU 会启用全部。OpenSSL 的 objective=false，不进入吞吐
几何平均，只制造可验证的周期竞争。

每个 measured root 先把 PID、start_ticks、name、role 写入 targets.jsonl。collector
随后用 PID+start_ticks 动态展开 descendants 和 threads，避免把复用 PID 当成同一 worker。

### 7.3 时间窗和 marker

~~~text
Guest run script                 dispatcher
       |                              |
       |-- stop/start service ------->|
       |<--------- SERVERS_READY -----|
       |-- write "20 60" window ----->|  (READY_FILE)
       |                              |
       |                              | 启动 measured jobs
       |                              | 写 measurement-window.start_ns
       |                              | touch MEASUREMENT_STARTED
       |<--------- collector/perf ----|
       |                              |
       |                              | 完成 60 s jobs
       |                              | 写 end_ns、metrics.json、COMPLETE
       |<--------- stop collector ----|
~~~

warmup jobs 的结果在测量前删除；measured jobs 必须先创建 target roots，再发布
MEASUREMENT_STARTED，保证 collector 在窗口一开始就能看到真实 PID。

OpenSSL 从 measurement marker 开始，每 10 s 记录 burst start/end；load-contract.json
固定保存这组参数，不允许报告从日志猜测。

## 8. Guest 采集链

### 8.1 collector

collector 在测量窗口内按 1 s 采样：

~~~text
/proc/stat
  -> 每 CPU user/nice/system/idle/iowait/irq/softirq/steal ticks

/proc/<pid>/schedstat + /proc/<pid>/task/*
  -> run_ns / wait_ns / timeslices / migrations
  -> start_ticks 防 PID reuse

target roots -> parent tree -> descendants -> all TIDs
  -> targets.jsonl / process-stats.jsonl / task-schedstat.jsonl

Agent variant:
  Tool workload.list(classification)
  Tool scheduler.health/stats
  /bench_out/scheduler-snapshot.json
  +5 s classification-snapshot.json
  每 5 s classification-snapshots.jsonl
~~~

Tool 查询按最多 64 个 TGID 一批，低于 Agent Tool 的 frame 上限。classification snapshot
和 timeline 只从 measurement start 之后计分，不把晚到分类追溯到更早时间。

### 8.2 perf

Guest 同时运行：

~~~text
perf stat -a -x, -o benchmark/perf-stat.csv
  -e task-clock,context-switches,cpu-migrations,page-faults,
     cycles,instructions,cache-references,cache-misses
  -- sleep 60
~~~

perf 缺失或事件缺失时，require_perf=true 会使 run 无效。

### 8.3 application-native summarizer

dispatcher 只负责运行程序；summarizer 读取每个应用的 stdout/result/log，生成：

~~~text
benchmark/real-workloads/apps/<name>/metrics.json
  completed
  role / objective
  elapsed_seconds
  p99_ms                 (latency)
  throughput_per_second  (throughput)
  exit_code
~~~

测试不把不同应用的单位直接相加。报告保留原始量纲，并另外计算几何平均。

## 9. 有效性门禁

### 9.1 Guest validation

生成的 Guest 脚本用内嵌 Python 校验 artifact，再决定 guest_result.valid：

~~~text
环境:
  CPU 数/拓扑/affinity/SMBIOS/service
时间:
  start_ns < end_ns，窗口约 60 s
应用:
  至少 3 latency + 4 throughput 目录
  metrics.completed=true，exit_code 为 0 或 124
负载:
  pressure_plan vCPU=6、budget=5、reserved_latency_cpu=1
  load-contract scenario=dynamic_mix
  completed burst >= 5
采集:
  collector samples/target_workers/target_apps 完整
Agent:
  protected:init/kthreadd/agent/scheduler 均被观察且未进 sched_ext
  ordinary target threads 全部 sched_ext_enabled=1
  snapshot/timeline 结构正确
  scheduler epoch 唯一，final snapshot registry_ready=true、degraded=false
清理:
  Agent 停止后 sched_ext state=disabled
~~~

### 9.2 Host analysis

analyze_run 再按测量时间戳从原始 JSONL 中取 delta，并增加：

- perf 必需事件；
- latency/throughput 指标完整；
- load-contract CPU 合同；
- Agent scheduler invalid counters：event_overflows、task_capacity_hits、
  degraded_transitions 必须为零。

任一门禁失败，run 保留全部原始文件但不进入有效比较。

## 10. load contract

dispatcher 写入的 load-contract.json 是验收合同，analysis.py 独立计算观察值：

~~~text
average CPU:
  target = 0.80
  minimum = 0.70
  maximum = 0.90

burst:
  period = 10 s
  active = 2 s
  start delay = 4 s
  workers = 3
  interval utilization >= 0.95 的样本至少 4 个
  completed bursts 至少 5 个

continuous throughput:
  FFmpeg、RocksDB、zstd 的 elapsed
  >= 0.90 * measured window
~~~

CPU 利用率来自 /proc/stat tick delta，不接受 workload 自己报告的占用率。核级统计按
physical_package_id:core_id 聚合，并计算 core busy coefficient of variation。

## 11. Native/Agent 配对分析

### 11.1 主指标口径

延迟：

~~~text
P99_geomean = geometric_mean(Redis P99, Nginx P99, PostgreSQL P99)
improvement = (Native / Agent - 1) * 100%
~~~

吞吐：

~~~text
Throughput_geomean = geometric_mean(FFmpeg, RocksDB, zstd rate)
improvement = (Agent / Native - 1) * 100%
~~~

每个应用同时输出 Native、Agent、相对变化；Redis/Nginx/PostgreSQL 的单位是 us，
持续任务的单位是 units/s，不能跨应用相加。

### 11.2 配对规则

~~~text
(scenario, variant, repeat)
  Native r01 <---- paired ----> Agent r01
  Native r02 <---- paired ----> Agent r02
  ...

只保留两侧都 valid 的同 repeat。
Native 缺失不能由另一个 repeat 补位。
~~~

single-round 只有一对，报告明确显示单轮观测，CI 为 N/A。formal profile 的 3 对才
计算 paired median 和 bootstrap 95% CI；bootstrap 只作用于 repeat 的相对变化，不
伪造单轮区间。

### 11.3 系统与 Agent 证据

系统对比不冒充主目标，但完整显示：

- task-clock、context-switches、cpu-migrations、page-faults；
- cycles、instructions、instructions/cycle；
- cache-references、cache-misses、cache miss ratio；
- core busy CV；
- run/wait/timeslices/migrations；
- 每应用、每 class 的 schedstat。

Agent evidence 额外聚合：

- events processed/suppressed、fallback、overflow；
- policy feedback/placement updates；
- private/local/direct/shared dispatch；
- shared Latency/ordinary dispatch success/failure；
- cross-LLC migration/dispatch；
- preemption、control-plane CPU seconds、Agent/scheduler max RSS。

## 12. 输出目录与报告

~~~text
test/output/performance/<campaign>/
|-- campaign.json             # manifest、seed、schedule、profile
|-- preflight.json            # Host/template 检查
|-- comparison.json           # 结构化总比较
|-- summary.csv               # 主指标表
|-- report.md                 # 本次分析自动生成
+-- runs/
    +-- 001__r01__dynamic_mix__native/
    |   |-- result.json
    |   |-- domain.xml
    |   |-- run_guest.sh
    |   |-- guest_ssh.stdout/stderr
    |   |-- benchmark-summary.json
    |   +-- benchmark/
    |       |-- environment.json
    |       |-- validation.json
    |       |-- perf-stat.csv
    |       |-- real-workloads/
    |       |   |-- load-contract.json
    |       |   |-- pressure-plan.json
    |       |   +-- apps/<name>/metrics.json
    |       +-- observations/*.jsonl
    +-- 002__r01__dynamic_mix__agent/
        +-- 同样的结构，另含 scheduler.stdout/stderr 与 snapshot
~~~

静态目录不保存性能结论文档；执行或 analyze-only 时才在 campaign 目录写
report.md。报告顺序是：

~~~text
主指标 -> 单项应用 -> load contract -> perf/system
       -> classification -> scheduler health
       -> control-plane overhead -> environment/provenance
~~~

## 13. 操作入口

~~~bash
# 代码与脚本回归
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/tests -v
bash -n test/image/real_workloads/aoa-real-workload

# Host 只读预检
python3 test/scripts/check_env.py

# 生成一对 RunSpec，不启动 VM
python3 test/scripts/benchmark.py dynamic_mix --single-round --dry-run

# 当前提交的完整一轮 Native + Agent
python3 test/scripts/benchmark.py dynamic_mix --single-round

# 需要 repeat 区间时的补充 profile
python3 test/scripts/benchmark.py dynamic_mix

# 只重算已有 campaign，并重新生成 report.md
python3 test/scripts/benchmark.py \
  --analyze-only test/output/performance/<timestamp>
~~~

## 14. 代码索引

| 主题 | 文件 |
| --- | --- |
| CLI、schedule、build、preflight | scripts/benchmark.py、test_core/benchmark/config.py |
| YAML 解析和 machine 校验 | test_core/config/parser.py |
| Host 模板/CPU/频率/libvirt 检查 | test_core/host/check.py |
| domain XML | test_core/vm/domain.py |
| overlay | test_core/vm/overlay.py |
| SSH/SCP、IP、tar fallback | test_core/vm/ssh.py |
| run 生命周期与 cleanup | test_core/vm/runner.py |
| Guest shell/Python validation | test_core/benchmark/guest.py |
| /proc、Tool、CPU 采集 | guest_tools/benchmark_collector.py |
| 真实 workload dispatcher | image/real_workloads/aoa-real-workload |
| 应用 summarizer | image/real_workloads/summarize_workloads.py |
| 统计、配对和 report.md | test_core/benchmark/analysis.py |

## 15. 设计不变量

1. Native 与 Agent 使用同一只读模板、同一 machine、同一 measured window。
2. 每个 run 都有独立 overlay、独立 domain 和独立 output 目录。
3. live XML 不符合 RunSpec 时不执行应用。
4. workload 不调用调度提示接口；压力来自真实应用本身。
5. PID 统计必须绑定 start_ticks，并动态覆盖 descendants/threads。
6. CPU 合同由 collector 的独立 tick delta 验证。
7. Agent run 的 protected task、epoch、Registry ready 和 degraded 状态必须可观测。
8. 任一失败 run 原始证据保留，但不进入 Native/Agent 比较。
9. 当前默认操作是一轮配对；区间只由多 repeat profile 计算。
10. 性能报告只生成在 test/output/performance/<campaign>/report.md。
