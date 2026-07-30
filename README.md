# Adaptive OS Agent

Adaptive OS Agent 是直接运行在目标 Linux 系统上的 workload-aware 调度服务。它不依赖
本仓库的虚拟机测试环境，也不要求固定 CPU 数、固定 CPU 编号、KVM、libvirt 或模板镜像。
物理服务器、工作站、云主机和虚拟机都可以作为目标机器，只要该机器的 Linux 内核提供
兼容的 `sched_ext` 与 BTF，并允许 root 加载 eBPF `struct_ops`。

~~~text
任意兼容 Linux 目标机

  ordinary processes and threads
                 |
                 v
  +-----------------------------------+
  | Adaptive OS Agent                 |
  | /proc discovery                   |
  | local + semantic + behavior       |
  | ClassificationRegistry            |
  +----------------+------------------+
                   | class + generation
                   v
  +-----------------------------------+
  | scx_adaptive                      |
  | Rust control + dynamic policy     |
  | eBPF select/enqueue/dispatch       |
  +----------------+------------------+
                   |
                   v
               Linux CPUs
~~~

Agent 负责发现、准入和分类，`scx_adaptive` 负责调度。LLM 请求不进入调度热路径；远端
语义不可用时，任务仍会沿本地证据、运行行为和安全默认类继续运行。

内部实现见 [总体设计](Design.md)。本文先说明通用机器上的正式部署，最后再单独说明
本项目当前使用的 Host + openEuler VM 性能测试环境。

## 仓库结构

~~~text
Adaptive-OS-Agent/
  configs/                 Agent 配置示例
  src/                     发现、分类、Registry、监管和只读 Tool
scheduler/
  rust/                    Rust 控制面与 eBPF sched_ext 数据面
  versions.lock            可复现实验使用的工具链和 Guest 基线
test/
  config.yaml              本机 VM 实验参数
  image/real_workloads/    Guest 内真实应用负载
  guest_tools/             Guest 观测器
  scripts/                 Host 预检、CPU 控制和 benchmark 入口
  test_core/               VM 编排、有效性判断和报告分析
~~~

`test/` 是验证项目性能的实验系统，不是运行 Agent 的依赖。

`scheduler/versions.lock` 中的 openEuler、Guest kernel、模板 hash 和 x86_64 target 用于
锁定当前性能实验，不是 Agent 的发行版白名单。通用部署仍以目标机的 sched_ext/BTF
兼容性和实际 attach 结果为准。

## 一、在通用 Linux 机器上运行

### 1. 运行条件

目标机器不需要与测试机使用相同发行版或拓扑，但必须满足以下边界：

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Linux；不能直接运行在 Windows 或 macOS 内核上 |
| 内核调度接口 | 启用兼容的 `sched_ext`，通常对应 `CONFIG_SCHED_CLASS_EXT=y` |
| BPF 类型信息 | `/sys/kernel/btf/vmlinux` 可读，通常对应 `CONFIG_DEBUG_INFO_BTF=y` |
| BPF 基础能力 | `CONFIG_BPF=y`、`CONFIG_BPF_SYSCALL=y`；建议启用 BPF JIT |
| 权限 | 当前交付方式使用 root 启动 Agent 与 scheduler |
| CPU | 不要求固定数量；scheduler 在启动时发现 online CPU、SMT core 和 LLC domain |
| 网络 | 仅在线语义模式需要访问配置的 HTTPS endpoint；离线模式不需要 |
| 已验证交付架构 | x86_64；其他架构应在目标机重新构建并完成 BPF attach 验证 |

先在目标机器执行：

~~~bash
uname -a
test -e /sys/kernel/sched_ext/state
test -r /sys/kernel/btf/vmlinux
cat /sys/kernel/sched_ext/state
~~~

启动前 `state` 通常为 `disabled`。如果该路径不存在，安装用户态依赖并不能补出
`sched_ext`，需要换用或构建启用了相应配置的内核。如果值已经是 `enabled`，说明系统
中已有 sched_ext scheduler，必须先正常停止它。

发行版提供内核配置时还可以核对：

~~~bash
grep -E 'CONFIG_(SCHED_CLASS_EXT|BPF|BPF_SYSCALL|BPF_JIT|DEBUG_INFO_BTF)=' \
  "/boot/config-$(uname -r)"
~~~

内核版本号本身不是充分条件。发行版可能回移 sched_ext，也可能使用与本项目不兼容的
接口版本，最终以 `scx_adaptive` 能否通过 verifier 并成功 attach 为准。

### 2. 安装构建依赖

项目使用 Rust 1.96.0。scheduler 构建需要 Clang 16 或更新版本；当前可复现实验锁定
Clang/LLVM 17.0.6。常见发行版的包名示例如下。

Debian/Ubuntu：

~~~bash
sudo apt-get update
sudo apt-get install -y \
  build-essential pkg-config clang llvm \
  libelf-dev zlib1g-dev libbpf-dev bpftool \
  curl ca-certificates git
~~~

Fedora/openEuler 系发行版：

~~~bash
sudo dnf install -y \
  gcc gcc-c++ make pkgconf-pkg-config clang llvm \
  elfutils-libelf-devel zlib-devel libbpf-devel bpftool \
  curl ca-certificates git
~~~

安装后先用 `clang --version` 确认 major version 不低于 16。需要完全复现实验工具链时，
再从发行版或 LLVM 软件源安装 Clang 17，并在构建时显式指定 `BPF_CLANG=clang-17`。

安装锁定的 Rust 工具链：

~~~bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
rustup toolchain install 1.96.0
rustup override set 1.96.0
rustc --version
cargo --version
~~~

这些是源码构建依赖。已经取得与目标内核兼容的两个 release 二进制时，运行阶段不需要
Rust、Clang、KVM 或 libvirt。

### 3. 构建

在仓库根目录执行：

~~~bash
cargo build \
  --manifest-path Adaptive-OS-Agent/Cargo.toml \
  --release --locked

BPF_CLANG=clang cargo \
  --config scheduler/rust/.cargo/config.toml \
  build --manifest-path scheduler/rust/Cargo.toml \
  --release --locked
~~~

产物为：

~~~text
Adaptive-OS-Agent/target/release/adaptive-os-agent
scheduler/rust/target/release/scx_adaptive
~~~

把二进制复制到另一台机器前，应执行 `ldd` 检查运行库。当前 x86_64 release 的
`scx_adaptive` 动态依赖 `libelf.so.1`、`libz.so.1`、`libgcc_s.so.1` 和 glibc；目标机
需要提供 ABI 兼容版本。最稳妥的方式是在目标机器本地构建。

若目标机器安装的是带版本名称的编译器：

~~~bash
BPF_CLANG=clang-17 cargo \
  --config scheduler/rust/.cargo/config.toml \
  build --manifest-path scheduler/rust/Cargo.toml \
  --release --locked
~~~

### 4. 先做无副作用校验

Agent 的 `--validate-only` 只解析和校验 TOML，不读取 API key，也不启动 scheduler：

~~~bash
Adaptive-OS-Agent/target/release/adaptive-os-agent \
  --config Adaptive-OS-Agent/configs/agent.example.toml \
  --validate-only
~~~

scheduler 的 `--validate-only` 发现本机 CPU/core/LLC 拓扑并校验内部参数，但不加载 BPF：

~~~bash
scheduler/rust/target/release/scx_adaptive --validate-only
~~~

这两条命令通过只能证明配置与拓扑可解析。真正的内核 ABI、BTF 和 verifier 兼容性要在
第一次受控启动时确认。

### 5. 配置运行模式

最小示例在 [agent.example.toml](Adaptive-OS-Agent/configs/agent.example.toml)。未写字段
使用源码中的受验证默认值，未知字段会被拒绝。

| 配置/选项 | 作用 |
| --- | --- |
| `scheduler_socket` | Agent 与 scheduler 的本地控制 socket，默认 `/run/scx_adaptive.sock` |
| `tool_socket` | 只读 Tool socket，默认 `/run/adaptive-os-agent-tools.sock` |
| `reconcile_interval_secs` | `/proc` 全量核对周期，默认 10 秒 |
| `behavior_window_secs` | 行为窗口和语义节拍，默认 1 秒 |
| `[deepseek]` | HTTPS endpoint、model、密钥位置、batch、worker 和 timeout |
| `[classification]` | 语义准入、行为确认与一次修正阈值 |
| `--offline` | 不访问远端语义服务，保留本地规则、行为证据和安全默认类 |
| `--snapshot-file PATH` | 原子写出最新 scheduler/Agent 观测快照 |
| `--debug` | 同时打开 Agent 与 scheduler child 的调试日志 |

#### 离线模式

离线模式不需要 API key，适合首次 attach、封闭网络或确定性诊断：

~~~bash
sudo Adaptive-OS-Agent/target/release/adaptive-os-agent \
  --offline \
  --config Adaptive-OS-Agent/configs/agent.example.toml \
  --scheduler-bin scheduler/rust/target/release/scx_adaptive
~~~

#### 在线语义模式

在线模式优先读取 `DEEPSEEK_API_KEY` 环境变量，也可以读取配置中
`deepseek.api_key_file` 指定的文件。使用示例配置时，在仓库根目录创建本机密钥文件：

~~~bash
umask 077
touch Adaptive-OS-Agent/configs/deepseek.env
chmod 0600 Adaptive-OS-Agent/configs/deepseek.env
read -r -s -p 'DEEPSEEK_API_KEY: ' AOA_DEEPSEEK_KEY
printf '\nDEEPSEEK_API_KEY=%s\n' "$AOA_DEEPSEEK_KEY" \
  > Adaptive-OS-Agent/configs/deepseek.env
unset AOA_DEEPSEEK_KEY
~~~

然后启动：

~~~bash
sudo Adaptive-OS-Agent/target/release/adaptive-os-agent \
  --config Adaptive-OS-Agent/configs/agent.example.toml \
  --scheduler-bin scheduler/rust/target/release/scx_adaptive
~~~

密钥不会写入 prompt、日志、Registry、scheduler snapshot 或测试报告。不要把
`deepseek.env` 提交到版本库。

### 6. 验证启动和正常退出

Agent 启动后会监管 scheduler，并只把通过安全准入的普通 `SCHED_OTHER` 用户线程送入
partial sched_ext 数据面。PID 1、内核线程、Agent、scheduler、RT 与 deadline 任务
保持 Linux 原生调度。

在另一个终端检查：

~~~bash
cat /sys/kernel/sched_ext/state
cat /sys/kernel/sched_ext/root/ops
ps -ef | grep -E 'adaptive-os-agent|scx_adaptive'
~~~

正常状态应为：

~~~text
state = enabled
ops   = scx_adaptive
~~~

前台运行时按 `Ctrl+C`，或向 Agent 发送 `SIGTERM`。不要直接对 scheduler 使用
`SIGKILL`。Agent 会停止新分类工作、关闭控制连接、请求 scheduler detach，并确认任务
回到 Linux 调度器。退出后检查：

~~~bash
cat /sys/kernel/sched_ext/state
~~~

预期值为 `disabled`。


## 二、本项目的本机 VM 性能测试

本节描述的是本项目当前用于比赛数据复现的实验室环境。它用于公平对比 Native 与
Agent，不是部署或运行 Agent 的前置条件。

~~~text
正式部署
  compatible Linux machine
       `-- Agent + scx_adaptive directly control this kernel

本机性能实验
  Ubuntu Host
       |-- CPU isolation / fixed frequency / libvirt
       |-- Native openEuler VM
       `-- Agent  openEuler VM
               `-- same template, workload and measurement window
~~~

### 7. 为什么测试使用独立 VM

每个 Native 或 Agent run 都从同一只读模板创建新的 qcow2 overlay。Host 固定 vCPU、
QEMU emulator、IRQ 和频率，Guest 内再运行相同真实应用。这样做是为了减少上一轮状态、
Host 调度、镜像写入和拓扑变化造成的噪声，而不是因为 Agent 只能在 Guest 中运行。

当前测试参数：

| 项目 | 本机实验值 |
| --- | --- |
| Host | 12 个在线逻辑 CPU，6 个完整 SMT 物理核 |
| Host 保留 CPU | 0-5，用于 Host、QEMU emulator 和 IRQ |
| Guest pin CPU | 6-11，对应 6 vCPU |
| Guest | openEuler 24.03 LTS-SP4 x86_64 |
| Guest kernel | 6.6.0-scx |
| Guest topology | 1 socket x 3 cores x 2 threads |
| Guest memory | 3 GiB |
| Host CPU 频率 | performance，3,300,000 kHz |
| workload warmup | 20 秒 |
| measurement | 60 秒 |
| 当前提交档位 | 1 组 Native/Agent 配对 |

详细测试实现见 [test/README.md](test/README.md) 与
[test/Design.md](test/Design.md)。

### 8. 安装本机测试专用依赖

以下命令只针对当前 Ubuntu/libvirt Host：

~~~bash
sudo apt-get update
sudo apt-get install -y \
  qemu-kvm qemu-utils libvirt-daemon-system libvirt-clients \
  dnsmasq-base python3 python3-yaml openssh-client tar \
  linux-tools-common linux-tools-generic

sudo systemctl enable --now libvirtd
sudo usermod -aG kvm,libvirt "$USER"
~~~

重新登录使组权限生效，然后检查：

~~~bash
id
test -r /dev/kvm
test -w /dev/kvm
virsh --connect qemu:///system list --all
virsh --connect qemu:///system net-info default
~~~

default network 尚未启动时：

~~~bash
sudo virsh net-start default
sudo virsh net-autostart default
~~~

### 9. 安装只读 Guest 模板、SSH key 和测试密钥

~~~bash
sudo install -d -m 0755 /var/lib/libvirt/images/aoa-lab
sudo install -m 0444 /path/to/template.qcow2 \
  /var/lib/libvirt/images/aoa-lab/template.qcow2

mkdir -p test/.local/ssh
install -m 0600 /path/to/test_ed25519 test/.local/ssh/test_ed25519

sha256sum /var/lib/libvirt/images/aoa-lab/template.qcow2
~~~

正式模板 SHA-256 必须为：

~~~text
f0ce5dab2fdb5c8eb7de515295c9967e10503f178f75cadcf7d02ec1ec530896
~~~

该值由 [scheduler/versions.lock](scheduler/versions.lock) 锁定。SSH 私钥必须与模板内
root 的 `authorized_keys` 匹配。

测试配置要求在线语义分类，因此还要准备：

~~~bash
umask 077
touch Adaptive-OS-Agent/configs/deepseek.env
chmod 0600 Adaptive-OS-Agent/configs/deepseek.env
read -r -s -p 'DEEPSEEK_API_KEY: ' AOA_DEEPSEEK_KEY
printf '\nDEEPSEEK_API_KEY=%s\n' "$AOA_DEEPSEEK_KEY" \
  > Adaptive-OS-Agent/configs/deepseek.env
unset AOA_DEEPSEEK_KEY
~~~

benchmark 只把该文件上传到当次 Agent Guest 的 `/run/aoa-secrets/`，不会写入报告。

### 10. 构建测试 payload

使用第一部分相同的 release 构建命令：

~~~bash
cargo build \
  --manifest-path Adaptive-OS-Agent/Cargo.toml \
  --release --locked

BPF_CLANG=clang-17 cargo \
  --config scheduler/rust/.cargo/config.toml \
  build --manifest-path scheduler/rust/Cargo.toml \
  --release --locked
~~~

测试模块回归：

~~~bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/tests -v
bash -n test/image/real_workloads/aoa-real-workload
python3 test/scripts/benchmark.py dynamic_mix --single-round --dry-run
~~~

### 11. 配置本机 CPU 隔离

当前 `test/config.yaml` 要求 online CPU 恰好为 `0-11`。先检查实际拓扑：

~~~bash
lscpu -e=CPU,CORE,SOCKET,ONLINE
cat /sys/devices/system/cpu/online
~~~

启用脚本会备份 `/etc/default/grub`，写入 `isolcpus=6-11`、`nohz_full=6-11`、
`rcu_nocbs=6-11` 和 `irqaffinity=0-5`：

~~~bash
sudo test/scripts/cpu_isolation.sh enable
sudo reboot
~~~

重启后确认：

~~~bash
cat /sys/devices/system/cpu/isolated
cat /sys/devices/system/cpu/nohz_full
cat /proc/cmdline
~~~

这组 CPU 编号只属于当前 benchmark 配置，不是 Agent 的通用运行要求。

### 12. 定频、预检和单轮配对

先保存 Host 原频率策略并锁定测试频率：

~~~bash
sudo test/scripts/set_cpu_frequency.sh
cpupower frequency-info
~~~

脚本把原状态保存到 `/var/tmp/aoa-test-cpu-frequency.state`。随后执行只读预检：

~~~bash
python3 test/scripts/check_env.py
~~~

预检会检查 KVM、libvirt network、模板 hash、CPU 分区、隔离参数、频率、release
payload、密钥权限和临时目录。

查看一组 Native/Agent RunSpec，不启动 VM：

~~~bash
python3 test/scripts/benchmark.py dynamic_mix --single-round --dry-run
~~~

运行当前提交使用的一轮完整配对：

~~~bash
python3 test/scripts/benchmark.py dynamic_mix --single-round
~~~

需要补充跨 repeat 离散程度时，可选运行 `config.yaml` 中的 3-pair profile：

~~~bash
python3 test/scripts/benchmark.py dynamic_mix --dry-run
python3 test/scripts/benchmark.py dynamic_mix
~~~

### 13. 报告与结果复算

每次 campaign 的展示报告只生成在本次输出目录：

~~~text
test/output/performance/<timestamp>/
|-- campaign.json
|-- preflight.json
|-- comparison.json
|-- summary.csv
|-- report.md
`-- runs/
    |-- <sequence>__r<repeat>__dynamic_mix__agent/
    `-- <sequence>__r<repeat>__dynamic_mix__native/
~~~

不启动 VM，只按当前分析代码复算已有数据：

~~~bash
python3 test/scripts/benchmark.py \
  --analyze-only test/output/performance/<timestamp>
~~~

最新有效单轮 campaign `20260730-144717-822781` 的结果为：

| 指标 | Native | Agent | Agent 改善 |
| --- | ---: | ---: | ---: |
| 聚合 P99 | 3,706.5 us | 1,851.0 us | 50.06% |
| 综合吞吐 | 51.211 units/s | 53.694 units/s | 4.85% |
| 平均 CPU | 80.91% | 80.63% | -0.28 pp |

该报告来自一组完整配对，因此不估计跨重复运行的置信区间。

### 14. 测试结束后的 Host 恢复

无论 benchmark 成功或失败，都恢复测试前的频率策略：

~~~bash
sudo test/scripts/restore_cpu_frequency.sh
~~~

不再需要该实验分区时，恢复 GRUB 并重启：

~~~bash
sudo test/scripts/cpu_isolation.sh disable
sudo reboot
~~~

这些 Host 操作只服务于可重复性能测量，不应在普通 Agent 部署机器上执行。

## 进一步阅读

- [总体设计](Design.md)
- [Agent README](Adaptive-OS-Agent/README.md)
- [Agent 设计](Adaptive-OS-Agent/Design.md)
- [scheduler README](scheduler/README.md)
- [scheduler 设计](scheduler/Design.md)
- [测试 README](test/README.md)
- [测试设计](test/Design.md)
