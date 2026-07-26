from __future__ import annotations

"""libvirt domain XML 生成。

domain XML 是 libvirt 对一台 VM 的完整描述。test 不直接拼很长的
qemu-system-x86_64 命令，而是生成 XML，再交给 virsh define/start。

这里生成的是最小但够用的测试 VM：

1. 一个 qcow2 virtio 磁盘；
2. 一个 default libvirt 网络网卡；
3. host-passthrough CPU；
4. 显式 vCPU pinning；
5. 串口和随机数设备。
"""

import html
from pathlib import Path
from typing import Any

from test_core.config.parser import parse_cpu_list, parse_memory_mib
from test_core.models import RunSpec


def build_domain_xml(
    spec: RunSpec,
    domain_name: str,
    disk_path: str | Path,
    *,
    dynamic_ownership: bool = True,
) -> str:
    """为单条 run 生成 libvirt domain XML。

    XML 保持简单，是为了减少变量：测试调度器时，我们只需要稳定的 CPU、
    内存、磁盘和网络，不需要复杂设备。
    """

    libvirt = spec.libvirt
    machine = spec.machine
    memory_mib = parse_memory_mib(machine["memory"])
    vcpus = int(machine["vcpus"])
    pin_cpus = parse_cpu_list(machine["pin_cpus"])
    emulator_cpus = str(machine["emulator_cpus"])
    topology = machine["topology"]
    network = str(libvirt.get("network", "default"))
    cpu_mode = str(libvirt.get("cpu_mode", "host-passthrough"))
    required_cpu_features = list(libvirt.get("required_cpu_features", []))

    # vcpupin 把 Guest 的第 N 个 vCPU 固定到指定 Host CPU，减少 Host
    # 调度器把 QEMU vCPU 线程迁移到其他 CPU 带来的噪声。
    pins = "\n".join(
        f'    <vcpupin vcpu="{vcpu}" cpuset="{pin_cpus[vcpu]}"/>'
        for vcpu in range(vcpus)
    )

    escaped_name = html.escape(domain_name, quote=True)
    escaped_disk = html.escape(str(disk_path), quote=True)
    escaped_network = html.escape(network, quote=True)
    escaped_cpu_mode = html.escape(cpu_mode, quote=True)
    escaped_emulator = html.escape(emulator_cpus, quote=True)
    scenario = str(spec.benchmark.get("scenario", ""))
    profile = (
        scenario
        if scenario in {"latency", "throughput", "balanced", "mix"}
        else "idle"
    )
    escaped_profile_serial = html.escape(f"aoa-profile-{profile}", quote=True)
    cpu_features = "\n".join(
        f'    <feature policy="require" name="{html.escape(feature, quote=True)}"/>'
        for feature in required_cpu_features
    )
    if cpu_features:
        cpu_features = "\n" + cpu_features
    security_label = "" if dynamic_ownership else '  <seclabel type="none"/>\n'

    return f"""<domain type="kvm">
  <name>{escaped_name}</name>
  <memory unit="MiB">{memory_mib}</memory>
  <currentMemory unit="MiB">{memory_mib}</currentMemory>
  <vcpu placement="static">{vcpus}</vcpu>
  <cputune>
{pins}
    <emulatorpin cpuset="{escaped_emulator}"/>
  </cputune>
  <os>
    <type arch="x86_64">hvm</type>
    <boot dev="hd"/>
    <smbios mode="sysinfo"/>
  </os>
  <sysinfo type="smbios">
    <system>
      <entry name="manufacturer">AOA</entry>
      <entry name="product">real-workload-benchmark</entry>
      <entry name="serial">{escaped_profile_serial}</entry>
    </system>
  </sysinfo>
  <features>
    <acpi/>
    <apic/>
  </features>
  <cpu mode="{escaped_cpu_mode}" check="none">
    <topology sockets="{int(topology['sockets'])}" cores="{int(topology['cores'])}" threads="{int(topology['threads'])}"/>{cpu_features}
  </cpu>
  <clock offset="utc"/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <disk type="file" device="disk">
      <driver name="qemu" type="qcow2" cache="none" discard="unmap" detect_zeroes="unmap"/>
      <source file="{escaped_disk}"/>
      <target dev="vda" bus="virtio"/>
    </disk>
    <interface type="network">
      <source network="{escaped_network}"/>
      <model type="virtio"/>
    </interface>
    <serial type="pty">
      <target type="isa-serial" port="0"/>
    </serial>
    <console type="pty">
      <target type="serial" port="0"/>
    </console>
    <rng model="virtio">
      <backend model="random">/dev/urandom</backend>
    </rng>
  </devices>
{security_label}</domain>
"""


def domain_name(spec: RunSpec, unique_suffix: str) -> str:
    """生成 libvirt 可接受的短 domain 名称。"""

    raw = (
        f"test-{spec.scheduler_name}-{spec.machine_name}-"
        f"{spec.case_name}-{unique_suffix}"
    )
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in raw.lower())
    suffix = "-" + unique_suffix.lower()
    prefix = safe.removesuffix(suffix)
    prefix_limit = max(1, 63 - len(suffix))
    return (prefix[:prefix_limit].rstrip("-") + suffix)[:63].strip("-")
