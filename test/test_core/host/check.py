from __future__ import annotations

"""只读的正式性能实验预检查。

测试程序不修改 GRUB、CPU 频率或 libvirt 配置；这些状态由操作者在启动
campaign 前准备好。本模块只确认配置已经生效，确认失败时不启动 VM。
"""

import hashlib
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path

import yaml

from test_core.config.parser import parse_cpu_list
from test_core.models import CheckResult, RunSpec


def check_template_integrity(
    specs: Sequence[RunSpec], versions_lock: str | Path
) -> CheckResult:
    failures: list[str] = []
    infos: list[str] = []
    images = {Path(spec.libvirt["template_image"]).resolve() for spec in specs}
    if len(images) != 1:
        failures.append(
            "campaign must reference exactly one template image: "
            f"{sorted(map(str, images))}"
        )
        return CheckResult(tuple(failures), tuple(infos))

    expected = _locked_template_sha256(Path(versions_lock), failures)
    if expected is None:
        return CheckResult(tuple(failures), tuple(infos))

    image = next(iter(images))
    try:
        actual, before, after = _sha256_regular_file(image)
    except OSError as exc:
        failures.append(f"cannot hash template image {image}: {exc}")
        return CheckResult(tuple(failures), tuple(infos))

    if stat.S_IMODE(before.st_mode) & 0o222:
        failures.append(f"template image must be read-only: {image}")
    if _file_identity(before) != _file_identity(after):
        failures.append(f"template image changed while hashing: {image}")
    if actual != expected:
        failures.append(
            f"template image SHA-256 mismatch: {image} "
            f"(expected={expected}, actual={actual})"
        )
    else:
        infos.append(f"template image SHA-256 verified: {actual} ({image})")
    return CheckResult(tuple(failures), tuple(infos))


def check_host(spec: RunSpec) -> CheckResult:
    failures: list[str] = []
    infos: list[str] = []
    libvirt = spec.libvirt

    _check_path(Path(libvirt["template_image"]), "libvirt.template_image", failures)
    _check_path(Path(libvirt["ssh_key"]), "libvirt.ssh_key", failures)
    _check_runtime_dir(Path(libvirt["runtime_dir"]), failures, infos)

    for command in ("virsh", "qemu-img", "ssh", "scp", "tar", "cpupower"):
        if not shutil.which(command):
            failures.append(f"missing command: {command}")

    kvm = Path("/dev/kvm")
    if kvm.exists() and os.access(kvm, os.R_OK | os.W_OK):
        infos.append("/dev/kvm is accessible")
    elif kvm.exists():
        failures.append("/dev/kvm exists but is not accessible")
    else:
        failures.append("missing /dev/kvm")

    _check_libvirt(spec, failures, infos)
    _check_cpu_partition(spec, failures, infos)
    _check_frequency(spec, failures, infos)
    _check_selected_payloads(spec, failures)
    infos.append(f"selected scheduler: {spec.scheduler_name}")
    return CheckResult(tuple(failures), tuple(infos))


def _locked_template_sha256(path: Path, failures: list[str]) -> str | None:
    try:
        with path.open("r", encoding="utf-8") as stream:
            data = yaml.safe_load(stream)
    except (OSError, yaml.YAMLError) as exc:
        failures.append(f"cannot read versions lock {path}: {exc}")
        return None
    target = data.get("target") if isinstance(data, dict) else None
    expected = target.get("template_sha256") if isinstance(target, dict) else None
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        failures.append(f"invalid target.template_sha256 in versions lock: {path}")
        return None
    return expected


def _sha256_regular_file(path: Path) -> tuple[str, os.stat_result, os.stat_result]:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise OSError("not a regular file")
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
        after = os.fstat(stream.fileno())
    return digest.hexdigest(), before, after


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _check_path(path: Path, label: str, failures: list[str]) -> None:
    if not path.exists():
        failures.append(f"missing {label}: {path}")


def _check_runtime_dir(path: Path, failures: list[str], infos: list[str]) -> None:
    if path.exists():
        if not os.access(path, os.W_OK):
            failures.append(f"runtime_dir is not writable: {path}")
        if any(path.iterdir()):
            failures.append(f"runtime_dir is not empty; remove stale runs: {path}")
        else:
            infos.append(f"runtime_dir is ready: {path}")
        return
    if path.parent.exists() and os.access(path.parent, os.W_OK):
        infos.append(f"runtime_dir can be created under: {path.parent}")
    else:
        failures.append(f"runtime_dir parent is not writable: {path.parent}")


def _check_libvirt(spec: RunSpec, failures: list[str], infos: list[str]) -> None:
    uri = str(spec.libvirt.get("uri", "qemu:///system"))
    domains = _virsh(uri, ["list", "--all", "--name"])
    if domains is None:
        failures.append(f"cannot connect to libvirt: {uri}")
        return
    stale = [name for name in domains.splitlines() if name.startswith("test-")]
    if stale:
        failures.append(f"stale test domains exist: {stale}")
    network = str(spec.libvirt.get("network", "default"))
    active_networks = _virsh(uri, ["net-list", "--name"])
    if active_networks is None or network not in active_networks.splitlines():
        failures.append(f"libvirt network is not active: {network}")
    else:
        infos.append(f"libvirt and network are ready: {uri}/{network}")


def _virsh(uri: str, args: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            ["virsh", "--connect", uri, *args],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "LC_ALL": "C"},
        )
    except OSError:
        return None
    return completed.stdout.strip() if completed.returncode == 0 else None


def _check_cpu_partition(spec: RunSpec, failures: list[str], infos: list[str]) -> None:
    initial_failures = len(failures)
    machine = spec.machine
    guest = set(parse_cpu_list(machine["pin_cpus"]))
    emulator = set(parse_cpu_list(machine["emulator_cpus"]))
    online = _read_cpu_set(Path("/sys/devices/system/cpu/online"))

    for label, cpus in (("Guest vCPU", guest), ("QEMU emulator", emulator)):
        missing = sorted(cpus - online)
        if missing:
            failures.append(f"{label} CPUs are not online: {missing}")
    if guest & emulator:
        failures.append(f"Guest and emulator CPU sets overlap: {sorted(guest & emulator)}")
    if guest | emulator != online:
        failures.append(
            "Guest and emulator CPU sets must cover all online CPUs "
            f"(online={_format_cpus(online)}, assigned={_format_cpus(guest | emulator)})"
        )

    guest_cores = _core_map(guest)
    emulator_cores = _core_map(emulator)
    if None in guest_cores or None in emulator_cores:
        failures.append("cannot read physical CPU topology")
        return
    if len(guest_cores) != 3 or len(emulator_cores) != 3:
        failures.append(
            f"expected three physical cores per side; Guest={len(guest_cores)}, "
            f"emulator={len(emulator_cores)}"
        )
    shared = guest_cores & emulator_cores
    if shared:
        failures.append(f"Guest and emulator share physical cores: {sorted(shared)}")
    _check_complete_cores("Guest", guest, guest_cores, failures)
    _check_complete_cores("emulator", emulator, emulator_cores, failures)

    isolated = _read_cpu_set(Path("/sys/devices/system/cpu/isolated"))
    if guest - isolated:
        failures.append(f"Guest CPUs are not isolated: {sorted(guest - isolated)}")
    if isolated - guest:
        failures.append(f"unexpected isolated CPUs: {sorted(isolated - guest)}")
    nohz_full = _read_cpu_set(Path("/sys/devices/system/cpu/nohz_full"))
    if guest - nohz_full:
        failures.append(f"Guest CPUs are not in nohz_full: {sorted(guest - nohz_full)}")

    cmdline = _read_text(Path("/proc/cmdline")) or ""
    rcu_nocbs = _kernel_cpu_argument(cmdline, "rcu_nocbs")
    if rcu_nocbs is None or guest - rcu_nocbs:
        failures.append("kernel cmdline must set rcu_nocbs for all Guest CPUs")
    irq_affinity = _kernel_cpu_argument(cmdline, "irqaffinity")
    if irq_affinity is None or not emulator <= irq_affinity or irq_affinity & guest:
        failures.append("kernel cmdline irqaffinity must target only Host CPUs")
    if len(failures) == initial_failures:
        infos.append(
            f"CPU partition ready: Guest={_format_cpus(guest)}, "
            f"Host={_format_cpus(emulator)}"
        )


def _check_complete_cores(
    label: str,
    cpus: set[int],
    cores: set[tuple[int, int] | None],
    failures: list[str],
) -> None:
    for core in cores:
        if core is None:
            continue
        members = {
            cpu for cpu in cpus if _physical_core(cpu) == core
        }
        siblings = _thread_siblings(next(iter(members))) if members else set()
        if members != siblings:
            failures.append(
                f"{label} must own complete SMT core {core}; "
                f"assigned={sorted(members)}, siblings={sorted(siblings)}"
            )


def _check_frequency(spec: RunSpec, failures: list[str], infos: list[str]) -> None:
    initial_failures = len(failures)
    machine = spec.machine
    frequency = machine["frequency"]
    expected_governor = str(frequency["governor"])
    expected_khz = str(frequency["khz"])
    cpus = sorted(
        set(parse_cpu_list(machine["pin_cpus"]))
        | set(parse_cpu_list(machine["emulator_cpus"]))
    )
    for cpu in cpus:
        root = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq")
        governor = _read_text(root / "scaling_governor")
        minimum = _read_text(root / "scaling_min_freq")
        maximum = _read_text(root / "scaling_max_freq")
        if governor != expected_governor or minimum != expected_khz or maximum != expected_khz:
            failures.append(
                f"cpu{cpu} frequency policy mismatch "
                f"(governor={governor!r}, min={minimum!r}, max={maximum!r}; "
                f"expected={expected_governor}/{expected_khz})"
            )
    if len(failures) == initial_failures:
        infos.append(f"frequency policy ready: {expected_governor} at {expected_khz} kHz")


def _check_selected_payloads(spec: RunSpec, failures: list[str]) -> None:
    for item in spec.benchmark.get("files", []) or []:
        source = Path(item["source"])
        if not source.is_file():
            failures.append(f"missing benchmark payload: {source}")
    scheduler = spec.scheduler
    if scheduler.get("kind") == "builtin":
        return
    targets: set[str] = set()
    for item in scheduler.get("files", []) or []:
        source = Path(item["source"])
        targets.add(str(item["target"]))
        if not source.is_file():
            failures.append(f"missing scheduler payload: {source}")
    command = str(scheduler.get("command", ""))
    if command not in targets:
        failures.append(f"selected scheduler command is not supplied by files: {command}")
    for item in scheduler.get("secret_files", []) or []:
        source = Path(item["source"])
        if not source.is_file():
            failures.append(f"missing local Agent secret file: {source}")
            continue
        if stat.S_IMODE(source.stat().st_mode) & 0o077:
            failures.append(f"Agent secret file must not be group/world accessible: {source}")
        name = str(item["required_env"])
        if not _env_value(source, name):
            failures.append(f"fill {name} in local Agent secret file: {source}")


def _env_value(path: Path, name: str) -> str | None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for raw in lines:
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            if key.strip() == name:
                return value.strip().strip("'\"") or None
    return None


def _read_cpu_set(path: Path) -> set[int]:
    text = _read_text(path)
    if not text or text in {"(null)", "null"}:
        return set()
    try:
        return set(parse_cpu_list(text))
    except ValueError:
        return set()


def _kernel_cpu_argument(cmdline: str, name: str) -> set[int] | None:
    match = re.search(rf"(?:^|\s){re.escape(name)}=([^\s]+)", cmdline)
    if not match:
        return None
    try:
        return set(parse_cpu_list(match.group(1)))
    except ValueError:
        return None


def _core_map(cpus: set[int]) -> set[tuple[int, int] | None]:
    return {_physical_core(cpu) for cpu in cpus}


def _physical_core(cpu: int) -> tuple[int, int] | None:
    package = _read_text(
        Path(f"/sys/devices/system/cpu/cpu{cpu}/topology/physical_package_id")
    )
    core = _read_text(Path(f"/sys/devices/system/cpu/cpu{cpu}/topology/core_id"))
    try:
        return int(package), int(core)
    except (TypeError, ValueError):
        return None


def _thread_siblings(cpu: int) -> set[int]:
    return _read_cpu_set(
        Path(f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list")
    )


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _format_cpus(cpus: set[int]) -> str:
    return ",".join(str(cpu) for cpu in sorted(cpus))
