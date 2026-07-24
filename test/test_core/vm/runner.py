from __future__ import annotations

import hashlib
import json
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from test_core.benchmark.guest import write_guest_script
from test_core.config.parser import parse_cpu_list
from test_core.models import RunSpec
from test_core.vm.domain import build_domain_xml, domain_name
from test_core.vm.overlay import create_overlay
from test_core.vm.ssh import BootTimeout, SSHError, download_guest_dir, run_ssh, scp_to_guest, wait_for_ssh


def run_one(
    spec: RunSpec,
    *,
    output_dir: str | Path,
) -> dict[str, Any]:
    run_dir = Path(output_dir)
    run_dir.mkdir(parents=True, exist_ok=False)
    unique = hashlib.sha256(str(run_dir.resolve()).encode()).hexdigest()[:8]
    domain = domain_name(spec, unique)
    runtime_dir = Path(spec.libvirt["runtime_dir"]) / domain
    overlay = runtime_dir / "disk.qcow2"
    guest_script = run_dir / "run_guest.sh"
    domain_xml = run_dir / "domain.xml"

    write_guest_script(guest_script, spec)
    domain_xml.write_text(build_domain_xml(spec, domain, overlay), encoding="utf-8")

    metadata: dict[str, Any] = {
        "status": "RUNNING",
        "failed_phase": None,
        "domain": domain,
        "run_dir": str(run_dir),
        "runtime_dir": str(runtime_dir),
        "overlay": str(overlay),
        "spec": _spec_payload(spec),
        "payloads": [],
        "started_at": _now(),
    }
    status = "FAIL"
    failed_phase: str | None = "prepare"
    error: str | None = None
    returncode: int | None = None
    host: str | None = None
    try:
        metadata["payloads"] = _payload_manifest(_payloads(spec))
        failed_phase = "overlay"
        create_overlay(spec.libvirt["template_image"], overlay)
        failed_phase = "boot"
        _virsh(spec.libvirt, ["define", str(domain_xml)])
        _virsh(spec.libvirt, ["start", domain])
        _verify_live_domain(spec, domain)
        host, _ = wait_for_ssh(spec.libvirt, domain, int(spec.libvirt.get("boot_timeout_seconds", 90)))
        print(f"guest ip: {host}", flush=True)
        print(f"guest ssh: {_ssh_hint(spec.libvirt, host)}", flush=True)

        failed_phase = "upload"
        _sync_payloads(spec, host)
        _sync_secret_files(spec, host)
        scp_to_guest(spec.libvirt, host, guest_script, "/tmp/test-run.sh")
        run_ssh(spec.libvirt, host, "chmod +x /tmp/test-run.sh")

        failed_phase = "agent_run"
        completed = run_ssh(
            spec.libvirt,
            host,
            "/tmp/test-run.sh",
            check=False,
            timeout=_guest_timeout(spec),
        )
        returncode = completed.returncode
        (run_dir / "guest_ssh.stdout").write_text(completed.stdout, encoding="utf-8", errors="replace")
        (run_dir / "guest_ssh.stderr").write_text(completed.stderr, encoding="utf-8", errors="replace")

        failed_phase = "download"
        download_guest_dir(spec.libvirt, host, spec.libvirt["guest_output_dir"], run_dir)
        guest_result_path = run_dir / "guest_result.json"
        guest_result = _read_json(guest_result_path)
        guest_result_path.unlink(missing_ok=True)
        status, failed_phase = _status_from_guest(returncode, guest_result)
        metadata["guest_result"] = guest_result
    except subprocess.TimeoutExpired as exc:
        status, failed_phase, error = "TIMEOUT", failed_phase or "agent_run", str(exc)
    except BootTimeout as exc:
        status, failed_phase, error = "FAIL", "boot", str(exc)
    except SSHError as exc:
        status, error = "FAIL", str(exc)
    except subprocess.CalledProcessError as exc:
        status, error = "FAIL", _called_process_error_text(exc)
    except Exception as exc:  # noqa: BLE001
        status, error = "FAIL", str(exc)
    finally:
        cleanup_errors = _cleanup_vm(spec.libvirt, domain, runtime_dir)
        if cleanup_errors:
            status = "FAIL"
            failed_phase = "cleanup"
            cleanup_text = "; ".join(cleanup_errors)
            error = f"{error}; {cleanup_text}" if error else cleanup_text

    metadata.update(
        {
            "status": status,
            "failed_phase": failed_phase,
            "returncode": returncode,
            "guest_host": host,
            "ssh_command": _ssh_hint(spec.libvirt, host) if host else None,
            "error": error,
            "finished_at": _now(),
        }
    )
    _write_json(run_dir / "result.json", metadata)
    return metadata


def _status_from_guest(returncode: int | None, result: dict[str, Any]) -> tuple[str, str | None]:
    checks = result.get("checks", {})
    if (
        returncode == 0
        and result.get("benchmark") is True
        and result.get("valid") is True
        and isinstance(checks, dict)
        and checks
        and all(value == 0 for value in checks.values())
    ):
        return "PASS", None
    if returncode == 124:
        return "TIMEOUT", "agent_run"
    failed = (
        next((name for name, value in checks.items() if value != 0), "guest_result")
        if isinstance(checks, dict)
        else "guest_result"
    )
    return "FAIL", failed


def _sync_payloads(spec: RunSpec, host: str) -> None:
    for item in _payloads(spec):
        source = Path(item["source"])
        target = str(item["target"])
        parent = str(Path(target).parent)
        run_ssh(spec.libvirt, host, f"mkdir -p {shlex.quote(parent)}")
        scp_to_guest(spec.libvirt, host, source, target)
        if item.get("executable", False):
            run_ssh(spec.libvirt, host, f"chmod +x {shlex.quote(target)}")


def _sync_secret_files(spec: RunSpec, host: str) -> None:
    for item in spec.scheduler.get("secret_files", []) or []:
        source = Path(item["source"])
        target = str(item["target"])
        parent = str(Path(target).parent)
        run_ssh(spec.libvirt, host, f"install -d -m 700 {shlex.quote(parent)}")
        scp_to_guest(spec.libvirt, host, source, target)
        run_ssh(spec.libvirt, host, f"chmod 600 {shlex.quote(target)}")


def _payloads(spec: RunSpec) -> list[dict[str, Any]]:
    payloads = [dict(item) for item in spec.scheduler.get("files", []) or []]
    payloads.extend(dict(item) for item in spec.benchmark.get("files", []) or [])
    return payloads


def _guest_timeout(spec: RunSpec) -> int:
    return (
        int(spec.benchmark["warmup_seconds"])
        + int(spec.benchmark["measurement_seconds"])
        + int(spec.benchmark["cooldown_seconds"])
        + int(spec.scheduler.get("warmup_seconds", 0))
        + int(spec.libvirt.get("vm_warmup_seconds", 0))
        + int(spec.scheduler.get("timeout_extra_seconds", 30))
        + 120
        + 30
    )


def _cleanup_vm(libvirt: dict[str, Any], domain: str, runtime_dir: Path) -> list[str]:
    uri = str(libvirt.get("uri", "qemu:///system"))
    subprocess.run(["virsh", "--connect", uri, "destroy", domain], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    subprocess.run(["virsh", "--connect", uri, "undefine", domain], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    domains = subprocess.run(
        ["virsh", "--connect", uri, "list", "--all", "--name"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    errors: list[str] = []
    if domains.returncode != 0:
        errors.append(f"cannot verify libvirt cleanup: {domains.stderr.strip()}")
        return errors
    if domain in domains.stdout.splitlines():
        errors.append(f"libvirt domain still exists: {domain}")
        return errors
    shutil.rmtree(runtime_dir, ignore_errors=True)
    if runtime_dir.exists():
        errors.append(f"runtime directory still exists: {runtime_dir}")
    return errors


def _virsh(libvirt: dict[str, Any], args: list[str]) -> subprocess.CompletedProcess[str]:
    command = ["virsh", "--connect", str(libvirt.get("uri", "qemu:///system")), *args]
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if completed.returncode:
        raise subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
    return completed


def _verify_live_domain(spec: RunSpec, domain: str) -> None:
    xml = _virsh(spec.libvirt, ["dumpxml", domain]).stdout
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise RuntimeError(f"libvirt returned invalid live domain XML: {exc}") from exc

    machine = spec.machine
    expected_pins = parse_cpu_list(machine["pin_cpus"])
    actual_pins: dict[int, set[int]] = {}
    for item in root.findall("./cputune/vcpupin"):
        actual_pins[int(item.attrib["vcpu"])] = set(
            parse_cpu_list(item.attrib["cpuset"])
        )
    expected = {index: {cpu} for index, cpu in enumerate(expected_pins)}
    if actual_pins != expected:
        raise RuntimeError(f"libvirt vCPU pin mismatch: expected={expected}, actual={actual_pins}")

    emulator = root.find("./cputune/emulatorpin")
    actual_emulator = parse_cpu_list(emulator.attrib["cpuset"]) if emulator is not None else []
    expected_emulator = parse_cpu_list(machine["emulator_cpus"])
    if actual_emulator != expected_emulator:
        raise RuntimeError(
            f"libvirt emulator pin mismatch: expected={expected_emulator}, "
            f"actual={actual_emulator}"
        )

    topology = root.find("./cpu/topology")
    expected_topology = machine["topology"]
    actual_topology = (
        {key: int(topology.attrib[key]) for key in ("sockets", "cores", "threads")}
        if topology is not None
        else None
    )
    if actual_topology != expected_topology:
        raise RuntimeError(
            f"libvirt Guest topology mismatch: expected={expected_topology}, "
            f"actual={actual_topology}"
        )

    expected_features = set(spec.libvirt.get("required_cpu_features", []))
    actual_features = {
        item.attrib.get("name")
        for item in root.findall("./cpu/feature")
        if item.attrib.get("policy") == "require"
    }
    if not expected_features.issubset(actual_features):
        raise RuntimeError(
            "libvirt required CPU feature mismatch: "
            f"expected={sorted(expected_features)}, actual={sorted(actual_features)}"
        )

    serial = root.find("./sysinfo/system/entry[@name='serial']")
    expected_serial = f"aoa-profile-{spec.benchmark['scenario']}"
    if serial is None or serial.text != expected_serial:
        raise RuntimeError(
            f"libvirt workload profile mismatch: expected={expected_serial}, "
            f"actual={serial.text if serial is not None else None}"
        )

    disk_driver = root.find("./devices/disk/driver")
    if disk_driver is None or disk_driver.attrib.get("discard") != "unmap":
        raise RuntimeError("libvirt benchmark disk must use discard=unmap")


def _spec_payload(spec: RunSpec) -> dict[str, Any]:
    scheduler = {
        key: value
        for key, value in spec.scheduler.items()
        if key not in {"files", "secret_files"}
    }
    benchmark = {
        key: value for key, value in spec.benchmark.items() if key != "files"
    }
    return {
        "case_name": spec.case_name,
        "machine_name": spec.machine_name,
        "scheduler_name": spec.scheduler_name,
        "machine": spec.machine,
        "scheduler": scheduler,
        "workload": spec.workload,
        "config_path": str(spec.config_path),
        "benchmark": benchmark,
    }


def _payload_manifest(files: Any) -> list[dict[str, Any]]:
    manifest = []
    for item in files or []:
        source = Path(item["source"])
        manifest.append(
            {
                "source": str(source),
                "target": str(item["target"]),
                "sha256": _sha256(source) if source.is_file() else None,
            }
        )
    return manifest


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _called_process_error_text(exc: subprocess.CalledProcessError) -> str:
    return (
        f"command failed rc={exc.returncode}: {exc.cmd}\n"
        f"stdout:\n{exc.output or ''}\n"
        f"stderr:\n{exc.stderr or ''}"
    )


def _ssh_hint(libvirt: dict[str, Any], host: str) -> str:
    command = [
        "ssh", "-i", str(libvirt["ssh_key"]), "-p", str(libvirt.get("ssh_port", 22)),
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        f"{libvirt['ssh_user']}@{host}",
    ]
    return shlex.join(command)
