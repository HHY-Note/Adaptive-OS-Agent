#!/usr/bin/env python3
"""Prepare a standalone candidate image containing the real benchmark apps.

The canonical template is never mounted or written directly.  Installation runs
inside a disposable qcow2 overlay, which is flattened into the requested output
only after the Guest has shut down cleanly.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

TEST_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = TEST_ROOT.parent
if str(TEST_ROOT) not in sys.path:
    sys.path.insert(0, str(TEST_ROOT))

from test_core.config.parser import load_config
from test_core.models import RunSpec
from test_core.vm.domain import build_domain_xml, domain_name
from test_core.vm.overlay import create_overlay
from test_core.vm.ssh import SSHError, run_ssh, scp_to_guest, wait_for_ssh


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/tmp/aoa-real-workloads-template.qcow2"),
        help="standalone qcow2 candidate path",
    )
    parser.add_argument(
        "--base-image",
        type=Path,
        help="optional qcow2 base for resuming from a retained disposable build layer",
    )
    parser.add_argument(
        "--download-cache",
        type=Path,
        help="optional host directory containing the five source archives",
    )
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    if args.timeout_seconds < 60:
        parser.error("--timeout-seconds must be at least 60")

    config = load_config(TEST_ROOT / "config.yaml", base_dir=REPO_ROOT)
    spec = _build_spec(config)

    output = args.output.expanduser().resolve()
    if output.exists() and not args.force:
        parser.error(f"candidate already exists: {output}; use --force to replace it")
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.base_image is not None:
        base_image = args.base_image.expanduser().resolve()
        if not base_image.is_file():
            parser.error(f"base image does not exist: {base_image}")
        spec.libvirt["template_image"] = str(base_image)
    workdir = Path(tempfile.mkdtemp(prefix="aoa-image-build-", dir="/tmp"))
    # libvirt launches QEMU as an unprivileged service account.  The build
    # overlay is the only temporary path it needs to traverse and modify.
    workdir.chmod(0o755)
    overlay = workdir / "disk.qcow2"
    xml_path = workdir / "domain.xml"
    domain = domain_name(spec, workdir.name.rsplit("-", 1)[-1][:8])
    candidate_tmp = output.with_name(f".{output.name}.partial")
    uri = str(spec.libvirt.get("uri", "qemu:///system"))
    domain_defined = False
    success = False

    try:
        create_overlay(spec.libvirt["template_image"], overlay)
        overlay.chmod(0o666)
        xml_path.write_text(build_domain_xml(spec, domain, overlay), encoding="utf-8")
        _virsh(uri, ["define", str(xml_path)])
        domain_defined = True
        _virsh(uri, ["start", domain])
        host, _port = wait_for_ssh(spec.libvirt, domain, int(spec.libvirt["boot_timeout_seconds"]))
        source = TEST_ROOT / "image" / "real_workloads"
        run_ssh(spec.libvirt, host, "rm -rf /tmp/aoa-real-workloads-image")
        scp_to_guest(spec.libvirt, host, source, "/tmp/aoa-real-workloads-image")
        if args.download_cache is not None:
            _upload_download_cache(spec.libvirt, host, args.download_cache)
        completed = run_ssh(
            spec.libvirt,
            host,
            "bash /tmp/aoa-real-workloads-image/install.sh",
            check=False,
            timeout=args.timeout_seconds,
        )
        (workdir / "install.stdout").write_text(completed.stdout, encoding="utf-8", errors="replace")
        (workdir / "install.stderr").write_text(completed.stderr, encoding="utf-8", errors="replace")
        if completed.returncode != 0:
            raise RuntimeError(f"Guest installer failed with rc={completed.returncode}")
        _verify_install(spec.libvirt, host)
        run_ssh(spec.libvirt, host, "sync && fstrim -av && sync", timeout=120)
        run_ssh(spec.libvirt, host, "shutdown -h now", check=False)
        _wait_for_shutdown(uri, domain, timeout_seconds=120)
        _virsh(uri, ["undefine", domain])
        domain_defined = False
        subprocess.run(
            ["qemu-img", "convert", "-O", "qcow2", str(overlay), str(candidate_tmp)],
            check=True,
        )
        candidate_tmp.replace(output)
        _write_manifest(output, spec)
        success = True
        print(f"candidate image: {output}")
        return 0
    except (SSHError, subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"image build failed: {exc}", file=sys.stderr)
        print(f"build logs retained: {workdir}", file=sys.stderr)
        return 1
    finally:
        if domain_defined:
            subprocess.run(["virsh", "--connect", uri, "destroy", domain], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            subprocess.run(["virsh", "--connect", uri, "undefine", domain], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        candidate_tmp.unlink(missing_ok=True)
        if success:
            shutil.rmtree(workdir, ignore_errors=True)


def _build_spec(config: dict[str, Any]) -> RunSpec:
    machine_name = str(config["performance"]["machine"])
    return RunSpec(
        case_name="image-build",
        machine_name=machine_name,
        scheduler_name="default",
        machine=dict(config["machines"][machine_name]),
        scheduler=dict(config["schedulers"]["default"]),
        libvirt=dict(config["libvirt"]),
        workload={},
        config_path=Path(config["__config_path"]),
        benchmark={"scenario": "image-build"},
    )


def _virsh(uri: str, arguments: list[str]) -> None:
    completed = subprocess.run(
        ["virsh", "--connect", uri, *arguments], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    if completed.returncode:
        raise RuntimeError(f"virsh {' '.join(arguments)} failed: {completed.stderr.strip()}")


def _wait_for_shutdown(uri: str, domain: str, *, timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        completed = subprocess.run(
            ["virsh", "--connect", uri, "domstate", domain], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
        )
        if completed.returncode == 0 and "shut off" in completed.stdout:
            return
        time.sleep(1)
    raise RuntimeError(f"Guest did not shut down within {timeout_seconds}s: {domain}")


def _verify_install(libvirt: dict[str, Any], host: str) -> None:
    command = " && ".join(
        (
            "test -x /usr/local/sbin/aoa-real-workload",
            "test -x /usr/local/libexec/aoa-summarize-workloads",
            "test -x /opt/aoa-workloads/bin/memtier_benchmark",
            "test -x /opt/aoa-workloads/bin/wrk2",
            "test -x /opt/aoa-workloads/bin/nats-server",
            "test -x /opt/aoa-workloads/bin/nats",
            "systemctl is-enabled aoa-real-workload-autostart.service",
            "redis-server --version >/dev/null",
            "pgbench --version >/dev/null",
            "/opt/aoa-workloads/bin/db_bench --version >/dev/null",
            "ffmpeg -version >/dev/null",
            "magick -version >/dev/null",
            "/usr/local/sbin/aoa-real-workload --from-dmi",
        )
    )
    run_ssh(libvirt, host, command, timeout=60)


def _upload_download_cache(
    libvirt: dict[str, Any], host: str, cache_dir: Path
) -> None:
    cache = cache_dir.expanduser().resolve()
    names = (
        "memtier.tar.gz",
        "wrk2.tar.gz",
        "nats-server.tar.gz",
        "nats.zip",
        "rocksdb.tar.gz",
    )
    missing = [name for name in names if not (cache / name).is_file()]
    if missing:
        raise RuntimeError(f"download cache is missing: {missing}")
    remote = "/var/tmp/aoa-workload-downloads"
    run_ssh(libvirt, host, f"install -d -m 0755 {remote}")
    for name in names:
        scp_to_guest(libvirt, host, cache / name, f"{remote}/{name}")


def _write_manifest(output: Path, spec: RunSpec) -> None:
    payload = {
        "schema_version": 1,
        "image": str(output),
        "template": str(spec.libvirt["template_image"]),
        "built_at": time.time(),
        "workloads": [
            "redis", "memcached", "nginx", "postgresql", "nats", "etcd",
            "ffmpeg", "rocksdb", "zstd", "openssl", "imagemagick", "memtier-build",
        ],
    }
    output.with_suffix(output.suffix + ".manifest.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    raise SystemExit(main())
