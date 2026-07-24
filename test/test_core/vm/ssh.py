from __future__ import annotations

"""SSH/SCP 传输工具。

VM 启动后，Host 和 Guest 之间所有控制动作都通过 SSH 完成：

1. 等待 Guest 拿到 IP；
2. 用 ssh true 判断 sshd 是否已经可登录；
3. scp 上传 run_guest.sh 和 Guest 工具；
4. ssh 执行 run_guest.sh；
5. 下载 /bench_out。

这里单独封装 SSH 的原因是：SSH 是 VM 测试中最容易因为时序、host key、
端口参数出问题的部分，集中处理更容易调试。
"""

import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any


class BootTimeout(RuntimeError):
    """VM 在规定时间内没有变成 SSH 可登录时抛出。"""


class SSHError(RuntimeError):
    """SSH 或 SCP 传输失败时抛出。"""


_DOWNLOAD_PROBE_TIMEOUT_SECONDS = 30
_DOWNLOAD_TRANSFER_TIMEOUT_SECONDS = 120


def wait_for_ssh(libvirt: dict[str, Any], domain_name: str, timeout_seconds: int) -> tuple[str, int]:
    """等待 Guest 拿到 IP 并接受 SSH 登录。"""

    deadline = time.monotonic() + timeout_seconds
    last_error = "waiting for IP address"
    port = int(libvirt.get("ssh_port", 22))

    while time.monotonic() < deadline:
        # 优先使用配置里的固定 ssh_host；如果没有，就从 libvirt DHCP lease
        # 查询 VM 的 192.168.122.x 地址。
        host = libvirt.get("ssh_host") or _domain_ip(libvirt, domain_name)
        if host:
            try:
                # 单次 SSH 探测可能因为 sshd 正在启动而超时，不能因此直接
                # 判定整台 VM 失败；只要总时间没超过 deadline，就继续等。
                completed = run_ssh(libvirt, host, "true", check=False, timeout=8)
                if completed.returncode == 0:
                    return str(host), port
                last_error = completed.stderr.strip() or completed.stdout.strip() or "ssh probe failed"
            except subprocess.TimeoutExpired:
                last_error = f"ssh probe timed out for {host}"
        time.sleep(2)

    raise BootTimeout(f"SSH did not become ready for {domain_name}: {last_error}")


def run_ssh(
    libvirt: dict[str, Any],
    host: str,
    remote_command: str,
    *,
    check: bool = True,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    """通过 SSH 在 Guest 内执行一条命令。"""

    command = [
        *_ssh_base(libvirt, host),
        remote_command,
    ]
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )
    if check and completed.returncode != 0:
        raise SSHError(
            f"ssh command failed rc={completed.returncode}: {remote_command}\n{completed.stderr}"
        )
    return completed


def scp_to_guest(libvirt: dict[str, Any], host: str, local_path: str | Path, remote_path: str) -> None:
    """把 Host 本地文件或目录复制到 Guest。"""

    command = [
        "scp",
        "-r",
        *_scp_options(libvirt),
        str(local_path),
        f"{libvirt['ssh_user']}@{host}:{remote_path}",
    ]
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if completed.returncode != 0:
        raise SSHError(f"scp to guest failed rc={completed.returncode}: {completed.stderr}")


def download_guest_dir(libvirt: dict[str, Any], host: str, remote_dir: str, local_dir: str | Path) -> None:
    """下载 Guest 输出目录。

    优先使用 tar，因为它能更稳定地保留目录结构和文件内容。早期模板镜像
    缺少 tar，所以这里保留 scp -r 兜底路径，避免 Guest 没 tar 时整条
    流程完全不可用。
    """

    local = Path(local_dir)
    local.mkdir(parents=True, exist_ok=True)

    try:
        tar_available = (
            run_ssh(
                libvirt,
                host,
                "command -v tar >/dev/null 2>&1",
                check=False,
                timeout=_DOWNLOAD_PROBE_TIMEOUT_SECONDS,
            ).returncode
            == 0
        )
    except subprocess.TimeoutExpired:
        # A busy Guest can answer the probe slowly after the benchmark has
        # finished.  The directory is still downloadable through scp.
        tar_available = False

    if tar_available:
        ssh_proc = subprocess.Popen(
            [*_ssh_base(libvirt, host), f"tar -C {shlex.quote(remote_dir)} -cf - ."],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
        )
        tar_proc = subprocess.run(
            ["tar", "-xf", "-", "-C", str(local)],
            stdin=ssh_proc.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if ssh_proc.stdout is not None:
            ssh_proc.stdout.close()
        _, ssh_stderr = ssh_proc.communicate()
        if ssh_proc.returncode == 0 and tar_proc.returncode == 0:
            return

    command = [
        "scp",
        "-r",
        *_scp_options(libvirt),
        f"{libvirt['ssh_user']}@{host}:{remote_dir.rstrip('/')}/.",
        str(local),
    ]
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=_DOWNLOAD_TRANSFER_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise SSHError(f"download guest directory failed rc={completed.returncode}: {completed.stderr}")


def _domain_ip(libvirt: dict[str, Any], domain_name: str) -> str | None:
    # libvirt default 网络会给 VM 分配 DHCP 地址。domifaddr --source lease
    # 可以从租约里拿到 Guest IP。
    uri = libvirt.get("uri", "qemu:///system")
    completed = subprocess.run(
        ["virsh", "--connect", uri, "domifaddr", domain_name, "--source", "lease"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        return None

    for line in completed.stdout.splitlines():
        match = re.search(r"\b(\d+\.\d+\.\d+\.\d+)/\d+\b", line)
        if match:
            return match.group(1)
    return None


def _ssh_base(libvirt: dict[str, Any], host: str) -> list[str]:
    return [
        "ssh",
        *_ssh_options(libvirt),
        f"{libvirt['ssh_user']}@{host}",
    ]


def _ssh_options(libvirt: dict[str, Any]) -> list[str]:
    options = [
        "-i",
        str(libvirt["ssh_key"]),
        "-p",
        str(libvirt.get("ssh_port", 22)),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=5",
    ]
    return options


def _scp_options(libvirt: dict[str, Any]) -> list[str]:
    """返回 scp 使用的连接参数。

    注意：ssh 的端口参数是 -p，scp 的端口参数是 -P。二者不能混用。
    之前真实 smoke 测试失败过一次，就是因为 scp 误用了 -p。
    """

    return [
        "-i",
        str(libvirt["ssh_key"]),
        "-P",
        str(libvirt.get("ssh_port", 22)),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=5",
    ]
