#!/bin/sh
set -eu

ACTION=${1:-}
case "$ACTION" in
    enable|disable) ;;
    *) echo "usage: sudo $0 enable|disable" >&2; exit 2 ;;
esac
[ "$(id -u)" -eq 0 ] || {
    echo "run with sudo: sudo $0 $ACTION" >&2
    exit 1
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONFIG_PATH=${AOA_TEST_CONFIG:-"$SCRIPT_DIR/../config.yaml"}
GRUB_DEFAULTS=${AOA_GRUB_DEFAULTS:-/etc/default/grub}
BACKUP=${AOA_GRUB_BACKUP:-/etc/default/grub.aoa-before-isolation}

command -v update-grub >/dev/null 2>&1 || {
    echo "missing command: update-grub" >&2
    exit 1
}

python3 - "$ACTION" "$CONFIG_PATH" "$GRUB_DEFAULTS" "$BACKUP" <<'PY'
import re
import shlex
import shutil
import sys
from pathlib import Path

import yaml

action, config_path, grub_path, backup_path = sys.argv[1:]
grub = Path(grub_path)
backup = Path(backup_path)

def parse_cpus(value):
    cpus = set()
    for part in value.split(","):
        bounds = part.strip().split("-", 1)
        cpus.update(range(int(bounds[0]), int(bounds[-1]) + 1))
    return cpus

def complete_cores(cpus):
    for cpu in cpus:
        path = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list")
        if not path.is_file() or not parse_cpus(path.read_text().strip()) <= cpus:
            return False
    return True

def replace_cmdline(text, replacement):
    pattern = re.compile(r"^GRUB_CMDLINE_LINUX_DEFAULT=.*$", re.MULTILINE)
    if not pattern.search(text):
        raise SystemExit("GRUB_CMDLINE_LINUX_DEFAULT is missing")
    return pattern.sub(replacement, text, count=1)

def cmdline_value(text):
    match = re.search(r"^GRUB_CMDLINE_LINUX_DEFAULT=(.*)$", text, re.MULTILINE)
    if not match:
        raise SystemExit("GRUB_CMDLINE_LINUX_DEFAULT is missing")
    values = shlex.split(match.group(1))
    if len(values) != 1:
        raise SystemExit("cannot parse GRUB_CMDLINE_LINUX_DEFAULT")
    return values[0]

if action == "enable":
    with open(config_path, encoding="utf-8") as stream:
        config = yaml.safe_load(stream)
    machine = config["machines"][config["performance"]["machine"]]
    guest_text = machine["pin_cpus"]
    host_text = machine["emulator_cpus"]
    guest = parse_cpus(guest_text)
    host = parse_cpus(host_text)
    online = parse_cpus(Path("/sys/devices/system/cpu/online").read_text().strip())
    if guest & host or guest | host != online:
        raise SystemExit("configured Guest/Host CPU partition does not match online CPUs")
    if not complete_cores(guest) or not complete_cores(host):
        raise SystemExit("configured CPU partition does not contain complete physical cores")

    if not backup.exists():
        shutil.copy2(grub, backup)
    current = grub.read_text(encoding="utf-8")
    tokens = shlex.split(cmdline_value(current))
    keys = {"isolcpus", "nohz_full", "rcu_nocbs", "irqaffinity"}
    tokens = [token for token in tokens if token.split("=", 1)[0] not in keys]
    tokens.extend(
        (
            f"isolcpus={guest_text}",
            f"nohz_full={guest_text}",
            f"rcu_nocbs={guest_text}",
            f"irqaffinity={host_text}",
        )
    )
    value = " ".join(tokens).replace("\\", "\\\\").replace('"', '\\"')
    updated = replace_cmdline(current, f'GRUB_CMDLINE_LINUX_DEFAULT="{value}"')
else:
    if not backup.is_file():
        raise SystemExit(f"isolation backup not found: {backup}")
    current = grub.read_text(encoding="utf-8")
    original = backup.read_text(encoding="utf-8")
    original_line = re.search(
        r"^GRUB_CMDLINE_LINUX_DEFAULT=.*$", original, re.MULTILINE
    )
    if not original_line:
        raise SystemExit("backup has no GRUB_CMDLINE_LINUX_DEFAULT")
    updated = replace_cmdline(current, original_line.group(0))

grub.write_text(updated, encoding="utf-8")
PY

update-grub
if [ "$ACTION" = disable ]; then
    rm -f "$BACKUP"
fi
echo "CPU isolation configuration updated; reboot is required"
