#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || {
    echo "run with sudo: sudo $0" >&2
    exit 1
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONFIG_PATH=${AOA_TEST_CONFIG:-"$SCRIPT_DIR/../config.yaml"}
STATE_FILE=${AOA_CPU_FREQUENCY_STATE:-/var/tmp/aoa-test-cpu-frequency.state}

set -- $(python3 - "$CONFIG_PATH" <<'PY'
import sys
import yaml

with open(sys.argv[1], encoding="utf-8") as stream:
    config = yaml.safe_load(stream)
machine = config["machines"][config["performance"]["machine"]]
frequency = machine["frequency"]
print(frequency["governor"], frequency["khz"])
PY
)
GOVERNOR=$1
TARGET_KHZ=$2

command -v cpupower >/dev/null 2>&1 || {
    echo "missing command: cpupower" >&2
    exit 1
}

set -- /sys/devices/system/cpu/cpufreq/policy*
[ -d "$1" ] || {
    echo "CPU frequency policies are unavailable" >&2
    exit 1
}

if [ ! -f "$STATE_FILE" ]; then
    umask 077
    state_tmp="${STATE_FILE}.$$"
    trap 'rm -f "$state_tmp"' 0 1 2 15
    : >"$state_tmp"
    for policy in "$@"; do
        name=${policy##*/}
        preference=-
        if [ -r "$policy/energy_performance_preference" ]; then
            preference=$(cat "$policy/energy_performance_preference")
        fi
        printf '%s|%s|%s|%s|%s\n' \
            "$name" \
            "$(cat "$policy/scaling_governor")" \
            "$(cat "$policy/scaling_min_freq")" \
            "$(cat "$policy/scaling_max_freq")" \
            "$preference" >>"$state_tmp"
    done
    mv "$state_tmp" "$STATE_FILE"
    trap - 0 1 2 15
fi

cpupower -c all frequency-set -g "$GOVERNOR" >/dev/null
cpupower -c all frequency-set -u "${TARGET_KHZ}kHz" >/dev/null
cpupower -c all frequency-set -d "${TARGET_KHZ}kHz" >/dev/null

for policy in "$@"; do
    [ "$(cat "$policy/scaling_governor")" = "$GOVERNOR" ]
    [ "$(cat "$policy/scaling_min_freq")" = "$TARGET_KHZ" ]
    [ "$(cat "$policy/scaling_max_freq")" = "$TARGET_KHZ" ]
done

echo "CPU frequency set to $GOVERNOR at $TARGET_KHZ kHz"
echo "saved previous state: $STATE_FILE"
