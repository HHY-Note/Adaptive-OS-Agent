#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || {
    echo "run with sudo: sudo $0" >&2
    exit 1
}

STATE_FILE=${AOA_CPU_FREQUENCY_STATE:-/var/tmp/aoa-test-cpu-frequency.state}
[ -r "$STATE_FILE" ] || {
    echo "saved CPU frequency state not found: $STATE_FILE" >&2
    exit 1
}

while IFS='|' read -r name governor minimum maximum preference; do
    case "$name" in
        policy[0-9]*) ;;
        *) echo "invalid policy in state file: $name" >&2; exit 1 ;;
    esac
    policy=/sys/devices/system/cpu/cpufreq/$name
    [ -d "$policy" ] || {
        echo "CPU frequency policy no longer exists: $name" >&2
        exit 1
    }

    cat "$policy/cpuinfo_min_freq" >"$policy/scaling_min_freq"
    printf '%s\n' "$maximum" >"$policy/scaling_max_freq"
    printf '%s\n' "$minimum" >"$policy/scaling_min_freq"
    printf '%s\n' "$governor" >"$policy/scaling_governor"
    if [ "$preference" != - ] && [ -w "$policy/energy_performance_preference" ]; then
        printf '%s\n' "$preference" >"$policy/energy_performance_preference"
    fi

    [ "$(cat "$policy/scaling_governor")" = "$governor" ]
    [ "$(cat "$policy/scaling_min_freq")" = "$minimum" ]
    [ "$(cat "$policy/scaling_max_freq")" = "$maximum" ]
done <"$STATE_FILE"

rm -f "$STATE_FILE"
echo "CPU frequency policy restored"
