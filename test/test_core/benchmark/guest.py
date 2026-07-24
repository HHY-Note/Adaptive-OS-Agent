from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

from test_core.models import RunSpec


def write_guest_script(path: str | Path, spec: RunSpec) -> None:
    target = Path(path)
    target.write_text(build_guest_script(spec), encoding="utf-8")
    target.chmod(0o755)


def build_guest_script(spec: RunSpec) -> str:
    benchmark = spec.benchmark
    scheduler = spec.scheduler
    workload = spec.workload
    kind = str(scheduler.get("kind", "builtin"))
    output_dir = str(spec.libvirt["guest_output_dir"])
    bench_dir = f"{output_dir}/benchmark"
    observations_dir = f"{bench_dir}/observations"
    warmup = int(benchmark["warmup_seconds"])
    measurement = int(benchmark["measurement_seconds"])
    cooldown = int(benchmark["cooldown_seconds"])
    scheduler_warmup = int(scheduler.get("warmup_seconds", 0))
    expected_ops = str(scheduler.get("expected_ops", ""))
    snapshot_file = str(scheduler.get("snapshot_file", ""))
    tool_socket = str(scheduler.get("tool_socket", ""))
    stop_signal = str(scheduler.get("stop_signal", "TERM"))
    stop_timeout = int(scheduler.get("stop_timeout_seconds", 10))
    topology = spec.machine["topology"]
    perf_events = ",".join(str(value) for value in benchmark["perf_events"])
    perf_missing = "exit 127" if benchmark["require_perf"] else ': >"$BENCH/perf-stat.csv"'

    scheduler_start = ":"
    if kind == "agent":
        scheduler_start = (
            f"( exec {_scheduler_command(scheduler)} ) "
            f">\"$OUT/scheduler.stdout\" 2>\"$OUT/scheduler.stderr\" &\n"
            "scheduler_pid=$!"
        )
    collector_command = _collector_command(
        benchmark,
        targets_file=str(workload["targets_file"]),
        observations_dir=observations_dir,
        stop_file=f"{bench_dir}/collector.stop",
        agent=kind == "agent",
        timeout=measurement + cooldown + 120,
    )

    header = f"""#!/bin/sh
set +e

OUT={shlex.quote(output_dir)}
BENCH={shlex.quote(bench_dir)}
OBSERVATIONS={shlex.quote(observations_dir)}
REAL={shlex.quote(str(workload['result_root']))}
READY_FILE={shlex.quote(str(workload['ready_file']))}
WINDOW_FILE={shlex.quote(str(workload['window_file']))}
TARGETS_FILE={shlex.quote(str(workload['targets_file']))}
WORKLOAD_SERVICE={shlex.quote(str(workload['service']))}
COLLECTOR={shlex.quote(str(benchmark['collector_target']))}
SCHEDULER_KIND={shlex.quote(kind)}
EXPECTED_OPS={shlex.quote(expected_ops)}
SNAPSHOT_FILE={shlex.quote(snapshot_file)}
TOOL_SOCKET={shlex.quote(tool_socket)}
STOP_SIGNAL={shlex.quote(stop_signal)}
STOP_TIMEOUT_SECONDS={stop_timeout}
VM_WARMUP_SECONDS={int(spec.libvirt.get('vm_warmup_seconds', 0))}
SCHEDULER_WARMUP_SECONDS={scheduler_warmup}
WARMUP_SECONDS={warmup}
MEASUREMENT_SECONDS={measurement}
COOLDOWN_SECONDS={cooldown}
SCENARIO={shlex.quote(str(benchmark['scenario']))}
VARIANT={shlex.quote(str(benchmark['variant']))}
REPEAT={int(benchmark['repeat'])}
EXPECTED_VCPUS={int(spec.machine['vcpus'])}
EXPECTED_SOCKETS={int(topology['sockets'])}
EXPECTED_CORES={int(topology['cores'])}
EXPECTED_THREADS={int(topology['threads'])}

scheduler_pid=0
collector_pid=0
perf_pid=0
scheduler_stop_forced=0
environment_rc=0
workload_ready_rc=0
scheduler_start_rc=0
scheduler_end_rc=0
cleanup_rc=0
workload_rc=0
perf_rc=0
collector_rc=0
artifact_rc=0
MEASUREMENT_START_NS=0
MEASUREMENT_END_NS=0

mkdir -p "$BENCH" "$OBSERVATIONS"
: >"$OUT/scheduler.stdout"
: >"$OUT/scheduler.stderr"
rm -f "$BENCH/collector.stop" "$READY_FILE" "$WINDOW_FILE"

read_scx_state() {{
    cat /sys/kernel/sched_ext/state 2>/dev/null || printf 'missing'
}}

read_scx_ops() {{
    cat /sys/kernel/sched_ext/root/ops 2>/dev/null || true
}}

ops_matches() {{
    [ "$1" = "$EXPECTED_OPS" ] && return 0
    case "$1" in
        "$EXPECTED_OPS"_*) return 0 ;;
        *) return 1 ;;
    esac
}}

process_alive() {{
    [ "$scheduler_pid" -gt 0 ] && kill -0 "$scheduler_pid" 2>/dev/null
}}

check_scheduler() {{
    state="$(read_scx_state)"
    if [ "$SCHEDULER_KIND" = builtin ]; then
        [ "$state" = disabled ]
        return
    fi
    process_alive && [ "$state" = enabled ] && ops_matches "$(read_scx_ops)"
}}

stop_scheduler() {{
    [ "$SCHEDULER_KIND" = builtin ] && return
    if process_alive; then
        kill -s "$STOP_SIGNAL" "$scheduler_pid" 2>/dev/null || true
        count=0
        limit=$((STOP_TIMEOUT_SECONDS * 2))
        while process_alive && [ "$count" -lt "$limit" ]; do
            sleep 0.5
            count=$((count + 1))
        done
        if process_alive; then
            scheduler_stop_forced=1
            kill -KILL "$scheduler_pid" 2>/dev/null || true
        fi
    fi
    wait "$scheduler_pid" 2>/dev/null || true
}}

wait_for_file() {{
    path="$1"
    seconds="$2"
    count=0
    limit=$((seconds * 2))
    while [ ! -f "$path" ] && [ "$count" -lt "$limit" ]; do
        sleep 0.5
        count=$((count + 1))
    done
    [ -f "$path" ]
}}

[ "$VM_WARMUP_SECONDS" -eq 0 ] || sleep "$VM_WARMUP_SECONDS"
wait_for_file "$REAL/SERVERS_READY" 120
workload_ready_rc="$?"
if [ "$workload_ready_rc" -eq 0 ]; then
    [ "$(cat "$REAL/profile" 2>/dev/null)" = "$SCENARIO" ] || workload_ready_rc=1
fi
"""

    environment = r'''python3 - "$BENCH/environment.json" "$EXPECTED_VCPUS" \
    "$EXPECTED_SOCKETS" "$EXPECTED_CORES" "$EXPECTED_THREADS" "$SCENARIO" \
    "$WORKLOAD_SERVICE" <<'PY'
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

def read(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None

def version(command):
    try:
        completed = subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return completed.stdout.splitlines()[0] if completed.stdout else None
    except OSError:
        return None

def cpu_list(text):
    cpus = set()
    for part in text.split(","):
        bounds = part.strip().split("-", 1)
        cpus.update(range(int(bounds[0]), int(bounds[-1]) + 1))
    return cpus

expected_vcpus, expected_sockets, expected_cores, expected_threads = map(int, sys.argv[2:6])
scenario, service = sys.argv[6:8]
online = sorted(cpu_list(read("/sys/devices/system/cpu/online") or ""))
topology = []
for cpu in online:
    root = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
    topology.append({
        "cpu": cpu,
        "socket": int(read(root / "physical_package_id") or -1),
        "core": int(read(root / "core_id") or -1),
    })
sockets = {row["socket"] for row in topology}
cores = {(row["socket"], row["core"]) for row in topology}
threads_per_core = {key: sum((row["socket"], row["core"]) == key for row in topology) for key in cores}
affinity = sorted(os.sched_getaffinity(0))
serial = read("/sys/class/dmi/id/product_serial")
service_enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", service], check=False).returncode == 0
errors = []
if len(online) != expected_vcpus:
    errors.append(f"online CPU count is {len(online)}, expected {expected_vcpus}")
if affinity != online:
    errors.append(f"process affinity {affinity} does not cover online CPUs {online}")
if len(sockets) != expected_sockets:
    errors.append(f"socket count is {len(sockets)}, expected {expected_sockets}")
if len(cores) != expected_sockets * expected_cores:
    errors.append(f"core count is {len(cores)}, expected {expected_sockets * expected_cores}")
if any(count != expected_threads for count in threads_per_core.values()):
    errors.append(f"threads per core are {threads_per_core}, expected {expected_threads}")
if serial != f"aoa-profile-{scenario}":
    errors.append(f"SMBIOS workload profile is {serial!r}, expected aoa-profile-{scenario!s}")
if not service_enabled:
    errors.append(f"workload service is not enabled: {service}")

environment = {
    "schema_version": 3,
    "uname": dict(platform.uname()._asdict()),
    "os_release": read("/etc/os-release"),
    "kernel_cmdline": read("/proc/cmdline"),
    "logical_cpus": os.cpu_count(),
    "online_cpus": online,
    "process_affinity": affinity,
    "topology": topology,
    "topology_errors": errors,
    "topology_valid": not errors,
    "workload_profile": serial,
    "workload_service_enabled": service_enabled,
    "workload_versions": read("/opt/aoa-workloads/versions.txt"),
    "perf_version": version(["perf", "--version"]),
}
Path(sys.argv[1]).write_text(json.dumps(environment, indent=2, sort_keys=True) + "\n", encoding="utf-8")
raise SystemExit(0 if not errors else 1)
PY
environment_rc="$?"
'''

    execution = f'''
{scheduler_start}
[ "$SCHEDULER_WARMUP_SECONDS" -eq 0 ] || sleep "$SCHEDULER_WARMUP_SECONDS"
check_scheduler
scheduler_start_rc="$?"

if [ "$environment_rc" -eq 0 ] && [ "$workload_ready_rc" -eq 0 ] && [ "$scheduler_start_rc" -eq 0 ]; then
    printf '%s %s\n' "$WARMUP_SECONDS" "$MEASUREMENT_SECONDS" >"$WINDOW_FILE"
    touch "$READY_FILE"
    if wait_for_file "$REAL/MEASUREMENT_STARTED" $((WARMUP_SECONDS + 60)); then
        MEASUREMENT_START_NS="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["start_ns"])' "$REAL/measurement-window.json")"
        CLASSIFICATION_SNAPSHOT_NS=$((MEASUREMENT_START_NS + 5000000000))
        {collector_command} >"$BENCH/collector.stdout" 2>"$BENCH/collector.stderr" &
        collector_pid=$!
        (
            if command -v perf >/dev/null 2>&1; then
                perf stat -a -x, -o "$BENCH/perf-stat.csv" \\
                    -e {shlex.quote(perf_events)} -- sleep "$MEASUREMENT_SECONDS"
            else
                {perf_missing}
            fi
        ) >"$BENCH/perf.stdout" 2>"$BENCH/perf.stderr" &
        perf_pid=$!

        wait_for_file "$REAL/COMPLETE" $((MEASUREMENT_SECONDS + 120))
        workload_rc="$?"
        wait "$perf_pid"
        perf_rc="$?"
        [ "$COOLDOWN_SECONDS" -eq 0 ] || sleep "$COOLDOWN_SECONDS"
        touch "$BENCH/collector.stop"
        wait "$collector_pid"
        collector_rc="$?"
        if [ "$workload_rc" -eq 0 ]; then
            MEASUREMENT_END_NS="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["end_ns"])' "$REAL/measurement-window.json")"
            count=0
            while systemctl is-active --quiet "$WORKLOAD_SERVICE" && [ "$count" -lt 50 ]; do
                sleep 0.2
                count=$((count + 1))
            done
            [ "$(systemctl show --value -p ExecMainStatus "$WORKLOAD_SERVICE")" = 0 ] || workload_rc=1
        fi
    else
        workload_rc=1
        perf_rc=1
        collector_rc=1
    fi
else
    workload_rc=1
    perf_rc=1
    collector_rc=1
fi

check_scheduler
scheduler_end_rc="$?"
'''

    validation = r'''python3 - "$BENCH" "$REAL" "$SCENARIO" "$SCHEDULER_KIND" \
    "$SNAPSHOT_FILE" "$MEASUREMENT_START_NS" "$MEASUREMENT_END_NS" \
    "$EXPECTED_VCPUS" "$MEASUREMENT_SECONDS" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

bench = Path(sys.argv[1])
real = Path(sys.argv[2])
scenario = sys.argv[3]
agent_required = sys.argv[4] == "agent"
snapshot_path = Path(sys.argv[5]) if sys.argv[5] else None
start_ns, end_ns, expected_vcpus, expected_duration = map(int, sys.argv[6:10])
errors = []

def load_json(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("root is not an object")
        return value
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"cannot read {path}: {exc}")
        return {}

def load_jsonl(path):
    rows = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"cannot read {path}: {exc}")
    return rows

if (real / "profile").read_text(encoding="utf-8").strip() != scenario:
    errors.append("workload profile mismatch")
window = load_json(real / "measurement-window.json")
if start_ns <= 0 or end_ns <= start_ns:
    errors.append("measurement window is invalid")
if window.get("start_ns") != start_ns or window.get("end_ns") != end_ns:
    errors.append("measurement window artifact mismatch")
duration_seconds = (end_ns - start_ns) / 1_000_000_000 if end_ns > start_ns else 0
maximum_duration = expected_duration + max(5.0, expected_duration * 0.1)
if duration_seconds < expected_duration * 0.8 or duration_seconds > maximum_duration:
    errors.append(
        f"measurement duration is {duration_seconds:.3f}s, expected {expected_duration}s"
    )

metrics = []
apps_root = real / "apps"
for directory in sorted(path for path in apps_root.iterdir() if path.is_dir()):
    metric = load_json(directory / "metrics.json")
    if metric:
        metrics.append(metric)
        if metric.get("name") != directory.name or metric.get("completed") is not True:
            errors.append(f"incomplete application metric: {directory.name}")
        if metric.get("exit_code") not in (0, 124):
            errors.append(f"application failed: {directory.name}")
        if not isinstance(metric.get("elapsed_seconds"), (int, float)) or metric["elapsed_seconds"] <= 0:
            errors.append(f"invalid elapsed time: {directory.name}")

role_counts = Counter(str(metric.get("role")) for metric in metrics)
minimums = {
    "latency": {"latency": 4, "throughput": 1},
    "throughput": {"throughput": 5},
    "mix": {"latency": 3, "throughput": 4, "balanced": 2},
}[scenario]
for role, minimum in minimums.items():
    if role_counts[role] < minimum:
        errors.append(f"expected at least {minimum} {role} apps, found {role_counts[role]}")
latency_metrics = [metric for metric in metrics if metric.get("role") == "latency" and isinstance(metric.get("p99_ms"), (int, float))]
throughput_metrics = [metric for metric in metrics if metric.get("role") == "throughput" and isinstance(metric.get("throughput_per_second"), (int, float))]
if scenario in {"latency", "mix"} and len(latency_metrics) < 2:
    errors.append("fewer than two latency applications produced P99 metrics")
if scenario in {"throughput", "mix"} and len(throughput_metrics) < 2:
    errors.append("fewer than two throughput applications produced rate metrics")

pressure = load_json(real / "pressure-plan.json")
if pressure.get("online_vcpus") != expected_vcpus:
    errors.append("pressure plan vCPU count mismatch")
if pressure.get("pressure_cpu_budget") != max(1, expected_vcpus - 1):
    errors.append("pressure plan CPU budget mismatch")
if expected_vcpus > 1 and pressure.get("reserved_latency_cpu") != 1:
    errors.append("pressure plan did not reserve latency capacity")

target_rows = load_jsonl(real / "targets.jsonl")
target_apps = {str(row.get("name")) for row in target_rows}
metric_apps = {str(metric.get("name")) for metric in metrics}
if target_apps != metric_apps:
    errors.append(f"target/application mismatch: targets={sorted(target_apps)}, metrics={sorted(metric_apps)}")

collector = load_json(bench / "observations" / "collector-summary.json")
if collector.get("samples", 0) < 1 or collector.get("target_workers", 0) < 1:
    errors.append("collector did not observe workload threads")
if set(collector.get("target_apps", [])) != metric_apps:
    errors.append("collector did not cover every workload application")
if collector.get("timed_out") is True:
    errors.append("collector timed out")

if agent_required:
    if collector.get("classification_snapshot_available") is not True:
        errors.append("classification snapshot was not collected")
    else:
        classification = load_json(bench / "observations" / "classification-snapshot.json")
        if classification.get("schema_version") != 1 or not isinstance(classification.get("processes"), list) or not isinstance(classification.get("threads"), list):
            errors.append("classification snapshot structure is invalid")
    scheduler_rows = [row for row in load_jsonl(bench / "observations" / "scheduler-stats.jsonl") if start_ns <= int(row.get("observed_ns", 0)) <= end_ns]
    epochs = {row.get("scheduler_epoch") for row in scheduler_rows if row.get("scheduler_epoch") is not None}
    if len(epochs) != 1:
        errors.append("scheduler epoch changed or was not observed during measurement")
    if any(int(row.get("data_plane", {}).get("stale_heartbeat_fallbacks") or 0) > 0 for row in scheduler_rows):
        errors.append("scheduler heartbeat fallback occurred during measurement")
    snapshot = load_json(snapshot_path) if snapshot_path else {}
    if snapshot.get("registry_ready") is not True or snapshot.get("degraded") is not False:
        errors.append("final scheduler snapshot is not healthy")

validation = {
    "schema_version": 2,
    "artifact_errors": errors,
    "applications": len(metrics),
    "roles": dict(sorted(role_counts.items())),
    "latency_p99_applications": len(latency_metrics),
    "throughput_rate_applications": len(throughput_metrics),
}
(bench / "validation.json").write_text(json.dumps(validation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
raise SystemExit(1 if errors else 0)
PY
validation_rc="$?"
[ "$validation_rc" -eq 0 ] || artifact_rc=1

stop_scheduler
[ "$scheduler_stop_forced" -eq 0 ] || cleanup_rc=1
sleep 1
[ "$(read_scx_state)" = disabled ] || cleanup_rc=1
'''

    result = r'''python3 - "$OUT/guest_result.json" "$BENCH/validation.json" \
    "$SCENARIO" "$VARIANT" "$REPEAT" "$MEASUREMENT_START_NS" \
    "$MEASUREMENT_END_NS" "$environment_rc" "$workload_ready_rc" \
    "$scheduler_start_rc" "$scheduler_end_rc" "$cleanup_rc" "$workload_rc" \
    "$perf_rc" "$collector_rc" "$artifact_rc" "$scheduler_stop_forced" <<'PY'
import json
import sys
from pathlib import Path

(
    output_path, validation_path, scenario, variant, repeat, start_ns, end_ns,
    environment_rc, workload_ready_rc, scheduler_start_rc, scheduler_end_rc,
    cleanup_rc, workload_rc, perf_rc, collector_rc, artifact_rc,
    scheduler_stop_forced,
) = sys.argv[1:]
checks = {
    "environment": int(environment_rc),
    "workload_ready": int(workload_ready_rc),
    "scheduler_start": int(scheduler_start_rc),
    "scheduler_end": int(scheduler_end_rc),
    "scheduler_cleanup": int(cleanup_rc),
    "workload": int(workload_rc),
    "perf": int(perf_rc),
    "collector": int(collector_rc),
    "artifacts": int(artifact_rc),
}
try:
    validation = json.loads(Path(validation_path).read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    validation = {}
result = {
    "benchmark": True,
    "schema_version": 2,
    "scenario": scenario,
    "variant": variant,
    "repeat": int(repeat),
    "measurement_start_ns": int(start_ns),
    "measurement_end_ns": int(end_ns),
    "checks": checks,
    "valid": all(value == 0 for value in checks.values()),
    "scheduler_stop_forced": bool(int(scheduler_stop_forced)),
    "validation": validation,
}
Path(output_path).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
raise SystemExit(0 if result["valid"] else 1)
PY
exit "$?"
'''
    return "\n".join((header, environment, execution, validation, result))


def _collector_command(
    benchmark: dict[str, Any],
    *,
    targets_file: str,
    observations_dir: str,
    stop_file: str,
    agent: bool,
    timeout: int,
) -> str:
    parts = [
        "python3",
        str(benchmark["collector_target"]),
        "--output-dir",
        observations_dir,
        "--targets",
        targets_file,
        "--stop-file",
        stop_file,
        "--interval-seconds",
        str(benchmark["sample_interval_seconds"]),
        "--timeout-seconds",
        str(timeout),
    ]
    command = shlex.join(parts)
    if agent:
        command += (
            ' --tool-socket "$TOOL_SOCKET" --agent-pid "$scheduler_pid"'
            ' --classification-snapshot-at-ns "$CLASSIFICATION_SNAPSHOT_NS"'
        )
    return command


def _scheduler_command(scheduler: dict[str, Any]) -> str:
    command = [str(scheduler["command"]), *map(str, scheduler.get("args", []))]
    env = scheduler.get("env", {})
    if isinstance(env, dict) and env:
        command = [
            "env",
            *[f"{key}={value}" for key, value in sorted(env.items())],
            *command,
        ]
    return shlex.join(command)
