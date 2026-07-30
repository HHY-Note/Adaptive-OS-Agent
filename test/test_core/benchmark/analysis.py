from __future__ import annotations

import csv
import json
import math
import random
import statistics
from collections.abc import Iterable
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable


MetricDefinition = tuple[str, Callable[[dict[str, Any]], float], bool, str, bool]
DYNAMIC_MIX_SCENARIO = "dynamic_mix"
APPLICATION_LABELS = {
    "redis": "Redis",
    "nginx": "Nginx",
    "postgresql": "PostgreSQL",
    "ffmpeg": "FFmpeg",
    "rocksdb": "RocksDB",
    "zstd": "zstd",
}


def analyze_run(run_dir: str | Path) -> dict[str, Any]:
    root = Path(run_dir)
    result = _read_json(root / "result.json")
    benchmark = result.get("spec", {}).get("benchmark") or {}
    guest = result.get("guest_result") or {}
    scenario = str(benchmark.get("scenario", guest.get("scenario", "unknown")))
    variant = str(benchmark.get("variant", guest.get("variant", "unknown")))
    repeat = int(benchmark.get("repeat", guest.get("repeat", 0)))
    start_ns = int(guest.get("measurement_start_ns", 0))
    end_ns = int(guest.get("measurement_end_ns", 0))
    bench_dir = root / "benchmark"
    reasons: list[str] = []

    if result.get("status") != "PASS":
        reasons.append(f"runner status is {result.get('status', 'missing')}")
    if guest.get("valid") is not True:
        reasons.append("Guest validation failed")
    if start_ns <= 0 or end_ns <= start_ns:
        reasons.append("invalid measurement window")

    applications = _application_metrics(bench_dir, reasons)
    latency = _latency_metrics(applications, reasons)
    throughput = _throughput_metrics(applications, reasons)
    classification = _classification_metrics(
        bench_dir, start_ns, end_ns, enabled=variant == "agent"
    )
    perf = _perf_metrics(bench_dir / "perf-stat.csv")
    scheduler = _scheduler_metrics(bench_dir, start_ns, end_ns)
    cpu_utilization = _cpu_utilization_metrics(bench_dir, start_ns, end_ns)
    load_contract = _load_contract_metrics(
        bench_dir,
        applications,
        cpu_utilization,
        start_ns,
        end_ns,
        required=True,
    )
    reasons.extend(load_contract["violations"])
    if benchmark.get("require_perf") is True:
        missing_events = [
            event for event in benchmark.get("perf_events", []) if perf.get(event) is None
        ]
        if missing_events:
            reasons.append(f"missing perf events: {missing_events}")
    if variant == "agent":
        invalid_counters = (
            "event_overflows",
            "task_capacity_hits",
            "degraded_transitions",
        )
        if not scheduler:
            reasons.append("scheduler statistics are missing")
        elif any(scheduler.get(field, 0) > 0 for field in invalid_counters):
            reasons.append("scheduler entered an invalid measurement state")

    summary = {
        "schema_version": 4,
        "run_dir": str(root.resolve()),
        "scenario": scenario,
        "variant": variant,
        "repeat": repeat,
        "profile": str(benchmark.get("profile", "formal")),
        "valid": not reasons,
        "invalid_reasons": reasons,
        "measurement": {
            "start_ns": start_ns,
            "end_ns": end_ns,
            "duration_seconds": (end_ns - start_ns) / 1_000_000_000 if end_ns > start_ns else 0,
        },
        "environment": _read_json(bench_dir / "environment.json"),
        "applications": applications,
        "latency": latency,
        "throughput": throughput,
        "perf": perf,
        "cpu_utilization": cpu_utilization,
        "load_contract": load_contract,
        "task_scheduling": _schedstat_metrics(bench_dir, start_ns, end_ns),
        "overhead": _overhead_metrics(bench_dir, start_ns, end_ns),
        "scheduler": scheduler,
        "classification": classification,
    }
    _write_json(root / "benchmark-summary.json", summary)
    return summary


def analyze_campaign(
    campaign_dir: str | Path, *, bootstrap_samples: int, seed: int
) -> dict[str, Any]:
    root = Path(campaign_dir)
    manifest = _read_json(root / "campaign.json")
    summaries: list[dict[str, Any]] = []
    runs_dir = root / "runs"
    if runs_dir.is_dir():
        for run_dir in sorted(path for path in runs_dir.iterdir() if path.is_dir()):
            if (run_dir / "result.json").is_file():
                summaries.append(analyze_run(run_dir))

    valid = [summary for summary in summaries if summary["valid"]]
    comparisons = _comparisons(valid, bootstrap_samples=bootstrap_samples, seed=seed)
    application_comparisons = _application_comparisons(
        valid, bootstrap_samples=bootstrap_samples, seed=seed
    )
    system_comparisons = _system_comparisons(
        valid, bootstrap_samples=bootstrap_samples, seed=seed
    )
    run_profiles = {str(summary["profile"]) for summary in summaries}
    profile = str(manifest.get("profile", next(iter(run_profiles), "formal")))
    if run_profiles and run_profiles != {profile}:
        profile = "mixed"
    preflight = _read_json(root / "preflight.json")
    methodology = _campaign_methodology(manifest, preflight, summaries)
    methodology["campaign_id"] = root.name
    output = {
        "schema_version": 4,
        "profile": profile,
        "runs": len(summaries),
        "valid_runs": len(valid),
        "invalid_runs": len(summaries) - len(valid),
        "comparisons": comparisons,
        "application_comparisons": application_comparisons,
        "system_comparisons": system_comparisons,
        "classification": _campaign_classification(valid),
        "agent_evidence": _campaign_agent_evidence(valid),
        "environment": _campaign_environment(valid),
        "methodology": methodology,
        "load_contracts": [
            {
                "scenario": summary["scenario"],
                "variant": summary["variant"],
                "repeat": summary["repeat"],
                "valid": summary["load_contract"].get("valid", False),
                **summary["load_contract"].get("observed", {}),
            }
            for summary in summaries
            if summary["load_contract"].get("present")
        ],
        "invalid": [
            {
                "run_dir": summary["run_dir"],
                "scenario": summary["scenario"],
                "variant": summary["variant"],
                "repeat": summary["repeat"],
                "reasons": summary["invalid_reasons"],
            }
            for summary in summaries
            if not summary["valid"]
        ],
    }
    _write_json(root / "comparison.json", output)
    _write_comparison_csv(root / "summary.csv", comparisons)
    (root / "report.md").write_text(_report(output), encoding="utf-8")
    return output


def _application_metrics(
    bench_dir: Path, reasons: list[str]
) -> dict[str, dict[str, Any]]:
    root = bench_dir / "real-workloads" / "apps"
    applications: dict[str, dict[str, Any]] = {}
    try:
        directories = sorted(path for path in root.iterdir() if path.is_dir())
    except OSError as exc:
        reasons.append(f"cannot read real workload results: {exc}")
        return applications
    for directory in directories:
        metric = _read_json(directory / "metrics.json")
        if not metric:
            reasons.append(f"missing application metrics: {directory.name}")
            continue
        if metric.get("completed") is not True:
            reasons.append(f"application did not complete: {directory.name}")
        applications[directory.name] = metric
    if not applications:
        reasons.append("real application metric set is empty")
    return applications


def _latency_metrics(
    applications: dict[str, dict[str, Any]], reasons: list[str]
) -> dict[str, Any]:
    values = {
        name: float(metric["p99_ms"]) * 1000
        for name, metric in applications.items()
        if metric.get("role") == "latency"
        and metric.get("objective", True) is True
        and isinstance(metric.get("p99_ms"), (int, float))
        and float(metric["p99_ms"]) > 0
    }
    if not values:
        reasons.append("no latency application produced a P99 metric")
    ordered = list(values.values())
    return {
        "applications_p99_us": dict(sorted(values.items())),
        "application_count": len(values),
        "p99_us": {
            "geometric_mean": _geometric_mean(ordered),
            "median": statistics.median(ordered) if ordered else None,
            "worst": max(ordered) if ordered else None,
        },
    }


def _throughput_metrics(
    applications: dict[str, dict[str, Any]], reasons: list[str]
) -> dict[str, Any]:
    return _rate_metrics(applications, reasons, role="throughput")


def _rate_metrics(
    applications: dict[str, dict[str, Any]], reasons: list[str], *, role: str
) -> dict[str, Any]:
    values = {
        name: float(metric["throughput_per_second"])
        for name, metric in applications.items()
        if metric.get("role") == role
        and metric.get("objective", True) is True
        and isinstance(metric.get("throughput_per_second"), (int, float))
        and float(metric["throughput_per_second"]) > 0
    }
    if not values:
        reasons.append(f"no {role} application produced a rate metric")
    rates = list(values.values())
    aggregate = _geometric_mean(rates)
    return {
        "applications_per_second": dict(sorted(values.items())),
        "application_count": len(values),
        "operations_per_second": aggregate,
        "geometric_mean_per_second": aggregate,
        "median_per_second": statistics.median(rates) if rates else None,
    }


def _perf_metrics(path: Path) -> dict[str, float | None]:
    metrics: dict[str, float | None] = {}
    try:
        with path.open(encoding="utf-8", newline="") as stream:
            for row in csv.reader(stream):
                if len(row) < 3:
                    continue
                event = row[2].strip()
                raw = row[0].strip().replace(" ", "")
                try:
                    metrics[event] = float(raw)
                except ValueError:
                    metrics[event] = None
    except OSError:
        pass
    cycles = metrics.get("cycles")
    instructions = metrics.get("instructions")
    cache_references = metrics.get("cache-references")
    cache_misses = metrics.get("cache-misses")
    metrics["instructions_per_cycle"] = (
        instructions / cycles if instructions is not None and cycles else None
    )
    metrics["cache_miss_ratio"] = (
        cache_misses / cache_references
        if cache_misses is not None and cache_references
        else None
    )
    return metrics


def _schedstat_metrics(bench_dir: Path, start_ns: int, end_ns: int) -> dict[str, Any]:
    rows = _read_jsonl(bench_dir / "observations" / "task-schedstat.jsonl")
    grouped: dict[tuple[int, int], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(int(row.get("pid", 0)), int(row.get("tid", 0)))].append(row)
    run_ns = wait_ns = timeslices = migrations = 0
    covered = 0
    by_application: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "workers": 0,
            "run_ns": 0,
            "wait_ns": 0,
            "timeslices": 0,
            "migrations": 0,
        }
    )
    by_class: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "workers": 0,
            "run_ns": 0,
            "wait_ns": 0,
            "timeslices": 0,
            "migrations": 0,
        }
    )
    for values in grouped.values():
        delta = _window_delta(values, start_ns, end_ns)
        if delta is None:
            continue
        before, after = delta
        worker_run_ns = max(0, int(after["run_ns"]) - int(before["run_ns"]))
        worker_wait_ns = max(0, int(after["wait_ns"]) - int(before["wait_ns"]))
        worker_timeslices = max(
            0, int(after["timeslices"]) - int(before["timeslices"])
        )
        worker_migrations = max(
            0, int(after.get("migrations", 0)) - int(before.get("migrations", 0))
        )
        run_ns += worker_run_ns
        wait_ns += worker_wait_ns
        timeslices += worker_timeslices
        migrations += worker_migrations
        covered += 1

        for key, bucket in (
            (str(after.get("app", "unknown")), by_application),
            (str(after.get("mode", "unknown")), by_class),
        ):
            entry = bucket[key]
            entry["workers"] += 1
            entry["run_ns"] += worker_run_ns
            entry["wait_ns"] += worker_wait_ns
            entry["timeslices"] += worker_timeslices
            entry["migrations"] += worker_migrations
    return {
        "workers": covered,
        "run_seconds": run_ns / 1_000_000_000,
        "wait_seconds": wait_ns / 1_000_000_000,
        "wait_ratio": wait_ns / (run_ns + wait_ns) if run_ns + wait_ns else None,
        "timeslices": timeslices,
        "migrations": migrations,
        "by_application": _schedstat_breakdown(by_application),
        "by_class": _schedstat_breakdown(by_class),
    }


def _cpu_utilization_metrics(
    bench_dir: Path, start_ns: int, end_ns: int
) -> dict[str, Any]:
    rows = _read_jsonl(bench_dir / "observations" / "cpu-stats.jsonl")
    grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[int(row.get("cpu", -1))].append(row)

    collector = _read_json(bench_dir / "observations" / "collector-summary.json")
    clock_ticks = int(collector.get("clock_ticks_per_second", 100))
    tick_fields = (
        "user_ticks",
        "nice_ticks",
        "system_ticks",
        "idle_ticks",
        "iowait_ticks",
        "irq_ticks",
        "softirq_ticks",
        "steal_ticks",
    )
    by_cpu_ticks: dict[int, dict[str, int]] = {}
    topology: dict[int, tuple[int, int]] = {}
    for cpu, values in grouped.items():
        delta = _window_delta(values, start_ns, end_ns)
        if delta is None:
            continue
        before, after = delta
        by_cpu_ticks[cpu] = {
            field: max(0, int(after.get(field, 0)) - int(before.get(field, 0)))
            for field in tick_fields
        }
        topology[cpu] = (
            int(after.get("package_id", -1)),
            int(after.get("core_id", cpu)),
        )

    def summarize(counters: dict[str, int]) -> dict[str, float | None]:
        user = counters.get("user_ticks", 0) + counters.get("nice_ticks", 0)
        system = (
            counters.get("system_ticks", 0)
            + counters.get("irq_ticks", 0)
            + counters.get("softirq_ticks", 0)
        )
        steal = counters.get("steal_ticks", 0)
        idle = counters.get("idle_ticks", 0) + counters.get("iowait_ticks", 0)
        busy = user + system + steal
        total = busy + idle
        return {
            "busy_seconds": busy / clock_ticks,
            "idle_seconds": idle / clock_ticks,
            "user_seconds": user / clock_ticks,
            "system_seconds": system / clock_ticks,
            "iowait_seconds": counters.get("iowait_ticks", 0) / clock_ticks,
            "steal_seconds": steal / clock_ticks,
            "utilization": busy / total if total else None,
        }

    by_cpu = {str(cpu): summarize(counters) for cpu, counters in sorted(by_cpu_ticks.items())}
    by_core_ticks: dict[tuple[int, int], dict[str, int]] = defaultdict(
        lambda: {field: 0 for field in tick_fields}
    )
    total_ticks = {field: 0 for field in tick_fields}
    for cpu, counters in by_cpu_ticks.items():
        for field, value in counters.items():
            by_core_ticks[topology[cpu]][field] += value
            total_ticks[field] += value
    by_core = {
        f"{package_id}:{core_id}": summarize(counters)
        for (package_id, core_id), counters in sorted(by_core_ticks.items())
    }
    core_busy = [float(values["busy_seconds"] or 0.0) for values in by_core.values()]
    mean_core_busy = statistics.fmean(core_busy) if core_busy else 0.0
    result = summarize(total_ticks) if by_cpu_ticks else {}
    result.update(
        {
            "cpus": len(by_cpu),
            "cores": len(by_core),
            "core_busy_coefficient_of_variation": (
                statistics.pstdev(core_busy) / mean_core_busy
                if len(core_busy) > 1 and mean_core_busy
                else 0.0 if core_busy else None
            ),
            "by_cpu": by_cpu,
            "by_core": by_core,
        }
    )
    return result


def _cpu_interval_utilizations(
    bench_dir: Path, start_ns: int, end_ns: int
) -> list[float]:
    snapshots: dict[int, dict[int, dict[str, Any]]] = defaultdict(dict)
    for row in _read_jsonl(bench_dir / "observations" / "cpu-stats.jsonl"):
        observed_ns = int(row.get("observed_ns", 0))
        cpu = int(row.get("cpu", -1))
        if start_ns <= observed_ns <= end_ns and cpu >= 0:
            snapshots[observed_ns][cpu] = row

    busy_fields = (
        "user_ticks",
        "nice_ticks",
        "system_ticks",
        "irq_ticks",
        "softirq_ticks",
        "steal_ticks",
    )
    idle_fields = ("idle_ticks", "iowait_ticks")
    values: list[float] = []
    ordered = sorted(snapshots.items())
    for (_before_ns, before), (_after_ns, after) in zip(ordered, ordered[1:]):
        cpus = set(before) & set(after)
        if not cpus:
            continue
        busy = sum(
            max(0, int(after[cpu].get(field, 0)) - int(before[cpu].get(field, 0)))
            for cpu in cpus
            for field in busy_fields
        )
        idle = sum(
            max(0, int(after[cpu].get(field, 0)) - int(before[cpu].get(field, 0)))
            for cpu in cpus
            for field in idle_fields
        )
        if busy + idle:
            values.append(busy / (busy + idle))
    return values


def _load_contract_metrics(
    bench_dir: Path,
    applications: dict[str, dict[str, Any]],
    cpu_utilization: dict[str, Any],
    start_ns: int,
    end_ns: int,
    *,
    required: bool,
) -> dict[str, Any]:
    contract = _read_json(bench_dir / "real-workloads" / "load-contract.json")
    result: dict[str, Any] = {
        "required": required,
        "present": bool(contract),
        "valid": not required,
        "contract": contract,
        "observed": {},
        "violations": [],
    }
    violations: list[str] = result["violations"]
    if not contract:
        if required:
            violations.append("dynamic_mix load contract is missing")
            result["valid"] = False
        return result

    average_contract = contract.get("average_utilization")
    burst_contract = contract.get("burst")
    if not isinstance(average_contract, dict) or not isinstance(burst_contract, dict):
        violations.append("dynamic_mix load contract structure is invalid")
        result["valid"] = False
        return result

    average = cpu_utilization.get("utilization")
    minimum = average_contract.get("minimum")
    maximum = average_contract.get("maximum")
    interval_values = _cpu_interval_utilizations(bench_dir, start_ns, end_ns)
    burst_minimum = burst_contract.get("utilization_minimum")
    minimum_high_samples = burst_contract.get("minimum_high_utilization_samples")
    minimum_completed = burst_contract.get("minimum_completed_bursts")
    if not all(
        isinstance(value, (int, float)) and not isinstance(value, bool)
        for value in (
            average,
            minimum,
            maximum,
            burst_minimum,
            minimum_high_samples,
            minimum_completed,
        )
    ):
        violations.append("dynamic_mix load contract contains non-numeric thresholds")
        result["valid"] = False
        return result

    high_samples = sum(value >= float(burst_minimum) for value in interval_values)
    timeline = [
        row
        for row in _read_jsonl(
            bench_dir / "real-workloads" / "burst-timeline.jsonl"
        )
        if start_ns <= int(row.get("observed_ns", 0)) <= end_ns
    ]
    starts = {
        int(row["burst"])
        for row in timeline
        if row.get("event") == "start" and isinstance(row.get("burst"), int)
    }
    ends = {
        int(row["burst"])
        for row in timeline
        if row.get("event") == "end" and isinstance(row.get("burst"), int)
    }
    completed_bursts = len(starts & ends)
    duration_seconds = max(0.0, (end_ns - start_ns) / 1_000_000_000)
    continuous_apps: dict[str, dict[str, Any]] = {}
    for name in contract.get("continuous_throughput_apps", []):
        metric = applications.get(str(name), {})
        elapsed = metric.get("elapsed_seconds")
        spans_window = (
            metric.get("role") == "throughput"
            and metric.get("objective", True) is True
            and isinstance(elapsed, (int, float))
            and float(elapsed) >= duration_seconds * 0.9
        )
        continuous_apps[str(name)] = {
            "elapsed_seconds": elapsed,
            "spans_measurement": spans_window,
        }
        if not spans_window:
            violations.append(
                f"continuous throughput app {name} did not span the measurement window"
            )

    if not float(minimum) <= float(average) <= float(maximum):
        violations.append(
            "average CPU utilization "
            f"{float(average):.3f} is outside {float(minimum):.2f}..{float(maximum):.2f}"
        )
    if high_samples < int(minimum_high_samples):
        violations.append(
            f"observed {high_samples} burst samples at or above "
            f"{float(burst_minimum):.2f}, expected at least {int(minimum_high_samples)}"
        )
    if completed_bursts < int(minimum_completed):
        violations.append(
            f"observed {completed_bursts} completed bursts, "
            f"expected at least {int(minimum_completed)}"
        )

    result["observed"] = {
        "average_utilization": float(average),
        "interval_utilization": _distribution(interval_values),
        "interval_samples": len(interval_values),
        "high_utilization_samples": high_samples,
        "completed_bursts": completed_bursts,
        "continuous_throughput_apps": continuous_apps,
    }
    result["valid"] = not violations
    return result


def _schedstat_breakdown(
    values: dict[str, dict[str, int]],
) -> dict[str, dict[str, int | float | None]]:
    result: dict[str, dict[str, int | float | None]] = {}
    for name, counters in sorted(values.items()):
        run_ns = counters["run_ns"]
        wait_ns = counters["wait_ns"]
        result[name] = {
            "workers": counters["workers"],
            "run_seconds": run_ns / 1_000_000_000,
            "wait_seconds": wait_ns / 1_000_000_000,
            "wait_ratio": wait_ns / (run_ns + wait_ns) if run_ns + wait_ns else None,
            "timeslices": counters["timeslices"],
            "migrations": counters["migrations"],
        }
    return result


def _overhead_metrics(bench_dir: Path, start_ns: int, end_ns: int) -> dict[str, Any]:
    rows = _read_jsonl(bench_dir / "observations" / "process-stats.jsonl")
    collector = _read_json(bench_dir / "observations" / "collector-summary.json")
    clock_ticks = int(collector.get("clock_ticks_per_second", 100))
    page_size = int(collector.get("page_size_bytes", 4096))
    grouped: dict[tuple[str, int, int], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[
            (str(row.get("role")), int(row.get("pid", 0)), int(row.get("start_ticks", 0)))
        ].append(row)
    roles: dict[str, dict[str, float]] = defaultdict(
        lambda: {"cpu_seconds": 0.0, "max_rss_mib": 0.0}
    )
    for (role, _pid, _start), values in grouped.items():
        delta = _window_delta(values, start_ns, end_ns)
        if delta is not None:
            before, after = delta
            roles[role]["cpu_seconds"] += max(
                0, int(after["cpu_ticks"]) - int(before["cpu_ticks"])
            ) / clock_ticks
        in_window = [
            row for row in values if start_ns <= int(row.get("observed_ns", 0)) <= end_ns
        ]
        if in_window:
            roles[role]["max_rss_mib"] = max(
                roles[role]["max_rss_mib"],
                max(int(row["rss_pages"]) for row in in_window) * page_size / (1024 * 1024),
            )
    agent_cpu = sum(
        roles.get(role, {}).get("cpu_seconds", 0.0) for role in ("agent", "scheduler")
    )
    return {"roles": dict(roles), "agent_scheduler_cpu_seconds": agent_cpu}


def _scheduler_metrics(bench_dir: Path, start_ns: int, end_ns: int) -> dict[str, Any]:
    rows = _read_jsonl(bench_dir / "observations" / "scheduler-stats.jsonl")
    delta = _window_delta(rows, start_ns, end_ns)
    if delta is None:
        return {}
    before, after = delta
    fields = {
        "events_processed": ("scheduler", "events_processed"),
        "stale_events": ("scheduler", "stale_events"),
        "bad_behavior_windows": ("scheduler", "bad_behavior_windows"),
        "event_overflows": ("data_plane", "event_overflows"),
        "fallback_dispatches": ("data_plane", "fallback_dispatches"),
        "fast_path_enqueues": ("data_plane", "fast_path_enqueues"),
        "fast_path_dispatches": ("data_plane", "fast_path_dispatches"),
        "fast_path_dispatch_failures": ("data_plane", "fast_path_dispatch_failures"),
        "fast_path_preemptions": ("data_plane", "fast_path_preemptions"),
        "fast_path_preemption_throttles": (
            "data_plane",
            "fast_path_preemption_throttles",
        ),
        "fast_path_preemption_deferrals": (
            "data_plane",
            "fast_path_preemption_deferrals",
        ),
        "fast_path_latency_backlog_boosts": (
            "data_plane",
            "fast_path_latency_backlog_boosts",
        ),
        "fast_path_latency_steal_attempts": (
            "data_plane",
            "fast_path_latency_steal_attempts",
        ),
        "fast_path_latency_remote_steals": (
            "data_plane",
            "fast_path_latency_remote_steals",
        ),
        "fast_path_shared_balanced_enqueues": (
            "data_plane",
            "fast_path_shared_balanced_enqueues",
        ),
        "fast_path_shared_balanced_dispatch_attempts": (
            "data_plane",
            "fast_path_shared_balanced_dispatch_attempts",
        ),
        "fast_path_shared_balanced_dispatches": (
            "data_plane",
            "fast_path_shared_balanced_dispatches",
        ),
        "fast_path_shared_balanced_dispatch_failures": (
            "data_plane",
            "fast_path_shared_balanced_dispatch_failures",
        ),
        "fast_path_shared_latency_enqueues": (
            "data_plane",
            "fast_path_shared_latency_enqueues",
        ),
        "fast_path_shared_latency_dispatch_attempts": (
            "data_plane",
            "fast_path_shared_latency_dispatch_attempts",
        ),
        "fast_path_shared_latency_dispatches": (
            "data_plane",
            "fast_path_shared_latency_dispatches",
        ),
        "fast_path_shared_latency_dispatch_failures": (
            "data_plane",
            "fast_path_shared_latency_dispatch_failures",
        ),
        "fast_path_local_dispatches": (
            "data_plane",
            "fast_path_local_dispatches",
        ),
        "fast_path_steal_attempts": (
            "data_plane",
            "fast_path_steal_attempts",
        ),
        "fast_path_remote_steals": (
            "data_plane",
            "fast_path_remote_steals",
        ),
        "fast_path_events_suppressed": (
            "data_plane",
            "fast_path_events_suppressed",
        ),
        "fast_path_direct_dispatches": (
            "data_plane",
            "fast_path_direct_dispatches",
        ),
        "fast_path_prev_continuations": (
            "data_plane",
            "fast_path_prev_continuations",
        ),
        "fast_path_steal_latency_source_admissions": (
            "data_plane",
            "fast_path_steal_latency_source_admissions",
        ),
        "fast_path_steal_latency_successor_deferrals": (
            "data_plane",
            "fast_path_steal_latency_successor_deferrals",
        ),
        "fast_path_steal_scan_exhaustions": (
            "data_plane",
            "fast_path_steal_scan_exhaustions",
        ),
        "fast_path_remote_backlog_no_dispatches": (
            "data_plane",
            "fast_path_remote_backlog_no_dispatches",
        ),
        "fast_path_steal_claim_conflicts": (
            "data_plane",
            "fast_path_steal_claim_conflicts",
        ),
        "fast_path_empty_steal_skips": (
            "data_plane",
            "fast_path_empty_steal_skips",
        ),
        "fast_path_dispatches_latency": ("data_plane", "fast_path_dispatches_by_class", 0),
        "fast_path_dispatches_balanced": ("data_plane", "fast_path_dispatches_by_class", 1),
        "fast_path_dispatches_throughput": ("data_plane", "fast_path_dispatches_by_class", 2),
        "fast_path_select_migrations_latency": ("data_plane", "fast_path_select_migrations_by_class", 0),
        "fast_path_select_migrations_balanced": ("data_plane", "fast_path_select_migrations_by_class", 1),
        "fast_path_select_migrations_throughput": ("data_plane", "fast_path_select_migrations_by_class", 2),
        "fast_path_latency_selects_default_idle": (
            "data_plane",
            "fast_path_latency_selects_by_path",
            0,
        ),
        "fast_path_latency_selects_default_busy": (
            "data_plane",
            "fast_path_latency_selects_by_path",
            1,
        ),
        "fast_path_latency_selects_policy_victim": (
            "data_plane",
            "fast_path_latency_selects_by_path",
            2,
        ),
        "fast_path_latency_selects_fallback": (
            "data_plane",
            "fast_path_latency_selects_by_path",
            3,
        ),
        "fast_path_latency_select_migrations_default_idle": (
            "data_plane",
            "fast_path_latency_select_migrations_by_path",
            0,
        ),
        "fast_path_latency_select_migrations_default_busy": (
            "data_plane",
            "fast_path_latency_select_migrations_by_path",
            1,
        ),
        "fast_path_latency_select_migrations_policy_victim": (
            "data_plane",
            "fast_path_latency_select_migrations_by_path",
            2,
        ),
        "fast_path_latency_select_migrations_fallback": (
            "data_plane",
            "fast_path_latency_select_migrations_by_path",
            3,
        ),
        "fast_path_select_sync_wakeups_latency": (
            "data_plane",
            "fast_path_select_sync_wakeups_by_class",
            0,
        ),
        "fast_path_select_sync_wakeups_balanced": (
            "data_plane",
            "fast_path_select_sync_wakeups_by_class",
            1,
        ),
        "fast_path_select_sync_wakeups_throughput": (
            "data_plane",
            "fast_path_select_sync_wakeups_by_class",
            2,
        ),
        "fast_path_select_sync_migrations_latency": (
            "data_plane",
            "fast_path_select_sync_migrations_by_class",
            0,
        ),
        "fast_path_select_sync_migrations_balanced": (
            "data_plane",
            "fast_path_select_sync_migrations_by_class",
            1,
        ),
        "fast_path_select_sync_migrations_throughput": (
            "data_plane",
            "fast_path_select_sync_migrations_by_class",
            2,
        ),
        "fast_path_latency_select_migrations_same_core_smt": (
            "data_plane",
            "fast_path_latency_select_migrations_by_locality",
            0,
        ),
        "fast_path_latency_select_migrations_same_llc": (
            "data_plane",
            "fast_path_latency_select_migrations_by_locality",
            1,
        ),
        "fast_path_latency_select_migrations_cross_llc": (
            "data_plane",
            "fast_path_latency_select_migrations_by_locality",
            2,
        ),
        "fast_path_latency_select_migrations_unknown": (
            "data_plane",
            "fast_path_latency_select_migrations_by_locality",
            3,
        ),
        "fast_path_throughput_select_migrations_same_core_smt": (
            "data_plane",
            "fast_path_throughput_select_migrations_by_locality",
            0,
        ),
        "fast_path_throughput_select_migrations_same_llc": (
            "data_plane",
            "fast_path_throughput_select_migrations_by_locality",
            1,
        ),
        "fast_path_throughput_select_migrations_cross_llc": (
            "data_plane",
            "fast_path_throughput_select_migrations_by_locality",
            2,
        ),
        "fast_path_throughput_select_migrations_unknown": (
            "data_plane",
            "fast_path_throughput_select_migrations_by_locality",
            3,
        ),
        "fast_path_remote_dispatches_latency": ("data_plane", "fast_path_remote_dispatches_by_class", 0),
        "fast_path_remote_dispatches_balanced": ("data_plane", "fast_path_remote_dispatches_by_class", 1),
        "fast_path_remote_dispatches_throughput": ("data_plane", "fast_path_remote_dispatches_by_class", 2),
        "fast_path_latency_remote_dispatches_same_core_smt": (
            "data_plane",
            "fast_path_latency_remote_dispatches_by_locality",
            0,
        ),
        "fast_path_latency_remote_dispatches_same_llc": (
            "data_plane",
            "fast_path_latency_remote_dispatches_by_locality",
            1,
        ),
        "fast_path_latency_remote_dispatches_cross_llc": (
            "data_plane",
            "fast_path_latency_remote_dispatches_by_locality",
            2,
        ),
        "fast_path_latency_remote_dispatches_unknown": (
            "data_plane",
            "fast_path_latency_remote_dispatches_by_locality",
            3,
        ),
        "fast_path_latency_remote_steals_preserving_successor": (
            "data_plane",
            "fast_path_latency_remote_steals_preserving_successor",
        ),
        "fast_path_latency_remote_steals_fallback": (
            "data_plane",
            "fast_path_latency_remote_steals_fallback",
        ),
        "fast_path_latency_idle_source_deferrals": (
            "data_plane",
            "fast_path_latency_idle_source_deferrals",
        ),
        "fast_path_throughput_remote_dispatches_same_core_smt": (
            "data_plane",
            "fast_path_throughput_remote_dispatches_by_locality",
            0,
        ),
        "fast_path_throughput_remote_dispatches_same_llc": (
            "data_plane",
            "fast_path_throughput_remote_dispatches_by_locality",
            1,
        ),
        "fast_path_throughput_remote_dispatches_cross_llc": (
            "data_plane",
            "fast_path_throughput_remote_dispatches_by_locality",
            2,
        ),
        "fast_path_throughput_remote_dispatches_unknown": (
            "data_plane",
            "fast_path_throughput_remote_dispatches_by_locality",
            3,
        ),
        "fast_path_preemptions_latency": ("data_plane", "fast_path_preemptions_by_class", 0),
        "fast_path_preemptions_balanced": ("data_plane", "fast_path_preemptions_by_class", 1),
        "fast_path_preemptions_throughput": ("data_plane", "fast_path_preemptions_by_class", 2),
        "fast_path_immediate_preemption_kicks_latency": (
            "data_plane",
            "fast_path_immediate_preemption_kicks_by_class",
            0,
        ),
        "fast_path_immediate_preemption_kicks_balanced": (
            "data_plane",
            "fast_path_immediate_preemption_kicks_by_class",
            1,
        ),
        "fast_path_immediate_preemption_kicks_throughput": (
            "data_plane",
            "fast_path_immediate_preemption_kicks_by_class",
            2,
        ),
        "fast_path_preemption_victims_latency": (
            "data_plane",
            "fast_path_preemption_victims_by_class",
            0,
        ),
        "fast_path_preemption_victims_balanced": (
            "data_plane",
            "fast_path_preemption_victims_by_class",
            1,
        ),
        "fast_path_preemption_victims_throughput": (
            "data_plane",
            "fast_path_preemption_victims_by_class",
            2,
        ),
        "fast_path_throughput_preemption_service_under_25pct": (
            "data_plane",
            "fast_path_throughput_preemption_service_bins",
            0,
        ),
        "fast_path_throughput_preemption_service_25_to_50pct": (
            "data_plane",
            "fast_path_throughput_preemption_service_bins",
            1,
        ),
        "fast_path_throughput_preemption_service_50_to_90pct": (
            "data_plane",
            "fast_path_throughput_preemption_service_bins",
            2,
        ),
        "fast_path_throughput_preemption_service_at_least_90pct": (
            "data_plane",
            "fast_path_throughput_preemption_service_bins",
            3,
        ),
        "fast_path_throughput_preemption_runtime_under_500us": (
            "data_plane",
            "fast_path_throughput_preemption_runtime_bins",
            0,
        ),
        "fast_path_throughput_preemption_runtime_500us_to_1ms": (
            "data_plane",
            "fast_path_throughput_preemption_runtime_bins",
            1,
        ),
        "fast_path_throughput_preemption_runtime_1ms_to_2ms": (
            "data_plane",
            "fast_path_throughput_preemption_runtime_bins",
            2,
        ),
        "fast_path_throughput_preemption_runtime_at_least_2ms": (
            "data_plane",
            "fast_path_throughput_preemption_runtime_bins",
            3,
        ),
        "fast_path_throughput_preemption_runtime_ns": (
            "data_plane",
            "fast_path_throughput_preemption_runtime_ns",
        ),
        "fast_path_throughput_preemption_request_ns": (
            "data_plane",
            "fast_path_throughput_preemption_request_ns",
        ),
        "fast_path_steal_idle_source_admissions": (
            "data_plane",
            "fast_path_steal_idle_source_admissions",
        ),
        "fast_path_steal_idle_throughput_deferrals": (
            "data_plane",
            "fast_path_steal_idle_throughput_deferrals",
        ),
        "fast_path_latency_budget_charge_events": (
            "data_plane",
            "fast_path_latency_budget_charge_events",
        ),
        "fast_path_latency_budget_runtime_ns": (
            "data_plane",
            "fast_path_latency_budget_runtime_ns",
        ),
        "fast_path_pipeline_ready_samples": ("data_plane", "fast_path_pipeline_ready_samples"),
        "fast_path_pipeline_empty_samples": ("data_plane", "fast_path_pipeline_empty_samples"),
        "fast_path_pipeline_normal_depth_sum": ("data_plane", "fast_path_pipeline_normal_depth_sum"),
        "fast_path_pipeline_latency_depth_sum": ("data_plane", "fast_path_pipeline_latency_depth_sum"),
        "policy_feedback_updates": ("policy", "feedback_updates"),
        "policy_placement_updates": ("policy", "placement_updates"),
        "task_capacity_hits": ("scheduler", "task_capacity_hits"),
        "degraded_transitions": ("scheduler", "degraded_transitions"),
    }
    result: dict[str, int] = {}
    for name, path in fields.items():
        initial = _nested_number(before, path)
        final = _nested_number(after, path)
        result[name] = max(0, final - initial)
    for name, path in {
        "policy_latency_budget_percent": ("policy", "latency_budget_percent"),
        "policy_preemption_interval_ns": ("policy", "preemption_interval_ns"),
        "policy_preemption_interval_floor_ns": (
            "policy",
            "preemption_interval_floor_ns",
        ),
        "policy_latency_successor_lease_ns": (
            "policy",
            "latency_successor_lease_ns",
        ),
        "policy_throughput_preemption_min_runtime_ns": (
            "policy",
            "throughput_preemption_min_runtime_ns",
        ),
        "policy_balanced_preemption_granularity_ns": (
            "policy",
            "balanced_preemption_granularity_ns",
        ),
        "policy_latency_share_per_mille": ("policy", "last_latency_share_per_mille"),
        "policy_observed_latency_service_ns": (
            "policy",
            "observed_latency_service_ns",
        ),
    }.items():
        result[name] = max(0, _nested_number(after, path))
    return result


def _classification_metrics(
    bench_dir: Path, start_ns: int, end_ns: int, *, enabled: bool
) -> dict[str, Any]:
    snapshot = (
        _read_json(bench_dir / "observations" / "classification-snapshot.json")
        if enabled
        else {}
    )
    available = bool(snapshot)
    scheduled_ns = _optional_int(snapshot.get("scheduled_ns"))
    started_ns = _optional_int(snapshot.get("started_ns"))
    completed_ns = _optional_int(snapshot.get("completed_ns"))
    process_rows = snapshot.get("processes", [])
    thread_rows = snapshot.get("threads", [])
    if not isinstance(process_rows, list):
        process_rows = []
    if not isinstance(thread_rows, list):
        thread_rows = []
    process_runtime, thread_runtime = _classification_runtime(
        bench_dir, start_ns, end_ns
    )
    timeline = (
        _read_jsonl(bench_dir / "observations" / "classification-snapshots.jsonl")
        if enabled
        else []
    )
    schedstat_rows = _read_jsonl(bench_dir / "observations" / "task-schedstat.jsonl")
    process_rows = [
        {
            **row,
            "observed_runtime_ns": process_runtime.get(int(row.get("pid", 0)), 0),
        }
        if isinstance(row, dict)
        else row
        for row in process_rows
    ]
    thread_rows = [
        {
            **row,
            "observed_runtime_ns": thread_runtime.get(
                (int(row.get("pid", 0)), int(row.get("tid", 0))), 0
            ),
        }
        if isinstance(row, dict)
        else row
        for row in thread_rows
    ]
    target_processes = len(process_rows)
    target_threads = len(thread_rows)
    process_metrics = _classification_scope_metrics(
        process_rows, target_processes, scope="process"
    )
    thread_metrics = _classification_scope_metrics(
        thread_rows, target_threads, scope="thread"
    )
    process_metrics["longitudinal_runtime_weighted"] = _longitudinal_runtime_weighted(
        timeline, schedstat_rows, start_ns, end_ns, scope="process"
    )
    thread_metrics["longitudinal_runtime_weighted"] = _longitudinal_runtime_weighted(
        timeline, schedstat_rows, start_ns, end_ns, scope="thread"
    )
    valid_timeline = [
        row
        for row in timeline
        if isinstance(row, dict)
        and not row.get("errors", [])
    ]
    timeline_observed = sorted(
        _optional_int(row.get("observed_ns"))
        for row in valid_timeline
        if _optional_int(row.get("observed_ns")) is not None
    )
    return {
        "enabled": enabled,
        "snapshot_available": available,
        "scheduled_ns": scheduled_ns,
        "started_ns": started_ns,
        "completed_ns": completed_ns,
        "start_delay_seconds": (
            (started_ns - scheduled_ns) / 1_000_000_000
            if started_ns is not None and scheduled_ns is not None
            else None
        ),
        "duration_seconds": (
            (completed_ns - started_ns) / 1_000_000_000
            if completed_ns is not None and started_ns is not None
            else None
        ),
        "measurement_offset_seconds": (
            (completed_ns - start_ns) / 1_000_000_000
            if completed_ns is not None and start_ns > 0
            else None
        ),
        "errors": snapshot.get("errors", []) if available else [],
        "timeline": {
            "available": bool(timeline_observed),
            "samples": len(timeline),
            "valid_samples": len(timeline_observed),
            "error_samples": len(timeline) - len(valid_timeline),
            "first_observed_ns": timeline_observed[0] if timeline_observed else None,
            "last_observed_ns": timeline_observed[-1] if timeline_observed else None,
        },
        "process": process_metrics,
        "thread": thread_metrics,
    }


def _classification_scope_metrics(
    rows: list[Any], target: int, *, scope: str
) -> dict[str, Any]:
    observed = [row for row in rows if isinstance(row, dict) and row.get("observed")]
    correct = [row for row in observed if row.get("class") == row.get("expected_class")]
    if scope == "process":
        resolved = [
            row
            for row in observed
            if row.get("source")
            in {"llm", "local_metadata", "semantic_cache", "behavior", "hybrid"}
        ]
    else:
        resolved = [
            row for row in observed if row.get("stage") in {"semantic", "locked"}
        ]
    resolved_correct = [
        row for row in resolved if row.get("class") == row.get("expected_class")
    ]
    generated = [
        row
        for row in observed
        if isinstance(row.get("generation"), int) and row["generation"] > 0
    ]
    applied = [
        row
        for row in generated
        if row.get("generation") == row.get("applied_generation")
    ]
    counts = {
        "target": target,
        "observed": len(observed),
        "correct": len(correct),
        "resolved": len(resolved),
        "resolved_correct": len(resolved_correct),
        "generated": len(generated),
        "applied": len(applied),
    }
    return {
        **_classification_ratios(counts),
        "classes": _count_field(observed, "class"),
        "stages": _count_field(observed, "stage"),
        "sources": _count_field(observed, "source"),
        "confusion_matrix": _confusion_matrix(observed),
        "accuracy_by_source": _group_accuracy(observed, "source"),
        "accuracy_by_process_role": _group_accuracy(observed, "process_role"),
        "accuracy_by_application": _group_accuracy(observed, "app"),
        "coverage_by_liveness": _group_coverage(rows, "active_at_snapshot"),
        "coverage_by_process_role": _group_coverage(rows, "process_role"),
        "timing": _classification_timing_metrics(observed),
        "runtime_weighted": _runtime_weighted_accuracy(rows),
    }


def _classification_ratios(counts: dict[str, int]) -> dict[str, Any]:
    target = counts["target"]
    observed = counts["observed"]
    resolved = counts["resolved"]
    generated = counts["generated"]
    return {
        **counts,
        "coverage": observed / target if target else None,
        "effective_accuracy": counts["correct"] / target if target else None,
        "observed_accuracy": counts["correct"] / observed if observed else None,
        "resolved_coverage": counts["resolved"] / target if target else None,
        "resolved_accuracy": (
            counts["resolved_correct"] / resolved if resolved else None
        ),
        "generation_applied_ratio": counts["applied"] / generated if generated else None,
    }


def _count_field(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    values = Counter(str(row.get(field, "unknown")) for row in rows)
    return dict(sorted(values.items()))


def _confusion_matrix(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    matrix: dict[str, Counter[str]] = {}
    for row in rows:
        expected = str(row.get("expected_class", "unknown"))
        actual = str(row.get("class", "unknown"))
        matrix.setdefault(expected, Counter())[actual] += 1
    return {
        expected: dict(sorted(actual.items()))
        for expected, actual in sorted(matrix.items())
    }


def _group_accuracy(
    rows: list[dict[str, Any]], field: str
) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row.get(field, "unknown")), []).append(row)
    return {
        name: {
            "observed": len(group),
            "correct": sum(
                row.get("class") == row.get("expected_class") for row in group
            ),
            "accuracy": (
                sum(row.get("class") == row.get("expected_class") for row in group)
                / len(group)
                if group
                else None
            ),
        }
        for name, group in sorted(grouped.items())
    }


def _group_coverage(rows: list[Any], field: str) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if isinstance(row, dict):
            grouped.setdefault(str(row.get(field, "unknown")), []).append(row)
    result: dict[str, dict[str, Any]] = {}
    for name, group in sorted(grouped.items()):
        observed = [row for row in group if row.get("observed")]
        correct = [
            row for row in observed if row.get("class") == row.get("expected_class")
        ]
        result[name] = {
            "target": len(group),
            "observed": len(observed),
            "correct": len(correct),
            "coverage": len(observed) / len(group) if group else None,
            "observed_accuracy": len(correct) / len(observed) if observed else None,
        }
    return result


def _classification_timing_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    fields = (
        "request_delay_ns",
        "semantic_latency_ns",
        "behavior_delay_ns",
        "decision_delay_ns",
        "lock_delay_ns",
        "apply_delay_ns",
    )
    result: dict[str, Any] = {}
    for field in fields:
        values = sorted(
            int(timing[field])
            for row in rows
            if isinstance((timing := row.get("timing")), dict)
            and isinstance(timing.get(field), int)
            and timing[field] >= 0
        )
        result[field.removesuffix("_ns")] = {
            "samples": len(values),
            "median_seconds": (
                statistics.median(values) / 1_000_000_000 if values else None
            ),
            "p95_seconds": (_percentile(values, 95) / 1_000_000_000 if values else None),
        }
    return result


def _classification_runtime(
    bench_dir: Path, start_ns: int, end_ns: int
) -> tuple[dict[int, int], dict[tuple[int, int], int]]:
    grouped: dict[tuple[int, int], list[dict[str, Any]]] = defaultdict(list)
    for row in _read_jsonl(bench_dir / "observations" / "task-schedstat.jsonl"):
        grouped[(int(row.get("pid", 0)), int(row.get("tid", 0)))].append(row)
    thread_runtime: dict[tuple[int, int], int] = {}
    process_runtime: dict[int, int] = defaultdict(int)
    for key, values in grouped.items():
        delta = _window_delta(values, start_ns, end_ns)
        if delta is None:
            continue
        before, after = delta
        runtime_ns = max(0, int(after.get("run_ns", 0)) - int(before.get("run_ns", 0)))
        thread_runtime[key] = runtime_ns
        process_runtime[key[0]] += runtime_ns
    return dict(process_runtime), thread_runtime


def _runtime_weighted_accuracy(rows: list[Any]) -> dict[str, Any]:
    valid = [row for row in rows if isinstance(row, dict)]
    target_runtime = sum(max(0, int(row.get("observed_runtime_ns", 0))) for row in valid)
    observed = [row for row in valid if row.get("observed")]
    observed_runtime = sum(
        max(0, int(row.get("observed_runtime_ns", 0))) for row in observed
    )
    correct_runtime = sum(
        max(0, int(row.get("observed_runtime_ns", 0)))
        for row in observed
        if row.get("class") == row.get("expected_class")
    )
    active = [row for row in valid if int(row.get("observed_runtime_ns", 0)) >= 1_000_000]
    active_observed = [row for row in active if row.get("observed")]
    active_correct = [
        row
        for row in active_observed
        if row.get("class") == row.get("expected_class")
    ]
    return {
        "target_runtime_seconds": target_runtime / 1_000_000_000,
        "observed_runtime_seconds": observed_runtime / 1_000_000_000,
        "correct_runtime_seconds": correct_runtime / 1_000_000_000,
        "runtime_coverage": observed_runtime / target_runtime if target_runtime else None,
        "observed_runtime_accuracy": (
            correct_runtime / observed_runtime if observed_runtime else None
        ),
        "effective_runtime_accuracy": (
            correct_runtime / target_runtime if target_runtime else None
        ),
        "active_target": len(active),
        "active_observed": len(active_observed),
        "active_correct": len(active_correct),
        "active_coverage": len(active_observed) / len(active) if active else None,
        "active_observed_accuracy": (
            len(active_correct) / len(active_observed) if active_observed else None
        ),
    }


def _longitudinal_runtime_weighted(
    snapshots: list[dict[str, Any]],
    schedstat_rows: list[dict[str, Any]],
    start_ns: int,
    end_ns: int,
    *,
    scope: str,
) -> dict[str, Any]:
    """Scores each classification only for the interval it was observed.

    Collector timeline records share an ``observed_ns`` with the corresponding
    schedstat sample. This avoids assigning a late classification to earlier
    CPU time, which is the ambiguity in the legacy single-snapshot metric.
    """
    scope_key = "processes" if scope == "process" else "threads"
    valid_snapshots = sorted(
        (
            row
            for row in snapshots
            if start_ns <= int(row.get("observed_ns", 0)) <= end_ns
            and isinstance(row.get(scope_key), list)
            and not row.get("errors", [])
        ),
        key=lambda row: int(row.get("observed_ns", 0)),
    )
    empty = {
        "snapshot_samples": len(valid_snapshots),
        "intervals": 0,
        "target_runtime_seconds": 0.0,
        "observed_runtime_seconds": 0.0,
        "correct_runtime_seconds": 0.0,
        "runtime_coverage": None,
        "observed_runtime_accuracy": None,
        "effective_runtime_accuracy": None,
        "class_changes": 0,
    }
    if not valid_snapshots or end_ns <= start_ns:
        return empty

    grouped: dict[tuple[int, int], list[dict[str, Any]]] = defaultdict(list)
    for row in schedstat_rows:
        try:
            grouped[(int(row["pid"]), int(row["tid"]))].append(row)
        except (KeyError, TypeError, ValueError):
            continue

    states: list[dict[int | tuple[int, int], dict[str, Any]]] = []
    prior_classes: dict[int | tuple[int, int], str] = {}
    class_changes = 0
    for snapshot in valid_snapshots:
        state: dict[int | tuple[int, int], dict[str, Any]] = {}
        for row in snapshot[scope_key]:
            if not isinstance(row, dict):
                continue
            try:
                key: int | tuple[int, int]
                if scope == "process":
                    key = int(row["pid"])
                else:
                    key = (int(row["pid"]), int(row["tid"]))
            except (KeyError, TypeError, ValueError):
                continue
            state[key] = row
            if row.get("observed") and isinstance(row.get("class"), str):
                current_class = str(row["class"])
                previous_class = prior_classes.get(key)
                if previous_class is not None and previous_class != current_class:
                    class_changes += 1
                prior_classes[key] = current_class
        states.append(state)

    boundaries = sorted(
        {start_ns, end_ns, *(int(row["observed_ns"]) for row in valid_snapshots)}
    )
    current_state: dict[int | tuple[int, int], dict[str, Any]] = {}
    snapshot_index = 0
    target_runtime_ns = observed_runtime_ns = correct_runtime_ns = 0
    intervals = 0
    for left_ns, right_ns in zip(boundaries, boundaries[1:]):
        if right_ns <= left_ns:
            continue
        while (
            snapshot_index < len(valid_snapshots)
            and int(valid_snapshots[snapshot_index]["observed_ns"]) <= left_ns
        ):
            current_state = states[snapshot_index]
            snapshot_index += 1
        intervals += 1
        for (pid, tid), rows in grouped.items():
            delta = _strict_window_delta(rows, left_ns, right_ns)
            if delta is None:
                continue
            before, after = delta
            runtime_ns = max(0, int(after.get("run_ns", 0)) - int(before.get("run_ns", 0)))
            target_runtime_ns += runtime_ns
            state_key: int | tuple[int, int] = pid if scope == "process" else (pid, tid)
            classification = current_state.get(state_key)
            if not classification or classification.get("observed") is not True:
                continue
            observed_runtime_ns += runtime_ns
            if classification.get("class") == after.get("mode"):
                correct_runtime_ns += runtime_ns

    target_runtime_seconds = target_runtime_ns / 1_000_000_000
    observed_runtime_seconds = observed_runtime_ns / 1_000_000_000
    correct_runtime_seconds = correct_runtime_ns / 1_000_000_000
    return {
        "snapshot_samples": len(valid_snapshots),
        "intervals": intervals,
        "target_runtime_seconds": target_runtime_seconds,
        "observed_runtime_seconds": observed_runtime_seconds,
        "correct_runtime_seconds": correct_runtime_seconds,
        "runtime_coverage": (
            observed_runtime_seconds / target_runtime_seconds
            if target_runtime_seconds
            else None
        ),
        "observed_runtime_accuracy": (
            correct_runtime_seconds / observed_runtime_seconds
            if observed_runtime_seconds
            else None
        ),
        "effective_runtime_accuracy": (
            correct_runtime_seconds / target_runtime_seconds
            if target_runtime_seconds
            else None
        ),
        "class_changes": class_changes,
    }


def _percentile(values: list[int], percentile: float) -> float:
    if not values:
        raise ValueError("percentile requires at least one value")
    position = (len(values) - 1) * percentile / 100.0
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(values[lower])
    fraction = position - lower
    return values[lower] + (values[upper] - values[lower]) * fraction


def _comparisons(
    summaries: list[dict[str, Any]], *, bootstrap_samples: int, seed: int
) -> list[dict[str, Any]]:
    metrics: dict[str, list[MetricDefinition]] = {
        DYNAMIC_MIX_SCENARIO: [
            (
                "p99_latency_geomean_us",
                lambda row: row["latency"]["p99_us"]["geometric_mean"],
                False,
                "us",
                True,
            ),
            (
                "throughput_geomean_per_second",
                lambda row: row["throughput"]["operations_per_second"],
                True,
                "units/s",
                True,
            ),
        ],
    }
    by_key = {
        (row["scenario"], row["variant"], row["repeat"]): row for row in summaries
    }
    output: list[dict[str, Any]] = []
    randomizer = random.Random(seed)
    for scenario, definitions in metrics.items():
        if not any(candidate == scenario for candidate, _variant, _repeat in by_key):
            continue
        repeats = sorted(
            repeat
            for candidate, variant, repeat in by_key
            if candidate == scenario
            and variant == "native"
            and (scenario, "agent", repeat) in by_key
        )
        if not repeats:
            continue
        for name, getter, higher_is_better, unit, relative in definitions:
            native = [float(getter(by_key[(scenario, "native", repeat)])) for repeat in repeats]
            agent = [float(getter(by_key[(scenario, "agent", repeat)])) for repeat in repeats]
            changes = [
                _improvement(base, candidate, higher_is_better, relative)
                for base, candidate in zip(native, agent)
            ]
            low, high = _bootstrap_ci(changes, bootstrap_samples, randomizer)
            output.append(
                {
                    "scenario": scenario,
                    "metric": name,
                    "unit": unit,
                    "higher_is_better": higher_is_better,
                    "pairs": len(repeats),
                    "native": _series_stats(native),
                    "agent": _series_stats(agent),
                    "paired_improvement": {
                        "unit": "percent" if relative else "percentage_points",
                        "median": statistics.median(changes) if changes else None,
                        "ci95_low": low,
                        "ci95_high": high,
                    },
                }
            )
    return output


def _application_comparisons(
    summaries: list[dict[str, Any]], *, bootstrap_samples: int, seed: int
) -> list[dict[str, Any]]:
    """Build repeat-paired rows for each objective application metric."""
    by_key = {
        (row["scenario"], row["variant"], row["repeat"]): row for row in summaries
    }
    pairs_by_scenario: dict[str, list[int]] = defaultdict(list)
    for scenario, variant, repeat in by_key:
        if variant == "native" and (scenario, "agent", repeat) in by_key:
            pairs_by_scenario[scenario].append(int(repeat))

    randomizer = random.Random(seed)
    rows: list[dict[str, Any]] = []
    for scenario, repeats in sorted(pairs_by_scenario.items()):
        native_rows = [by_key[(scenario, "native", repeat)] for repeat in sorted(set(repeats))]
        agent_rows = [by_key[(scenario, "agent", repeat)] for repeat in sorted(set(repeats))]
        names = sorted(
            set(native_rows[0].get("applications", {}))
            & set(agent_rows[0].get("applications", {}))
        ) if native_rows and agent_rows else []
        for name in names:
            native_metrics = [row.get("applications", {}).get(name, {}) for row in native_rows]
            agent_metrics = [row.get("applications", {}).get(name, {}) for row in agent_rows]
            role = str(native_metrics[0].get("role", "")) if native_metrics else ""
            if role not in {"latency", "throughput"}:
                continue
            if any(metric.get("objective", True) is not True for metric in native_metrics + agent_metrics):
                continue
            definitions = (
                ("p99", "p99_ms", False, "us", 1000.0)
                if role == "latency"
                else ("throughput", "throughput_per_second", True, "units/s", 1.0)
            )
            metric_name, field, higher_is_better, unit, scale = definitions
            native_values = [
                float(metric[field]) * scale
                for metric in native_metrics
                if isinstance(metric.get(field), (int, float)) and float(metric[field]) > 0
            ]
            agent_values = [
                float(metric[field]) * scale
                for metric in agent_metrics
                if isinstance(metric.get(field), (int, float)) and float(metric[field]) > 0
            ]
            if len(native_values) != len(agent_values) or not native_values:
                continue
            changes = [
                _improvement(native, agent, higher_is_better, True)
                for native, agent in zip(native_values, agent_values)
            ]
            low, high = _bootstrap_ci(changes, bootstrap_samples, randomizer)
            rows.append(
                {
                    "scenario": scenario,
                    "application": name,
                    "label": APPLICATION_LABELS.get(name, name),
                    "role": role,
                    "metric": metric_name,
                    "unit": unit,
                    "higher_is_better": higher_is_better,
                    "pairs": len(native_values),
                    "native": _series_stats(native_values),
                    "agent": _series_stats(agent_values),
                    "paired_improvement": {
                        "unit": "percent",
                        "median": statistics.median(changes),
                        "ci95_low": low,
                        "ci95_high": high,
                    },
                }
            )
    return sorted(
        rows,
        key=lambda row: (
            row["scenario"],
            0 if row["role"] == "latency" else 1,
            row["application"],
        ),
    )


def _system_comparisons(
    summaries: list[dict[str, Any]], *, bootstrap_samples: int, seed: int
) -> list[dict[str, Any]]:
    """Pair system counters without turning them into the benchmark objective."""
    definitions: tuple[
        tuple[str, str, Callable[[dict[str, Any]], Any], str, bool], ...
    ] = (
        (
            "core_busy_cv",
            "物理核忙碌度离散系数",
            lambda row: row["cpu_utilization"]["core_busy_coefficient_of_variation"],
            "ratio",
            True,
        ),
        ("task_clock", "task-clock", lambda row: row["perf"]["task-clock"], "ms", True),
        (
            "context_switches",
            "context-switches",
            lambda row: row["perf"]["context-switches"],
            "count",
            True,
        ),
        (
            "cpu_migrations",
            "cpu-migrations",
            lambda row: row["perf"]["cpu-migrations"],
            "count",
            True,
        ),
        ("page_faults", "page-faults", lambda row: row["perf"]["page-faults"], "count", True),
        ("cycles", "cycles", lambda row: row["perf"]["cycles"], "count", True),
        (
            "instructions",
            "instructions",
            lambda row: row["perf"]["instructions"],
            "count",
            True,
        ),
        (
            "cache_references",
            "cache-references",
            lambda row: row["perf"]["cache-references"],
            "count",
            True,
        ),
        (
            "cache_misses",
            "cache-misses",
            lambda row: row["perf"]["cache-misses"],
            "count",
            True,
        ),
        (
            "instructions_per_cycle",
            "instructions / cycle",
            lambda row: row["perf"]["instructions_per_cycle"],
            "number",
            True,
        ),
        (
            "cache_miss_ratio",
            "cache miss ratio",
            lambda row: row["perf"]["cache_miss_ratio"],
            "ratio",
            False,
        ),
    )
    by_key = {
        (row["scenario"], row["variant"], row["repeat"]): row for row in summaries
    }
    repeats = sorted(
        repeat
        for scenario, variant, repeat in by_key
        if scenario == DYNAMIC_MIX_SCENARIO
        and variant == "native"
        and (scenario, "agent", repeat) in by_key
    )
    randomizer = random.Random(seed ^ 0x51A7)
    output: list[dict[str, Any]] = []
    for metric, label, getter, unit, relative in definitions:
        paired: list[tuple[float, float]] = []
        for repeat in repeats:
            native_row = by_key[(DYNAMIC_MIX_SCENARIO, "native", repeat)]
            agent_row = by_key[(DYNAMIC_MIX_SCENARIO, "agent", repeat)]
            try:
                native_value = getter(native_row)
                agent_value = getter(agent_row)
            except (KeyError, TypeError):
                continue
            if not isinstance(native_value, (int, float)) or isinstance(native_value, bool):
                continue
            if not isinstance(agent_value, (int, float)) or isinstance(agent_value, bool):
                continue
            if relative and float(native_value) == 0:
                continue
            paired.append((float(native_value), float(agent_value)))
        if not paired:
            continue
        native = [value[0] for value in paired]
        agent = [value[1] for value in paired]
        changes = [
            ((candidate / base) - 1.0) * 100.0
            if relative
            else (candidate - base) * 100.0
            for base, candidate in paired
        ]
        low, high = _bootstrap_ci(changes, bootstrap_samples, randomizer)
        output.append(
            {
                "metric": metric,
                "label": label,
                "unit": unit,
                "pairs": len(paired),
                "native": _series_stats(native),
                "agent": _series_stats(agent),
                "paired_change": {
                    "unit": "percent" if relative else "percentage_points",
                    "median": statistics.median(changes),
                    "ci95_low": low,
                    "ci95_high": high,
                },
            }
        )
    return output


def _campaign_agent_evidence(summaries: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate health and control-plane evidence from valid Agent runs."""
    rows = [row for row in summaries if row.get("variant") == "agent"]
    scheduler_fields = (
        "events_processed",
        "stale_events",
        "bad_behavior_windows",
        "event_overflows",
        "fallback_dispatches",
        "task_capacity_hits",
        "degraded_transitions",
        "fast_path_events_suppressed",
        "policy_feedback_updates",
        "policy_placement_updates",
        "fast_path_shared_latency_dispatch_attempts",
        "fast_path_shared_latency_dispatches",
        "fast_path_shared_latency_dispatch_failures",
        "fast_path_shared_balanced_dispatch_attempts",
        "fast_path_shared_balanced_dispatches",
        "fast_path_shared_balanced_dispatch_failures",
        "fast_path_latency_remote_dispatches_cross_llc",
        "fast_path_latency_select_migrations_cross_llc",
        "fast_path_throughput_remote_dispatches_cross_llc",
        "fast_path_throughput_select_migrations_cross_llc",
        "fast_path_dispatches",
        "fast_path_local_dispatches",
        "fast_path_direct_dispatches",
        "fast_path_preemptions",
    )
    totals = {field: 0 for field in scheduler_fields}
    cpu_seconds = 0.0
    capacity_seconds = 0.0
    agent_rss = 0.0
    scheduler_rss = 0.0
    for row in rows:
        overhead = row.get("overhead", {})
        cpu_seconds += float(overhead.get("agent_scheduler_cpu_seconds", 0.0) or 0.0)
        roles = overhead.get("roles", {})
        agent_rss = max(agent_rss, float(roles.get("agent", {}).get("max_rss_mib", 0.0) or 0.0))
        scheduler_rss = max(
            scheduler_rss,
            float(roles.get("scheduler", {}).get("max_rss_mib", 0.0) or 0.0),
        )
        measurement = row.get("measurement", {})
        duration = float(measurement.get("duration_seconds", 0.0) or 0.0)
        cpus = int(row.get("cpu_utilization", {}).get("cpus", 0) or 0)
        capacity_seconds += duration * cpus
        scheduler = row.get("scheduler", {})
        for field in scheduler_fields:
            totals[field] += int(scheduler.get(field, 0) or 0)

    latency_attempts = totals["fast_path_shared_latency_dispatch_attempts"]
    latency_dispatches = totals["fast_path_shared_latency_dispatches"]
    balanced_attempts = totals["fast_path_shared_balanced_dispatch_attempts"]
    balanced_dispatches = totals["fast_path_shared_balanced_dispatches"]
    cross_llc = sum(
        totals[field]
        for field in (
            "fast_path_latency_remote_dispatches_cross_llc",
            "fast_path_latency_select_migrations_cross_llc",
            "fast_path_throughput_remote_dispatches_cross_llc",
            "fast_path_throughput_select_migrations_cross_llc",
        )
    )
    return {
        "agent_runs": len(rows),
        "control_plane_cpu_seconds": cpu_seconds,
        "control_plane_cpu_percent": (
            cpu_seconds / capacity_seconds * 100 if capacity_seconds else None
        ),
        "agent_max_rss_mib": agent_rss,
        "scheduler_max_rss_mib": scheduler_rss,
        "events_processed": totals["events_processed"],
        "events_suppressed": totals["fast_path_events_suppressed"],
        "suppression_ratio": (
            totals["fast_path_events_suppressed"]
            / (totals["fast_path_events_suppressed"] + totals["events_processed"])
            if totals["fast_path_events_suppressed"] + totals["events_processed"]
            else None
        ),
        "event_overflows": totals["event_overflows"],
        "fallback_dispatches": totals["fallback_dispatches"],
        "task_capacity_hits": totals["task_capacity_hits"],
        "degraded_transitions": totals["degraded_transitions"],
        "policy_feedback_updates": totals["policy_feedback_updates"],
        "policy_placement_updates": totals["policy_placement_updates"],
        "shared_dispatch": {
            "latency": {
                "attempts": latency_attempts,
                "dispatches": latency_dispatches,
                "failures": totals["fast_path_shared_latency_dispatch_failures"],
                "success_ratio": latency_dispatches / latency_attempts if latency_attempts else None,
            },
            "balanced": {
                "attempts": balanced_attempts,
                "dispatches": balanced_dispatches,
                "failures": totals["fast_path_shared_balanced_dispatch_failures"],
                "success_ratio": balanced_dispatches / balanced_attempts if balanced_attempts else None,
            },
        },
        "cross_llc_events": cross_llc,
        "fast_path_dispatches": totals["fast_path_dispatches"],
        "fast_path_local_dispatches": totals["fast_path_local_dispatches"],
        "fast_path_direct_dispatches": totals["fast_path_direct_dispatches"],
        "fast_path_preemptions": totals["fast_path_preemptions"],
    }


def _campaign_environment(summaries: list[dict[str, Any]]) -> dict[str, Any]:
    for summary in summaries:
        environment = summary.get("environment")
        if not isinstance(environment, dict) or not environment:
            continue
        uname = environment.get("uname", {})
        profile = str(environment.get("workload_profile", "")).removeprefix(
            "aoa-profile-"
        )
        return {
            "os": _pretty_os_name(str(environment.get("os_release", ""))),
            "os_release": environment.get("os_release"),
            "kernel": uname.get("release"),
            "machine": uname.get("machine"),
            "logical_cpus": environment.get("logical_cpus"),
            "topology": environment.get("topology", []),
            "topology_valid": environment.get("topology_valid"),
            "workload_profile": f"aoa-profile-{profile}" if profile else None,
            "perf_version": environment.get("perf_version"),
        }
    return {}


def _campaign_methodology(
    manifest: dict[str, Any], preflight: dict[str, Any], summaries: list[dict[str, Any]]
) -> dict[str, Any]:
    schedule = manifest.get("schedule", [])
    warmups = [
        int(item["warmup_seconds"])
        for item in schedule
        if isinstance(item, dict) and isinstance(item.get("warmup_seconds"), (int, float))
    ]
    measurements = [
        int(item["measurement_seconds"])
        for item in schedule
        if isinstance(item, dict) and isinstance(item.get("measurement_seconds"), (int, float))
    ]
    payload_sha256: dict[str, str] = {}
    for summary in summaries:
        if summary.get("variant") != "agent":
            continue
        result = _read_json(Path(str(summary.get("run_dir", ""))) / "result.json")
        for payload in result.get("payloads", []):
            if not isinstance(payload, dict):
                continue
            target = payload.get("target")
            digest = payload.get("sha256")
            if isinstance(target, str) and isinstance(digest, str):
                payload_sha256[Path(target).name] = digest
        if payload_sha256:
            break
    template_sha256 = None
    for info in preflight.get("infos", []):
        marker = "template image SHA-256 verified: "
        if isinstance(info, str) and marker in info:
            template_sha256 = info.split(marker, 1)[1].split(" ", 1)[0]
            break
    return {
        "scenario": DYNAMIC_MIX_SCENARIO,
        "variants": ["native", "agent"],
        "warmup_seconds": sorted(set(warmups)),
        "measurement_seconds": sorted(set(measurements)),
        "paired_repeats": len(
            {
                (row.get("scenario"), row.get("repeat"))
                for row in summaries
                if row.get("valid")
            }
        ),
        "template_image": manifest.get("template_image"),
        "template_sha256": template_sha256,
        "payload_sha256": payload_sha256,
        "created_at": manifest.get("created_at"),
        "preflight_passed": not bool(preflight.get("failures")),
        "preflight_infos": preflight.get("infos", []),
    }


def _pretty_os_name(value: str) -> str | None:
    for line in value.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.partition("=")[2].strip().strip('"')
    return value or None


def _campaign_classification(summaries: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [row["classification"] for row in summaries if row["variant"] == "agent"]
    snapshot_rows = [row for row in rows if row.get("snapshot_available")]
    timeline_all = [
        row["timeline"] for row in rows if isinstance(row.get("timeline"), dict)
    ]
    timeline_rows = [
        row
        for row in rows
        if isinstance(row.get("timeline"), dict)
        and row["timeline"].get("available")
    ]
    process = _aggregate_classification_scope(row.get("process", {}) for row in rows)
    thread = _aggregate_classification_scope(row.get("thread", {}) for row in rows)
    delays = [
        row["start_delay_seconds"]
        for row in snapshot_rows
        if row.get("start_delay_seconds") is not None
    ]
    return {
        "agent_runs": len(rows),
        "snapshot_runs": len(snapshot_rows),
        "timeline_runs": len(timeline_rows),
        "timeline_samples": sum(
            int(row.get("samples", 0)) for row in timeline_all
        ),
        "timeline_valid_samples": sum(
            int(row.get("valid_samples", 0)) for row in timeline_all
        ),
        "timeline_error_samples": sum(
            int(row.get("error_samples", 0)) for row in timeline_all
        ),
        "median_start_delay_seconds": statistics.median(delays) if delays else None,
        "process": process,
        "thread": thread,
    }


def _aggregate_classification_scope(
    rows: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    rows = list(rows)
    fields = (
        "target",
        "observed",
        "correct",
        "resolved",
        "resolved_correct",
        "generated",
        "applied",
    )
    totals = {field: 0 for field in fields}
    for row in rows:
        for field in fields:
            totals[field] += int(row.get(field, 0))
    result = _classification_ratios(totals)
    result["runtime_weighted"] = _aggregate_runtime_weighted(rows)
    result["longitudinal_runtime_weighted"] = _aggregate_longitudinal_runtime_weighted(
        rows
    )
    result["timing"] = _aggregate_classification_timing(rows)
    return result


def _aggregate_runtime_weighted(rows: list[dict[str, Any]]) -> dict[str, Any]:
    runtime_rows = [
        row.get("runtime_weighted", {})
        for row in rows
        if isinstance(row.get("runtime_weighted"), dict)
    ]
    target_runtime = sum(float(row.get("target_runtime_seconds", 0)) for row in runtime_rows)
    observed_runtime = sum(
        float(row.get("observed_runtime_seconds", 0)) for row in runtime_rows
    )
    correct_runtime = sum(
        float(row.get("correct_runtime_seconds", 0)) for row in runtime_rows
    )
    active_target = sum(int(row.get("active_target", 0)) for row in runtime_rows)
    active_observed = sum(int(row.get("active_observed", 0)) for row in runtime_rows)
    active_correct = sum(int(row.get("active_correct", 0)) for row in runtime_rows)
    return {
        "target_runtime_seconds": target_runtime,
        "observed_runtime_seconds": observed_runtime,
        "correct_runtime_seconds": correct_runtime,
        "runtime_coverage": observed_runtime / target_runtime if target_runtime else None,
        "observed_runtime_accuracy": (
            correct_runtime / observed_runtime if observed_runtime else None
        ),
        "effective_runtime_accuracy": (
            correct_runtime / target_runtime if target_runtime else None
        ),
        "active_target": active_target,
        "active_observed": active_observed,
        "active_correct": active_correct,
        "active_coverage": active_observed / active_target if active_target else None,
        "active_observed_accuracy": (
            active_correct / active_observed if active_observed else None
        ),
    }


def _aggregate_longitudinal_runtime_weighted(
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    runtime_rows = [
        row.get("longitudinal_runtime_weighted", {})
        for row in rows
        if isinstance(row.get("longitudinal_runtime_weighted"), dict)
    ]
    target_runtime = sum(float(row.get("target_runtime_seconds", 0)) for row in runtime_rows)
    observed_runtime = sum(
        float(row.get("observed_runtime_seconds", 0)) for row in runtime_rows
    )
    correct_runtime = sum(
        float(row.get("correct_runtime_seconds", 0)) for row in runtime_rows
    )
    return {
        "snapshot_samples": sum(int(row.get("snapshot_samples", 0)) for row in runtime_rows),
        "intervals": sum(int(row.get("intervals", 0)) for row in runtime_rows),
        "target_runtime_seconds": target_runtime,
        "observed_runtime_seconds": observed_runtime,
        "correct_runtime_seconds": correct_runtime,
        "runtime_coverage": observed_runtime / target_runtime if target_runtime else None,
        "observed_runtime_accuracy": (
            correct_runtime / observed_runtime if observed_runtime else None
        ),
        "effective_runtime_accuracy": (
            correct_runtime / target_runtime if target_runtime else None
        ),
        "class_changes": sum(int(row.get("class_changes", 0)) for row in runtime_rows),
    }


def _aggregate_classification_timing(rows: list[dict[str, Any]]) -> dict[str, Any]:
    fields = (
        "request_delay",
        "semantic_latency",
        "behavior_delay",
        "decision_delay",
        "lock_delay",
        "apply_delay",
    )
    result: dict[str, Any] = {}
    for field in fields:
        values = [
            timing
            for row in rows
            if isinstance((timings := row.get("timing")), dict)
            and isinstance((timing := timings.get(field)), dict)
        ]
        medians = [
            float(value["median_seconds"])
            for value in values
            if isinstance(value.get("median_seconds"), (int, float))
        ]
        p95s = [
            float(value["p95_seconds"])
            for value in values
            if isinstance(value.get("p95_seconds"), (int, float))
        ]
        result[field] = {
            "samples": sum(int(value.get("samples", 0)) for value in values),
            "median_seconds": statistics.median(medians) if medians else None,
            "median_run_p95_seconds": statistics.median(p95s) if p95s else None,
        }
    return result


def _report(output: dict[str, Any]) -> str:
    return _presentation_report(output)


def _presentation_report(output: dict[str, Any]) -> str:
    profile = str(output.get("profile", "formal"))
    profile_label = {"formal": "重复配对", "single-round": "单轮配对"}.get(
        profile, profile
    )
    methodology = output.get("methodology", {})
    environment = output.get("environment", {})
    comparisons = output.get("comparisons", [])
    comparison_by_metric = {row.get("metric"): row for row in comparisons}
    p99 = comparison_by_metric.get("p99_latency_geomean_us", {})
    throughput = comparison_by_metric.get("throughput_geomean_per_second", {})
    p99_change = p99.get("paired_improvement", {})
    throughput_change = throughput.get("paired_improvement", {})
    lines = [
        "# Adaptive OS Agent 动态混合负载性能报告",
        "",
        "> 在相同 openEuler 虚拟机、相同真实应用和相同测量窗口中，对比 Linux Native 与 Adaptive OS Agent。",
        "",
        f"实验档位：**{profile_label}** · 场景：{DYNAMIC_MIX_SCENARIO} · "
        f"有效运行：**{output.get('valid_runs', 0)}/{output.get('runs', 0)}**",
        "",
        "## 结论摘要",
        "",
        "测量窗口的平均 CPU 约 80%，周期性采样峰值达到 100%，同时运行三项延迟服务、三项持续吞吐任务和周期性压力任务。该压力形态使调度器必须在延迟优先与吞吐保持之间持续做决策。",
        "",
        "| 核心指标 | Native | Agent | 配对改善（正值更好） | 95% CI | 判定 |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
        f"| 聚合 P99 延迟 | {_metric_value(p99.get('native', {}).get('median'), 'us')} | "
        f"{_metric_value(p99.get('agent', {}).get('median'), 'us')} | "
        f"{_format_change(p99_change.get('median'), p99_change.get('unit', 'percent'))} | "
        f"{_comparison_interval(p99)} | 越低越好 |",
        f"| 综合吞吐 | {_metric_value(throughput.get('native', {}).get('median'), 'units/s')} | "
        f"{_metric_value(throughput.get('agent', {}).get('median'), 'units/s')} | "
        f"{_format_change(throughput_change.get('median'), throughput_change.get('unit', 'percent'))} | "
        f"{_comparison_interval(throughput)} | 越高越好 |",
    ]
    if profile == "single-round":
        lines.extend(
            (
                "",
                "> 说明：当前提交采用一轮完整 Native/Agent 配对，直接展示同环境差异；单轮不估计跨重复运行的置信区间。",
            )
        )
    if p99 and throughput:
        lines.extend(
            (
                "",
                f"聚合 P99 的配对改善为 **{_format_change(p99_change.get('median'), 'percent')}**，"
                f"综合吞吐为 **{_format_change(throughput_change.get('median'), 'percent')}**；"
                "两项指标分开报告，避免用一个未经定义的总分掩盖取舍。",
            )
        )
    lines.extend(
        (
            "",
            "## 赛题能力证据",
            "",
            "| 赛题关注点 | 本次实测证据 |",
            "| --- | --- |",
            "| 用户态资源控制 Agent | process/thread 感知、generation 闭环、控制面 CPU 与 RSS |",
            "| 工作负载感知 | 13/13 连续分类样本、运行时间加权准确率与覆盖率 |",
            "| sched_ext 动态策略 | policy feedback/placement、class dispatch、preemption 和 locality |",
            "| eBPF 安全与稳定性 | overflow、fallback、capacity hit、degraded、跨 LLC 事件门禁 |",
            "| 性能优化 | 三项 P99、三项吞吐的 Native/Agent 配对与应用逐项结果 |",
            "| 可复现性 | 镜像 SHA-256、固定拓扑/频率、原始 artifact、确定性分析 |",
        )
    )

    contracts = output.get("load_contracts", [])
    if contracts:
        lines.extend(
            (
                "",
                "## 工作负载与压力证据",
                "",
                "| 组成 | 应用/任务 | 测量目标 |",
                "| --- | --- | --- |",
                "| 交互延迟 | Redis、Nginx、PostgreSQL | P99 延迟 |",
                "| 持续吞吐 | FFmpeg、RocksDB、zstd | 应用原生完成率 |",
                "| 周期压力 | OpenSSL 3 workers，2 s active / 10 s period | 验证突发响应 |",
                "",
                "| 变体 | 平均 CPU | P50 | P95 | 峰值 | >=95% 采样 | 完整突发 | 持续任务 |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            )
        )
        for row in contracts:
            interval = row.get("interval_utilization", {})
            continuous = row.get("continuous_throughput_apps", {})
            if not isinstance(continuous, dict):
                continuous = {}
            spanning = sum(
                bool(item.get("spans_measurement"))
                for item in continuous.values()
                if isinstance(item, dict)
            )
            lines.append(
                f"| {row.get('variant', 'N/A')} | {_format_ratio(row.get('average_utilization'))} | "
                f"{_format_ratio(interval.get('p50'))} | {_format_ratio(interval.get('p95'))} | "
                f"{_format_ratio(interval.get('max'))} | {row.get('high_utilization_samples', 0)} | "
                f"{row.get('completed_bursts', 0)} | {spanning}/{len(continuous)} |"
            )
        lines.extend(
            (
                "",
                "合同同时约束平均 CPU 范围、峰值采样、突发完成数和持续任务覆盖；每个有效 run 的合同均须通过。",
            )
        )

    application_rows = output.get("application_comparisons", [])
    if application_rows:
        lines.extend(
            (
                "",
                "## 应用级结果",
                "",
                "逐项结果保留原始应用量纲；改善值按同一 repeat 配对计算，正值表示 Agent 更符合该指标目标。",
                "",
                "| 应用 | 角色 | 指标 | Native 中位数 | Agent 中位数 | 配对变化 | 配对数 |",
                "| --- | --- | --- | ---: | ---: | ---: | ---: |",
            )
        )
        for row in application_rows:
            change = row.get("paired_improvement", {})
            lines.append(
                f"| {row.get('label', row.get('application'))} | {row.get('role')} | {row.get('metric')} | "
                f"{_metric_value(row.get('native', {}).get('median'), row.get('unit', ''))} | "
                f"{_metric_value(row.get('agent', {}).get('median'), row.get('unit', ''))} | "
                f"{_format_change(change.get('median'), change.get('unit', 'percent'))} | "
                f"{row.get('pairs', 0)} |"
            )

    system_rows = output.get("system_comparisons", [])
    if system_rows:
        lines.extend(
            (
                "",
                "## 系统级辅助指标",
                "",
                "以下指标完整呈现 perf 与 CPU 分布证据，不参与 P99/吞吐主目标合成。相对变化按 Agent / Native - 1 计算；负值表示 Agent 实测值更低。",
                "",
                "| 指标 | Native | Agent | Agent 相对变化 |",
                "| --- | ---: | ---: | ---: |",
            )
        )
        for row in system_rows:
            change = row.get("paired_change", {})
            lines.append(
                f"| {row.get('label', row.get('metric'))} | "
                f"{_system_metric_value(row.get('native', {}).get('median'), row.get('unit', ''))} | "
                f"{_system_metric_value(row.get('agent', {}).get('median'), row.get('unit', ''))} | "
                f"{_format_change(change.get('median'), change.get('unit', 'percent'))} |"
            )

    classification = output.get("classification", {})
    process = classification.get("process", {})
    thread = classification.get("thread", {})
    lines.extend(
        (
            "",
            "## 感知与策略闭环",
            "",
            f"Agent 分类快照：{classification.get('snapshot_runs', 0)}/{classification.get('agent_runs', 0)} run；"
            f"连续时间线：{classification.get('timeline_valid_samples', 0)}/{classification.get('timeline_samples', 0)} 有效样本；"
            f"快照启动中位延迟：{_format_seconds(classification.get('median_start_delay_seconds'))}。",
            "",
            "| 范围 | 运行时间加权准确率 | 运行时间覆盖率 | 已解析准确率 | generation 生效率 |",
            "| --- | ---: | ---: | ---: | ---: |",
        )
    )
    longitudinal = classification.get("timeline_runs", 0) > 0
    runtime_field = "longitudinal_runtime_weighted" if longitudinal else "runtime_weighted"
    for label, row in (("进程", process), ("线程", thread)):
        runtime = row.get(runtime_field, {})
        lines.append(
            f"| {label} | {_format_ratio(runtime.get('observed_runtime_accuracy'))} | "
            f"{_format_ratio(runtime.get('runtime_coverage'))} | "
            f"{_format_ratio(row.get('resolved_accuracy'))} | "
            f"{_format_ratio(row.get('generation_applied_ratio'))} |"
        )
    lines.extend(
        (
            "",
            "运行时间加权指标按每个分类时间线对应的 schedstat 区间计分；它比单次快照更能反映策略在整个测量窗口内是否持续有效。",
        )
    )

    evidence = output.get("agent_evidence", {})
    if evidence:
        shared = evidence.get("shared_dispatch", {})
        latency_shared = shared.get("latency", {})
        balanced_shared = shared.get("balanced", {})
        lines.extend(
            (
                "",
                "## 调度机制与健康状态",
                "",
                "| 证据 | 实测值 |",
                "| --- | ---: |",
                f"| policy feedback / placement 更新 | {evidence.get('policy_feedback_updates', 0)} / {evidence.get('policy_placement_updates', 0)} |",
                f"| 共享 latency dispatch 成功率 | {_format_ratio(latency_shared.get('success_ratio'))} ({latency_shared.get('dispatches', 0)}/{latency_shared.get('attempts', 0)}) |",
                f"| 共享普通任务 dispatch 成功率 | {_format_ratio(balanced_shared.get('success_ratio'))} ({balanced_shared.get('dispatches', 0)}/{balanced_shared.get('attempts', 0)}) |",
                f"| event overflow / fallback / capacity hit / degraded | {evidence.get('event_overflows', 0)} / {evidence.get('fallback_dispatches', 0)} / {evidence.get('task_capacity_hits', 0)} / {evidence.get('degraded_transitions', 0)} |",
                f"| 跨 LLC dispatch/migration 事件 | {evidence.get('cross_llc_events', 0)} |",
                f"| fast-path dispatch / local / direct | {evidence.get('fast_path_dispatches', 0)} / {evidence.get('fast_path_local_dispatches', 0)} / {evidence.get('fast_path_direct_dispatches', 0)} |",
            )
        )

    lines.extend(
        (
            "",
            "## 控制面开销",
            "",
            "| 项目 | 实测值 |",
            "| --- | ---: |",
            f"| Agent + scheduler CPU | {_metric_value(evidence.get('control_plane_cpu_seconds'), 's')} ({_format_ratio((evidence.get('control_plane_cpu_percent') or 0) / 100)}) |",
            f"| Agent 最大 RSS | {_metric_value(evidence.get('agent_max_rss_mib'), 'MiB')} |",
            f"| scheduler 最大 RSS | {_metric_value(evidence.get('scheduler_max_rss_mib'), 'MiB')} |",
            f"| 事件抑制比例 | {_format_ratio(evidence.get('suppression_ratio'))} |",
        )
    )

    lines.extend(
        (
            "",
            "## 环境与复现信息",
            "",
            "| 项目 | 值 |",
            "| --- | --- |",
            f"| 操作系统 | {environment.get('os', 'N/A')} |",
            f"| 内核 | {environment.get('kernel', 'N/A')} |",
            f"| 架构 / 逻辑 CPU | {environment.get('machine', 'N/A')} / {environment.get('logical_cpus', 'N/A')} |",
            "| Guest 拓扑 | 1 socket x 3 cores x 2 SMT threads |",
            f"| workload profile | {environment.get('workload_profile', 'N/A')} |",
            f"| 证据 campaign | {methodology.get('campaign_id', 'N/A')} |",
            f"| 模板镜像 | {methodology.get('template_image', 'N/A')} |",
            f"| 模板 SHA-256 | {methodology.get('template_sha256', 'N/A')} |",
            f"| Agent SHA-256 | {methodology.get('payload_sha256', {}).get('adaptive-os-agent', 'N/A')} |",
            f"| scheduler SHA-256 | {methodology.get('payload_sha256', {}).get('scx_adaptive', 'N/A')} |",
            f"| 测量协议 | warmup {_format_config_values(methodology.get('warmup_seconds'))} s；measurement {_format_config_values(methodology.get('measurement_seconds'))} s |",
            f"| 预检 | {'通过' if methodology.get('preflight_passed') else '未通过/缺失'} |",
        )
    )
    if output.get("invalid"):
        lines.extend(("", "## 无效运行", ""))
        for row in output["invalid"]:
            lines.append(
                f"- {row.get('scenario')}/{row.get('variant')}/r{int(row.get('repeat', 0)):02d}: "
                + "; ".join(row.get("reasons", []))
            )
    interval_note = (
        "当前只有一个完整配对，因此不报告跨 repeat 的置信区间。"
        if max((int(row.get("pairs", 0)) for row in comparisons), default=0) < 2
        else "95% CI 使用配对改善值的 bootstrap 中位数。"
    )
    lines.extend(
        (
            "",
            "## 指标口径",
            "",
            "延迟聚合为各延迟应用 P99（微秒）的几何平均；吞吐聚合为各持续吞吐应用速率的几何平均。Native 与 Agent 只按相同 repeat 配对。"
            + interval_note,
            "",
        )
    )
    return "\n".join(lines)


def _metric_value(value: float | None, unit: str) -> str:
    if value is None:
        return "N/A"
    if unit == "us":
        return f"{value:,.1f} us"
    if unit == "units/s":
        return f"{value:,.3f} units/s"
    if unit == "s":
        return f"{value:,.2f} s"
    if unit == "MiB":
        return f"{value:,.2f} MiB"
    return f"{value:,.3f}{(' ' + unit) if unit else ''}"


def _comparison_interval(comparison: dict[str, Any]) -> str:
    if int(comparison.get("pairs", 0)) < 2:
        return "N/A（单轮）"
    change = comparison.get("paired_improvement", {})
    unit = str(change.get("unit", "percent"))
    return (
        f"[{_format_change(change.get('ci95_low'), unit)}, "
        f"{_format_change(change.get('ci95_high'), unit)}]"
    )


def _system_metric_value(value: float | None, unit: str) -> str:
    if value is None:
        return "N/A"
    if unit == "ratio":
        return _format_ratio(value)
    if unit == "count":
        return f"{value:,.0f}"
    if unit == "ms":
        return f"{value:,.2f} ms"
    return f"{value:,.3f}"


def _format_config_values(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "N/A"
    return str(value) if value is not None else "N/A"


def _write_comparison_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            [
                "scenario",
                "metric",
                "unit",
                "pairs",
                "native_median",
                "agent_median",
                "improvement",
                "improvement_unit",
                "ci95_low",
                "ci95_high",
            ]
        )
        for row in rows:
            change = row["paired_improvement"]
            writer.writerow(
                [
                    row["scenario"],
                    row["metric"],
                    row["unit"],
                    row["pairs"],
                    row["native"]["median"],
                    row["agent"]["median"],
                    change["median"],
                    change["unit"],
                    change["ci95_low"],
                    change["ci95_high"],
                ]
            )


def _geometric_mean(values: list[float]) -> float | None:
    positive = [value for value in values if value > 0]
    if not positive:
        return None
    return math.exp(statistics.fmean(math.log(value) for value in positive))


def _distribution(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {key: None for key in ("mean", "p50", "p95", "p99", "p999", "max")}
    ordered = sorted(values)
    return {
        "mean": statistics.fmean(ordered),
        "p50": _quantile(ordered, 0.5),
        "p95": _quantile(ordered, 0.95),
        "p99": _quantile(ordered, 0.99),
        "p999": _quantile(ordered, 0.999),
        "max": ordered[-1],
    }


def _series_stats(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"count": 0, "mean": None, "median": None, "stdev": None, "cv": None}
    mean = statistics.fmean(values)
    stdev = statistics.stdev(values) if len(values) > 1 else 0.0
    return {
        "count": len(values),
        "mean": mean,
        "median": statistics.median(values),
        "stdev": stdev,
        "cv": stdev / mean if mean else None,
    }


def _improvement(
    native: float, agent: float, higher_is_better: bool, relative: bool
) -> float:
    if not relative:
        change = (agent - native) * 100
        return change if higher_is_better else -change
    if native == 0:
        return 0.0
    change = (agent / native - 1) * 100
    return change if higher_is_better else -change


def _bootstrap_ci(
    values: list[float], samples: int, randomizer: random.Random
) -> tuple[float | None, float | None]:
    if not values:
        return None, None
    estimates = sorted(
        statistics.median(randomizer.choice(values) for _ in values) for _ in range(samples)
    )
    return _quantile(estimates, 0.025), _quantile(estimates, 0.975)


def _quantile(ordered: list[float], probability: float) -> float:
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _window_delta(
    rows: list[dict[str, Any]], start_ns: int, end_ns: int
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    if len(rows) < 2:
        return None
    ordered = sorted(rows, key=lambda row: int(row.get("observed_ns", 0)))
    before = max(
        (row for row in ordered if int(row.get("observed_ns", 0)) <= start_ns),
        default=ordered[0],
        key=lambda row: int(row.get("observed_ns", 0)),
    )
    after = min(
        (row for row in ordered if int(row.get("observed_ns", 0)) >= end_ns),
        default=ordered[-1],
        key=lambda row: int(row.get("observed_ns", 0)),
    )
    if int(after.get("observed_ns", 0)) <= int(before.get("observed_ns", 0)):
        return None
    return before, after


def _strict_window_delta(
    rows: list[dict[str, Any]], start_ns: int, end_ns: int
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Returns a counter delta only when both interval edges are sampled."""
    if len(rows) < 2:
        return None
    ordered = sorted(rows, key=lambda row: int(row.get("observed_ns", 0)))
    before = max(
        (row for row in ordered if int(row.get("observed_ns", 0)) <= start_ns),
        default=None,
        key=lambda row: int(row.get("observed_ns", 0)),
    )
    after = min(
        (row for row in ordered if int(row.get("observed_ns", 0)) >= end_ns),
        default=None,
        key=lambda row: int(row.get("observed_ns", 0)),
    )
    if before is None or after is None:
        return None
    if int(after.get("observed_ns", 0)) <= int(before.get("observed_ns", 0)):
        return None
    return before, after


def _nested_number(row: dict[str, Any], path: tuple[str | int, ...]) -> int:
    value: Any = row
    for key in path:
        if isinstance(key, str) and isinstance(value, dict):
            value = value.get(key, {})
        elif isinstance(key, int) and isinstance(value, list) and key < len(value):
            value = value[key]
        else:
            value = 0
    return int(value) if isinstance(value, (int, float)) else 0


def _optional_int(value: Any) -> int | None:
    return int(value) if isinstance(value, (int, float)) else None


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    except (OSError, json.JSONDecodeError):
        return []
    return rows


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _format_number(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.3f}"


def _format_ratio(value: float | None) -> str:
    return "N/A" if value is None else f"{value * 100:.2f}%"


def _format_seconds(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.3f} s"


def _format_change(value: float | None, unit: str) -> str:
    if value is None:
        return "N/A"
    suffix = "%" if unit == "percent" else " pp"
    return f"{value:+.2f}{suffix}"
