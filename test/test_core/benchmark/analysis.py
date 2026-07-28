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
    latency = (
        _latency_metrics(applications, reasons)
        if scenario in {"latency", "mix"}
        else None
    )
    throughput = (
        _throughput_metrics(applications, reasons)
        if scenario in {"throughput", "mix"}
        else None
    )
    balanced = (
        _balanced_metrics(applications, reasons)
        if scenario in {"balanced", "mix"}
        else None
    )
    classification = _classification_metrics(
        bench_dir, start_ns, end_ns, enabled=variant == "agent"
    )
    perf = _perf_metrics(bench_dir / "perf-stat.csv")
    scheduler = _scheduler_metrics(bench_dir, start_ns, end_ns)
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
        "applications": applications,
        "latency": latency,
        "throughput": throughput,
        "balanced": balanced,
        "perf": perf,
        "cpu_utilization": _cpu_utilization_metrics(bench_dir, start_ns, end_ns),
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
    run_profiles = {str(summary["profile"]) for summary in summaries}
    profile = str(manifest.get("profile", next(iter(run_profiles), "formal")))
    if run_profiles and run_profiles != {profile}:
        profile = "mixed"
    output = {
        "schema_version": 4,
        "profile": profile,
        "runs": len(summaries),
        "valid_runs": len(valid),
        "invalid_runs": len(summaries) - len(valid),
        "comparisons": comparisons,
        "classification": _campaign_classification(valid),
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


def _balanced_metrics(
    applications: dict[str, dict[str, Any]], reasons: list[str]
) -> dict[str, Any]:
    return _rate_metrics(applications, reasons, role="balanced")


def _rate_metrics(
    applications: dict[str, dict[str, Any]], reasons: list[str], *, role: str
) -> dict[str, Any]:
    values = {
        name: float(metric["throughput_per_second"])
        for name, metric in applications.items()
        if metric.get("role") == role
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
        "fast_path_latency_backlog_boosts": (
            "data_plane",
            "fast_path_latency_backlog_boosts",
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
        "task_capacity_hits": ("scheduler", "task_capacity_hits"),
        "degraded_transitions": ("scheduler", "degraded_transitions"),
    }
    result: dict[str, int] = {}
    for name, path in fields.items():
        initial = _nested_number(before, path)
        final = _nested_number(after, path)
        result[name] = max(0, final - initial)
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
        "process": _classification_scope_metrics(
            process_rows, target_processes, scope="process"
        ),
        "thread": _classification_scope_metrics(
            thread_rows, target_threads, scope="thread"
        ),
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
        "latency": [
            (
                "p99_latency_geomean_us",
                lambda row: row["latency"]["p99_us"]["geometric_mean"],
                False,
                "us",
                True,
            ),
        ],
        "throughput": [
            (
                "throughput_geomean_per_second",
                lambda row: row["throughput"]["operations_per_second"],
                True,
                "units/s",
                True,
            )
        ],
        "balanced": [
            (
                "balanced_geomean_per_second",
                lambda row: row["balanced"]["operations_per_second"],
                True,
                "units/s",
                True,
            )
        ],
        "mix": [
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
            (
                "balanced_geomean_per_second",
                lambda row: row["balanced"]["operations_per_second"],
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


def _campaign_classification(summaries: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [row["classification"] for row in summaries if row["variant"] == "agent"]
    snapshot_rows = [row for row in rows if row.get("snapshot_available")]
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
    profile = str(output.get("profile", "formal"))
    profile_label = {
        "formal": "正式三轮",
        "single-round": "单轮迭代",
    }.get(profile, profile)
    lines = [
        "# Agent 与 Linux 原生调度器对比",
        "",
        f"实验配置：{profile_label}，Guest 独占三个物理核（六个 SMT 线程）",
        "",
        f"有效运行：{output['valid_runs']}；无效运行：{output['invalid_runs']}；总运行：{output['runs']}。",
    ]
    if profile == "single-round":
        lines.extend(("", "本报告仅用于调度方案迭代；单次配对不构成正式统计结论。"))
    if output["comparisons"]:
        lines.extend(
            [
                "",
                "| 场景 | 指标 | Native 中位数 | Agent 中位数 | 配对改善（正值更好） | 95% CI | 配对数 |",
                "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for row in output["comparisons"]:
            change = row["paired_improvement"]
            lines.append(
                (
                    "| {scenario} | {metric} ({unit}) | {native} | {agent} | "
                    "{delta} | {ci} | {pairs} |"
                ).format(
                    scenario=row["scenario"],
                    metric=row["metric"],
                    unit=row["unit"],
                    native=_format_number(row["native"]["median"]),
                    agent=_format_number(row["agent"]["median"]),
                    delta=_format_change(change["median"], change["unit"]),
                    ci=f"[{_format_change(change['ci95_low'], change['unit'])}, "
                    f"{_format_change(change['ci95_high'], change['unit'])}]",
                    pairs=row["pairs"],
                )
            )
    else:
        lines.extend(("", "没有完整的同 repeat Native/Agent 配对。"))
    classification = output["classification"]
    process = classification["process"]
    thread = classification["thread"]
    lines.extend(
        [
            "",
            "## 测量阶段分类快照",
            "",
            f"Agent 快照采集：{classification['snapshot_runs']}/{classification['agent_runs']}；"
            f"快照调用相对计划时间的中位延迟：{_format_seconds(classification['median_start_delay_seconds'])}。",
            "",
            "分类只作为观测指标，不作为运行有效性门禁；有效性仍由虚拟机、调度器、采集器和原始数据完整性决定。",
            "",
            "| 范围 | 观察覆盖率 | 全目标正确率 | 已解析覆盖率 | 已解析正确率 | generation 应用率 |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
            (
                "| 进程 | {process_coverage} | {process_effective} | "
                "{process_resolved_coverage} | {process_resolved} | {process_applied} |"
            ).format(
                process_coverage=_format_ratio(process["coverage"]),
                process_effective=_format_ratio(process["effective_accuracy"]),
                process_resolved_coverage=_format_ratio(process["resolved_coverage"]),
                process_resolved=_format_ratio(process["resolved_accuracy"]),
                process_applied=_format_ratio(process["generation_applied_ratio"]),
            ),
            (
                "| 线程 | {thread_coverage} | {thread_effective} | "
                "{thread_resolved_coverage} | {thread_resolved} | {thread_applied} |"
            ).format(
                thread_coverage=_format_ratio(thread["coverage"]),
                thread_effective=_format_ratio(thread["effective_accuracy"]),
                thread_resolved_coverage=_format_ratio(thread["resolved_coverage"]),
                thread_resolved=_format_ratio(thread["resolved_accuracy"]),
                thread_applied=_format_ratio(thread["generation_applied_ratio"]),
            ),
        ]
    )
    process_runtime = process["runtime_weighted"]
    thread_runtime = thread["runtime_weighted"]
    process_timing = process["timing"]
    thread_timing = thread["timing"]
    lines.extend(
        [
            "",
            (
                "运行时间加权准确率：进程 {process_accuracy}（覆盖 {process_coverage}）；"
                "线程 {thread_accuracy}（覆盖 {thread_coverage}）。"
            ).format(
                process_accuracy=_format_ratio(
                    process_runtime["observed_runtime_accuracy"]
                ),
                process_coverage=_format_ratio(process_runtime["runtime_coverage"]),
                thread_accuracy=_format_ratio(thread_runtime["observed_runtime_accuracy"]),
                thread_coverage=_format_ratio(thread_runtime["runtime_coverage"]),
            ),
            (
                "分类中位时延：进程 LLM {process_semantic}、决策 {process_decision}、生效 "
                "{process_apply}；线程本地首证据 {thread_behavior}、决策 {thread_decision}、"
                "生效 {thread_apply}。"
            ).format(
                process_semantic=_format_seconds(
                    process_timing["semantic_latency"]["median_seconds"]
                ),
                process_decision=_format_seconds(
                    process_timing["decision_delay"]["median_seconds"]
                ),
                process_apply=_format_seconds(
                    process_timing["apply_delay"]["median_seconds"]
                ),
                thread_behavior=_format_seconds(
                    thread_timing["behavior_delay"]["median_seconds"]
                ),
                thread_decision=_format_seconds(
                    thread_timing["decision_delay"]["median_seconds"]
                ),
                thread_apply=_format_seconds(
                    thread_timing["apply_delay"]["median_seconds"]
                ),
            ),
        ]
    )
    if output["invalid"]:
        lines.extend(("", "## 无效运行", ""))
        for row in output["invalid"]:
            lines.append(
                f"- {row['scenario']}/{row['variant']}/r{row['repeat']:02d}: "
                + "; ".join(row["reasons"])
            )
    lines.append("")
    return "\n".join(lines)


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
