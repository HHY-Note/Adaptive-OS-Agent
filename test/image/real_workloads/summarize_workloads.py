#!/usr/bin/env python3
"""Produce one conservative machine-readable record for every real workload."""
from __future__ import annotations

import json
import math
import re
import statistics
import sys
from pathlib import Path
from typing import Any


def number(value: str) -> float | None:
    try:
        return float(value.replace(",", ""))
    except ValueError:
        return None


def elapsed_seconds(path: Path) -> float | None:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        value = number(line.strip())
        if value is not None:
            return value
    return None


def duration_ms(value: str) -> float | None:
    match = re.fullmatch(r"([0-9.]+)\s*(us|ms|s)?", value.strip(), re.I)
    if not match:
        return None
    raw = float(match.group(1))
    unit = (match.group(2) or "ms").lower()
    return raw / 1000 if unit == "us" else raw * 1000 if unit == "s" else raw


def percentile(values: list[float], ratio: float) -> float | None:
    if not values:
        return None
    values.sort()
    index = min(len(values) - 1, max(0, math.ceil(len(values) * ratio) - 1))
    return values[index]


def memtier_metrics(app: Path, text: str) -> tuple[float | None, float | None]:
    p99 = None
    ops = None
    try:
        payload = json.loads((app / "result.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = None
    if isinstance(payload, dict):
        totals = payload.get("ALL STATS", {}).get("Totals", {})
        if isinstance(totals, dict):
            raw_ops = totals.get("Ops/sec")
            percentiles = totals.get("Percentile Latencies", {})
            raw_p99 = percentiles.get("p99.00") if isinstance(percentiles, dict) else None
            if isinstance(raw_ops, (int, float)):
                ops = float(raw_ops)
            if isinstance(raw_p99, (int, float)):
                p99 = float(raw_p99)

    def walk(value: Any) -> None:
        nonlocal ops, p99
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = str(key).lower().replace(" ", "")
                if isinstance(child, (int, float)):
                    if ops is None and normalized in {"ops/sec", "ops_sec", "opspersec", "throughput"}:
                        ops = max(ops or 0.0, float(child))
                    if p99 is None and normalized in {"99.00", "99", "p99", "p99.0", "p99.00"}:
                        p99 = max(p99 or 0.0, float(child))
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    if payload is not None:
        walk(payload)
    if ops is None:
        match = re.search(r"Ops/sec\s*[:=]\s*([0-9.,]+)", text, re.I)
        ops = number(match.group(1)) if match else None
    return p99, ops


def wrk_metrics(text: str) -> tuple[float | None, float | None]:
    rate = None
    p99 = None
    match = re.search(r"Requests/sec:\s*([0-9.,]+)", text, re.I)
    if match:
        rate = number(match.group(1))
    for line in text.splitlines():
        match = re.match(r"\s*99(?:\.\d+)?%\s+([0-9.]+\s*(?:us|ms|s))", line, re.I)
        if match:
            p99 = duration_ms(match.group(1))
    return p99, rate


def pgbench_metrics(app: Path, text: str) -> tuple[float |None, float | None]:
    samples: list[float] = []
    for path in app.glob("pgbench_log.*"):
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                fields = line.split()
                if fields and fields[-1].isdigit():
                    samples.append(int(fields[-1]) / 1000)
        except OSError:
            continue
    match = re.search(r"tps\s*=\s*([0-9.,]+)", text, re.I)
    return percentile(samples, 0.99), number(match.group(1)) if match else None


def generic_rate(text: str, elapsed: float | None) -> float | None:
    rates: list[float] = []
    for pattern in (
        r"([0-9.,]+)\s+ops/sec",
        r"([0-9.,]+)\s+operations per second",
        r"Requests/sec:\s*([0-9.,]+)",
        r"tps\s*=\s*([0-9.,]+)",
    ):
        for match in re.finditer(pattern, text, re.I):
            value = number(match.group(1))
            if value is not None and value > 0:
                rates.append(value)
    if rates:
        return max(rates)
    if elapsed and elapsed > 0:
        for label in ("work_units", "iterations"):
            match = re.search(rf"{label}=(\d+)", text)
            if match:
                return int(match.group(1)) / elapsed
    return None


def openssl_rate(text: str) -> float | None:
    rates: list[float] = []
    multipliers = {"": 1.0, "k": 1_000.0, "m": 1_000_000.0, "g": 1_000_000_000.0}
    for line in text.splitlines():
        if not line.lstrip().startswith("AES-256-GCM"):
            continue
        for raw, suffix in re.findall(r"([0-9.]+)([kKmMgG]?)", line):
            rates.append(float(raw) * multipliers[suffix.lower()])
    return max(rates) if rates else None


def summarize(root: Path) -> None:
    for app in sorted(path for path in (root / "apps").iterdir() if path.is_dir()):
        role = (app / "role").read_text(encoding="utf-8").strip() if (app / "role").exists() else "unknown"
        elapsed = elapsed_seconds(app / "elapsed_seconds")
        exit_code = int((app / "exit_code").read_text(encoding="utf-8").strip()) if (app / "exit_code").exists() else None
        text = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in (app / "stdout", app / "stderr") if path.exists()
        )
        p99 = None
        throughput = None
        if app.name.startswith(("redis", "memcached")):
            p99, throughput = memtier_metrics(app, text)
        elif app.name == "nginx":
            p99, throughput = wrk_metrics(text)
        elif app.name == "postgresql":
            p99, throughput = pgbench_metrics(app, text)
        elif app.name == "openssl":
            throughput = openssl_rate(text)
        else:
            throughput = generic_rate(text, elapsed)
        work_units = None
        for label in ("work_units", "iterations"):
            match = re.search(rf"{label}=(\d+)", text)
            if match:
                work_units = int(match.group(1))
                break
        metric = {
            "schema_version": 1,
            "name": app.name,
            "role": role,
            "exit_code": exit_code,
            "elapsed_seconds": elapsed,
            "p99_ms": p99,
            "throughput_per_second": throughput,
            "work_units": work_units,
            "completed": exit_code in {0, 124},
        }
        (app / "metrics.json").write_text(json.dumps(metric, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    root = Path(sys.argv[1])
    summarize(root)
