#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import struct
import time
from pathlib import Path
from typing import Any


stop_requested = False


def _request_stop(_signal_number: int, _frame: Any) -> None:
    global stop_requested
    stop_requested = True


class ToolClient:
    def __init__(self, path: str, timeout_seconds: float = 5.0) -> None:
        self.path = path
        self.timeout_seconds = timeout_seconds
        self.connection: socket.socket | None = None
        self.request_id = 0

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def query(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.request_id += 1
        request = {
            "request_id": self.request_id,
            "tool": tool,
            "arguments": arguments,
        }
        body = json.dumps(request, separators=(",", ":")).encode("utf-8")
        try:
            connection = self._connect()
            connection.sendall(struct.pack("!I", len(body)) + body)
            size = struct.unpack("!I", self._receive_exact(connection, 4))[0]
            response = json.loads(self._receive_exact(connection, size))
        except (OSError, ValueError, json.JSONDecodeError):
            self.close()
            raise
        if response.get("request_id") != self.request_id:
            raise RuntimeError("Tool response request_id mismatch")
        if response.get("ok") is not True:
            raise RuntimeError(str(response.get("error", "Tool request failed")))
        result = response.get("result")
        if not isinstance(result, dict):
            raise RuntimeError("Tool result is not an object")
        return result

    def _connect(self) -> socket.socket:
        if self.connection is None:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(self.timeout_seconds)
            connection.connect(self.path)
            self.connection = connection
        return self.connection

    @staticmethod
    def _receive_exact(connection: socket.socket, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = connection.recv(size - len(data))
            if not chunk:
                raise ConnectionError("Tool socket closed during a frame")
            data.extend(chunk)
        return bytes(data)


class JsonlWriter:
    def __init__(self, path: Path) -> None:
        self.stream = path.open("w", encoding="utf-8", buffering=1)

    def write(self, value: dict[str, Any]) -> None:
        json.dump(value, self.stream, separators=(",", ":"), sort_keys=True)
        self.stream.write("\n")

    def close(self) -> None:
        self.stream.close()


def _proc_identity(pid: int) -> tuple[int, int] | None:
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        fields = text[text.rfind(")") + 2 :].split()
        return int(fields[1]), int(fields[19])
    except (OSError, IndexError, ValueError):
        return None


def _load_process_targets(
    path: Path,
) -> tuple[dict[tuple[int, int], dict[str, Any]], set[tuple[int, int]]]:
    roots: dict[int, dict[str, Any]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    for line in lines:
        try:
            row = json.loads(line)
            pid = int(row["pid"])
            start_ticks = int(row.get("start_ticks", 0))
            name = str(row["name"])
            role = str(row["role"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            continue
        identity = _proc_identity(pid)
        if identity is None or (start_ticks and identity[1] != start_ticks):
            continue
        roots[pid] = {"name": name, "mode": role}

    parent_by_pid: dict[int, int] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        identity = _proc_identity(pid)
        if identity is not None:
            parent_by_pid[pid] = identity[0]

    targets: dict[tuple[int, int], dict[str, Any]] = {}
    for root_pid, root in roots.items():
        process_depths = {root_pid: 0}
        changed = True
        while changed:
            changed = False
            for pid, parent in parent_by_pid.items():
                if pid not in process_depths and parent in process_depths:
                    process_depths[pid] = process_depths[parent] + 1
                    changed = True
        for pid, process_depth in process_depths.items():
            task_root = Path(f"/proc/{pid}/task")
            try:
                tids = [int(entry.name) for entry in task_root.iterdir() if entry.name.isdigit()]
            except OSError:
                continue
            for tid in tids:
                key = (pid, tid)
                targets[key] = {
                    "pid": pid,
                    "tid": tid,
                    "mode": root["mode"],
                    "worker": f"{root['name']}:{tid}",
                    "app": root["name"],
                    "root_pid": root_pid,
                    "process_depth": process_depth,
                    "process_role": "root" if process_depth == 0 else "descendant",
                }
    return targets, set(targets)


def _map_classification_entries(
    items: list[Any], targets: dict[tuple[int, int], dict[str, Any]]
) -> tuple[
    dict[tuple[int, int], dict[str, Any]],
    dict[int, dict[str, Any]],
]:
    task_entries: dict[tuple[int, int], dict[str, Any]] = {}
    process_entries: dict[int, dict[str, Any]] = {}
    target_processes = {pid for pid, _tid in targets}
    for item in items:
        if not isinstance(item, dict):
            continue
        identity = item.get("identity")
        if not isinstance(identity, dict):
            continue
        if item.get("kind") == "process":
            try:
                pid = int(identity["tgid"])
            except (KeyError, TypeError, ValueError):
                continue
            if pid in target_processes:
                process_entries[pid] = item
        elif item.get("kind") == "task":
            process = item.get("process")
            if not isinstance(process, dict):
                continue
            try:
                key = (int(process["tgid"]), int(identity["tid"]))
            except (KeyError, TypeError, ValueError):
                continue
            if key in targets:
                task_entries[key] = item
                process_entries.setdefault(key[0], {"identity": process})
    return task_entries, process_entries


def _process_targets(
    targets: dict[tuple[int, int], dict[str, Any]],
) -> dict[int, dict[str, Any]]:
    grouped: dict[int, list[dict[str, Any]]] = {}
    for (pid, _tid), target in targets.items():
        grouped.setdefault(pid, []).append(target)
    result: dict[int, dict[str, Any]] = {}
    for pid, rows in grouped.items():
        modes = {str(row["mode"]) for row in rows}
        apps = {str(row.get("app", "unknown")) for row in rows}
        roots = {int(row.get("root_pid", pid)) for row in rows}
        depths = {int(row.get("process_depth", 0)) for row in rows}
        result[pid] = {
            "expected_class": next(iter(modes)) if len(modes) == 1 else "mixed",
            "app": next(iter(apps)) if len(apps) == 1 else "mixed",
            "root_pid": next(iter(roots)) if len(roots) == 1 else None,
            "process_depth": min(depths) if depths else None,
            "process_role": "root" if depths == {0} else "descendant",
        }
    return result


def _classification_snapshot(
    client: ToolClient,
    targets: dict[tuple[int, int], dict[str, Any]],
    active: set[tuple[int, int]],
    scheduled_ns: int,
    expected_workers: int,
) -> dict[str, Any]:
    started_ns = time.monotonic_ns()
    snapshot_targets = dict(targets)
    task_entries: dict[tuple[int, int], dict[str, Any]] = {}
    process_entries: dict[int, dict[str, Any]] = {}
    errors: list[dict[str, Any]] = []
    try:
        listing = client.query(
            "workload.list",
            {
                "scope": "all",
                "limit": 1000,
                "tgids": sorted({pid for pid, _tid in snapshot_targets}),
            },
        )
        task_entries, process_entries = _map_classification_entries(
            listing.get("items", []), snapshot_targets
        )
    except (OSError, RuntimeError, ValueError) as exc:
        errors.append({"scope": "list", "error": str(exc)})

    processes = []
    active_processes = {pid for pid, _tid in active}
    for pid, target in sorted(_process_targets(snapshot_targets).items()):
        row: dict[str, Any] = {
            "pid": pid,
            **target,
            "active_at_snapshot": pid in active_processes,
            "observed": False,
        }
        entry = process_entries.get(pid)
        if entry is not None:
            try:
                classification = entry.get("classification")
                if isinstance(classification, dict):
                    row.update(classification)
                else:
                    row.update(
                        client.query(
                            "classification.get", {"process": entry["identity"]}
                        )
                    )
                row["observed"] = True
            except (OSError, RuntimeError, ValueError) as exc:
                row["error"] = str(exc)
                errors.append({"scope": "process", "pid": pid, "error": str(exc)})
        processes.append(row)

    threads = []
    for key, target in sorted(snapshot_targets.items()):
        pid, tid = key
        row = {
            "pid": pid,
            "tid": tid,
            "worker": target["worker"],
            "app": target.get("app", "unknown"),
            "root_pid": target.get("root_pid", pid),
            "process_depth": target.get("process_depth", 0),
            "process_role": target.get("process_role", "root"),
            "expected_class": target["mode"],
            "active_at_snapshot": key in active,
            "observed": False,
        }
        entry = task_entries.get(key)
        if entry is not None:
            try:
                classification = entry.get("classification")
                if isinstance(classification, dict):
                    row.update(classification)
                else:
                    row.update(
                        client.query(
                            "classification.get", {"task": entry["identity"]}
                        )
                    )
                row["observed"] = True
            except (OSError, RuntimeError, ValueError) as exc:
                row["error"] = str(exc)
                errors.append(
                    {"scope": "thread", "pid": pid, "tid": tid, "error": str(exc)}
                )
        threads.append(row)

    return {
        "schema_version": 2,
        "scheduled_ns": scheduled_ns,
        "started_ns": started_ns,
        "completed_ns": time.monotonic_ns(),
        "expected_workers": expected_workers,
        "processes": processes,
        "threads": threads,
        "errors": errors,
    }


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def _read_schedstat(target: dict[str, Any]) -> dict[str, Any] | None:
    task_root = Path(f"/proc/{target['pid']}/task/{target['tid']}")
    try:
        fields = (task_root / "schedstat").read_text(encoding="utf-8").split()
        sched = (task_root / "sched").read_text(encoding="utf-8")
        run_ns, wait_ns, timeslices = (int(value) for value in fields[:3])
        migrations = next(
            (
                int(line.split(":", 1)[1])
                for line in sched.splitlines()
                if line.strip().startswith("se.nr_migrations")
            ),
            0,
        )
    except (OSError, ValueError):
        return None
    return {
        **target,
        "run_ns": run_ns,
        "wait_ns": wait_ns,
        "timeslices": timeslices,
        "migrations": migrations,
    }


def _read_process_stat(pid: int, role: str) -> dict[str, Any] | None:
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        fields = text[text.rfind(")") + 2 :].split()
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    except OSError:
        return None
    voluntary = 0
    involuntary = 0
    for line in status.splitlines():
        if line.startswith("voluntary_ctxt_switches:"):
            voluntary = int(line.split()[1])
        elif line.startswith("nonvoluntary_ctxt_switches:"):
            involuntary = int(line.split()[1])
    try:
        return {
            "role": role,
            "pid": pid,
            "cpu_ticks": int(fields[11]) + int(fields[12]),
            "start_ticks": int(fields[19]),
            "rss_pages": int(fields[21]),
            "voluntary_context_switches": voluntary,
            "involuntary_context_switches": involuntary,
        }
    except (IndexError, ValueError):
        return None


def _scheduler_pids(agent_pid: int) -> list[int]:
    try:
        text = Path(f"/proc/{agent_pid}/task/{agent_pid}/children").read_text(
            encoding="utf-8"
        )
    except OSError:
        return []
    return [int(value) for value in text.split() if value.isdigit()]


def _scheduler_sample(stats: dict[str, Any], observed_ns: int) -> dict[str, Any]:
    scheduler = stats.get("scheduler") if isinstance(stats.get("scheduler"), dict) else {}
    data_plane = stats.get("data_plane") if isinstance(stats.get("data_plane"), dict) else {}
    return {
        "observed_ns": observed_ns,
        "scheduler_epoch": stats.get("scheduler_epoch"),
        "cpu_count": stats.get("cpu_count"),
        "tasks": stats.get("tasks"),
        "scheduler": {
            key: scheduler.get(key)
            for key in (
                "events_processed",
                "refill_commands",
                "command_rejects_by_reason",
                "preempt_dispatches",
                "latency_slo_admissions",
                "root_latency_dispatches",
                "latency_budget_denials",
                "preemption_budget_denials",
                "repeated_preemptions_avoided",
                "latency_preemptions_by_victim_class",
                "request_resumptions",
                "planned_migrations_by_class",
                "smt_busy_placements_by_class",
                "dispatch_overhead_samples",
                "dispatch_overhead_ns",
                "dispatches_by_class",
                "runtime_by_class_ns",
                "task_capacity_hits",
                "degraded_transitions",
            )
        },
        "data_plane": {
            key: data_plane.get(key)
            for key in (
                "commands_accepted",
                "commands_rejected",
                "event_overflows",
                "fallback_dispatches",
                "stale_heartbeat_fallbacks",
                "max_normal_staged_depth",
                "fast_path_enqueues",
                "fast_path_dispatches",
                "fast_path_dispatch_failures",
                "fast_path_preemptions",
                "fast_path_dispatches_by_class",
                "fast_path_local_dispatches",
                "fast_path_steal_attempts",
                "fast_path_remote_steals",
                "fast_path_events_suppressed",
                "fast_path_direct_dispatches",
                "fast_path_prev_continuations",
                "fast_path_steal_claim_conflicts",
                "cpu_state_events_suppressed",
                "fast_path_empty_steal_skips",
                "fast_path_preemption_throttles",
                "fast_path_latency_backlog_boosts",
            )
        },
    }


def collect(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    targets_path = Path(args.targets)
    stop_file = Path(args.stop_file)
    client = ToolClient(args.tool_socket) if args.tool_socket else None
    writers = {
        "scheduler": JsonlWriter(output_dir / "scheduler-stats.jsonl"),
        "schedstat": JsonlWriter(output_dir / "task-schedstat.jsonl"),
        "process": JsonlWriter(output_dir / "process-stats.jsonl"),
        "errors": JsonlWriter(output_dir / "collector-errors.jsonl"),
    }
    classification_snapshot: dict[str, Any] | None = None
    seen_targets: dict[tuple[int, int], dict[str, Any]] = {}
    samples = 0
    tool_errors = 0
    started_ns = time.monotonic_ns()
    deadline = time.monotonic() + args.timeout_seconds
    next_sample = time.monotonic()

    try:
        while not stop_requested and not stop_file.exists() and time.monotonic() < deadline:
            now = time.monotonic()
            if now < next_sample:
                time.sleep(min(next_sample - now, 0.1))
                continue
            observed_ns = time.monotonic_ns()
            targets, active = _load_process_targets(targets_path)
            seen_targets.update(targets)

            if (
                client is not None
                and classification_snapshot is None
                and args.classification_snapshot_at_ns
                and observed_ns >= args.classification_snapshot_at_ns
                and active
            ):
                classification_snapshot = _classification_snapshot(
                    client,
                    seen_targets,
                    active,
                    args.classification_snapshot_at_ns,
                    args.expected_workers or len(active),
                )
                _write_json_atomic(
                    output_dir / "classification-snapshot.json",
                    classification_snapshot,
                )
                for error in classification_snapshot["errors"]:
                    writers["errors"].write(
                        {
                            "observed_ns": classification_snapshot["started_ns"],
                            **error,
                        }
                    )
                tool_errors += len(classification_snapshot["errors"])

            for key in sorted(active):
                target = targets[key]
                row = _read_schedstat(target)
                if row is not None:
                    writers["schedstat"].write({"observed_ns": observed_ns, **row})

            process_roles = {
                pid: f"workload:{targets[(pid, tid)]['mode']}"
                for pid, tid in active
            }
            if args.agent_pid:
                process_roles[args.agent_pid] = "agent"
                for pid in _scheduler_pids(args.agent_pid):
                    process_roles[pid] = "scheduler"
            for pid, role in sorted(process_roles.items()):
                row = _read_process_stat(pid, role)
                if row is not None:
                    writers["process"].write({"observed_ns": observed_ns, **row})

            if client is not None:
                try:
                    stats = client.query("scheduler.stats", {})
                    writers["scheduler"].write(_scheduler_sample(stats, observed_ns))
                except (OSError, RuntimeError, ValueError) as exc:
                    tool_errors += 1
                    writers["errors"].write(
                        {"observed_ns": observed_ns, "error": str(exc)}
                    )

            samples += 1
            next_sample += args.interval_seconds
            if next_sample <= now:
                next_sample = now + args.interval_seconds
    finally:
        if client is not None:
            client.close()
        for writer in writers.values():
            writer.close()

    summary = {
        "schema_version": 2,
        "started_ns": started_ns,
        "finished_ns": time.monotonic_ns(),
        "samples": samples,
        "target_workers": len(seen_targets),
        "target_processes": len({pid for pid, _tid in seen_targets}),
        "target_apps": sorted(
            {str(target.get("app")) for target in seen_targets.values() if target.get("app")}
        ),
        "classification_snapshot_available": classification_snapshot is not None,
        "classification_snapshot_scheduled_ns": (
            args.classification_snapshot_at_ns or None
        ),
        "classification_snapshot_completed_ns": (
            classification_snapshot["completed_ns"]
            if classification_snapshot is not None
            else None
        ),
        "classification_snapshot_errors": (
            len(classification_snapshot["errors"])
            if classification_snapshot is not None
            else 0
        ),
        "tool_errors": tool_errors,
        "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
        "page_size_bytes": os.sysconf("SC_PAGE_SIZE"),
        "timed_out": time.monotonic() >= deadline and not stop_file.exists(),
    }
    with (output_dir / "collector-summary.json").open("w", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return 1 if summary["timed_out"] else 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect real workload and Agent observations")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--targets", required=True)
    parser.add_argument("--stop-file", required=True)
    parser.add_argument("--tool-socket")
    parser.add_argument("--agent-pid", type=int, default=0)
    parser.add_argument("--interval-seconds", type=float, default=1.0)
    parser.add_argument("--classification-snapshot-at-ns", type=int, default=0)
    parser.add_argument("--expected-workers", type=int, default=0)
    parser.add_argument("--timeout-seconds", type=float, required=True)
    args = parser.parse_args(argv)
    if args.interval_seconds <= 0:
        parser.error("--interval-seconds must be positive")
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be positive")
    if args.expected_workers < 0:
        parser.error("--expected-workers cannot be negative")
    if args.classification_snapshot_at_ns and not args.tool_socket:
        parser.error("--classification-snapshot-at-ns requires --tool-socket")
    return args


def main(argv: list[str] | None = None) -> int:
    signal.signal(signal.SIGINT, _request_stop)
    signal.signal(signal.SIGTERM, _request_stop)
    return collect(parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
