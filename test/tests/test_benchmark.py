from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch


TEST_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = TEST_ROOT.parent
if str(TEST_ROOT) not in sys.path:
    sys.path.insert(0, str(TEST_ROOT))

from test_core.benchmark.analysis import (
    _classification_scope_metrics,
    _comparisons,
    _schedstat_metrics,
    analyze_run,
)
from test_core.benchmark.config import (
    SCENARIOS,
    build_spec,
    campaign_schedule,
    load_performance,
)
from test_core.benchmark.guest import write_guest_script
from test_core.config.parser import load_config
from test_core.vm.domain import build_domain_xml, domain_name
from test_core.vm.runner import _payloads
from test_core.vm.ssh import download_guest_dir

sys.path.insert(0, str(TEST_ROOT / "guest_tools"))
from benchmark_collector import (
    _classification_snapshot,
    _load_process_targets,
    _proc_identity,
)

sys.path.insert(0, str(TEST_ROOT / "image" / "real_workloads"))
from summarize_workloads import elapsed_seconds, generic_rate, openssl_rate


class BenchmarkConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_config(TEST_ROOT / "config.yaml", base_dir=REPO_ROOT)
        cls.performance = load_performance(cls.config)

    def test_formal_matrix_and_baked_workload_contract(self) -> None:
        self.assertEqual(self.performance["machine"], "formal_performance")
        self.assertEqual(set(self.performance["variants"]), {"native", "agent"})
        self.assertEqual(self.performance["repeats"], 3)
        self.assertEqual(self.performance["warmup_seconds"], 20)
        self.assertEqual(self.performance["measurement_seconds"], 60)
        agent = self.config["schedulers"][self.performance["variants"]["agent"]]
        self.assertEqual(agent["startup_timeout_seconds"], 20)
        self.assertEqual(self.performance["workload"]["kind"], "baked-real-apps")
        self.assertNotIn("scenarios", self.performance)
        machine = self.config["machines"][self.performance["machine"]]
        self.assertEqual(machine["pin_cpus"], "6-11")
        self.assertEqual(machine["emulator_cpus"], "0-5")
        self.assertEqual(machine["topology"], {"sockets": 1, "cores": 3, "threads": 2})

    def test_schedule_keeps_each_pair_adjacent(self) -> None:
        schedule = campaign_schedule(
            list(SCENARIOS), ["native", "agent"], 3, 17
        )
        self.assertEqual(len(schedule), 24)
        self.assertEqual(len(set(schedule)), 24)
        for index in range(0, len(schedule), 2):
            first, second = schedule[index : index + 2]
            self.assertEqual(first[:2], second[:2])
            self.assertEqual({first[2], second[2]}, {"native", "agent"})

    def test_single_round_all_scenarios_has_eight_runs(self) -> None:
        completed = subprocess.run(
            [sys.executable, TEST_ROOT / "scripts" / "benchmark.py", "--single-round", "--dry-run"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("profile: single-round", completed.stdout)
        self.assertIn("runs: 8", completed.stdout)
        self.assertEqual(completed.stdout.count(" repeat=1 "), 8)

    def test_single_scenario_argument_has_one_native_agent_pair(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                TEST_ROOT / "scripts" / "benchmark.py",
                "throughput",
                "--single-round",
                "--dry-run",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("runs: 2", completed.stdout)
        self.assertEqual(completed.stdout.count("scenario=throughput"), 2)
        self.assertNotIn("scenario=latency", completed.stdout)
        self.assertNotIn("scenario=balanced", completed.stdout)
        self.assertNotIn("scenario=mix", completed.stdout)
        self.assertIn(
            f"template_image: {self.config['libvirt']['template_image']}",
            completed.stdout,
        )

    def test_guest_scripts_use_image_workload_and_valid_shell(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for scenario in SCENARIOS:
                for variant in ("native", "agent"):
                    spec = build_spec(
                        self.config,
                        self.performance,
                        scenario=scenario,
                        variant=variant,
                        repeat=1,
                    )
                    path = Path(directory) / f"{scenario}-{variant}.sh"
                    write_guest_script(path, spec)
                    subprocess.run(["sh", "-n", path], check=True)
                    script = path.read_text(encoding="utf-8")
                    self.assertIn("SERVERS_READY", script)
                    self.assertIn("--targets", script)
                    self.assertIn("measurement duration is", script)
                    self.assertIn("missing_target_apps = metric_apps - target_apps", script)
                    self.assertIn(
                        'set(collector.get("target_apps", [])) != target_apps', script
                    )
                    self.assertIn("aoa-real-workload-autostart.service", script)
                    self.assertIn(
                        'wait_for_scheduler "$SCHEDULER_START_TIMEOUT_SECONDS"', script
                    )
                    self.assertNotIn("taskbench", script)
                    self.assertNotIn("workload-build", script)
                    if variant == "agent":
                        self.assertIn("--classification-snapshot-at-ns", script)
                    else:
                        self.assertNotIn("--classification-snapshot-at-ns", script)

    def test_payloads_do_not_upload_a_workload_program(self) -> None:
        spec = build_spec(
            self.config,
            self.performance,
            scenario="latency",
            variant="native",
            repeat=1,
        )
        payloads = _payloads(spec)
        self.assertEqual(len(payloads), 1)
        self.assertTrue(payloads[0]["target"].endswith("benchmark_collector.py"))

    def test_spec_profiles(self) -> None:
        formal = build_spec(
            self.config,
            self.performance,
            scenario="latency",
            variant="native",
            repeat=1,
        )
        single = build_spec(
            self.config,
            self.performance,
            scenario="mix",
            variant="agent",
            repeat=1,
            profile="single-round",
        )
        self.assertEqual(formal.benchmark["profile"], "formal")
        self.assertEqual(single.benchmark["profile"], "single-round")
        self.assertEqual(formal.benchmark["warmup_seconds"], 20)

    def test_domain_xml_contains_profile_pins_topology_and_discard(self) -> None:
        spec = build_spec(
            self.config,
            self.performance,
            scenario="latency",
            variant="native",
            repeat=1,
        )
        root = ET.fromstring(build_domain_xml(spec, "test-domain", "/tmp/test.qcow2"))
        pins = {
            int(item.attrib["vcpu"]): item.attrib["cpuset"]
            for item in root.findall("./cputune/vcpupin")
        }
        self.assertEqual(pins, {index: str(cpu) for index, cpu in enumerate(range(6, 12))})
        self.assertEqual(root.find("./cputune/emulatorpin").attrib["cpuset"], "0-5")
        self.assertEqual(
            root.find("./cpu/topology").attrib,
            {"sockets": "1", "cores": "3", "threads": "2"},
        )
        self.assertEqual(
            root.find("./sysinfo/system/entry[@name='serial']").text,
            "aoa-profile-latency",
        )
        self.assertEqual(root.find("./devices/disk/driver").attrib["discard"], "unmap")

    def test_domain_xml_selects_balanced_workload_profile(self) -> None:
        spec = build_spec(
            self.config,
            self.performance,
            scenario="balanced",
            variant="native",
            repeat=1,
        )
        root = ET.fromstring(build_domain_xml(spec, "test-balanced", "/tmp/test.qcow2"))
        self.assertEqual(
            root.find("./sysinfo/system/entry[@name='serial']").text,
            "aoa-profile-balanced",
        )

    def test_host_control_scripts_have_valid_shell_syntax(self) -> None:
        for name in ("cpu_isolation.sh", "set_cpu_frequency.sh", "restore_cpu_frequency.sh"):
            subprocess.run(["sh", "-n", TEST_ROOT / "scripts" / name], check=True)

    def test_long_domain_name_keeps_unique_suffix(self) -> None:
        spec = build_spec(
            self.config,
            self.performance,
            scenario="latency",
            variant="agent",
            repeat=1,
        )
        first = domain_name(spec, "11111111")
        second = domain_name(spec, "22222222")
        self.assertLessEqual(len(first), 63)
        self.assertNotEqual(first, second)
        self.assertTrue(first.endswith("-11111111"))


class CollectorTests(unittest.TestCase):
    def test_process_manifest_discovers_live_threads_and_rejects_stale_pid(self) -> None:
        pid = os.getpid()
        identity = _proc_identity(pid)
        self.assertIsNotNone(identity)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.jsonl"
            path.write_text(
                json.dumps(
                    {"pid": pid, "start_ticks": identity[1], "name": "unit-app", "role": "latency"}
                ) + "\n",
                encoding="utf-8",
            )
            targets, active = _load_process_targets(path)
            self.assertIn((pid, pid), active)
            self.assertEqual(targets[(pid, pid)]["app"], "unit-app")
            self.assertEqual(targets[(pid, pid)]["mode"], "latency")
            self.assertEqual(targets[(pid, pid)]["root_pid"], pid)
            self.assertEqual(targets[(pid, pid)]["process_depth"], 0)
            self.assertEqual(targets[(pid, pid)]["process_role"], "root")

            path.write_text(
                json.dumps(
                    {"pid": pid, "start_ticks": identity[1] + 1, "name": "stale", "role": "latency"}
                ) + "\n",
                encoding="utf-8",
            )
            self.assertEqual(_load_process_targets(path), ({}, set()))

    def test_classification_snapshot_reports_accuracy_and_application(self) -> None:
        metrics = _classification_scope_metrics(
            [
                {
                    "observed": True,
                    "expected_class": "latency",
                    "class": "latency",
                    "stage": "semantic",
                    "source": "llm",
                    "generation": 2,
                    "applied_generation": 2,
                    "process_role": "root",
                    "app": "latency-app",
                    "timing": {
                        "request_delay_ns": 1_000_000_000,
                        "semantic_latency_ns": 2_000_000_000,
                        "decision_delay_ns": 3_000_000_000,
                        "apply_delay_ns": 4_000_000_000,
                    },
                },
                {
                    "observed": True,
                    "expected_class": "throughput",
                    "class": "throughput",
                    "stage": "locked",
                    "source": "behavior",
                    "generation": 3,
                    "applied_generation": 2,
                    "process_role": "descendant",
                    "app": "throughput-app",
                    "timing": {
                        "behavior_delay_ns": 2_000_000_000,
                        "decision_delay_ns": 4_000_000_000,
                        "lock_delay_ns": 4_000_000_000,
                    },
                },
            ],
            2,
            scope="thread",
        )
        self.assertEqual(metrics["effective_accuracy"], 1.0)
        self.assertEqual(metrics["generation_applied_ratio"], 0.5)
        self.assertEqual(metrics["confusion_matrix"]["latency"]["latency"], 1)
        self.assertEqual(metrics["accuracy_by_source"]["behavior"]["accuracy"], 1.0)
        self.assertEqual(
            metrics["accuracy_by_process_role"]["descendant"]["accuracy"], 1.0
        )
        self.assertEqual(metrics["timing"]["decision_delay"]["samples"], 2)
        self.assertEqual(metrics["timing"]["decision_delay"]["median_seconds"], 3.5)

        process_metrics = _classification_scope_metrics(
            [
                {
                    "observed": True,
                    "expected_class": "latency",
                    "class": "latency",
                    "source": "behavior",
                    "generation": 1,
                    "applied_generation": 1,
                },
                {
                    "observed": True,
                    "expected_class": "balanced",
                    "class": "balanced",
                    "source": "semantic_cache",
                    "generation": 2,
                    "applied_generation": 2,
                },
                {
                    "observed": True,
                    "expected_class": "throughput",
                    "class": "throughput",
                    "source": "local_metadata",
                    "generation": 1,
                    "applied_generation": 1,
                },
            ],
            3,
            scope="process",
        )
        self.assertEqual(process_metrics["resolved_coverage"], 1.0)
        self.assertEqual(process_metrics["resolved_accuracy"], 1.0)

    def test_classification_snapshot_queries_each_process_once(self) -> None:
        class Client:
            def __init__(self) -> None:
                self.calls: list[tuple[str, dict[str, object]]] = []

            def query(self, tool: str, arguments: dict[str, object]) -> dict[str, object]:
                self.calls.append((tool, arguments))
                if tool == "workload.list":
                    process = {"tgid": 10, "process_cookie": 1, "exec_generation": 1}
                    return {
                        "items": [
                            {"kind": "task", "identity": {"tid": tid, "task_cookie": tid}, "process": process}
                            for tid in (11, 12)
                        ]
                    }
                if "process" in arguments:
                    return {"class": "latency", "source": "llm", "generation": 1, "applied_generation": 1}
                return {
                    "class": "latency",
                    "stage": "semantic",
                    "source": "llm",
                    "generation": 1,
                    "applied_generation": 1,
                }

        targets = {
            (10, tid): {
                "mode": "latency",
                "worker": f"app:{tid}",
                "app": "app",
                "root_pid": 10,
                "process_depth": 0,
                "process_role": "root",
            }
            for tid in (11, 12)
        }
        client = Client()
        snapshot = _classification_snapshot(client, targets, set(targets), 100, 2)
        self.assertEqual(len(snapshot["processes"]), 1)
        self.assertEqual(len(snapshot["threads"]), 2)
        self.assertEqual(snapshot["schema_version"], 2)
        self.assertEqual(snapshot["processes"][0]["app"], "app")
        self.assertEqual(snapshot["processes"][0]["process_role"], "root")
        self.assertEqual(snapshot["errors"], [])
        self.assertEqual(
            [tool for tool, _arguments in client.calls],
            ["workload.list", "classification.get", "classification.get", "classification.get"],
        )

    def test_classification_snapshot_uses_batched_list_projection(self) -> None:
        process = {"tgid": 10, "process_cookie": 1, "exec_generation": 1}

        class Client:
            def __init__(self) -> None:
                self.calls: list[str] = []

            def query(self, tool: str, _arguments: dict[str, object]) -> dict[str, object]:
                self.calls.append(tool)
                if tool != "workload.list":
                    raise AssertionError(f"unexpected per-item query: {tool}")
                process_classification = {
                    "class": "latency",
                    "source": "llm",
                    "generation": 1,
                    "applied_generation": 1,
                }
                items: list[dict[str, object]] = [
                    {
                        "kind": "process",
                        "identity": process,
                        "classification": process_classification,
                    }
                ]
                for tid in (11, 12):
                    items.append(
                        {
                            "kind": "task",
                            "identity": {"tid": tid, "task_cookie": tid},
                            "process": process,
                            "classification": {
                                **process_classification,
                                "stage": "semantic",
                            },
                        }
                    )
                return {"items": items}

        targets = {
            (10, tid): {
                "mode": "latency",
                "worker": f"app:{tid}",
                "app": "app",
                "root_pid": 10,
                "process_depth": 0,
                "process_role": "root",
            }
            for tid in (11, 12)
        }
        client = Client()
        snapshot = _classification_snapshot(client, targets, set(targets), 100, 2)

        self.assertEqual(client.calls, ["workload.list"])
        self.assertTrue(all(row["observed"] for row in snapshot["processes"]))
        self.assertTrue(all(row["observed"] for row in snapshot["threads"]))


class WorkloadSummaryTests(unittest.TestCase):
    def test_server_targets_are_objective_neutral(self) -> None:
        dispatcher = (
            TEST_ROOT / "image" / "real_workloads" / "aoa-real-workload"
        ).read_text(encoding="utf-8")
        self.assertNotRegex(
            dispatcher,
            r"start_server\s+\S+\s+(?:latency|throughput)\b",
        )

    def test_throughput_profile_keeps_redis_as_latency_sentinel(self) -> None:
        dispatcher = (
            TEST_ROOT / "image" / "real_workloads" / "aoa-real-workload"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'redis_job redis-sentinel latency "$phase" "$duration"', dispatcher
        )
        self.assertNotIn(
            'redis_job redis-sentinel throughput "$phase" "$duration"', dispatcher
        )

    def test_rocksdb_rate_ignores_initial_zero(self) -> None:
        output = (
            "Read rate: 0 ops/second\n"
            "readrandomwriterandom : 6.307 micros/op 475226 ops/sec\n"
        )
        self.assertEqual(generic_rate(output, 8.0), 475226.0)

    def test_openssl_rate_parses_aggregate_bytes_per_second(self) -> None:
        output = "AES-256-GCM      11228301.31k\n"
        self.assertEqual(openssl_rate(output), 11_228_301_310.0)

    def test_elapsed_seconds_uses_last_numeric_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "elapsed"
            path.write_text(
                "Command exited with non-zero status 124\n8.01\n",
                encoding="utf-8",
            )
            self.assertEqual(elapsed_seconds(path), 8.01)


class SSHTransferTests(unittest.TestCase):
    def test_tar_probe_timeout_falls_back_to_scp(self) -> None:
        libvirt = {"ssh_user": "root", "ssh_key": "/tmp/test_ed25519", "ssh_port": 22}
        with tempfile.TemporaryDirectory() as directory:
            timeout = subprocess.TimeoutExpired(["ssh"], 30)
            completed = subprocess.CompletedProcess(["scp"], 0, "", "")
            with (
                patch("test_core.vm.ssh.run_ssh", side_effect=timeout) as probe,
                patch("test_core.vm.ssh.subprocess.run", return_value=completed) as run,
            ):
                download_guest_dir(libvirt, "192.0.2.1", "/bench_out", directory)
        probe.assert_called_once()
        self.assertEqual(run.call_args.args[0][0], "scp")
        self.assertEqual(run.call_args.kwargs["timeout"], 120)


class AnalysisTests(unittest.TestCase):
    def test_schedstat_metrics_break_down_existing_samples(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bench_dir = Path(directory)
            observations = bench_dir / "observations"
            observations.mkdir()
            rows = [
                {
                    "observed_ns": observed_ns,
                    "app": app,
                    "mode": mode,
                    "pid": pid,
                    "tid": pid,
                    "run_ns": run_ns,
                    "wait_ns": wait_ns,
                    "timeslices": timeslices,
                    "migrations": migrations,
                }
                for observed_ns, app, mode, pid, run_ns, wait_ns, timeslices, migrations in (
                    (100, "api", "latency", 1, 10, 20, 1, 2),
                    (200, "api", "latency", 1, 40, 60, 4, 5),
                    (100, "batch", "throughput", 2, 5, 5, 1, 1),
                    (200, "batch", "throughput", 2, 25, 15, 3, 2),
                )
            ]
            (observations / "task-schedstat.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
            )

            metrics = _schedstat_metrics(bench_dir, 100, 200)

            self.assertEqual(metrics["workers"], 2)
            self.assertEqual(metrics["migrations"], 4)
            self.assertEqual(metrics["by_application"]["api"]["timeslices"], 3)
            self.assertEqual(metrics["by_application"]["api"]["migrations"], 3)
            self.assertAlmostEqual(
                metrics["by_class"]["latency"]["wait_ratio"], 40 / 70
            )

    def test_real_application_metrics_use_geometric_means(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            _write_native_result(run_dir, "mix", 100, 200)
            _write_metric(run_dir, "redis", "latency", p99_ms=1.0, throughput=1000.0)
            _write_metric(run_dir, "nginx", "latency", p99_ms=4.0, throughput=4000.0)
            _write_metric(run_dir, "ffmpeg", "throughput", throughput=100.0)
            _write_metric(run_dir, "rocksdb", "throughput", throughput=400.0)
            _write_metric(run_dir, "etcd", "balanced", throughput=25.0)
            _write_metric(run_dir, "nats", "balanced", throughput=100.0)
            analyzed = analyze_run(run_dir)
            self.assertTrue(analyzed["valid"])
            self.assertAlmostEqual(analyzed["latency"]["p99_us"]["geometric_mean"], 2000.0)
            self.assertAlmostEqual(analyzed["throughput"]["operations_per_second"], 200.0)
            self.assertAlmostEqual(analyzed["balanced"]["operations_per_second"], 50.0)

    def test_comparisons_pair_by_repeat(self) -> None:
        rows = []
        for repeat, native, agent in ((1, 100.0, 120.0), (2, 200.0, 220.0)):
            for variant, value in (("native", native), ("agent", agent)):
                rows.append(
                    {
                        "scenario": "throughput",
                        "variant": variant,
                        "repeat": repeat,
                        "throughput": {"operations_per_second": value},
                    }
                )
        comparison = next(
            row
            for row in _comparisons(rows, bootstrap_samples=200, seed=1)
            if row["scenario"] == "throughput"
        )
        self.assertEqual(comparison["pairs"], 2)
        self.assertAlmostEqual(comparison["paired_improvement"]["median"], 15.0)

    def test_latency_improvement_uses_lower_is_better(self) -> None:
        rows = [
            {
                "scenario": "latency",
                "variant": variant,
                "repeat": 1,
                "latency": {"p99_us": {"geometric_mean": value}},
            }
            for variant, value in (("native", 100.0), ("agent", 90.0))
        ]
        comparison = _comparisons(rows, bootstrap_samples=100, seed=1)[0]
        self.assertEqual(comparison["metric"], "p99_latency_geomean_us")
        self.assertAlmostEqual(comparison["paired_improvement"]["median"], 10.0)

    def test_balanced_improvement_uses_higher_is_better(self) -> None:
        rows = [
            {
                "scenario": "balanced",
                "variant": variant,
                "repeat": 1,
                "balanced": {"operations_per_second": value},
            }
            for variant, value in (("native", 100.0), ("agent", 110.0))
        ]
        comparison = _comparisons(rows, bootstrap_samples=100, seed=1)[0]
        self.assertEqual(comparison["metric"], "balanced_geomean_per_second")
        self.assertAlmostEqual(comparison["paired_improvement"]["median"], 10.0)


def _write_native_result(run_dir: Path, scenario: str, start_ns: int, end_ns: int) -> None:
    result = {
        "status": "PASS",
        "spec": {
            "benchmark": {
                "scenario": scenario,
                "variant": "native",
                "repeat": 1,
                "profile": "formal",
                "require_perf": False,
            }
        },
        "guest_result": {
            "valid": True,
            "scenario": scenario,
            "variant": "native",
            "repeat": 1,
            "measurement_start_ns": start_ns,
            "measurement_end_ns": end_ns,
        },
    }
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def _write_metric(
    run_dir: Path,
    name: str,
    role: str,
    *,
    p99_ms: float | None = None,
    throughput: float | None = None,
) -> None:
    directory = run_dir / "benchmark" / "real-workloads" / "apps" / name
    directory.mkdir(parents=True, exist_ok=True)
    metric = {
        "schema_version": 1,
        "name": name,
        "role": role,
        "exit_code": 0,
        "elapsed_seconds": 10.0,
        "p99_ms": p99_ms,
        "throughput_per_second": throughput,
        "work_units": None,
        "completed": True,
    }
    (directory / "metrics.json").write_text(
        json.dumps(metric, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    unittest.main()
