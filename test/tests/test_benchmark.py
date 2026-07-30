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
    _application_comparisons,
    _campaign_agent_evidence,
    _classification_scope_metrics,
    _comparisons,
    _load_contract_metrics,
    _longitudinal_runtime_weighted,
    _scheduler_metrics,
    _schedstat_metrics,
    _system_comparisons,
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
from test_core.host import check as host_check
from test_core.models import CheckResult
from test_core.vm.domain import build_domain_xml, domain_name
from test_core.vm.runner import _payloads
from test_core.vm.ssh import download_guest_dir
from scripts import benchmark as benchmark_script
from scripts import check_env as check_env_script

sys.path.insert(0, str(TEST_ROOT / "guest_tools"))
from benchmark_collector import (
    _classification_snapshot,
    _load_process_targets,
    _proc_identity,
    _scheduler_sample,
)

sys.path.insert(0, str(TEST_ROOT / "image" / "real_workloads"))
from summarize_workloads import elapsed_seconds, generic_rate, openssl_rate, wrk_metrics


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
        self.assertEqual(len(schedule), 6)
        self.assertEqual(len(set(schedule)), 6)
        for index in range(0, len(schedule), 2):
            first, second = schedule[index : index + 2]
            self.assertEqual(first[:2], second[:2])
            self.assertEqual({first[2], second[2]}, {"native", "agent"})

    def test_single_round_has_one_native_agent_pair(self) -> None:
        completed = subprocess.run(
            [sys.executable, TEST_ROOT / "scripts" / "benchmark.py", "--single-round", "--dry-run"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("profile: single-round", completed.stdout)
        self.assertIn("runs: 2", completed.stdout)
        self.assertEqual(completed.stdout.count(" repeat=1 "), 2)
        self.assertEqual(completed.stdout.count("scenario=dynamic_mix"), 2)

    def test_explicit_scenario_has_one_native_agent_pair(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                TEST_ROOT / "scripts" / "benchmark.py",
                "dynamic_mix",
                "--single-round",
                "--dry-run",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("runs: 2", completed.stdout)
        self.assertEqual(completed.stdout.count("scenario=dynamic_mix"), 2)
        self.assertIn(
            f"template_image: {self.config['libvirt']['template_image']}",
            completed.stdout,
        )

    def test_template_integrity_hashes_shared_image_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "template.qcow2"
            image.write_bytes(b"abc")
            image.chmod(0o444)
            versions_lock = root / "versions.lock"
            versions_lock.write_text(
                "target:\n"
                "  template_sha256: "
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n",
                encoding="utf-8",
            )
            specs = [
                build_spec(
                    self.config,
                    self.performance,
                    scenario="dynamic_mix",
                    variant=variant,
                    repeat=1,
                )
                for variant in ("native", "agent")
            ]
            for spec in specs:
                spec.libvirt["template_image"] = str(image)

            with patch.object(
                host_check,
                "_sha256_regular_file",
                wraps=host_check._sha256_regular_file,
            ) as sha256_file:
                result = host_check.check_template_integrity(specs, versions_lock)

            self.assertTrue(result.ok)
            self.assertEqual(sha256_file.call_count, 1)
            self.assertIn("ba7816bf", result.infos[0])

    def test_template_integrity_rejects_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "template.qcow2"
            image.write_bytes(b"abc")
            image.chmod(0o444)
            versions_lock = root / "versions.lock"
            versions_lock.write_text(
                f"target:\n  template_sha256: \"{'0' * 64}\"\n", encoding="utf-8"
            )
            spec = build_spec(
                self.config,
                self.performance,
                scenario="dynamic_mix",
                variant="native",
                repeat=1,
            )
            spec.libvirt["template_image"] = str(image)

            result = host_check.check_template_integrity([spec], versions_lock)

            self.assertFalse(result.ok)
            self.assertIn("SHA-256 mismatch", result.failures[0])
            self.assertIn("expected=" + "0" * 64, result.failures[0])
            self.assertIn("actual=ba7816bf", result.failures[0])

    def test_invalid_template_lock_fails_before_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "template.qcow2"
            image.write_bytes(b"abc")
            versions_lock = root / "versions.lock"
            versions_lock.write_text(
                "target:\n  template_sha256: invalid\n", encoding="utf-8"
            )
            spec = build_spec(
                self.config,
                self.performance,
                scenario="dynamic_mix",
                variant="native",
                repeat=1,
            )
            spec.libvirt["template_image"] = str(image)

            with patch.object(host_check, "_sha256_regular_file") as sha256_file:
                result = host_check.check_template_integrity([spec], versions_lock)

            self.assertFalse(result.ok)
            sha256_file.assert_not_called()
            self.assertIn("invalid target.template_sha256", result.failures[0])

    def test_campaign_and_environment_each_request_one_integrity_check(self) -> None:
        specs = [
            build_spec(
                self.config,
                self.performance,
                scenario=scenario,
                variant=variant,
                repeat=1,
            )
            for variant in ("native", "agent")
            for scenario in ("dynamic_mix",)
        ]
        success = CheckResult((), ())
        with (
            patch.object(
                benchmark_script, "check_template_integrity", return_value=success
            ) as campaign_integrity,
            patch.object(benchmark_script, "check_host", return_value=success) as host,
        ):
            result = benchmark_script._preflight(specs)
        self.assertTrue(result.ok)
        campaign_integrity.assert_called_once()
        self.assertEqual(host.call_count, 2)

        with (
            patch.object(
                check_env_script, "check_template_integrity", return_value=success
            ) as environment_integrity,
            patch.object(check_env_script, "check_host", return_value=success) as host,
        ):
            self.assertEqual(check_env_script.main(), 0)
        environment_integrity.assert_called_once()
        self.assertEqual(host.call_count, 2)

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
                    self.assertIn('systemctl stop "$WORKLOAD_SERVICE"', script)
                    self.assertIn('install -m 0755 "$WORKLOAD_LAUNCHER"', script)
                    self.assertIn('systemctl start --no-block "$WORKLOAD_SERVICE"', script)
                    self.assertIn(
                        'wait_for_scheduler "$SCHEDULER_START_TIMEOUT_SECONDS"', script
                    )
                    self.assertNotIn("taskbench", script)
                    self.assertNotIn("workload-build", script)
                    if variant == "agent":
                        self.assertIn("--classification-snapshot-at-ns", script)
                        self.assertIn("--classification-timeline-start-ns", script)
                        self.assertIn("--classification-interval-seconds 5", script)
                    else:
                        self.assertNotIn("--classification-snapshot-at-ns", script)
                        self.assertNotIn("--classification-timeline-start-ns", script)

    def test_payloads_sync_collector_launcher_and_summarizer(self) -> None:
        spec = build_spec(
            self.config,
            self.performance,
            scenario="dynamic_mix",
            variant="native",
            repeat=1,
        )
        payloads = _payloads(spec)
        self.assertEqual(len(payloads), 3)
        targets = {str(payload["target"]) for payload in payloads}
        self.assertIn(self.performance["collector"]["target"], targets)
        self.assertIn("/tmp/aoa-real-workload", targets)
        self.assertIn("/tmp/aoa-summarize-workloads", targets)
        launcher = next(
            payload for payload in payloads if payload["target"] == "/tmp/aoa-real-workload"
        )
        self.assertEqual(
            Path(launcher["source"]),
            TEST_ROOT / "image" / "real_workloads" / "aoa-real-workload",
        )
        self.assertTrue(launcher["executable"])

    def test_workload_launcher_has_bounded_batch_jobs_and_valid_shell(self) -> None:
        launcher = TEST_ROOT / "image" / "real_workloads" / "aoa-real-workload"
        subprocess.run(["bash", "-n", launcher], check=True)
        source = launcher.read_text(encoding="utf-8")
        self.assertEqual(source.count("bounded_iterations \"$1\""), 2)
        self.assertNotIn("build_job()", source)
        self.assertIn("aoa-profile-dynamic_mix", source)
        self.assertIn("bursty_openssl_job burst-openssl", source)
        self.assertIn("load-contract.json", source)

        bounded = subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; trap - EXIT INT TERM; bounded_iterations 1 7 sleep 5',
                "bounded-iterations-test",
                str(launcher),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(bounded.stdout, "iterations=0\nwork_units=0\n")

        failed = subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; trap - EXIT INT TERM; bounded_iterations 5 0 sh -c "exit 23"',
                "bounded-iterations-test",
                str(launcher),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(failed.returncode, 23)

    def test_spec_profiles(self) -> None:
        formal = build_spec(
            self.config,
            self.performance,
            scenario="dynamic_mix",
            variant="native",
            repeat=1,
        )
        single = build_spec(
            self.config,
            self.performance,
            scenario="dynamic_mix",
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
            scenario="dynamic_mix",
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
            "aoa-profile-dynamic_mix",
        )
        self.assertEqual(root.find("./devices/disk/driver").attrib["discard"], "unmap")

    def test_host_control_scripts_have_valid_shell_syntax(self) -> None:
        for name in ("cpu_isolation.sh", "set_cpu_frequency.sh", "restore_cpu_frequency.sh"):
            subprocess.run(["sh", "-n", TEST_ROOT / "scripts" / name], check=True)

    def test_long_domain_name_keeps_unique_suffix(self) -> None:
        spec = build_spec(
            self.config,
            self.performance,
            scenario="dynamic_mix",
            variant="agent",
            repeat=1,
        )
        first = domain_name(spec, "11111111")
        second = domain_name(spec, "22222222")
        self.assertLessEqual(len(first), 63)
        self.assertNotEqual(first, second)
        self.assertTrue(first.endswith("-11111111"))


class CollectorTests(unittest.TestCase):
    def test_scheduler_sample_preserves_throughput_preemption_runtime(self) -> None:
        stats = {
            "data_plane": {
                "fast_path_throughput_preemption_runtime_bins": [1, 2, 3, 4],
                "fast_path_throughput_preemption_runtime_ns": 5,
                "fast_path_throughput_preemption_request_ns": 6,
                "fast_path_steal_idle_source_admissions": 10,
                "fast_path_steal_idle_throughput_deferrals": 11,
                "fast_path_steal_latency_successor_deferrals": 9,
                "fast_path_latency_selects_by_path": [12, 13, 14, 15],
                "fast_path_latency_select_migrations_by_path": [16, 17, 18, 19],
                "fast_path_immediate_preemption_kicks_by_class": [20, 21, 0],
                "fast_path_select_sync_wakeups_by_class": [22, 23, 24],
                "fast_path_select_sync_migrations_by_class": [25, 26, 27],
                "fast_path_shared_balanced_enqueues": 28,
                "fast_path_shared_balanced_dispatch_attempts": 29,
                "fast_path_shared_balanced_dispatches": 30,
                "fast_path_shared_balanced_dispatch_failures": 31,
                "fast_path_shared_latency_enqueues": 32,
                "fast_path_shared_latency_dispatch_attempts": 33,
                "fast_path_shared_latency_dispatches": 34,
                "fast_path_shared_latency_dispatch_failures": 35,
            },
            "policy": {
                "preemption_interval_floor_ns": 7,
                "latency_successor_lease_ns": 6,
                "observed_latency_service_ns": 8,
            },
        }

        sample = _scheduler_sample(stats, 100)

        self.assertEqual(
            sample["data_plane"]["fast_path_throughput_preemption_runtime_bins"],
            [1, 2, 3, 4],
        )
        self.assertEqual(
            sample["data_plane"]["fast_path_throughput_preemption_runtime_ns"],
            5,
        )
        self.assertEqual(
            sample["data_plane"]["fast_path_throughput_preemption_request_ns"],
            6,
        )
        self.assertEqual(
            sample["data_plane"]["fast_path_steal_idle_source_admissions"],
            10,
        )
        self.assertEqual(
            sample["data_plane"]["fast_path_steal_idle_throughput_deferrals"],
            11,
        )
        self.assertEqual(
            sample["data_plane"]["fast_path_steal_latency_successor_deferrals"],
            9,
        )
        self.assertEqual(
            sample["data_plane"]["fast_path_latency_selects_by_path"],
            [12, 13, 14, 15],
        )
        self.assertEqual(
            sample["data_plane"]["fast_path_latency_select_migrations_by_path"],
            [16, 17, 18, 19],
        )
        self.assertEqual(
            sample["data_plane"]["fast_path_immediate_preemption_kicks_by_class"],
            [20, 21, 0],
        )
        self.assertEqual(
            sample["data_plane"]["fast_path_select_sync_wakeups_by_class"],
            [22, 23, 24],
        )
        self.assertEqual(
            sample["data_plane"]["fast_path_select_sync_migrations_by_class"],
            [25, 26, 27],
        )
        self.assertEqual(
            sample["data_plane"]["fast_path_shared_balanced_enqueues"],
            28,
        )
        self.assertEqual(
            sample["data_plane"]["fast_path_shared_balanced_dispatch_attempts"],
            29,
        )
        self.assertEqual(
            sample["data_plane"]["fast_path_shared_balanced_dispatches"],
            30,
        )
        self.assertEqual(
            sample["data_plane"]["fast_path_shared_balanced_dispatch_failures"],
            31,
        )
        self.assertEqual(
            sample["data_plane"]["fast_path_shared_latency_enqueues"],
            32,
        )
        self.assertEqual(
            sample["data_plane"]["fast_path_shared_latency_dispatch_attempts"],
            33,
        )
        self.assertEqual(
            sample["data_plane"]["fast_path_shared_latency_dispatches"],
            34,
        )
        self.assertEqual(
            sample["data_plane"]["fast_path_shared_latency_dispatch_failures"],
            35,
        )
        self.assertEqual(sample["policy"]["preemption_interval_floor_ns"], 7)
        self.assertEqual(sample["policy"]["latency_successor_lease_ns"], 6)
        self.assertEqual(sample["policy"]["observed_latency_service_ns"], 8)

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

    def test_longitudinal_accuracy_does_not_backdate_a_correction(self) -> None:
        snapshots = [
            {
                "observed_ns": 100,
                "processes": [
                    {
                        "pid": 10,
                        "observed": True,
                        "class": "balanced",
                    }
                ],
                "threads": [],
            },
            {
                "observed_ns": 200,
                "processes": [
                    {
                        "pid": 10,
                        "observed": True,
                        "class": "throughput",
                    }
                ],
                "threads": [],
            },
        ]
        schedstat = [
            {
                "observed_ns": observed_ns,
                "pid": 10,
                "tid": 11,
                "mode": "throughput",
                "run_ns": run_ns,
            }
            for observed_ns, run_ns in ((100, 0), (200, 100), (300, 200))
        ]

        metrics = _longitudinal_runtime_weighted(
            snapshots, schedstat, 100, 300, scope="process"
        )

        self.assertEqual(metrics["snapshot_samples"], 2)
        self.assertEqual(metrics["class_changes"], 1)
        self.assertEqual(metrics["runtime_coverage"], 1.0)
        self.assertEqual(metrics["observed_runtime_accuracy"], 0.5)

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

    def test_classification_snapshot_splits_large_tgid_projection(self) -> None:
        class Client:
            def __init__(self) -> None:
                self.batches: list[list[int]] = []

            def query(self, tool: str, arguments: dict[str, object]) -> dict[str, object]:
                if tool != "workload.list":
                    raise AssertionError(f"unexpected per-item query: {tool}")
                tgids = [int(pid) for pid in arguments["tgids"]]  # type: ignore[index]
                self.batches.append(tgids)
                return {
                    "items": [
                        {
                            "kind": "process",
                            "identity": {
                                "tgid": pid,
                                "process_cookie": pid,
                                "exec_generation": 1,
                            },
                            "classification": {
                                "class": "balanced",
                                "source": "local_metadata",
                                "generation": 1,
                                "applied_generation": 1,
                            },
                        }
                        for pid in tgids
                    ]
                }

        targets = {
            (pid, pid): {
                "mode": "balanced",
                "worker": f"app:{pid}",
                "app": "app",
                "root_pid": pid,
                "process_depth": 0,
                "process_role": "root",
            }
            for pid in range(1000, 1300)
        }
        client = Client()
        snapshot = _classification_snapshot(client, targets, set(targets), 100, 300)

        self.assertEqual(len(client.batches), 5)
        self.assertLessEqual(max(map(len, client.batches)), 64)
        self.assertEqual(len(snapshot["processes"]), 300)
        self.assertTrue(all(row["observed"] for row in snapshot["processes"]))
        self.assertEqual(snapshot["errors"], [])

    def test_longitudinal_accuracy_ignores_failed_snapshots(self) -> None:
        snapshots = [
            {
                "observed_ns": 100,
                "errors": [],
                "processes": [{"pid": 10, "observed": True, "class": "throughput"}],
                "threads": [],
            },
            {
                "observed_ns": 200,
                "errors": [{"scope": "list", "error": "closed"}],
                "processes": [{"pid": 10, "observed": False}],
                "threads": [],
            },
        ]
        schedstat = [
            {"observed_ns": 100, "pid": 10, "tid": 11, "mode": "throughput", "run_ns": 0},
            {"observed_ns": 300, "pid": 10, "tid": 11, "mode": "throughput", "run_ns": 200},
        ]

        metrics = _longitudinal_runtime_weighted(
            snapshots, schedstat, 100, 300, scope="process"
        )

        self.assertEqual(metrics["snapshot_samples"], 1)
        self.assertEqual(metrics["runtime_coverage"], 1.0)
        self.assertEqual(metrics["observed_runtime_accuracy"], 1.0)


class WorkloadSummaryTests(unittest.TestCase):
    def test_server_targets_are_objective_neutral(self) -> None:
        dispatcher = (
            TEST_ROOT / "image" / "real_workloads" / "aoa-real-workload"
        ).read_text(encoding="utf-8")
        self.assertNotRegex(
            dispatcher,
            r"start_server\s+\S+\s+(?:latency|throughput)\b",
        )

    def test_dynamic_mix_contains_all_objective_applications(self) -> None:
        dispatcher = (
            TEST_ROOT / "image" / "real_workloads" / "aoa-real-workload"
        ).read_text(encoding="utf-8")
        for application in (
            "redis_job redis latency",
            "nginx_job nginx",
            "postgres_job postgresql",
            "ffmpeg_job ffmpeg",
            "rocksdb_job rocksdb",
            "zstd_job zstd throughput",
        ):
            self.assertIn(application, dispatcher)

    def test_rocksdb_rate_ignores_initial_zero(self) -> None:
        output = (
            "Read rate: 0 ops/second\n"
            "readrandomwriterandom : 6.307 micros/op 475226 ops/sec\n"
        )
        self.assertEqual(generic_rate(output, 8.0), 475226.0)

    def test_openssl_rate_parses_aggregate_bytes_per_second(self) -> None:
        output = "AES-256-GCM      11228301.31k\n"
        self.assertEqual(openssl_rate(output), 11_228_301_310.0)

    def test_wrk_metrics_selects_exact_p99_not_deeper_tail(self) -> None:
        output = (
            " 99.000%    5.89ms\n"
            " 99.900%    8.31ms\n"
            " 99.990%   19.73ms\n"
            " 99.999%   91.71ms\n"
            "Requests/sec: 1799.63\n"
        )
        self.assertEqual(wrk_metrics(output), (5.89, 1799.63))

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
    def test_scheduler_metrics_break_down_throughput_disruption_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bench_dir = Path(directory)
            observations = bench_dir / "observations"
            observations.mkdir()
            rows = (
                {
                    "observed_ns": 100,
                    "scheduler": {},
                    "data_plane": {
                        "fast_path_latency_select_migrations_by_locality": [1, 2, 3, 4],
                        "fast_path_latency_remote_dispatches_by_locality": [5, 6, 7, 8],
                        "fast_path_latency_remote_steals_preserving_successor": 19,
                        "fast_path_latency_remote_steals_fallback": 20,
                        "fast_path_latency_idle_source_deferrals": 21,
                        "fast_path_latency_selects_by_path": [1, 2, 3, 4],
                        "fast_path_latency_select_migrations_by_path": [5, 6, 7, 8],
                        "fast_path_immediate_preemption_kicks_by_class": [9, 10, 0],
                        "fast_path_select_sync_wakeups_by_class": [11, 12, 13],
                        "fast_path_select_sync_migrations_by_class": [14, 15, 16],
                        "fast_path_throughput_select_migrations_by_locality": [1, 2, 3, 4],
                        "fast_path_throughput_remote_dispatches_by_locality": [5, 6, 7, 8],
                        "fast_path_throughput_preemption_service_bins": [9, 10, 11, 12],
                        "fast_path_throughput_preemption_runtime_bins": [13, 14, 15, 16],
                        "fast_path_throughput_preemption_runtime_ns": 17,
                        "fast_path_throughput_preemption_request_ns": 18,
                    },
                    "policy": {},
                },
                {
                    "observed_ns": 200,
                    "scheduler": {},
                    "data_plane": {
                        "fast_path_latency_select_migrations_by_locality": [11, 22, 33, 44],
                        "fast_path_latency_remote_dispatches_by_locality": [55, 66, 77, 88],
                        "fast_path_latency_remote_steals_preserving_successor": 119,
                        "fast_path_latency_remote_steals_fallback": 220,
                        "fast_path_latency_idle_source_deferrals": 221,
                        "fast_path_latency_selects_by_path": [11, 22, 33, 44],
                        "fast_path_latency_select_migrations_by_path": [55, 66, 77, 88],
                        "fast_path_immediate_preemption_kicks_by_class": [99, 110, 0],
                        "fast_path_select_sync_wakeups_by_class": [121, 132, 143],
                        "fast_path_select_sync_migrations_by_class": [154, 165, 176],
                        "fast_path_throughput_select_migrations_by_locality": [11, 22, 33, 44],
                        "fast_path_throughput_remote_dispatches_by_locality": [55, 66, 77, 88],
                        "fast_path_throughput_preemption_service_bins": [99, 110, 121, 132],
                        "fast_path_throughput_preemption_runtime_bins": [143, 154, 165, 176],
                        "fast_path_throughput_preemption_runtime_ns": 187,
                        "fast_path_throughput_preemption_request_ns": 198,
                    },
                    "policy": {},
                },
            )
            (observations / "scheduler-stats.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
            )

            metrics = _scheduler_metrics(bench_dir, 100, 200)

            self.assertEqual(
                metrics["fast_path_latency_select_migrations_same_core_smt"],
                10,
            )
            self.assertEqual(
                metrics["fast_path_latency_select_migrations_cross_llc"],
                30,
            )
            self.assertEqual(
                metrics["fast_path_latency_remote_dispatches_same_llc"],
                60,
            )
            self.assertEqual(
                metrics["fast_path_latency_remote_dispatches_unknown"],
                80,
            )
            self.assertEqual(
                metrics["fast_path_latency_remote_steals_preserving_successor"],
                100,
            )
            self.assertEqual(
                metrics["fast_path_latency_remote_steals_fallback"],
                200,
            )
            self.assertEqual(
                metrics["fast_path_latency_idle_source_deferrals"],
                200,
            )
            self.assertEqual(metrics["fast_path_latency_selects_default_idle"], 10)
            self.assertEqual(metrics["fast_path_latency_selects_default_busy"], 20)
            self.assertEqual(metrics["fast_path_latency_selects_policy_victim"], 30)
            self.assertEqual(metrics["fast_path_latency_selects_fallback"], 40)
            self.assertEqual(
                metrics["fast_path_latency_select_migrations_default_idle"], 50
            )
            self.assertEqual(
                metrics["fast_path_latency_select_migrations_default_busy"], 60
            )
            self.assertEqual(
                metrics["fast_path_latency_select_migrations_policy_victim"], 70
            )
            self.assertEqual(
                metrics["fast_path_latency_select_migrations_fallback"], 80
            )
            self.assertEqual(
                metrics["fast_path_immediate_preemption_kicks_latency"], 90
            )
            self.assertEqual(
                metrics["fast_path_immediate_preemption_kicks_balanced"], 100
            )
            self.assertEqual(metrics["fast_path_select_sync_wakeups_latency"], 110)
            self.assertEqual(metrics["fast_path_select_sync_wakeups_balanced"], 120)
            self.assertEqual(metrics["fast_path_select_sync_wakeups_throughput"], 130)
            self.assertEqual(metrics["fast_path_select_sync_migrations_latency"], 140)
            self.assertEqual(metrics["fast_path_select_sync_migrations_balanced"], 150)
            self.assertEqual(
                metrics["fast_path_select_sync_migrations_throughput"], 160
            )
            self.assertEqual(
                metrics["fast_path_throughput_select_migrations_same_core_smt"],
                10,
            )
            self.assertEqual(
                metrics["fast_path_throughput_select_migrations_cross_llc"],
                30,
            )
            self.assertEqual(
                metrics["fast_path_throughput_remote_dispatches_same_llc"],
                60,
            )
            self.assertEqual(
                metrics["fast_path_throughput_remote_dispatches_unknown"],
                80,
            )
            self.assertEqual(
                metrics["fast_path_throughput_preemption_service_25_to_50pct"],
                100,
            )
            self.assertEqual(
                metrics["fast_path_throughput_preemption_service_at_least_90pct"],
                120,
            )
            self.assertEqual(
                metrics["fast_path_throughput_preemption_runtime_500us_to_1ms"],
                140,
            )
            self.assertEqual(
                metrics["fast_path_throughput_preemption_runtime_at_least_2ms"],
                160,
            )
            self.assertEqual(
                metrics["fast_path_throughput_preemption_runtime_ns"],
                170,
            )
            self.assertEqual(
                metrics["fast_path_throughput_preemption_request_ns"],
                180,
            )

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
            _write_native_result(run_dir, "dynamic_mix", 100, 200)
            _write_metric(run_dir, "redis", "latency", p99_ms=1.0, throughput=1000.0)
            _write_metric(run_dir, "nginx", "latency", p99_ms=4.0, throughput=4000.0)
            _write_metric(run_dir, "ffmpeg", "throughput", throughput=100.0)
            _write_metric(run_dir, "rocksdb", "throughput", throughput=400.0)
            _write_metric(
                run_dir,
                "burst-openssl",
                "throughput",
                throughput=10_000.0,
                objective=False,
            )
            _write_dynamic_mix_evidence(run_dir / "benchmark", 100, 200)
            analyzed = analyze_run(run_dir)
            self.assertTrue(analyzed["valid"])
            self.assertAlmostEqual(analyzed["latency"]["p99_us"]["geometric_mean"], 2000.0)
            self.assertAlmostEqual(analyzed["throughput"]["operations_per_second"], 200.0)

    def test_dynamic_mix_contract_checks_average_bursts_and_long_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bench_dir = Path(directory)
            real = bench_dir / "real-workloads"
            observations = bench_dir / "observations"
            real.mkdir()
            observations.mkdir()
            (real / "load-contract.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "scenario": "dynamic_mix",
                        "average_utilization": {
                            "target": 0.8,
                            "minimum": 0.7,
                            "maximum": 0.9,
                        },
                        "burst": {
                            "utilization_minimum": 0.95,
                            "minimum_high_utilization_samples": 1,
                            "minimum_completed_bursts": 1,
                        },
                        "continuous_throughput_apps": ["batch"],
                    }
                ),
                encoding="utf-8",
            )
            timeline = (
                {"burst": 1, "event": "start", "observed_ns": 150},
                {"burst": 1, "event": "end", "observed_ns": 250},
            )
            (real / "burst-timeline.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in timeline),
                encoding="utf-8",
            )
            cpu_rows = []
            for observed_ns, user_ticks, idle_ticks in (
                (100, 0, 0),
                (200, 80, 20),
                (300, 180, 20),
                (400, 260, 40),
            ):
                cpu_rows.append(
                    {
                        "observed_ns": observed_ns,
                        "cpu": 0,
                        "user_ticks": user_ticks,
                        "nice_ticks": 0,
                        "system_ticks": 0,
                        "idle_ticks": idle_ticks,
                        "iowait_ticks": 0,
                        "irq_ticks": 0,
                        "softirq_ticks": 0,
                        "steal_ticks": 0,
                    }
                )
            (observations / "cpu-stats.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in cpu_rows),
                encoding="utf-8",
            )

            result = _load_contract_metrics(
                bench_dir,
                {
                    "batch": {
                        "role": "throughput",
                        "objective": True,
                        "elapsed_seconds": 60.0,
                    }
                },
                {"utilization": 0.8},
                100,
                400,
                required=True,
            )

            self.assertTrue(result["valid"])
            self.assertEqual(result["observed"]["high_utilization_samples"], 1)
            self.assertEqual(result["observed"]["completed_bursts"], 1)

    def test_dynamic_mix_comparisons_pair_by_repeat_and_direction(self) -> None:
        rows = []
        values = (
            (1, 100.0, 90.0, 100.0, 120.0),
            (2, 200.0, 180.0, 200.0, 220.0),
        )
        for repeat, native_p99, agent_p99, native_rate, agent_rate in values:
            for variant, p99, rate in (
                ("native", native_p99, native_rate),
                ("agent", agent_p99, agent_rate),
            ):
                rows.append(
                    {
                        "scenario": "dynamic_mix",
                        "variant": variant,
                        "repeat": repeat,
                        "latency": {"p99_us": {"geometric_mean": p99}},
                        "throughput": {"operations_per_second": rate},
                        "applications": {
                            "redis": {
                                "role": "latency",
                                "objective": True,
                                "p99_ms": p99 / 1000,
                            },
                            "rocksdb": {
                                "role": "throughput",
                                "objective": True,
                                "throughput_per_second": rate,
                            },
                        },
                    }
                )
        comparisons = {
            row["metric"]: row
            for row in _comparisons(rows, bootstrap_samples=200, seed=1)
        }
        self.assertEqual(comparisons["p99_latency_geomean_us"]["pairs"], 2)
        self.assertAlmostEqual(
            comparisons["p99_latency_geomean_us"]["paired_improvement"]["median"],
            10.0,
        )
        self.assertAlmostEqual(
            comparisons["throughput_geomean_per_second"]["paired_improvement"]["median"],
            15.0,
        )
        applications = _application_comparisons(
            rows, bootstrap_samples=200, seed=1
        )
        self.assertEqual({row["application"] for row in applications}, {"redis", "rocksdb"})

    def test_agent_evidence_aggregates_health_and_overhead(self) -> None:
        evidence = _campaign_agent_evidence(
            [
                {
                    "variant": "agent",
                    "measurement": {"duration_seconds": 60.0},
                    "cpu_utilization": {"cpus": 6},
                    "overhead": {
                        "agent_scheduler_cpu_seconds": 1.8,
                        "roles": {
                            "agent": {"max_rss_mib": 12.0},
                            "scheduler": {"max_rss_mib": 14.0},
                        },
                    },
                    "scheduler": {
                        "event_overflows": 0,
                        "fallback_dispatches": 0,
                        "task_capacity_hits": 0,
                        "degraded_transitions": 0,
                        "policy_feedback_updates": 60,
                        "policy_placement_updates": 60,
                        "fast_path_shared_latency_dispatch_attempts": 100,
                        "fast_path_shared_latency_dispatches": 100,
                    },
                }
            ]
        )
        self.assertAlmostEqual(evidence["control_plane_cpu_percent"], 0.5)
        self.assertEqual(evidence["policy_feedback_updates"], 60)
        self.assertEqual(evidence["shared_dispatch"]["latency"]["success_ratio"], 1.0)
        self.assertEqual(evidence["event_overflows"], 0)

    def test_system_comparisons_report_paired_auxiliary_metrics(self) -> None:
        rows = [
            {
                "scenario": "dynamic_mix",
                "variant": "native",
                "repeat": 1,
                "cpu_utilization": {"core_busy_coefficient_of_variation": 0.04},
                "perf": {"context-switches": 100.0, "cache_miss_ratio": 0.20},
            },
            {
                "scenario": "dynamic_mix",
                "variant": "agent",
                "repeat": 1,
                "cpu_utilization": {"core_busy_coefficient_of_variation": 0.02},
                "perf": {"context-switches": 110.0, "cache_miss_ratio": 0.21},
            },
        ]
        comparisons = {
            row["metric"]: row
            for row in _system_comparisons(rows, bootstrap_samples=100, seed=1)
        }
        self.assertAlmostEqual(
            comparisons["core_busy_cv"]["paired_change"]["median"], -50.0
        )
        self.assertAlmostEqual(
            comparisons["context_switches"]["paired_change"]["median"], 10.0
        )
        self.assertAlmostEqual(
            comparisons["cache_miss_ratio"]["paired_change"]["median"], 1.0
        )


def _write_dynamic_mix_evidence(bench_dir: Path, start_ns: int, end_ns: int) -> None:
    real = bench_dir / "real-workloads"
    observations = bench_dir / "observations"
    real.mkdir(parents=True, exist_ok=True)
    observations.mkdir(parents=True, exist_ok=True)
    (real / "load-contract.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "scenario": "dynamic_mix",
                "average_utilization": {
                    "target": 0.8,
                    "minimum": 0.7,
                    "maximum": 0.9,
                },
                "burst": {
                    "utilization_minimum": 0.95,
                    "minimum_high_utilization_samples": 0,
                    "minimum_completed_bursts": 0,
                },
                "continuous_throughput_apps": ["ffmpeg", "rocksdb"],
            }
        ),
        encoding="utf-8",
    )
    rows = (
        {
            "observed_ns": start_ns,
            "cpu": 0,
            "package_id": 0,
            "core_id": 0,
            "user_ticks": 0,
            "nice_ticks": 0,
            "system_ticks": 0,
            "idle_ticks": 0,
            "iowait_ticks": 0,
            "irq_ticks": 0,
            "softirq_ticks": 0,
            "steal_ticks": 0,
        },
        {
            "observed_ns": end_ns,
            "cpu": 0,
            "package_id": 0,
            "core_id": 0,
            "user_ticks": 80,
            "nice_ticks": 0,
            "system_ticks": 0,
            "idle_ticks": 20,
            "iowait_ticks": 0,
            "irq_ticks": 0,
            "softirq_ticks": 0,
            "steal_ticks": 0,
        },
    )
    (observations / "cpu-stats.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


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
    objective: bool = True,
) -> None:
    directory = run_dir / "benchmark" / "real-workloads" / "apps" / name
    directory.mkdir(parents=True, exist_ok=True)
    metric = {
        "schema_version": 1,
        "name": name,
        "role": role,
        "objective": objective,
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
