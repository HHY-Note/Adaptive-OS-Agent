from __future__ import annotations

import copy
import random
import re
from pathlib import Path
from typing import Any

from test_core.config.parser import ConfigError
from test_core.models import RunSpec


SCENARIOS = ("latency", "throughput", "mix")
VARIANTS = ("native", "agent")
PROFILES = ("formal", "single-round")


def load_performance(config: dict[str, Any]) -> dict[str, Any]:
    raw = config.get("performance")
    if not isinstance(raw, dict):
        raise ConfigError("performance must be a mapping")
    performance = copy.deepcopy(raw)
    _reject_unknown(
        performance,
        {
            "machine",
            "variants",
            "repeats",
            "seed",
            "warmup_seconds",
            "measurement_seconds",
            "cooldown_seconds",
            "sample_interval_seconds",
            "require_perf",
            "perf_events",
            "bootstrap_samples",
            "workload",
            "collector",
        },
        "performance",
    )

    machine_name = _reference(performance, "machine", config["machines"], "performance")
    machine = config["machines"][machine_name]
    if machine["vcpus"] != 6:
        raise ConfigError("performance.machine must provide exactly 6 vCPUs")
    if machine["topology"] != {"sockets": 1, "cores": 3, "threads": 2}:
        raise ConfigError(
            "performance.machine must use one socket, three cores, and two threads per core"
        )
    if machine["frequency"]["governor"] != "performance":
        raise ConfigError("performance.machine must use the performance governor")

    variants = performance.get("variants")
    if not isinstance(variants, dict) or set(variants) != set(VARIANTS):
        raise ConfigError("performance.variants must contain exactly native and agent")
    for variant in VARIANTS:
        _reference(variants, variant, config["schedulers"], "performance.variants")
    native = config["schedulers"][variants["native"]]
    agent = config["schedulers"][variants["agent"]]
    if native.get("kind") != "builtin":
        raise ConfigError("performance.variants.native must reference a builtin scheduler")
    if agent.get("kind") != "agent":
        raise ConfigError("performance.variants.agent must reference an Agent scheduler")
    if "--offline" in agent.get("args", []):
        raise ConfigError("performance Agent must use online classification")
    if not agent.get("require_process_llm") or not agent.get("require_thread_llm"):
        raise ConfigError("performance Agent must require process and thread LLM classification")

    _integer(performance, "repeats", minimum=3, maximum=100)
    _integer(performance, "seed", minimum=0)
    _integer(performance, "warmup_seconds", minimum=5, maximum=3600)
    _integer(performance, "measurement_seconds", minimum=10, maximum=86400)
    _integer(performance, "cooldown_seconds", minimum=0, maximum=300)
    _number(performance, "sample_interval_seconds", minimum=0.1, maximum=10.0)
    _integer(performance, "bootstrap_samples", minimum=100, maximum=100000)
    if not isinstance(performance.get("require_perf"), bool):
        raise ConfigError("performance.require_perf must be a boolean")
    events = performance.get("perf_events")
    if not isinstance(events, list) or not events or not all(
        isinstance(value, str) and value for value in events
    ):
        raise ConfigError("performance.perf_events must be a non-empty list of strings")

    root = Path(config["__base_dir"])
    performance["workload"] = _workload_config(performance.get("workload"), root)
    performance["collector"] = _collector_config(performance.get("collector"), root)
    return performance


def build_spec(
    config: dict[str, Any],
    performance: dict[str, Any],
    *,
    scenario: str,
    variant: str,
    repeat: int,
    profile: str = "formal",
) -> RunSpec:
    if scenario not in SCENARIOS:
        raise ConfigError(f"unknown performance scenario: {scenario}")
    if variant not in VARIANTS:
        raise ConfigError(f"unknown performance variant: {variant}")
    if repeat < 1:
        raise ConfigError("performance repeat must be positive")
    if profile not in PROFILES:
        raise ConfigError(f"unknown performance profile: {profile}")
    machine_name = str(performance["machine"])
    scheduler_name = str(performance["variants"][variant])
    machine = dict(config["machines"][machine_name])
    benchmark = {
        "schema_version": 3,
        "profile": profile,
        "scenario": scenario,
        "variant": variant,
        "repeat": repeat,
        "seed": int(performance["seed"]) + repeat,
        "warmup_seconds": int(performance["warmup_seconds"]),
        "measurement_seconds": int(performance["measurement_seconds"]),
        "cooldown_seconds": int(performance["cooldown_seconds"]),
        "sample_interval_seconds": float(performance["sample_interval_seconds"]),
        "require_perf": bool(performance["require_perf"]),
        "perf_events": list(performance["perf_events"]),
        "collector_target": str(performance["collector"]["target"]),
        "files": [dict(performance["collector"])],
    }
    return RunSpec(
        case_name=f"benchmark-{scenario}-{variant}-r{repeat:02d}",
        machine_name=machine_name,
        scheduler_name=scheduler_name,
        machine=machine,
        scheduler=dict(config["schedulers"][scheduler_name]),
        libvirt=dict(config["libvirt"]),
        workload=dict(performance["workload"]),
        config_path=Path(config["__config_path"]),
        benchmark=benchmark,
    )


def campaign_schedule(
    scenarios: list[str], variants: list[str], repeats: int, seed: int
) -> list[tuple[int, str, str]]:
    if repeats < 1:
        raise ConfigError("repeats must be positive")
    if not scenarios or any(value not in SCENARIOS for value in scenarios):
        raise ConfigError("invalid scenario selection")
    if not variants or any(value not in VARIANTS for value in variants):
        raise ConfigError("invalid variant selection")
    randomizer = random.Random(seed)
    schedule: list[tuple[int, str, str]] = []
    for repeat in range(1, repeats + 1):
        blocks = list(scenarios)
        randomizer.shuffle(blocks)
        for scenario in blocks:
            block_variants = list(variants)
            randomizer.shuffle(block_variants)
            schedule.extend((repeat, scenario, variant) for variant in block_variants)
    return schedule


def _workload_config(value: Any, root: Path) -> dict[str, Any]:
    label = "performance.workload"
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be a mapping")
    required = {
        "kind",
        "service",
        "result_root",
        "ready_file",
        "window_file",
        "targets_file",
    }
    _reject_unknown(value, required, label)
    for key in required:
        if not isinstance(value.get(key), str) or not value[key]:
            raise ConfigError(f"{label}.{key} must be a non-empty string")
    if value["kind"] != "baked-real-apps":
        raise ConfigError(f"{label}.kind must be baked-real-apps")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", value["service"]):
        raise ConfigError(f"{label}.service must be a systemd service unit name")
    for key in {"result_root", "ready_file", "window_file", "targets_file"}:
        if not value[key].startswith("/"):
            raise ConfigError(f"{label}.{key} must be an absolute Guest path")
    return dict(value)


def _collector_config(value: Any, root: Path) -> dict[str, Any]:
    label = "performance.collector"
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be a mapping")
    required = {"source", "target"}
    _reject_unknown(value, required, label)
    for key in required:
        if not isinstance(value.get(key), str) or not value[key]:
            raise ConfigError(f"{label}.{key} must be a non-empty string")
    if not value["target"].startswith("/"):
        raise ConfigError(f"{label}.target must be an absolute Guest path")
    result = dict(value)
    source = Path(result["source"]).expanduser()
    result["source"] = str((source if source.is_absolute() else root / source).resolve())
    result["executable"] = True
    return result


def _reference(
    mapping: dict[str, Any], key: str, choices: dict[str, Any], label: str
) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or value not in choices:
        raise ConfigError(f"{label}.{key} references unknown value: {value}")
    return value


def _integer(
    mapping: dict[str, Any], key: str, *, minimum: int, maximum: int | None = None
) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ConfigError(f"performance.{key} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise ConfigError(f"performance.{key} must be <= {maximum}")
    return value


def _number(
    mapping: dict[str, Any], key: str, *, minimum: float, maximum: float
) -> float:
    value = mapping.get(key)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ConfigError(f"performance.{key} must be a number")
    if not minimum <= float(value) <= maximum:
        raise ConfigError(f"performance.{key} must be in {minimum}..={maximum}")
    return float(value)


def _reject_unknown(mapping: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ConfigError(f"{label} contains unknown fields: {unknown}")
