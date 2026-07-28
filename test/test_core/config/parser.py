from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    raise SystemExit("PyYAML is required: python3 -m pip install PyYAML") from exc


class ConfigError(ValueError):
    pass


REQUIRED_TOP_LEVEL = ("libvirt", "machines", "schedulers", "performance")
VALID_TOP_LEVEL = {*REQUIRED_TOP_LEVEL, "__config_path", "__base_dir"}
VALID_SCHEDULER_KINDS = {"builtin", "agent"}
VALID_STOP_SIGNALS = {"INT", "TERM"}


def load_config(path: str | Path, *, base_dir: str | Path | None = None) -> dict[str, Any]:
    config_path = Path(path).expanduser()
    if not config_path.is_absolute():
        config_path = Path.cwd() / config_path
    config_path = config_path.resolve()
    with config_path.open("r", encoding="utf-8") as stream:
        data = yaml.safe_load(stream)
    if not isinstance(data, dict):
        raise ConfigError(f"config must be a non-empty mapping: {config_path}")

    root = Path(base_dir).expanduser().resolve() if base_dir else Path.cwd().resolve()
    config = copy.deepcopy(data)
    config["__config_path"] = str(config_path)
    config["__base_dir"] = str(root)
    _normalize_host_paths(config, root)
    validate_config(config)
    return config


def validate_config(config: dict[str, Any]) -> None:
    unknown = sorted(set(config) - VALID_TOP_LEVEL)
    if unknown:
        raise ConfigError(f"config contains unknown fields: {unknown}")
    for key in REQUIRED_TOP_LEVEL:
        if not isinstance(config.get(key), dict) or not config[key]:
            raise ConfigError(f"{key} must be a non-empty mapping")

    _validate_libvirt(config["libvirt"])
    _validate_machines(config["machines"])
    _validate_schedulers(config["schedulers"])


def parse_cpu_list(value: str) -> list[int]:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError("CPU list must be a non-empty string")
    cpus: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            raise ConfigError(f"invalid CPU list: {value}")
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            if not start_text.isdigit() or not end_text.isdigit():
                raise ConfigError(f"invalid CPU range: {part}")
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ConfigError(f"invalid descending CPU range: {part}")
            cpus.update(range(start, end + 1))
        elif part.isdigit():
            cpus.add(int(part))
        else:
            raise ConfigError(f"invalid CPU id: {part}")
    return sorted(cpus)


def parse_memory_mib(value: str | int) -> int:
    if isinstance(value, int):
        if value <= 0:
            raise ConfigError("memory must be positive")
        return value
    if not isinstance(value, str):
        raise ConfigError("memory must be an integer MiB value or a string such as 3G")
    match = re.fullmatch(r"\s*(\d+)\s*([KkMmGgTt]?)\s*", value)
    if not match:
        raise ConfigError(f"invalid memory value: {value}")
    number = int(match.group(1))
    unit = match.group(2).upper() or "M"
    mib = int(number * {"K": 1 / 1024, "M": 1, "G": 1024, "T": 1024 * 1024}[unit])
    if mib <= 0:
        raise ConfigError("memory must be positive")
    return mib


def _normalize_host_paths(config: dict[str, Any], root: Path) -> None:
    libvirt = config.get("libvirt", {})
    for key in ("template_image", "runtime_dir", "ssh_key"):
        value = libvirt.get(key)
        if isinstance(value, str) and value:
            libvirt[key] = str(_resolve_host_path(value, root))
    for scheduler in config.get("schedulers", {}).values():
        if not isinstance(scheduler, dict):
            continue
        for field in ("files", "secret_files"):
            for payload in scheduler.get(field, []) or []:
                if isinstance(payload, dict) and isinstance(payload.get("source"), str):
                    payload["source"] = str(_resolve_host_path(payload["source"], root))


def _resolve_host_path(value: str, root: Path) -> Path:
    path = Path(value).expanduser()
    return (path if path.is_absolute() else root / path).resolve()


def _validate_libvirt(libvirt: dict[str, Any]) -> None:
    required = (
        "uri", "template_image", "runtime_dir", "ssh_user", "ssh_key", "guest_output_dir",
    )
    for key in required:
        if not isinstance(libvirt.get(key), str) or not libvirt[key]:
            raise ConfigError(f"libvirt.{key} must be a non-empty string")
    for key in ("network", "cpu_mode"):
        if key in libvirt and not isinstance(libvirt[key], str):
            raise ConfigError(f"libvirt.{key} must be a string")
    required_cpu_features = libvirt.get("required_cpu_features", [])
    if (
        not isinstance(required_cpu_features, list)
        or not all(
            isinstance(feature, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", feature)
            for feature in required_cpu_features
        )
        or len(set(required_cpu_features)) != len(required_cpu_features)
    ):
        raise ConfigError(
            "libvirt.required_cpu_features must be a list of unique CPU feature names"
        )
    for key in ("vm_warmup_seconds", "boot_timeout_seconds"):
        value = libvirt.get(key, 0)
        if not isinstance(value, int) or value < 0:
            raise ConfigError(f"libvirt.{key} must be a non-negative integer")
    if int(libvirt.get("boot_timeout_seconds", 0)) < 1:
        raise ConfigError("libvirt.boot_timeout_seconds must be at least 1")


def _validate_machines(machines: dict[str, Any]) -> None:
    for name, machine in machines.items():
        if not isinstance(machine, dict):
            raise ConfigError(f"machines.{name} must be a mapping")
        allowed = {
            "vcpus",
            "memory",
            "pin_cpus",
            "emulator_cpus",
            "topology",
            "frequency",
        }
        unknown = sorted(set(machine) - allowed)
        if unknown:
            raise ConfigError(f"machines.{name} contains unknown fields: {unknown}")
        vcpus = machine.get("vcpus")
        if not isinstance(vcpus, int) or vcpus < 1:
            raise ConfigError(f"machines.{name}.vcpus must be a positive integer")
        parse_memory_mib(machine.get("memory"))
        cpus = parse_cpu_list(machine.get("pin_cpus"))
        if len(cpus) != vcpus:
            raise ConfigError(f"machines.{name}.pin_cpus must contain exactly {vcpus} CPUs")
        emulator_cpus = parse_cpu_list(machine.get("emulator_cpus"))
        overlap = sorted(set(cpus) & set(emulator_cpus))
        if overlap:
            raise ConfigError(
                f"machines.{name} vCPU and emulator CPU sets overlap: {overlap}"
            )

        topology = machine.get("topology")
        topology_keys = {"sockets", "cores", "threads"}
        if not isinstance(topology, dict) or set(topology) != topology_keys:
            raise ConfigError(
                f"machines.{name}.topology must contain exactly {sorted(topology_keys)}"
            )
        if any(
            not isinstance(topology[key], int) or topology[key] < 1
            for key in topology_keys
        ):
            raise ConfigError(f"machines.{name}.topology values must be positive integers")
        topology_vcpus = topology["sockets"] * topology["cores"] * topology["threads"]
        if topology_vcpus != vcpus:
            raise ConfigError(
                f"machines.{name}.topology describes {topology_vcpus} vCPUs, expected {vcpus}"
            )

        frequency = machine.get("frequency")
        if not isinstance(frequency, dict) or set(frequency) != {"governor", "khz"}:
            raise ConfigError(
                f"machines.{name}.frequency must contain exactly governor and khz"
            )
        if not isinstance(frequency["governor"], str) or not frequency["governor"]:
            raise ConfigError(f"machines.{name}.frequency.governor must be a string")
        if not isinstance(frequency["khz"], int) or frequency["khz"] < 1:
            raise ConfigError(f"machines.{name}.frequency.khz must be a positive integer")


def _validate_schedulers(schedulers: dict[str, Any]) -> None:
    for name, scheduler in schedulers.items():
        if not isinstance(scheduler, dict):
            raise ConfigError(f"schedulers.{name} must be a mapping")
        kind = scheduler.get("kind")
        if kind not in VALID_SCHEDULER_KINDS:
            raise ConfigError(f"schedulers.{name}.kind must be one of {sorted(VALID_SCHEDULER_KINDS)}")
        if kind != "builtin":
            command = scheduler.get("command")
            if not isinstance(command, str) or not command:
                raise ConfigError(f"schedulers.{name}.command must be a non-empty string")
        args = scheduler.get("args", [])
        if not isinstance(args, list) or not all(isinstance(value, str) for value in args):
            raise ConfigError(f"schedulers.{name}.args must be a list of strings")
        warmup = scheduler.get("warmup_seconds", 0)
        if not isinstance(warmup, int) or warmup < 0:
            raise ConfigError(f"schedulers.{name}.warmup_seconds must be a non-negative integer")
        startup_timeout = scheduler.get("startup_timeout_seconds", 30)
        if not isinstance(startup_timeout, int) or startup_timeout < 1:
            raise ConfigError(
                f"schedulers.{name}.startup_timeout_seconds must be a positive integer"
            )
        stop_timeout = scheduler.get("stop_timeout_seconds", 5)
        if not isinstance(stop_timeout, int) or stop_timeout < 1:
            raise ConfigError(f"schedulers.{name}.stop_timeout_seconds must be a positive integer")
        timeout_extra = scheduler.get("timeout_extra_seconds", 0)
        if not isinstance(timeout_extra, int) or timeout_extra < 0:
            raise ConfigError(f"schedulers.{name}.timeout_extra_seconds must be a non-negative integer")
        signal = scheduler.get("stop_signal", "TERM")
        if signal not in VALID_STOP_SIGNALS:
            raise ConfigError(f"schedulers.{name}.stop_signal must be one of {sorted(VALID_STOP_SIGNALS)}")
        if kind != "builtin":
            expected_ops = scheduler.get("expected_ops")
            if not isinstance(expected_ops, str) or not expected_ops:
                raise ConfigError(f"schedulers.{name}.expected_ops must be a non-empty string")
        if kind == "agent":
            tool_socket = scheduler.get("tool_socket")
            if not isinstance(tool_socket, str) or not tool_socket.startswith("/"):
                raise ConfigError(f"schedulers.{name}.tool_socket must be an absolute path")
        env = scheduler.get("env", {})
        if not isinstance(env, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in env.items()):
            raise ConfigError(f"schedulers.{name}.env must be a mapping of strings")
        _validate_files(scheduler.get("files", []), f"schedulers.{name}.files")
        _validate_secret_files(scheduler.get("secret_files", []), f"schedulers.{name}.secret_files")
        require_process_llm = scheduler.get("require_process_llm", False)
        if not isinstance(require_process_llm, bool):
            raise ConfigError(f"schedulers.{name}.require_process_llm must be a boolean")
        if require_process_llm:
            if kind != "agent":
                raise ConfigError(f"schedulers.{name}.require_process_llm requires kind=agent")
            if "--offline" in args:
                raise ConfigError(f"schedulers.{name} cannot require process LLM with --offline")
            if not scheduler.get("secret_files"):
                raise ConfigError(f"schedulers.{name}.require_process_llm needs secret_files")
        require_thread_llm = scheduler.get("require_thread_llm", False)
        if not isinstance(require_thread_llm, bool):
            raise ConfigError(f"schedulers.{name}.require_thread_llm must be a boolean")
        if require_thread_llm:
            if kind != "agent":
                raise ConfigError(f"schedulers.{name}.require_thread_llm requires kind=agent")
            if "--offline" in args:
                raise ConfigError(f"schedulers.{name} cannot require thread LLM with --offline")
            if not scheduler.get("secret_files"):
                raise ConfigError(f"schedulers.{name}.require_thread_llm needs secret_files")


def _validate_files(files: Any, label: str) -> None:
    if not isinstance(files, list):
        raise ConfigError(f"{label} must be a list")
    for item in files:
        if not isinstance(item, dict):
            raise ConfigError(f"{label} entries must be mappings")
        if not isinstance(item.get("source"), str) or not item["source"]:
            raise ConfigError(f"{label} entries need a source string")
        target = item.get("target")
        if not isinstance(target, str) or not target.startswith("/"):
            raise ConfigError(f"{label} target must be an absolute Guest path")
        if not isinstance(item.get("executable", False), bool):
            raise ConfigError(f"{label}.executable must be a boolean")


def _validate_secret_files(files: Any, label: str) -> None:
    if not isinstance(files, list):
        raise ConfigError(f"{label} must be a list")
    for item in files:
        if not isinstance(item, dict):
            raise ConfigError(f"{label} entries must be mappings")
        if not isinstance(item.get("source"), str) or not item["source"]:
            raise ConfigError(f"{label} entries need a source string")
        target = item.get("target")
        if not isinstance(target, str) or not target.startswith("/"):
            raise ConfigError(f"{label} target must be an absolute Guest path")
        required_env = item.get("required_env")
        if not isinstance(required_env, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", required_env):
            raise ConfigError(f"{label}.required_env must be a valid environment variable name")
