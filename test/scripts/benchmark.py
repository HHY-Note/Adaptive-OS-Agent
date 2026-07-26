from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

TEST_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = TEST_ROOT / "config.yaml"
OUTPUT_ROOT = TEST_ROOT / "output" / "performance"
if str(TEST_ROOT) not in sys.path:
    sys.path.insert(0, str(TEST_ROOT))

from test_core.benchmark.analysis import analyze_campaign, analyze_run
from test_core.benchmark.config import (
    SCENARIOS,
    VARIANTS,
    build_spec,
    campaign_schedule,
    load_performance,
)
from test_core.config.parser import ConfigError, load_config
from test_core.host.check import check_host
from test_core.models import CheckResult
from test_core.vm.runner import run_one


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.analyze_only and args.single_round:
        parser.error("--single-round cannot be combined with --analyze-only")
    if args.analyze_only and args.scenario != "all":
        parser.error("a scenario cannot be combined with --analyze-only")
    try:
        config = load_config(CONFIG_PATH, base_dir=REPO_ROOT)
        performance = load_performance(config)
    except (ConfigError, OSError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    if args.analyze_only:
        if not args.analyze_only.is_dir():
            print(f"campaign directory does not exist: {args.analyze_only}", file=sys.stderr)
            return 2
        comparison = analyze_campaign(
            args.analyze_only,
            bootstrap_samples=int(performance["bootstrap_samples"]),
            seed=int(performance["seed"]),
        )
        print(f"report: {Path(args.analyze_only) / 'report.md'}")
        return 0 if comparison["runs"] > 0 and comparison["invalid_runs"] == 0 else 1

    profile = "single-round" if args.single_round else "formal"
    repeats = 1 if args.single_round else int(performance["repeats"])
    scenarios = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    try:
        schedule = campaign_schedule(
            scenarios,
            list(VARIANTS),
            repeats,
            int(performance["seed"]),
        )
        specs = [
            build_spec(
                config,
                performance,
                scenario=scenario,
                variant=variant,
                repeat=repeat,
                profile=profile,
            )
            for repeat, scenario, variant in schedule
        ]
        if args.template_image is not None:
            template_image = str(args.template_image.expanduser().resolve())
            for spec in specs:
                spec.libvirt["template_image"] = template_image
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    _print_schedule(profile, specs)
    if args.dry_run:
        return 0
    if _build_release() != 0:
        return 1
    preflight = _preflight(specs)
    if not preflight.ok:
        return 1

    campaign_dir = args.output or _default_output()
    try:
        campaign_dir.mkdir(parents=True, exist_ok=False)
        (campaign_dir / "runs").mkdir()
    except FileExistsError:
        print(f"output already exists: {campaign_dir}", file=sys.stderr)
        return 2
    manifest = _manifest(config, performance, profile, specs)
    _write_json(campaign_dir / "campaign.json", manifest)
    _write_json(
        campaign_dir / "preflight.json",
        {
            "schema_version": 1,
            "checked_at": _now(),
            "profile": profile,
            "failures": list(preflight.failures),
            "infos": list(preflight.infos),
        },
    )

    all_valid = True
    for index, spec in enumerate(specs, start=1):
        run_dir = campaign_dir / "runs" / (
            f"{index:03d}__r{spec.benchmark['repeat']:02d}__"
            f"{spec.benchmark['scenario']}__{spec.benchmark['variant']}"
        )
        print(f"[{index}/{len(specs)}] {spec.case_name}", flush=True)
        result = run_one(spec, output_dir=run_dir)
        summary = analyze_run(run_dir)
        valid = result.get("status") == "PASS" and summary["valid"]
        all_valid = all_valid and valid
        print(f"  status={result.get('status')} analysis_valid={summary['valid']}")

    comparison = analyze_campaign(
        campaign_dir,
        bootstrap_samples=int(performance["bootstrap_samples"]),
        seed=int(performance["seed"]),
    )
    manifest.update(
        {
            "finished_at": _now(),
            "valid_runs": comparison["valid_runs"],
            "invalid_runs": comparison["invalid_runs"],
        }
    )
    _write_json(campaign_dir / "campaign.json", manifest)
    print(f"report: {campaign_dir / 'report.md'}")
    return 0 if all_valid and comparison["valid_runs"] == len(specs) else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="运行 latency、throughput、balanced、mix 的 Native/Agent 配对性能实验"
    )
    parser.add_argument(
        "scenario",
        nargs="?",
        choices=(*SCENARIOS, "all"),
        default="all",
        help="只运行一种镜像内真实应用负载；默认 all",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--template-image",
        type=Path,
        help="override the configured VM image for this controlled campaign",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--analyze-only", type=Path)
    parser.add_argument(
        "--single-round",
        action="store_true",
        help="run one latency/throughput/balanced/mix Native/Agent iteration round",
    )
    return parser


def _build_release() -> int:
    projects = (REPO_ROOT / "scheduler" / "rust", REPO_ROOT / "Adaptive-OS-Agent")
    for project in projects:
        print(f"build: {project.relative_to(REPO_ROOT)}", flush=True)
        completed = subprocess.run(
            ["cargo", "build", "--release", "--locked"], cwd=project, check=False
        )
        if completed.returncode != 0:
            return completed.returncode
    return 0


def _preflight(specs: list[Any]) -> CheckResult:
    failures: set[str] = set()
    infos: set[str] = set()
    checked: set[str] = set()
    for spec in specs:
        if spec.scheduler_name in checked:
            continue
        checked.add(spec.scheduler_name)
        result = check_host(spec)
        failures.update(result.failures)
        infos.update(result.infos)
    for info in sorted(infos):
        print(f"info: {info}")
    for failure in sorted(failures):
        print(f"failure: {failure}", file=sys.stderr)
    return CheckResult(tuple(sorted(failures)), tuple(sorted(infos)))


def _manifest(
    config: dict[str, Any],
    performance: dict[str, Any],
    profile: str,
    specs: list[Any],
) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "created_at": _now(),
        "config_path": config["__config_path"],
        "machine": performance["machine"],
        "profile": profile,
        "template_image": specs[0].libvirt["template_image"] if specs else None,
        "variants": dict(performance["variants"]),
        "schedule": [
            {
                "sequence": index,
                "repeat": spec.benchmark["repeat"],
                "scenario": spec.benchmark["scenario"],
                "variant": spec.benchmark["variant"],
                "warmup_seconds": spec.benchmark["warmup_seconds"],
                "measurement_seconds": spec.benchmark["measurement_seconds"],
            }
            for index, spec in enumerate(specs, start=1)
        ],
    }


def _print_schedule(profile: str, specs: list[Any]) -> None:
    print(f"profile: {profile}")
    print(f"runs: {len(specs)}")
    if specs:
        print(f"template_image: {specs[0].libvirt['template_image']}")
    for index, spec in enumerate(specs, start=1):
        print(
            f"  {index:03d} repeat={spec.benchmark['repeat']} "
            f"scenario={spec.benchmark['scenario']} variant={spec.benchmark['variant']} "
            f"warmup={spec.benchmark['warmup_seconds']}s "
            f"measurement={spec.benchmark['measurement_seconds']}s"
        )


def _default_output() -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    return OUTPUT_ROOT / stamp


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
