from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True

TEST_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = REPO_ROOT / "test" / "config.yaml"
if str(TEST_ROOT) not in sys.path:
    sys.path.insert(0, str(TEST_ROOT))

from test_core.benchmark.config import build_spec, load_performance
from test_core.config.parser import ConfigError, load_config
from test_core.host.check import check_host


def main() -> int:
    try:
        config = load_config(CONFIG_PATH, base_dir=REPO_ROOT)
        performance = load_performance(config)
    except (ConfigError, OSError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    failures: set[str] = set()
    infos: set[str] = set()
    for variant in ("native", "agent"):
        spec = build_spec(
            config,
            performance,
            scenario="latency",
            variant=variant,
            repeat=1,
        )
        result = check_host(spec)
        failures.update(result.failures)
        infos.update(result.infos)

    print("profile: formal")
    _print_group("INFO", tuple(sorted(infos)))
    _print_group("FAILURE", tuple(sorted(failures)))

    if failures:
        print("environment check failed")
        return 1
    print("environment check passed")
    return 0


def _print_group(title: str, items: tuple[str, ...]) -> None:
    if not items:
        return
    print(f"\n{title}:")
    for item in items:
        print(f"  - {item}")


if __name__ == "__main__":
    raise SystemExit(main())
