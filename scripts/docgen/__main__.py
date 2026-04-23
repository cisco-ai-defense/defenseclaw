# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Driver for the docs-site generator pipeline.

Run via:
  python -m scripts.docgen [--only NAME[,NAME,...]]

Or via make:
  make docs-gen
"""

from __future__ import annotations

import argparse
import sys
from typing import Callable, Dict, List, Tuple

from . import (
    api_routes,
    cli_go,
    cli_py,
    env_vars,
    exit_codes,
    make_targets,
    otel_spec,
    providers,
    rego_mod,
    rules,
    schemas,
)


GENERATORS: Dict[str, Callable[[], List[Tuple[str, bool]]]] = {
    "cli_py": cli_py.run,
    "cli_go": cli_go.run,
    "api_routes": api_routes.run,
    "make_targets": make_targets.run,
    "schemas": schemas.run,
    "env_vars": env_vars.run,
    "exit_codes": exit_codes.run,
    "providers": providers.run,
    "otel": otel_spec.run,
    "rules": rules.run,
    "rego": rego_mod.run,
}


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m scripts.docgen")
    p.add_argument("--only", help="Comma-separated generator names to run "
                                   f"(default: all). Available: {', '.join(GENERATORS)}")
    p.add_argument("--list", action="store_true", help="List generators and exit.")
    args = p.parse_args(argv)

    if args.list:
        for name in GENERATORS:
            print(name)
        return 0

    names = list(GENERATORS)
    if args.only:
        requested = [n.strip() for n in args.only.split(",") if n.strip()]
        unknown = [n for n in requested if n not in GENERATORS]
        if unknown:
            print(f"unknown generator(s): {unknown}", file=sys.stderr)
            return 2
        names = requested

    total_changed = 0
    total = 0
    for name in names:
        print(f"[{name}]")
        try:
            for path, changed in GENERATORS[name]():
                total += 1
                marker = "CHANGED " if changed else "ok      "
                total_changed += int(changed)
                print(f"  {marker}{path}")
        except Exception as e:
            print(f"  ERROR: {e}", file=sys.stderr)
            return 1
    print(f"\n{total_changed}/{total} file(s) updated across {len(names)} generator(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
