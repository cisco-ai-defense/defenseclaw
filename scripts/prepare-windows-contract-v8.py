#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Prepare the isolated Windows connector contract's exact-v8 config."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_CLI_ROOT = Path(__file__).resolve().parents[1] / "cli"
if str(_CLI_ROOT) not in sys.path:
    sys.path.insert(0, str(_CLI_ROOT))

from defenseclaw.observability.v8_config import load_validate_v8  # noqa: E402
from defenseclaw.observability.v8_writer import (  # noqa: E402
    V8CandidateValidator,
    mutate_v8_config,
)
from defenseclaw.observability.v8_yaml import V8YAMLMutation  # noqa: E402


def prepare_windows_contract_v8(
    config_path: Path,
    *,
    data_dir: Path,
    jsonl_path: Path,
    validator: V8CandidateValidator | None = None,
) -> None:
    """Add the contract-only JSONL destination.

    The contract owns a newly initialized disposable profile. Accept only an
    absent or exactly empty observability mapping, or the exact destination
    this helper already installed, so it can never replace an operator-authored
    destination graph.
    """

    destination = {
        "name": "windows-contract-jsonl",
        "kind": "jsonl",
        "path": str(jsonl_path),
    }
    validated = load_validate_v8(config_path.read_bytes(), source_name=str(config_path))
    observability = validated.source.get("observability")
    if observability == {"destinations": [destination]}:
        # Copilot and Antigravity use installer-shaped init again when the
        # contract changes from observe to action. Preserve the exact
        # destination this helper already installed without broadening the
        # accepted shape to an operator-authored observability graph.
        return
    if observability not in (None, {}):
        raise ValueError(
            "Windows contract requires an absent or empty fresh-v8 "
            "observability mapping, or the exact owned destination"
        )
    mutations = (V8YAMLMutation.set(("observability", "destinations", 0), destination),)
    if validator is None:
        mutate_v8_config(config_path, mutations, data_dir=str(data_dir))
    else:
        mutate_v8_config(
            config_path,
            mutations,
            data_dir=str(data_dir),
            validator=validator,
        )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--jsonl-path", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    prepare_windows_contract_v8(
        args.config,
        data_dir=args.data_dir,
        jsonl_path=args.jsonl_path,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
