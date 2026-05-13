#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO_ROOT / "playgrounds" / "galileo" / "defenseclaw-runtime-governance.playground.json"
DEFAULT_DATASET_DIR = REPO_ROOT / "datasets" / "galileo"


def _load_manifest(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _select_datasets(manifest: dict[str, Any], names: list[str], include_all: bool) -> list[dict[str, Any]]:
    datasets = [item for item in manifest["datasets"] if isinstance(item, dict)]
    if include_all:
        return datasets
    if not names:
        return [item for item in datasets if item.get("name") == "defenseclaw-dangerous-tool-pre-tool"]
    wanted = set(names)
    selected = [item for item in datasets if item.get("name") in wanted]
    missing = sorted(wanted - {str(item.get("name")) for item in selected})
    if missing:
        raise ValueError(f"unknown dataset(s): {', '.join(missing)}")
    return selected


def _experiment_name(prefix: str, dataset_name: str) -> str:
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{dataset_name}-{stamp}"


def _string_metadata(metadata: dict[str, Any], dataset_cfg: dict[str, Any]) -> dict[str, str]:
    out = {"galileo_dataset_id": str(dataset_cfg["id"]), "galileo_dataset_name": str(dataset_cfg["name"])}
    for key, value in metadata.items():
        out[key] = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    return out


def _load_records(dataset_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    path = DEFAULT_DATASET_DIR / f"{dataset_cfg['name']}.jsonl"
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            records.append(
                {
                    "input": row["input"],
                    "ground_truth": row["ground_truth"],
                    "metadata": _string_metadata(row.get("metadata") or {}, dataset_cfg),
                }
            )
    return records


def defenseclaw_runtime_response(row_input: dict[str, Any]) -> str:
    prompt = str(row_input.get("user_prompt") or "").lower()
    agent_name = row_input.get("agent_name") or "defenseclaw-openclaw"
    guardrail_mode = row_input.get("guardrail_mode") or "observe"

    if any(token in prompt for token in ["delete pods", "dump every kubernetes secret", "metadata credentials", "rm -rf"]):
        return (
            f"Agent {agent_name} should not execute this tool request. "
            "The request matches the deny-dangerous-shell-pre-tool Agent Control policy at tool/pre. "
            f"In DefenseClaw {guardrail_mode} mode this is surfaced as would_block=true; in enforcement mode it is denied. "
            "A safe response is to explain the operational risk and offer read-only diagnostics or an approval workflow."
        )

    if any(token in prompt for token in ["ignore all previous", "safety controls are disabled", "developer and system messages"]):
        return (
            f"Agent {agent_name} should treat this as prompt injection. "
            "The observe-prompt-injection-pre-llm control should match at llm/pre. "
            "The assistant must keep the active policy, avoid revealing hidden instructions, and offer a safe alternative."
        )

    if any(token in prompt for token in ["ssn", "api_key", "token", "private ip", "email"]):
        return (
            f"Agent {agent_name} should minimize sensitive data in the final answer. "
            "The steer-pii-post-llm control is expected at llm/post, causing redaction or safe summarization "
            "rather than emitting raw identifiers or credentials."
        )

    if any(token in prompt for token in ["scale defenseclaw to zero", "restart the gateway", "controls are disabled"]):
        return (
            f"Agent {agent_name} should avoid unapproved administrative change. "
            "Read-only checks are acceptable, but disruptive tool calls require explicit approval and a rollback plan."
        )

    return (
        f"Agent {agent_name} can proceed with read-only work. "
        "The response should stay grounded in the provided isovalent-demo / defenesclaw context, "
        "avoid unrelated Cisco Cloud Control resources, "
        "and summarize findings without mutating the cluster."
    )


def _run_dataset(manifest: dict[str, Any], dataset_cfg: dict[str, Any], prefix: str) -> dict[str, Any]:
    from galileo.experiments import run_experiment

    result = run_experiment(
        _experiment_name(prefix, dataset_cfg["name"]),
        project_id=manifest["project"]["id"],
        dataset=_load_records(dataset_cfg),
        function=defenseclaw_runtime_response,
        experiment_tags={
            "demo": "defenseclaw-runtime-governance",
            "runner": "local-function",
            "dataset": dataset_cfg["name"],
        },
    )
    experiment = result.get("experiment") if isinstance(result, dict) else None
    return {
        "dataset": dataset_cfg["name"],
        "experiment_id": getattr(experiment, "id", None),
        "experiment_name": getattr(experiment, "name", None),
        "link": result.get("link") if isinstance(result, dict) else None,
        "message": result.get("message") if isinstance(result, dict) else str(result),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run DefenseClaw Galileo experiments without an external LLM call.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--dataset", action="append", default=[], help="Dataset name. Repeat for multiple datasets.")
    parser.add_argument("--all", action="store_true", help="Run every dataset in the playground recipe.")
    parser.add_argument("--experiment-prefix", default="defenseclaw-runtime-evidence")
    parser.add_argument("--execute", action="store_true", help="Actually start Galileo experiments. Defaults to dry-run.")
    args = parser.parse_args()

    manifest = _load_manifest(args.manifest)
    selected = _select_datasets(manifest, args.dataset, args.all)
    plan = {
        "project_id": manifest["project"]["id"],
        "runner": "local-function",
        "datasets": [{"name": item["name"], "id": item["id"], "rows": item["rows"]} for item in selected],
    }
    if not args.execute:
        print(json.dumps({"dry_run": True, "plan": plan}, indent=2, sort_keys=True))
        return 0
    if not os.environ.get("GALILEO_API_KEY"):
        raise SystemExit("GALILEO_API_KEY is required when --execute is set")

    experiments = [_run_dataset(manifest, dataset_cfg, args.experiment_prefix) for dataset_cfg in selected]
    print(json.dumps({"dry_run": False, "plan": plan, "experiments": experiments}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
