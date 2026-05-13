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


def _load_manifest(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    if not isinstance(manifest.get("datasets"), list):
        raise ValueError(f"{path}: datasets must be a list")
    return manifest


def _select_datasets(manifest: dict[str, Any], names: list[str], include_all: bool) -> list[dict[str, Any]]:
    datasets = [item for item in manifest["datasets"] if isinstance(item, dict)]
    if include_all:
        return datasets
    wanted = set(names)
    if not wanted:
        return [item for item in datasets if item.get("name") == "defenseclaw-safe-ops"]
    selected = [item for item in datasets if item.get("name") in wanted]
    missing = sorted(wanted - {str(item.get("name")) for item in selected})
    if missing:
        raise ValueError(f"unknown dataset(s): {', '.join(missing)}")
    return selected


def _experiment_name(prefix: str, dataset_name: str) -> str:
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{dataset_name}-{stamp}"


def _plan(manifest: dict[str, Any], selected: list[dict[str, Any]], model_alias: str) -> dict[str, Any]:
    return {
        "project_id": manifest["project"]["id"],
        "prompt": manifest["prompt"]["name"],
        "prompt_id": manifest["prompt"]["id"],
        "model_alias": model_alias,
        "datasets": [
            {
                "name": item["name"],
                "id": item["id"],
                "rows": item["rows"],
                "metrics": item["default_metrics"],
            }
            for item in selected
        ],
    }


def _run_experiment(
    manifest: dict[str, Any],
    dataset_cfg: dict[str, Any],
    model_alias: str,
    experiment_prefix: str,
) -> dict[str, Any]:
    from galileo.datasets import get_dataset
    from galileo.experiments import run_experiment
    from galileo.prompts import get_prompt

    project_id = manifest["project"]["id"]
    prompt = get_prompt(id=manifest["prompt"]["id"])
    dataset = get_dataset(id=dataset_cfg["id"])
    if prompt is None:
        raise RuntimeError(f"prompt not found: {manifest['prompt']['id']}")
    if dataset is None:
        raise RuntimeError(f"dataset not found: {dataset_cfg['id']}")

    settings = dict(manifest["model"]["settings"])
    settings["model_alias"] = model_alias
    result = run_experiment(
        _experiment_name(experiment_prefix, dataset_cfg["name"]),
        dataset=dataset,
        prompt_template=prompt,
        prompt_settings=settings,
        metrics=dataset_cfg["default_metrics"],
        project_id=project_id,
        experiment_tags={
            "demo": "defenseclaw-runtime-governance",
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
    parser = argparse.ArgumentParser(description="Run the DefenseClaw Galileo playground recipe as experiments.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--dataset", action="append", default=[], help="Dataset name. Repeat for multiple datasets.")
    parser.add_argument("--all", action="store_true", help="Run every dataset in the playground recipe.")
    parser.add_argument("--model-alias", default=None)
    parser.add_argument("--experiment-prefix", default="defenseclaw-playground")
    parser.add_argument("--execute", action="store_true", help="Actually start Galileo experiments. Defaults to dry-run.")
    args = parser.parse_args()

    manifest = _load_manifest(args.manifest)
    model_alias = args.model_alias or manifest["model"]["default_alias"]
    selected = _select_datasets(manifest, args.dataset, args.all)
    plan = _plan(manifest, selected, model_alias)
    if not args.execute:
        print(json.dumps({"dry_run": True, "plan": plan}, indent=2, sort_keys=True))
        return 0

    if not os.environ.get("GALILEO_API_KEY"):
        raise SystemExit("GALILEO_API_KEY is required when --execute is set")

    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for dataset_cfg in selected:
        try:
            results.append(_run_experiment(manifest, dataset_cfg, model_alias, args.experiment_prefix))
        except Exception as exc:
            errors.append(
                {
                    "dataset": str(dataset_cfg["name"]),
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }
            )
    payload: dict[str, Any] = {"dry_run": False, "plan": plan, "experiments": results}
    if errors:
        payload["errors"] = errors
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
