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
import json
import os
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET_DIR = REPO_ROOT / "datasets" / "galileo"
DEFAULT_PROMPT_FILE = REPO_ROOT / "prompts" / "galileo" / "defenseclaw-runtime-governance.md"
DEFAULT_PROMPT_NAME = "defenseclaw-runtime-governance"


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: row must be a JSON object")
            rows.append(row)
    if not rows:
        raise ValueError(f"{path}: no rows found")
    return rows


def _dataset_name(path: Path, prefix: str) -> str:
    stem = path.stem.replace("_", "-")
    return f"{prefix}{stem}"


def _load_galileo():
    try:
        from galileo.datasets import create_dataset, get_dataset
        from galileo.prompts import create_prompt, get_prompt
    except ImportError as exc:
        raise SystemExit(
            "Galileo SDK is not installed. Install it in a temporary venv with "
            "`python3 -m pip install galileo` and rerun this script."
        ) from exc
    return create_dataset, get_dataset, create_prompt, get_prompt


def _create_prompt_version(template_id: str, template: str) -> tuple[str | None, int | None]:
    from galileo.config import GalileoPythonConfig
    from galileo.resources.api.prompts import (
        create_global_prompt_template_version_templates_template_id_versions_post,
        set_selected_global_template_version_templates_template_id_versions_version_put,
    )
    from galileo.resources.models import BasePromptTemplateVersion, HTTPValidationError

    config = GalileoPythonConfig.get()
    body = BasePromptTemplateVersion(template=template)
    response = create_global_prompt_template_version_templates_template_id_versions_post.sync(
        template_id=template_id,
        client=config.api_client,
        body=body,
    )
    if response is None or isinstance(response, HTTPValidationError):
        raise RuntimeError(f"failed to create prompt version for {template_id}")
    set_selected_global_template_version_templates_template_id_versions_version_put.sync(
        template_id=template_id,
        version=response.version,
        client=config.api_client,
    )
    return response.id, response.version


def _project_kwargs(project_id: str | None, project_name: str | None) -> dict[str, str]:
    if project_id:
        return {"project_id": project_id}
    if project_name:
        return {"project_name": project_name}
    return {}


def _get_existing(get_dataset, name: str, project_kwargs: dict[str, str]):
    try:
        return get_dataset(name=name, **project_kwargs)
    except Exception:
        return None


def upload_datasets(
    dataset_dir: Path,
    prefix: str,
    skip_existing: bool,
    project_id: str | None,
    project_name: str | None,
) -> list[dict[str, Any]]:
    if not os.environ.get("GALILEO_API_KEY"):
        raise SystemExit("GALILEO_API_KEY is required")

    create_dataset, get_dataset, _, _ = _load_galileo()
    project_kwargs = _project_kwargs(project_id, project_name)
    paths = sorted(dataset_dir.glob("*.jsonl"))
    if not paths:
        raise SystemExit(f"No JSONL datasets found in {dataset_dir}")

    results: list[dict[str, Any]] = []
    for path in paths:
        name = _dataset_name(path, prefix)
        rows = _load_jsonl(path)
        existing = _get_existing(get_dataset, name, project_kwargs)
        if existing is not None and skip_existing:
            results.append(
                {
                    "name": name,
                    "source": str(path.relative_to(REPO_ROOT)),
                    "rows": len(rows),
                    "status": "exists",
                    "id": getattr(existing, "id", None),
                }
            )
            continue

        dataset = create_dataset(name=name, content=rows, **project_kwargs)
        results.append(
            {
                "name": name,
                "source": str(path.relative_to(REPO_ROOT)),
                "rows": len(rows),
                "status": "created",
                "id": getattr(dataset, "id", None),
            }
        )
    return results


def upload_prompt(
    prompt_file: Path,
    prompt_name: str,
    skip_existing: bool,
    project_id: str | None,
    project_name: str | None,
) -> dict[str, Any]:
    if not os.environ.get("GALILEO_API_KEY"):
        raise SystemExit("GALILEO_API_KEY is required")
    _, _, create_prompt, get_prompt = _load_galileo()
    project_kwargs = _project_kwargs(project_id, project_name)
    template = prompt_file.read_text(encoding="utf-8")
    existing = _get_existing(get_prompt, prompt_name, project_kwargs)
    if existing is not None and skip_existing:
        if getattr(existing, "template", None) != template:
            version_id, version = _create_prompt_version(existing.id, template)
            return {
                "name": prompt_name,
                "source": str(prompt_file.relative_to(REPO_ROOT)),
                "status": "updated",
                "id": getattr(existing, "id", None),
                "version": version,
                "version_id": version_id,
            }
        return {
            "name": prompt_name,
            "source": str(prompt_file.relative_to(REPO_ROOT)),
            "status": "exists",
            "id": getattr(existing, "id", None),
        }
    prompt = create_prompt(name=prompt_name, template=template, **project_kwargs)
    return {
        "name": prompt_name,
        "source": str(prompt_file.relative_to(REPO_ROOT)),
        "status": "created",
        "id": getattr(prompt, "id", None),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Upload DefenseClaw demo datasets and prompt to Galileo.")
    parser.add_argument("--dataset-dir", type=Path, default=DEFAULT_DATASET_DIR)
    parser.add_argument("--prefix", default="", help="Optional dataset name prefix.")
    parser.add_argument("--prompt-file", type=Path, default=DEFAULT_PROMPT_FILE)
    parser.add_argument("--prompt-name", default=DEFAULT_PROMPT_NAME)
    parser.add_argument("--skip-prompt", action="store_true")
    parser.add_argument("--project-id", default=os.environ.get("GALILEO_PROJECT_ID"))
    parser.add_argument("--project-name", default=os.environ.get("GALILEO_PROJECT"))
    parser.add_argument(
        "--create-duplicates",
        action="store_true",
        help="Create a new dataset even when a dataset with the same name already exists.",
    )
    args = parser.parse_args(argv)

    datasets = upload_datasets(
        args.dataset_dir,
        args.prefix,
        skip_existing=not args.create_duplicates,
        project_id=args.project_id,
        project_name=args.project_name,
    )
    payload: dict[str, Any] = {"datasets": datasets}
    if not args.skip_prompt:
        payload["prompt"] = upload_prompt(
            args.prompt_file,
            args.prompt_name,
            skip_existing=not args.create_duplicates,
            project_id=args.project_id,
            project_name=args.project_name,
        )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
