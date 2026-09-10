#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize synthetic Hugging Face red-team trajectories with real arguments.

The source is generated, authorized red-team material. It is useful for
deterministic grammar and bounded-chain coverage discovery, but not for
population FPR or unauthorized-intent claims. Only tool names and decoded JSON
arguments are retained; prompts, reasoning, and generated outputs are excluded.
Synthetic credential literals already present in tool arguments remain part of
the grammar. Outcomes remain unknown because source verification is not an
environment-execution attestation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,159}$")
MAX_ARGUMENT_BYTES = 65_536
MAX_EVENTS = 64


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=Path("benchmarks/schema/case-v1.schema.json"))
    return parser.parse_args()


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def generated_payload(source_messages: object) -> dict[str, Any] | None:
    if not isinstance(source_messages, list):
        return None
    completions = [
        message.get("content")
        for message in source_messages
        if isinstance(message, dict)
        and message.get("role") == "assistant"
        and isinstance(message.get("content"), str)
    ]
    if not completions:
        return None
    content = completions[-1]
    marker = content.find("</think>")
    if marker >= 0:
        content = content[marker + len("</think>") :]
    start = content.find("{")
    if start < 0:
        return None
    try:
        value, end = json.JSONDecoder().raw_decode(content[start:])
    except json.JSONDecodeError:
        return None
    if content[start + end :].strip() or not isinstance(value, dict):
        return None
    return value


def trajectory_events(payload: dict[str, Any]) -> list[dict[str, Any]]:
    messages = payload.get("messages")
    if not isinstance(messages, list):
        return []
    responses = {
        message.get("tool_call_id"): message
        for message in messages
        if isinstance(message, dict)
        and message.get("role") == "tool"
        and isinstance(message.get("tool_call_id"), str)
    }
    events: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for message in messages:
        if not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        calls = message.get("tool_calls")
        if calls is None:
            continue
        if not isinstance(calls, list):
            return []
        for call in calls:
            if not isinstance(call, dict):
                return []
            call_id = call.get("id")
            function = call.get("function")
            if (
                not isinstance(call_id, str)
                or not call_id
                or call_id in seen_ids
                or call_id not in responses
                or not isinstance(function, dict)
            ):
                return []
            name = function.get("name")
            arguments = function.get("arguments")
            if not isinstance(name, str) or not SAFE_TOOL.fullmatch(name):
                return []
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    return []
            if not isinstance(arguments, dict):
                return []
            if len(canonical_json(arguments).encode("utf-8")) > MAX_ARGUMENT_BYTES:
                return []
            response_name = responses[call_id].get("name")
            if response_name is not None and response_name != name:
                return []
            seen_ids.add(call_id)
            events.append(
                {
                    "tool_name": name,
                    "args": arguments,
                    "dialect": "none",
                    "outcome": "unknown",
                    "offset_seconds": len(events),
                }
            )
            if len(events) > MAX_EVENTS:
                return []
    return events if len(events) >= 2 else []


def normalize(lines: Iterable[str], revision: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    source_rows = 0
    for line in lines:
        source_rows += 1
        try:
            source = json.loads(line)
        except json.JSONDecodeError:
            skipped["invalid_source_json"] += 1
            continue
        if not isinstance(source, dict) or source.get("verified") is not True:
            skipped["not_source_verified"] += 1
            continue
        payload = generated_payload(source.get("messages"))
        if payload is None:
            skipped["invalid_generated_payload"] += 1
            continue
        events = trajectory_events(payload)
        if not events:
            skipped["invalid_tool_trajectory"] += 1
            continue
        sector = source.get("sector")
        if not isinstance(sector, str) or not sector.strip():
            skipped["missing_sector"] += 1
            continue
        source_identity = digest(canonical_json(source))
        sector = sector.strip()
        rows.append(
            {
                "schema_version": "1",
                "id": f"hf-agentic-red-team/{source_identity[:24]}",
                "source": {
                    "dataset": "hf-agentic-red-team",
                    "revision": revision,
                    "original_id": f"row:{source_identity[:24]}",
                    "license": "Apache-2.0",
                    "redistribution": "download-only",
                },
                "split": "development",
                "surface": "stateful",
                "payload": {"events": events},
                "truth": {
                    "source_truth": "malicious",
                    "deterministic_truth": "contextual_or_dual_use",
                    "label_confidence": "low",
                    "label_source": "source:synthetic_authorized_red_team",
                    "applicability": "in_scope",
                    "expected_disposition": "detect_only",
                    "categories": [
                        "synthetic_authorized_red_team",
                        "multi_tool_chain",
                        sector,
                    ],
                },
                "strata": {
                    "campaign": sector,
                    "domain": "structured_tool_call",
                    "hard_negative": False,
                    "split_group": digest(f"sector\x00{sector}")[:24],
                },
            }
        )
    rows.sort(key=lambda row: str(row["id"]))
    manifest = {
        "schema_version": "1",
        "source_id": "hf-agentic-red-team",
        "source_revision": revision,
        "source_license": "Apache-2.0",
        "source_rows": source_rows,
        "cases": len(rows),
        "row_count": len(rows),
        "event_count": sum(len(row["payload"]["events"]) for row in rows),
        "skipped": dict(sorted(skipped.items())),
        "normalization": (
            "source-verified generated trajectories; exact tool names and decoded JSON arguments only; "
            "reasoning, prompts, and tool outputs excluded; argument literals retained; "
            "outcomes set to unknown; "
            "sector-disjoint split groups"
        ),
        "label_limitation": (
            "All examples are synthetic authorized red-team scenarios. Use for grammar and bounded-chain "
            "coverage discovery only, not real-world execution, unauthorized-intent, or FPR claims."
        ),
    }
    return rows, manifest


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path) -> None:
    import jsonschema

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for row in rows:
        errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if errors:
            location = ".".join(str(part) for part in errors[0].absolute_path)
            raise ValueError(f"{row.get('id', '<unknown>')}:{location}: {errors[0].message}")


def main() -> int:
    args = parse_args()
    with args.input.open(encoding="utf-8") as handle:
        rows, manifest = normalize(handle, args.revision)
    validate_cases(rows, args.schema)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    output = "".join(canonical_json(row) + "\n" for row in rows)
    args.output.write_text(output, encoding="utf-8")
    manifest["output_sha256"] = hashlib.sha256(output.encode("utf-8")).hexdigest()
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
