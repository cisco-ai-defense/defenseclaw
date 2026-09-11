#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Project normalized stateful cases into an atomic-event benchmark lens."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

EVENT_PAYLOAD_FIELDS = (
    "tool_name",
    "command",
    "argv",
    "args",
    "dialect",
    "cwd",
    "active_home",
    "active_agent_files",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=Path("benchmarks/schema/case-v1.schema.json"))
    return parser.parse_args()


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def project(lines: Iterable[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    output: list[dict[str, Any]] = []
    source_cases = 0
    for line_number, line in enumerate(lines, 1):
        row = json.loads(line)
        source_cases += 1
        if row.get("surface") != "stateful":
            raise ValueError(f"line {line_number}: expected stateful surface")
        events = row.get("payload", {}).get("events")
        if not isinstance(events, list) or len(events) < 2:
            raise ValueError(f"line {line_number}: missing stateful events")
        trajectory_id = digest(str(row["id"]))[:24]
        for index, event in enumerate(events):
            if not isinstance(event, dict):
                raise ValueError(f"line {line_number}: event {index} is not an object")
            payload = {
                key: copy.deepcopy(event[key])
                for key in EVENT_PAYLOAD_FIELDS
                if key in event
            }
            truth = copy.deepcopy(row["truth"])
            categories = list(truth.get("categories", []))
            if "projected_atomic_event" not in categories:
                categories.append("projected_atomic_event")
            truth["categories"] = categories
            source = copy.deepcopy(row["source"])
            source["original_id"] = f"{source['original_id']}#event-{index + 1}"
            strata = copy.deepcopy(row.get("strata", {}))
            strata.update(
                {
                    "domain": "structured_tool_call_event",
                    "trajectory_id": trajectory_id,
                    "sequence_index": index,
                    "call_index": index,
                }
            )
            output.append(
                {
                    "schema_version": "1",
                    "id": f"{row['id']}/event-{index + 1:02d}",
                    "source": source,
                    "split": row["split"],
                    "surface": "action",
                    "payload": payload,
                    "truth": truth,
                    "strata": strata,
                }
            )
    manifest = {
        "schema_version": "1",
        "source_cases": source_cases,
        "row_count": len(output),
        "projection": "one action case per stateful event; outcomes and offsets excluded",
    }
    return output, manifest


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
        rows, manifest = project(handle)
    validate_cases(rows, args.schema)
    output = "".join(canonical_json(row) + "\n" for row in rows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output, encoding="utf-8")
    manifest["output_sha256"] = hashlib.sha256(output.encode("utf-8")).hexdigest()
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
