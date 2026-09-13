#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize CrossMCP-Bench core scenarios without inventing execution evidence.

The source's ``expected_tools`` field is a canonical ordered list of tool names,
not an execution trace.  Its authorization context and expected policy are
scenario-level metadata.  This adapter therefore emits one case per scenario:

* every attack remains a complete stateful source-positive scenario;
* multi-tool benign scenarios become stateful benign hard negatives; and
* single-tool benign scenarios become atomic benign hard negatives.

No constituent attack call is emitted as atomic malicious.  The source contains
no call arguments, result status, timestamps, or per-call identities, so this
adapter does not manufacture them.  User instructions, descriptions, reasoning,
and other prose are excluded from normalized output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"
DATASET_ID = "MLZoo/CrossMCP-Bench"
SOURCE_URL = "https://huggingface.co/datasets/MLZoo/CrossMCP-Bench"
SOURCE_LICENSE = "CC-BY-4.0"
SOURCE_REDISTRIBUTION = "download-only"
MAX_SOURCE_LINE_BYTES = 1_048_576
MAX_TOOL_EVENTS = 64
MAX_CONTEXT_BYTES = 64 * 1024

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"

SOURCE_KEYS = frozenset(
    {
        "id",
        "is_attack",
        "attack_type",
        "sensitivity_label",
        "auth_context",
        "expected_policy",
        "expected_tools",
        "description",
        "user_instruction",
    }
)
AUTHORIZATION_KEYS = frozenset(
    {"approved_recipients", "approved_data_domains", "approved_sink_classes"}
)
AUTHORIZATION_LIST_LIMIT = 128
SAFE_SOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
SAFE_TOOL_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,159}$")
SAFE_CATEGORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$")
SAFE_POLICY = re.compile(r"^P[1-9][0-9]*_[A-Z][A-Z0-9_]{0,118}$")
SENSITIVITY_LABELS = frozenset({"public", "internal", "sensitive"})


class ProjectionError(ValueError):
    """An untrusted source row cannot be projected conservatively."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument(
        "--split", choices=("development", "validation", "test"), required=True
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    return parser.parse_args()


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProjectionError("duplicate_json_key")
        result[key] = value
    return result


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def required_text(value: object, code: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ProjectionError(code)
    return value.strip()


def parse_embedded_json(value: object, code: str) -> object:
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_CONTEXT_BYTES:
        raise ProjectionError(code)
    try:
        return json.loads(value, object_pairs_hook=strict_object)
    except (json.JSONDecodeError, ProjectionError, RecursionError) as exc:
        raise ProjectionError(code) from exc


def bounded_string_list(value: object, code: str) -> list[str]:
    if not isinstance(value, list) or len(value) > AUTHORIZATION_LIST_LIMIT:
        raise ProjectionError(code)
    projected: list[str] = []
    for item in value:
        text = required_text(item, code, maximum=4096)
        if text in projected:
            raise ProjectionError(code)
        projected.append(text)
    return projected


def project_authorization(value: object) -> dict[str, list[str]]:
    parsed = parse_embedded_json(value, "invalid_auth_context")
    if not isinstance(parsed, dict) or set(parsed) != AUTHORIZATION_KEYS:
        raise ProjectionError("invalid_auth_context")
    return {
        key: bounded_string_list(parsed[key], "invalid_auth_context")
        for key in sorted(AUTHORIZATION_KEYS)
    }


def project_tools(value: object) -> tuple[str, ...]:
    parsed = parse_embedded_json(value, "invalid_expected_tools")
    if not isinstance(parsed, list) or not 1 <= len(parsed) <= MAX_TOOL_EVENTS:
        raise ProjectionError("invalid_expected_tools")
    tools: list[str] = []
    for value in parsed:
        name = required_text(value, "invalid_tool_name", maximum=160)
        if not SAFE_TOOL_NAME.fullmatch(name):
            raise ProjectionError("invalid_tool_name")
        tools.append(name)
    return tuple(tools)


def source_record(revision: str, source_id: str) -> dict[str, str]:
    return {
        "dataset": DATASET_ID,
        "revision": revision,
        "original_id": source_id,
        "license": SOURCE_LICENSE,
        "redistribution": SOURCE_REDISTRIBUTION,
    }


def scenario_context(
    authorization: Mapping[str, Sequence[str]],
    *,
    sensitivity: str,
    expected_policy: str | None,
) -> dict[str, Any]:
    context: dict[str, Any] = {
        "authorization": {key: list(authorization[key]) for key in sorted(authorization)},
        "sensitivity_label": sensitivity,
    }
    if expected_policy is not None:
        context["expected_policy"] = expected_policy
    return {"_crossmcp_context": context}


def truth(
    *,
    is_attack: bool,
    attack_type: str | None,
    expected_policy: str | None,
    authorized: bool,
) -> dict[str, Any]:
    categories = [
        "crossmcp_bench",
        "canonical_expected_tool_sequence",
        "policy_authorization_context",
        "no_execution_result",
    ]
    if is_attack:
        assert attack_type is not None and expected_policy is not None
        categories.extend(
            [
                "trajectory_only_positive",
                f"attack_type.{attack_type}",
                f"policy.{expected_policy}",
            ]
        )
        return {
            "source_truth": "malicious",
            "deterministic_truth": "contextual_or_dual_use",
            "label_confidence": "high",
            "label_source": "crossmcp_bench:canonical_attack_scenario",
            "applicability": "in_scope",
            "expected_disposition": "detect_only",
            "categories": categories,
        }
    categories.extend(
        [
            "benign_hard_negative",
            "source_labeled_benign",
            "explicit_authorization" if authorized else "no_explicit_authorization",
        ]
    )
    return {
        "source_truth": "benign",
        "deterministic_truth": "benign",
        "label_confidence": "high",
        "label_source": "crossmcp_bench:canonical_benign_scenario",
        "applicability": "in_scope",
        "expected_disposition": "allow",
        "categories": categories,
    }


def project_row(
    row: Mapping[str, Any], *, revision: str, split: str
) -> dict[str, Any]:
    if set(row) != SOURCE_KEYS:
        raise ProjectionError("invalid_source_shape")
    source_id = required_text(row.get("id"), "invalid_source_id", maximum=120)
    if not SAFE_SOURCE_ID.fullmatch(source_id):
        raise ProjectionError("invalid_source_id")
    if type(row.get("is_attack")) is not bool:
        raise ProjectionError("invalid_attack_label")
    is_attack = bool(row["is_attack"])

    sensitivity = required_text(
        row.get("sensitivity_label"), "invalid_sensitivity_label", maximum=32
    )
    if sensitivity not in SENSITIVITY_LABELS:
        raise ProjectionError("invalid_sensitivity_label")
    authorization = project_authorization(row.get("auth_context"))
    tools = project_tools(row.get("expected_tools"))

    attack_type: str | None = None
    expected_policy: str | None = None
    if is_attack:
        attack_type = required_text(row.get("attack_type"), "invalid_attack_type", maximum=120)
        if not SAFE_CATEGORY.fullmatch(attack_type):
            raise ProjectionError("invalid_attack_type")
        expected_policy = required_text(
            row.get("expected_policy"), "invalid_expected_policy", maximum=120
        )
        if not SAFE_POLICY.fullmatch(expected_policy):
            raise ProjectionError("invalid_expected_policy")
        if len(tools) < 2:
            raise ProjectionError("attack_requires_stateful_sequence")
    elif row.get("attack_type") is not None or row.get("expected_policy") is not None:
        raise ProjectionError("benign_has_attack_metadata")

    identity = digest(DATASET_ID, revision, source_id)
    authorized = any(authorization.values())
    common = {
        "schema_version": SCHEMA_VERSION,
        "id": f"crossmcp-bench/{identity[:24]}/scenario",
        "source": source_record(revision, source_id),
        "split": split,
        "truth": truth(
            is_attack=is_attack,
            attack_type=attack_type,
            expected_policy=expected_policy,
            authorized=authorized,
        ),
        "strata": {
            "ecosystem": "mcp",
            "campaign": expected_policy or "benign_canonical_scenario",
            "domain": attack_type or sensitivity,
            "hard_negative": not is_attack,
            "split_group": identity[:24],
            "trajectory_id": identity[:24],
            "sequence_index": 0,
            "call_index": 0,
        },
    }
    context = scenario_context(
        authorization,
        sensitivity=sensitivity,
        expected_policy=expected_policy,
    )
    if len(tools) == 1:
        if is_attack:
            raise ProjectionError("attack_requires_stateful_sequence")
        return {
            **common,
            "surface": "action",
            "payload": {
                "direction": "tool_call",
                "tool_name": tools[0],
                "args": context,
                "dialect": "none",
            },
        }
    return {
        **common,
        "surface": "stateful",
        "payload": {
            "direction": "tool_call",
            "args": context,
            "events": [
                {"tool_name": tool_name, "args": {}, "dialect": "none"}
                for tool_name in tools
            ],
        },
    }


def normalize(
    rows: Iterable[Mapping[str, Any]], *, revision: str, split: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    revision = required_text(revision, "invalid_revision", maximum=160)
    if split not in {"development", "validation", "test"}:
        raise ValueError("invalid split")

    cases: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    skipped: Counter[str] = Counter()
    tool_names: Counter[str] = Counter()
    seen_source_ids: set[str] = set()

    for row in rows:
        counts["source_rows"] += 1
        if not isinstance(row, Mapping):
            skipped["invalid_source_shape"] += 1
            continue
        try:
            source_id = required_text(row.get("id"), "invalid_source_id", maximum=120)
            if source_id in seen_source_ids:
                raise ProjectionError("duplicate_source_id")
            case = project_row(row, revision=revision, split=split)
            tools = project_tools(row.get("expected_tools"))
        except ProjectionError as exc:
            skipped[exc.code] += 1
            continue
        seen_source_ids.add(source_id)
        cases.append(case)
        counts["projected_tool_calls"] += len(tools)
        counts[f"{case['truth']['source_truth']}_{case['surface']}_cases"] += 1
        tool_names.update(tools)

    cases.sort(key=lambda case: str(case["id"]))
    counts["cases"] = len(cases)
    counts["attack_scenarios"] = sum(
        case["truth"]["source_truth"] == "malicious" for case in cases
    )
    counts["benign_scenarios"] = sum(
        case["truth"]["source_truth"] == "benign" for case in cases
    )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "source_id": DATASET_ID,
        "source_url": SOURCE_URL,
        "source_revision": revision,
        "source_license": SOURCE_LICENSE,
        "split": split,
        "row_count": len(cases),
        "counts": dict(sorted(counts.items())),
        "tool_names": dict(sorted(tool_names.items())),
        "skipped": dict(sorted(skipped.items())),
        "normalization": (
            "one case per canonical scenario; ordered expected tool names plus exact "
            "scenario-level authorization, sensitivity, and expected policy only"
        ),
        "excluded_fields": ["description", "user_instruction"],
        "label_limitation": (
            "Expected tools are canonical plans without arguments, call IDs, timestamps, or "
            "execution results. Attack truth applies only to the complete stateful scenario; "
            "no constituent attack tool is emitted as an atomic malicious case."
        ),
    }
    return cases, manifest


def jsonl_rows(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("rb") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            if len(raw_line) > MAX_SOURCE_LINE_BYTES:
                raise ValueError(f"source line {line_number} exceeds the byte limit")
            if not raw_line.strip():
                continue
            try:
                row = json.loads(raw_line, object_pairs_hook=strict_object)
            except (json.JSONDecodeError, UnicodeDecodeError, ProjectionError, RecursionError) as exc:
                raise ValueError(f"invalid source JSON on line {line_number}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"source line {line_number} is not an object")
            yield row


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - CLI dependency guidance
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    seen_ids: set[str] = set()
    for row in rows:
        case_id = str(row.get("id", ""))
        if case_id in seen_ids:
            raise ValueError("duplicate benchmark case ID")
        seen_ids.add(case_id)
        errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if errors:
            location = ".".join(str(part) for part in errors[0].absolute_path)
            raise ValueError(f"{case_id}:{location or '<root>'}: {errors[0].message}")

        payload = row["payload"]
        source_truth = row["truth"]["source_truth"]
        context = payload.get("args", {}).get("_crossmcp_context")
        if not isinstance(context, dict) or "authorization" not in context:
            raise ValueError(f"{case_id}: missing source authorization context")
        if row["surface"] == "action":
            if source_truth != "benign":
                raise ValueError(f"{case_id}: attack call cannot be atomic malicious")
            if set(payload) != {"direction", "tool_name", "args", "dialect"}:
                raise ValueError(f"{case_id}: atomic payload contains excluded fields")
        elif row["surface"] == "stateful":
            if set(payload) != {"direction", "args", "events"}:
                raise ValueError(f"{case_id}: stateful payload contains excluded fields")
            if not 2 <= len(payload["events"]) <= MAX_TOOL_EVENTS:
                raise ValueError(f"{case_id}: invalid stateful event count")
            for event in payload["events"]:
                if set(event) != {"tool_name", "args", "dialect"} or event["args"] != {}:
                    raise ValueError(f"{case_id}: event contains invented call evidence")
        else:
            raise ValueError(f"{case_id}: unsupported surface")


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def write_outputs(
    cases: Sequence[dict[str, Any]],
    manifest: dict[str, Any],
    *,
    output: Path,
    manifest_path: Path,
) -> None:
    output_data = "".join(canonical_json(case) + "\n" for case in cases).encode("utf-8")
    manifest = {**manifest, "output_sha256": hashlib.sha256(output_data).hexdigest()}
    atomic_write(output, output_data)
    atomic_write(
        manifest_path,
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def main() -> int:
    args = parse_args()
    cases, manifest = normalize(
        jsonl_rows(args.input), revision=args.revision, split=args.split
    )
    validate_cases(cases, args.schema)
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    write_outputs(cases, manifest, output=args.output, manifest_path=manifest_path)
    print(json.dumps({"output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
