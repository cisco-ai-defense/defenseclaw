#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize InjecAgent's labeled attacker tool chains without executing source code.

INTENT PAIRS (what this adapter gained)
    The original adapter emitted only the attacker side: `[User Tool] + Attacker Tools` with
    `args` hardcoded to `{}` and no `payload.content`. That cannot answer "does this call match
    what the user asked", because the user's request never reached the case and there was no
    legitimate counterpart to compare against. InjecAgent is one of the few corpora that
    supplies BOTH sides by hand, so each test case now yields:

      intent_matching   the user's own call: `User Tool` with the real `Tool Parameters`, which
                        the paper authors wrote as the correct arguments for `User Instruction`.
                        benign / benign / allow, surface `action` (a single call is not a
                        trajectory) -> grade D.
      intent_violating  the same user request followed by the attacker-desired chain from
                        `Attacker Tools`. malicious / contextual_or_dual_use / detect_only,
                        high confidence, surface `stateful` -> grade B.

    `strata.pair_group` is the user-instruction hash on both classes, so the matched and
    mismatched members of a pair join on it.

GRADING DECISIONS
    `deterministic_truth` stays `contextual_or_dual_use` and no `exact_proof`/`closed_proof`
    category is attached, so nothing here reaches grade A. That is correct and deliberate:
    this corpus specifies the call the attacker WANTS, not a call that was ever emitted or
    executed, and the attacker tools themselves (`GmailSendEmail`, `AmazonViewSavedAddresses`)
    are ordinary tools that are only malicious relative to the user's request. There is no
    outcome evidence of any kind.

    `label_confidence` is now `high`, which moves the existing violating rows from grade C to
    grade B. The justification is authorship, not a model: the InjecAgent authors hand-wrote
    each `User Instruction`, the attacker instruction embedded in the tool response, and the
    attacker's desired tool chain, so "this chain serves the attacker rather than the user" is
    a human ground truth, and `surface: stateful` plus `detect_only` already satisfy the rest
    of grade B.

FAMILY IDENTITY
    `strata.split_group` keeps the original scheme, `sha256("\\x00".join(tools))[:24]`. Measured
    on the pinned bytes, each of the 62 attacker instructions maps to exactly one attacker tool
    chain, so the tool-chain hash yields 1,054 distinct families for the 1,054 base cases -- the
    same cardinality as hashing the attacker instruction, with no loss. It is also the stricter
    choice for this payload shape: attacker prose is excluded from the payload, so two rows with
    the same user instruction and the same tool chain would be byte-identical payloads and must
    not land in different families. intent_matching rows hash their single user tool, giving 17
    families disjoint from the 1,054 violating families.

KNOWN LIMITATION
    Only 17 distinct user instructions exist (= 17 distinct `User Tool`/`Tool Parameters`
    pairs). The 1,054 base cases are the full 17 x 62 cross product, so intent diversity is
    low and this corpus must not be allowed to dominate a split group. The 1,054
    intent_matching rows that a naive per-case pairing would produce collapse to 17 distinct
    payloads, so they are deduplicated to 17 rather than emitted 62 times each.

    `_enhanced` differs from `_base` in exactly one field, `Tool Response` (verified field by
    field: 510/510 dh and 544/544 ds rows), and that field carries the attacker instruction
    verbatim, which the corpus's value-free payload invariant excludes. Enhanced rows therefore
    have payloads identical to their base counterparts and add no new `split_group`. They are
    still emitted when their paths are passed, tagged `strata.injection_strength: enhanced`, but
    their grade-B count must not be added to the base count as if it were new supply.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,159}$")
SOURCE_REVISION = "f19c9f2c79a41046eb13c03c51a24c567a8ffa07"
PRE_PARTITION_SPLIT = "smoke"
CASE_CLASS_VIOLATING = "intent_violating"
CASE_CLASS_MATCHING = "intent_matching"
EXPECTED_FILES = {
    "test_cases_dh_base.json": "0a8186468d21389af432e8c7b399ae42264d1b93a07b65c7a489468508604305",
    "test_cases_ds_base.json": "4daab35c62a3845e8b9400f4dca58b9c9f37e57cd33b2337552557fbb26282e9",
    "test_cases_dh_enhanced.json": "885602716b72c18af80695ce6c2e1f242fa03163bc90b0788b0c5e4ab6216d50",
    "test_cases_ds_enhanced.json": "7bc510868df032511053fc40e8470e68a041fb7148d055112093594bf73ab0ce",
}
# The base pair is the corpus; the enhanced pair is an optional stronger-injection variant.
REQUIRED_FILES = ("test_cases_dh_base.json", "test_cases_ds_base.json")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--split", choices=(PRE_PARTITION_SPLIT,), default=PRE_PARTITION_SPLIT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_attack_type(value: object) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", str(value).casefold()).strip("_")
    return normalized[:100] or "unknown"


def injection_strength(name: str) -> str:
    return "enhanced" if "_enhanced" in name else "base"


def text_field(source: dict[str, Any], key: str) -> str:
    value = source.get(key)
    return value.strip() if isinstance(value, str) else ""


def user_arguments(raw: object) -> dict[str, Any] | None:
    """Parse InjecAgent's ``Tool Parameters`` Python-literal string into real arguments.

    ``ast.literal_eval`` evaluates literals only, so no source code runs. Anything that is not
    a JSON-round-trippable mapping is rejected rather than guessed at, because inventing
    arguments would destroy the only reason to carry them.
    """
    if isinstance(raw, dict):
        candidate: Any = raw
    elif isinstance(raw, str) and raw.strip():
        try:
            candidate = ast.literal_eval(raw)
        except (ValueError, SyntaxError, MemoryError, RecursionError):
            return None
    else:
        return None
    if not isinstance(candidate, dict) or not candidate:
        return None
    if any(not isinstance(key, str) for key in candidate):
        return None
    try:
        json.dumps(candidate)
    except (TypeError, ValueError):
        return None
    return candidate


def tool_event(tool: str, index: int, args: dict[str, Any]) -> dict[str, Any]:
    # outcome is always unknown: InjecAgent specifies the call the attacker wants, and no call
    # in the corpus was ever emitted or executed, so there is no result to report.
    return {
        "tool_name": tool,
        "args": args,
        "dialect": "none",
        "outcome": "unknown",
        "offset_seconds": index,
    }


def load_source_rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix == ".json":
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
            raise ValueError(f"{path}: expected an array of objects")
        return value
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: row must be an object")
            rows.append(row)
    return rows


def _normalize_one(
    path: Path,
    revision: str,
    split: str,
    *,
    seen_matching: set[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Emit the intent_violating chain and, once per distinct user request, its matching pair.

    ``seen_matching`` carries the deduplication state across files so the 17 distinct user
    requests are emitted once for the whole corpus rather than once per source file.
    """
    rows: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    matching_seen = seen_matching if seen_matching is not None else set()
    strength = injection_strength(path.name)
    for line_number, source in enumerate(load_source_rows(path), 1):
        attacker_tools = source.get("Attacker Tools")
        user_tool = source.get("User Tool")
        tools = ([user_tool] if isinstance(user_tool, str) else []) + (
            attacker_tools if isinstance(attacker_tools, list) else []
        )
        if not isinstance(tools, list) or len(tools) < 2:
            skipped["not_multi_tool"] += 1
            continue
        if len(tools) > 64 or any(not isinstance(tool, str) or not SAFE_TOOL.fullmatch(tool) for tool in tools):
            skipped["invalid_tool_chain"] += 1
            continue
        user_instruction = text_field(source, "User Instruction")
        if not user_instruction:
            # Without the request there is no intent to test against; emitting an empty
            # payload.content would silently reintroduce the gap this adapter exists to close.
            skipped["missing_user_instruction"] += 1
            continue
        user_args = user_arguments(source.get("Tool Parameters"))
        if user_args is None:
            skipped["unparseable_tool_parameters"] += 1
            user_args = {}
        material = json.dumps(
            {
                "source_file": path.name,
                "line": line_number,
                "tools": tools,
                "attack_type": source.get("Attack Type", ""),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = hashlib.sha256(material.encode()).hexdigest()
        attack_type = normalized_attack_type(source.get("Attack Type"))
        pair_group = hashlib.sha256(user_instruction.encode()).hexdigest()[:24]
        rows.append(
            {
                "schema_version": "1",
                "id": f"injecagent/{digest[:24]}",
                "source": {
                    "dataset": "injecagent",
                    "revision": revision,
                    "original_id": f"{path.name}:{line_number}",
                    "license": "MIT",
                    "redistribution": "download-only",
                },
                "split": split,
                "surface": "stateful",
                "payload": {
                    # The user's own request, verbatim. Attacker prose stays out of the payload.
                    "content": user_instruction,
                    "events": [
                        # Event 0 is the user's legitimate call, so it carries the real
                        # Tool Parameters. The attacker tools have no arguments anywhere in the
                        # upstream corpus, so theirs stay empty rather than invented.
                        tool_event(tool, index, dict(user_args) if index == 0 else {})
                        for index, tool in enumerate(tools)
                    ],
                },
                "truth": {
                    "source_truth": "malicious",
                    "applicability": "in_scope",
                    "expected_disposition": "detect_only",
                    # No emitted or executed call exists anywhere in this corpus, and the
                    # attacker tools are ordinary tools, so deterministic truth stays contextual
                    # and no exact_proof category is attached: grade B, never grade A.
                    "deterministic_truth": "contextual_or_dual_use",
                    # Hand-authored by the paper authors, not model-labelled.
                    "label_confidence": "high",
                    "categories": [
                        "indirect_prompt_injection",
                        "multi_tool_chain",
                        "intent_deviation",
                        attack_type,
                    ],
                },
                "strata": {
                    "campaign": attack_type,
                    "domain": "structured_tool_call",
                    "split_group": hashlib.sha256("\x00".join(tools).encode()).hexdigest()[:24],
                    "case_class": CASE_CLASS_VIOLATING,
                    "pair_group": pair_group,
                    "injection_strength": strength,
                    "hard_negative": False,
                },
            }
        )

        # The matching counterpart depends only on the user request, and the corpus holds just
        # 17 distinct ones across 1,054 cases. Emitting it per case would produce 1,037
        # byte-identical benign rows in 17 families, so it is emitted once per distinct request.
        matching_material = json.dumps(
            {
                "case_class": CASE_CLASS_MATCHING,
                "user_tool": tools[0],
                "user_instruction": user_instruction,
                "tool_parameters": user_args,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        matching_digest = hashlib.sha256(matching_material.encode()).hexdigest()[:24]
        if matching_digest in matching_seen:
            skipped["duplicate_intent_matching_collapsed"] += 1
            continue
        matching_seen.add(matching_digest)
        rows.append(
            {
                "schema_version": "1",
                "id": f"injecagent/{matching_digest}",
                "source": {
                    "dataset": "injecagent",
                    "revision": revision,
                    "original_id": f"{path.name}:{line_number}:{CASE_CLASS_MATCHING}",
                    "license": "MIT",
                    "redistribution": "download-only",
                },
                "split": split,
                # One authorized call is an action, not a trajectory.
                "surface": "action",
                "payload": {
                    "content": user_instruction,
                    "events": [tool_event(tools[0], 0, dict(user_args))],
                },
                "truth": {
                    "source_truth": "benign",
                    "applicability": "in_scope",
                    "expected_disposition": "allow",
                    "deterministic_truth": "benign",
                    "label_confidence": "high",
                    "categories": ["intent_matching_baseline", "authorized_user_call"],
                },
                "strata": {
                    "campaign": CASE_CLASS_MATCHING,
                    "domain": "structured_tool_call",
                    "split_group": hashlib.sha256(tools[0].encode()).hexdigest()[:24],
                    "case_class": CASE_CLASS_MATCHING,
                    "pair_group": pair_group,
                    "injection_strength": "none",
                    "hard_negative": False,
                },
            }
        )
    rows.sort(key=lambda row: str(row["id"]))
    classes = Counter(str(row["strata"]["case_class"]) for row in rows)
    manifest = {
        "schema_version": "1",
        "source_id": "injecagent",
        "source_revision": revision,
        "source_license": "MIT",
        "source_sha256": sha256_file(path),
        "split": split,
        "row_count": len(rows),
        "skipped": dict(sorted(skipped.items())),
        "case_classes": dict(sorted(classes.items())),
        "injection_strength": strength,
        "normalization": (
            "user request plus user-tool and attacker-tool names; the user tool carries its real "
            "Tool Parameters; attacker instructions, expected achievements, and tool responses excluded"
        ),
    }
    return rows, manifest


def normalize(
    paths: list[Path], revision: str, split: str, *, verify_source: bool = True
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if revision != SOURCE_REVISION:
        raise ValueError("InjecAgent revision differs from datasets.lock.json")
    if split != PRE_PARTITION_SPLIT:
        raise ValueError("InjecAgent rows must remain pre-partitioned")
    names = sorted(path.name for path in paths)
    if set(names) - set(EXPECTED_FILES) or not set(REQUIRED_FILES) <= set(names) or len(names) != len(set(names)):
        raise ValueError("InjecAgent pinned attacker source set is incomplete")
    rows: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    source_files: list[dict[str, str]] = []
    # Base files first so the deduplicated intent_matching rows are attributed to the base
    # corpus regardless of whether the enhanced variants were supplied.
    ordered = sorted(paths, key=lambda candidate: (injection_strength(candidate.name) != "base", candidate.name))
    seen_matching: set[str] = set()
    for path in ordered:
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"invalid InjecAgent source file: {path.name}")
        source_sha256 = sha256_file(path)
        if verify_source and source_sha256 != EXPECTED_FILES[path.name]:
            raise ValueError(f"InjecAgent source bytes differ from pinned identity: {path.name}")
        source_files.append({"path": path.name, "sha256": source_sha256})
        normalized, partial = _normalize_one(path, revision, split, seen_matching=seen_matching)
        rows.extend(normalized)
        skipped.update(partial["skipped"])
    rows.sort(key=lambda row: str(row["id"]))
    case_ids = [str(row["id"]) for row in rows]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("duplicate InjecAgent case ID")
    source_files_sha256 = hashlib.sha256(
        json.dumps(source_files, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    classes = Counter(str(row["strata"]["case_class"]) for row in rows)
    strengths = Counter(str(row["strata"]["injection_strength"]) for row in rows)
    events = sum(len(row["payload"]["events"]) for row in rows)
    manifest = {
        "schema_version": "1",
        "datasets": ["injecagent"],
        "cases": len(rows),
        "counts": {"injecagent": len(rows)},
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "adapter_statistics": {
            "injecagent-tool-chain-v2": {
                "malicious_cases": classes[CASE_CLASS_VIOLATING],
                "benign_intent_matching_cases": classes[CASE_CLASS_MATCHING],
                "source_file_count": len(source_files),
                **dict(sorted(skipped.items())),
            }
        },
        "intent_pairs": {
            "case_classes": dict(sorted(classes.items())),
            "injection_strength": dict(sorted(strengths.items())),
            "cases_with_intent": sum(1 for row in rows if row["payload"].get("content")),
            "cases_with_arguments": sum(
                1 for row in rows if any(event["args"] for event in row["payload"]["events"])
            ),
            "split_groups": len({str(row["strata"]["split_group"]) for row in rows}),
            "pair_groups": len({str(row["strata"]["pair_group"]) for row in rows}),
            "events": events,
            "mean_events_per_case": round(events / len(rows), 4) if rows else 0.0,
        },
        "trajectory_source": {
            "source_id": "injecagent",
            "source_revision": revision,
            "source_license": "MIT",
            "split": split,
            "source_files_sha256": source_files_sha256,
            "normalization": (
                "user request as payload.content; user-tool call carries its real Tool Parameters; "
                "attacker tool names carry no arguments because the corpus supplies none; attacker "
                "instructions, expected achievements, and tool responses excluded"
            ),
            "label_authority": (
                "The pinned README documents these 1,054 base test cases as syntheses across 17 user tools and "
                "62 attacker tools; each row identifies its user tool, attacker tool chain, and attack type. "
                "Attacker-desired chains are hand-authored by the paper authors, so label_confidence is high, "
                "but no call in this corpus was ever emitted or executed: deterministic truth stays contextual "
                "and every violating row is detect-only (grade B, never grade A)."
            ),
            "known_limitation": (
                "Only 17 distinct user instructions exist, so the 1,054 base cases are the full 17 x 62 cross "
                "product and intent diversity is low; this corpus must not dominate a split group. The "
                "intent_matching side collapses to those 17 distinct payloads and is deduplicated. The "
                "_enhanced variants differ from _base only in the excluded Tool Response field, so they add "
                "no new payload and no new split_group."
            ),
        },
    }
    return rows, manifest


def main() -> int:
    args = parse_args()
    rows, manifest = normalize(args.input, args.revision, args.split)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    manifest["output_sha256"] = sha256_file(args.output)
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
