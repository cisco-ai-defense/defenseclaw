#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Prepare privacy-bounded public trajectory candidates for offline labeling.

The input is one or more normalized DefenseClaw case-v1 JSONL corpora.  The
output deliberately is not a copy of case-v1: it contains only ordered tool
events needed by an offline trajectory annotator.  Source provenance, labels,
prompts, local identities, digests, and unrelated case metadata never cross
this boundary.

Only English, development-split, contextual or bounded-proof candidates from
public-looking normalized sources are eligible.  Each candidate contains its
current event and no more than eight predecessors.  No network or model API is
used by this program.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"
DEFAULT_MAX_PREDECESSORS = 8
DEFAULT_MAX_TOTAL_CHARS = 60_000
DEFAULT_MAX_TOTAL_ELEMENTS = 4_096
MAX_INPUT_LINE_CHARS = 8 * 1024 * 1024
MAX_DEPTH = 32
MAX_TOOL_NAME_CHARS = 240

CONTEXTUAL_CATEGORIES = frozenset(
    {
        "bounded_action_sequence",
        "bounded_chain",
        "contextual",
        "contextual_action",
        "contextual_side_task",
        "contextual_tool_call",
        "proof_pending",
        "source_harmful_scenario",
    }
)
PUBLIC_REDISTRIBUTION = frozenset({"aggregate-only", "download-only", "vendored"})
PRIVATE_SOURCE_RE = re.compile(
    r"(?:^|[/_.:-])(?:codex[-_ ]?sessions?|internal|local[-_ ]?sessions?|private)(?:$|[/_.:-])",
    re.IGNORECASE,
)
SAFE_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,239}$")

DROP_KEYS = frozenset(
    {
        "checksum",
        "dataset",
        "final_answer",
        "license",
        "metadata",
        "original_id",
        "provenance",
        "reasoning",
        "redistribution",
        "revision",
        "sha1",
        "sha256",
        "thought",
        "thoughts",
        "transcript",
        "usage",
    }
)
SENSITIVE_KEYS_RE = re.compile(
    r"(?:^|[_-])(?:api[_-]?keys?|authorization|cookies?|credentials?|passwd|passwords?|"
    r"private[_-]?keys?|secrets?|session[_-]?(?:id|key|token)s?|tokens?)(?:$|[_-])",
    re.IGNORECASE,
)
IDENTITY_KEYS = frozenset({"author", "email", "owner", "user", "username"})
HASH_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,128}(?![0-9A-Fa-f])")
JWT_RE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])")
BEARER_RE = re.compile(r"(?i)\bbearer\s+[^\s,;]+")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key)\s*([:=])\s*([^\s,;]+)"
)
POSIX_HOME_RE = re.compile(r"(?<![A-Za-z0-9_.-])/(?:Users|home)/[^/\s]+")
WINDOWS_HOME_RE = re.compile(r"(?i)(?<![A-Za-z0-9_.-])[A-Z]:\\Users\\[^\\\s]+")
EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.-])")
INTERNAL_HOST_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9.-])(?:localhost|127\.0\.0\.1|[A-Za-z0-9.-]+\.(?:corp|internal))(?![A-Za-z0-9.-])"
)

ACTION_ARGUMENT_FIELDS = ("command", "argv", "cwd", "filename", "target", "dialect")
RESULT_FIELDS = ("result", "output", "observation", "response", "return_value")
ACTION_FACT_FIELDS = frozenset(
    {
        "control_flow",
        "destination_trust",
        "operation",
        "resource",
        "result",
        "scope",
        "sensitivity",
    }
)


class ProjectionError(ValueError):
    """A normalized row cannot safely cross the candidate boundary."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CandidateDraft:
    group: tuple[str, str]
    ordinal: tuple[int, int]
    case_id: str
    events: tuple[Mapping[str, Any], ...]


class Redactor:
    """Replace sensitive literals consistently within one bounded candidate."""

    def __init__(self) -> None:
        self._values: dict[tuple[str, str], str] = {}
        self._counts: Counter[str] = Counter()

    def token(self, category: str, raw: object) -> str:
        canonical = canonical_json(raw)
        key = (category, canonical)
        if key not in self._values:
            self._counts[category] += 1
            self._values[key] = f"<redacted-{category}-{self._counts[category]:04d}>"
        return self._values[key]

    def text(self, value: str, *, key: str = "") -> str:
        if SENSITIVE_KEYS_RE.search(key):
            return self.token("secret", value)
        if key.casefold() in IDENTITY_KEYS:
            return self.token("identity", value)

        result = POSIX_HOME_RE.sub("<local-home>", value)
        result = WINDOWS_HOME_RE.sub("<local-home>", result)
        result = EMAIL_RE.sub(lambda match: self.token("identity", match.group(0)), result)
        result = INTERNAL_HOST_RE.sub(lambda match: self.token("host", match.group(0)), result)
        result = JWT_RE.sub(lambda match: self.token("secret", match.group(0)), result)
        result = BEARER_RE.sub(lambda match: self.token("secret", match.group(0)), result)

        def replace_assignment(match: re.Match[str]) -> str:
            token = self.token("secret", match.group(3))
            return f"{match.group(1)}{match.group(2)}{token}"

        result = SECRET_ASSIGNMENT_RE.sub(replace_assignment, result)
        result = HASH_RE.sub(lambda match: self.token("hash", match.group(0)), result)
        return result


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProjectionError("duplicate_json_key")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise ProjectionError(f"non_finite_json:{value}")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--max-predecessors",
        type=int,
        default=DEFAULT_MAX_PREDECESSORS,
        help="Predecessor count, from zero through eight",
    )
    parser.add_argument("--max-total-chars", type=int, default=DEFAULT_MAX_TOTAL_CHARS)
    parser.add_argument("--max-total-elements", type=int, default=DEFAULT_MAX_TOTAL_ELEMENTS)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"input must be a regular non-symlink file: {path}")
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if len(line) > MAX_INPUT_LINE_CHARS:
                raise ValueError(f"{path}:{line_number}: input line exceeds safety limit")
            if not line.strip():
                continue
            try:
                row = json.loads(
                    line,
                    object_pairs_hook=strict_object,
                    parse_constant=reject_nonfinite,
                )
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: expected one JSON object")
            yield row


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _text(value: object, code: str, maximum: int = 240) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ProjectionError(code)
    return value


def _integer(value: object, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ProjectionError(code)
    return value


def _eligible_language(row: Mapping[str, Any]) -> bool:
    language = _mapping(row.get("strata")).get("language")
    return isinstance(language, str) and (
        language.casefold() in {"en", "english"} or language.casefold().startswith("en-")
    )


def _public_source(row: Mapping[str, Any]) -> bool:
    source = _mapping(row.get("source"))
    dataset = source.get("dataset")
    redistribution = source.get("redistribution")
    if not isinstance(dataset, str) or not dataset or PRIVATE_SOURCE_RE.search(dataset):
        return False
    if redistribution not in PUBLIC_REDISTRIBUTION:
        return False
    visibility = source.get("visibility")
    return not (isinstance(visibility, str) and visibility.casefold() in {"internal", "private"})


def _is_contextual(row: Mapping[str, Any]) -> bool:
    truth = _mapping(row.get("truth"))
    if truth.get("deterministic_truth") == "contextual_or_dual_use":
        return True
    if truth.get("stateful_lens") == "bounded_intent":
        return True
    categories = truth.get("categories")
    if not isinstance(categories, list):
        return False
    normalized = {value.casefold() for value in categories if isinstance(value, str)}
    return bool(normalized & CONTEXTUAL_CATEGORIES)


def _group_identity(row: Mapping[str, Any]) -> tuple[str, str]:
    strata = _mapping(row.get("strata"))
    split_group = _text(strata.get("split_group"), "missing_split_group", 128)
    trajectory_id = _text(strata.get("trajectory_id"), "missing_trajectory_id", 128)
    return split_group, trajectory_id


def _ordinal(row: Mapping[str, Any]) -> tuple[int, int]:
    strata = _mapping(row.get("strata"))
    return (
        _integer(strata.get("sequence_index"), "invalid_sequence_index"),
        _integer(strata.get("call_index"), "invalid_call_index"),
    )


def _sanitize(value: object, redactor: Redactor, *, key: str = "", depth: int = 0) -> object:
    if depth > MAX_DEPTH:
        raise ProjectionError("value_too_deep")
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ProjectionError("non_finite_value")
        return value
    if isinstance(value, str):
        return redactor.text(value, key=key)
    if isinstance(value, list):
        return [_sanitize(item, redactor, key=key, depth=depth + 1) for item in value]
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key in sorted(value):
            if not isinstance(raw_key, str):
                raise ProjectionError("non_string_object_key")
            normalized_key = raw_key.casefold()
            if normalized_key in DROP_KEYS or normalized_key.endswith("_sha256"):
                continue
            child = value[raw_key]
            if SENSITIVE_KEYS_RE.search(raw_key):
                result[raw_key] = redactor.token("secret", child)
            else:
                result[raw_key] = _sanitize(child, redactor, key=raw_key, depth=depth + 1)
        return result
    raise ProjectionError("unsupported_value_type")


def _arguments(event: Mapping[str, Any], redactor: Redactor) -> dict[str, Any]:
    raw_args = event.get("args")
    if raw_args is None:
        raw_args = event.get("arguments", {})
    if not isinstance(raw_args, Mapping):
        raise ProjectionError("invalid_arguments")
    projected = _sanitize(raw_args, redactor)
    if not isinstance(projected, dict):
        raise AssertionError("mapping projection changed type")
    for field in ACTION_ARGUMENT_FIELDS:
        if field in event and field not in projected:
            projected[field] = _sanitize(event[field], redactor, key=field)
    return projected


def _result(event: Mapping[str, Any], redactor: Redactor) -> dict[str, Any]:
    projected: dict[str, Any] = {}
    outcome = event.get("outcome")
    if isinstance(outcome, str):
        projected["outcome"] = redactor.text(outcome)
    for field in RESULT_FIELDS:
        if field in event:
            projected["data"] = _sanitize(event[field], redactor, key=field)
            break
    return projected


def _action_facts(event: Mapping[str, Any], redactor: Redactor) -> dict[str, Any]:
    raw = event.get("action_facts", event.get("facts"))
    if not isinstance(raw, Mapping):
        return {}
    projected = {
        key: _sanitize(raw[key], redactor, key=key)
        for key in sorted(raw)
        if isinstance(key, str) and key in ACTION_FACT_FIELDS
    }
    return projected


def _project_events(events: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    redactor = Redactor()
    projected: list[dict[str, Any]] = []
    for event_index, event in enumerate(events):
        tool_name = _text(event.get("tool_name"), "invalid_tool_name", MAX_TOOL_NAME_CHARS)
        if SAFE_TOOL_NAME_RE.fullmatch(tool_name) is None:
            raise ProjectionError("invalid_tool_name")
        item: dict[str, Any] = {
            "event_index": event_index,
            "tool_name": tool_name,
            "arguments": _arguments(event, redactor),
            "result": _result(event, redactor),
        }
        facts = _action_facts(event, redactor)
        if facts:
            item["action_facts"] = facts
        projected.append(item)
    return projected


def _element_count(value: object) -> int:
    if isinstance(value, Mapping):
        return 1 + sum(1 + _element_count(item) for item in value.values())
    if isinstance(value, list):
        return 1 + sum(_element_count(item) for item in value)
    return 1


def _bounded_projection(
    events: Sequence[Mapping[str, Any]],
    *,
    max_predecessors: int,
    max_total_chars: int,
    max_total_elements: int,
) -> tuple[list[dict[str, Any]] | None, int]:
    bounded = list(events[-(max_predecessors + 1) :])
    removed_for_limits = 0
    while bounded:
        projected = _project_events(bounded)
        if (
            len(canonical_json(projected)) <= max_total_chars
            and _element_count(projected) <= max_total_elements
        ):
            return projected, removed_for_limits
        if len(bounded) == 1:
            return None, removed_for_limits
        bounded = bounded[1:]
        removed_for_limits += 1
    return None, removed_for_limits


def _base_eligible(row: Mapping[str, Any], statistics: Counter[str]) -> bool:
    statistics["input_rows"] += 1
    split = row.get("split")
    if split != "development":
        statistics["excluded_non_development"] += 1
        return False
    if not _eligible_language(row):
        statistics["excluded_non_english"] += 1
        return False
    if not _public_source(row):
        statistics["excluded_non_public_source"] += 1
        return False
    return True


def _drafts(rows: Iterable[Mapping[str, Any]], statistics: Counter[str]) -> list[CandidateDraft]:
    stateful: list[CandidateDraft] = []
    actions: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    stateful_groups: set[tuple[str, str]] = set()
    seen_case_ids: set[str] = set()

    for row in rows:
        if not _base_eligible(row, statistics):
            continue
        case_id = row.get("id")
        if not isinstance(case_id, str) or not case_id:
            statistics["excluded_invalid_case"] += 1
            continue
        if case_id in seen_case_ids:
            raise ValueError(f"duplicate normalized case ID: {case_id}")
        seen_case_ids.add(case_id)
        try:
            group = _group_identity(row)
            ordinal = _ordinal(row)
        except ProjectionError as exc:
            statistics[f"excluded_{exc.code}"] += 1
            continue

        surface = row.get("surface")
        if surface == "action":
            actions[group].append(row)
            continue
        if surface != "stateful" or not _is_contextual(row):
            statistics["excluded_not_contextual_trajectory"] += 1
            continue
        raw_events = _mapping(row.get("payload")).get("events")
        if not isinstance(raw_events, list) or not raw_events or not all(
            isinstance(event, Mapping) for event in raw_events
        ):
            statistics["excluded_invalid_stateful_events"] += 1
            continue
        stateful.append(CandidateDraft(group, ordinal, case_id, tuple(raw_events)))
        stateful_groups.add(group)
        statistics["selected_stateful_drafts"] += 1

    for group, group_rows in actions.items():
        if group in stateful_groups:
            statistics["excluded_action_group_with_stateful"] += sum(
                1 for row in group_rows if _is_contextual(row)
            )
            continue
        ordered = sorted(group_rows, key=lambda row: (*_ordinal(row), str(row.get("id", ""))))
        deduplicated: list[Mapping[str, Any]] = []
        seen_ordinals: set[tuple[int, int]] = set()
        for row in ordered:
            ordinal = _ordinal(row)
            if ordinal in seen_ordinals:
                statistics["excluded_duplicate_action_ordinal"] += 1
                continue
            seen_ordinals.add(ordinal)
            deduplicated.append(row)
        for current, row in enumerate(deduplicated):
            if not _is_contextual(row):
                continue
            ordinal = _ordinal(row)
            events = tuple(_mapping(item.get("payload")) for item in deduplicated[: current + 1])
            stateful.append(CandidateDraft(group, ordinal, str(row["id"]), events))
            statistics["selected_action_drafts"] += 1

    stateful.sort(key=lambda item: (item.group, item.ordinal, item.case_id))
    return stateful


def prepare_candidates(
    rows: Iterable[Mapping[str, Any]],
    *,
    max_predecessors: int = DEFAULT_MAX_PREDECESSORS,
    max_total_chars: int = DEFAULT_MAX_TOTAL_CHARS,
    max_total_elements: int = DEFAULT_MAX_TOTAL_ELEMENTS,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    if not 0 <= max_predecessors <= DEFAULT_MAX_PREDECESSORS:
        raise ValueError("max_predecessors must be between zero and eight")
    if max_total_chars < 1 or max_total_elements < 1:
        raise ValueError("total character and element limits must be positive")

    statistics: Counter[str] = Counter()
    drafts = _drafts(rows, statistics)
    group_numbers = {group: index for index, group in enumerate(sorted({draft.group for draft in drafts}), 1)}
    prepared: list[tuple[CandidateDraft, list[dict[str, Any]]]] = []
    for draft in drafts:
        try:
            events, removed = _bounded_projection(
                draft.events,
                max_predecessors=max_predecessors,
                max_total_chars=max_total_chars,
                max_total_elements=max_total_elements,
            )
        except ProjectionError as exc:
            statistics[f"excluded_{exc.code}"] += 1
            continue
        statistics["predecessors_removed_for_limits"] += removed
        if events is None:
            statistics["excluded_current_event_over_limit"] += 1
            continue
        prepared.append((draft, events))

    candidates: list[dict[str, Any]] = []
    for candidate_number, (draft, events) in enumerate(prepared, 1):
        candidates.append(
            {
                "schema_version": SCHEMA_VERSION,
                "candidate_id": f"trajectory-candidate-{candidate_number:08d}",
                "trajectory_group": f"trajectory-{group_numbers[draft.group]:08d}",
                "split": "development",
                "target_event_index": len(events) - 1,
                "events": events,
            }
        )
    statistics["candidate_count"] = len(candidates)
    statistics["candidate_event_count"] = sum(len(item["events"]) for item in candidates)
    return candidates, dict(sorted(statistics.items()))


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    if path.exists():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(canonical_json(row) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.dry_run and args.output is None:
        raise ValueError("--output is required unless --dry-run is used")
    rows = (row for path in args.input for row in read_jsonl(path))
    candidates, statistics = prepare_candidates(
        rows,
        max_predecessors=args.max_predecessors,
        max_total_chars=args.max_total_chars,
        max_total_elements=args.max_total_elements,
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "workflow": "offline_trajectory_candidate_preparation",
        "dry_run": bool(args.dry_run),
        "max_predecessors": args.max_predecessors,
        "max_total_chars": args.max_total_chars,
        "max_total_elements": args.max_total_elements,
        "statistics": statistics,
    }
    if not args.dry_run:
        _write_jsonl(args.output, candidates)
    print(canonical_json(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
