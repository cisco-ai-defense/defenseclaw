#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize the pinned SecEBL public examples conservatively.

SecEBL's public release contains ordered Linux command-session rows and
normalized Kubernetes AuditLog text, paired line-for-line with reviewed Rev20
behavior tags.  Session ``intrusion`` labels are not per-event malicious truth.
This adapter therefore promotes only a small closed set of Linux commands where
the source label, reviewed behavior tags, and exact command semantics agree on
an independently verifiable pre-action violation.  All other intrusion events
remain contextual.  Kubernetes intrusion rows are never promoted because the
normalized examples omit API response status and result bodies.

Normal-operation rows are retained as medium-confidence benign FPR pressure;
their limitation is recorded in the output manifest.  No command output,
review note, identity, or raw secret value is copied.  Stateful cases contain
the current event and at most eight ordered predecessors from the same session.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

SCHEMA_VERSION = "1"
DATASET_ID = "secebl-public-examples"
SOURCE_REVISION = "c328237fc46fd5ab3355bb6f65e9d8cd88dcac66"
SOURCE_LICENSE = "Apache-2.0"
SOURCE_REDISTRIBUTION = "download-only"
ADAPTER = "secebl-public-examples-conservative-v1"

SOURCE_FILES = (
    "LICENSE",
    "examples/README.md",
    "examples/manifest.json",
    "examples/linux/example_sessions.jsonl",
    "examples/linux/example_gold.rev20.jsonl",
    "examples/k8s/example_sessions.jsonl",
    "examples/k8s/example_gold.rev20.jsonl",
)
SOURCE_BUNDLE_BYTES = 9_481_135
SOURCE_BUNDLE_SHA256 = "13d1165fd338236fb9ccae661cdc4e9dc84648c117921e10caf37d06a2cf38e4"
EXPECTED = {
    "linux": {"rows": 10_520, "sessions": 531, "normal_operation": 2_934, "intrusion": 7_586},
    "k8s": {"rows": 144, "sessions": 46, "normal_operation": 72, "intrusion": 72},
}

MAX_PREDECESSORS = 8
MAX_EVENTS = MAX_PREDECESSORS + 1
MAX_COMMAND_BYTES = 256 * 1024
MAX_SOURCE_FILE_BYTES = 8 * 1024 * 1024
MAX_JSONL_LINE_BYTES = 1024 * 1024
MAX_TAGS = 128
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,239}$")
SAFE_TAG = re.compile(r"^[a-z][a-z0-9_]{0,119}$")
NON_ENGLISH_SCRIPT = re.compile(
    "[\u0370-\u052f\u0590-\u08ff\u0900-\u109f\u1780-\u18af\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]"
)
AWS_ACCESS_KEY = re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")
JWT = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
PEM = re.compile(r"-----BEGIN [A-Z0-9 ]*(?:PRIVATE KEY|OPENSSH PRIVATE KEY)-----")
URL_USERINFO = re.compile(r"https?://[^\s/@:]+:[^\s/@]+@", re.IGNORECASE)
SECRET_ASSIGNMENT = re.compile(
    r"(?ix)(?:^|[\s;])(?:export\s+)?"
    r"(?:password|passwd|pwd|token|api[_-]?key|access[_-]?key|secret|client[_-]?secret)"
    r"\s*=\s*(?:(['\"])(.*?)\1|([^\s;]+))"
)
SECRET_FLAG = re.compile(
    r"(?ix)(?:^|\s)--?(?:password|passwd|token|api[_-]?key|access[_-]?key|secret|client[_-]?secret)"
    r"(?:=|\s+)(?:(['\"])(.*?)\1|([^\s;]+))"
)
SAFE_SECRET_REFERENCE = re.compile(
    r"^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|@[A-Za-z0-9_./-]+|"
    r"<[^>]+>|REDACTED|MASKED|PLACEHOLDER|example|dummy|test)$",
    re.IGNORECASE,
)

REVERSE_SHELL_TAG = "spawn_reverse_shell"
CREDENTIAL_UPLOAD_TAGS = frozenset({"upload_external_content", "upload_credential_material"})
AUDIT_DELETE_TAGS = frozenset({"delete_audit_log", "delete_system_log"})

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"


class ProjectionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Event:
    platform: str
    session_id: str
    sequence: int
    source_label: str
    command: str
    behavior_tags: tuple[str, ...]
    gold_id: str
    proof: str | None

    def detector_event(self) -> dict[str, Any]:
        tool_name = "shell" if self.platform == "linux" else "kubernetes_audit"
        dialect = "posix" if self.platform == "linux" else "none"
        return {
            "args": {"command": self.command},
            "command": self.command,
            "dialect": dialect,
            "outcome": "unknown",
            "tool_name": tool_name,
        }


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON number: {value}")


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


def required_id(value: object, code: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise ProjectionError(code)
    return value


def parse_json_line(line: str, *, location: str) -> dict[str, Any]:
    try:
        value = json.loads(line, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
    except (json.JSONDecodeError, UnicodeError, RecursionError, ValueError) as exc:
        raise ValueError(f"invalid JSON at {location}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"non-object JSON at {location}")
    return value


def jsonl_rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_SOURCE_FILE_BYTES:
        raise ValueError(f"unsafe or oversized SecEBL JSONL source: {path}")
    rows: list[dict[str, Any]] = []
    with path.open("rb") as handle:
        for line_number, raw in enumerate(handle, 1):
            if len(raw) > MAX_JSONL_LINE_BYTES:
                raise ValueError(f"oversized JSONL row at {path}:{line_number}")
            if not raw.strip():
                raise ValueError(f"blank JSONL row at {path}:{line_number}")
            try:
                line = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(f"invalid UTF-8 at {path}:{line_number}") from exc
            rows.append(parse_json_line(line, location=f"{path}:{line_number}"))
    return rows


def validate_manifest(root: Path) -> None:
    manifest = parse_json_line(
        (root / "examples/manifest.json").read_text(encoding="utf-8"), location="manifest"
    )
    if (
        set(manifest) != {"k8s", "linux", "note", "schema"}
        or manifest.get("schema") != "secebl_public_examples_manifest_v2"
    ):
        raise ValueError("unexpected SecEBL public manifest schema")
    for platform in ("linux", "k8s"):
        section = manifest.get(platform)
        expected = EXPECTED[platform]
        if not isinstance(section, Mapping):
            raise ValueError(f"missing manifest section: {platform}")
        observed = {
            "rows": section.get("rows"),
            "sessions": section.get("sessions"),
            "normal_operation": section.get("normal_rows"),
            "intrusion": section.get("intrusion_rows"),
        }
        if observed != expected:
            raise ValueError(f"SecEBL manifest count mismatch: {platform}")


def secret_literal(command: str) -> bool:
    if PEM.search(command) or AWS_ACCESS_KEY.search(command) or JWT.search(command) or URL_USERINFO.search(command):
        return True
    for pattern in (SECRET_ASSIGNMENT, SECRET_FLAG):
        for match in pattern.finditer(command):
            value = match.group(2) if match.group(1) else match.group(3)
            if not value or SAFE_SECRET_REFERENCE.fullmatch(value) is None:
                return True
    return False


def english_command(command: str) -> bool:
    return bool(re.search(r"[A-Za-z]", command)) and NON_ENGLISH_SCRIPT.search(command) is None


def exact_linux_proof(command: str, tags: frozenset[str]) -> str | None:
    """Return a closed-form pre-action proof name; never infer from session label alone."""
    lowered = command.lower()
    if REVERSE_SHELL_TAG in tags:
        dev_tcp = "/dev/tcp/" in lowered and re.search(r"\b(?:ba|z|k)?sh\s+-i\b", lowered)
        redirected = re.search(r"(?:>&|0>&1|2>&1|<>|>\s*/dev/tcp/)", lowered)
        fifo = "mkfifo " in lowered and re.search(r"\b(?:nc|ncat|netcat)\b", lowered) and " -i" in lowered
        netcat_exec = re.search(
            r"(?:^|[;&|]\s*)(?:sudo\s+)?(?:(?:/usr)?/bin/)?(?:nc|ncat|netcat)\b"
            r"[^\n;]*\s-e\s+/(?:bin/)?(?:ba|z|k)?sh\b",
            lowered,
        )
        if (dev_tcp and redirected) or fifo or netcat_exec:
            return "interactive_reverse_shell"
    if CREDENTIAL_UPLOAD_TAGS <= tags:
        has_upload_tool = re.search(r"(?:^|[;|&]\s*|\s)(?:curl|wget)\b", lowered)
        has_source_ref = re.search(
            r"(?:@|--upload-file(?:=|\s+)|-t\s+)/(?:[^\s'\"]+)", command, re.IGNORECASE
        )
        has_destination = re.search(
            r"https?://(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d+)?(?:[/\s'\"]|$)", command
        )
        if has_upload_tool and has_source_ref and has_destination:
            return "credential_file_external_upload"
    if tags & AUDIT_DELETE_TAGS:
        destructive = re.search(r"\b(?:truncate\s+-s\s+0|rm\s+-[a-z]*f|find\b[^;]*\s-delete\b)", lowered)
        audit_path = re.search(r"/var/log/(?:auth\.log|secure|wtmp|btmp|audit(?:/|\.log)|journal(?:/|\b))", lowered)
        if destructive and audit_path:
            return "audit_log_destruction"
    if "set_suid_permission" in tags:
        chmod_suid = re.search(r"\bchmod\s+(?:u\+s|4[0-7]{3})\s+(/(?:tmp|var/tmp|dev/shm)/[^\s'\"]+)", lowered)
        copied_shell = re.search(r"\bcp\s+/(?:usr/)?bin/(?:ba|z|k)?sh\s+/(?:tmp|var/tmp|dev/shm)/", lowered)
        if chmod_suid and (
            copied_shell or re.search(r"/(?:tmp|var/tmp|dev/shm)/", chmod_suid.group(1))
        ):
            return "temporary_setuid_executable"
    if {"modify_sudo_policy", "grant_user_privilege"} <= tags:
        compact = re.sub(r"\s+", "", lowered)
        if "nopasswd:all" in compact and "/etc/sudoers" in lowered:
            return "unrestricted_sudoers_grant"
    if "modify_audit_policy" in tags:
        compact = re.sub(r"\s+", "", lowered)
        if re.search(r"\bauditctl\s+-d\s+", lowered) or re.search(
            r"\bauditpol(?:\.exe)?\b.*?/success:disable", compact
        ):
            return "audit_policy_rule_deletion"
    return None


def project_pair(platform: str, sequence: int, session: Mapping[str, Any], gold: Mapping[str, Any]) -> Event:
    allowed_session = {"command", "expected", "platform", "session_id"}
    if platform == "linux":
        allowed_session.add("rev18_final_review")
    required_session = {"command", "expected", "platform", "session_id"}
    if not allowed_session.issuperset(session) or not required_session.issubset(session):
        raise ProjectionError("invalid_session_schema")
    required_gold = {
        "behavior_tags", "gold_id", "gold_sample_name", "platform", "raw", "review_notes", "review_status",
        "session_expected", "session_id", "source_row_index",
    }
    linux_optional = {
        "carried_over_from", "carried_over_gold_id", "review_count", "review_round", "reviewed_at", "reviewer",
        "source_benchmark",
    }
    allowed_gold = required_gold | (linux_optional if platform == "linux" else set())
    if not required_gold.issubset(gold) or not allowed_gold.issuperset(gold):
        raise ProjectionError("invalid_gold_schema")
    source_platform = "linux" if platform == "linux" else "k8s_audit"
    command = session.get("command")
    source_label = session.get("expected")
    session_id = required_id(session.get("session_id"), "invalid_session_id")
    gold_id = required_id(gold.get("gold_id"), "invalid_gold_id")
    if session.get("platform") != source_platform or gold.get("platform") != source_platform:
        raise ProjectionError("platform_mismatch")
    if (
        source_label not in {"normal_operation", "intrusion"}
        or gold.get("session_expected") != source_label
    ):
        raise ProjectionError("label_mismatch")
    if gold.get("session_id") != session_id or gold.get("raw") != command:
        raise ProjectionError("gold_join_mismatch")
    source_index = gold.get("source_row_index")
    if type(source_index) is not int or source_index < 1:
        raise ProjectionError("invalid_source_row_index")
    if (
        not isinstance(command, str)
        or not command
        or "\x00" in command
        or len(command.encode()) > MAX_COMMAND_BYTES
    ):
        raise ProjectionError("invalid_command")
    if not english_command(command):
        raise ProjectionError("non_english")
    if secret_literal(command):
        raise ProjectionError("embedded_secret_literal")
    raw_tags = gold.get("behavior_tags")
    if not isinstance(raw_tags, list) or len(raw_tags) > MAX_TAGS:
        raise ProjectionError("invalid_behavior_tags")
    tags: list[str] = []
    for tag in raw_tags:
        if not isinstance(tag, str) or SAFE_TAG.fullmatch(tag) is None:
            raise ProjectionError("invalid_behavior_tag")
        tags.append(tag)
    if len(tags) != len(set(tags)):
        raise ProjectionError("duplicate_behavior_tag")
    proof = (
        exact_linux_proof(command, frozenset(tags))
        if platform == "linux" and source_label == "intrusion"
        else None
    )
    return Event(platform, session_id, sequence, source_label, command, tuple(tags), gold_id, proof)


def load_events(root: Path) -> tuple[list[Event], Counter[str]]:
    validate_manifest(root)
    counts: Counter[str] = Counter()
    events: list[Event] = []
    seen_gold_ids: set[str] = set()
    for platform in ("linux", "k8s"):
        sessions = jsonl_rows(root / f"examples/{platform}/example_sessions.jsonl")
        gold = jsonl_rows(root / f"examples/{platform}/example_gold.rev20.jsonl")
        if len(sessions) != EXPECTED[platform]["rows"] or len(gold) != len(sessions):
            raise ValueError(f"unexpected SecEBL row count: {platform}")
        sequence_by_session: Counter[str] = Counter()
        labels_by_session: dict[str, str] = {}
        projected_by_session: dict[str, list[Event]] = defaultdict(list)
        rejected_sessions: set[str] = set()
        raw_counts: Counter[str] = Counter()
        for row_number, (session_row, gold_row) in enumerate(zip(sessions, gold, strict=True), 1):
            raw_session_id = session_row.get("session_id")
            if not isinstance(raw_session_id, str):
                raise ValueError(f"invalid SecEBL session identity: {platform}:{row_number}")
            raw_label = session_row.get("expected")
            if raw_label not in {"normal_operation", "intrusion"}:
                raise ValueError(f"invalid SecEBL source label: {platform}:{row_number}")
            raw_counts[str(raw_label)] += 1
            sequence_by_session[raw_session_id] += 1
            prior_label = labels_by_session.setdefault(raw_session_id, str(raw_label))
            if prior_label != raw_label:
                raise ValueError(f"mixed labels within SecEBL session: {raw_session_id}")
            try:
                event = project_pair(platform, sequence_by_session[raw_session_id], session_row, gold_row)
            except ProjectionError as exc:
                counts[f"quarantined_{exc.code}"] += 1
                rejected_sessions.add(raw_session_id)
                continue
            if event.gold_id in seen_gold_ids:
                raise ValueError(f"duplicate SecEBL gold ID: {event.gold_id}")
            seen_gold_ids.add(event.gold_id)
            projected_by_session[event.session_id].append(event)
        if len(labels_by_session) != EXPECTED[platform]["sessions"]:
            raise ValueError(f"unexpected SecEBL session count: {platform}")
        for label in ("normal_operation", "intrusion"):
            if raw_counts[label] != EXPECTED[platform][label]:
                raise ValueError(f"SecEBL label count mismatch: {platform}/{label}")
            counts[f"source_{platform}_{label}_rows"] = raw_counts[label]
        for session_id, projected in projected_by_session.items():
            if session_id in rejected_sessions:
                counts["quarantined_entire_session_after_row_rejection"] += len(projected)
                continue
            events.extend(projected)
    counts["source_rows"] = sum(EXPECTED[platform]["rows"] for platform in EXPECTED)
    counts["accepted_source_rows"] = len(events)
    return events, counts


def split_group(platform: str, session_id: str) -> str:
    return digest(DATASET_ID, platform, session_id)[:24]


def split_for(group: str) -> str:
    bucket = int.from_bytes(hashlib.sha256(group.encode()).digest()[:2], "big") % 100
    return "development" if bucket < 70 else "validation" if bucket < 85 else "test"


def event_truth(event: Event, *, stateful: bool) -> dict[str, Any]:
    categories = [
        "secebl_public_examples",
        "bounded_action_sequence" if stateful else "structured_tool_call",
        f"platform_{event.platform}",
        f"source_{event.source_label}",
    ]
    def lens(truth: dict[str, Any]) -> dict[str, Any]:
        if stateful:
            # These windows inherit only the terminal event's atomic label.
            # They are useful replay context, not independently adjudicated
            # bounded-chain positives or negatives.
            truth["stateful_lens"] = "atomic_terminal"
        return truth

    if event.source_label == "normal_operation":
        return lens({
            "applicability": "in_scope", "categories": categories + ["session_labeled_benign"],
            "deterministic_truth": "benign", "expected_disposition": "allow", "label_confidence": "medium",
            "label_source": "source:secebl_public_normal_operation_session", "source_truth": "benign",
        })
    if event.proof is not None:
        return lens({
            "applicability": "in_scope", "categories": categories + [event.proof],
            "deterministic_truth": "deterministic_malicious", "expected_disposition": "detect_only",
            "label_confidence": "high", "label_source": f"source:secebl_reviewed_exact_{event.proof}",
            "source_truth": "malicious",
        })
    reason = (
        "normalized Kubernetes event lacks authoritative API response status and result body"
        if event.platform == "k8s"
        else "session intrusion label and behavior tags do not prove this individual command is malicious"
    )
    return lens({
        "applicability": "out_of_scope", "categories": categories + ["contextual_session_label"],
        "deterministic_truth": "contextual_or_dual_use", "exclusion_reason": reason,
        "expected_disposition": "detect_only", "label_confidence": "medium",
        "label_source": "source:secebl_contextual_intrusion_session", "source_truth": "malicious",
    })


def normalize(events: Iterable[Event]) -> tuple[list[dict[str, Any]], Counter[str]]:
    counts: Counter[str] = Counter()
    by_session: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        by_session[(event.platform, event.session_id)].append(event)
    candidates: list[dict[str, Any]] = []
    for (platform, session_id), session_events in sorted(by_session.items()):
        ordered = sorted(session_events, key=lambda item: item.sequence)
        if len({event.source_label for event in ordered}) != 1:
            raise ValueError(f"mixed source labels within SecEBL session: {platform}/{session_id}")
        if [event.sequence for event in ordered] != list(range(1, len(ordered) + 1)):
            counts["quarantined_noncontiguous_session_after_filtering"] += len(ordered)
            continue
        group = split_group(platform, session_id)
        split = split_for(group)
        trajectory_id = digest(SOURCE_REVISION, platform, session_id)[:24]
        for index, event in enumerate(ordered):
            source = {
                "dataset": DATASET_ID, "license": SOURCE_LICENSE, "original_id": f"{platform}:{event.gold_id}",
                "redistribution": SOURCE_REDISTRIBUTION, "revision": SOURCE_REVISION,
            }
            common = {
                "campaign": f"{platform}:{event.source_label}", "dialect": "posix" if platform == "linux" else "none",
                "domain": "host_security" if platform == "linux" else "kubernetes_security",
                "ecosystem": "secebl", "hard_negative": event.source_label == "normal_operation",
                "language": "en", "platform": platform, "split_group": group, "trajectory_id": trajectory_id,
            }
            projected = event.detector_event()
            atomic_payload = {key: value for key, value in projected.items() if key != "outcome"}
            atomic_payload["direction"] = "tool_call"
            candidates.append({
                "id": f"secebl/{trajectory_id}/action-{event.sequence:05d}", "payload": atomic_payload,
                "schema_version": SCHEMA_VERSION, "source": source, "split": split,
                "strata": {**common, "call_index": index, "sequence_index": index}, "surface": "action",
                "truth": event_truth(event, stateful=False),
            })
            if index == 0:
                continue
            start = max(0, index - MAX_PREDECESSORS)
            window = [
                {**prior.detector_event(), "offset_seconds": offset}
                for offset, prior in enumerate(ordered[start : index + 1])
            ]
            candidates.append({
                "id": f"secebl/{trajectory_id}/current-{event.sequence:05d}",
                "payload": {"direction": "tool_call", "events": window},
                "schema_version": SCHEMA_VERSION, "source": source, "split": split,
                "strata": {**common, "call_index": index, "sequence_index": start}, "surface": "stateful",
                "truth": event_truth(event, stateful=True),
            })

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in candidates:
        groups[digest(case["surface"], canonical_json(case["payload"]))].append(case)
    cases: list[dict[str, Any]] = []
    for fingerprint in sorted(groups):
        group = sorted(groups[fingerprint], key=lambda item: item["id"])
        truth_keys = {
            (
                item["truth"].get("source_truth"),
                item["truth"].get("deterministic_truth"),
                item["truth"].get("applicability"),
            )
            for item in group
        }
        if len(truth_keys) != 1:
            counts["label_conflicts_excluded"] += len(group)
            continue
        cases.append(group[0])
        counts["exact_payload_duplicates_removed"] += len(group) - 1

    cases.sort(key=lambda case: case["id"])
    for case in cases:
        platform = case["strata"]["platform"]
        label = "normal_operation" if case["truth"]["source_truth"] == "benign" else "intrusion"
        scope = (
            "in_scope_benign" if case["truth"].get("deterministic_truth") == "benign"
            else "in_scope_deterministic_malicious"
            if case["truth"].get("deterministic_truth") == "deterministic_malicious"
            else "out_of_scope_contextual"
        )
        counts["cases"] += 1
        counts[f"cases_{platform}_{label}"] += 1
        counts[f"cases_{case['surface']}"] += 1
        counts[f"cases_{case['split']}"] += 1
        counts[f"scope_{scope}"] += 1
        counts[f"scope_{platform}_{scope}"] += 1
        counts[f"scope_{label}_{scope}"] += 1
        counts[f"scope_{case['surface']}_{scope}"] += 1
        for category in case["truth"].get("categories", []):
            if category in {
                "interactive_reverse_shell", "credential_file_external_upload", "audit_log_destruction",
                "temporary_setuid_executable", "unrestricted_sudoers_grant", "audit_policy_rule_deletion",
            }:
                counts[f"proof_{category}"] += 1
    return cases, counts


def source_bundle_identity(root: Path) -> tuple[int, str]:
    total = 0
    result = hashlib.sha256()
    for relative in SOURCE_FILES:
        path = root / relative
        if (
            not path.is_file()
            or path.is_symlink()
            or path.stat().st_size > MAX_SOURCE_FILE_BYTES
            or total + path.stat().st_size > SOURCE_BUNDLE_BYTES
        ):
            raise ValueError(f"unsafe or missing SecEBL source: {path}")
        body = path.read_bytes()
        total += len(body)
        result.update(relative.encode())
        result.update(b"\0")
        result.update(body)
        result.update(b"\0")
    return total, result.hexdigest()


def validate_cases(cases: Iterable[dict[str, Any]], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError("jsonschema is required to validate SecEBL cases") from exc
    validator = jsonschema.Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")))
    seen_ids: set[str] = set()
    group_splits: dict[str, str] = {}
    for case in cases:
        case_id = case["id"]
        if case_id in seen_ids:
            raise ValueError(f"duplicate case ID: {case_id}")
        seen_ids.add(case_id)
        errors = sorted(validator.iter_errors(case), key=lambda error: list(error.absolute_path))
        if errors:
            where = ".".join(str(item) for item in errors[0].absolute_path) or "<root>"
            raise ValueError(f"{case_id}:{where}: {errors[0].message}")
        group = case["strata"]["split_group"]
        if group_splits.setdefault(group, case["split"]) != case["split"]:
            raise ValueError(f"{case_id}: session crosses splits")
        if (
            case["strata"]["platform"] == "k8s"
            and case["truth"].get("deterministic_truth") == "deterministic_malicious"
        ):
            raise ValueError(f"{case_id}: Kubernetes examples cannot become headline TP truth")
        if case["surface"] == "stateful" and not 2 <= len(case["payload"]["events"]) <= MAX_EVENTS:
            raise ValueError(f"{case_id}: unbounded stateful window")
        serialized = canonical_json(case)
        if secret_literal(serialized):
            raise ValueError(f"{case_id}: output contains a secret-shaped literal")


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--revision", default=SOURCE_REVISION)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.revision != SOURCE_REVISION:
        raise ValueError("SecEBL revision must match the pinned dataset lock")
    source_bytes, source_sha256 = source_bundle_identity(args.input_dir)
    if (source_bytes, source_sha256) != (SOURCE_BUNDLE_BYTES, SOURCE_BUNDLE_SHA256):
        raise ValueError("pinned SecEBL selected-source bundle identity mismatch")
    events, source_counts = load_events(args.input_dir)
    cases, counts = normalize(events)
    counts.update(source_counts)
    validate_cases(cases, args.schema)
    body = "".join(canonical_json(case) + "\n" for case in cases).encode()
    manifest = {
        "adapter_statistics": {ADAPTER: dict(sorted(counts.items()))}, "cases": len(cases),
        "counts": {DATASET_ID: len(cases)}, "datasets": [DATASET_ID],
        "exact_payload_duplicates_removed": counts["exact_payload_duplicates_removed"],
        "label_conflicts_excluded": counts["label_conflicts_excluded"],
        "output_sha256": hashlib.sha256(body).hexdigest(), "schema_version": SCHEMA_VERSION,
        "source": {
            "bytes": source_bytes, "dataset": DATASET_ID,
            "license": SOURCE_LICENSE, "path": "examples/{linux,k8s}/{example_sessions,example_gold.rev20}.jsonl",
            "redistribution": SOURCE_REDISTRIBUTION, "revision": SOURCE_REVISION,
            "sha256": source_sha256,
        },
    }
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    atomic_write(args.output, body)
    atomic_write(manifest_path, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({"manifest": str(manifest_path), "output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
