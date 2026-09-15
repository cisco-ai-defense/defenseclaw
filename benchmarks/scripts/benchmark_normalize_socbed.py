#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize execution-backed SOCBED process telemetry conservatively.

The adapter pairs ``run_attack`` and ``attack_succeeded`` records from the
attack-console log, then considers only Sysmon process-start events inside the
paired interval.  A process is an applicable malicious case only when its
concrete process arguments also match an allowlisted identity supplied by that
same paired run (currently an executed artifact path or an autorun value/name).
All other telemetry in a successful attack interval is contextual and never a
benign negative.  No attack-console labels, descriptions, or raw results enter
detector payloads.

Both the original ``dataset.zip`` and selectively extracted run directories are
accepted.  Zip members are streamed and never unpacked by this program.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import zipfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

SCHEMA_VERSION = "1"
DATASET = "fkie-cad/socbed-eval-acsac-2021"
SOURCE_URL = "https://github.com/fkie-cad/socbed-eval-acsac-2021"
SOURCE_REVISION = "c264060f0e65ea69c2d891525ae835a543f851ca"
SOURCE_LICENSE = "MIT"
REDISTRIBUTION = "download-only"
ADAPTER = "socbed-v1"
PRE_PARTITION_SPLIT = "smoke"

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"

MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_SELECTED_BYTES = 2 * 1024 * 1024 * 1024
MAX_LINE_BYTES = 8 * 1024 * 1024
MAX_COMMAND_BYTES = 1024 * 1024
MAX_ARG_BYTES = 64 * 1024
MAX_ARGV = 4096
MAX_DEPTH = 24
MAX_ITEMS = 4096
MAX_INTERVAL_SECONDS = 300
MAX_PREDECESSORS = 8
MAX_EVENTS = MAX_PREDECESSORS + 1

RUN_RE = re.compile(r"^(?P<timestamp>\S+)\s+\S+\s+\S+\s+\[(?P<fields>[^\]]+)\]\s+(?:Run attack|Attack succeeded)\s*$")
FIELD_RE = re.compile(r'(?P<key>[A-Za-z][A-Za-z0-9_]*)="(?P<value>(?:\\.|[^"\\])*)"')
IPV4_RE = re.compile(r"(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9])")
URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s'\"]+")
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
SECRET_OPTION_RE = re.compile(
    r"(?i)(?P<prefix>(?:--?(?:password|passwd|token|secret|api[_-]?key)|/p(?:assword)?)\s*[=:]?\s*)"
    r"(?P<value>[^\s'\"]+|['\"][^'\"]+['\"])"
)
ASSIGNMENT_SECRET_RE = re.compile(r"(?i)\b(?P<key>password|passwd|token|secret|api[_-]?key)=(?P<value>[^\s&;]+)")


class ProjectionError(ValueError):
    """Source material cannot be projected without ambiguity."""


@dataclass(frozen=True)
class AttackInterval:
    member: str
    ordinal: int
    attack: str
    started: datetime
    succeeded: datetime
    attributes: Mapping[str, str]


@dataclass(frozen=True)
class ProcessEvent:
    member: str
    line_number: int
    timestamp: datetime
    host_ref: str
    identity: str
    parent_identity: str | None
    executable: str
    name: str
    argv: tuple[str, ...]
    command: str
    cwd: str | None
    artifact_sha256: str | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="SOCBED dataset.zip or extracted directory")
    parser.add_argument("--revision", default=SOURCE_REVISION)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    return parser.parse_args()


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")


def digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ProjectionError("invalid_timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProjectionError("invalid_timestamp") from exc
    if parsed.tzinfo is None:
        raise ProjectionError("naive_timestamp")
    return parsed.astimezone(timezone.utc)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProjectionError("duplicate_json_key")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise ProjectionError(f"non_finite_json:{value}")


def validate_shape(value: object, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ProjectionError("maximum_json_depth_exceeded")
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_COMMAND_BYTES:
            raise ProjectionError("oversized_source_string")
    elif isinstance(value, Mapping):
        if len(value) > MAX_ITEMS:
            raise ProjectionError("too_many_object_members")
        for key, child in value.items():
            if not isinstance(key, str):
                raise ProjectionError("non_string_object_key")
            validate_shape(child, depth + 1)
    elif isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise ProjectionError("too_many_array_items")
        for child in value:
            validate_shape(child, depth + 1)


def safe_member_name(name: str) -> str:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or len(name) > 4096:
        raise ValueError(f"unsafe source member: {name}")
    return path.as_posix()


class Source:
    def __init__(self, root: Path):
        self.root = root.resolve(strict=True)
        self.archive: zipfile.ZipFile | None = None
        if self.root.is_file():
            if self.root.stat().st_size > MAX_ARCHIVE_BYTES:
                raise ValueError("SOCBED archive exceeds size bound")
            if not zipfile.is_zipfile(self.root):
                raise ValueError("input file is not a ZIP archive")
            self.archive = zipfile.ZipFile(self.root)
        elif not self.root.is_dir():
            raise ValueError("input must be a ZIP archive or directory")

    def close(self) -> None:
        if self.archive is not None:
            self.archive.close()

    def __enter__(self) -> Source:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def members(self) -> list[str]:
        if self.archive is not None:
            selected: list[str] = []
            total = 0
            for info in self.archive.infolist():
                name = safe_member_name(info.filename)
                if info.is_dir() or not relevant_member(name):
                    continue
                if info.file_size > MAX_MEMBER_BYTES or info.compress_size > MAX_MEMBER_BYTES:
                    raise ValueError(f"oversized selected source member: {name}")
                total += info.file_size
                if total > MAX_SELECTED_BYTES:
                    raise ValueError("selected source members exceed total size bound")
                selected.append(name)
            return sorted(selected)
        selected = []
        total = 0
        for path in self.root.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            relative = safe_member_name(path.relative_to(self.root).as_posix())
            if relevant_member(relative):
                if path.stat().st_size > MAX_MEMBER_BYTES:
                    raise ValueError(f"oversized selected source member: {relative}")
                total += path.stat().st_size
                if total > MAX_SELECTED_BYTES:
                    raise ValueError("selected source members exceed total size bound")
                selected.append(relative)
        return sorted(selected)

    def open(self, member: str) -> BinaryIO:
        safe_member_name(member)
        if self.archive is not None:
            return self.archive.open(member)
        path = (self.root / member).resolve(strict=True)
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("source member escapes input root") from exc
        if path.is_symlink():
            raise ValueError("source member must not be a symlink")
        return path.open("rb")

    def metadata(self, members: Sequence[str]) -> dict[str, object]:
        if self.archive is not None:
            size = self.root.stat().st_size
            value = hashlib.sha256()
            with self.root.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    value.update(chunk)
            path = self.root.name
        else:
            value = hashlib.sha256()
            size = 0
            for member in members:
                value.update(member.encode("utf-8") + b"\0")
                with self.open(member) as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        size += len(chunk)
                        value.update(chunk)
            path = self.root.name
        return {
            "dataset": DATASET,
            "revision": SOURCE_REVISION,
            "license": SOURCE_LICENSE,
            "redistribution": REDISTRIBUTION,
            "path": path,
            "bytes": size,
            "sha256": value.hexdigest(),
        }


def relevant_member(name: str) -> bool:
    basename = PurePosixPath(name).name
    return bool(re.fullmatch(r"attackconsole_\d\d\.log", basename) or re.fullmatch(r"winlogbeat_\d\d\.jsonl", basename))


def paired_member(member: str, prefix: str) -> str:
    path = PurePosixPath(member)
    match = re.fullmatch(r"(?:attackconsole|winlogbeat)_(\d\d)\.(?:log|jsonl)", path.name)
    if match is None:
        raise ValueError("invalid SOCBED run member")
    suffix = ".log" if prefix == "attackconsole" else ".jsonl"
    return (path.parent / f"{prefix}_{match.group(1)}{suffix}").as_posix()


def parse_console_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in FIELD_RE.finditer(text):
        key = match.group("key")
        if key in fields:
            raise ProjectionError("duplicate_console_field")
        value = match.group("value")
        if len(value.encode("utf-8")) > MAX_ARG_BYTES:
            raise ProjectionError("oversized_console_field")
        fields[key] = value
    if not fields or fields.get("event") not in {"run_attack", "attack_succeeded"}:
        raise ProjectionError("unsupported_console_event")
    return fields


def read_attack_intervals(handle: BinaryIO, member: str, stats: Counter[str]) -> list[AttackInterval]:
    pending: tuple[datetime, str, dict[str, str]] | None = None
    intervals: list[AttackInterval] = []
    for line_number, raw in enumerate(handle, 1):
        stats["console_lines"] += 1
        if len(raw) > MAX_LINE_BYTES:
            stats["malformed_console_lines"] += 1
            pending = None
            continue
        try:
            line = raw.decode("utf-8", errors="strict").rstrip("\r\n")
            match = RUN_RE.fullmatch(line)
            if match is None:
                continue
            fields = parse_console_fields(match.group("fields"))
            timestamp = parse_timestamp(match.group("timestamp"))
            attack = fields.get("attack")
            if not attack or len(attack) > 120:
                raise ProjectionError("invalid_attack_identity")
        except (ProjectionError, UnicodeDecodeError):
            stats["malformed_console_lines"] += 1
            pending = None
            continue
        attributes = {key: value for key, value in fields.items() if key not in {"event", "attack"}}
        if fields["event"] == "run_attack":
            if pending is not None:
                stats["unpaired_attack_runs"] += 1
            pending = (timestamp, attack, attributes)
            continue
        if pending is None:
            stats["orphan_attack_successes"] += 1
            continue
        started, pending_attack, pending_attributes = pending
        pending = None
        if (
            pending_attack != attack
            or pending_attributes != attributes
            or timestamp < started
            or (timestamp - started).total_seconds() > MAX_INTERVAL_SECONDS
        ):
            stats["ambiguous_attack_pairs"] += 1
            continue
        intervals.append(AttackInterval(member, len(intervals), attack, started, timestamp, attributes))
        stats["successful_attack_intervals"] += 1
    if pending is not None:
        stats["unpaired_attack_runs"] += 1
    return intervals


def bounded_string(value: object, field: str, maximum: int = MAX_ARG_BYTES) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ProjectionError(f"invalid_{field}")
    return value


def process_event(row: Mapping[str, Any], member: str, line_number: int) -> ProcessEvent | None:
    event = row.get("event")
    process = row.get("process")
    if not isinstance(event, Mapping) or event.get("code") not in {1, "1"} or not isinstance(process, Mapping):
        return None
    timestamp = parse_timestamp(row.get("@timestamp"))
    identity_raw = bounded_string(process.get("entity_id"), "process_identity", 512)
    executable = bounded_string(process.get("executable"), "process_executable", 4096)
    name = bounded_string(process.get("name"), "process_name", 512)
    command = bounded_string(process.get("command_line"), "command", MAX_COMMAND_BYTES)
    argv_raw = process.get("args")
    if not isinstance(argv_raw, list) or not argv_raw or len(argv_raw) > MAX_ARGV:
        raise ProjectionError("invalid_process_argv")
    argv = tuple(bounded_string(item, "argv", MAX_ARG_BYTES) for item in argv_raw)
    parent = process.get("parent")
    parent_raw = parent.get("entity_id") if isinstance(parent, Mapping) else None
    parent_identity = (
        digest("socbed-process", str(parent_raw))[:24] if isinstance(parent_raw, str) and parent_raw else None
    )
    host = row.get("host")
    host_name = (
        host.get("name")
        if isinstance(host, Mapping)
        else row.get("agent", {}).get("hostname")
        if isinstance(row.get("agent"), Mapping)
        else None
    )
    host_ref = digest("socbed-host", bounded_string(host_name, "host", 512))[:24]
    cwd_raw = process.get("working_directory")
    cwd = bounded_string(cwd_raw, "cwd", 4096) if isinstance(cwd_raw, str) and cwd_raw else None
    process_hash = process.get("hash")
    sha256 = process_hash.get("sha256") if isinstance(process_hash, Mapping) else None
    artifact_sha256 = sha256.lower() if isinstance(sha256, str) and re.fullmatch(r"[0-9A-Fa-f]{64}", sha256) else None
    return ProcessEvent(
        member=member,
        line_number=line_number,
        timestamp=timestamp,
        host_ref=host_ref,
        identity=digest("socbed-process", identity_raw)[:24],
        parent_identity=parent_identity,
        executable=executable,
        name=name,
        argv=argv,
        command=command,
        cwd=cwd,
        artifact_sha256=artifact_sha256,
    )


def read_process_events(
    handle: BinaryIO, member: str, intervals: Sequence[AttackInterval], stats: Counter[str]
) -> list[ProcessEvent]:
    if not intervals:
        return []
    earliest = min(item.started for item in intervals) - timedelta(seconds=1)
    latest = max(item.succeeded for item in intervals) + timedelta(seconds=1)
    result: list[ProcessEvent] = []
    for line_number, raw in enumerate(handle, 1):
        stats["telemetry_lines"] += 1
        if not raw.strip() or len(raw) > MAX_LINE_BYTES:
            stats["malformed_telemetry_lines"] += 1
            continue
        try:
            row = json.loads(raw, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
            validate_shape(row)
            if not isinstance(row, Mapping):
                raise ProjectionError("telemetry_not_object")
            event = process_event(row, member, line_number)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ProjectionError):
            stats["malformed_telemetry_lines"] += 1
            continue
        if event is None:
            continue
        stats["process_start_events"] += 1
        if earliest <= event.timestamp <= latest and any(
            interval.started - timedelta(seconds=1) <= event.timestamp <= interval.succeeded + timedelta(seconds=1)
            for interval in intervals
        ):
            result.append(event)
    return result


def normalized_windows_value(value: str) -> str:
    return value.strip(" '\"").replace("/", "\\").casefold()


def exact_attack_proof(interval: AttackInterval, event: ProcessEvent) -> str | None:
    executable = normalized_windows_value(event.executable)
    argv = [normalized_windows_value(item) for item in event.argv]
    command = normalized_windows_value(event.command)
    if interval.attack == "misc_execute_malware":
        artifact = interval.attributes.get("file")
        if artifact:
            expected = normalized_windows_value(artifact)
            basename = PurePosixPath(expected.replace("\\", "/")).name
            if executable == expected and (argv[0] == expected or normalized_windows_value(event.name) == basename):
                return "executed_artifact"
    if interval.attack == "misc_set_autostart":
        data = interval.attributes.get("data")
        name = interval.attributes.get("name")
        if data and name and normalized_windows_value(event.name) == "reg.exe":
            expected_data = normalized_windows_value(data)
            expected_name = normalized_windows_value(name)
            if (
                re.search(r"(?:^|\s)reg(?:\.exe)?\s+add(?:\s|$)", command)
                and "hklm\\software\\microsoft\\windows\\currentversion\\run" in command
                and expected_data in argv
                and expected_name in argv
            ):
                return "autorun_registry_write"
    return None


def interval_for_event(event: ProcessEvent, intervals: Sequence[AttackInterval]) -> AttackInterval | None:
    matches = [
        interval
        for interval in intervals
        if interval.started - timedelta(seconds=1) <= event.timestamp <= interval.succeeded + timedelta(seconds=1)
    ]
    return matches[0] if len(matches) == 1 else None


def redact(value: str) -> str:
    value = URL_RE.sub("<target-url>", value)
    value = EMAIL_RE.sub("<target-email>", value)
    value = IPV4_RE.sub("<target-ip>", value)
    value = SECRET_OPTION_RE.sub(lambda match: f"{match.group('prefix')}<sensitive>", value)
    value = ASSIGNMENT_SECRET_RE.sub(lambda match: f"{match.group('key')}=<sensitive>", value)
    return value


def redact_argv(argv: Sequence[str]) -> list[str]:
    result: list[str] = []
    redact_next = False
    for value in argv:
        if redact_next:
            result.append("<sensitive>")
            redact_next = False
            continue
        projected = redact(value)
        result.append(projected)
        if re.fullmatch(r"(?i)--?(?:password|passwd|token|secret|api[_-]?key)|/p(?:assword)?", value):
            redact_next = True
    return result


def dialect(event: ProcessEvent) -> str:
    lowered = event.name.casefold()
    if lowered in {"powershell.exe", "pwsh.exe"}:
        return "powershell"
    return "cmd"


def event_payload(event: ProcessEvent, *, stateful: bool = False, offset: int = 0) -> dict[str, Any]:
    args: dict[str, Any] = {
        "timestamp": event.timestamp.isoformat().replace("+00:00", "Z"),
        "host_ref": event.host_ref,
        "process_ref": event.identity,
        "process_image": redact(event.executable),
        "process_name": event.name,
    }
    if event.parent_identity:
        args["parent_process_ref"] = event.parent_identity
    if event.artifact_sha256:
        args["artifact_sha256"] = event.artifact_sha256
    result: dict[str, Any] = {
        "tool_name": "windows.process_start",
        "command": redact(event.command),
        "argv": redact_argv(event.argv),
        "args": args,
        "dialect": dialect(event),
    }
    if event.cwd:
        result["cwd"] = redact(event.cwd)
    if stateful:
        result["outcome"] = "succeeded"
        result["offset_seconds"] = offset
    return result


def truth(proof: str | None) -> dict[str, Any]:
    if proof is not None:
        return {
            "source_truth": "malicious",
            "deterministic_truth": "deterministic_malicious",
            "label_confidence": "high",
            "label_source": "socbed:paired-execution-outcome-v1",
            "applicability": "in_scope",
            "expected_disposition": "block",
            "categories": ["execution-grounded", "successful-attack", proof],
        }
    return {
        "source_truth": "unknown",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "high",
        "label_source": "socbed:successful-interval-context-v1",
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "categories": ["execution-grounded", "successful-interval-context"],
        "exclusion_reason": "successful_attack_interval_without_exact_action_identity_linkage",
    }


def ancestors(current: ProcessEvent, events: Sequence[ProcessEvent]) -> list[ProcessEvent]:
    by_identity = {event.identity: event for event in events if event.timestamp <= current.timestamp}
    chain: list[ProcessEvent] = []
    seen = {current.identity}
    parent = current.parent_identity
    while parent and parent not in seen and len(chain) < MAX_PREDECESSORS:
        candidate = by_identity.get(parent)
        if candidate is None or candidate.host_ref != current.host_ref or candidate.timestamp > current.timestamp:
            break
        chain.append(candidate)
        seen.add(parent)
        parent = candidate.parent_identity
    chain.reverse()
    return chain


def source_record(revision: str, original_id: str) -> dict[str, str]:
    return {
        "dataset": DATASET,
        "revision": revision,
        "original_id": original_id[:240],
        "license": SOURCE_LICENSE,
        "redistribution": REDISTRIBUTION,
    }


def base_case(
    event: ProcessEvent, interval: AttackInterval, revision: str, suffix: str, proof: str | None
) -> dict[str, Any]:
    run_ref = digest("socbed-run", interval.member, str(interval.ordinal))[:24]
    case_ref = digest("socbed-case", event.member, str(event.line_number), suffix)[:32]
    return {
        "schema_version": SCHEMA_VERSION,
        "id": f"socbed/{case_ref}",
        "source": source_record(revision, f"{event.member}:{event.line_number}:{suffix}"),
        "split": PRE_PARTITION_SPLIT,
        "truth": truth(proof),
        "strata": {
            "platform": "windows",
            "dialect": dialect(event),
            "language": "english",
            "ecosystem": "endpoint-telemetry",
            "campaign": "executed-security-simulation",
            "domain": "endpoint-security",
            "hard_negative": False,
            "split_group": run_ref,
            "trajectory_id": run_ref,
            "sequence_index": event.line_number,
            "call_index": 0,
        },
    }


def deduplicate(rows: Sequence[dict[str, Any]], stats: Counter[str]) -> list[dict[str, Any]]:
    chosen: dict[bytes, dict[str, Any]] = {}
    labels: dict[bytes, str] = {}
    conflicts: set[bytes] = set()
    for row in sorted(rows, key=lambda item: str(item["id"])):
        key = canonical_json({"surface": row["surface"], "payload": row["payload"]})
        label = str(row["truth"]["deterministic_truth"])
        if key in labels and labels[key] != label:
            conflicts.add(key)
            continue
        if key in chosen:
            stats["exact_payload_duplicates_removed"] += 1
            continue
        chosen[key] = row
        labels[key] = label
    for key in conflicts:
        chosen.pop(key, None)
    stats["label_conflicts_excluded"] += len(conflicts)
    return sorted(chosen.values(), key=lambda item: str(item["id"]))


def build_corpus(
    run_data: Sequence[tuple[str, Sequence[AttackInterval], Sequence[ProcessEvent]]],
    *,
    revision: str,
    stats: Counter[str],
    source_metadata: Mapping[str, object] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if revision != SOURCE_REVISION:
        raise ValueError("SOCBED revision must match the pinned source revision")
    rows: list[dict[str, Any]] = []
    for _, intervals, events in run_data:
        ordered = sorted(events, key=lambda item: (item.timestamp, item.identity, item.line_number))
        for event in ordered:
            interval = interval_for_event(event, intervals)
            if interval is None:
                stats["ambiguous_or_unlinked_interval_events"] += 1
                continue
            proof = exact_attack_proof(interval, event)
            base = base_case(event, interval, revision, "action", proof)
            base["surface"] = "action"
            base["payload"] = {"direction": "tool_call", **event_payload(event)}
            rows.append(base)
            stats["deterministic_atomic_cases" if proof else "contextual_action_cases"] += 1
            if proof is None:
                continue
            prior = ancestors(event, ordered)
            if not prior:
                continue
            window = [*prior[-MAX_PREDECESSORS:], event]
            start = window[0].timestamp
            stateful = base_case(event, interval, revision, "chain", proof)
            stateful["surface"] = "stateful"
            stateful["payload"] = {
                "direction": "tool_call",
                "events": [
                    event_payload(item, stateful=True, offset=int((item.timestamp - start).total_seconds()))
                    for item in window
                ],
            }
            stateful["truth"]["categories"] = [*stateful["truth"]["categories"], "exact-process-lineage"]
            rows.append(stateful)
            stats["deterministic_stateful_cases"] += 1

    rows = deduplicate(rows, stats)
    output = b"".join(canonical_json(row) for row in rows)
    stats["cases"] = len(rows)
    stats["run_groups"] = len({row["strata"]["split_group"] for row in rows})
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "datasets": [DATASET],
        "cases": len(rows),
        "counts": {DATASET: len(rows)},
        "exact_payload_duplicates_removed": int(stats["exact_payload_duplicates_removed"]),
        "label_conflicts_excluded": int(stats["label_conflicts_excluded"]),
        "adapter_statistics": {ADAPTER: {key: int(value) for key, value in sorted(stats.items())}},
        "output_sha256": hashlib.sha256(output).hexdigest(),
    }
    if source_metadata is not None:
        manifest["source"] = dict(source_metadata)
    return rows, manifest


def normalize(root: Path, *, revision: str = SOURCE_REVISION) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    stats: Counter[str] = Counter()
    run_data: list[tuple[str, Sequence[AttackInterval], Sequence[ProcessEvent]]] = []
    with Source(root) as source:
        members = source.members()
        source_metadata = source.metadata(members)
        member_set = set(members)
        stats["selected_source_members"] = len(members)
        for console_member in [name for name in members if PurePosixPath(name).name.startswith("attackconsole_")]:
            telemetry_member = paired_member(console_member, "winlogbeat")
            if telemetry_member not in member_set:
                stats["runs_missing_telemetry"] += 1
                continue
            with source.open(console_member) as handle:
                intervals = read_attack_intervals(handle, console_member, stats)
            with source.open(telemetry_member) as handle:
                events = read_process_events(handle, telemetry_member, intervals, stats)
            run_data.append((console_member, intervals, events))
            stats["runs_read"] += 1
    return build_corpus(run_data, revision=revision, stats=stats, source_metadata=source_metadata)


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path = DEFAULT_SCHEMA) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for row in rows:
        validator.validate(row)


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    args = parse_args()
    rows, manifest = normalize(args.input, revision=args.revision)
    validate_cases(rows, args.schema)
    output = b"".join(canonical_json(row) for row in rows)
    atomic_write(args.output, output)
    atomic_write(args.manifest, json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    print(json.dumps({"cases": len(rows), "output_sha256": manifest["output_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
