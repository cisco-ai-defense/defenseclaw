#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize a small, execution-backed slice of OTRF Security-Datasets.

The adapter intentionally accepts only six audited archives from one pinned
revision. Dataset membership supplies adversarial source truth, but never an
applicable positive by itself. Applicable cases additionally require a closed
operation whose maliciousness is visible in the emitted detector payload: a
full NTDS IFM export or an exact EventLog-service disablement. Successful
execution alone cannot turn an opaque PID dump, firewall exception, padded
file, or attack-window process chain into universal deterministic truth. Those
records remain contextual and are never treated as benign.

Only detector-relevant commands are emitted. Metadata titles, ATT&CK labels,
free-form messages, users, hosts, raw destinations, and outcomes used for
labeling are excluded from detector payloads.
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
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, NamedTuple

SCHEMA_VERSION = "1"
DATASET = "OTRF/Security-Datasets"
SOURCE_URL = "https://github.com/OTRF/Security-Datasets"
SOURCE_REVISION = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
SOURCE_LICENSE = "MIT"
REDISTRIBUTION = "download-only"
ADAPTER = "otrf-security-selective-v1"
PRE_PARTITION_SPLIT = "smoke"

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 2 * 1024 * 1024
MAX_COMMAND_BYTES = 32 * 1024
MAX_EVENTS = 9  # current event plus at most eight predecessors
MAX_WINDOW_SECONDS = 1800

IPV4_RE = re.compile(r"(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9])")
USER_PATH_RE = re.compile(r"(?i)([A-Z]:\\Users\\)[^\\\s\"']+")
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
ATTACK_ID_RE = re.compile(r"(?i)(?<![A-Za-z0-9])T\d{4}(?:\.\d{3})?(?![A-Za-z0-9])")
FIREWALL_RULE_RE = re.compile(r'(?i)(\bname\s*=\s*)"[^"\r\n]{1,160}"')
AUDIT_ID_RE = re.compile(r"audit\((?P<seconds>\d+)(?:\.\d+)?:\d+\)")
AUDIT_FIELD_RE = re.compile(r'(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>"(?:[^"\\]|\\.)*"|\S+)')


class ArchiveSpec(NamedTuple):
    key: str
    path: str
    member: str
    sha256: str
    parser: str
    platform: str


ARCHIVES = (
    ArchiveSpec(
        "windows-ntdsutil",
        "datasets/atomic/windows/credential_access/host/cmd_dumping_ntds_dit_file_ntdsutil.zip",
        "cmd_dumping_ntds_dit_file_ntdsutil.json",
        "4633882ab1e9eadd156b29a89a5a6e24b680ead1b11ee259fdbe0d19ddbf77cf",
        "windows_json",
        "windows",
    ),
    ArchiveSpec(
        "windows-lsass-comsvcs",
        "datasets/atomic/windows/credential_access/host/psh_lsass_memory_dump_comsvcs.zip",
        "psh_lsass_memory_dump_comsvcs_2020-10-18T19500924.json",
        "0af9e920220d746432f0972be83ad057629695540aecd68c15869d190786e1ae",
        "windows_json",
        "windows",
    ),
    ArchiveSpec(
        "windows-eventlog-start",
        "datasets/atomic/windows/defense_evasion/host/cmd_disable_eventlog_service_startuptype_modification_via_registry.zip",
        "cmd_disable_eventlog_service_startuptype_modification_via_registry.json",
        "4312946d5bb0883e691da3b1130d4179b951a413278b450a75c05d56a2858a1a",
        "windows_json",
        "windows",
    ),
    ArchiveSpec(
        "windows-firewall-open",
        "datasets/atomic/windows/defense_evasion/host/cmd_netsh_fw_mod_open_ports.zip",
        "cmd_netsh_fw_mod_open_ports_2020-10-2100191105.json",
        "3d887b38c6a92892f950029f40114fe4598a798ad20453671dbe3d111b9ce4a2",
        "windows_json",
        "windows",
    ),
    ArchiveSpec(
        "linux-dd-padding",
        "datasets/atomic/linux/defense_evasion/host/sh_binary_padding_dd.zip",
        "sh_binary_padding_dd_2020-11-10081941.log",
        "dbba0766a0ea4e0e90f1eef8bbe3e2c819d1349a9f9081b6d54fa86ecb1d39bc",
        "linux_audit",
        "linux",
    ),
    ArchiveSpec(
        "linux-log4shell-chain",
        "datasets/compound/Log4Shell/syslog_auoms_auditd_log4shell_cve2021_44228_jndi_reference.zip",
        "syslog_auoms_auditd_log4shell_cve2021_44228_jndi_reference_2022-05-11181020.json",
        "20ca2d3371daca5bff0e6e1ede0c74c6f4df5c8696f959e5bbafb6f058a1b724",
        "auoms_json",
        "linux",
    ),
)


class ProjectionError(ValueError):
    """An untrusted source record cannot be projected safely."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--revision", default=SOURCE_REVISION)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    return parser.parse_args()


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProjectionError("duplicate_json_key")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise ProjectionError(f"non_finite_json:{value}")


def parse_json_line(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_LINE_BYTES:
        raise ProjectionError("oversized_json_line")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=strict_object,
            parse_constant=reject_nonfinite,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise ProjectionError("invalid_json_line") from exc
    if not isinstance(value, dict):
        raise ProjectionError("json_record_not_object")
    return value


def safe_archive_path(root: Path, relative: str) -> Path:
    path = root.joinpath(*PurePosixPath(relative).parts)
    if path.is_symlink() or not path.is_file():
        raise ProjectionError(f"missing_archive:{relative}")
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ProjectionError(f"oversized_archive:{relative}")
    return path


def read_member(root: Path, spec: ArchiveSpec) -> bytes:
    archive = safe_archive_path(root, spec.path)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != spec.sha256:
        raise ProjectionError(f"archive_digest_mismatch:{spec.key}")
    with zipfile.ZipFile(archive) as handle:
        members = [
            item for item in handle.infolist() if not item.is_dir() and not item.filename.startswith("__MACOSX/")
        ]
        if len(members) != 1 or members[0].filename != spec.member:
            raise ProjectionError(f"unexpected_archive_members:{spec.key}")
        member = members[0]
        member_path = PurePosixPath(member.filename)
        if member_path.is_absolute() or ".." in member_path.parts or member.file_size > MAX_MEMBER_BYTES:
            raise ProjectionError(f"unsafe_archive_member:{spec.key}")
        with handle.open(member) as source:
            data = source.read(MAX_MEMBER_BYTES + 1)
        if len(data) > MAX_MEMBER_BYTES:
            raise ProjectionError(f"oversized_archive_member:{spec.key}")
        return data


def clean_command(command: object) -> str:
    if not isinstance(command, str):
        raise ProjectionError("missing_command")
    value = command.strip().replace("\x00", "")
    if not value or len(value.encode("utf-8")) > MAX_COMMAND_BYTES:
        raise ProjectionError("invalid_command")
    value = USER_PATH_RE.sub(r"\1<user>", value)
    value = IPV4_RE.sub("<ipv4>", value)
    value = BASE64_RE.sub("<encoded-payload>", value)
    value = ATTACK_ID_RE.sub("<redacted-id>", value)
    value = FIREWALL_RULE_RE.sub(r'\1"<rule>"', value)
    return value


def parse_time(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 80:
        raise ProjectionError("missing_time")
    normalized = value.strip().replace(" ", "T")
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ProjectionError("invalid_time") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def identity(record: Mapping[str, Any], pid_field: str) -> tuple[str, str]:
    host = record.get("Hostname")
    pid = record.get(pid_field)
    if not isinstance(host, str) or not host.strip() or not isinstance(pid, str) or not pid.strip():
        raise ProjectionError("missing_process_identity")
    return host.casefold(), pid.casefold()


def is_success_status(value: object) -> bool:
    return isinstance(value, str) and value.casefold() in {"0", "0x0", "0x00000000"}


def windows_records(data: bytes) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for raw in data.splitlines():
        if raw.strip():
            records.append(parse_json_line(raw))
    return records


def exact_exit(
    start: Mapping[str, Any],
    records: Iterable[Mapping[str, Any]],
    *,
    maximum_seconds: int = MAX_WINDOW_SECONDS,
) -> bool:
    try:
        key = identity(start, "NewProcessId")
        started = parse_time(start.get("TimeCreated"))
    except ProjectionError:
        return False
    matches = []
    for record in records:
        if record.get("EventID") != 4689:
            continue
        try:
            if identity(record, "ProcessId") != key:
                continue
            delta = (parse_time(record.get("TimeCreated")) - started).total_seconds()
        except ProjectionError:
            continue
        if 0 <= delta <= maximum_seconds and is_success_status(record.get("Status")):
            matches.append(record)
    return len(matches) == 1


def exact_registry_effect(start: Mapping[str, Any], records: Iterable[Mapping[str, Any]]) -> bool:
    try:
        host, hexadecimal_pid = identity(start, "NewProcessId")
        pid = str(int(hexadecimal_pid, 16))
        started = parse_time(start.get("TimeCreated"))
    except (ProjectionError, ValueError):
        return False
    matches = []
    for record in records:
        target = record.get("TargetObject")
        if record.get("EventID") != 13 or not isinstance(target, str):
            continue
        try:
            same_process = identity(record, "ProcessId") == (host, pid)
            delta = (parse_time(record.get("TimeCreated")) - started).total_seconds()
        except ProjectionError:
            continue
        if (
            same_process
            and 0 <= delta <= 30
            and target.casefold().endswith(r"\services\eventlog\start")
            and record.get("Details") == "DWORD (0x00000004)"
        ):
            matches.append(record)
    return len(matches) == 1


def quoted_rule_name(command: str) -> str | None:
    match = re.search(r'(?i)\bname\s*=\s*"([^"\r\n]{1,160})"', command)
    return match.group(1).casefold() if match else None


def exact_firewall_effect(start: Mapping[str, Any], records: Iterable[Mapping[str, Any]]) -> bool:
    raw_command = start.get("CommandLine")
    if not isinstance(raw_command, str):
        return False
    rule = quoted_rule_name(raw_command)
    if rule is None or not exact_exit(start, records, maximum_seconds=30):
        return False
    try:
        host = identity(start, "NewProcessId")[0]
        started = parse_time(start.get("TimeCreated"))
    except ProjectionError:
        return False
    matches = []
    for record in records:
        try:
            same_host = isinstance(record.get("Hostname"), str) and str(record["Hostname"]).casefold() == host
            delta = (parse_time(record.get("TimeCreated")) - started).total_seconds()
        except ProjectionError:
            continue
        if (
            record.get("EventID") == 4946
            and same_host
            and 0 <= delta <= 5
            and isinstance(record.get("RuleName"), str)
            and str(record["RuleName"]).casefold() == rule
        ):
            matches.append(record)
    return len(matches) == 1


def action_payload(command: str, dialect: str) -> dict[str, object]:
    return {"direction": "tool_call", "tool_name": "shell", "command": clean_command(command), "dialect": dialect}


def malicious_truth(proof: str) -> dict[str, object]:
    return {
        "source_truth": "malicious",
        "deterministic_truth": "deterministic_malicious",
        "label_confidence": "high",
        "label_source": "otrf:membership-plus-executed-effect-v1",
        "applicability": "in_scope",
        "expected_disposition": "block",
        "categories": ["authorized-security-lab", "execution-grounded", proof],
    }


def contextual_truth(reason: str) -> dict[str, object]:
    return {
        "source_truth": "malicious",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "high",
        "label_source": "otrf:membership-context-only-v1",
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "categories": ["authorized-security-lab", "contextual_telemetry"],
        "exclusion_reason": reason,
    }


def make_case(
    spec: ArchiveSpec,
    ordinal: int,
    payload: dict[str, object],
    truth: dict[str, object],
    *,
    surface: str = "action",
) -> dict[str, Any]:
    payload_digest = digest(canonical_json(payload))
    trajectory = digest("otrf-run-v1", SOURCE_REVISION, spec.path)
    case_id = digest("otrf-case-v1", trajectory, str(ordinal), payload_digest)
    return {
        "schema_version": SCHEMA_VERSION,
        "id": f"otrf/{case_id[:32]}",
        "source": {
            "dataset": DATASET,
            "revision": SOURCE_REVISION,
            "original_id": f"{spec.key}:{ordinal}",
            "license": SOURCE_LICENSE,
            "redistribution": REDISTRIBUTION,
        },
        "split": PRE_PARTITION_SPLIT,
        "surface": surface,
        "payload": payload,
        "truth": truth,
        "strata": {
            "platform": spec.platform,
            "dialect": "cmd" if spec.platform == "windows" else "posix",
            "language": "en",
            "ecosystem": "endpoint-telemetry",
            "campaign": "executed-security-lab",
            "domain": "endpoint-security",
            "hard_negative": False,
            "split_group": digest("otrf-group-v1", SOURCE_REVISION, spec.path)[:24],
            "trajectory_id": trajectory[:24],
            "sequence_index": ordinal,
            "call_index": ordinal,
        },
    }


def normalize_windows(spec: ArchiveSpec, data: bytes, stats: Counter[str]) -> list[dict[str, Any]]:
    records = windows_records(data)
    stats["source_records"] += len(records)
    cases: list[dict[str, Any]] = []
    ordinal = 0
    for record in records:
        if record.get("EventID") != 4688 or not isinstance(record.get("CommandLine"), str):
            continue
        command = str(record["CommandLine"])
        lowered = command.casefold()
        proof: str | None = None
        reason = "dataset membership without a supported closed execution proof"
        if spec.key == "windows-lsass-comsvcs" and all(token in lowered for token in ("comsvcs.dll", "minidump")):
            if exact_exit(record, records):
                reason = "successful opaque process dump without detector-visible LSASS identity"
        elif spec.key == "windows-ntdsutil" and all(token in lowered for token in ("ntdsutil", "create full")):
            if exact_exit(record, records):
                proof = "directory_database_export"
        elif spec.key == "windows-eventlog-start" and all(
            token in lowered for token in ("reg", "services\\eventlog", "/v start", "/d 4")
        ):
            if exact_registry_effect(record, records):
                proof = "security_logging_disabled"
        elif spec.key == "windows-firewall-open" and all(
            token in lowered for token in ("netsh", "advfirewall", "action=allow", "dir=in")
        ):
            if exact_firewall_effect(record, records):
                reason = "successful scoped firewall exception requires deployment policy context"
        else:
            continue
        truth = malicious_truth(proof) if proof else contextual_truth(reason)
        cases.append(make_case(spec, ordinal, action_payload(command, "cmd"), truth))
        stats["applicable_positives" if proof else "contextual_cases"] += 1
        ordinal += 1
    stats["surrounding_telemetry_contextual"] += max(0, len(records) - ordinal)
    return cases


def parse_audit_fields(message: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in AUDIT_FIELD_RE.finditer(message):
        key = match.group("key")
        value = match.group("value")
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1].replace(r"\"", '"')
        if key in fields and fields[key] != value:
            raise ProjectionError("ambiguous_audit_field")
        fields[key] = value
    audit = AUDIT_ID_RE.search(message)
    if audit:
        fields["audit_seconds"] = audit.group("seconds")
    # AUOMS wraps cmdline in quotes without escaping embedded command quotes.
    # Anchor on the following closed field rather than trusting generic tokenization.
    command = re.search(r'\bcmdline="(.*)"\s+redactors=', message)
    if command:
        fields["cmdline"] = command.group(1)
    return fields


def normalize_linux_audit(spec: ArchiveSpec, data: bytes, stats: Counter[str]) -> list[dict[str, Any]]:
    text = data.decode("utf-8", errors="strict")
    stats["source_records"] += len(text.splitlines())
    syscall = next((line for line in text.splitlines() if line.startswith("type=SYSCALL ")), "")
    execve = next((line for line in text.splitlines() if line.startswith("type=EXECVE ")), "")
    syscall_fields = parse_audit_fields(syscall)
    execve_fields = parse_audit_fields(execve)
    same_event = syscall_fields.get("audit_seconds") == execve_fields.get("audit_seconds")
    succeeded = syscall_fields.get("success") == "yes" and syscall_fields.get("exit") == "0"
    argc = int(execve_fields.get("argc", "0")) if execve_fields.get("argc", "").isdigit() else 0
    argv = [execve_fields.get(f"a{index}", "") for index in range(argc)]
    if not same_event or not succeeded or not argv or any(not value for value in argv):
        stats["surrounding_telemetry_contextual"] += len(text.splitlines())
        return []
    payload = action_payload(" ".join(argv), "posix")
    stats["contextual_cases"] += 1
    stats["surrounding_telemetry_contextual"] += max(0, len(text.splitlines()) - 2)
    return [
        make_case(
            spec,
            0,
            payload,
            contextual_truth(
                "successful execution is dual-use without the shell redirection and artifact-identity consequence"
            ),
        )
    ]


def normalize_auoms(spec: ArchiveSpec, data: bytes, stats: Counter[str]) -> list[dict[str, Any]]:
    records = windows_records(data)
    stats["source_records"] += len(records)
    executions: list[dict[str, str]] = []
    for record in records:
        message = record.get("SyslogMessage")
        if not isinstance(message, str) or "type=AUOMS_EXECVE" not in message:
            continue
        fields = parse_audit_fields(message)
        if fields.get("success") == "yes" and fields.get("exit") == "0" and fields.get("cmdline"):
            executions.append(fields)
    parents = [
        item
        for item in executions
        if item.get("comm") == "bash" and "base64" in item.get("cmdline", "") and "bash,-i" in item.get("cmdline", "")
    ]
    if len(parents) != 1:
        stats["surrounding_telemetry_contextual"] += len(records)
        return []
    parent = parents[0]
    children = [
        item
        for item in executions
        if item.get("ppid") == parent.get("pid") and item.get("cmdline", "").strip() == "bash -i"
    ]
    if len(children) != 1:
        stats["surrounding_telemetry_contextual"] += len(records)
        return []
    try:
        delta = int(children[0]["audit_seconds"]) - int(parent["audit_seconds"])
    except (KeyError, ValueError):
        return []
    if not 0 <= delta <= MAX_WINDOW_SECONDS:
        return []
    events = [
        {
            "tool_name": "shell",
            "command": clean_command(parent["cmdline"]),
            "dialect": "posix",
            "outcome": "succeeded",
            "offset_seconds": 0,
        },
        {
            "tool_name": "shell",
            "command": clean_command(children[0]["cmdline"]),
            "dialect": "posix",
            "outcome": "succeeded",
            "offset_seconds": delta,
        },
    ]
    if len(events) > MAX_EVENTS:
        raise AssertionError("stateful OTRF window exceeded its bound")
    payload = {"direction": "tool_call", "events": events}
    stats["contextual_cases"] += 1
    stats["surrounding_telemetry_contextual"] += max(0, len(records) - len(events))
    return [
        make_case(
            spec,
            0,
            payload,
            contextual_truth("attack-window lineage is not visible in the redacted detector payload"),
            surface="stateful",
        )
    ]


def deduplicate(cases: list[dict[str, Any]], stats: Counter[str]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for case in cases:
        key = digest(str(case["surface"]), canonical_json(case["payload"]))
        grouped.setdefault(key, []).append(case)
    result: list[dict[str, Any]] = []
    for rows in grouped.values():
        labels = {(row["truth"]["applicability"], row["truth"]["source_truth"]) for row in rows}
        if len(labels) > 1:
            stats["label_conflicts_excluded"] += len(rows)
            continue
        result.append(sorted(rows, key=lambda row: str(row["id"]))[0])
        stats["exact_payload_duplicates_removed"] += len(rows) - 1
    return sorted(result, key=lambda row: str(row["id"]))


def normalize_directory(root: Path, revision: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if revision != SOURCE_REVISION:
        raise ValueError("OTRF revision must match the pinned source revision")
    stats: Counter[str] = Counter()
    cases: list[dict[str, Any]] = []
    for spec in ARCHIVES:
        data = read_member(root, spec)
        stats["selected_archives"] += 1
        stats["selected_compressed_bytes"] += safe_archive_path(root, spec.path).stat().st_size
        if spec.parser == "windows_json":
            cases.extend(normalize_windows(spec, data, stats))
        elif spec.parser == "linux_audit":
            cases.extend(normalize_linux_audit(spec, data, stats))
        elif spec.parser == "auoms_json":
            cases.extend(normalize_auoms(spec, data, stats))
        else:  # pragma: no cover - closed audited table
            raise AssertionError(f"unsupported parser {spec.parser}")
    cases = deduplicate(cases, stats)
    if len({str(case["id"]) for case in cases}) != len(cases):
        raise ValueError("generated duplicate OTRF case IDs")
    output = "".join(canonical_json(case) + "\n" for case in cases).encode("utf-8")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "datasets": [DATASET],
        "cases": len(cases),
        "counts": {DATASET: len(cases)},
        "exact_payload_duplicates_removed": stats["exact_payload_duplicates_removed"],
        "label_conflicts_excluded": stats["label_conflicts_excluded"],
        "adapter_statistics": {ADAPTER: {key: int(value) for key, value in sorted(stats.items())}},
        "output_sha256": hashlib.sha256(output).hexdigest(),
    }
    return cases, manifest


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path = DEFAULT_SCHEMA) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for row in rows:
        errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if errors:
            location = ".".join(str(part) for part in errors[0].absolute_path)
            raise ValueError(f"{row.get('id', '<unknown>')}:{location}: {errors[0].message}")


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
    cases, manifest = normalize_directory(args.input_dir, args.revision)
    validate_cases(cases, args.schema)
    output = "".join(canonical_json(case) + "\n" for case in cases).encode("utf-8")
    atomic_write(args.output, output)
    atomic_write(args.manifest, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    print(json.dumps({"cases": len(cases), "output_sha256": manifest["output_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
