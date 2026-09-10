#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize the pinned Zenodo cybersecurity-training shell-command corpus.

The source describes where commands were collected, not whether each command
is deterministically malicious. Every normalized case therefore starts outside
the scoring scope pending independent adjudication. Source commands are read as
inert strings and are never passed to a shell.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

if __package__:
    from .benchmark_normalize import command_family
else:
    from benchmark_normalize import command_family

SOURCE_ID = "zenodo-cyber-training-shell-v4"
SOURCE_REVISION = "v4-record-8136017-data-md5-a11b58d28a4c7d16482e84ed9540e238"
SOURCE_LICENSE = "CC-BY-4.0"
SOURCE_ARCHIVE_SHA256 = "f1922981d9e96f8b02ac4e1a4608468189d8fe59a28228c3e0e6be27f4d6f176"
EXPECTED_FILES = 267
EXPECTED_RECORDS = 21_108
EXPECTED_VALID_COMMANDS = 21_089
EXPECTED_METADATA_RECORDS = 19
EXPECTED_UNIQUE_COMMANDS = 6_271
COMMAND_TYPES = {"bash-command", "msf-command"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_digest(*values: str) -> str:
    return hashlib.sha256("\0".join(values).encode()).hexdigest()[:24]


def normalized_command(raw: object) -> str:
    return raw.replace("\x00", "").strip() if isinstance(raw, str) else ""


def normalize(data_root: Path, *, enforce_release: bool = True) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not data_root.is_dir():
        raise ValueError("source data directory does not exist")
    paths = sorted(data_root.rglob("*useractions.json"))
    if not paths:
        raise ValueError("source contains no user-action files")

    by_command: dict[str, dict[str, Any]] = {}
    records = 0
    valid_commands = 0
    metadata_records = 0
    command_type_counts: Counter[str] = Counter()
    host_role_counts: Counter[str] = Counter()
    occurrence_counts: Counter[str] = Counter()

    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"unsupported source entry: {path}")
        relative = path.relative_to(data_root).as_posix()
        scenario = relative.split("/", 1)[0]
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                raise ValueError(f"{relative}:{line_number}: blank record")
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{relative}:{line_number}: expected an object")
            records += 1
            command = normalized_command(value.get("cmd"))
            if not command:
                if "cmd" not in value and isinstance(value.get("tags"), list):
                    metadata_records += 1
                    continue
                raise ValueError(f"{relative}:{line_number}: invalid command")
            command_type = value.get("cmd_type")
            hostname = value.get("hostname")
            if command_type not in COMMAND_TYPES or not isinstance(hostname, str) or not hostname:
                raise ValueError(f"{relative}:{line_number}: invalid command type or host role")
            valid_commands += 1
            command_type_counts[str(command_type)] += 1
            host_role_counts[hostname] += 1
            occurrence_counts[command] += 1
            entry = by_command.setdefault(
                command,
                {
                    "original_id": f"{relative}:{line_number}",
                    "command_types": set(),
                    "host_roles": set(),
                    "scenarios": set(),
                },
            )
            entry["command_types"].add(str(command_type))
            entry["host_roles"].add(hostname)
            entry["scenarios"].add(scenario)

    observed = {
        "files": len(paths),
        "records": records,
        "valid_commands": valid_commands,
        "metadata_records": metadata_records,
        "unique_commands": len(by_command),
    }
    expected = {
        "files": EXPECTED_FILES,
        "records": EXPECTED_RECORDS,
        "valid_commands": EXPECTED_VALID_COMMANDS,
        "metadata_records": EXPECTED_METADATA_RECORDS,
        "unique_commands": EXPECTED_UNIQUE_COMMANDS,
    }
    if enforce_release and observed != expected:
        raise ValueError(f"source release cardinality differs: observed={observed}, expected={expected}")

    rows: list[dict[str, Any]] = []
    for command, metadata in sorted(by_command.items()):
        command_types = sorted(metadata["command_types"])
        host_roles = sorted(metadata["host_roles"])
        scenarios = sorted(metadata["scenarios"])
        family = command_family(command)
        rows.append(
            {
                "schema_version": "1",
                "id": f"{SOURCE_ID}/{stable_digest(SOURCE_ID, command)}",
                "source": {
                    "dataset": SOURCE_ID,
                    "revision": SOURCE_REVISION,
                    "original_id": metadata["original_id"],
                    "license": SOURCE_LICENSE,
                    "redistribution": "download-only",
                },
                "split": "development",
                "surface": "action",
                "payload": {
                    "tool_name": "shell",
                    "command": command,
                    "dialect": "posix",
                    "cwd": "/repo",
                    "active_home": "/home/alice",
                },
                "truth": {
                    "source_truth": "unknown",
                    "applicability": "out_of_scope",
                    "expected_disposition": "detect_only",
                    "categories": ["cybersecurity-training", "pending-command-adjudication"],
                    "exclusion_reason": "pending_gpt_oss_120b_review",
                },
                "strata": {
                    "platform": "linux",
                    "dialect": "posix",
                    "ecosystem": command_types[0] if len(command_types) == 1 else "mixed",
                    "campaign": scenarios[0] if len(scenarios) == 1 else "mixed",
                    "domain": host_roles[0] if len(host_roles) == 1 else "mixed",
                    "hard_negative": False,
                    "split_group": stable_digest(SOURCE_ID, family),
                },
            }
        )
    rows.sort(key=lambda row: row["id"])
    manifest = {
        "schema_version": "1",
        "dataset": SOURCE_ID,
        "revision": SOURCE_REVISION,
        "license": SOURCE_LICENSE,
        "cases": len(rows),
        **observed,
        "duplicate_occurrences_removed": valid_commands - len(rows),
        "command_type_counts": dict(sorted(command_type_counts.items())),
        "host_role_counts": dict(sorted(host_role_counts.items())),
        "occurrence_count_histogram": dict(sorted(Counter(occurrence_counts.values()).items())),
        "label_contract": "source context is not malicious truth; independent GPT-OSS plus literal proof gate required",
    }
    return rows, manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    archive_digest = sha256_file(args.archive)
    if archive_digest != SOURCE_ARCHIVE_SHA256:
        raise ValueError("source archive digest differs from the pinned Zenodo release")
    rows, manifest = normalize(args.input_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    manifest["source_archive_sha256"] = archive_digest
    manifest["output_sha256"] = sha256_file(args.output)
    args.output.with_suffix(".manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({key: manifest[key] for key in ("cases", "records", "output_sha256")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
