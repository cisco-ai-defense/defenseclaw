#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Require the public D1 subset to contain only synthetic identifiers and paths."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

ALLOWED_KEYS = {"id", "kind", "tool_name", "cc_tool", "command", "args", "expected"}
PAYLOAD_KEYS = ("kind", "tool_name", "cc_tool", "command", "args")
APPROVED = Path(__file__).resolve().parents[1] / "internal/gateway/testdata/d1-shapes-approved.tsv"
EXPECTED_CELLS = {"claudecode/oss", "claudecode/managed-balanced", "codex/oss", "codex/managed-balanced"}
ALLOWED_DECISIONS = {"allow", "alert", "block"}
ALLOWED_ACCOUNTS = {"git:git", "testuser:testuser", "user:user"}
ALLOWED_USERS = {"git", "testuser", "user"}
ALLOWED_HOSTS = {"localhost", "example.invalid"}
# All literal absolute paths in the reviewed public subset. New paths require an
# explicit review of this list as well as the row payload manifest.
ALLOWED_ABSOLUTE_PATHS = {
    "/",
    "/.*",
    "/HIT",
    "/HIT*",
    "/d",
    "/dev/null",
    "/example.invalid",
    "/sample",
    "/sample.js",
    "/sample.ts",
    "/testbed",
    "/testbed/example.invalid",
    "/testbed/final_test.ts",
    "/testbed/flexx/ui/widgets/_slider.py",
    "/testbed/lib/function/algebra/simplify.js",
    "/testbed/macro",
    "/testbed/moto/iot/responses.py",
    "/testbed/msgp/read.go",
    "/testbed/pkg/vpa/service.go",
    "/testbed/retry/retry.go",
    "/testbed/rich/pretty.py",
    "/testbed/routing/*.go",
    "/testbed/score/deployment_test.go",
    "/testbed/snapshot/upload/upload.go",
    "/testbed/src/immutableStateInvariantMiddleware.test.ts",
    "/testbed/test",
    "/testbed/test/enforce-map-style_test.go",
    "/testbed/test_adjacent_closers.ts",
    "/testbed/test_adjacent_closers2.ts",
    "/testbed/test_credentials.ts",
    "/testbed/xarray_dataclasses/dataarray.py",
}
ABSOLUTE_PATH = re.compile(r"(?<![\w$./])/([A-Za-z0-9._~+*?-]+(?:/[A-Za-z0-9._~+*?-]+)*)")
ACCOUNT_OPERAND = re.compile(r"\b(?:chown|chgrp|su|runuser|useradd|usermod|passwd)\s+(?:-[A-Za-z]+\s+)*([^\s;&|]+)")
SUDO_USER = re.compile(r"\bsudo\s+-u\s+([^\s;&|]+)")
HOST_OPERAND = re.compile(r"\b(?:ssh|ssh-keyscan|scp|rsync|ping|nslookup|dig)\s+(?:-[A-Za-z]+\s+)*([^\s;&|]+)")
URL = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+")
USER_AT_HOST = re.compile(r"\b([A-Za-z][A-Za-z0-9_.+-]*)@([A-Za-z][A-Za-z0-9_.-]*)")
GIT_ACCOUNT = re.compile(r"\buser\.(?:name|email)\s*(?:=|\s)\s*([^\s;&|\"']+)", re.I)
GIT_IDENTITY = re.compile(r"\bGIT_(?:AUTHOR|COMMITTER)_(?:NAME|EMAIL)=([^\s;&|\"']+)", re.I)
GIT_TRANSPORT = re.compile(
    r"\bgit\b[^\n;&|]{0,300}\b(?:clone|fetch|push|pull|ls-remote|remote\s+(?:add|set-url))\b([^\n;&|]*)",
    re.I,
)
GIT_SCP_ENDPOINT = re.compile(r"(?<![\w./])(?:([A-Za-z][A-Za-z0-9_.+-]*)@)?([A-Za-z][A-Za-z0-9_.-]*):(?!//)[^\s;&|]+")
HOST_ASSIGNMENT = re.compile(r"\b(?:host|hostname|server|remote|user|username|account)=([^\s;&|\"']+)", re.I)
BAD_TEXT = (
    re.compile(
        r"(?<![A-Za-z0-9])/(?:home|Users|root|tmp|var|workspace|mnt|opt|etc|usr|proc|run|private|app)(?:/|\b)", re.I
    ),
    re.compile(r"[A-Za-z]:\\"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@(?!example\.invalid\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"https?://(?!example\.invalid(?:/|\b))", re.I),
    re.compile(r"\b[A-Za-z0-9_-]+\.(?:com|net|org|io|ai|edu|gov|local|internal)\b", re.I),
    re.compile(r"(?i)\b(?:api[_-]?key|auth[_-]?token|access[_-]?token|password|passwd|secret)\s*[=:]\s*(?!sample\b)"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{12,}\b"),
)


def payload_digest(row: dict) -> str:
    payload = {key: row.get(key) for key in PAYLOAD_KEYS}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def approved_payloads(path: Path) -> dict[str, str]:
    rows = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        row_id, digest = line.split("\t")
        if row_id in rows or not re.fullmatch(r"d1-\d{4}", row_id) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid approved D1 payload manifest")
        rows[row_id] = digest
    return rows


def strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def synthetic_operands(row: dict) -> bool:
    for value in strings({key: row.get(key) for key in ("command", "args")}):
        without_urls = re.sub(r"https?://example\.invalid(?:/[A-Za-z0-9._/-]*)?", "example.invalid", value)
        for match in ABSOLUTE_PATH.finditer(without_urls):
            path = match.group()
            if path not in ALLOWED_ABSOLUTE_PATHS:
                return False
        for match in list(ACCOUNT_OPERAND.finditer(value)) + list(SUDO_USER.finditer(value)):
            if match.group(1) not in ALLOWED_ACCOUNTS | ALLOWED_USERS:
                return False
        for match in HOST_OPERAND.finditer(value):
            if match.group(1) not in ALLOWED_HOSTS:
                return False
        # Host and account syntax is checked wherever it appears, including Git
        # transports and configuration, rather than only for a command allowlist.
        for match in URL.finditer(value):
            try:
                parsed = urlsplit(match.group().rstrip(".,)"))
                if parsed.hostname not in ALLOWED_HOSTS or (parsed.username and parsed.username not in ALLOWED_USERS):
                    return False
            except ValueError:
                return False
        for match in USER_AT_HOST.finditer(value):
            if match.group(1) not in ALLOWED_USERS or match.group(2) not in ALLOWED_HOSTS:
                return False
        for match in list(GIT_ACCOUNT.finditer(value)) + list(GIT_IDENTITY.finditer(value)):
            account = match.group(1)
            if account not in ALLOWED_USERS and account not in {f"{user}@example.invalid" for user in ALLOWED_USERS}:
                return False
        for match in GIT_TRANSPORT.finditer(value):
            for endpoint in GIT_SCP_ENDPOINT.finditer(match.group(1)):
                if (endpoint.group(1) and endpoint.group(1) not in ALLOWED_USERS) or endpoint.group(
                    2
                ) not in ALLOWED_HOSTS:
                    return False
        for match in HOST_ASSIGNMENT.finditer(value):
            name = match.group(0).split("=", 1)[0].lower()
            allowed = ALLOWED_USERS if name in {"user", "username", "account"} else ALLOWED_HOSTS
            if match.group(1) not in allowed:
                return False
    return True


def check(path: Path, approved_path: Path = APPROVED) -> list[str]:
    errors = []
    seen = set()
    try:
        approved = approved_payloads(approved_path)
    except (OSError, ValueError) as error:
        return [f"invalid approved D1 payload manifest: {error}"]
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            errors.append(f"line {number}: invalid JSON")
            continue
        if not isinstance(row, dict):
            errors.append(f"line {number}: invalid row")
            continue
        row_id = row.get("id", "")
        if not isinstance(row_id, str) or not re.fullmatch(r"d1-\d{4}", row_id) or row_id in seen:
            errors.append(f"line {number}: invalid or repeated id")
            continue
        seen.add(row_id)
        if set(row) - ALLOWED_KEYS:
            errors.append(f"line {number}: private metadata fields")
        if (
            not isinstance(row.get("expected"), dict)
            or set(row["expected"]) != EXPECTED_CELLS
            or any(value not in ALLOWED_DECISIONS for value in row["expected"].values())
        ):
            errors.append(f"line {number}: invalid expected decisions")
        text = json.dumps({k: v for k, v in row.items() if k in ("command", "args")}, ensure_ascii=False)
        if any(pattern.search(text) for pattern in BAD_TEXT):
            errors.append(f"line {number}: unsanitized content")
        if not synthetic_operands(row):
            errors.append(f"line {number}: unapproved host, account or absolute path")
        if approved.get(row_id) != payload_digest(row):
            errors.append(f"line {number}: unapproved public payload")
    if len(seen) < 250:
        errors.append(f"public subset has only {len(seen)} rows")
    if seen != set(approved):
        errors.append("public subset differs from the approved row set")
    return errors


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else Path("internal/gateway/testdata/d1-shapes.jsonl")
    errors = check(path)
    for error in errors[:25]:
        print(error, file=sys.stderr)
    if errors:
        print(f"D1 scrub check: {len(errors)} issue(s)", file=sys.stderr)
        return 1
    print("D1 scrub check: public subset contains synthetic identifiers and paths")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
