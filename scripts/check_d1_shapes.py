#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Require the public D1 subset to contain only synthetic identifiers and paths."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import sys
from pathlib import Path
from urllib.parse import urlsplit

ALLOWED_KEYS = {"id", "kind", "tool_name", "cc_tool", "command", "args", "expected"}
PAYLOAD_KEYS = ("kind", "tool_name", "cc_tool", "command", "args")
ALLOWED_KINDS = {"edit", "grep", "read", "shell", "write"}
ALLOWED_TOOLS = {
    "Bash",
    "Edit",
    "Grep",
    "PowerShell",
    "Read",
    "Write",
    "bash",
    "bash_command",
    "execute",
    "execute_bash",
    "read_file",
    "run_shell_command",
    "shell",
    "str_replace_editor",
}
ALLOWED_CC_TOOLS = {"Edit", "Grep", "Read", "Write"}
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
NETWORK_CLIENT = re.compile(r"\b(?:curl|wget|fetch|ftp)\b([^\n;&|<>]*)", re.I)
SOCKET_CLIENT = re.compile(r"\b(?:nc|ncat|netcat|telnet)\b([^\n;&|<>]*)", re.I)
NETWORK_ACCOUNT_OPTIONS = {"-u", "--user", "--proxy-user", "--http-user", "--ftp-user"}
NETWORK_ENDPOINT_OPTIONS = {"-x", "--url", "--proxy", "--preproxy", "--doh-url", "--resolve", "--connect-to"}
NETWORK_VALUE_OPTIONS = {
    "-o",
    "-O",
    "-H",
    "-d",
    "-X",
    "-A",
    "-e",
    "--output",
    "--header",
    "--proxy-header",
    "--data",
    "--request",
    "--user-agent",
    "--referer",
    "--post-data",
    "--post-file",
    "--output-document",
}
# The reviewed payload vocabulary is independent of the per-row digest
# manifest. Adding a new literal identifier requires an explicit scrub review.
TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_.@+-]*")
APPROVED_VOCAB_DIGEST = "ac352a8206e7d72b06b3da62d9a5fdf5845dc50ddd617c1ce17836a233bb5513"
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
        for key, item in value.items():
            yield from strings(key)
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def synthetic_network_operands(value: str) -> bool:
    """Check identity and endpoint operands for network clients as one class."""

    def approved_endpoint(word: str) -> bool:
        if "://" not in word and word.count(":") > 1:
            return False
        try:
            parsed = urlsplit(word if "://" in word else "//" + word)
            return parsed.hostname in ALLOWED_HOSTS and (not parsed.username or parsed.username in ALLOWED_USERS)
        except ValueError:
            return False

    def approved_header(header: str) -> bool:
        if not header:
            return False
        if any(marker in header for marker in ("$(", "${", "`", "$'")) or re.search(
            r"\\(?:x[0-9a-fA-F]{2}|[0-7]{3})", header
        ):
            return False
        host_header = re.fullmatch(r"\s*(?:Host|:authority|X-Forwarded-Host)\s*:\s*(.+)", header, re.I)
        return not host_header or approved_endpoint(host_header.group(1))

    def approved_endpoint_option(option: str, endpoint: str) -> bool:
        if option == "--resolve":
            parts = endpoint.split(":", 2)
            return (
                len(parts) == 3
                and parts[0] in ALLOWED_HOSTS
                and parts[1].isdecimal()
                and all(approved_endpoint(address) for address in parts[2].split(","))
            )
        if option == "--connect-to":
            parts = endpoint.split(":")
            return (
                len(parts) == 4
                and parts[0] in ALLOWED_HOSTS
                and parts[2] in ALLOWED_HOSTS
                and all(port.isdecimal() for port in (parts[1], parts[3]))
            )
        return approved_endpoint(endpoint)

    # Shell ANSI-C strings can construct an endpoint or header name from
    # escaped bytes. The public corpus uses literal network identities.
    if "$'" in value:
        return False

    for match in SOCKET_CLIENT.finditer(value):
        try:
            words = shlex.split(match.group(1))
        except ValueError:
            return False
        listening = False
        host_seen = False
        index = 0
        while index < len(words):
            word = words[index]
            if word in {"-c", "-e"}:
                if index + 1 >= len(words) or not synthetic_network_operands(words[index + 1]):
                    return False
                index += 2
                continue
            if word == "-s":
                if index + 1 >= len(words) or not approved_endpoint(words[index + 1]):
                    return False
                index += 2
                continue
            if word.startswith(("-s", "-x")) and len(word) > 2 and not word.startswith("--"):
                if not approved_endpoint(word[2:]):
                    return False
                index += 1
                continue
            if word in {"-p", "-w", "-i", "-U"}:
                if index + 1 >= len(words):
                    return False
                index += 2
                continue
            if word.startswith("-l"):
                listening = True
            if word.startswith("-"):
                index += 1
                continue
            if word.isdecimal() and (host_seen or listening):
                index += 1
                continue
            if not approved_endpoint(word):
                return False
            host_seen = True
            index += 1

    for match in NETWORK_CLIENT.finditer(value):
        client = match.group(0).split()[0].lower()
        fragment = match.group(1)
        if match.end() < len(value) and value[match.end()] in "<>":
            fragment = re.sub(r"\s+\d+$", "", fragment)
        try:
            words = shlex.split(fragment)
        except ValueError:
            return False
        index = 0
        while index < len(words):
            word = words[index]
            option, separator, inline = word.partition("=")
            if option in NETWORK_ACCOUNT_OPTIONS:
                account = inline if separator else (words[index + 1] if index + 1 < len(words) else "")
                if account not in ALLOWED_ACCOUNTS | ALLOWED_USERS:
                    return False
                index += 1 if separator else 2
                continue
            if word.startswith("-u") and not word.startswith("--"):
                if word[2:] not in ALLOWED_ACCOUNTS | ALLOWED_USERS:
                    return False
                index += 1
                continue
            if word.startswith("-x") and not word.startswith("--"):
                endpoint = word[2:] or (words[index + 1] if index + 1 < len(words) else "")
                if not approved_endpoint(endpoint):
                    return False
                index += 1 if word[2:] else 2
                continue
            if option in NETWORK_ENDPOINT_OPTIONS:
                endpoint = inline if separator else (words[index + 1] if index + 1 < len(words) else "")
                if not approved_endpoint_option(option, endpoint):
                    return False
                index += 1 if separator else 2
                continue
            if option in NETWORK_VALUE_OPTIONS:
                if option == "-H" and client != "curl":
                    index += 1
                    continue
                if option in {"-H", "--header", "--proxy-header"}:
                    header = inline if separator else (words[index + 1] if index + 1 < len(words) else "")
                    if not approved_header(header):
                        return False
                index += 1 if separator else 2
                continue
            if client == "curl" and word.startswith("-H") and len(word) > 2 and not word.startswith("--"):
                if not approved_header(word[2:]):
                    return False
                index += 1
                continue
            if word.startswith("-") or word in {"", "//"}:
                index += 1
                continue
            # Every remaining operand is an endpoint. A scheme-free spelling
            # must be parsed as an authority, not as a URL scheme.
            if not approved_endpoint(word):
                return False
            index += 1
    return True


def synthetic_operands(row: dict) -> bool:
    for value in strings({key: row.get(key) for key in ("command", "args")}):
        # The public fixture is an ASCII synthetic language. Non-ASCII words
        # cannot be silently omitted by the reviewed literal vocabulary.
        if not value.isascii() or not synthetic_network_operands(value):
            return False
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
    vocabulary: set[str] = set()
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
        kind, tool, cc_tool = row.get("kind"), row.get("tool_name"), row.get("cc_tool")
        if (
            not isinstance(kind, str)
            or kind not in ALLOWED_KINDS
            or not isinstance(tool, str)
            or tool not in ALLOWED_TOOLS
            or ("cc_tool" in row and (not isinstance(cc_tool, str) or cc_tool not in ALLOWED_CC_TOOLS))
        ):
            errors.append(f"line {number}: unapproved public tool")
        if (
            not isinstance(row.get("expected"), dict)
            or set(row["expected"]) != EXPECTED_CELLS
            or any(value not in ALLOWED_DECISIONS for value in row["expected"].values())
        ):
            errors.append(f"line {number}: invalid expected decisions")
        text = json.dumps({k: v for k, v in row.items() if k in ("command", "args")}, ensure_ascii=False)
        for value in strings({key: row.get(key) for key in ("command", "args")}):
            vocabulary.update(TOKEN.findall(value))
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
    digest = hashlib.sha256("\n".join(sorted(vocabulary)).encode("utf-8")).hexdigest()
    if digest != APPROVED_VOCAB_DIGEST:
        errors.append("unreviewed public vocabulary")
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
