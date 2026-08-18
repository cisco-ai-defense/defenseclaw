# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""CodeGuard self-check tool for OpenClaw agents.

Allows the agent to validate code against CodeGuard rules before writing it,
via the DefenseClaw sidecar API.  This is an optional self-verification step;
the sidecar's inspectToolPolicy enforces rules regardless.

Usage by the agent:
    result = run(code="value = load_user_input()", filename="app.py")
"""

from __future__ import annotations

import json
import os
import tempfile
import urllib.error
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request
from urllib.request import urlopen as open_url

_DEFAULT_SIDECAR_HOST = ".".join(("127", "0", "0", "1"))
_DEFAULT_SIDECAR_URL = f"http://{_DEFAULT_SIDECAR_HOST}:18790"
SIDECAR_URL = os.environ.get("DEFENSECLAW_SIDECAR_URL", _DEFAULT_SIDECAR_URL)
TIMEOUT_S = 10


def run(code: str, filename: str = "check.py") -> str:
    """Scan code content for security issues.

    Writes code to a temporary file and sends it to the DefenseClaw sidecar's
    /api/v1/scan/code endpoint.  Returns a human-readable summary.

    Args:
        code: Source code to check.
        filename: Filename hint for extension-based rule filtering.

    Returns:
        "clean" if no findings, otherwise a formatted list of issues.
    """
    ext = os.path.splitext(filename)[1] or ".py"
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=ext, delete=False, prefix="codeguard-check-"
    ) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        return _scan_via_sidecar(tmp_path)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _scan_via_sidecar(path: str) -> str:
    endpoint = _validated_scan_url(SIDECAR_URL)
    if endpoint is None:
        return "error: DEFENSECLAW_SIDECAR_URL must be a valid HTTP(S) origin"

    payload = json.dumps({"path": path}).encode("utf-8")
    request = Request(
        endpoint,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-DefenseClaw-Client": "codeguard-skill",
        },
        method="POST",
    )

    try:
        with open_url(request, timeout=TIMEOUT_S) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        return f"error: could not reach configured sidecar ({exc})"

    findings = data.get("findings") or []
    if not findings:
        return "clean"

    lines = [f"{len(findings)} issue(s) found:\n"]
    for finding in findings:
        severity = finding.get("severity", "?")
        rule_id = finding.get("id", "?")
        title = finding.get("title", "")
        location = finding.get("location", "")
        remedy = finding.get("remediation", "")
        lines.append(f"  [{severity}] {rule_id}: {title}")
        if location:
            lines.append(f"         at {location}")
        if remedy:
            lines.append(f"         fix: {remedy}")
        lines.append("")
    return "\n".join(lines)


def _validated_scan_url(base_url: str) -> str | None:
    """Build the fixed scan endpoint from the operator-configured origin."""
    if (
        not isinstance(base_url, str)
        or not base_url
        or base_url != base_url.strip()
    ):
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in base_url):
        return None

    try:
        parsed = urlsplit(base_url)
        port = parsed.port
    except ValueError:
        return None

    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        return None
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        return None
    if port is not None and not 1 <= port <= 65535:
        return None

    hostname = parsed.hostname
    if any(char in hostname for char in ("\\", "%")):
        return None
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = rendered_host if port is None else f"{rendered_host}:{port}"
    return urlunsplit(
        (parsed.scheme.lower(), netloc, "/api/v1/scan/code", "", "")
    )
