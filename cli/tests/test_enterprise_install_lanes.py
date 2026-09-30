# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""The standalone managed-enterprise install lanes.

On every pull request CI installs the real deb (Ubuntu runner), rpm (RHEL 9
and RHEL 8 containers booted with systemd), macOS pkg (macOS runner) and the
hash-pinned unsigned Windows Setup (Windows runner), then converges, verifies,
detects, uninstalls and checks what is left. The lanes themselves are the
behavioral check; these tests exercise the result checker and the unit check
every lane relies on.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
CHECKER = SCRIPTS / "check_enterprise_lifecycle_result.py"
UNIX_LANE = SCRIPTS / "test-enterprise-unix-install.sh"


def _result(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": 2,
        "ok": True,
        "action": "ensure",
        "noop": False,
        "profile": "standalone",
        "platform": "linux",
        "product_version": "1.4.0",
        "installed_version": "1.4.0",
        "installed": True,
        "transaction_pending": False,
        "services": [
            {"name": "defenseclaw-gateway.service", "kind": "gateway", "state": "active/running", "required": True},
            {"name": "defenseclaw-enterprise-verify.timer", "kind": "timer", "state": "active/waiting", "required": True},
            {"name": "defenseclaw-enterprise-verify.service", "kind": "oneshot", "state": "inactive/dead", "required": False},
        ],
        "readiness": {"gateway": True, "guardian": True, "enumerator": True, "sensor_helper": True},
        "inspection": {"local": "active", "ai_defense": "disabled"},
        "machine_policy": {
            "codex": {"ownership": "merge", "lock": "enforce", "effective_lock": "enforce", "owned_entries": 10, "foreign_entries": 0},
        },
        "enrollment": {"targets": 0, "pending": 0, "failed": 0, "exempt": 0},
        "coverage_complete": True,
        "security_complete": True,
        "errors": [],
        "warnings": [],
        "exit_code": 0,
    }
    document.update(overrides)
    return document


def _check(tmp_path: Path, document: Any, *arguments: str, raw: bytes | None = None) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "result.json"
    path.write_bytes(raw if raw is not None else json.dumps(document).encode("utf-8"))
    return subprocess.run(
        [sys.executable, str(CHECKER), str(path), "--label", "step", *arguments],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


FULL = ("--action", "ensure", "--platform", "linux", "--changed", "--installed", "--version", "1.4.0", "--ready")


def test_checker_accepts_a_matching_result(tmp_path: Path) -> None:
    result = _check(
        tmp_path,
        _result(),
        *FULL,
        "--complete",
        "--machine-policy",
        "codex",
        "--machine-policy-enforced",
        "codex",
        "--machine-policy-target",
        "codex",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("ok   step: action=ensure ok=True noop=False installed=True installed_version=1.4.0")
    assert "coverage_complete=True security_complete=True" in result.stdout


@pytest.mark.parametrize(
    ("overrides", "arguments", "problem"),
    [
        ({"ok": False, "errors": [{"code": "activation_failed", "message": "gateway did not become ready"}]}, FULL, "ok is false"),
        ({"exit_code": 1}, FULL, "exit_code is 1"),
        ({"transaction_pending": True}, FULL, "a transaction is still pending"),
        ({"profile": "secure_client"}, FULL, "profile is 'secure_client', want 'standalone'"),
        ({"installed_version": "1.3.9"}, FULL, "installed_version is '1.3.9', want '1.4.0'"),
        (
            {"services": [{"name": "defenseclaw-hook-guardian.service", "kind": "guardian", "state": "failed/failed", "required": True}]},
            FULL,
            "required service defenseclaw-hook-guardian.service is 'failed/failed'",
        ),
        (
            {"machine_policy": {"codex": {"ownership": "merge", "effective_lock": "preserve", "owned_entries": 10, "foreign_entries": 0}}},
            ("--machine-policy-enforced", "codex"),
            "machine_policy.codex.effective_lock is 'preserve', want 'enforce'",
        ),
        # ok only means "no errors": the lifecycle reports a failed guardian
        # target, an unverified hook contract and a rejected config as
        # warnings, with security_complete false.
        (
            {"security_complete": False, "warnings": [{"code": "guardian_target_failed", "message": "1 of 2 targets failed"}]},
            FULL,
            "unexpected warning guardian_target_failed",
        ),
        ({"schema_version": 1}, FULL, "schema_version is 1, want 2"),
    ],
)
def test_checker_rejects_a_result_that_does_not_match(
    tmp_path: Path, overrides: dict[str, Any], arguments: tuple[str, ...], problem: str
) -> None:
    result = _check(tmp_path, _result(**overrides), *arguments)
    assert result.returncode == 1, result.stdout
    assert f"  - {problem}" in result.stderr.splitlines(), result.stderr
    assert result.stderr.startswith("FAIL step: ")


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
def test_unit_check_fails_on_diagnostics_outside_the_allow_list(tmp_path: Path) -> None:
    """The lane's unit check fails on a directive the systemd 239 allow list does not name."""
    bin_dir, unit_dir = tmp_path / "bin", tmp_path / "units"
    bin_dir.mkdir()
    unit_dir.mkdir()
    output = tmp_path / "verify-output.txt"
    output.write_text(
        "/usr/lib/systemd/system/defenseclaw-gateway.service:70: Unknown lvalue 'ProtectNew' in section 'Service'\n",
        encoding="utf-8",
    )
    fakes = {
        "systemctl": '#!/bin/sh\necho "systemd 239 (239-1.test)"\necho "+PAM +AUDIT"\n',
        "systemd-analyze": f"#!/bin/sh\ncat {shlex.quote(str(output))} >&2\n",
    }
    for name, body in fakes.items():
        fake = bin_dir / name
        fake.write_text(body, encoding="utf-8")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    for unit in ("defenseclaw-gateway.service", "defenseclaw-enterprise-apply.path", "defenseclaw.conf"):
        (unit_dir / unit).write_text("", encoding="utf-8")
    text = UNIX_LANE.read_text(encoding="utf-8")
    functions = "".join(
        re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.MULTILINE | re.DOTALL).group(0)
        for name in ("die", "directive_minimum", "unit_diagnostics")
    )
    harness = "\n".join(
        [
            "set -euo pipefail",
            f"PATH={shlex.quote(str(bin_dir))}:$PATH",
            f"unit_dir={shlex.quote(str(unit_dir))}",
            functions,
            "unit_diagnostics",
            "echo UNITS-PASSED",
        ]
    )
    result = subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 1, result.stdout
    assert "UNITS-PASSED" not in result.stdout
    assert "unit diagnostics outside the systemd 239 allow list" in result.stderr
