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


def test_checker_upgrade_gate_options(tmp_path: Path) -> None:
    # The rollback drill's step must fail with the test fault and roll back.
    drill = _result(
        ok=False,
        exit_code=1,
        errors=[{"code": "lifecycle_test_fault", "message": "fault"}],
        warnings=[{"code": "lifecycle_test_fault", "message": "fault"}, {"code": "rolled_back", "message": "restored"}],
    )
    result = _check(
        tmp_path, drill, "--expect-error", "lifecycle_test_fault",
        "--allow-warning", "lifecycle_test_fault", "--allow-warning", "rolled_back",
    )
    assert result.returncode == 0, result.stderr
    failed_rollback = dict(
        drill,
        errors=[*drill["errors"], {"code": "rollback_failed", "message": "gateway did not restart"}],
        readiness={key: False for key in drill["readiness"]},
    )
    result = _check(
        tmp_path, failed_rollback, "--expect-error", "lifecycle_test_fault",
        "--allow-warning", "lifecycle_test_fault", "--allow-warning", "rolled_back",
    )
    assert result.returncode == 1, result.stderr
    assert "unexpected error rollback_failed" in result.stderr
    # The upgrade itself must report an applied policy from a newer config generation.
    upgraded = _result(policy={"effective_digest": "sha256:ab", "config_generation": 2, "applied": True})
    assert _check(tmp_path, upgraded, *FULL, "--policy-applied", "--config-generation-above", "1").returncode == 0
    result = _check(tmp_path, _result(), *FULL, "--policy-applied")
    assert "  - the result reports no policy" in result.stderr.splitlines(), result.stderr


def test_upgrade_config_check_requires_every_v8_value_kept_or_recorded(tmp_path: Path) -> None:
    import hashlib

    before = b"config_version: 8\nguardrail:\n  mode: observe\n  connectors:\n    codex: {enabled: true}\nskill_actions:\n  high: {install: block}\n"
    (tmp_path / "v8.yaml").write_bytes(before)
    record = {
        "from_version": 8,
        "to_version": 9,
        "source_sha256": hashlib.sha256(before).hexdigest(),
        "moved": [{"from": "skill_actions.high.install", "to": "admission.skill.actions.high"}],
        "conflicts": [],
    }
    (tmp_path / "record.json").write_text(json.dumps(record), encoding="utf-8")

    def run(after: str) -> subprocess.CompletedProcess[str]:
        (tmp_path / "v9.yaml").write_text(after, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(SCRIPTS / "check_enterprise_upgrade_config.py"), "--before", str(tmp_path / "v8.yaml"),
             "--after", str(tmp_path / "v9.yaml"), "--record", str(tmp_path / "record.json")],
            capture_output=True, text=True, timeout=60, check=False,
        )

    kept = "config_version: 9\nguardrail:\n  mode: observe\n  connectors:\n    codex: {enabled: true}\nadmission:\n  skill:\n    actions: {high: block}\n"
    assert run(kept).returncode == 0, run(kept).stderr
    moved_changed = run(kept.replace("actions: {high: block}", "actions: {high: allow}"))
    assert moved_changed.returncode == 1
    assert "skill_actions.high.install moved to admission.skill.actions.high" in moved_changed.stderr
    record["moved"].append({"from": "update_check", "to": "update.check", "value": False})
    (tmp_path / "v8.yaml").write_bytes(before + b"update_check: true\n")
    record["source_sha256"] = hashlib.sha256((tmp_path / "v8.yaml").read_bytes()).hexdigest()
    (tmp_path / "record.json").write_text(json.dumps(record), encoding="utf-8")
    changed_boolean = run(kept + "update: {check: false}\n")
    assert changed_boolean.returncode == 1
    assert "update_check moved to update.check" in changed_boolean.stderr
    changed = run(kept.replace("mode: observe", "mode: action"))
    assert changed.returncode == 1
    assert "  - guardrail.mode changed from 'observe' to 'action'" in changed.stderr.splitlines()


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
def test_unix_upgrade_lane_applies_v8_to_previous_package(tmp_path: Path) -> None:
    lane = UNIX_LANE.read_text(encoding="utf-8")
    writer = re.search(r"^write_admin_config\(\) \{\n.*?^\}\n", lane, re.MULTILINE | re.DOTALL)
    upgrade = re.search(r"^upgrade_lane\(\) \{\n.*?^\}\n", lane, re.MULTILINE | re.DOTALL)
    assert writer and upgrade
    assert "write_admin_config" in upgrade.group(0)
    env = {**os.environ, "stage": str(tmp_path), "data_dir": str(tmp_path / "data"),
           "vendor_policy_dir": str(tmp_path / "policy"), "upgrade_from": str(tmp_path / "previous.pkg")}
    # A 0.8.x package reads only version 8 (GAP-0496); a 1.x one gets version 9 (GAP-0510).
    for previous, want in (("0.8.10", "config_version: 8\n"), ("1.0.0", "config_version: 9\n")):
        result = subprocess.run(["bash", "-c", writer.group(0) + "\nwrite_admin_config"],
                                env={**env, "previous_version": previous}, capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stderr
        text = (tmp_path / "config.yaml").read_text()
        assert text.startswith(want), (previous, text)
        assert ("rule_pack: default" in text) == (want == "config_version: 9\n"), text


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
