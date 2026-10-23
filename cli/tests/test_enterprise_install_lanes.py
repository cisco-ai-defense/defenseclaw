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
    # On Linux the package hold keeps the apply trigger stopped while the
    # postinstall writes the result of the drill (GAP-0268).
    held = dict(drill, services=[*drill["services"], {"name": "defenseclaw-enterprise-apply.path", "kind": "path",
                                                       "state": "inactive/dead", "required": True}])
    drill_args = ("--expect-error", "lifecycle_test_fault", "--allow-warning", "lifecycle_test_fault",
                  "--allow-warning", "rolled_back", "--ready")
    assert "required service defenseclaw-enterprise-apply.path" in _check(tmp_path, held, *drill_args).stderr
    assert _check(tmp_path, held, *drill_args, "--held-service", "defenseclaw-enterprise-apply.path").returncode == 0
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


def test_upgrade_config_check_requires_a_v9_source_and_every_value_kept(tmp_path: Path) -> None:
    before = "config_version: 9\nguardrail:\n  mode: observe\n  connectors:\n    codex: {enabled: true}\n"
    (tmp_path / "before.yaml").write_text(before, encoding="utf-8")

    def run(after: str) -> subprocess.CompletedProcess[str]:
        (tmp_path / "after.yaml").write_text(after, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(SCRIPTS / "check_enterprise_upgrade_config.py"), "--before", str(tmp_path / "before.yaml"),
             "--after", str(tmp_path / "after.yaml")],
            capture_output=True, text=True, timeout=60, check=False,
        )

    assert run(before).returncode == 0, run(before).stderr
    changed = run(before.replace("mode: observe", "mode: action"))
    assert changed.returncode == 1
    assert "  - guardrail.mode changed from 'observe' to 'action'" in changed.stderr.splitlines()
    gone = run("config_version: 9\nguardrail:\n  mode: observe\n")
    assert "  - guardrail.connectors.codex.enabled is gone" in gone.stderr.splitlines()
    (tmp_path / "before.yaml").write_text(before.replace("config_version: 9", "config_version: 8"), encoding="utf-8")
    v8 = run(before)
    assert v8.returncode == 1
    assert "want 9 (the lanes upgrade from 1.x)" in v8.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
def test_unix_upgrade_lane_refuses_a_0x_previous_release(tmp_path: Path) -> None:
    # No 0.x release ships a standalone enterprise package, and 0.8.10 has no
    # enterprise secret set or ensure --from-package; the lane used to write a
    # version 8 config for one and then fail later on a missing command.
    for previous in ("0.8.10", "v0.8.10"):
        result = subprocess.run(
            ["bash", str(UNIX_LANE), "--package", str(tmp_path / "new.deb"), "--version", "1.0.4",
             "--upgrade-from", str(tmp_path / "old.deb"), "--previous-version", previous],
            capture_output=True, text=True, timeout=60, check=False,
        )
        assert result.returncode == 2, result.stderr
        assert "no 0.x release ships a standalone enterprise package" in result.stderr
    lane = UNIX_LANE.read_text(encoding="utf-8")
    writer = re.search(r"^write_admin_config\(\) \{\n.*?^\}\n", lane, re.MULTILINE | re.DOTALL)
    assert writer
    env = {**os.environ, "stage": str(tmp_path), "data_dir": str(tmp_path / "data"),
           "vendor_policy_dir": str(tmp_path / "policy")}
    result = subprocess.run(["bash", "-c", writer.group(0) + "\nwrite_admin_config"], env=env,
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    text = (tmp_path / "config.yaml").read_text()
    assert text.startswith("config_version: 9\n") and "  rule_pack: default\n" in text, text


def test_windows_upgrade_lane_refuses_a_0x_previous_release() -> None:
    lane = (SCRIPTS / "test-enterprise-windows-install.ps1").read_text(encoding="utf-8")
    checks = lane[lane.index("if ($UpgradeFrom) {"):lane.index("if (-not $ResultsRoot) {")]
    assert "no 0.x release ships a standalone enterprise Setup" in checks
    assert "config_version: 8" not in lane and "v8.bak" not in lane and "migration-v9.json" not in lane


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
def test_unix_upgrade_lane_checks_a_stored_credential_survives(tmp_path: Path) -> None:
    # The secrets check hashed an empty store before and after the upgrade,
    # which proves nothing; the lane now stores a credential first.
    lane = UNIX_LANE.read_text(encoding="utf-8")
    upgrade = re.search(r"^upgrade_lane\(\) \{\n.*?^\}\n", lane, re.MULTILINE | re.DOTALL)
    helpers = re.search(r"^upgrade_secret_name=.*?^upgrade_secret_kept\(\) \{\n.*?^\}\n", lane, re.MULTILINE | re.DOTALL)
    assert upgrade and helpers, "the upgrade lane has no protected-credential fixture"
    body = upgrade.group(0)
    assert body.index("seed_upgrade_secret") < body.index('previous_secrets_sha=$(tree_sha "$secrets_dir")')
    assert body.index("lifecycle 06-upgrade") < body.index("upgrade_secret_kept ||")
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    gateway = tmp_path / "gateway"
    gateway.write_text(
        '#!/bin/sh\nwhile [ $# -gt 0 ]; do [ "$1" = --name ] && n=$2; shift; done\n'
        'IFS= read -r v; printf %s "$v" >"$FAKE_SECRETS/$n"\n',
        encoding="utf-8",
    )
    gateway.chmod(0o755)
    (tmp_path / "results").mkdir()
    script = helpers.group(0) + (
        '\ndie() { echo "FAIL: $*" >&2; exit 1; }\n'
        "seed_upgrade_secret 02-previous-secret\n"
        "upgrade_secret_kept || exit 3\n"
        'printf x >>"$secrets_dir/$upgrade_secret_name"\n'
        "! upgrade_secret_kept || exit 4\n"
    )
    env = {**os.environ, "gateway": str(gateway), "secrets_dir": str(secrets), "results": str(tmp_path / "results"),
           "FAKE_SECRETS": str(secrets)}
    result = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert (secrets / "ci-upgrade-lane").read_text().startswith("ci-upgrade-lane-")


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
def test_unix_upgrade_lane_secret_check_needs_no_cmp(tmp_path: Path) -> None:
    # GAP-0886: the pinned UBI 9 init image of the rpm-el9 lane has no
    # diffutils, so a cmp-based check failed after a good secret set.
    lane = UNIX_LANE.read_text(encoding="utf-8")
    helpers = re.search(r"^upgrade_secret_name=.*?^upgrade_secret_kept\(\) \{\n.*?^\}\n", lane, re.MULTILINE | re.DOTALL)
    assert helpers, "the upgrade lane has no protected-credential fixture"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("od", "tr", "python3", "cat"):
        found = subprocess.run(["bash", "-c", f"command -v {tool}"], capture_output=True, text=True, check=False).stdout.strip()
        if found:
            (bin_dir / tool).symlink_to(found)
    assert not (bin_dir / "cmp").exists()
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    gateway = tmp_path / "gateway"
    gateway.write_text(
        '#!/bin/sh\nwhile [ $# -gt 0 ]; do [ "$1" = --name ] && n=$2; shift; done\n'
        'IFS= read -r v; printf %s "$v" >"$FAKE_SECRETS/$n"\n',
        encoding="utf-8",
    )
    gateway.chmod(0o755)
    (tmp_path / "results").mkdir()
    script = helpers.group(0) + (
        '\ndie() { echo "FAIL: $*" >&2; exit 1; }\n'
        "seed_upgrade_secret 02-previous-secret\n"
        "upgrade_secret_kept || exit 3\n"
        'printf x >>"$secrets_dir/$upgrade_secret_name"\n'
        "! upgrade_secret_kept || exit 4\n"
    )
    env = {"PATH": str(bin_dir), "gateway": str(gateway), "secrets_dir": str(secrets), "results": str(tmp_path / "results"),
           "FAKE_SECRETS": str(secrets)}
    bash = subprocess.run(["bash", "-c", "command -v bash"], capture_output=True, text=True, check=True).stdout.strip()
    result = subprocess.run([bash, "-c", script], env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_windows_upgrade_lane_checks_a_stored_credential_survives() -> None:
    lane = (SCRIPTS / "test-enterprise-windows-install.ps1").read_text(encoding="utf-8")
    upgrade = lane[lane.index("if ($UpgradeFrom) {"):lane.index("Step 'Setup /ensure with an administrator config")]
    assert "function Add-UpgradeSecret" in lane and "enterprise secret set --name $upgradeSecretName --from-stdin" in lane
    assert upgrade.index("Add-UpgradeSecret") < upgrade.index("$previousSecretsSha = Get-TreeSha")
    assert upgrade.index("01-setup-ensure-upgrade") < upgrade.index("Test-UpgradeSecretKept")


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
