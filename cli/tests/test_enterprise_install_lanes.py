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

import ast
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
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
CHECKER = SCRIPTS / "check_enterprise_lifecycle_result.py"
RESULT_CHECKER_TEST = SCRIPTS / "test_check_enterprise_lifecycle_result.py"
UNIX_LANE = SCRIPTS / "test-enterprise-unix-install.sh"
POSTINSTALL_RESULT_TEST = ROOT / "packaging/linux/tests/test_postinstall_result.sh"
SANDBOX_HOLD_TEST = ROOT / "packaging/linux/tests/test_upgrade_holds_legacy_sandbox_daemons.sh"
# CI selects this module for preremove.sh changes by its basename (GAP-0137).
PREREMOVE = ROOT / "packaging/linux/preremove.sh"
PREREMOVE_USER_UNITS_TEST = ROOT / "packaging/linux/tests/test_preremove_resets_failed_user_units.sh"
# CI selects Python modules that name the changed file's basename: the hold
# lives in preinstall.sh and the macOS package's build script (GAP-1809).
POSTINSTALL = ROOT / "packaging/linux/postinstall.sh"
PREINSTALL = ROOT / "packaging/linux/preinstall.sh"
MACOS_PKG_BUILD = ROOT / "scripts/build-macos-enterprise-pkg.sh"
MACOS_TEST_RUNNER = ROOT / "packaging/macos/tests/run_tests.sh"
MACOS_SANDBOX_HOLD_TEST = ROOT / "packaging/macos/tests/test_enterprise_pkg_sandbox_hold.sh"


def test_hook_process_warning_keeps_install_lanes_honest(tmp_path: Path) -> None:
    """Enabled Claude/Codex coverage is complete while prevention is not."""
    result = _result(
        action="verify", security_complete=False,
        warnings=[{"code": "hook_process_fail_open", "message": "codex hook can fail open"}],
    )
    accepted = _check(tmp_path, result, "--coverage-complete", "--security-incomplete",
                      "--allow-warning", "hook_process_fail_open")
    assert accepted.returncode == 0, accepted.stderr

    unix = UNIX_LANE.read_text(encoding="utf-8")
    lines = unix.splitlines()
    for step in ("02-ensure-config", "03-ensure-noop", "04-verify", "05-status", "06-upgrade"):
        matches = [i for i, line in enumerate(lines) if f'check "$results/{step}.json"' in line]
        assert len(matches) == 1, step
        i = matches[0]
        args = lines[i]
        while lines[i].rstrip().endswith("\\"):
            i += 1
            args += " " + lines[i]
        assert "--coverage-complete" in args and "--security-incomplete" in args
        assert "--allow-warning hook_process_fail_open" in args
        assert "--complete" not in args

    windows = (SCRIPTS / "test-enterprise-windows-install.ps1").read_text(encoding="utf-8")
    checks = windows[windows.index("$installedChecks = @("):windows.index("\n)", windows.index("$installedChecks = @("))]
    assert "'--coverage-complete'" in checks and "'--security-incomplete'" in checks
    assert "'hook_process_fail_open'" in checks

    docs = ROOT / "docs-site/content/docs/enterprise"
    for page in ("get-started.mdx", "linux.mdx", "macos.mdx",
                 "windows.mdx"):
        text = (docs / page).read_text(encoding="utf-8")
        assert "hook_process_fail_open" in text and "security_complete" in text, page


def test_lifecycle_checker_keeps_python36_annotations() -> None:
    # RHEL 8 runs this file with platform-python 3.6, where built-in
    # collection generics and union annotations cannot be evaluated.
    source = CHECKER.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(CHECKER), feature_version=(3, 6))
    for node in ast.walk(tree):
        assert not (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id in {"dict", "list", "tuple", "set", "frozenset"}
        ), f"Python 3.6 cannot evaluate {ast.get_source_segment(source, node)}"
        assert not (
            isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr)
        ), f"Python 3.6 cannot evaluate {ast.get_source_segment(source, node)}"


# Secure Client results carry no hook_process_fail_open warning (the warning
# is standalone-only), so its pages may still expect security_complete true.
_SECURE_CLIENT_PAGES = ("enterprise/secure-client.mdx",)
_WARNED_CONNECTOR_KEYS = re.compile(r'"(antigravity|claudecode|codex|copilot|devin|hermes|kiro)"\s*:')


def test_docs_never_promise_security_complete_with_hook_residual() -> None:
    """No status example or verification step expects a plain security_complete true.

    Standalone status, verify and ensure report security_complete false and
    hook_process_fail_open whenever Codex, Claude Code, Copilot, Devin, Hermes,
    Kiro or Antigravity is enabled. An install guide, operations sample,
    troubleshooting check or agent instruction that expects true would make
    an operator or agent report a healthy install as failed.
    """
    problems: list[str] = []
    for page in sorted((ROOT / "docs-site/content/docs").rglob("*.mdx")):
        rel = page.relative_to(ROOT / "docs-site/content/docs").as_posix()
        if rel.endswith(_SECURE_CLIENT_PAGES):
            continue
        text = page.read_text(encoding="utf-8")
        for block in re.findall(r"```json[^\n]*\n(.*?)```", text, flags=re.S):
            if '"security_complete": true' in block and _WARNED_CONNECTOR_KEYS.search(block):
                problems.append(f"{rel}: JSON sample with a warned connector reports security_complete true")
        for number, line in enumerate(text.splitlines(), 1):
            expects_true = (
                re.match(r"\|\s*`security_complete`\s*\|\s*`true`", line)
                or "`security_complete` is `true`" in line
                or ("Expected:" in line and "security_complete" in line and "`true`" in line)
            )
            if expects_true and "hook_process_fail_open" not in line:
                problems.append(f"{rel}:{number}: expects security_complete true without hook_process_fail_open")
    assert not problems, "\n".join(problems)


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


def test_policy_view_result_contract_runs_in_ci() -> None:
    result = subprocess.run(
        [sys.executable, str(RESULT_CHECKER_TEST)],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.name == "nt", reason="Linux postinstall requires a POSIX shell")
def test_postinstall_failure_contract_runs_in_ci() -> None:
    assert POSTINSTALL.is_file()
    result = subprocess.run(
        ["sh", str(POSTINSTALL_RESULT_TEST)],
        cwd=ROOT, capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.name == "nt", reason="Linux preremove requires a POSIX shell")
def test_preremove_resets_failed_user_units_runs_in_ci() -> None:
    """GAP-0137: the package removal leaves each account's sandbox user units
    inactive, not failed, after an uninstall made the daemon exit 78."""
    assert PREREMOVE.is_file()
    result = subprocess.run(
        ["sh", str(PREREMOVE_USER_UNITS_TEST), str(PREREMOVE)],
        cwd=ROOT, capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the hold reads /proc")
def test_upgrade_holds_legacy_sandbox_daemons_runs_in_ci() -> None:
    """GAP-0868 and GAP-1553: the package's hold of a pre-1.0.4 sandbox
    daemon runs in CI, not only in gate scripts (GAP-1596)."""
    result = subprocess.run(
        ["sh", str(SANDBOX_HOLD_TEST)],
        cwd=ROOT, capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the stand-in ps reads /proc")
def test_macos_pkg_sandbox_hold_runs_in_ci() -> None:
    """GAP-1554 and RB1-1: the macOS package's hold of a pre-1.0.4 sandbox
    daemon (in build-macos-enterprise-pkg.sh) runs in CI too; its test is
    written to run on Linux (GAP-1809)."""
    assert PREINSTALL.is_file() and MACOS_PKG_BUILD.is_file()
    result = subprocess.run(
        ["bash", str(MACOS_TEST_RUNNER), str(MACOS_SANDBOX_HOLD_TEST)],
        cwd=ROOT, capture_output=True, text=True, timeout=180, check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "skip" not in output, output


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


def test_the_rollback_drill_accepts_the_warnings_of_the_restored_release(tmp_path: Path) -> None:
    # GAP-1412: the pinned UBI 1.0.3 -> 1.0.4 lane stopped at 05-upgrade-fault
    # although the rollback worked: the new release reported the restored
    # 1.0.3 install's hook residual, its connectors without a trusted
    # policy-view digest and the host's ptrace sysctl, and the drill's
    # allow list named none of them. Its own checker call is run here.
    lines = UNIX_LANE.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if '"$checker" "$results/05-upgrade-fault.json"' in line)
    call = lines[start]
    while lines[start].rstrip().endswith("\\"):
        start += 1
        call += " " + lines[start]
    words = shlex.split(call.replace("\\", " "))
    words = words[words.index('$results/05-upgrade-fault.json') + 1:]
    # The host's own policy-view warnings are required, not allowed, by
    # ${kernel_views[@]} (empty on a host without them, as here).
    words = [w for w in words if not w.startswith("${held") and not w.startswith("${kernel_views")]
    words = ["linux" if w == "$platform" else w for w in words]
    drill = _result(
        ok=False, exit_code=1, installed_version="1.0.3", security_complete=False,
        errors=[{"code": "lifecycle_test_fault", "message": "fault"}],
        warnings=[{"code": code, "message": code} for code in (
            "lifecycle_test_fault", "rolled_back", "machine_policy_incomplete", "machine_policy_incomplete",
            "hook_process_fail_open", "hook_process_fail_open")],
    )
    result = _check(tmp_path, drill, *words)
    assert result.returncode == 0, (words, result.stderr)
    # A warning the restored release does not report still fails the drill.
    other = dict(drill, warnings=[*drill["warnings"], {"code": "guardian_target_failed", "message": "x"}])
    assert "unexpected warning guardian_target_failed" in _check(tmp_path, other, *words).stderr


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
    # A release older than the first that reads version 9 is given version 8 and
    # is migrated: the source may be 8, the upgraded config must be 9.
    (tmp_path / "before.yaml").write_text(before.replace("config_version: 9", "config_version: 8"), encoding="utf-8")
    assert run(before).returncode == 0, run(before).stderr
    still_v8 = run(before.replace("config_version: 9", "config_version: 8"))
    assert still_v8.returncode == 1 and "config_version is 8, want 9" in still_v8.stderr
    (tmp_path / "before.yaml").write_text(before.replace("config_version: 9", "config_version: 7"), encoding="utf-8")
    v7 = run(before)
    assert v7.returncode == 1
    assert "want 8 or 9 (the lanes upgrade from 1.x)" in v7.stderr


def _unix_lane_functions(*names: str) -> str:
    lane = UNIX_LANE.read_text(encoding="utf-8")
    found = []
    for name in names:
        match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", lane, re.MULTILINE | re.DOTALL)
        assert match, name
        found.append(match.group(0))
    cut = re.search(r"^config_v9_first_release=\S+\n", lane, re.MULTILINE)
    assert cut
    return cut.group(0) + "\n".join(found)


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
@pytest.mark.parametrize(
    ("previous", "want"),
    [("1.0.0", 8), ("v1.0.0", 8), ("1.0.0-rc.2", 8), ("1.0.1", 9), ("v1.0.5", 9), ("1.1.0", 9), ("2.0.0", 9),
     ("1.0", 9), ("latest", 9), ("", 9)],
)
def test_unix_upgrade_lane_writes_the_previous_releases_config_version(tmp_path: Path, previous: str, want: int) -> None:
    # GAP-1424: the lane wrote config_version 9 for every previous release, so a
    # 1.0.0 previous answered config_version_unsupported.
    functions = _unix_lane_functions("release_number", "admin_config_version", "write_admin_config")
    env = {**os.environ, "stage": str(tmp_path), "data_dir": str(tmp_path / "data"),
           "vendor_policy_dir": str(tmp_path / "policy"), "upgrade_from": "old.rpm", "previous_version": previous}
    result = subprocess.run(["bash", "-c", functions + "\nwrite_admin_config"], env=env,
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    text = (tmp_path / "config.yaml").read_text(encoding="utf-8")
    assert text.startswith(f"config_version: {want}\n"), text
    # A version 8 file leaves the pack to the layout; version 9 names it.
    assert ("  rule_pack: default\n" in text) == (want == 9), text
    document = yaml.safe_load(text)
    assert document["config_version"] == want and document["guardrail"]["connectors"]["codex"] == {"enabled": True}


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
def test_unix_install_lane_writes_version_9_without_a_previous_release(tmp_path: Path) -> None:
    functions = _unix_lane_functions("release_number", "admin_config_version", "write_admin_config")
    env = {**os.environ, "stage": str(tmp_path), "data_dir": str(tmp_path / "data"),
           "vendor_policy_dir": str(tmp_path / "policy"), "upgrade_from": "", "previous_version": "1.0.0"}
    result = subprocess.run(["bash", "-c", functions + "\nwrite_admin_config"], env=env,
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "config.yaml").read_text(encoding="utf-8").startswith("config_version: 9\n")


def test_windows_upgrade_lane_writes_the_previous_releases_config_version() -> None:
    lane = (SCRIPTS / "test-enterprise-windows-install.ps1").read_text(encoding="utf-8")
    assert "function Get-AdminConfigVersion" in lane and "-lt [version]'1.0.1'" in lane
    assert "\"config_version: $adminConfigVersion\"" in lane and "'config_version: 9'" not in lane
    cut = re.search(r"^config_v9_first_release=(\S+)$", UNIX_LANE.read_text(encoding="utf-8"), re.MULTILINE)
    assert cut and f"[version]'{cut.group(1)}'" in lane, "the Unix and Windows lanes name different version 9 cuts"


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
