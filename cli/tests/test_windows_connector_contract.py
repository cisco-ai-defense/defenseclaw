# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The required Windows connector contract covers every Windows connector.

windows-native.yml runs scripts/live-connector-e2e/run-windows-install.ps1 for
each connector on an install.ps1 install of the pull request's own assets.
Dropping a connector from the matrix, the harness or Windows Native Required
fails here, and so does a new Windows connector nobody added.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.platform_support import WINDOWS_SUPPORTED_CONNECTORS  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = REPO / ".github" / "workflows" / "windows-native.yml"
HARNESS = REPO / "scripts" / "live-connector-e2e" / "run-windows-install.ps1"
RUN_SH = REPO / "scripts" / "live-connector-e2e" / "run.sh"
GOLDEN = REPO / "scripts" / "live-connector-e2e" / "golden"

# Windows connectors outside the shell-hook list of run.sh, and why.
PLUGIN_CONNECTORS = {"opencode"}  # a plugin: its golden commands go through the installed plugin
# Kiro has no golden hook contract in the live harness on any OS, so it stays out of the 1.0.9 gate.
# GAP-0676 changes its per-user Windows command (a cmd.exe-wrapped bridge that answers a launcher
# that cannot start); the Go Windows shard exercises that. A registration-only cell or a golden
# is a 1.0.10 item.
NO_CONTRACT = {"kiro"}


def _jobs() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def _shell_hook_connectors() -> set[str]:
    match = re.search(r"^ALL_CONNECTORS=\(([^)]*)\)", RUN_SH.read_text(encoding="utf-8"), re.MULTILINE)
    assert match, "run.sh ALL_CONNECTORS not found"
    return set(match.group(1).split())


def _matrix() -> list[str]:
    return list(_jobs()["connector-contract"]["strategy"]["matrix"]["connector"])


def test_the_matrix_is_every_windows_shell_hook_connector_plus_the_plugins() -> None:
    matrix = _matrix()
    assert len(matrix) == len(set(matrix))
    assert set(matrix) == (_shell_hook_connectors() & WINDOWS_SUPPORTED_CONNECTORS) | PLUGIN_CONNECTORS


def test_every_windows_connector_is_in_the_matrix_or_named_with_a_reason() -> None:
    assert set(_matrix()) | NO_CONTRACT == WINDOWS_SUPPORTED_CONNECTORS
    assert not set(_matrix()) & NO_CONTRACT


def test_the_harness_accepts_exactly_the_matrix() -> None:
    match = re.search(r"\[ValidateSet\(([^)]*)\)\]\s*\[string\]\$Connector", HARNESS.read_text(encoding="utf-8"))
    assert match, "run-windows-install.ps1 -Connector ValidateSet not found"
    assert set(re.findall(r"'([a-z]+)'", match.group(1))) == set(_matrix())


def test_every_matrix_connector_has_allow_and_block_payloads() -> None:
    for connector in _matrix():
        assert (GOLDEN / connector / "pre_tool_allow.json").is_file(), connector
        assert (GOLDEN / connector / "pre_tool_block.json").is_file(), connector
    # The Windows block commands where the POSIX one does not apply.
    for connector in ("copilot", "opencode"):
        assert "Remove-Item" in (GOLDEN / connector / "pre_tool_block_windows.json").read_text(encoding="utf-8")


def test_the_contract_installs_this_trees_assets_with_install_ps1() -> None:
    jobs = _jobs()
    build = "\n".join(step.get("run", "") for step in jobs["contract-assets"]["steps"])
    assert "scripts/build-release-assets.sh" in build and "windows/amd64" in build
    contract = jobs["connector-contract"]
    assert set(contract["needs"]) == {"changes", "contract-assets"}
    assert contract["strategy"]["fail-fast"] is False
    run = "\n".join(step.get("run", "") for step in contract["steps"])
    assert "run-windows-install.ps1 -Operation contract -Connector $env:CONNECTOR" in run
    lifecycle = jobs["install-lifecycle"]
    assert lifecycle["strategy"]["matrix"]["cell"] == ["uninstall", "fresh", "files-in-use"]
    steps = "\n".join(step.get("run", "") for step in lifecycle["steps"])
    assert "run-windows-install.ps1 -Operation lifecycle" in steps
    assert "test-install-lifecycle.ps1" in steps and "-Lanes $env:CELL" in steps
    harness = HARNESS.read_text(encoding="utf-8")
    assert "'-Local', $Assets" in harness and "contract-smoke.sh" in harness


def test_windows_native_required_needs_the_contract_jobs() -> None:
    jobs = _jobs()
    needs = set(jobs["windows-native-required"]["needs"])
    assert {"contract-assets", "connector-contract", "install-lifecycle"} <= needs
    # The selector feeds the asset build, and the cells follow it.
    assert "windows_contract" in jobs["changes"]["outputs"]
    assert "needs.changes.outputs.windows_contract" in jobs["contract-assets"]["if"]
    for name in ("connector-contract", "install-lifecycle"):
        assert "needs.contract-assets.result == 'success'" in jobs[name]["if"]


def test_the_parser_self_test_runs_in_the_powershell_job() -> None:
    steps = "\n".join(step.get("run", "") for step in _jobs()["powershell-static"]["steps"])
    assert "run-windows-install.ps1 -Operation self-test" in steps
    harness = HARNESS.read_text(encoding="utf-8")
    # Both Codex start forms and both bridge forms (rel-1-0-6 GAP-0676).
    assert "launcher-guard-sibling" in harness and "(?<answer>" in harness


def test_the_self_test_reads_bridges_as_the_generator_renders_them() -> None:
    """The fixture holds decoded generator output, not a hand-written copy.

    g676's launcher-start answer writes its sentence through [Console]::Error
    and, in Constrained Language mode, through Write-Error. A parser written
    against another text rejects every shipped bridge (review g088r M1).
    """
    harness = HARNESS.read_text(encoding="utf-8")
    assert "windows-hook-bridges.json" in harness
    bridges = json.loads((HARNESS.parent / "testdata" / "windows-hook-bridges.json").read_text(encoding="utf-8"))["bridges"]
    answering = [bridge for bridge in bridges if not bridge["name"].endswith("unanswered")]
    assert any(bridge["name"] == "antigravity/PreToolUse" for bridge in answering)
    assert sum(bridge["name"].startswith("codex/") for bridge in answering) >= 7
    assert len(answering) < len(bridges)
    for bridge in answering:
        script = bridge["script"]
        # The same answer in the three places, each with the Write-Error fallback.
        assert script.count("Microsoft.PowerShell.Utility\\Write-Error -Message") == 3, bridge["name"]
        assert "catch { }" not in script, bridge["name"]
    # The parser accepts the Write-Error form and the self-test refuses `catch { }`.
    assert "Microsoft\\.PowerShell\\.Utility\\\\Write-Error -Message" in harness
    assert "catch { } in all three places" in harness


def test_the_harness_runs_only_on_a_disposable_account() -> None:
    """It writes agent stand-ins to the real Known Folders and may edit the user Path."""
    harness = HARNESS.read_text(encoding="utf-8")
    assert "$env:RUNNER_ENVIRONMENT -eq 'github-hosted'" in harness
    assert "DEFENSECLAW_CONTRACT_ALLOW_REAL_PROFILE" in harness
    # The guard runs before the profile is built and before anything is installed.
    assert harness.index("DEFENSECLAW_CONTRACT_ALLOW_REAL_PROFILE") < harness.index("function Enter-Profile")


def test_the_lifecycle_cell_has_a_user_path_entry_to_remove() -> None:
    lifecycle = _jobs()["install-lifecycle"]
    steps = "\n".join(step.get("run", "") for step in lifecycle["steps"])
    assert "run-windows-install.ps1 -Operation lifecycle -PersistPath" in steps
    # fresh and files-in-use took 8 and 3.5 minutes on a faster host: the job needs room.
    assert lifecycle["timeout-minutes"] >= 30
