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


def test_one_codex_cell_runs_where_only_the_powershell_bridge_can_start_the_launcher() -> None:
    """Setup writes Codex's bridge form for a launcher path cmd.exe cannot carry (review g088r S1).

    windowsCmdDirectPath (internal/gateway/connector/helpers.go) carries letters, digits and
    \\ . _ - ~ only, so a folder such as "Jean (work)" or "O'Brien" gets the encoded PowerShell
    bridge. That form is the whole fail-closed answer on such a path, so one more Codex cell runs
    the contract (setup, the Doctor row, allow and block through the hook) from a state root that
    has such a character. The harness reads both bridge forms (before and after GAP-0676), so the
    cell needs no gate on the g676 branch.
    """
    contract = _jobs()["connector-contract"]
    matrix = contract["strategy"]["matrix"]
    # `leaf` has one value for every connector; the include overwrites it, which is what makes the
    # include a new cell and not an extra key on the existing codex one.
    assert matrix["leaf"] == ["contract"]
    extra = [entry for entry in matrix["include"] if entry["connector"] == "codex"]
    assert len(extra) == 1 and len(matrix["include"]) == 1
    leaf = extra[0]["leaf"]
    assert leaf != "contract"
    assert re.search(r"[^A-Za-z0-9\\._~ -]", leaf), f"{leaf!r} is a folder the direct cmd.exe form can carry"
    run = "\n".join(step.get("run", "") for step in contract["steps"])
    assert "-StateRoot (Join-Path $env:DC_STATE_ROOT $env:CONTRACT_LEAF)" in run
    assert contract["env"]["CONTRACT_LEAF"] == "${{ matrix.leaf }}"
    # Two codex cells must not upload to the same artifact name or read the other's results.
    # The suffix must sit on the truthy side: "a && '' || b" is always b, because '' is falsy (review g088r M1).
    assert contract["name"] == (
        "Windows x64 connector contract / ${{ matrix.connector }}"
        "${{ matrix.leaf != 'contract' && ' (launcher path with parentheses)' || '' }}"
    )
    uploads = [step["with"] for step in contract["steps"] if str(step.get("uses", "")).startswith("actions/upload-artifact")]
    assert [upload["name"] for upload in uploads] == [
        "windows-native-contract-results-${{ matrix.connector }}${{ matrix.leaf != 'contract' && '-bridge' || '' }}",
        "windows-native-contract-diagnostics-${{ matrix.connector }}${{ matrix.leaf != 'contract' && '-bridge' || '' }}",
    ]
    assert "matrix.leaf" in uploads[0]["path"]
    assert "&& '' ||" not in WORKFLOW.read_text(encoding="utf-8")
    # Evaluate the three names for every cell (the official @actions/expressions evaluator gave the
    # same answers; see IN-r109-g088r.md). Only the bridge cell is renamed, and no two cells collide.
    cells = [{"connector": connector, "leaf": leaf} for connector in matrix["connector"] for leaf in matrix["leaf"]]
    cells += [dict(entry) for entry in matrix["include"]]
    names = {"job": [], "results": [], "diagnostics": []}
    for cell in cells:
        for key, template in (("job", contract["name"]), ("results", uploads[0]["name"]), ("diagnostics", uploads[1]["name"])):
            names[key].append(_render(template, cell))
    for key, rendered in names.items():
        assert len(rendered) == len(set(rendered)) == len(matrix["connector"]) + 1, (key, rendered)
    renamed = [cell for cell, name in zip(cells, names["results"]) if name.endswith("-bridge")]
    assert renamed == extra
    assert [name for name in names["job"] if name.endswith(" (launcher path with parentheses)")] == [
        "Windows x64 connector contract / codex (launcher path with parentheses)"
    ]
    harness = HARNESS.read_text(encoding="utf-8")
    # The harness computes the same condition and refuses the direct form on such a path. The throw
    # statement itself is pinned, so removing it (or its condition) fails here and not only the text.
    assert "$script:BinNeedsBridge" in harness
    assert "[\\p{L}\\p{Nd} \\\\._~-]" in harness
    assert re.search(
        r"if \(\$script:BinNeedsBridge -and \$null -ne \$bridge\) \{\s*throw \"Codex command_windows starts the launcher "
        r"through cmd\.exe although \$script:Bin has a character that form cannot carry",
        harness,
    )


def _render(template: str, cell: dict[str, str]) -> str:
    """Evaluate the only expression shapes the contract names use: matrix.connector and the leaf ternary."""

    def one(match: re.Match[str]) -> str:
        expression = match.group(1).strip()
        if expression == "matrix.connector":
            return cell["connector"]
        ternary = re.fullmatch(r"matrix\.leaf != 'contract' && '([^']+)' \|\| ''", expression)
        assert ternary, f"unexpected expression {expression!r}"
        return ternary.group(1) if cell["leaf"] != "contract" else ""

    return re.sub(r"\$\{\{(.*?)\}\}", one, template)


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
    # files-in-use is the longest cell: 10-15 minutes of whole-job time on hosted runners
    # (ci.yml runs the same lane), so the job keeps the full 20-minute pull request budget.
    assert lifecycle["timeout-minutes"] == 20
