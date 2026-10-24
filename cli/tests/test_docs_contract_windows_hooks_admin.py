# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0604: on a managed Windows computer an elevated prompt has none of the
guardian service's settings, so `enterprise hooks status` and `verify` load
no config and refuse (managedWindowsConfigLoadError). The pages must not tell
a Windows administrator to run them; `enterprise windows status` and `verify`
run them with the service's settings."""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs-site/content/docs"
CLI_GO = REPO / "internal/cli"
MODULE = REPO / "packaging/windows/DefenseClawEnterprise.psm1"


def _go_func(text: str, name: str) -> str:
    start = text.index(f"\nfunc {name}(")
    end = text.find("\n}\n", start)
    return text[start:end]


def _hooks_commands_without_config() -> set[str]:
    """`enterprise hooks` subcommands that skip the config load, so the
    managed-Windows refusal does not apply to them."""
    names = set()
    for path in CLI_GO.glob("enterprise_hooks*.go"):
        if path.name.endswith("_test.go"):
            continue
        for block in re.findall(r"&cobra\.Command\{(.*?)\n\}", path.read_text(encoding="utf-8"), re.S):
            use = re.search(r'Use:\s+"([a-z-]+)', block)
            if use and '"defenseclaw.skip-daemon-bootstrap": "true"' in block:
                names.add(use.group(1))
    return names


def _admin_hooks_commands() -> dict[str, str]:
    """The cli.mdx `enterprise hooks` table rows: verb -> who runs it."""
    text = (DOCS / "reference/commands/cli.mdx").read_text(encoding="utf-8")
    section = text.split("### Per-user hooks (`enterprise hooks`)", 1)[1].split("\n### ", 1)[0]
    rows = {}
    for line in section.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 3:
            continue
        for verb in re.findall(r"enterprise hooks ([a-z-]+)", cells[0]) + re.findall(
            r"`([a-z-]+)`", cells[0].split("`,", 1)[-1]
        ):
            rows[verb] = cells[1]
    return rows


def test_managed_windows_refuses_the_per_user_config_load():
    root = (CLI_GO / "root.go").read_text(encoding="utf-8")
    assert "managedWindowsConfigLoadError(cmd, err)" in root
    guard = _go_func((CLI_GO / "managed_host_guard.go").read_text(encoding="utf-8"), "managedWindowsConfigLoadError")
    assert "managedHostWindowsStandalone()" in guard
    assert guard.rstrip().endswith("return managedWindowsAdminCommandAnswer(where, command)")
    # Only the in-process service pin skips the per-user config, and an
    # elevated prompt does not have it.
    assert "managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv))" in guard


def test_windows_lifecycle_runs_the_hooks_status_and_verify():
    module = MODULE.read_text(encoding="utf-8")
    assert "$verb = if ($LiveVerify) { 'verify' } else { 'status' }" in module
    assert "-Arguments @('enterprise', 'hooks', $verb, '--manifest', $Layout.ManifestPath, '--json')" in module
    status = module.split("function Get-DefenseClawLifecycleStatus", 1)[1].split("\nfunction ", 1)[0]
    assert "Get-DefenseClawGuardianStatusReport" in status
    report = module.split("function Get-DefenseClawGuardianStatusReport", 1)[1].split("\nfunction ", 1)[0]
    assert "@('enterprise', 'hooks', 'status'" in report
    assert_deployment = module.split("function Assert-DefenseClawEnterpriseDeployment", 1)[1].split("\nfunction ", 1)[0]
    assert "-LiveVerify" in assert_deployment


def test_cli_reference_hooks_table_names_the_windows_command_for_administrators():
    exempt = _hooks_commands_without_config()
    assert "scrub" in exempt
    rows = _admin_hooks_commands()
    assert {"status", "verify"} <= set(rows)
    wrong = []
    for verb, who in rows.items():
        if verb in exempt or "administrator" not in who.lower():
            continue
        if "Linux and macOS" not in who or f"On Windows, `enterprise windows {verb}` runs it" not in who:
            wrong.append((verb, who))
    assert not wrong, wrong


def test_no_page_runs_enterprise_hooks_status_or_verify_from_a_standalone_windows_prompt():
    exempt = _hooks_commands_without_config()
    offenders = []
    for page in sorted(DOCS.rglob("*.mdx")):
        text = page.read_text(encoding="utf-8")
        for block in re.findall(r"```(?:powershell|pwsh|ps1)\n(.*?)```", text, re.S):
            # The refusal is the standalone deployment's; Secure Client
            # pages and paths are out of its scope.
            if "secure-client" in page.stem or "Cisco Secure Client" in block:
                continue
            for verb in re.findall(r"enterprise hooks ([a-z-]+)", block):
                if verb not in exempt:
                    offenders.append((str(page.relative_to(DOCS)), verb))
        for line in text.splitlines():
            if not line.lstrip().startswith("|") or "dministrator" not in line:
                continue
            for verb in re.findall(r"enterprise hooks ([a-z-]+)", line):
                if verb not in exempt and not re.search(r"Linux|macOS|sudo", line):
                    offenders.append((str(page.relative_to(DOCS)), line.strip()[:120]))
    assert not offenders, offenders


def test_cli_reference_says_how_a_windows_administrator_checks_the_hooks():
    text = " ".join((DOCS / "reference/commands/cli.mdx").read_text(encoding="utf-8").split())
    assert "To run `status` or `verify` yourself on Linux or macOS" in text
    assert (
        "On a managed Windows computer an elevated prompt has none of the service's settings, so "
        "`enterprise hooks status` and `verify` refuse and name `enterprise windows status --profile standalone`"
    ) in text
    # The refusal's own hint.
    hint = _go_func((CLI_GO / "managed_host_guard.go").read_text(encoding="utf-8"), "managedWindowsAdminStatusHint")
    assert "enterprise windows status --profile standalone" in hint
