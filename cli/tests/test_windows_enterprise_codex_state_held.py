r"""GAP-0765: the upgrade from 1.0.8 does not report success, or fail late,
when a user holds the Codex managed-hooks state of 1.0.8 open.

1.0.8 wrote C:\ProgramData\OpenAI\Codex\.defenseclaw-managed-hooks.state where
every standard user can read it, so a user can open it with FileShare.None.
The upgrade reads that file twice (the transaction snapshot, then the first
Codex transaction of this release). Before anything is stopped, Setup waits
for the release (bounded), and a holder still there defers the run with the
retryable codex_state_held (exit 1618), naming the program, with the file
untouched. Standalone only: Secure Client keeps the state at its fixed name.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"


def _text() -> str:
    return MODULE.read_text(encoding="utf-8")


def _function_body(text: str, name: str) -> str:
    start = text.index(f"function {name} {{\n")
    end = text.index("\n}\n", start)
    return text[start : end + 3]


def test_the_transaction_checks_the_codex_state_before_it_changes_anything() -> None:
    body = _function_body(_text(), "New-DefenseClawTransaction")
    check = body.index("Assert-DefenseClawCodexStateNotHeld -Layout $Layout")
    guard = body.rindex("if ((Test-DefenseClawStandaloneProfile) -and -not $SkipRedactionKeySnapshot) {", 0, check)
    assert check - guard < 600
    # Secure Client and the uninstall transaction are not gated.
    assert body.index("Assert-DefenseClawHookNotHeld -Layout $Layout") < check
    assert check < body.index("New-DefenseClawDirectory -Path $directory")
    assert check < body.index("Set-DefenseClawServiceStartMode")
    assert check < body.index("Publish-DefenseClawEarlyHook")
    assert check < body.index("$quiescingIntentPublished = $true")


def test_the_codex_state_hold_is_a_retryable_named_refusal() -> None:
    body = _function_body(_text(), "Assert-DefenseClawCodexStateNotHeld")
    assert "[int]$TimeoutSeconds = 30" in body
    assert "throw (\"codex_state_held: " in body
    assert "state file is as it was" in body
    assert "exit 1618" in body
    # The holders are named by Restart Manager, as for the installed hook.
    assert "Get-DefenseClawStateFileHolders -Layout $Layout -Paths @($path)" in body
    probe = _function_body(_text(), "Test-DefenseClawFileReadBlocked")
    assert "[IO.FileAccess]::Read" in probe
    assert "-band 0xFFFF) -in @(32, 33)" in probe
    assert "return $false" in probe  # a failed probe never blocks: the read reports it


def test_setup_exits_1618_for_a_held_codex_state() -> None:
    go = (ROOT / "internal" / "cli" / "windows_enterprise_standalone.go").read_text(encoding="utf-8")
    assert re.search(r'case "hook_calls_running", "hook_in_use", "codex_state_held":', go)


_HARNESS = r"""
param([string]$ModulePath, [string]$Scratch, [string]$Case)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "module parse failed: $($errors[0].Message)" }
foreach ($name in @('Assert-DefenseClawCodexStateNotHeld')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true)
    if ($null -eq $definition) { throw "missing $name" }
    . ([ScriptBlock]::Create($definition.Extent.Text))
}
$script:events = [Collections.Generic.List[string]]::new()
$script:looks = 0
$state = Join-Path $Scratch '.defenseclaw-managed-hooks.state'
if ($Case -ne 'absent') { Set-Content -LiteralPath $state -Value 'state-of-1.0.8' -NoNewline }
function Test-DefenseClawFileReadBlocked {
    param([string]$Path)
    $script:looks++
    $script:events.Add('look:' + [string]$script:looks)
    return ($Case -eq 'held-stays' -or $Case -eq 'held-unnamed' -or ($Case -eq 'held-closes' -and $script:looks -le 2))
}
function Get-DefenseClawStateFileHolders {
    param([hashtable]$Layout, [string[]]$Paths, $Excluded)
    $script:events.Add('holders')
    if ($Case -eq 'held-unnamed') { return @{} }
    return @{ '4343/1' = [pscustomobject]@{ Id = 4343; Name = 'holder.exe'; UserName = 'EC2\user1'; Parent = ''; File = '' } }
}
$threw = ''
try {
    Assert-DefenseClawCodexStateNotHeld -Layout @{ CodexManagedHooksStatePath = $state } -TimeoutSeconds 2
}
catch { $threw = $_.Exception.Message }
[pscustomobject]@{
    threw = $threw
    events = @($script:events)
    state = $(if (Test-Path -LiteralPath $state) { [IO.File]::ReadAllText($state) } else { '<absent>' })
} | ConvertTo-Json -Compress
"""


def _pwsh() -> str | None:
    return shutil.which("pwsh")


def _run(tmp_path: Path, case: str) -> dict:
    engine = _pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    harness = tmp_path / "codex-state-held.ps1"
    harness.write_text(_HARNESS, encoding="utf-8")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness),
         "-ModulePath", str(MODULE), "-Scratch", str(scratch), "-Case", case],
        capture_output=True, text=True, timeout=180, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_a_state_file_nobody_holds_does_not_defer_the_run(tmp_path: Path) -> None:
    result = _run(tmp_path, "free")
    assert result["threw"] == "", result
    assert result["events"] == ["look:1"], result


def test_no_state_file_means_nothing_to_wait_for(tmp_path: Path) -> None:
    result = _run(tmp_path, "absent")
    assert result["threw"] == "", result
    assert result["events"] == [], result


def test_the_run_goes_on_once_the_holder_released_the_state(tmp_path: Path) -> None:
    result = _run(tmp_path, "held-closes")
    assert result["threw"] == "", result
    assert result["events"] == ["look:1", "look:2", "look:3"], result


def test_a_holder_still_there_defers_the_run_and_the_state_is_untouched(tmp_path: Path) -> None:
    result = _run(tmp_path, "held-stays")
    assert result["threw"].startswith("codex_state_held: holder.exe (process id 4343, EC2\\user1) has "), result
    assert "this run stopped and changed nothing" in result["threw"], result
    assert "run the same Setup command again" in result["threw"], result
    assert result["events"][-1] == "holders", result
    assert result["state"] == "state-of-1.0.8", result


def test_an_unnamed_holder_still_defers_the_run(tmp_path: Path) -> None:
    result = _run(tmp_path, "held-unnamed")
    assert result["threw"].startswith("codex_state_held: a program has "), result
