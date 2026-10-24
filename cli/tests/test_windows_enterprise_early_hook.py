"""GAP-0993: a managed Windows upgrade puts the replacement hook in place
before it stops the services.

During the documented 1.0.2 -> 1.0.4 Setup upgrade the 1.0.2 hook binary kept
answering at its fixed path after the lifecycle had stopped the gateway
service, and it lets a Hermes tool call run whenever its gateway is down (16
calls ran in the T8 lane). New-DefenseClawTransaction now publishes the
replacement hook (this release's, which answers closed while the lifecycle
has the services disabled) before it disables and stops them, keeps the
prior hook as its preimage, and every path that restarts the prior services
before the snapshot exists puts the prior hook back.

GAP-1070: a call the replaced hook had already taken (a process still reading
its input or waiting for its answer) still met the stopped service. After the
swap the transaction waits, bounded, until every hook process that started
before it has ended, while the old gateway still answers them. GAP-1124: the
bound covers the replaced hook's whole budget for a call.
"""

from __future__ import annotations

import json
import os
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


def test_the_transaction_publishes_the_hook_before_it_stops_the_services() -> None:
    module = _text()
    transaction = _function_body(module, "New-DefenseClawTransaction")
    publish = transaction.index("Publish-DefenseClawEarlyHook")
    # After the intent that recovery reads, before the first service change.
    assert transaction.index("$quiescingIntentPublished = $true") < publish
    assert publish < transaction.index("Write-DefenseClawLifecyclePhase -Stage 'transaction quiesce disable services'")
    assert publish < transaction.index("Stop-DefenseClawService -Name $GatewayServiceName")
    # The snapshot's hook preimage is the prior release's bytes.
    assert "$preimageSource = $earlyHookPreimage" in transaction
    assert "Copy-Item -LiteralPath $preimageSource -Destination $backup -Force" in transaction
    # A failed snapshot puts the prior hook back before it restarts the
    # prior services.
    catch = transaction[transaction.index("$restartErrors = [Collections.Generic.List[string]]::new()") :]
    assert catch.index("Restore-DefenseClawEarlyHook") < catch.index("Start-DefenseClawTransactionServices")
    # So does the recovery of an interrupted transaction.
    recovery = _function_body(module, "Recover-DefenseClawQuiescingIntent")
    assert recovery.index("Restore-DefenseClawEarlyHook") < recovery.index("Start-DefenseClawTransactionServices")
    # Install, Upgrade and Repair hand it the authenticated replacement hook.
    assert "-EarlyHookSource $earlyHookSource" in module
    assert "$earlyHookSource = $Sources['hook']" in module
    # GAP-1070: the wait for the replaced hook's calls is part of the early
    # publish, so it ends before the services are disabled and stopped.
    publish_body = _function_body(module, "Publish-DefenseClawEarlyHook")
    swap = publish_body.index("Install-DefenseClawSourceDescriptor -Source $Source -Destination $Layout.HookPath")
    wait = publish_body.index("Wait-DefenseClawPriorHookCalls -HookPath $Layout.HookPath -StartedBefore ([DateTime]::Now)")
    assert swap < wait < publish_body.index("return $preimage")


_HARNESS = r"""
param([string]$ModulePath, [string]$Scratch, [string]$Case)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "module parse failed: $($errors[0].Message)" }
foreach ($name in @('Publish-DefenseClawEarlyHook', 'Restore-DefenseClawEarlyHook', 'Wait-DefenseClawPriorHookCalls', 'Get-DefenseClawPriorHookProcessIds')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true)
    if ($null -eq $definition) { throw "missing $name" }
    . ([ScriptBlock]::Create($definition.Extent.Text))
}
$script:events = [Collections.Generic.List[string]]::new()
function Assert-DefenseClawNoReparsePath { param([string]$Path, [switch]$AllowMissingLeaf) }
function Write-DefenseClawJsonAtomic {
    param($Value, [string]$Path)
    $script:events.Add('intent:' + [string]($Value.Contains('early_hook_preimage')))
    ($Value | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $Path -Encoding utf8
}
function Install-DefenseClawSourceDescriptor {
    param([hashtable]$Source, [string]$Destination)
    $script:events.Add('publish:' + (Get-Content -LiteralPath $Destination -Raw))
    Copy-Item -LiteralPath $Source.path -Destination $Destination -Force
}
function Write-DefenseClawLifecyclePhase {
    param([string]$Stage)
    $script:events.Add('phase:' + $Stage)
}
if ($Case -like 'drain*') {
    # The replaced release's hook process 4242 ends after two looks (drain),
    # or never (drain-timeout).
    $script:looks = 0
    function Get-DefenseClawPriorHookProcessIds {
        param([string]$HookPath, [datetime]$StartedBefore)
        $script:looks++
        $script:events.Add('look:' + [string]$script:looks)
        if ($Case -eq 'drain-timeout' -or $script:looks -le 2) { 4242 }
    }
}
function Install-DefenseClawFileAtomic {
    param([string]$Source, [string]$Destination, [string]$ExpectedSHA256)
    $script:events.Add('restore')
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}
$bin = Join-Path $Scratch 'bin'
$transaction = Join-Path $Scratch 'transaction'
New-Item -ItemType Directory -Path $bin, $transaction -Force | Out-Null
$hook = Join-Path $bin 'defenseclaw-hook.exe'
$new = Join-Path $Scratch 'new-hook.exe'
Set-Content -LiteralPath $hook -Value 'hook-1.0.2' -NoNewline
Set-Content -LiteralPath $new -Value 'hook-1.0.4' -NoNewline
$layout = @{ HookPath = $hook; PendingPath = (Join-Path $Scratch 'pending.json') }
$intent = [ordered]@{ schema_version = 1; phase = 'quiescing' }
$result = [ordered]@{ case = $Case; threw = '' }
try {
    switch ($Case) {
        'publish' {
            $preimage = Publish-DefenseClawEarlyHook -Layout $layout -Source @{ path = $new } -TransactionDirectory $transaction -Intent $intent -PriorDeploymentActive
            $result.preimage = $preimage
            $result.preimage_bytes = Get-Content -LiteralPath $preimage -Raw
            $result.hook = Get-Content -LiteralPath $hook -Raw
            $result.pending = (Get-Content -LiteralPath $layout.PendingPath -Raw | ConvertFrom-Json).early_hook_preimage
            # Recovery reads the intent back from pending.json.
            $read = Get-Content -LiteralPath $layout.PendingPath -Raw | ConvertFrom-Json
            Restore-DefenseClawEarlyHook -Layout $layout -Intent $read -TransactionDirectory $transaction
            $result.restored = Get-Content -LiteralPath $hook -Raw
        }
        'snapshot-failure' {
            [void](Publish-DefenseClawEarlyHook -Layout $layout -Source @{ path = $new } -TransactionDirectory $transaction -Intent $intent -PriorDeploymentActive)
            Restore-DefenseClawEarlyHook -Layout $layout -Intent $intent -TransactionDirectory $transaction
            $result.restored = Get-Content -LiteralPath $hook -Raw
        }
        'first-install' {
            $result.preimage = Publish-DefenseClawEarlyHook -Layout $layout -Source @{ path = $new } -TransactionDirectory $transaction -Intent $intent
            $result.hook = Get-Content -LiteralPath $hook -Raw
            Restore-DefenseClawEarlyHook -Layout $layout -Intent $intent -TransactionDirectory $transaction
        }
        'no-source' {
            $result.preimage = Publish-DefenseClawEarlyHook -Layout $layout -Source $null -TransactionDirectory $transaction -Intent $intent -PriorDeploymentActive
            $result.hook = Get-Content -LiteralPath $hook -Raw
        }
        'drain' {
            [void](Publish-DefenseClawEarlyHook -Layout $layout -Source @{ path = $new } -TransactionDirectory $transaction -Intent $intent -PriorDeploymentActive)
            $script:events.Add('returned')
        }
        'drain-timeout' {
            $started = [DateTime]::UtcNow
            $result.running = @(Wait-DefenseClawPriorHookCalls -HookPath $hook -StartedBefore ([DateTime]::Now) -TimeoutSeconds 1)
            $result.seconds = ([DateTime]::UtcNow - $started).TotalSeconds
        }
        'started-before' {
            # This PowerShell process runs under its own image name: it
            # counts when it started before the swap, never when after.
            $self = [Diagnostics.Process]::GetCurrentProcess()
            $image = $self.ProcessName + '.exe'
            $result.before = @(Get-DefenseClawPriorHookProcessIds -HookPath (Join-Path $bin $image) -StartedBefore ([DateTime]::Now)) -contains $self.Id
            $result.after = @(Get-DefenseClawPriorHookProcessIds -HookPath (Join-Path $bin $image) -StartedBefore $self.StartTime.AddSeconds(-1)) -contains $self.Id
        }
        'foreign-preimage' {
            $intent['early_hook_preimage'] = (Join-Path $Scratch 'elsewhere.exe')
            Set-Content -LiteralPath $intent['early_hook_preimage'] -Value 'attacker' -NoNewline
            Restore-DefenseClawEarlyHook -Layout $layout -Intent $intent -TransactionDirectory $transaction
        }
    }
}
catch {
    $result.threw = $_.Exception.Message
}
$result.events = @($script:events)
$result | ConvertTo-Json -Compress -Depth 6
"""


def _pwsh() -> str | None:
    return os.environ.get("DEFENSECLAW_TEST_PWSH") or shutil.which("pwsh") or shutil.which("pwsh.exe")


def _run(tmp_path: Path, case: str) -> dict:
    engine = _pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    harness = tmp_path / "early-hook.ps1"
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


def test_the_replacement_hook_goes_in_after_its_preimage_is_recorded(tmp_path: Path) -> None:
    result = _run(tmp_path, "publish")
    assert result["threw"] == "", result
    assert result["preimage_bytes"] == "hook-1.0.2", result
    assert result["hook"] == "hook-1.0.4", result
    assert result["pending"] == result["preimage"], result
    # The intent names the preimage before the hook changes.
    assert result["events"][:2] == ["intent:True", "publish:hook-1.0.2"], result
    # Recovery of the interrupted transaction puts the prior hook back.
    assert result["restored"] == "hook-1.0.2", result


def test_a_failed_snapshot_puts_the_prior_hook_back(tmp_path: Path) -> None:
    result = _run(tmp_path, "snapshot-failure")
    assert result["threw"] == "", result
    assert result["restored"] == "hook-1.0.2", result


@pytest.mark.parametrize("case", ["first-install", "no-source"])
def test_nothing_is_published_early_without_a_prior_deployment_or_a_replacement(tmp_path: Path, case: str) -> None:
    result = _run(tmp_path, case)
    assert result["threw"] == "", result
    assert result["preimage"] == "", result
    assert result["hook"] == "hook-1.0.2", result
    assert "restore" not in result["events"], result


def test_the_early_publish_waits_for_the_replaced_hooks_calls(tmp_path: Path) -> None:
    result = _run(tmp_path, "drain")
    assert result["threw"] == "", result
    events = result["events"]
    # The swap, then looks until the replaced hook's process has ended, then
    # the transaction goes on (and disables and stops the services).
    assert events[:2] == ["intent:True", "publish:hook-1.0.2"], result
    assert events[2:] == ["look:1", "look:2", "look:3", "returned"], result


def test_the_wait_for_the_replaced_hooks_calls_is_bounded(tmp_path: Path) -> None:
    result = _run(tmp_path, "drain-timeout")
    assert result["threw"] == "", result
    assert result["running"] == [4242], result
    assert result["seconds"] < 30, result


def test_the_wait_covers_the_replaced_hooks_whole_budget() -> None:
    """GAP-1124: the 60 s wait ended before a replaced hook's call could no
    longer reach the gateway: a 1.0.3 Claude Code Stop, SubagentStop or
    PostToolBatch call has 90 s, counted from a start up to 30 s after the
    process was created, and the transaction then stopped the gateway under
    it. The wait covers both, and is the Linux and macOS lifecycle's wait for
    their replaced shell hooks (replacedHookCallsBudget)."""
    body = _function_body(_text(), "Wait-DefenseClawPriorHookCalls")
    match = re.search(r"\[int\]\$TimeoutSeconds = (\d+)", body)
    assert match is not None, body
    windows = int(match.group(1))
    assert windows >= 90 + 30, windows
    unix = (ROOT / "internal" / "enterpriseunix" / "replaced_hooks.go").read_text(encoding="utf-8")
    match = re.search(r"replacedHookCallsBudget = (\d+) \* time\.Second", unix)
    assert match is not None
    assert int(match.group(1)) == windows


def test_only_hook_processes_started_before_the_swap_are_waited_for(tmp_path: Path) -> None:
    result = _run(tmp_path, "started-before")
    assert result["threw"] == "", result
    assert result["before"] is True, result
    assert result["after"] is False, result


def test_recovery_refuses_a_preimage_outside_its_transaction(tmp_path: Path) -> None:
    result = _run(tmp_path, "foreign-preimage")
    assert "unexpected hook preimage" in result["threw"], result
    assert "restore" not in result["events"], result
