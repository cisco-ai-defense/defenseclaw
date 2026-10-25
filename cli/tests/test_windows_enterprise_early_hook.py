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
    # A failed snapshot keeps this release's hook in place until the prior
    # gateway has passed its restored-service readiness check.
    catch = transaction[transaction.index("$restartErrors = [Collections.Generic.List[string]]::new()") :]
    assert "if (-not (Test-DefenseClawStandaloneProfile))" in catch
    assert catch.index("Start-DefenseClawTransactionServices") < catch.rindex("Restore-DefenseClawEarlyHook")
    # So does the recovery of an interrupted transaction. A 1.0.2 Hermes
    # hook at its registered path answers open if restored while SCM is down.
    recovery = _function_body(module, "Recover-DefenseClawQuiescingIntent")
    assert "if (-not (Test-DefenseClawStandaloneProfile))" in recovery
    assert recovery.index("Start-DefenseClawTransactionServices") < recovery.rindex("Restore-DefenseClawEarlyHook")
    restore = _function_body(module, "Restore-DefenseClawTransaction")
    assert "Hold-DefenseClawEarlyHookGuard" in restore
    assert "if ($transitionHookSHA256 -ne ''" in restore
    assert restore.index("Start-DefenseClawTransactionServices") < restore.index("Restore-DefenseClawSnapshotHookAfterActivation")
    deferred = _function_body(module, "Restore-DefenseClawTransactionWithManagedHooksRollback")
    assert deferred.index("Start-DefenseClawTransactionServices") < deferred.index("Restore-DefenseClawSnapshotHookAfterActivation")
    # Install, Upgrade and Repair hand it the authenticated replacement hook.
    assert "-EarlyHookSource $earlyHookSource" in module
    assert "$earlyHookSource = $Sources['hook']" in module
    # GAP-1070: the wait for the replaced hook's calls is part of the early
    # publish, so it ends before the services are disabled and stopped.
    publish_body = _function_body(module, "Publish-DefenseClawEarlyHook")
    swap = publish_body.index("Install-DefenseClawSourceDescriptor -Source $Source -Destination $Layout.HookPath")
    wait = publish_body.index("Wait-DefenseClawPriorHookCalls -HookPath $Layout.HookPath -StartedBefore ([DateTime]::Now)")
    assert swap < wait < publish_body.index("return $preimage")



def test_standalone_publishes_the_hook_after_the_prior_guardian_stopped() -> None:
    # GAP-1446: a running 1.0.2 or 1.0.3 guardian took the swapped hook for
    # damage and restored its own release's hook through a temporary that
    # the stop left in bin (defenseclaw-hook.exe.restore-<hex>), which the
    # next uninstall refused. Standalone swaps the hook once that guardian
    # has exited and its temporaries are removed, while the prior gateway
    # still answers; Secure Client keeps its order.
    transaction = _function_body(_text(), "New-DefenseClawTransaction")
    first = transaction.index("Publish-DefenseClawEarlyHook")
    standalone = transaction.rindex("Publish-DefenseClawEarlyHook")
    assert first != standalone
    assert "if (-not (Test-DefenseClawStandaloneProfile)) {" in transaction[first - 200 : first]
    guardian = transaction.index("Stop-DefenseClawService -Name $GuardianServiceName")
    sweep = transaction.index("Remove-DefenseClawStaleReplacementBackups -Destination $Layout.HookPath")
    gateway = transaction.index("Stop-DefenseClawService -Name $GatewayServiceName")
    assert first < guardian < sweep < standalone < gateway
    assert "if (Test-DefenseClawStandaloneProfile) {" in transaction[guardian:sweep]
    # GAP-1451: the guardian's process is taken before its stop, and the swap
    # waits for that process itself to exit; the publication is checked once
    # the replaced hook's calls drained, before the gateway stops.
    identity = transaction.index("$priorGuardianProcess = Get-DefenseClawServiceProcessIdentity -Name $GuardianServiceName")
    exit_wait = transaction.index("Wait-DefenseClawServiceProcessExit -Name $GuardianServiceName -Identity $priorGuardianProcess")
    assert identity < guardian < exit_wait < sweep
    publish_body = _function_body(_text(), "Publish-DefenseClawEarlyHook")
    drain = publish_body.index("Wait-DefenseClawPriorHookCalls -HookPath")
    check = publish_body.index("Assert-DefenseClawEarlyHookPublished -Layout $Layout -Source $Source")
    assert drain < check < publish_body.index("return $preimage")
    assert "if (Test-DefenseClawStandaloneProfile) {" in publish_body[drain:check]

_HARNESS = r"""
param([string]$ModulePath, [string]$Scratch, [string]$Case)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "module parse failed: $($errors[0].Message)" }
foreach ($name in @('Publish-DefenseClawEarlyHook', 'Assert-DefenseClawEarlyHookPublished', 'Restore-DefenseClawEarlyHook', 'Get-DefenseClawEarlyHookField', 'Hold-DefenseClawEarlyHookGuard', 'Restore-DefenseClawSnapshotHookAfterActivation', 'Wait-DefenseClawPriorHookCalls', 'Get-DefenseClawPriorHookProcessIds', 'Wait-DefenseClawServiceProcessExit', 'Test-DefenseClawProcessIdentityRunning')) {
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
    $previous = if (Test-Path -LiteralPath $Destination) { Get-Content -LiteralPath $Destination -Raw } else { '<absent>' }
    $script:events.Add('publish:' + [IO.Path]::GetFileName($Destination) + ':' + $previous)
    Copy-Item -LiteralPath $Source.path -Destination $Destination -Force
}
function Test-DefenseClawStandaloneProfile { return $true }
function Assert-DefenseClawDescendant { param([string]$Path, [string]$Root, [string]$Label) return $Path }
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
if ($Case -like 'restorer*') {
    # GAP-1451: a writer of the replaced release (its guardian's restore)
    # puts its hook back while the replaced hook's calls drain: once
    # (restorer-once), or after every publication (restorer-persists).
    $script:restores = 0
    function Get-DefenseClawPriorHookProcessIds {
        param([string]$HookPath, [datetime]$StartedBefore)
        if ($script:restores -eq 0) {
            $script:restores++
            Set-Content -LiteralPath $HookPath -Value 'hook-1.0.2' -NoNewline
            $script:events.Add('prior-writer')
        }
    }
    if ($Case -eq 'restorer-persists') {
        function Install-DefenseClawSourceDescriptor {
            param([hashtable]$Source, [string]$Destination)
            $script:events.Add('publish:' + [IO.Path]::GetFileName($Destination))
            Copy-Item -LiteralPath $Source.path -Destination $Destination -Force
            if ([IO.Path]::GetFileName($Destination) -ceq 'defenseclaw-hook.exe' -and $script:restores -gt 0) {
                Set-Content -LiteralPath $Destination -Value 'hook-1.0.2' -NoNewline
                $script:events.Add('prior-writer')
            }
        }
    }
}
function Install-DefenseClawFileAtomic {
    param([string]$Source, [string]$Destination, [string]$ExpectedSHA256, [switch]$SkipIfContentMatches)
    if ($ExpectedSHA256 -and (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash -ne $ExpectedSHA256) {
        throw 'source digest mismatch'
    }
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
# An authenticated source descriptor carries the digest it was admitted by.
$newSource = @{ path = $new; sha256 = (Get-FileHash -LiteralPath $new -Algorithm SHA256).Hash }
$layout = @{ HookPath = $hook; PendingPath = (Join-Path $Scratch 'pending.json'); StateRoot = $Scratch }
$intent = [ordered]@{ schema_version = 1; phase = 'quiescing' }
$result = [ordered]@{ case = $Case; threw = '' }
try {
    switch ($Case) {
        'publish' {
            $preimage = Publish-DefenseClawEarlyHook -Layout $layout -Source $newSource -TransactionDirectory $transaction -Intent $intent -PriorDeploymentActive
            $result.preimage = $preimage
            $result.preimage_bytes = Get-Content -LiteralPath $preimage -Raw
            $result.hook = Get-Content -LiteralPath $hook -Raw
            $result.guard = Get-Content -LiteralPath $intent['early_hook_guard_copy'] -Raw
            $result.pending = (Get-Content -LiteralPath $layout.PendingPath -Raw | ConvertFrom-Json).early_hook_preimage
            # Recovery reads the intent back from pending.json.
            $read = Get-Content -LiteralPath $layout.PendingPath -Raw | ConvertFrom-Json
            Restore-DefenseClawEarlyHook -Layout $layout -Intent $read -TransactionDirectory $transaction
            $result.restored = Get-Content -LiteralPath $hook -Raw
        }
        'snapshot-failure' {
            [void](Publish-DefenseClawEarlyHook -Layout $layout -Source $newSource -TransactionDirectory $transaction -Intent $intent -PriorDeploymentActive)
            Restore-DefenseClawEarlyHook -Layout $layout -Intent $intent -TransactionDirectory $transaction
            $result.restored = Get-Content -LiteralPath $hook -Raw
        }
        'recovery-guard' {
            [void](Publish-DefenseClawEarlyHook -Layout $layout -Source $newSource -TransactionDirectory $transaction -Intent $intent -PriorDeploymentActive)
            # Simulate an interrupted older rollback that republished its
            # 1.0.2 hook before service restoration was complete.
            Copy-Item -LiteralPath $intent['early_hook_preimage'] -Destination $hook -Force
            [void](Hold-DefenseClawEarlyHookGuard -Layout $layout -TransactionDirectory $transaction -GuardCopy $intent['early_hook_guard_copy'] -GuardSHA256 $intent['early_hook_guard_sha256'])
            $result.during_restore = Get-Content -LiteralPath $hook -Raw
            $script:events.Add('gateway-ready')
            $snapshot = [pscustomobject]@{
                early_hook_guard_copy = $intent['early_hook_guard_copy']
                early_hook_preimage_sha256 = $intent['early_hook_preimage_sha256']
                files = @([pscustomobject]@{
                    path = $hook
                    backup = $intent['early_hook_preimage']
                    existed = $true
                })
            }
            Restore-DefenseClawSnapshotHookAfterActivation -Snapshot $snapshot -Layout $layout
            $result.restored = Get-Content -LiteralPath $hook -Raw
        }
        'guard-tamper' {
            [void](Publish-DefenseClawEarlyHook -Layout $layout -Source $newSource -TransactionDirectory $transaction -Intent $intent -PriorDeploymentActive)
            Set-Content -LiteralPath $intent['early_hook_guard_copy'] -Value 'tampered' -NoNewline
            [void](Hold-DefenseClawEarlyHookGuard -Layout $layout -TransactionDirectory $transaction -GuardCopy $intent['early_hook_guard_copy'] -GuardSHA256 $intent['early_hook_guard_sha256'])
        }
        'first-install' {
            $result.preimage = Publish-DefenseClawEarlyHook -Layout $layout -Source $newSource -TransactionDirectory $transaction -Intent $intent
            $result.hook = Get-Content -LiteralPath $hook -Raw
            Restore-DefenseClawEarlyHook -Layout $layout -Intent $intent -TransactionDirectory $transaction
        }
        'no-source' {
            $result.preimage = Publish-DefenseClawEarlyHook -Layout $layout -Source $null -TransactionDirectory $transaction -Intent $intent -PriorDeploymentActive
            $result.hook = Get-Content -LiteralPath $hook -Raw
        }
        'drain' {
            [void](Publish-DefenseClawEarlyHook -Layout $layout -Source $newSource -TransactionDirectory $transaction -Intent $intent -PriorDeploymentActive)
            $script:events.Add('returned')
        }
        { $_ -like 'restorer*' } {
            try {
                [void](Publish-DefenseClawEarlyHook -Layout $layout -Source $newSource -TransactionDirectory $transaction -Intent $intent -PriorDeploymentActive)
                $script:events.Add('returned')
            }
            finally {
                $result.hook = Get-Content -LiteralPath $hook -Raw
            }
        }
        { $_ -like 'process-*' } {
            # A real process stands for the prior guardian's: one that exits
            # on its own (process-exits), one that keeps running after its
            # service stopped (process-lingers), and an identity whose id a
            # later process reuses (process-reused).
            $engine = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
            $seconds = if ($Case -eq 'process-exits') { 1 } else { 60 }
            $child = Start-Process -FilePath $engine -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', "Start-Sleep -Seconds $seconds") -PassThru
            $identity = [pscustomobject]@{ Id = $child.Id; StartTime = $child.StartTime }
            if ($Case -eq 'process-reused') {
                $identity.StartTime = $child.StartTime.AddMinutes(-5)
            }
            $script:DefenseClawTerminatedServiceProcesses = @()
            $started = [DateTime]::UtcNow
            Wait-DefenseClawServiceProcessExit -Name 'DefenseClawHookGuardian' -Identity $identity -TimeoutSeconds 3
            $result.seconds = ([DateTime]::UtcNow - $started).TotalSeconds
            $child.Refresh()
            $result.exited = $child.HasExited
            $result.terminated = @($script:DefenseClawTerminatedServiceProcesses)
            if (-not $child.HasExited) { $child.Kill() }
            # No identity (no prior guardian process): nothing to wait for.
            Wait-DefenseClawServiceProcessExit -Name 'DefenseClawHookGuardian' -Identity $null
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


# GAP-1381: the guard copy runs through the real payload admission. Under
# HashPinned trust an unsigned payload file is admitted only by the SHA-256 the
# administrator's payload manifest pins for its name; early-hook-closed.exe has
# no such name, so the copy must be admitted by the pin of the hook it copies.
_TRUST_HARNESS = r"""
param([string]$ModulePath, [string]$Scratch, [string]$Case)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "module parse failed: $($errors[0].Message)" }
foreach ($name in @(
        'Publish-DefenseClawEarlyHook',
        'Assert-DefenseClawEarlyHookPublished',
        'Hold-DefenseClawEarlyHookGuard',
        'Get-DefenseClawSourceDescriptor',
        'Assert-DefenseClawSourceDescriptorCurrent',
        'Install-DefenseClawSourceDescriptor',
        'Assert-DefenseClawRegularSource',
        'Test-DefenseClawStandalonePayloadTrusted')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true)
    if ($null -eq $definition) { throw "missing $name" }
    # Every test file is unsigned, as an rc build's payload is.
    $text = $definition.Extent.Text.Replace(
        'Microsoft.PowerShell.Security\Get-AuthenticodeSignature', 'Get-TestAuthenticodeSignature')
    . ([ScriptBlock]::Create($text))
}
function Get-TestAuthenticodeSignature {
    param([string]$LiteralPath)
    [pscustomobject]@{ Status = [Management.Automation.SignatureStatus]::NotSigned; SignerCertificate = $null }
}
function Resolve-DefenseClawFullPath {
    param([string]$Path, [switch]$MustExist, [switch]$Leaf)
    $full = [IO.Path]::GetFullPath($Path)
    if ($MustExist -and -not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "missing: $full" }
    return $full
}
# The NTFS owner, DACL and volume checks have their own smokes.
function Assert-DefenseClawTrustedSource { param([string]$Path, [string]$Label) return $Path }
function Assert-DefenseClawNoReparsePath { param([string]$Path, [switch]$AllowMissingLeaf) }
function Test-DefenseClawStandaloneProfile { return $true }
function Write-DefenseClawJsonAtomic {
    param($Value, [string]$Path)
    ($Value | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $Path -Encoding utf8
}
function Wait-DefenseClawPriorHookCalls { param([string]$HookPath, [datetime]$StartedBefore) @() }
function Write-DefenseClawLifecyclePhase { param([string]$Stage) }
# A file named here is changed right after the atomic copy wrote it (a swap
# after the copy's own digest check).
$script:SwapLeaf = ''
function Install-DefenseClawFileAtomic {
    param([string]$Source, [string]$Destination, [string]$ExpectedSHA256, [switch]$SkipIfContentMatches)
    if ($ExpectedSHA256 -and (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash -ne $ExpectedSHA256) {
        throw 'source digest mismatch'
    }
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    if ($script:SwapLeaf -and [IO.Path]::GetFileName($Destination) -ceq $script:SwapLeaf) {
        Set-Content -LiteralPath $Destination -Value 'swapped' -NoNewline
    }
}
function Get-TestSHA256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
$stage = Join-Path $Scratch 'setup'
$bin = Join-Path $Scratch 'bin'
$transaction = Join-Path $Scratch 'transaction'
New-Item -ItemType Directory -Path $stage, $bin, $transaction -Force | Out-Null
$staged = Join-Path $stage 'defenseclaw-hook.exe'
$hook = Join-Path $bin 'defenseclaw-hook.exe'
Set-Content -LiteralPath $staged -Value 'hook-1.0.4' -NoNewline
Set-Content -LiteralPath $hook -Value 'hook-1.0.2' -NoNewline
$swapped = Join-Path $Scratch 'swapped.bin'
Set-Content -LiteralPath $swapped -Value 'swapped' -NoNewline
$script:DefenseClawAllowedSignerSHA256 = @()
$script:DefenseClawTrustMode = 'HashPinned'
$script:DefenseClawPinnedPayloadSHA256 = @{ 'defenseclaw-hook.exe' = (Get-TestSHA256 $staged) }
switch ($Case) {
    'unpinned-source' { $script:DefenseClawPinnedPayloadSHA256['defenseclaw-hook.exe'] = ('0' * 64) }
    'authenticode-mode' { $script:DefenseClawTrustMode = 'Authenticode' }
    'guard-swapped' { $script:SwapLeaf = 'early-hook-closed.exe' }
    'guard-swapped-guard-name-pinned' {
        # A manifest that also pins the guard's own name to other bytes does
        # not admit a guard copy that differs from the hook it copies.
        $script:SwapLeaf = 'early-hook-closed.exe'
        $script:DefenseClawPinnedPayloadSHA256['early-hook-closed.exe'] = (Get-TestSHA256 $swapped)
    }
    'hook-swapped' { $script:SwapLeaf = 'defenseclaw-hook.exe' }
}
$layout = @{ HookPath = $hook; PendingPath = (Join-Path $Scratch 'pending.json'); StateRoot = $Scratch }
$intent = [ordered]@{ schema_version = 1; phase = 'quiescing' }
$result = [ordered]@{ case = $Case; threw = ''; pin = (Get-TestSHA256 $staged) }
try {
    $source = Get-DefenseClawSourceDescriptor -Path $staged -Label 'hook executable' -Authenticode
    [void](Publish-DefenseClawEarlyHook -Layout $layout -Source $source -TransactionDirectory $transaction -Intent $intent -PriorDeploymentActive)
    $result.guard_sha256 = [string]$intent['early_hook_guard_sha256']
    $result.guard_bytes = Get-Content -LiteralPath $intent['early_hook_guard_copy'] -Raw
    $result.hook_after_publish = Get-Content -LiteralPath $hook -Raw
    # An interrupted rollback put the 1.0.2 hook back while the services
    # were down: the guard republishes this release's closed hook.
    Copy-Item -LiteralPath $intent['early_hook_preimage'] -Destination $hook -Force
    $read = Get-Content -LiteralPath $layout.PendingPath -Raw | ConvertFrom-Json
    $result.held = Hold-DefenseClawEarlyHookGuard -Layout $layout -TransactionDirectory $transaction -GuardCopy $read.early_hook_guard_copy -GuardSHA256 $read.early_hook_guard_sha256
    $result.hook_held = Get-Content -LiteralPath $hook -Raw
}
catch {
    $result.threw = $_.Exception.Message
}
$result.hook = Get-Content -LiteralPath $hook -Raw
$result.pending = Test-Path -LiteralPath $layout.PendingPath
$result | ConvertTo-Json -Compress -Depth 6
"""


def _pwsh() -> str | None:
    return os.environ.get("DEFENSECLAW_TEST_PWSH") or shutil.which("pwsh") or shutil.which("pwsh.exe")


def _run(tmp_path: Path, case: str, harness_text: str = _HARNESS) -> dict:
    engine = _pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    harness = tmp_path / "early-hook.ps1"
    harness.write_text(harness_text, encoding="utf-8")
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
    assert result["guard"] == "hook-1.0.4", result
    assert result["events"][:3] == [
        "publish:early-hook-closed.exe:<absent>",
        "intent:True",
        "publish:defenseclaw-hook.exe:hook-1.0.2",
    ], result
    # Recovery of the interrupted transaction puts the prior hook back.
    assert result["restored"] == "hook-1.0.2", result


def test_a_failed_snapshot_puts_the_prior_hook_back(tmp_path: Path) -> None:
    result = _run(tmp_path, "snapshot-failure")
    assert result["threw"] == "", result
    assert result["restored"] == "hook-1.0.2", result


def test_recovery_republishes_closed_hook_until_restored_gateway_is_ready(tmp_path: Path) -> None:
    result = _run(tmp_path, "recovery-guard")
    assert result["threw"] == "", result
    assert result["during_restore"] == "hook-1.0.4", result
    assert result["restored"] == "hook-1.0.2", result
    assert result["events"][-2:] == ["gateway-ready", "restore"], result


def test_recovery_refuses_a_modified_closed_hook_copy(tmp_path: Path) -> None:
    result = _run(tmp_path, "guard-tamper")
    assert "closed hook guard changed" in result["threw"], result


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
    assert events[:3] == [
        "publish:early-hook-closed.exe:<absent>",
        "intent:True",
        "publish:defenseclaw-hook.exe:hook-1.0.2",
    ], result
    assert events[3:] == ["look:1", "look:2", "look:3", "returned"], result


def test_the_hook_is_published_again_when_a_prior_writer_restored_it(tmp_path: Path) -> None:
    """GAP-1451: the replaced release's guardian restored its own fail-open
    hook while the candidate waited for the replaced hook's calls, and the
    gateway then stopped with that hook in place. The publication is checked
    after the wait and made once more."""
    result = _run(tmp_path, "restorer-once")
    assert result["threw"] == "", result
    assert result["hook"] == "hook-1.0.4", result
    events = result["events"]
    assert events.index("prior-writer") < events.index("returned"), result
    again = [e for e in events if "publishing it again" in e]
    assert len(again) == 1, result
    assert events.index("prior-writer") < events.index(again[0]), result
    assert events[-2:] == ["publish:defenseclaw-hook.exe:hook-1.0.2", "returned"], result


def test_a_hook_replaced_again_fails_the_transaction(tmp_path: Path) -> None:
    result = _run(tmp_path, "restorer-persists")
    assert "replaced again before the prior gateway stopped" in result["threw"], result
    assert "returned" not in result["events"], result


@pytest.mark.parametrize("case", ["process-exits", "process-lingers", "process-reused"])
def test_the_swap_waits_for_the_prior_guardians_process_to_exit(tmp_path: Path, case: str) -> None:
    """GAP-1451: a 1.0.2 or 1.0.3 guardian reports its service stopped before
    its process exits, and its hook watch can restore its hook meanwhile."""
    result = _run(tmp_path, case)
    assert result["threw"] == "", result
    if case == "process-exits":
        assert result["exited"] is True, result
        assert result["terminated"] == [], result
    elif case == "process-lingers":
        # Ended after the bound, and named in the lifecycle's result.
        assert result["exited"] is True, result
        assert result["seconds"] >= 3, result
        assert len(result["terminated"]) == 1 and "DefenseClawHookGuardian" in result["terminated"][0], result
    else:
        # Another process now has that id: it is not waited for or ended.
        assert result["exited"] is False, result
        assert result["seconds"] < 3, result
        assert result["terminated"] == [], result


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


def test_a_hash_pinned_upgrade_admits_its_guard_copy_by_the_hooks_pin(tmp_path: Path) -> None:
    """GAP-1381: the published 1.0.2 -> rc.8 managed Setup upgrade under
    HashPinned trust ended 1603 because the guard copy was admitted by its
    own name, which the payload manifest does not pin."""
    result = _run(tmp_path, "hash-pinned", _TRUST_HARNESS)
    assert result["threw"] == "", result
    assert result["guard_bytes"] == "hook-1.0.4", result
    assert result["guard_sha256"] == result["pin"], result
    assert result["hook_after_publish"] == "hook-1.0.4", result
    assert result["held"] == result["pin"], result
    assert result["hook_held"] == "hook-1.0.4", result


@pytest.mark.parametrize("case", ["guard-swapped", "guard-swapped-guard-name-pinned"])
def test_a_guard_copy_without_the_hooks_pinned_bytes_is_refused(tmp_path: Path, case: str) -> None:
    result = _run(tmp_path, case, _TRUST_HARNESS)
    assert "hook executable is not admitted by the standalone payload trust policy" in result["threw"], result
    assert "early-hook-closed.exe" in result["threw"], result
    # Refused before the intent names a guard and before the hook changes.
    assert result["pending"] is False, result
    assert result["hook"] == "hook-1.0.2", result


@pytest.mark.parametrize("case", ["unpinned-source", "authenticode-mode", "hook-swapped"])
def test_the_hook_payload_trust_is_unchanged(tmp_path: Path, case: str) -> None:
    result = _run(tmp_path, case, _TRUST_HARNESS)
    assert "hook executable is not admitted by the standalone payload trust policy" in result["threw"], result
    if case == "hook-swapped":
        # The hook path's own copy is still checked against the pin.
        assert "defenseclaw-hook.exe" in result["threw"], result
    else:
        assert result["pending"] is False, result
        assert result["hook"] == "hook-1.0.2", result
