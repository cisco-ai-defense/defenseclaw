r"""GAP-0765 and the r11 residual (g582 round 11c): Setup finds a Codex
machine-policy file that a program holds open in the way of this run before
it stops anything.

1.0.8 wrote C:\ProgramData\OpenAI\Codex\.defenseclaw-managed-hooks.state where
every standard user can read it, so a user can open it with FileShare.None.
requirements.toml can be held the same way. The snapshot reads both, the first
Codex transaction of this release reads the state again, and a drifted access
list on requirements.toml is stamped under a hold that refuses write or delete
access. Before anything is stopped, Setup holds both files for read (so a
program that arrives later cannot open them without read sharing), waits for
the release (bounded), and a holder still there defers the run with the
retryable codex_state_held or codex_requirements_held (exit 1618), naming the
program, with the files untouched. Standalone only: Secure Client keeps the
state at its fixed name.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
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


def test_the_transaction_checks_the_codex_files_before_it_changes_anything() -> None:
    body = _function_body(_text(), "New-DefenseClawTransaction")
    check = body.index("$codexReadHolds = Assert-DefenseClawCodexFilesNotHeld")
    guard = body.rindex("if ((Test-DefenseClawStandaloneProfile) -and -not $SkipRedactionKeySnapshot -and", 0, check)
    assert check - guard < 1500
    # Only a transaction that snapshots the Codex files is gated (L4); Secure
    # Client and the uninstall transaction are not.
    assert "$IncludeCodexMachineState) {" in body[guard:check]
    assert body.index("Assert-DefenseClawHookNotHeld -Layout $Layout") < check
    assert check < body.index("New-DefenseClawDirectory -Path $directory")
    assert check < body.index("Set-DefenseClawServiceStartMode")
    assert check < body.index("Publish-DefenseClawEarlyHook")
    assert check < body.index("$quiescingIntentPublished = $true")


def test_the_snapshot_copies_the_codex_files_from_the_handles_the_gate_holds() -> None:
    body = _function_body(_text(), "New-DefenseClawTransaction")
    copy = body.index("$heldStream.CopyTo($backupStream)")
    assert body.index("$codexReadHolds.Contains($heldKey)") < copy
    # The handles are closed once the files are copied, and on the failure
    # path before the rollback restarts the services.
    closed = body.index("Close-DefenseClawCodexFileHolds -Holds $codexReadHolds", copy)
    assert closed < body.index("$priorAttestationExists = ")
    failure = body.index("$snapshotError = $_")
    assert body.index("Close-DefenseClawCodexFileHolds -Holds $codexReadHolds", failure) < body.index(
        "$restartErrors = ", failure
    )


def test_the_codex_hold_is_a_retryable_named_refusal() -> None:
    body = _function_body(_text(), "Assert-DefenseClawCodexFilesNotHeld")
    assert "[int]$TimeoutSeconds = 30" in body
    assert 'throw ("{0}: {1} has {2}, {3}, {4};' in body
    assert "the file is as it was" in body
    assert "exit 1618" in body
    # The holders are named by Restart Manager, as for the installed hook.
    assert "Get-DefenseClawStateFileHolders -Layout $Layout -Paths @([string]$blocked.Path)" in body
    probe = _function_body(_text(), "Get-DefenseClawCodexFileHold")
    assert "codex_state_held" in probe and "codex_requirements_held" in probe
    assert "[IO.FileAccess]::Read" in probe
    assert "([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)" in probe
    assert "-band 0xFFFF) -in @(32, 33)" in probe
    # requirements.toml is checked for a stamp-blocking holder only when its
    # access list has to be written.
    assert probe.index("Test-DefenseClawPathAclCanonical") < probe.index("Test-DefenseClawRestampHeldByOther")
    # A holder that denies delete sharing stops the replace and the rollback of
    # requirements.toml, so it defers the run too (nothing stopped yet).
    assert probe.index("Test-DefenseClawFileDeleteBlocked -Path $requirements") < probe.index(
        "Test-DefenseClawPathAclCanonical"
    )
    assert "open without delete sharing, so Setup could not replace it" in probe
    delete_probe = _function_body(_text(), "Test-DefenseClawFileDeleteBlocked")
    assert "[uint32]0x00010000) -in @(32, 33)" in delete_probe
    assert "return $false" in delete_probe
    # Only the fixed-name state and requirements.toml are opened here; a hook
    # copy of the state (.state.<n>) is not, because a user may hold those.
    assert probe.count("[IO.FileStream]::new(") == 1
    assert "Path = [string]$Layout.CodexManagedHooksStatePath" in probe
    assert "Path = [string]$Layout.CodexMachinePolicyPath" in probe
    reader = _function_body(_text(), "Test-DefenseClawFileReadBlocked")
    assert "[IO.FileAccess]::Read" in reader
    assert "-band 0xFFFF) -in @(32, 33)" in reader
    assert "return $false" in reader  # a failed probe never blocks: the read reports it


def test_the_message_does_not_repeat_the_code_and_names_the_kind_of_hold() -> None:
    gate = _function_body(_text(), "Get-DefenseClawCodexFileHold")
    assert "open without read sharing, so Setup could not read it" in gate
    assert "open with write or delete access, so Setup could not change its access list" in gate
    go = (ROOT / "internal" / "cli" / "windows_enterprise_standalone.go").read_text(encoding="utf-8")
    assert "windowsEnterpriseTrimHeldCodePrefix(code, message)" in go


def test_setup_exits_1618_for_a_held_codex_file() -> None:
    go = (ROOT / "internal" / "cli" / "windows_enterprise_standalone.go").read_text(encoding="utf-8")
    assert re.search(
        r'case "hook_calls_running", "hook_in_use", "codex_state_held", "codex_requirements_held"(, "[a-z_]+")*:', go
    )


def test_a_canonical_file_is_not_probed_and_a_held_state_copy_is_not_refused() -> None:
    body = _function_body(_text(), "Set-DefenseClawPathAcl")
    canonical = body.index("Test-DefenseClawPathAclCanonical -Path $Path -Kind $Kind")
    # Nothing to write: no probe, no hold.
    assert canonical < body.index("Open-DefenseClawRestampHold -Path $Path -TolerateHeld")
    assert canonical < body.index("$hold = Open-DefenseClawRestampHold -Path $Path\n")
    assert "Test-DefenseClawCodexStateCopyPath -Path $Path -Kind $Kind" in body
    # The other managed files keep the refusal.
    assert "else {\n            $hold = Open-DefenseClawRestampHold -Path $Path\n" in body
    hold = _function_body(_text(), "Open-DefenseClawRestampHold")
    assert "[switch]$TolerateHeld" in hold
    assert hold.index("if ($TolerateHeld)") < hold.index("refusing to re-stamp a managed file while another program holds it open")


def test_the_state_copy_preflight_tolerates_a_held_copy_only() -> None:
    body = _function_body(_text(), "Assert-DefenseClawCodexManagedHooksStateFilePreflight")
    assert "Test-DefenseClawRestampHeldByOther -Path $copy" in body
    assert "refusing to re-stamp*" in body
    final = _function_body(_text(), "Assert-DefenseClawCodexManagedHooksStateFile")
    assert "Test-DefenseClawRestampHeldByOther" not in final


def test_a_recovery_puts_the_requirements_read_back_before_the_guardian_starts() -> None:
    body = _function_body(_text(), "Start-DefenseClawTransactionServices")
    repair = body.index("Repair-DefenseClawCodexRequirementsAccessBeforeGuardian")
    assert repair < body.index("$gatewayNeedsProtection = (")
    assert repair < body.index("$guardianTemporarilyRequired = (")
    helper = _function_body(_text(), "Repair-DefenseClawCodexRequirementsAccessBeforeGuardian")
    assert "-not (Test-DefenseClawStandaloneProfile)" in helper
    assert "CodexRequirementsOwnershipPath" in helper  # only a file DefenseClaw owns


def test_a_stamp_puts_the_native_hold_switch_back() -> None:
    body = _function_body(_text(), "Invoke-DefenseClawPathAclStamp")
    assert "$refuseHeldBefore = $nativeSecurity::RefuseHeldRestamp" in body
    assert "$nativeSecurity::RefuseHeldRestamp = $refuseHeldBefore" in body
    assert body.index("finally {\n            $nativeSecurity::RefuseHeldRestamp = $refuseHeldBefore") > body.index(
        "RefuseHeldRestamp = $false"
    )


_HARNESS = r"""
param([string]$ModulePath, [string]$Scratch, [string]$Case)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "module parse failed: $($errors[0].Message)" }
foreach ($name in @('Assert-DefenseClawCodexFilesNotHeld', 'Close-DefenseClawCodexFileHolds')) {
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
function Get-DefenseClawCodexFileHold {
    param([hashtable]$Layout, [string]$GatewayServiceName, [hashtable]$Holds)
    $script:looks++
    $script:events.Add('look:' + [string]$script:looks)
    $blocked = ($Case -in @('held-stays', 'held-unnamed', 'requirements-held')) -or ($Case -eq 'held-closes' -and $script:looks -le 2)
    if ($blocked) {
        $Holds['a'] = [IO.MemoryStream]::new()
        if ($Case -eq 'requirements-held') {
            return [pscustomobject]@{ Path = 'C:\ProgramData\OpenAI\Codex\requirements.toml'; Code = 'codex_requirements_held'; What = 'the Codex machine requirements'; Why = 'open with write or delete access, so Setup could not change its access list' }
        }
        return [pscustomobject]@{ Path = $state; Code = 'codex_state_held'; What = 'the Codex managed-hooks state of the installed release'; Why = 'open without read sharing, so Setup could not read it' }
    }
    $Holds['b'] = [IO.MemoryStream]::new()
    return $null
}
function Get-DefenseClawStateFileHolders {
    param([hashtable]$Layout, [string[]]$Paths, $Excluded)
    $script:events.Add('holders')
    if ($Case -eq 'held-unnamed') { return @{} }
    return @{ '4343/1' = [pscustomobject]@{ Id = 4343; Name = 'holder.exe'; UserName = 'EC2\user1'; Parent = ''; File = '' } }
}
$threw = ''
$held = -1
try {
    $result = Assert-DefenseClawCodexFilesNotHeld -Layout @{ CodexManagedHooksStatePath = $state } -GatewayServiceName 'DefenseClawGateway' -TimeoutSeconds 2
    $held = @($result.Keys).Count
}
catch { $threw = $_.Exception.Message }
[pscustomobject]@{
    threw = $threw
    held = $held
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


def test_files_nobody_holds_do_not_defer_the_run_and_stay_held_for_the_snapshot(tmp_path: Path) -> None:
    result = _run(tmp_path, "free")
    assert result["threw"] == "", result
    assert result["events"] == ["look:1"], result
    assert result["held"] == 1, result


def test_no_codex_files_means_nothing_to_wait_for(tmp_path: Path) -> None:
    result = _run(tmp_path, "absent")
    assert result["threw"] == "", result
    assert result["events"] == ["look:1"], result


def test_the_run_goes_on_once_the_holder_released_the_files(tmp_path: Path) -> None:
    result = _run(tmp_path, "held-closes")
    assert result["threw"] == "", result
    assert result["events"] == ["look:1", "look:2", "look:3"], result
    assert result["held"] == 1, result  # the blocked tries' handles were closed


def test_a_holder_still_there_defers_the_run_and_the_state_is_untouched(tmp_path: Path) -> None:
    result = _run(tmp_path, "held-stays")
    assert result["threw"].startswith("codex_state_held: holder.exe (process id 4343, EC2\\user1) has "), result
    assert "open without read sharing, so Setup could not read it" in result["threw"], result
    assert "this run stopped and changed nothing" in result["threw"], result
    assert "run the same command again" in result["threw"], result
    assert result["events"][-1] == "holders", result
    assert result["state"] == "state-of-1.0.8", result


def test_a_requirements_holder_defers_the_run_with_its_own_code(tmp_path: Path) -> None:
    result = _run(tmp_path, "requirements-held")
    assert result["threw"].startswith(
        "codex_requirements_held: holder.exe (process id 4343, EC2\\user1) has C:\\ProgramData\\OpenAI\\Codex\\requirements.toml, "
    ), result
    assert "open with write or delete access, so Setup could not change its access list" in result["threw"], result


def test_an_unnamed_holder_still_defers_the_run(tmp_path: Path) -> None:
    result = _run(tmp_path, "held-unnamed")
    assert result["threw"].startswith("codex_state_held: a program has "), result


_NATIVE = r"""
param([string]$ModulePath, [string]$Scratch, [string]$Case)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
foreach ($name in @('Get-DefenseClawCodexFileHold', 'Close-DefenseClawCodexFileHolds')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true)
    . ([ScriptBlock]::Create($definition.Extent.Text))
}
function Get-DefenseClawServiceSID { param([string]$ServiceName) 'S-1-5-80-1' }
function Test-DefenseClawPathAclCanonical { param($Path, $Kind, $GatewayServiceSID) $true }
function Test-DefenseClawRestampHeldByOther { param($Path) $false }
# The delete probe opens through the native helper this harness does not compile; no holder denies delete here.
function Test-DefenseClawFileDeleteBlocked { param($Path) $false }
$state = Join-Path $Scratch '.defenseclaw-managed-hooks.state'
$req = Join-Path $Scratch 'requirements.toml'
Set-Content -LiteralPath $state -Value 'state' -NoNewline
Set-Content -LiteralPath $req -Value 'req' -NoNewline
$layout = @{ CodexManagedHooksStatePath = $state; CodexMachinePolicyPath = $req }
$out = [ordered]@{}
if ($Case -eq 'late-holder') {
    $holds = @{}
    $blocked = Get-DefenseClawCodexFileHold -Layout $layout -GatewayServiceName 'x' -Holds $holds
    $out.blocked = ($null -ne $blocked)
    $out.holds = @($holds.Keys).Count
    # A program that arrives after the check cannot open either file without read sharing.
    foreach ($p in @($state, $req)) {
        try { [IO.File]::Open($p, 'Open', 'Read', 'None').Dispose(); $out["late-$([IO.Path]::GetFileName($p))"] = 'opened' }
        catch { $out["late-$([IO.Path]::GetFileName($p))"] = 'refused' }
        try { [IO.File]::Open($p, 'Open', 'Read', 'Write,Delete').Dispose(); $out["late2-$([IO.Path]::GetFileName($p))"] = 'opened' }
        catch { $out["late2-$([IO.Path]::GetFileName($p))"] = 'refused' }
        try { [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite,Delete').Dispose(); $out["reader-$([IO.Path]::GetFileName($p))"] = 'opened' }
        catch { $out["reader-$([IO.Path]::GetFileName($p))"] = 'refused' }
    }
    Close-DefenseClawCodexFileHolds -Holds $holds
    try { [IO.File]::Open($req, 'Open', 'Read', 'None').Dispose(); $out.afterClose = 'opened' } catch { $out.afterClose = 'refused' }
}
elseif ($Case -in @('state-held', 'requirements-held')) {
    $target = if ($Case -eq 'state-held') { $state } else { $req }
    $holder = [IO.File]::Open($target, 'Open', 'Read', 'Write,Delete')
    try {
        $holds = @{}
        $blocked = Get-DefenseClawCodexFileHold -Layout $layout -GatewayServiceName 'x' -Holds $holds
        $out.code = if ($null -eq $blocked) { '' } else { $blocked.Code }
        $out.path = if ($null -eq $blocked) { '' } else { [IO.Path]::GetFileName([string]$blocked.Path) }
        Close-DefenseClawCodexFileHolds -Holds $holds
        $out.leftOpen = @($holds.Keys).Count
    }
    finally { $holder.Dispose() }
}
$out | ConvertTo-Json -Compress
"""


@pytest.mark.skipif(sys.platform != "win32", reason="share modes are enforced by Windows")
@pytest.mark.parametrize("case", ["late-holder", "state-held", "requirements-held"])
def test_the_gate_holds_the_files_so_a_late_holder_cannot_deny_the_read(tmp_path: Path, case: str) -> None:
    engine = _pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    harness = tmp_path / "native.ps1"
    harness.write_text(_NATIVE, encoding="utf-8")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness),
         "-ModulePath", str(MODULE), "-Scratch", str(scratch), "-Case", case],
        capture_output=True, text=True, timeout=180, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    if case == "late-holder":
        assert result["blocked"] is False and result["holds"] == 2, result
        for name in (".defenseclaw-managed-hooks.state", "requirements.toml"):
            assert result[f"late-{name}"] == "refused", result  # no sharing: refused
            assert result[f"late2-{name}"] == "refused", result  # write and delete sharing only: refused
            assert result[f"reader-{name}"] == "opened", result  # an ordinary reader is not in the way
        assert result["afterClose"] == "opened", result
    else:
        code = "codex_state_held" if case == "state-held" else "codex_requirements_held"
        assert result["code"] == code, result
        assert result["leftOpen"] == 0, result


def test_a_rollback_to_a_release_without_writer_state_drops_the_writer_lock() -> None:
    body = _function_body(_text(), "Sync-DefenseClawCodexManagedHooksStateCopy")
    gate = body.index("if (-not [IO.File]::Exists($committed)) {")
    # The lock goes only when the restored deployment has no writer copy, and
    # before the function returns: the counter alone names a hook copy that
    # the rollback removed, and the recovery verification failed on it.
    assert body.index("[IO.File]::Delete($lock)", gate) < body.index("return", gate + 200)
    assert body.index("'.defenseclaw-managed-hooks.writer.lock'", gate) > gate
    assert gate < body.index("[IO.File]::ReadAllBytes($committed)")

def test_a_recovery_republishes_a_hand_edited_requirements_file_instead_of_stopping() -> None:
    """GAP-0802: the restored requirements.toml may carry an administrator's
    edit of the managed policy; the standalone recovery replaces it."""
    text = _text()
    readiness = _function_body(text, "Assert-DefenseClawRestoredTransactionReadyForActivation")
    assert "-RepairRecoveredCodexRequirements:(Test-DefenseClawStandaloneProfile)" in readiness
    deployment = _function_body(text, "Assert-DefenseClawEnterpriseDeployment")
    gate = deployment.index("if ($RepairRecoveredCodexRequirements -and $ServicingTransaction -and")
    # The repair runs before the verify that used to stop the recovery.
    assert gate < deployment.index("-Action $(if ($codexTargetEnabled) { 'verify' } else { 'inspect' }))")
    assert "(Test-DefenseClawStandaloneProfile)" in deployment[gate : gate + 200]
    body = _function_body(text, "Repair-DefenseClawRecoveredCodexRequirements")
    assert body.index("-Action verify)") < body.index("[IO.FileMode]::CreateNew") < body.index("-Action reconcile)")
    # Held: the retryable code, before anything is saved or written.
    assert body.index("New-DefenseClawCodexFileHeldMessage") < body.index("[IO.FileMode]::CreateNew")
    # The content comes from DefenseClaw's record, verified by its hash.
    assert "Get-DefenseClawRecordedCodexRequirementsPreimage" in body
    # GAP-1001: the recorded preimage is the base the gateway renders the managed policy into beside the
    # file (no swap of a base over the live path), and the reconcile that does it comes last.
    assert "-Action reconcile" in body[body.index("-BaseFile $staged") - 200 :]
    assert "Install-DefenseClawFileAtomic" not in body
    record = _function_body(text, "Get-DefenseClawRecordedCodexRequirementsPreimage")
    assert "preimage_sha256" in record and "SHA256" in record and "requirements_path" in record
    # Secure Client keeps its recovery.
    assert body.index("if (-not (Test-DefenseClawStandaloneProfile)) {") < body.index("-Action verify)")
    assert "recovered_codex_requirements" in text


def test_a_rollback_that_a_late_holder_stops_ends_with_the_retryable_held_code() -> None:
    """GAP-0803: bounded waits, then codex_*_held (exit 1618), transaction pending."""
    text = _text()
    restore = _function_body(text, "Restore-DefenseClawTransaction")
    assert "-Why 'open without delete sharing, so the rollback could not put it back'" in restore
    assert "Open-DefenseClawCodexRollbackHold -Layout $Layout -Path $destination" in restore
    assert "-Why 'open without delete sharing, so the rollback could not remove it'" in restore
    hold = _function_body(text, "Open-DefenseClawCodexRollbackHold")
    assert "[ValidateRange(0, 120)][int]$TimeoutSeconds = 30" in hold
    assert "Start-Sleep -Milliseconds 500" in hold
    message = _function_body(text, "New-DefenseClawCodexFileHeldMessage")
    assert "'codex_requirements_held'" in message and "'codex_state_held'" in message
    # GAP-0947: the shared builder says the transaction is still pending.
    assert "the transaction is still pending" in _function_body(text, "New-DefenseClawRollbackHeldMessage")
