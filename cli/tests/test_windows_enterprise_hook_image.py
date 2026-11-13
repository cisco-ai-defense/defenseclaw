r"""GAP-0751: versioned managed hook images in the Windows Setup module.

A standalone agent hook config names <bin>\hooks\<d16>\defenseclaw-hook.exe
(the launch image, the hook guard beside it). Setup stages a new folder for a
new release through the gateway's hidden `enterprise windows hook-image stage`
right after the payload loop (it starts the copies once), the guardian's first
reconcile switches the configs, a rollback removes a hooks folder only the
transaction created, and a committed upgrade prunes every folder but the
current and the replaced release's. The transition image at bin\ and its
early-hook protocol (GAP-0993) are unchanged, and Secure Client never reaches
any of it.
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
    return MODULE.read_text(encoding="utf-8").replace("\r\n", "\n")


def _function_body(text: str, name: str) -> str:
    start = text.index(f"function {name} {{\n")
    end = text.index("\n}\n", start)
    return text[start : end + 3]


def test_the_layout_has_a_hook_images_folder_only_without_the_broker() -> None:
    layout = _function_body(_text(), "Get-DefenseClawLayout")
    assert "$hookImagesDirectory = ''\n    if (-not $brokerEnabled) {\n        $hookImagesDirectory = (Microsoft.PowerShell.Management\\Join-Path $bin 'hooks')" in layout
    assert "        HookImagesDirectory = $hookImagesDirectory\n" in layout
    # The transition image keeps its fixed path.
    assert "HookPath = (Microsoft.PowerShell.Management\\Join-Path $bin 'defenseclaw-hook.exe')" in layout


def test_the_stage_runs_after_the_payload_and_before_any_hook_config_writer() -> None:
    lifecycle = _function_body(_text(), "Invoke-DefenseClawInstallLikeLifecycle")
    stage = lifecycle.index("Install-DefenseClawStandaloneHookImage `")
    opened = lifecycle.index("$snapshot = New-DefenseClawTransaction `")
    # The payload loop (the transition images) comes first; the #1445 rule
    # packs are written later, after the applied config copy, and do not
    # depend on the launch images.
    assert stage < lifecycle.index("Install-DefenseClawStandaloneShippedRulePacks `")
    assert lifecycle.index("Install-DefenseClawSourceDescriptor `\n                -Source $Sources[$name]") < stage
    assert stage < lifecycle.index("throw \"required managed artifact is missing after $Action staging: $requiredPath\"")
    assert stage > opened
    # The first hook config writers of the transaction come after the stage.
    assert stage < lifecycle.index("-Action capture", opened)
    assert stage < lifecycle.index("Invoke-DefenseClawCodexRequirementsCommand", opened)
    assert stage < lifecycle.index("Start-DefenseClawService -Name $GatewayServiceName", opened)
    guard = lifecycle.rindex("if (Test-DefenseClawStandaloneProfile) {", 0, stage)
    assert stage - guard < 600


def test_the_prune_runs_only_after_the_commit_and_only_when_the_image_changed() -> None:
    lifecycle = _function_body(_text(), "Invoke-DefenseClawInstallLikeLifecycle")
    prune = lifecycle.index("Invoke-DefenseClawStandaloneHookImagePrune `")
    assert lifecycle.rindex("Complete-DefenseClawTransaction -SnapshotPath $snapshot -Layout $Layout\n", 0, prune) > 0
    assert prune < lifecycle.index("$result = Get-DefenseClawLifecycleStatus `")
    block = lifecycle[lifecycle.rindex("if ((Test-DefenseClawStandaloneProfile) -and $Sources.ContainsKey('hook')", 0, prune) : prune]
    assert "$replacedHookImageSHA256 -cmatch '^[0-9a-f]{64}$'" in block
    assert "if ($replacedHookImage -cne $currentHookImage) {" in block
    assert "-Keep @($currentHookImage, $replacedHookImage)" in lifecycle[prune : prune + 300]
    # The replaced digest is read before the transaction writes the new record.
    read = lifecycle.index("$replacedHookImageSHA256 = [string](Get-DefenseClawRecordedHookSHA256 -Layout $Layout)")
    assert read < lifecycle.index("$snapshot = New-DefenseClawTransaction `")


def test_the_snapshot_records_whether_the_hooks_folder_existed_on_standalone_only() -> None:
    transaction = _function_body(_text(), "New-DefenseClawTransaction")
    record = transaction.index("$snapshot['hook_images_root_existed'] = [bool](")
    assert transaction.rindex("if (Test-DefenseClawStandaloneProfile) {", 0, record) > transaction.index("$snapshot = [ordered]@{")
    assert record < transaction.index("Write-DefenseClawJsonAtomic -Value $snapshot -Path $snapshotPath")


def test_the_rollback_removes_a_created_hooks_folder_beside_the_codex_folders() -> None:
    restore = _function_body(_text(), "Restore-DefenseClawTransaction")
    shared = restore.index("Remove-DefenseClawTransactionCreatedSharedDirectories `")
    images = restore.index("Remove-DefenseClawTransactionCreatedHookImages `")
    assert 0 < images - shared < 200


def test_the_install_and_retired_trees_admit_the_launch_folders() -> None:
    text = _text()
    tree = _function_body(text, "Assert-DefenseClawManagedInstallTree")
    assert "$hookImages = Get-DefenseClawHookImageTreeItems -BinDirectory ([string]$Layout.BinDirectory)" in tree
    assert tree.rindex("if (Test-DefenseClawStandaloneProfile) {", 0, tree.index("$hookImages =")) > 0
    retired = _function_body(text, "Get-DefenseClawRetiredInstallTreeAllowlist")
    assert "Get-DefenseClawHookImageTreeItems -BinDirectory (Microsoft.PowerShell.Management\\Join-Path $RetiredRoot 'bin')" in retired
    backups = _function_body(text, "Remove-DefenseClawStandaloneInstallTreeReplacementBackups")
    assert "foreach ($hookImageItem in @(Get-DefenseClawHookImageAclItems -Layout $Layout)) {" in backups


def test_recorded_hook_paths_accept_this_layouts_launch_images() -> None:
    text = _text()
    binding = _function_body(text, "Get-DefenseClawClaudeEffectivePolicyBinding")
    assert "-not (Test-DefenseClawManagedHookImagePath -Layout $Layout -Path $recordedHook)) {" in binding
    assert "-LiteralPath $launchedHook `" in binding
    for name in ("Assert-DefenseClawManagedHooksTeardownSchema6Journal", "Get-DefenseClawManagedHooksTeardownJournalPhase"):
        body = _function_body(text, name)
        assert "Test-DefenseClawManagedHookImagePath -Layout $Layout -Path $recorded" in body, name
    codex = _function_body(text, "Invoke-DefenseClawCodexRequirementsCommand")
    assert "'hook_binary' {\n                Test-DefenseClawManagedHookImagePath -Layout $Layout -Path $actual" in codex
    assert "Codex requirements report managed_dir is not the folder of its hook_binary" in codex
    others = _function_body(text, "Get-DefenseClawRuntimeSelectorOtherHooks")
    assert "(Test-DefenseClawSameHookImageFamily -Path $full -Other $OwnHook)" in others
    orphans = _function_body(text, "Remove-DefenseClawStandaloneOrphanedHookMachineState")
    assert "$text -match $launchHookPattern" in orphans
    held = _function_body(text, "Get-DefenseClawCommittedUninstallHeldTargets")
    assert "What = 'an installed hook launch image'" in held


def test_acls_verify_and_the_content_gate_cover_the_launch_folders() -> None:
    text = _text()
    acls = _function_body(text, "Set-DefenseClawManagedAcls")
    assert "Set-DefenseClawPathAcl -Path $hookImageItem.Path -Kind ([string]$hookImageItem.Kind) -GatewayServiceSID $gatewaySID" in acls
    verify = _function_body(text, "Assert-DefenseClawEnterpriseDeployment")
    assert "foreach ($hookImageItem in @(Get-DefenseClawHookImageAclItems -Layout $Layout)) {" in verify
    gate = _function_body(text, "Assert-DefenseClawStandaloneContentTrusted")
    assert "Get-DefenseClawHookImageAclItems -Layout $Layout -FoldersOnly" in gate
    artifacts = _function_body(text, "Assert-DefenseClawInstalledArtifacts")
    assert 'throw "installed launch image hash drift: $($pair[0]) ($launchImage)"' in artifacts
    items = _function_body(text, "Get-DefenseClawHookImageAclItems")
    assert "if (-not (Test-DefenseClawStandaloneProfile)) {\n        return @($items)" in items


def test_the_fixed_path_protocol_is_unchanged() -> None:
    # The early publish, its preimage and its closed guard keep the transition
    # image at $Layout.HookPath: no launch image takes part.
    text = _text()
    for name in ("Publish-DefenseClawEarlyHook", "Copy-DefenseClawRecordedHookPreimage", "Restore-DefenseClawEarlyHook",
                 "Hold-DefenseClawEarlyHookGuard", "Restore-DefenseClawSnapshotHookAfterActivation"):
        body = _function_body(text, name)
        assert "HookImage" not in body, name


_HARNESS = r"""
param([string]$ModulePath, [string]$Scratch, [string]$Case, [int]$Standalone = 1)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "module parse failed: $($errors[0].Message)" }
foreach ($name in @('Get-DefenseClawManagedHookImageLocation', 'Test-DefenseClawSameHookImageFamily', 'Test-DefenseClawManagedHookImagePath', 'Get-DefenseClawHookImageDigest', 'Test-DefenseClawHookImageFileName', 'Get-DefenseClawHookImageTreeItems', 'Get-DefenseClawHookImageGatewayReport', 'Install-DefenseClawStandaloneHookImage', 'Remove-DefenseClawTransactionCreatedHookImages', 'Invoke-DefenseClawStandaloneHookImagePrune', 'Get-DefenseClawOptionalLayoutValue', 'ConvertTo-DefenseClawBoundedDiagnostic', 'Add-DefenseClawRollbackLeftovers')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true)
    if ($null -eq $definition) { throw "missing $name" }
    . ([ScriptBlock]::Create($definition.Extent.Text))
}
$script:DefenseClawRollbackLeftovers = @()
$script:events = [Collections.Generic.List[string]]::new()
$script:calls = [Collections.Generic.List[string]]::new()
$script:probe = $null
function Test-DefenseClawStandaloneProfile { [bool]$Standalone }
function Write-DefenseClawResilienceEvent { param([string]$Marker, [hashtable]$Fields) $script:events.Add($Marker + ': ' + $Fields['reason']) }
function Write-DefenseClawLifecyclePhase { param([string]$Stage) $script:events.Add('phase: ' + $Stage) }
function Format-DefenseClawRerunStep { param([switch]$SameSetupCommand) 'run the same Setup command again' }
function Assert-DefenseClawNoReparsePath { param([string]$Path, [switch]$AllowMissingLeaf) }
function Invoke-DefenseClawGatewayCommand {
    param([hashtable]$Layout, [string]$GatewayServiceName, [string[]]$Arguments, [switch]$Capture, [switch]$AllowFailure)
    $script:calls.Add(($Arguments -join ' '))
    return $script:probe
}
function Set-Probe([int]$Exit, [string[]]$Lines) { $script:probe = [pscustomobject]@{ exit_code = $Exit; output = $Lines } }
$bin = Join-Path $Scratch 'bin'
$root = Join-Path $bin 'hooks'
$layout = @{ BinDirectory = $bin; HookImagesDirectory = $root; HookPath = 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe'; HookGuardPath = 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook-guard.exe' }
$hookSHA = '0123456789abcdef' + ('a' * 48)
$guardSHA = 'fedcba9876543210' + ('b' * 48)
$sources = @{ hook = @{ sha256 = $hookSHA.ToUpperInvariant() }; hook_guard = @{ sha256 = $guardSHA } }
function New-Tree {
    $launch = Join-Path $root '0123456789abcdef'
    $staging = Join-Path $root ('.staging-' + ('c' * 32))
    foreach ($dir in @($launch, $staging, (Join-Path $root 'other'), (Join-Path $root '0123456789ABCDEF0'))) { [void](New-Item -ItemType Directory -Force -Path $dir) }
    foreach ($file in @(
        (Join-Path $launch 'defenseclaw-hook.exe'), (Join-Path $launch 'defenseclaw-hook-guard.exe'),
        (Join-Path $launch ('defenseclaw-hook.exe.backup.' + ('d' * 32))), (Join-Path $launch ('defenseclaw-hook.exe.restore-' + ('e' * 16))),
        (Join-Path $launch 'notes.txt'), (Join-Path $staging 'defenseclaw-hook.exe'), (Join-Path (Join-Path $root 'other') 'x.exe'))) {
        [IO.File]::WriteAllText($file, 'x')
    }
}
function Rel([string[]]$Paths) { @($Paths | ForEach-Object { $_.Substring($Scratch.Length).Replace('\', '/') } | Sort-Object) }
$out = [ordered]@{}
switch ($Case) {
    'location' {
        $paths = @(
            'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe',
            'C:\Program Files\Cisco\DefenseClaw\bin\hooks\0123456789ABCDEF\DefenseClaw-Hook-Guard.EXE',
            'C:/Program Files/Cisco/DefenseClaw/bin/hooks/0123456789abcdef/defenseclaw-hook.exe',
            'C:\Program Files\Cisco\DefenseClaw\bin\hooks\0123456789abcdeg\defenseclaw-hook.exe',
            'C:\Program Files\Cisco\DefenseClaw\bin\hooks\.staging-0123\defenseclaw-hook.exe',
            'C:\Program Files\Cisco\DefenseClaw\bin\other\0123456789abcdef\defenseclaw-hook.exe',
            'C:\Program Files\Cisco\DefenseClaw\bin\hooks\..\defenseclaw-hook.exe',
            'C:\Program Files\Cisco\DefenseClaw\lib\defenseclaw-hook.exe',
            'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe',
            '\\server\share\bin\defenseclaw-hook.exe',
            'bin\defenseclaw-hook.exe',
            'C:\bin\hooks\0123456789abcdef\defenseclaw-hook.exe',
            '')
        $out.locations = @($paths | ForEach-Object {
            $l = Get-DefenseClawManagedHookImageLocation -Path $_
            if ($null -eq $l) { 'none' } else { '{0}|{1}|{2}' -f $l.Bin, $l.Name, $l.Digest }
        })
        $fixed = 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe'
        $launch = 'C:\Program Files\Cisco\DefenseClaw\bin\hooks\0123456789abcdef\defenseclaw-hook.exe'
        $older = 'C:\PROGRAM FILES\Cisco\DefenseClaw\BIN\hooks\aaaaaaaaaaaaaaaa\defenseclaw-hook.exe'
        $guard = 'C:\Program Files\Cisco\DefenseClaw\bin\hooks\0123456789abcdef\defenseclaw-hook-guard.exe'
        $other = 'C:\Program Files\Cisco\DefenseClawCert\bin\hooks\0123456789abcdef\defenseclaw-hook.exe'
        $out.family = @(
            (Test-DefenseClawSameHookImageFamily -Path $fixed -Other $launch),
            (Test-DefenseClawSameHookImageFamily -Path $older -Other $launch),
            (Test-DefenseClawSameHookImageFamily -Path $launch -Other $guard),
            (Test-DefenseClawSameHookImageFamily -Path $launch -Other $other),
            (Test-DefenseClawSameHookImageFamily -Path '' -Other $launch))
        $out.managed = @(
            (Test-DefenseClawManagedHookImagePath -Layout $layout -Path $older),
            (Test-DefenseClawManagedHookImagePath -Layout $layout -Path $guard),
            (Test-DefenseClawManagedHookImagePath -Layout $layout -Path $guard -Guard),
            (Test-DefenseClawManagedHookImagePath -Layout $layout -Path $other))
        $out.digest = Get-DefenseClawHookImageDigest -SHA256 $hookSHA.ToUpperInvariant()
        $out.badDigest = try { Get-DefenseClawHookImageDigest -SHA256 'abc'; 'accepted' } catch { 'refused' }
    }
    'secure-client' {
        $launch = 'C:\Program Files\Cisco\DefenseClaw\bin\hooks\0123456789abcdef\defenseclaw-hook.exe'
        $out.managed = @(
            (Test-DefenseClawManagedHookImagePath -Layout $layout -Path $launch),
            (Test-DefenseClawManagedHookImagePath -Layout $layout -Path 'C:\Program Files\Cisco\DefenseClaw\bin\DEFENSECLAW-HOOK.exe'))
        Set-Probe 0 @('{"schema_version":1,"ok":true}')
        Install-DefenseClawStandaloneHookImage -Layout $layout -GatewayServiceName 'G' -Sources $sources
        $out.calls = @($script:calls)
    }
    'tree' {
        New-Tree
        $items = Get-DefenseClawHookImageTreeItems -BinDirectory $bin
        $out.directories = Rel $items.directories
        $out.files = Rel $items.files
        $out.empty = @((Get-DefenseClawHookImageTreeItems -BinDirectory (Join-Path $Scratch 'none')).directories).Count
    }
    'stage' {
        $folder = Join-Path $root '0123456789abcdef'
        $report = [ordered]@{ schema_version = 1; ok = $true; folder = $folder; hook = (Join-Path $folder 'defenseclaw-hook.exe'); guard = (Join-Path $folder 'defenseclaw-hook-guard.exe'); created_root = $true; created_folder = $true; changed = $true; reason = ''; error = '' }
        Set-Probe 0 @('progress line', ($report | ConvertTo-Json -Compress))
        Install-DefenseClawStandaloneHookImage -Layout $layout -GatewayServiceName 'G' -Sources $sources
        $out.calls = @($script:calls)
        $out.events = @($script:events)
        $results = [ordered]@{}
        foreach ($variant in @('start', 'digest', 'unknown', 'exit', 'folder', 'nohook', 'two', 'schema')) {
            $r = [ordered]@{}
            foreach ($key in @($report.Keys)) { $r[$key] = $report[$key] }
            $lines = $null
            switch ($variant) {
                'start' { $r.ok = $false; $r.reason = 'hook_image_start_failed'; $r.error = 'defenseclaw-hook.exe --version-json: access denied' }
                'digest' { $r.ok = $false; $r.reason = 'hook_image_digest_mismatch'; $r.error = 'transition hook has another digest' }
                'unknown' { $r.ok = $false; $r.reason = 'something_else'; $r.error = 'x' }
                'folder' { $r.folder = (Join-Path $root 'aaaaaaaaaaaaaaaa') }
                'nohook' { $r.hook = '' }
                'schema' { $r.schema_version = 2 }
            }
            $json = $r | ConvertTo-Json -Compress
            $lines = if ($variant -eq 'two') { @($json, $json) } else { @($json) }
            Set-Probe $(if ($variant -eq 'exit') { 1 } else { 0 }) $lines
            $results[$variant] = try { Install-DefenseClawStandaloneHookImage -Layout $layout -GatewayServiceName 'G' -Sources $sources; 'ok' } catch { $_.Exception.Message }
        }
        $out.results = $results
        $script:calls.Clear()
        Install-DefenseClawStandaloneHookImage -Layout $layout -GatewayServiceName 'G' -Sources @{ gateway = @{ sha256 = $hookSHA } }
        $out.noHookCalls = $script:calls.Count
    }
    'rollback' {
        $results = [ordered]@{}
        foreach ($variant in @('created', 'existed', 'absent', 'unexpected')) {
            if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
            $launch = Join-Path $root '0123456789abcdef'
            [void](New-Item -ItemType Directory -Force -Path $launch)
            [IO.File]::WriteAllText((Join-Path $launch 'defenseclaw-hook.exe'), 'x')
            $snapshot = switch ($variant) {
                'existed' { [pscustomobject]@{ hook_images_root_existed = $true } }
                'absent' { [pscustomobject]@{ id = 'x' } }
                default { [pscustomobject]@{ hook_images_root_existed = $false } }
            }
            if ($variant -eq 'unexpected') { [IO.File]::WriteAllText((Join-Path $launch 'admin-notes.txt'), 'x') }
            Remove-DefenseClawTransactionCreatedHookImages -Snapshot $snapshot -Layout $layout
            $results[$variant] = [bool](Test-Path -LiteralPath $root)
        }
        $out.results = $results
        $out.leftovers = @($script:DefenseClawRollbackLeftovers)
        $out.events = @($script:events)
    }
    'prune' {
        Set-Probe 0 @('{"schema_version":1,"ok":true,"removed":["a"],"kept":["b"],"in_use":[{"folder":"C:\\x\\bin\\hooks\\cccccccccccccccc","error":"in use"}],"error":""}')
        Invoke-DefenseClawStandaloneHookImagePrune -Layout $layout -GatewayServiceName 'G' -Keep @('0123456789abcdef', 'aaaaaaaaaaaaaaaa', '0123456789abcdef') -WarningVariable warned -WarningAction SilentlyContinue
        $out.calls = @($script:calls)
        $out.warnings = @($warned | ForEach-Object { [string]$_ })
        Set-Probe 1 @('{"schema_version":1,"ok":false,"error":"boom"}')
        Invoke-DefenseClawStandaloneHookImagePrune -Layout $layout -GatewayServiceName 'G' -Keep @('0123456789abcdef') -WarningVariable failed -WarningAction SilentlyContinue
        $out.failed = @($failed | ForEach-Object { [string]$_ })
        Set-Probe 0 @('not json')
        Invoke-DefenseClawStandaloneHookImagePrune -Layout $layout -GatewayServiceName 'G' -Keep @('0123456789abcdef') -WarningVariable none -WarningAction SilentlyContinue
        $out.noReport = @($none | ForEach-Object { [string]$_ })
    }
}
$out | ConvertTo-Json -Compress -Depth 5
"""


def _run(tmp_path: Path, case: str, standalone: bool = True) -> dict:
    engine = shutil.which("pwsh")
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    harness = tmp_path / "hook-image.ps1"
    harness.write_text(_HARNESS, encoding="utf-8")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness),
         "-ModulePath", str(MODULE), "-Scratch", str(scratch), "-Case", case,
         "-Standalone", "1" if standalone else "0"],
        capture_output=True, text=True, timeout=180, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_the_location_parser_mirrors_the_go_resolver(tmp_path: Path) -> None:
    result = _run(tmp_path, "location")
    bin_ = "C:\\Program Files\\Cisco\\DefenseClaw\\bin"
    assert result["locations"] == [
        f"{bin_}|defenseclaw-hook.exe|",
        f"{bin_}|defenseclaw-hook-guard.exe|0123456789abcdef",
        f"{bin_}|defenseclaw-hook.exe|0123456789abcdef",
        "none", "none", "none", "none", "none", "none", "none", "none",
        "C:\\bin|defenseclaw-hook.exe|0123456789abcdef",
        "none",
    ], result
    assert result["family"] == [True, True, False, False, False], result
    assert result["managed"] == [True, False, True, False], result
    assert result["digest"] == "0123456789abcdef" and result["badDigest"] == "refused", result


def test_secure_client_keeps_the_exact_hook_and_stages_nothing(tmp_path: Path) -> None:
    result = _run(tmp_path, "secure-client", standalone=False)
    assert result["managed"] == [False, True], result
    assert result["calls"] == [], result


def test_the_tree_lists_only_what_defenseclaw_puts_there(tmp_path: Path) -> None:
    result = _run(tmp_path, "tree")
    assert sorted(result["directories"]) == sorted([
        "/bin/hooks", "/bin/hooks/0123456789abcdef", "/bin/hooks/.staging-" + "c" * 32,
    ]), result
    assert sorted(result["files"]) == sorted([
        "/bin/hooks/0123456789abcdef/defenseclaw-hook.exe",
        "/bin/hooks/0123456789abcdef/defenseclaw-hook-guard.exe",
        "/bin/hooks/0123456789abcdef/defenseclaw-hook.exe.backup." + "d" * 32,
        "/bin/hooks/0123456789abcdef/defenseclaw-hook.exe.restore-" + "e" * 16,
        "/bin/hooks/.staging-" + "c" * 32 + "/defenseclaw-hook.exe",
    ]), result
    assert result["empty"] == 0, result


def test_the_stage_calls_the_gateway_and_throws_with_its_reason(tmp_path: Path) -> None:
    result = _run(tmp_path, "stage")
    hook = "0123456789abcdef" + "a" * 48
    guard = "fedcba9876543210" + "b" * 48
    assert result["calls"] == [f"enterprise windows hook-image stage --sha256 {hook} --guard-sha256 {guard} --json"], result
    assert any(e.startswith("phase: hook image staged: ") for e in result["events"]), result
    r = result["results"]
    assert r["start"].startswith("hook_image_start_failed: the hook image of this release could not be staged in "), r
    assert "Nothing switched: every agent hook still runs the installed image." in r["start"], r
    assert "application control (WDAC or AppLocker)" in r["start"] and "\\*\\defenseclaw-hook.exe" in r["start"], r
    assert "allow the DefenseClaw signer" in r["start"] and r["start"].endswith("run the same Setup command again"), r
    assert r["digest"].startswith("hook_image_digest_mismatch: ") and "keeps changing" in r["digest"], r
    assert r["unknown"].startswith("hook_image_stage_failed: "), r
    assert r["exit"].startswith("hook_image_stage_failed: "), r
    assert r["folder"].startswith("hook_image_stage_failed: the hook image was staged in "), r
    assert r["nohook"].startswith("hook_image_stage_failed: the stage did not report the hook image"), r
    assert "expected exactly one" in r["two"], r
    assert "unsupported report schema: 2" in r["schema"], r
    assert result["noHookCalls"] == 0, result


def test_the_rollback_removes_only_a_hooks_folder_it_created(tmp_path: Path) -> None:
    result = _run(tmp_path, "rollback")
    assert result["results"] == {"created": False, "existed": True, "absent": True, "unexpected": True}, result
    (leftover,) = result["leftovers"]
    assert "transaction-created hook images folder left in place" in leftover, result
    assert "an item DefenseClaw did not put there" in leftover and "admin-notes.txt" in leftover, result
    assert any(e.startswith("defenseclaw_accept: transaction-created hook images folder left in place") for e in result["events"]), result


def test_the_prune_keeps_two_images_and_never_fails(tmp_path: Path) -> None:
    result = _run(tmp_path, "prune")
    assert result["calls"] == ["enterprise windows hook-image prune --keep 0123456789abcdef --keep aaaaaaaaaaaaaaaa --json"], result
    assert any("cccccccccccccccc is still in use and stays until the next upgrade" in w for w in result["warnings"]), result
    assert any("the earlier hook images were kept: boom" in w for w in result["failed"]), result
    assert any("expected exactly one" in w for w in result["noReport"]), result


def test_the_gateway_command_contract_is_the_one_the_design_names() -> None:
    text = _text()
    stage = _function_body(text, "Install-DefenseClawStandaloneHookImage")
    assert "$arguments = @('stage', '--sha256', $hookSHA256)" in stage
    assert "$arguments += @('--guard-sha256', $guardSHA256)" in stage
    assert "@('hook_image_start_failed', 'hook_image_digest_mismatch', 'hook_image_stage_failed')" in stage
    report = _function_body(text, "Get-DefenseClawHookImageGatewayReport")
    assert "@('enterprise', 'windows', 'hook-image') + $Arguments + @('--json')" in report
    assert re.search(r"\[string\]\$schema\.Value -cne '1'", report)
