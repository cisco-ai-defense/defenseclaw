# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""The Intune reference rule-pack app (GAP-0109).

A base config that names a custom rule pack needs the pack on the device, with
NT SERVICE\\DefenseClawGateway able to read it and its parent folder, before
Setup runs; the live lab script granted only SYSTEM and Administrators and
Setup refused the base app with 1639. These tests run the kit's scripts under
pwsh on any OS: -PlanOnly for the icacls command lines, and the functions
(dot-sourced, with icacls and Get-Acl replaced) for the install, its
idempotence and the permission check.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
KIT = ROOT / "packaging" / "mdm" / "intune" / "windows"
INSTALL = KIT / "Install-DefenseClawRulePack.ps1"
DETECT = KIT / "Detect-DefenseClawRulePack.ps1"
PACKAGER = KIT / "New-DefenseClawIntunePackage.ps1"
GATEWAY = "S-1-5-80-1858176940-1394861675-2895326486-505287571-2610476274"
REGION_BEGIN = "# region DefenseClaw rule pack helpers"
REGION_END = "# endregion DefenseClaw rule pack helpers"
PACKS = r"C:\ProgramData\DefenseClaw-RulePacks"

# Exit code 1639 (invalid arguments); a POSIX shell keeps its low 8 bits.
INVALID_ARGUMENTS = 1639 if os.name == "nt" else 1639 & 0xFF

needs_pwsh = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh is required for the Intune kit scripts")


def _region(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    return text[text.index(REGION_BEGIN) : text.index(REGION_END)]


def test_rule_pack_helpers_are_identical() -> None:
    assert _region(INSTALL) == _region(DETECT)


def _pack(root: Path, files: dict[str, str]) -> Path:
    pack = root / "p2int"
    for name, body in files.items():
        path = pack / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="ascii")
    return pack


def _tree_sha256(pack: Path) -> str:
    lines = sorted(
        f"{p.relative_to(pack).as_posix()}\t{hashlib.sha256(p.read_bytes()).hexdigest()}\n"
        for p in pack.rglob("*")
        if p.is_file()
    )
    return hashlib.sha256("".join(lines).encode()).hexdigest()


def _pwsh(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", *args], capture_output=True, text=True, timeout=120)


@needs_pwsh
def test_plan_grants_the_gateway_on_the_pack_and_its_parent(tmp_path: Path) -> None:
    pack = _pack(tmp_path, {"rules/r.yaml": "rules: []\n", "judge/j.yaml": "j: 1\n"})
    run = _pwsh("-File", str(INSTALL), "-PackName", "p2int", "-SourcePath", str(pack), "-PlanOnly")
    assert run.returncode == 0, run.stdout + run.stderr
    lines = run.stdout.splitlines()
    assert lines[0] == f"rule pack p2int tree sha256 {_tree_sha256(pack)}"
    grant = rf"*S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *{GATEWAY}:(OI)(CI)RX"
    target = PACKS + r"\p2int"
    assert lines[2:] == [
        f'icacls "{PACKS}" /setowner *S-1-5-32-544 /C',
        f'icacls "{PACKS}" /inheritance:r /grant:r {grant}',
        f'icacls "{PACKS}" /remove:g *S-1-5-32-545 *S-1-5-11 *S-1-1-0 *S-1-5-4',
        f'icacls "{target}" /reset /T /C',
        f'icacls "{target}" /grant:r {grant}',
        f'icacls "{target}" /setowner *S-1-5-32-544 /T /C',
    ]


@needs_pwsh
@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["-PackName", "../x"], "invalid_arguments: -PackName"),
        (["-PackName", "p2int", "-PacksRoot", "C:\\"], "invalid_arguments: -PacksRoot"),
        (["-PackName", "p2int", "-PacksRoot", r"C:\Packs\..\Windows"], "invalid_arguments: -PacksRoot"),
        (["-PackName", "p2int", "-ExpectedTreeSha256", "a" * 64], "rule_pack_hash_mismatch"),
    ],
)
def test_install_refuses_bad_arguments_and_a_changed_pack(tmp_path: Path, args: list[str], message: str) -> None:
    pack = _pack(tmp_path, {"rules/r.yaml": "rules: []\n"})
    run = _pwsh("-File", str(INSTALL), "-SourcePath", str(pack), "-PlanOnly", *args)
    assert run.returncode != 0 and run.stdout.startswith(message), run.stdout
    assert "icacls" not in run.stdout


# The install replaces the owner and permissions of -PacksRoot; a typo that
# names a system, profile or DefenseClaw folder must change nothing.
REFUSED_ROOTS = [
    r"C:\ProgramData",
    r"c:\programdata",
    r"C:\Windows",
    r"D:\Windows\Temp\packs",
    r"C:\Program Files",
    r"C:\Program Files (x86)\Packs",
    r"C:\Users",
    r"C:\Users\alice\packs",
    r"C:\ProgramData\Microsoft\packs",
    r"C:\ProgramData\Cisco",
    r"C:\ProgramData\Cisco\DefenseClaw",
    r"C:\ProgramData\Cisco\DefenseClaw\policies",
    r"C:\ProgramData\DefenseClaw",
    r"C:\PROGRA~3\packs",
    r"C:\ProgramData.\packs",
    r"C:\Windows \packs",
]


@needs_pwsh
@pytest.mark.parametrize("packs_root", REFUSED_ROOTS)
def test_install_refuses_a_system_profile_or_install_folder(tmp_path: Path, packs_root: str) -> None:
    pack = _pack(tmp_path, {"rules/r.yaml": "rules: []\n"})
    for extra in ([], ["-Remove"]):
        run = _pwsh(
            "-File",
            str(INSTALL),
            "-PackName",
            "p2int",
            "-SourcePath",
            str(pack),
            "-PacksRoot",
            packs_root,
            "-PlanOnly",
            *extra,
        )
        assert run.returncode == INVALID_ARGUMENTS, (extra, run.returncode, run.stdout)
        assert run.stdout.startswith("invalid_arguments: -PacksRoot"), (extra, run.stdout)
        assert "icacls" not in run.stdout
    detect = _pwsh(
        "-File", str(DETECT), "-PackName", "p2int", "-PacksRoot", packs_root, "-ExpectedTreeSha256", "a" * 64
    )
    assert detect.returncode == 1 and "set $PackName, $PacksRoot" in detect.stderr, detect.stderr


@needs_pwsh
@pytest.mark.parametrize("packs_root", [PACKS, r"D:\Policy\Packs", r"C:\ProgramData\Cisco\RulePacks", r"C:\Packs"])
def test_install_plans_for_a_folder_of_its_own(tmp_path: Path, packs_root: str) -> None:
    pack = _pack(tmp_path, {"rules/r.yaml": "rules: []\n"})
    run = _pwsh(
        "-File", str(INSTALL), "-PackName", "p2int", "-SourcePath", str(pack), "-PacksRoot", packs_root, "-PlanOnly"
    )
    assert run.returncode == 0 and f'icacls "{packs_root}" /inheritance:r' in run.stdout, run.stdout


# Dot-sources a kit script, replaces what touches Windows (icacls, Get-Acl,
# the elevation and drive-path checks), runs the scenario and prints JSON.
HARNESS = r"""
param([string]$Script, [string]$Scenario, [string]$Work)
$ErrorActionPreference = 'Stop'
. $Script
. $env:DC_DETECT
$global:Calls = New-Object System.Collections.Generic.List[string]
$global:Acl = @{}
$global:Good = [pscustomobject]@{ Owner = 'S-1-5-32-544'; Entries = @(
    [pscustomobject]@{ Sid = 'S-1-5-18'; Rights = 0x1F01FF; Allow = $true; InheritOnly = $false },
    [pscustomobject]@{ Sid = 'S-1-5-32-544'; Rights = 0x1F01FF; Allow = $true; InheritOnly = $false },
    [pscustomobject]@{ Sid = $script:DcGatewaySid; Rights = 0x1200A9; Allow = $true; InheritOnly = $false }) }
function Invoke-DcIcacls { param([string[]]$Arguments) $global:Calls.Add(($Arguments -join ' ')) }
function Test-DcElevated { return $true }
function Test-DcPacksRoot { param([string]$Path) return $true }
function Get-DcAclState { param([string]$Path) if ($global:Acl.ContainsKey($Path)) { return $global:Acl[$Path] } return $global:Good }
$root = Join-Path $Work 'packs'
$global:PacksRootPath = $root
$source = Join-Path $Work 'p2int'
$result = [ordered]@{}
function Install { return Invoke-DcRulePackInstall -PackName 'p2int' -SourcePath $source -PacksRoot $root -ExpectedTreeSha256 '' }
switch ($Scenario) {
    'lifecycle' {
        $result.first = Install; $result.firstCalls = @($global:Calls); $global:Calls.Clear()
        $result.firstTree = (Get-DcRulePackTree -Path (Join-Path $root 'p2int')).Sha256
        $result.sourceTree = (Get-DcRulePackTree -Path $source).Sha256
        $result.again = Install; $result.againCalls = @($global:Calls); $global:Calls.Clear()
        Set-Content -LiteralPath (Join-Path $source 'rules/r.yaml') -Value 'rules: [changed]' -NoNewline
        $result.changed = Install; $result.changedCalls = @($global:Calls); $global:Calls.Clear()
        $result.changedContent = Get-Content -LiteralPath (Join-Path $root 'p2int/rules/r.yaml') -Raw
        # The permissions drifted, the content did not: re-apply, do not copy.
        $global:Acl[$root] = [pscustomobject]@{ Owner = 'S-1-5-32-544'; Entries = @($global:Good.Entries[0], $global:Good.Entries[1]) }
        function Invoke-DcIcacls { param([string[]]$Arguments) $global:Calls.Add(($Arguments -join ' ')); $global:Acl.Remove($global:PacksRootPath) }
        $result.drift = Install; $result.driftCalls = @($global:Calls); $global:Calls.Clear()
        $result.removed = Invoke-DcRulePackInstall -PackName 'p2int' -SourcePath '' -PacksRoot $root -ExpectedTreeSha256 '' -Remove
        $result.removedExists = Test-Path -LiteralPath (Join-Path $root 'p2int')
        $result.leftovers = @(Get-ChildItem -LiteralPath $root -Force | ForEach-Object { $_.Name })
    }
    'strangers' {
        # An existing PacksRoot that holds more than packs is refused before
        # any icacls; other packs and this script's leftovers are not.
        # A PacksRoot that is a file or a link is not a folder of its own.
        Set-Content -LiteralPath $root -Value 'x'
        $result.rootFile = Install
        Remove-Item -LiteralPath $root
        $elsewhere = Join-Path $Work 'elsewhere'
        New-Item -ItemType Directory -Path $elsewhere | Out-Null
        New-Item -ItemType SymbolicLink -Path $root -Target $elsewhere | Out-Null
        $result.rootLink = Install; $result.linkCalls = @($global:Calls)
        Remove-Item -LiteralPath $root
        New-Item -ItemType Directory -Path $root | Out-Null
        # A file named like a pack is still not a pack folder.
        Set-Content -LiteralPath (Join-Path $root 'readme') -Value 'x'
        $result.file = Install; $result.fileCalls = @($global:Calls)
        Remove-Item -LiteralPath (Join-Path $root 'readme')
        New-Item -ItemType Directory -Path (Join-Path $root 'Microsoft Edge') | Out-Null
        $result.folder = Install; $result.folderCalls = @($global:Calls)
        Remove-Item -LiteralPath (Join-Path $root 'Microsoft Edge')
        New-Item -ItemType Directory -Path (Join-Path $root 'other-pack') | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $root '.p2int.old-0123abcd') | Out-Null
        $result.packs = Install
        $result.left = @(Get-ChildItem -LiteralPath $root -Force | ForEach-Object { $_.Name } | Sort-Object)
    }
    'ancestor' {
        # A folder above PacksRoot does not let the gateway list it.
        $null = Install
        $sha = (Get-DcRulePackTree -Path (Join-Path $root 'p2int')).Sha256
        $global:Acl[$Work] = [pscustomobject]@{ Owner = 'S-1-5-18'; Entries = @($global:Good.Entries[0], $global:Good.Entries[1]) }
        $result.detected = Invoke-DcRulePackDetect -PackName 'p2int' -PacksRoot $root -ExpectedTreeSha256 $sha
        $result.code = Install
    }
    'unreadable' {
        # The parent stays without the gateway entry after icacls ran.
        $global:Acl[$root] = [pscustomobject]@{ Owner = 'S-1-5-32-544'; Entries = @($global:Good.Entries[0], $global:Good.Entries[1]) }
        $result.code = Install
    }
    'detect' {
        $null = Install
        $sha = (Get-DcRulePackTree -Path (Join-Path $root 'p2int')).Sha256
        $result.detected = Invoke-DcRulePackDetect -PackName 'p2int' -PacksRoot $root -ExpectedTreeSha256 $sha
        $result.otherPack = Invoke-DcRulePackDetect -PackName 'p2int' -PacksRoot $root -ExpectedTreeSha256 ('0' * 64)
        $global:Acl[(Join-Path $root 'p2int')] = [pscustomobject]@{ Owner = 'S-1-5-32-544'; Entries = @($global:Good.Entries + [pscustomobject]@{ Sid = 'S-1-5-32-545'; Rights = 0x1200A9; Allow = $true; InheritOnly = $false }) }
        $result.usersRead = Invoke-DcRulePackDetect -PackName 'p2int' -PacksRoot $root -ExpectedTreeSha256 $sha
    }
}
[Console]::Out.WriteLine('RESULT:' + ($result | ConvertTo-Json -Compress -Depth 4))
"""


def _harness(tmp_path: Path, scenario: str) -> tuple[dict, str]:
    source = _pack(tmp_path, {"rules/r.yaml": "rules: []\n", "judge/j.yaml": "j: 1\n"})
    before = _tree_sha256(source)
    harness = tmp_path / "harness.ps1"
    harness.write_text(HARNESS, encoding="ascii")
    run = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(harness),
            "-Script",
            str(INSTALL),
            "-Scenario",
            scenario,
            "-Work",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "DC_DETECT": str(DETECT)},
    )
    assert run.returncode == 0, run.stdout + run.stderr
    line = next(line for line in run.stdout.splitlines() if line.startswith("RESULT:"))
    return {**json.loads(line[len("RESULT:") :]), "pythonTree": before}, run.stdout


@needs_pwsh
def test_install_is_idempotent_swaps_a_changed_pack_and_repairs_permissions(tmp_path: Path) -> None:
    result, out = _harness(tmp_path, "lifecycle")
    root = str(tmp_path / "packs")
    pack = str(tmp_path / "packs" / "p2int")
    gateway_grant = f"*{GATEWAY}:(OI)(CI)RX"
    # First install: the parent first (owner, entries, no Users), then the pack.
    assert result["first"] == 0, out
    calls = result["firstCalls"]
    assert [c.split(" ")[1] for c in calls] == [
        "/setowner",
        "/inheritance:r",
        "/remove:g",
        "/reset",
        "/grant:r",
        "/setowner",
    ]
    assert calls[1].startswith(root + " /inheritance:r /grant:r") and gateway_grant in calls[1]
    assert calls[4].startswith(pack + " /grant:r") and gateway_grant in calls[4]
    assert result["firstTree"] == result["sourceTree"] == result["pythonTree"]
    # Run again: nothing to do.
    assert result["again"] == 0 and result["againCalls"] == []
    assert "already installed" in out and "nothing changed" in out
    # A changed pack is copied beside the old one and swapped in.
    assert result["changed"] == 0
    assert result["changedContent"] == "rules: [changed]"
    assert any(c == pack + " /reset /T /C" for c in result["changedCalls"])
    # Drifted permissions with the same content are re-applied without a copy.
    assert result["drift"] == 0 and len(result["driftCalls"]) == 6
    assert result["removed"] == 0 and result["removedExists"] is False
    assert result["leftovers"] == []


@needs_pwsh
def test_install_fails_when_the_gateway_still_cannot_read_the_parent(tmp_path: Path) -> None:
    result, out = _harness(tmp_path, "unreadable")
    assert result["code"] == 1603
    root = str(tmp_path / "packs")
    assert f"rule_pack_not_ready: the gateway service account NT SERVICE\\DefenseClawGateway cannot read {root}" in out
    assert f'icacls "{root}" /grant "NT SERVICE\\DefenseClawGateway:RX"' in out


@needs_pwsh
def test_install_refuses_a_packs_root_that_holds_more_than_packs(tmp_path: Path) -> None:
    result, out = _harness(tmp_path, "strangers")
    root = tmp_path / "packs"
    assert result["rootFile"] == 1639 and result["rootLink"] == 1639 and result["linkCalls"] == [], out
    assert result["file"] == 1639 and result["fileCalls"] == [], out
    assert (
        f"invalid_arguments: -PacksRoot {root} must hold only rule pack folders, and {root / 'readme'} is not one"
        in out
    )
    assert result["folder"] == 1639 and result["folderCalls"] == [], out
    assert result["packs"] == 0, out
    assert result["left"] == ["other-pack", "p2int"]


@needs_pwsh
def test_install_and_detect_check_every_folder_above_the_packs_root(tmp_path: Path) -> None:
    result, out = _harness(tmp_path, "ancestor")
    assert result["detected"] == 1 and result["code"] == 1603, out
    assert (
        f"rule_pack_not_ready: the gateway service account NT SERVICE\\DefenseClawGateway cannot read {tmp_path}" in out
    )
    assert f"cannot read {tmp_path / 'packs'}" not in out


@needs_pwsh
def test_detect_requires_the_tree_and_private_permissions(tmp_path: Path) -> None:
    result, out = _harness(tmp_path, "detect")
    assert result["detected"] == 0 and "DefenseClaw rule pack p2int installed in" in out
    assert result["otherPack"] == 1
    assert result["usersRead"] == 1


ACL_CASES = r"""
param([string]$Script)
. $Script
$gw = $script:DcGatewaySid
function E([string]$Sid, [int64]$Rights, [bool]$Allow = $true, [bool]$InheritOnly = $false) { [pscustomobject]@{ Sid = $Sid; Rights = $Rights; Allow = $Allow; InheritOnly = $InheritOnly } }
$admins = @((E 'S-1-5-18' 0x1F01FF), (E 'S-1-5-32-544' 0x1F01FF))
$cases = [ordered]@{
    good          = @{ Owner = 'S-1-5-32-544'; Entries = $admins + (E $gw 0x1200A9); Role = 'pack' }
    genericRead   = @{ Owner = 'S-1-5-18'; Entries = $admins + (E $gw 0x80000000L); Role = 'pack' }
    noGateway     = @{ Owner = 'S-1-5-32-544'; Entries = $admins; Role = 'pack' }
    inheritOnly   = @{ Owner = 'S-1-5-32-544'; Entries = $admins + (E $gw 0x1200A9 $true $true); Role = 'pack' }
    denied        = @{ Owner = 'S-1-5-32-544'; Entries = $admins + (E $gw 0x1200A9) + (E 'S-1-1-0' 0x20000 $false); Role = 'pack' }
    usersRead     = @{ Owner = 'S-1-5-32-544'; Entries = $admins + (E $gw 0x1200A9) + (E 'S-1-5-32-545' 0x1200A9); Role = 'pack' }
    domainUsers   = @{ Owner = 'S-1-5-32-544'; Entries = $admins + (E $gw 0x1200A9) + (E 'S-1-5-21-1-2-3-513' 0x1200A9); Role = 'pack' }
    userWrite     = @{ Owner = 'S-1-5-32-544'; Entries = $admins + (E $gw 0x1200A9) + (E 'S-1-5-21-1-2-3-1001' 0x2); Role = 'pack' }
    userOwner     = @{ Owner = 'S-1-5-21-1-2-3-1001'; Entries = $admins + (E $gw 0x1200A9); Role = 'pack' }
    ancestorUsers = @{ Owner = 'S-1-5-21-1-2-3-1001'; Entries = @((E 'S-1-5-32-545' 0x1200A9), (E 'S-1-5-11' 0x6)); Role = 'ancestor' }
    ancestorNone  = @{ Owner = 'S-1-5-18'; Entries = $admins; Role = 'ancestor' }
}
$out = [ordered]@{}
foreach ($name in $cases.Keys) {
    $c = $cases[$name]
    $found = Get-DcAclProblems -State ([pscustomobject]@{ Owner = $c.Owner; Entries = $c.Entries }) -Path 'X' -IsDirectory $true -Role $c.Role
    $out[$name] = $found
}
[Console]::Out.WriteLine(($out | ConvertTo-Json -Compress -Depth 4))
"""


@needs_pwsh
def test_permission_check_matches_what_setup_requires(tmp_path: Path) -> None:
    script = tmp_path / "acl.ps1"
    script.write_text(ACL_CASES, encoding="ascii")
    run = _pwsh("-File", str(script), "-Script", str(INSTALL))
    assert run.returncode == 0, run.stdout + run.stderr
    problems = json.loads(run.stdout.strip().splitlines()[-1])
    assert problems["good"] == [] and problems["genericRead"] == [] and problems["ancestorUsers"] == []
    unreadable = "the gateway service account NT SERVICE\\DefenseClawGateway cannot read X"
    for name in ("noGateway", "inheritOnly", "denied", "ancestorNone"):
        assert problems[name] == [unreadable], (name, problems[name])
    assert problems["usersRead"] == ["X can be read by standard users (S-1-5-32-545)"]
    assert problems["domainUsers"] == ["X can be read by standard users (S-1-5-21-1-2-3-513)"]
    assert problems["userWrite"] == ["X can be changed by S-1-5-21-1-2-3-1001, which is not SYSTEM or Administrators"]
    assert problems["userOwner"] == ["X is owned by S-1-5-21-1-2-3-1001, not by SYSTEM or Administrators"]


@needs_pwsh
@pytest.mark.parametrize(
    ("pack_path", "hinted"),
    [
        (r"'C:\ProgramData\DefenseClaw-RulePacks\p2int'", True),
        (r"D:\Policy\p2int", True),
        (r"'C:\ProgramData\Cisco\DefenseClaw\policies\p2int'", False),
    ],
)
def test_packager_names_the_rule_pack_prerequisite(tmp_path: Path, pack_path: str, hinted: bool) -> None:
    setup = tmp_path / "DefenseClawSetup-Enterprise-Standalone-x64.exe"
    setup.write_bytes(b"packager-only stub")
    config = tmp_path / "config.yaml"
    config.write_text(
        "guardrail:\n  block_at: HIGH\n  rule_pack: p2int\n  custom_packs:\n    p2int:\n"
        f"      path: {pack_path}\n      digest: sha256:{'a' * 64}\n",
        encoding="ascii",
    )
    run = _pwsh(
        "-File",
        str(PACKAGER),
        "-SetupPath",
        str(setup),
        "-Sha256",
        hashlib.sha256(setup.read_bytes()).hexdigest(),
        "-ConfigPath",
        str(config),
        "-OutputDirectory",
        str(tmp_path / "out"),
    )
    assert run.returncode == 0, run.stderr
    prerequisite = [line for line in run.stdout.splitlines() if line.startswith("Prerequisite:")]
    if hinted:
        assert len(prerequisite) == 1 and "p2int at " + pack_path.strip("'") in prerequisite[0], run.stdout
        assert "Install-DefenseClawRulePack.ps1" in run.stdout and "dependency of the" in run.stdout
    else:
        assert prerequisite == [], run.stdout


@needs_pwsh
def test_packager_without_custom_packs_prints_no_prerequisite(tmp_path: Path) -> None:
    setup = tmp_path / "DefenseClawSetup-Enterprise-Standalone-x64.exe"
    setup.write_bytes(b"packager-only stub")
    config = tmp_path / "config.yaml"
    config.write_text("guardrail:\n  block_at: HIGH\n  rule_pack: default\n", encoding="ascii")
    run = _pwsh(
        "-File",
        str(PACKAGER),
        "-SetupPath",
        str(setup),
        "-Sha256",
        hashlib.sha256(setup.read_bytes()).hexdigest(),
        "-ConfigPath",
        str(config),
        "-OutputDirectory",
        str(tmp_path / "out"),
    )
    assert run.returncode == 0, run.stderr
    assert "Prerequisite:" not in run.stdout
