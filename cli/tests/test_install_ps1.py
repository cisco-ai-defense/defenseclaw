# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Contracts for the native-Setup compatibility bootstrap on Windows."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALL_PS1 = ROOT / "scripts" / "install.ps1"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yaml"
POWERSHELL = shutil.which("powershell.exe") or shutil.which("pwsh.exe")


def _ps_quote(value: str | Path) -> str:
    return str(value).replace("'", "''")


def _run_powershell(script: str, *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    if not POWERSHELL:
        pytest.skip("PowerShell is not installed")
    env = os.environ.copy()
    env.pop("DEFENSECLAW_HOME", None)
    return subprocess.run(
        [
            POWERSHELL,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=env,
        check=False,
    )


def _dot_source(arguments: str = "") -> str:
    suffix = f" {arguments}" if arguments else ""
    return f". '{_ps_quote(INSTALL_PS1)}'{suffix}"


def _manifest(version: str = "1.2.3") -> dict[str, object]:
    return {
        "schema_version": 1,
        "release_version": version,
        "min_upgrade_protocol": 1,
        "migration_failure_policy": "fail",
        "required_cli_migrations": [],
        "windows_installer": {
            "asset": "DefenseClawSetup-x64.exe",
            "architectures": ["amd64"],
            "handoff_args": ["/upgrade", "/quiet", "/norestart", "INSTALLSCOPE=user"],
            "authenticode": {
                "required": True,
                "publisher": "Cisco Systems, Inc.",
            },
            "managed_policy": "respect",
        },
    }


def _provenance(
    setup_sha256: str,
    version: str = "1.2.3",
    *,
    unsigned: bool = False,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "artifact": "DefenseClawSetup-x64.exe",
        "artifact_sha256": setup_sha256,
        "version": version,
        "source_commit": "a" * 40,
        "distribution_flavor": "oss",
        "built_at_utc": "2026-07-14T00:00:00Z",
        "unsigned": unsigned,
        "inputs": {},
        "toolchain": {},
    }


def test_bootstrap_contains_no_legacy_dependency_install_path() -> None:
    text = INSTALL_PS1.read_text(encoding="utf-8")
    forbidden = (
        "Invoke-Uv",
        "Install-Uv",
        "Ensure-Python",
        "Install-ManagedWheel",
        "uv pip",
        "uv venv",
        "astral.sh/uv",
        "py3-none-any.whl",
        "defenseclaw_*_windows_",
        "Invoke-Expression",
    )
    for token in forbidden:
        assert token not in text
    assert "DefenseClawSetup-x64.exe" in text
    assert '$ProvenanceAsset = "$SetupAsset.provenance.json"' in text
    assert "Assert-SetupProvenance" in text
    assert "artifact_sha256" in text
    assert "Invoke-NativeSetup" in text
    assert "Get-AuthenticodeSignature" in text


def test_remote_verification_is_fail_closed_and_release_identity_is_exact() -> None:
    text = INSTALL_PS1.read_text(encoding="utf-8")
    assert "checksums.txt.sig" in text
    assert "checksums.txt.pem" in text
    assert "checksums.txt.bundle" in text
    assert "DD6C61E510DA627BCAED4CD9DB844EC11CACD09826D814D89F7F68D40FEB07BE" in text
    assert "--certificate-identity-regexp" in text
    assert '"--offline"' in text
    assert (
        "^https://github\\.com/cisco-ai-defense/defenseclaw/\\.github/workflows/"
        "release\\.yaml@refs/(tags/$escapedVersion|heads/main)$" in text
    )
    assert "Release checksum signature verification failed" in text
    assert 'Status -ne "Valid"' in text
    assert '$ExpectedPublisher = "Cisco Systems, Inc."' in text
    assert "warning-and-continue" not in text.lower()


def test_release_publishes_offline_sigstore_verification_material() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert workflow.count("cosign-release: v2.6.2") == 2
    assert workflow.count("--bundle=dist/checksums.txt.bundle") == 2
    assert "! -name checksums.txt.bundle" in workflow
    assert "dist/checksums.txt.bundle" in workflow


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_powershell_parser_and_help_are_network_free() -> None:
    completed = _run_powershell(
        rf"""
$tokens = $null
$errors = $null
[Management.Automation.Language.Parser]::ParseFile(
  '{_ps_quote(INSTALL_PS1)}', [ref]$tokens, [ref]$errors
) | Out-Null
if (@($errors).Count -ne 0) {{ throw ($errors -join '; ') }}
& '{_ps_quote(POWERSHELL or "")}' -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File '{_ps_quote(INSTALL_PS1)}' -Help
if ($LASTEXITCODE -ne 0) {{ throw "help exited $LASTEXITCODE" }}
"""
    )
    assert completed.returncode == 0, completed.stderr
    assert "DefenseClaw native Windows bootstrap" in completed.stdout


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
@pytest.mark.parametrize(
    ("parameters", "expected"),
    [
        (
            "-Connector codex -Yes -Quickstart -QuickstartMode action",
            [
                "/quiet",
                "/norestart",
                "INSTALLSCOPE=user",
                "CONNECTOR=codex",
                "MODE=action",
                "STARTGATEWAY=1",
            ],
        ),
        (
            "-Connector claudecode -Yes -Quickstart",
            [
                "/quiet",
                "/norestart",
                "INSTALLSCOPE=user",
                "CONNECTOR=claudecode",
                "MODE=observe",
                "STARTGATEWAY=1",
            ],
        ),
        (
            "-NoOpenclaw -Yes -Quickstart",
            [
                "/quiet",
                "/norestart",
                "INSTALLSCOPE=user",
                "CONNECTOR=none",
                "STARTGATEWAY=0",
            ],
        ),
        ("", ["/norestart", "INSTALLSCOPE=user"]),
    ],
)
def test_compatibility_flags_map_to_native_setup_properties(
    parameters: str,
    expected: list[str],
) -> None:
    completed = _run_powershell(
        rf"""
{_dot_source(parameters)}
$selected = Resolve-SelectedConnector
@((New-SetupArgumentList -SelectedConnector $selected)) | ConvertTo-Json -Compress
"""
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout.strip().splitlines()[-1]) == expected


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_no_persist_path_fails_before_release_resolution() -> None:
    completed = _run_powershell(
        rf"""
{_dot_source("-NoPersistPath -Yes -Version 1.2.3")}
function Resolve-RemoteVersion {{ throw 'NETWORK_OR_RELEASE_RESOLUTION_CALLED' }}
try {{ $null = Main; throw 'expected failure' }} catch {{ "ERROR=$($_.Exception.Message)" }}
"""
    )
    assert completed.returncode == 0, completed.stderr
    assert "no safe native Setup equivalent" in completed.stdout
    assert "NETWORK_OR_RELEASE_RESOLUTION_CALLED" not in completed.stdout


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_checksum_manifest_requires_one_exact_entry(tmp_path: Path) -> None:
    checksums = tmp_path / "checksums.txt"
    checksums.write_text(
        "a" * 64 + "  ./DefenseClawSetup-x64.exe\n" + "b" * 64 + "  nested/DefenseClawSetup-x64.exe\n",
        encoding="ascii",
    )
    completed = _run_powershell(
        rf"""
{_dot_source()}
Get-AuthenticatedChecksum -ChecksumsPath '{_ps_quote(checksums)}' `
  -FileName 'DefenseClawSetup-x64.exe'
"""
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "a" * 64

    checksums.write_text(
        "a" * 64 + "  DefenseClawSetup-x64.exe\n" + "b" * 64 + " *DefenseClawSetup-x64.exe\n",
        encoding="ascii",
    )
    completed = _run_powershell(
        rf"""
{_dot_source()}
try {{
  $null = Get-AuthenticatedChecksum -ChecksumsPath '{_ps_quote(checksums)}' `
    -FileName 'DefenseClawSetup-x64.exe'
  throw 'expected duplicate rejection'
}} catch {{ "ERROR=$($_.Exception.Message)" }}
"""
    )
    assert completed.returncode == 0, completed.stderr
    assert "contains 2 entries" in completed.stdout


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_cosign_verification_freezes_authenticated_checksum_content(tmp_path: Path) -> None:
    checksums = tmp_path / "checksums.txt"
    checksums.write_text("a" * 64 + "  DefenseClawSetup-x64.exe\n", encoding="ascii")
    signature = tmp_path / "checksums.txt.sig"
    certificate = tmp_path / "checksums.txt.pem"
    bundle = tmp_path / "checksums.txt.bundle"
    for item in (signature, certificate, bundle):
        item.write_bytes(b"fixture")
    # A real PE avoids cmd.exe reinterpreting the Sigstore identity regex pipe.
    # doskey accepts and ignores this argument shape with a successful exit.
    verifier_source = shutil.which("doskey.exe")
    if not verifier_source:
        pytest.skip("Windows doskey executable is unavailable")
    verifier = tmp_path / "cosign.exe"
    shutil.copyfile(verifier_source, verifier)
    verifier_sha = hashlib.sha256(verifier.read_bytes()).hexdigest()

    completed = _run_powershell(
        rf"""
{_dot_source()}
$script:CosignSha256 = '{verifier_sha}'
$frozen = Invoke-CosignVerification -Verifier '{_ps_quote(verifier)}' `
  -ChecksumsPath '{_ps_quote(checksums)}' -SignaturePath '{_ps_quote(signature)}' `
  -CertificatePath '{_ps_quote(certificate)}' -BundlePath '{_ps_quote(bundle)}' `
  -ReleaseVersion '1.2.3'
[IO.File]::WriteAllText('{_ps_quote(checksums)}', ('b' * 64) + "  DefenseClawSetup-x64.exe`n")
Get-AuthenticatedChecksum -ChecksumsContent $frozen -FileName 'DefenseClawSetup-x64.exe'
"""
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip().splitlines()[-1] == "a" * 64


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_authenticated_manifest_requires_exact_windows_policy(tmp_path: Path) -> None:
    manifest = tmp_path / "upgrade-manifest.json"
    manifest.write_text(json.dumps(_manifest()), encoding="utf-8")
    valid = _run_powershell(
        rf"""
{_dot_source()}
Assert-UpgradeManifest -Path '{_ps_quote(manifest)}' -ReleaseVersion '1.2.3'
Write-Output 'VALID'
"""
    )
    assert valid.returncode == 0, valid.stderr
    assert "VALID" in valid.stdout

    altered = _manifest()
    altered["windows_installer"]["authenticode"]["publisher"] = "Lookalike Publisher"  # type: ignore[index]
    manifest.write_text(json.dumps(altered), encoding="utf-8")
    invalid = _run_powershell(
        rf"""
{_dot_source()}
try {{
  Assert-UpgradeManifest -Path '{_ps_quote(manifest)}' -ReleaseVersion '1.2.3'
  throw 'expected policy rejection'
}} catch {{ "ERROR=$($_.Exception.Message)" }}
"""
    )
    assert invalid.returncode == 0, invalid.stderr
    assert "does not require the pinned DefenseClaw publisher" in invalid.stdout


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_authenticated_provenance_binds_signed_setup_checksum(tmp_path: Path) -> None:
    setup_sha = "a" * 64
    provenance = tmp_path / "DefenseClawSetup-x64.exe.provenance.json"
    provenance.write_text(json.dumps(_provenance(setup_sha)), encoding="utf-8")
    valid = _run_powershell(
        rf"""
{_dot_source()}
Assert-SetupProvenance -Path '{_ps_quote(provenance)}' `
  -ReleaseVersion '1.2.3' -SetupSha256 '{setup_sha}'
Write-Output 'VALID'
"""
    )
    assert valid.returncode == 0, valid.stderr
    assert "VALID" in valid.stdout

    provenance.write_text(json.dumps(_provenance("b" * 64)), encoding="utf-8")
    wrong_hash = _run_powershell(
        rf"""
{_dot_source()}
try {{
  Assert-SetupProvenance -Path '{_ps_quote(provenance)}' `
    -ReleaseVersion '1.2.3' -SetupSha256 '{setup_sha}'
  throw 'expected provenance rejection'
}} catch {{ "ERROR=$($_.Exception.Message)" }}
"""
    )
    assert wrong_hash.returncode == 0, wrong_hash.stderr
    assert "does not match the exact signed checksum" in wrong_hash.stdout

    provenance.write_text(json.dumps(_provenance(setup_sha, unsigned=True)), encoding="utf-8")
    unsigned = _run_powershell(
        rf"""
{_dot_source()}
try {{
  Assert-SetupProvenance -Path '{_ps_quote(provenance)}' `
    -ReleaseVersion '1.2.3' -SetupSha256 '{setup_sha}'
  throw 'expected unsigned provenance rejection'
}} catch {{ "ERROR=$($_.Exception.Message)" }}
"""
    )
    assert unsigned.returncode == 0, unsigned.stderr
    assert "does not describe a signed release artifact" in unsigned.stdout


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_untrusted_authenticode_is_rejected(tmp_path: Path) -> None:
    setup = tmp_path / "DefenseClawSetup-x64.exe"
    setup.write_bytes(b"unsigned fixture")
    completed = _run_powershell(
        rf"""
{_dot_source()}
function Get-AuthenticodeSignature {{
  [pscustomobject]@{{ Status = 'NotSigned'; SignerCertificate = $null }}
}}
try {{
  Assert-SetupAuthenticode -Path '{_ps_quote(setup)}'
  throw 'expected Authenticode rejection'
}} catch {{ "ERROR=$($_.Exception.Message)" }}
"""
    )
    assert completed.returncode == 0, completed.stderr
    assert "status='NotSigned'" in completed.stdout


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_local_authenticode_uses_setup_cache_only_verifier(tmp_path: Path) -> None:
    setup = tmp_path / "DefenseClawSetup-x64.exe"
    setup.write_bytes(b"authenticated setup fixture")
    completed = _run_powershell(
        rf"""
{_dot_source(f"-Local '{_ps_quote(tmp_path)}'")}
function Get-AuthenticodeSignature {{ throw 'NETWORK_CAPABLE_VERIFIER_CALLED' }}
function Invoke-BoundedNativeProcess {{
  param($FilePath, [string[]]$Arguments, $TimeoutSeconds, [switch]$Hidden)
  if ($FilePath -ne '{_ps_quote(setup)}' -or ($Arguments -join '|') -ne '/verify') {{
    throw 'wrong offline verifier invocation'
  }}
  return 0
}}
Assert-SetupAuthenticode -Path '{_ps_quote(setup)}'
Write-Output 'VERIFIED'
"""
    )
    assert completed.returncode == 0, completed.stderr
    assert "NETWORK_CAPABLE_VERIFIER_CALLED" not in completed.stdout + completed.stderr
    assert "VERIFIED" in completed.stdout


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_local_bundle_delegates_without_any_network_or_dependency_tool(
    tmp_path: Path,
) -> None:
    release = tmp_path / "offline release"
    release.mkdir()
    setup = release / "DefenseClawSetup-x64.exe"
    setup.write_bytes(b"signed setup fixture bytes")
    setup_sha = hashlib.sha256(setup.read_bytes()).hexdigest()
    manifest = release / "upgrade-manifest.json"
    manifest.write_text(json.dumps(_manifest()) + "\n", encoding="utf-8")
    provenance = release / "DefenseClawSetup-x64.exe.provenance.json"
    provenance.write_text(json.dumps(_provenance(setup_sha)) + "\n", encoding="utf-8")
    checksums = release / "checksums.txt"
    checksums.write_text(
        f"{setup_sha}  {setup.name}\n"
        f"{hashlib.sha256(manifest.read_bytes()).hexdigest()}  {manifest.name}\n"
        f"{hashlib.sha256(provenance.read_bytes()).hexdigest()}  {provenance.name}\n",
        encoding="ascii",
    )
    (release / "checksums.txt.sig").write_bytes(b"fixture signature")
    (release / "checksums.txt.pem").write_bytes(b"fixture certificate")
    (release / "checksums.txt.bundle").write_bytes(b"fixture Sigstore bundle")
    cosign = release / "cosign-windows-amd64.exe"
    cosign.write_bytes(b"pinned verifier fixture")
    cosign_sha = hashlib.sha256(cosign.read_bytes()).hexdigest()
    completed = _run_powershell(
        rf"""
{_dot_source(f"-Local '{_ps_quote(release)}' -CosignPath '{_ps_quote(cosign)}' -Connector codex -Yes -Quickstart -QuickstartMode action")}
$script:CosignSha256 = '{cosign_sha}'
function Invoke-WebRequest {{ throw 'NETWORK_CALLED' }}
function Invoke-RestMethod {{ throw 'NETWORK_CALLED' }}
function Invoke-DownloadFile {{ throw 'NETWORK_CALLED' }}
function Invoke-CosignVerification {{
  param($Verifier, $ChecksumsPath, $SignaturePath, $CertificatePath, $BundlePath, $ReleaseVersion)
  if ($ReleaseVersion -ne '1.2.3') {{ throw "wrong version: $ReleaseVersion" }}
  Write-Host 'COSIGN_VERIFIED'
  return [IO.File]::ReadAllText($ChecksumsPath)
}}
function Assert-SetupAuthenticode {{ param($Path) Write-Host 'AUTHENTICODE_VERIFIED' }}
function Invoke-NativeSetup {{
  param($SetupPath, $ExpectedSha256, [string[]]$Arguments)
  if ($ExpectedSha256 -ne '{setup_sha}') {{ throw 'wrong setup checksum' }}
  if (-not (Test-Path -LiteralPath $SetupPath -PathType Leaf)) {{ throw 'missing staged setup' }}
  Write-Host ('SETUP_ARGS=' + ($Arguments -join '|'))
  return 0
}}
$result = Main
Write-Output "RESULT=$result"
""",
        timeout=90,
    )
    assert completed.returncode == 0, completed.stderr
    assert "NETWORK_CALLED" not in completed.stdout + completed.stderr
    assert "COSIGN_VERIFIED" in completed.stdout
    # Authenticode is checked once after staged checksum verification and again
    # immediately before the real handoff; the test seam observes both calls.
    assert completed.stdout.count("AUTHENTICODE_VERIFIED") == 1
    assert (
        "SETUP_ARGS=/quiet|/norestart|INSTALLSCOPE=user|CONNECTOR=codex|MODE=action|STARTGATEWAY=1" in completed.stdout
    )
    assert "RESULT=0" in completed.stdout


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_native_setup_exit_code_is_preserved_by_main() -> None:
    completed = _run_powershell(
        rf"""
{_dot_source("-Version 1.2.3 -Yes")}
function Assert-NativeWindowsX64 {{}}
function Assert-CompatibleLayoutRequest {{}}
function Stage-RemoteBundle {{
  [pscustomobject]@{{ Root=''; Setup='fixture.exe'; SetupSha256=('a' * 64); Version='1.2.3' }}
}}
function Invoke-NativeSetup {{ return 1603 }}
$result = Main
Write-Output "RESULT=$result"
"""
    )
    assert completed.returncode == 0, completed.stderr
    assert "RESULT=1603" in completed.stdout


def test_setup_is_reauthenticated_immediately_before_handoff() -> None:
    text = INSTALL_PS1.read_text(encoding="utf-8")
    function = text.split("function Invoke-NativeSetup", 1)[1].split("\nfunction Main", 1)[0]
    checksum = function.index("Assert-Sha256")
    authenticode = function.index("Assert-SetupAuthenticode")
    execution = function.index("Invoke-BoundedNativeProcess")
    assert checksum < authenticode < execution
    assert "& $SetupPath" not in function


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows process semantics")
def test_bounded_native_process_waits_for_windows_gui_exit_code(tmp_path: Path) -> None:
    go = shutil.which("go")
    if not go:
        pytest.skip("Go toolchain is unavailable")
    source = tmp_path / "gui_exit.go"
    source.write_text(
        'package main\nimport ("os"; "time")\n'
        'func main() { time.Sleep(200 * time.Millisecond); os.Exit(23) }\n',
        encoding="utf-8",
    )
    executable = tmp_path / "gui-exit.exe"
    build = subprocess.run(
        [go, "build", "-ldflags=-H=windowsgui", "-o", executable, source],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert build.returncode == 0, build.stderr

    completed = _run_powershell(
        rf"""
{_dot_source()}
$code = Invoke-BoundedNativeProcess -FilePath '{_ps_quote(executable)}' `
  -Arguments @() -TimeoutSeconds 30 -Hidden
Write-Output "EXIT=$code"
""",
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    assert "EXIT=23" in completed.stdout


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows process-tree semantics")
def test_bounded_native_process_timeout_cleans_gui_process_tree(tmp_path: Path) -> None:
    go = shutil.which("go")
    if not go:
        pytest.skip("Go toolchain is unavailable")
    source = tmp_path / "gui_tree.go"
    source.write_text(
        "package main\n"
        'import ("os"; "os/exec"; "strconv"; "time")\n'
        "func main() {\n"
        ' marker := os.Getenv("DC_GUI_CHILD_PID")\n'
        ' if len(os.Args) > 1 && os.Args[1] == "child" {\n'
        "  _ = os.WriteFile(marker, []byte(strconv.Itoa(os.Getpid())), 0600)\n"
        "  time.Sleep(30 * time.Second); return\n"
        " }\n"
        ' child := exec.Command(os.Args[0], "child")\n'
        " _ = child.Start()\n"
        " deadline := time.Now().Add(5 * time.Second)\n"
        " for time.Now().Before(deadline) { if _, err := os.Stat(marker); err == nil { break }; time.Sleep(20 * time.Millisecond) }\n"
        " time.Sleep(30 * time.Second)\n"
        "}\n",
        encoding="utf-8",
    )
    executable = tmp_path / "gui-tree.exe"
    build = subprocess.run(
        [go, "build", "-ldflags=-H=windowsgui", "-o", executable, source],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert build.returncode == 0, build.stderr
    marker = tmp_path / "child.pid"

    completed = _run_powershell(
        rf"""
{_dot_source()}
$env:DC_GUI_CHILD_PID = '{_ps_quote(marker)}'
$message = ''
try {{
  Invoke-BoundedNativeProcess -FilePath '{_ps_quote(executable)}' `
    -Arguments @() -TimeoutSeconds 1 -Hidden | Out-Null
  throw 'expected timeout'
}} catch {{
  $message = $_.Exception.Message
}}
if (-not (Test-Path -LiteralPath '{_ps_quote(marker)}' -PathType Leaf)) {{
  throw 'child PID marker was not created'
}}
$childPid = [int]([IO.File]::ReadAllText('{_ps_quote(marker)}'))
Start-Sleep -Milliseconds 500
$alive = Get-Process -Id $childPid -ErrorAction SilentlyContinue
if ($null -ne $alive) {{
  Stop-Process -Id $childPid -Force -ErrorAction SilentlyContinue
  throw "timed-out GUI descendant remained alive: $childPid"
}}
Write-Output "TIMEOUT=$message"
""",
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert "TIMEOUT=Native process timed out" in completed.stdout


def test_dot_source_is_the_only_no_run_seam() -> None:
    text = INSTALL_PS1.read_text(encoding="utf-8")
    assert "if ($MyInvocation.InvocationName -ne '.')" in text
    assert "in-memory ScriptBlock" in text
    assert "if (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) { exit 0 }" in text
    assert "DEFENSECLAW_" + "INSTALLER_TEST" not in text
    assert "AllowUnsigned" not in text
