# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Contracts for the authenticated native Windows rescue bootstrap."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from defenseclaw.resolver_hint import (
    COSIGN_BOOTSTRAP_SHA256,
    COSIGN_BOOTSTRAP_VERSION,
)

ROOT = Path(__file__).resolve().parents[2]
RESCUE = ROOT / "scripts" / "defenseclaw-rescue.ps1"
POWERSHELL = shutil.which("pwsh")

FIELD_ORDER = (
    "schema",
    "channel",
    "repository",
    "target_version",
    "target_tag",
    "target_ref",
    "target_commit",
    "resolver_name",
    "resolver_url",
    "resolver_sha256",
    "posix_installer_name",
    "posix_installer_url",
    "posix_installer_sha256",
    "windows_installer_name",
    "windows_installer_url",
    "windows_installer_sha256",
)


def _source() -> str:
    return RESCUE.read_text(encoding="ascii")


def _main(source: str) -> str:
    return source.split("foreach ($unsafeName in @(", 1)[1]


def test_windows_rescue_has_one_fixed_authenticated_trust_chain() -> None:
    source = _source()

    assert source.endswith("exit $finalExitCode\n# DefenseClaw Windows rescue bootstrap complete v1\n")
    assert "Set-StrictMode -Version Latest" in source
    assert '$Repository = "cisco-ai-defense/defenseclaw"' in source
    assert ('"https://github.com/$Repository/.github/workflows/release.yaml@refs/heads/main"') in source
    assert '$SigstoreOIDCIssuer = "https://token.actions.githubusercontent.com"' in source
    assert f'$CosignVersion = "{COSIGN_BOOTSTRAP_VERSION}"' in source
    assert f'$CosignSha256 = "{COSIGN_BOOTSTRAP_SHA256[("windows", "amd64")]}"' in source
    assert ('"https://github.com/sigstore/cosign/releases/download/v$CosignVersion/$CosignAsset"') in source
    assert "--certificate-identity $ReleaseWorkflowIdentity" in source
    assert "--certificate-oidc-issuer $SigstoreOIDCIssuer" in source
    assert "--certificate-identity-regexp" not in source


def test_windows_rescue_normalizes_a_missing_installer_exit_code() -> None:
    source = _source()
    main = _main(source)

    assert "function ConvertTo-RescueExitCode {" in source
    assert "if ($null -eq $ExitCode)" in source
    assert "return 1" in source
    assert "return [int]$ExitCode" in source
    assert "$finalExitCode = ConvertTo-RescueExitCode -ExitCode $LASTEXITCODE" in main


def test_windows_rescue_cleanup_failure_preserves_authoritative_exit_code() -> None:
    main = _main(_source())
    cleanup = main[main.rindex("} finally {") :]

    assert "Remove-PrivateStageRoot -Path $stageRoot" in cleanup
    assert "Could not remove private rescue staging directory" in cleanup
    assert re.search(r"(?m)^\s*\$finalExitCode\s*=", cleanup) is None


@pytest.mark.skipif(
    POWERSHELL is None,
    reason="PowerShell 7 is unavailable on this host",
)
def test_windows_rescue_exit_code_normalizer_preserves_native_statuses(
    tmp_path: Path,
) -> None:
    assert POWERSHELL is not None
    source = _source()
    normalizer = source[
        source.index("function ConvertTo-RescueExitCode {") : source.index("function Show-RescueHelp {")
    ]
    harness = tmp_path / "exit-code-normalizer.ps1"
    harness.write_text(
        (
            "Set-StrictMode -Version Latest\n"
            '$ErrorActionPreference = "Stop"\n'
            f"{normalizer}\n"
            "$actual = @(\n"
            "    (ConvertTo-RescueExitCode -ExitCode $null),\n"
            "    (ConvertTo-RescueExitCode -ExitCode 0),\n"
            "    (ConvertTo-RescueExitCode -ExitCode 23),\n"
            "    (ConvertTo-RescueExitCode -ExitCode 255)\n"
            ")\n"
            "$expected = @(1, 0, 23, 255)\n"
            "for ($index = 0; $index -lt $expected.Count; $index++) {\n"
            "    if ($actual[$index] -ne $expected[$index]) {\n"
            "        [Console]::Error.WriteLine(\n"
            '            "exit-code mismatch at ${index}: $($actual[$index])"\n'
            "        )\n"
            "        exit 90\n"
            "    }\n"
            "}\n"
            "exit 0\n"
        ),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            POWERSHELL,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(harness),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr


def test_windows_rescue_requires_the_fixed_sixteen_field_channel_schema() -> None:
    source = _source()
    field_block = source.split("$ChannelFields = @(", 1)[1].split("\n)", 1)[0]
    fields = tuple(re.findall(r'^\s+"([a-z0-9_]+)"[,]?$', field_block, re.MULTILINE))

    assert fields == FIELD_ORDER
    assert "($lines.Length - 1) -ne $ChannelFields.Count" in source
    assert "$line.StartsWith($prefix, [StringComparison]::Ordinal)" in source
    assert "$bytes[$bytes.Length - 1] -ne 10" in source
    assert "$value -eq 0 -or $value -eq 13 -or $value -gt 127" in source
    assert "[Text.Encoding]::ASCII.GetBytes($canonical)" in source


def test_windows_rescue_pins_one_commit_before_downloading_channel_proof() -> None:
    source = _source()
    main = _main(source)

    assert ('$ChannelRefUrl = "https://api.github.com/repos/$Repository/git/ref/heads/release-channel"') in source
    assert '"refs/heads/release-channel"' in source
    assert "([string]$shaProperty.Value) -notmatch '^[0-9a-f]{40}$'" in source
    assert '$commitBase = "$ChannelRawBaseUrl/$channelCommit"' in main
    assert '"$commitBase/stable.txt"' in main
    assert '"$commitBase/stable.txt.bundle"' in main
    assert "release-channel/stable.txt" not in source
    assert main.index("$channelCommit = Get-ReleaseChannelCommit") < main.index('"$commitBase/stable.txt"')


@pytest.mark.skipif(
    POWERSHELL is None,
    reason="PowerShell 7 is unavailable on this host",
)
@pytest.mark.parametrize(
    ("payload", "diagnostic"),
    (
        ("null", "release-channel ref response must contain exactly one object"),
        (
            '{"ref":"refs/heads/release-channel"}',
            "release-channel ref response must contain exactly one object",
        ),
        (
            '{"object":{"type":"commit","sha":"' + ("a" * 40) + '"}}',
            "release-channel ref response names an unexpected ref",
        ),
        (
            '{"ref":"refs/heads/release-channel","object":{"sha":"' + ("a" * 40) + '"}}',
            "release-channel ref does not resolve to a commit",
        ),
        (
            '{"ref":"refs/heads/release-channel","object":{"type":"commit"}}',
            "release-channel ref response has an invalid commit ID",
        ),
    ),
)
def test_windows_rescue_ref_parser_routes_missing_members_through_diagnostics(
    tmp_path: Path,
    payload: str,
    diagnostic: str,
) -> None:
    assert POWERSHELL is not None
    source = _source()
    die = source[source.index("function Die {") : source.index("function Show-RescueHelp {")]
    parser = source[
        source.index("function Get-ReleaseChannelCommit {") : source.index("function Clear-UntrustedEnvironment {")
    ]
    fixture = tmp_path / "ref.json"
    fixture.write_text(payload, encoding="utf-8")
    harness = tmp_path / "ref-parser.ps1"
    harness.write_text(
        (
            "Set-StrictMode -Version Latest\n"
            '$ErrorActionPreference = "Stop"\n'
            f"{die}\n"
            f"{parser}\n"
            "try {\n"
            "    Get-ReleaseChannelCommit -Path $env:DC_TEST_RESCUE_REF_FIXTURE | Out-Null\n"
            "    exit 90\n"
            "} catch {\n"
            "    [Console]::Error.WriteLine($_.Exception.Message)\n"
            "    exit 23\n"
            "}\n"
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["DC_TEST_RESCUE_REF_FIXTURE"] = str(fixture)
    completed = subprocess.run(
        [
            POWERSHELL,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(harness),
        ],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=30,
    )

    assert completed.returncode == 23, completed
    assert f"DefenseClaw rescue failed: {diagnostic}" in completed.stderr
    assert "property" not in completed.stderr.lower()


def test_windows_rescue_authenticates_before_parsing_or_downloading_installer() -> None:
    source = _source()
    main = _main(source)

    verify = main.index("Invoke-CosignChannelVerification")
    parse = main.index("$channel = Read-CanonicalChannel")
    bind = main.index("Assert-ChannelBindings -Record $channel")
    download = main.index("-Uri $channel.windows_installer_url")
    digest = main.index("-Expected $channel.windows_installer_sha256")
    syntax = main.index("Assert-PowerShellSyntax -Path $installerLease.Path")
    execute = main.index("& $trustedPowerShellLease.Path @installerArguments")

    assert verify < parse < bind < download < digest < syntax < execute
    assert ('"https://github.com/$Repository/releases/download/$($Record.target_version)"') in source
    assert '"$releaseBase/$WindowsInstallerName"' in source
    assert "$Record.windows_installer_sha256 -notmatch '^[0-9a-f]{64}$'" in source
    assert "[Management.Automation.Language.Parser]::ParseFile(" in source


def test_windows_rescue_refuses_target_and_trust_bypasses() -> None:
    source = _source()
    main = _main(source)

    assert "[CmdletBinding(PositionalBinding = $false)]" in source
    assert "foreach ($unsafeName in @(" in source
    for parameter in ("Version", "Local", "CosignPath", "AllowUnverified", "NoPersistPath"):
        assert f'[string]${parameter} = ""' in source or f"[switch]${parameter}" in source
    assert "$PSBoundParameters.ContainsKey($unsafeName)" in main
    assert "the authenticated stable channel owns the rescue target and verifier" in source
    assert "unsupported rescue arguments" in source
    assert "DEFENSECLAW_UPGRADE_ALLOW_UNVERIFIED" in source
    assert "Clear-UntrustedEnvironment" in main
    assert '"-Version",' in main
    assert "$channel.target_version" in main
    assert '"-AllowUnverified"' not in main
    assert '"-CosignPath"' not in main
    assert '"-Local"' not in main
    assert '"-NoPersistPath"' not in main
    assert "-NoPersistPath       Forward" not in source


def test_windows_rescue_validates_connector_before_network_or_forwarding() -> None:
    source = _source()
    main = _main(source)

    assert "function Assert-SafeConnectorName {" in source
    assert '$Name.StartsWith("-", [StringComparison]::Ordinal)' in source
    assert "$Name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'" in source
    validation = main.index("Assert-SafeConnectorName -Name $Connector")
    assert validation < main.index("Assert-NativeWindowsX64")
    assert validation < main.index('"-Connector", $Connector')


@pytest.mark.skipif(
    POWERSHELL is None,
    reason="PowerShell 7 is unavailable on this host",
)
def test_windows_rescue_connector_validator_rejects_argument_shaped_values(
    tmp_path: Path,
) -> None:
    assert POWERSHELL is not None
    source = _source()
    die = source[source.index("function Die {") : source.index("function Show-RescueHelp {")]
    validator = source[
        source.index("function Assert-SafeConnectorName {") : source.index("\nforeach ($unsafeName in @(")
    ]
    harness = tmp_path / "connector-validator.ps1"
    harness.write_text(
        (
            "Set-StrictMode -Version Latest\n"
            '$ErrorActionPreference = "Stop"\n'
            f"{die}\n"
            f"{validator}\n"
            "foreach ($valid in @('', 'codex', 'Claude-Code', 'future.connector_1')) {\n"
            "    Assert-SafeConnectorName -Name $valid\n"
            "}\n"
            "foreach ($invalid in @('-Yes', 'bad value', '../codex', 'a/b', "
            "('a' * 65))) {\n"
            "    try {\n"
            "        Assert-SafeConnectorName -Name $invalid\n"
            "        exit 90\n"
            "    } catch {\n"
            "        if ($_.Exception.Message -notlike "
            "'DefenseClaw rescue failed: invalid -Connector value*') {\n"
            "            throw\n"
            "        }\n"
            "    }\n"
            "}\n"
            "exit 0\n"
        ),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            POWERSHELL,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(harness),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr


def test_windows_rescue_never_executes_remote_text_or_an_ambient_verifier() -> None:
    source = _source()

    assert "Invoke-Expression" not in source
    assert "ScriptBlock" not in source
    assert re.search(r"\b(irm|iex)\b", source, re.IGNORECASE) is None
    assert "Copy-RegularFile" in source
    assert "-Source $Candidate" in source
    assert "-Expected $CosignSha256" in source
    assert "& $Verifier verify-blob" in source
    verify = source[
        source.index("function Invoke-CosignChannelVerification {") : source.index("\nfunction Read-CanonicalChannel {")
    ]
    assert '$ErrorActionPreference = "Continue"' in verify
    assert "$ErrorActionPreference = $previousErrorActionPreference" in verify
    assert verify.index('$ErrorActionPreference = "Continue"') < verify.index("& $Verifier verify-blob")
    assert verify.index("& $Verifier verify-blob") < verify.index(
        "$ErrorActionPreference = $previousErrorActionPreference"
    )
    assert "& $ambientCosign" not in source
    assert "[IO.FileMode]::CreateNew" in source
    assert "$MaximumCosignBytes = 209715200" in source
    assert "$MaximumInstallerBytes = 4194304" in source


def test_windows_rescue_isolates_native_cosign_stderr_from_stop_preference() -> None:
    source = _source()
    verification = source[
        source.index("function Invoke-CosignChannelVerification {") : source.index("\nfunction Read-CanonicalChannel {")
    ]

    save = verification.index("$previousErrorActionPreference = $ErrorActionPreference")
    initialize_output = verification.index("$output = @()", save)
    initialize_status = verification.index("$exitCode = 1", initialize_output)
    begin_guard = verification.index("try {", initialize_status)
    continue_native = verification.index('$ErrorActionPreference = "Continue"', begin_guard)
    invoke = verification.index("& $Verifier verify-blob", continue_native)
    capture_status = verification.index("$exitCode = $LASTEXITCODE", invoke)
    restore = verification.index("$ErrorActionPreference = $previousErrorActionPreference", capture_status)
    reject = verification.index("if ($exitCode -ne 0)", restore)

    assert (
        save
        < initialize_output
        < initialize_status
        < begin_guard
        < continue_native
        < invoke
        < capture_status
        < restore
        < reject
    )
    guarded_region = verification[begin_guard:restore]
    assert "} finally {" in guarded_region
    assert "$output = @(" in guarded_region
    assert "$($output -join ' ')" in verification[reject:]


def test_windows_rescue_streaming_download_has_one_end_to_end_deadline() -> None:
    source = _source()
    download = source[
        source.index("function Invoke-SingleBoundedDownload {") : source.index("\nfunction Invoke-BoundedDownload {")
    ]

    assert "$DownloadTransferTimeoutSeconds = 300" in source
    assert "$client.Timeout = [Threading.Timeout]::InfiniteTimeSpan" in source
    assert "$transferCancellation = [Threading.CancellationTokenSource]::new()" in download
    assert "$transferCancellation.CancelAfter(" in download
    assert download.count("$transferToken") == 3
    assert "[Net.Http.HttpCompletionOption]::ResponseHeadersRead," in download
    assert "$inputStream.ReadAsync(" in download
    assert "$inputStream.Read(" not in download
    assert "$transferCancellation.Dispose()" in download


@pytest.mark.skipif(
    POWERSHELL is None,
    reason="PowerShell 7 is unavailable on this host",
)
def test_windows_rescue_stream_deadline_cancels_a_stalled_body(
    tmp_path: Path,
) -> None:
    assert POWERSHELL is not None
    source = _source()
    die = source[source.index("function Die {") : source.index("\nfunction Show-RescueHelp {")]
    regular_file = source[source.index("function Assert-RegularFile {") : source.index("\nfunction Get-Sha256Hex {")]
    download = source[
        source.index("function Invoke-SingleBoundedDownload {") : source.index("\nfunction Get-ReleaseChannelCommit {")
    ]
    destination = tmp_path / "stalled-download"
    harness = tmp_path / "stalled-download.ps1"
    harness.write_text(
        (
            "Set-StrictMode -Version Latest\n"
            '$ErrorActionPreference = "Stop"\n'
            "$DownloadTransferTimeoutSeconds = 1\n"
            f"{die}\n"
            f"{regular_file}\n"
            f"{download}\n"
            r"""
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

public sealed class DefenseClawStallingStream : Stream {
    public override bool CanRead { get { return true; } }
    public override bool CanSeek { get { return false; } }
    public override bool CanWrite { get { return false; } }
    public override long Length { get { throw new NotSupportedException(); } }
    public override long Position {
        get { throw new NotSupportedException(); }
        set { throw new NotSupportedException(); }
    }
    public override void Flush() { }
    public override int Read(byte[] buffer, int offset, int count) {
        throw new InvalidOperationException("synchronous read was used");
    }
    public override Task<int> ReadAsync(
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken
    ) {
        var completion = new TaskCompletionSource<int>();
        cancellationToken.Register(() => completion.TrySetCanceled());
        return completion.Task;
    }
    public override long Seek(long offset, SeekOrigin origin) {
        throw new NotSupportedException();
    }
    public override void SetLength(long value) {
        throw new NotSupportedException();
    }
    public override void Write(byte[] buffer, int offset, int count) {
        throw new NotSupportedException();
    }
}

public sealed class DefenseClawStallingHandler : HttpMessageHandler {
    public static int Attempts = 0;
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken
    ) {
        Interlocked.Increment(ref Attempts);
        var response = new HttpResponseMessage(HttpStatusCode.OK);
        response.RequestMessage = request;
        response.Content = new StreamContent(new DefenseClawStallingStream());
        return Task.FromResult(response);
    }
}
'@

$client = [Net.Http.HttpClient]::new(
    [DefenseClawStallingHandler]::new(),
    $true
)
$client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
$watch = [Diagnostics.Stopwatch]::StartNew()
try {
    Invoke-BoundedDownload `
        -Client $client `
        -Uri "https://fixture.invalid/stalled" `
        -Destination $env:DC_TEST_RESCUE_DOWNLOAD_FIXTURE `
        -Label "stalled fixture" `
        -MaximumBytes 1024
    exit 90
} catch {
    $watch.Stop()
    if ($watch.Elapsed.TotalSeconds -gt 7) {
        [Console]::Error.WriteLine("stream cancellation exceeded its deadline")
        exit 91
    }
    if ([IO.File]::Exists($env:DC_TEST_RESCUE_DOWNLOAD_FIXTURE)) {
        [Console]::Error.WriteLine("cancelled stream retained a partial output")
        exit 92
    }
    if ([DefenseClawStallingHandler]::Attempts -ne 3) {
        [Console]::Error.WriteLine(
            "stream cancellation attempted $([DefenseClawStallingHandler]::Attempts) transfers"
        )
        exit 93
    }
    if ($_.Exception.ToString() -notmatch "could not download") {
        [Console]::Error.WriteLine($_.Exception.ToString())
        exit 94
    }
    exit 0
} finally {
    $client.Dispose()
}
"""
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["DC_TEST_RESCUE_DOWNLOAD_FIXTURE"] = str(destination)

    completed = subprocess.run(
        [
            POWERSHELL,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(harness),
        ],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=120,
    )

    assert completed.returncode == 0, completed.stderr
    assert not destination.exists()


def test_windows_rescue_uses_private_custody_and_a_fresh_trusted_shell() -> None:
    source = _source()

    assert "$security.SetAccessRuleProtection($true, $false)" in source
    assert "$verified.AreAccessRulesProtected" in source
    assert "$verifiedOwner.Equals($identity.User)" in source
    assert "$rule.IsInherited" in source
    assert '[Security.Principal.SecurityIdentifier]::new("S-1-5-18")' in source
    assert "[IO.FileAttributes]::ReparsePoint" in source
    assert "Assert-TrustedPowerShellStable -Identity $trustedPowerShell" in source
    assert '"-NoProfile",' in source
    assert '"-NonInteractive",' in source
    assert '"-File",' in source
    assert "Remove-PrivateStageRoot -Path $stageRoot" in source


def test_windows_rescue_stages_on_a_fixed_local_os_known_folder() -> None:
    source = _source()
    ancestor = source[
        source.index("function Get-FixedLocalStageAncestor {") : source.index("\nfunction New-PrivateStageRoot {")
    ]
    create = source[
        source.index("function New-PrivateStageRoot {") : source.index("\nfunction Remove-PrivateStageRoot {")
    ]
    cleanup = source[
        source.index("function Remove-PrivateStageRoot {") : source.index("\nfunction Open-AuthenticatedFileLease {")
    ]

    assert "[Environment+SpecialFolder]::LocalApplicationData" in ancestor
    assert "[IO.DriveType]::Fixed" in ancestor
    assert "local non-UNC path" in ancestor
    assert "[IO.FileAttributes]::ReparsePoint" in ancestor
    assert "$current = $current.Parent" in ancestor
    assert "[IO.Path]::GetTempPath()" not in source
    assert "$ancestor = Get-FixedLocalStageAncestor" in create
    assert "$ancestor = Get-FixedLocalStageAncestor" in cleanup
    assert "[IO.Path]::Combine(\n        $ancestor," in create
    assert "$expectedParent.Equals(\n            $ancestor," in cleanup


def test_windows_rescue_holds_authenticated_file_leases_through_execution() -> None:
    source = _source()
    lease = source[
        source.index("function Open-AuthenticatedFileLease {") : source.index("\nfunction Copy-RegularFile {")
    ]
    main = _main(source)

    assert "[IO.FileShare]::Read" in lease
    assert "$sha256.ComputeHash($stream)" in lease
    assert "$stream.Position = 0" in lease
    assert "return [pscustomobject]@{" in lease
    assert "Stream = $stream" in lease

    resolve_cosign = main.index("$cosign = Resolve-AuthenticatedCosign")
    lease_cosign = main.index("$cosignLease = Open-AuthenticatedFileLease")
    lease_ref = main.index("$refLease = Open-AuthenticatedFileLease")
    read_ref = main.index("$channelCommit = Get-ReleaseChannelCommit -Path $refLease.Path")
    lease_channel = main.index("$candidateChannelLease = Open-AuthenticatedFileLease")
    lease_bundle = main.index("$candidateBundleLease = Open-AuthenticatedFileLease")
    verify = main.index("Invoke-CosignChannelVerification")
    channel_path = main.index("$channelPath = $channelLease.Path")
    parse_channel = main.index("$channel = Read-CanonicalChannel -Path $channelPath")
    installer_digest = main.index("-Expected $channel.windows_installer_sha256")
    lease_installer = main.index("$installerLease = Open-AuthenticatedFileLease")
    syntax = main.index("Assert-PowerShellSyntax -Path $installerLease.Path")
    lease_shell = main.index("$trustedPowerShellLease = Open-AuthenticatedFileLease")
    execute = main.index("& $trustedPowerShellLease.Path @installerArguments")

    assert resolve_cosign < lease_cosign < lease_ref < read_ref
    assert lease_channel < lease_bundle < verify < channel_path < parse_channel
    assert installer_digest < lease_installer < syntax < lease_shell < execute
    verification = main[verify:channel_path]
    assert "-Verifier $cosignLease.Path" in verification
    assert "-ChannelPath $candidateChannelLease.Path" in verification
    assert "-BundlePath $candidateBundleLease.Path" in verification
    assert "$installerLease.Path" in main[lease_installer:execute]

    final_cleanup = main[main.rindex("} finally {") :]
    dispose = final_cleanup.index("$lease.Stream.Dispose()")
    remove = final_cleanup.index("Remove-PrivateStageRoot -Path $stageRoot")
    assert dispose < remove
    for name in (
        "$installerLease",
        "$channelBundleLease",
        "$channelLease",
        "$cosignLease",
        "$trustedPowerShellLease",
    ):
        assert name in final_cleanup


def test_windows_rescue_preserves_acl_hardening_failure_when_cleanup_fails() -> None:
    source = _source()
    private_root = source[
        source.index("function New-PrivateStageRoot {") : source.index("\nfunction Remove-PrivateStageRoot {")
    ]

    capture = private_root.index("$hardeningException = $_.Exception")
    cleanup = private_root.index("[IO.Directory]::Delete($root, $true)", capture)
    rethrow = private_root.index("throw $hardeningException", cleanup)
    assert capture < cleanup < rethrow
    assert "Cleanup is best effort" in private_root
    assert private_root.count("catch {") == 2


@pytest.mark.skipif(
    POWERSHELL is None,
    reason="PowerShell 7 parser is unavailable on this host",
)
def test_windows_rescue_parses_as_powershell() -> None:
    assert POWERSHELL is not None
    env = os.environ.copy()
    env["DC_TEST_RESCUE_PARSE_FILE"] = str(RESCUE)
    completed = subprocess.run(
        [
            POWERSHELL,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                "$tokens = $null; $errors = $null; "
                "[Management.Automation.Language.Parser]::ParseFile("
                "$env:DC_TEST_RESCUE_PARSE_FILE, [ref]$tokens, [ref]$errors"
                ") | Out-Null; "
                "if (@($errors).Count -ne 0) { "
                "  [Console]::Error.WriteLine(($errors -join '; ')); exit 1 "
                "}"
            ),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        env=env,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.skipif(
    POWERSHELL is None,
    reason="PowerShell 7 is unavailable on this host",
)
def test_windows_rescue_help_is_network_free_and_unsafe_override_is_refused() -> None:
    assert POWERSHELL is not None
    source = _source()
    main = _main(source)
    help_guard = main.index("if ($Help) {")
    before_help = main[:help_guard]
    for network_operation in (
        "New-HttpClient",
        "Resolve-AuthenticatedCosign",
        "Invoke-BoundedDownload",
        "Get-ReleaseChannelCommit",
        "Invoke-CosignChannelVerification",
    ):
        assert network_operation not in before_help
        assert help_guard < main.index(network_operation)

    prefix = [
        POWERSHELL,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(RESCUE),
    ]
    help_result = subprocess.run(
        [*prefix, "-Help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    assert help_result.returncode == 0, help_result.stderr
    assert "DefenseClaw authenticated Windows rescue" in help_result.stdout

    assert "-NoPersistPath" not in help_result.stdout

    main = _main(source)
    unsafe_refusal = main.index("$PSBoundParameters.ContainsKey($unsafeName)")
    assert unsafe_refusal < main.index("Assert-NativeWindowsX64")
    for unsafe_arguments in (
        ("-Version", "9.9.9"),
        ("-NoPersistPath",),
    ):
        override_result = subprocess.run(
            [*prefix, *unsafe_arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
        assert override_result.returncode != 0
        assert "the authenticated stable channel owns the rescue target" in " ".join(override_result.stderr.split())
