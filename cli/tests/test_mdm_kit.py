# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Contracts for the MDM deployment kit (packaging/mdm).

Each script ships as a standalone file an MDM uploads on its own, so shared
helpers are copied rather than sourced; these checks keep the copies
identical, keep the Windows Intune-facing scripts runnable in Windows
PowerShell 5.1, keep every result on the lifecycle-result schema, and check the
optional release signing helpers.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MDM = ROOT / "packaging" / "mdm"
SCHEMA = MDM / "contract" / "lifecycle-result.schema.json"
UNIX_SCRIPTS = ("defenseclaw-enterprise.sh", "detect.sh", "uninstall.sh")
WINDOWS_SHARED = (
    MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1",
    MDM / "windows" / "detect.ps1",
    MDM / "windows" / "uninstall.ps1",
    MDM / "intune" / "windows" / "Install-DefenseClawIntune.ps1",
    MDM / "intune" / "windows" / "Remediate-Detect.ps1",
    MDM / "intune" / "windows" / "Remediate-Fix.ps1",
)
# Scripts Intune runs inside its 32-bit Windows PowerShell 5.1 host.
WINDOWS_51 = [path for path in WINDOWS_SHARED if path.name != "Invoke-DefenseClawEnterprise.ps1"]
SHARED_BEGIN = "# region DefenseClaw MDM shared helpers"
SHARED_END = "# endregion DefenseClaw MDM shared helpers"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _shell_function(text: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}$", text, re.MULTILINE | re.DOTALL)
    if not match:
        match = re.search(rf"^{re.escape(name)}\(\) \{{[^\n]*\}}$", text, re.MULTILINE)
    assert match, f"{name} not found"
    return match.group(0)


def _schema_validator():
    jsonschema = pytest.importorskip("jsonschema")
    return jsonschema.Draft202012Validator(json.loads(_text(SCHEMA)))


def test_every_mdm_script_is_ascii() -> None:
    # Windows PowerShell 5.1 reads BOM-less files as the ANSI code page, and
    # MDM consoles show uploaded scripts; ASCII avoids both problems.
    for path in sorted(MDM.rglob("*")):
        if path.suffix in {".sh", ".ps1"}:
            data = path.read_bytes()
            assert all(byte < 0x80 for byte in data), f"{path.relative_to(ROOT)} has non-ASCII bytes"
            assert b"\r\n" not in data, f"{path.relative_to(ROOT)} has CRLF line endings"


def _shared_region(text: str) -> str:
    start = text.index(SHARED_BEGIN)
    end = text.index(SHARED_END) + len(SHARED_END)
    return text[start:end]


def test_copied_helpers_are_identical() -> None:
    for name in UNIX_SCRIPTS:
        linux = _text(MDM / "linux" / name).splitlines()
        macos = _text(MDM / "macos" / name).splitlines()
        assert len(linux) == len(macos), name
        assert [(a, b) for a, b in zip(linux, macos) if a != b] == [(
            "DC_SCRIPT_OS=linux # linux | darwin - the only line that differs between the copies",
            "DC_SCRIPT_OS=darwin # linux | darwin - the only line that differs between the copies",
        )], name
    scripts = {name: _text(MDM / "linux" / name) for name in UNIX_SCRIPTS}
    for function in ("dc_platform", "dc_stat_uid", "dc_stat_mode", "dc_acl_write_entry", "dc_trusted_path"):
        assert len({_shell_function(text, function) for text in scripts.values()}) == 1, function
    for function in ("dc_json_escape", "dc_log", "dc_busy_output"):
        wrapper = _shell_function(scripts["defenseclaw-enterprise.sh"], function)
        assert wrapper == _shell_function(scripts["uninstall.sh"], function), function
    canonical = _shared_region(_text(MDM / "windows" / "detect.ps1"))
    drifted = [path.name for path in WINDOWS_SHARED if _shared_region(_text(path)) != canonical]
    assert not drifted, f"copy the shared region from packaging/mdm/windows/detect.ps1 into {drifted}"


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_macos_trusted_path_refuses_write_acl_entries(tmp_path: Path) -> None:
    # GAP-1322: a root-owned 0600 --config-file with an ACL entry that lets a
    # standard user write it passed the owner and mode check and was staged.
    wrapper = _text(MDM / "macos" / "defenseclaw-enterprise.sh")
    functions = "\n".join(_shell_function(wrapper, name) for name in ("dc_acl_write_entry", "dc_trusted_path"))
    target = tmp_path / "config.yaml"
    target.write_text("guardrail: {}\n", encoding="utf-8")

    def trusted(os_name: str, entry: str) -> tuple[bool, str]:
        # ls -lde prints the path line, then one indented line per ACL entry.
        script = (
            f"DC_SCRIPT_OS={os_name}\n"
            "dc_stat_uid() { echo 0; }\n"
            "dc_stat_mode() { echo 600; }\n"
            f"ls() {{ printf '%s\\n' \"-rw-------+ 1 root wheel 1 Oct 10 00:00 $3\"; "
            f"[ \"$3\" != '{target}' ] || printf '%s\\n' '{entry}'; }}\n"
            f"{functions}\n"
            f"if dc_trusted_path '{target}'; then echo trusted; fi; printf '%s' \"$DC_TRUST_ACL\""
        )
        result = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        return result.stdout.startswith("trusted"), result.stdout

    write = " 0: user:dcuser inherited allow write,append"
    ok, note = trusted("darwin", write)
    assert not ok
    assert "user:dcuser inherited allow write,append" in note and f"chmod -N {target}" in note
    for entry in ("", " 0: group:admin allow write", " 0: user:dcuser deny write", " 0: user:dcuser allow read"):
        assert trusted("darwin", entry)[0], entry
    assert trusted("linux", write)[0]


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_missing_staging_folder_returns_structured_refusal(tmp_path: Path) -> None:
    for platform in ("linux", "macos"):
        wrapper = _text(MDM / platform / "defenseclaw-enterprise.sh")
        stage = tmp_path / "missing"
        functions = "\n".join(_shell_function(wrapper, name) for name in ("dc_stage_parent",))
        script = (
            "set -u\nDC_EXIT_FAILURE=1\n"
            f"DC_SCRIPT_OS={platform}\nDC_STAGING_DIR='{stage}'\n"
            "dc_trusted_path() { return 1; }\n"
            "dc_fail_result() { printf '%s|%s|%s' \"$1\" \"$2\" \"$3\"; }\n"
            f"{functions}\ndc_stage_parent\n"
        )
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert "mdm_staging_untrusted" in result.stdout
        assert "missing" in result.stdout

def test_intune_entrypoints_refuse_constrained_language_before_native_helpers() -> None:
    entrypoints = {
        MDM / "intune" / "windows" / "Install-DefenseClawIntune.ps1": "1603",
        MDM / "windows" / "detect.ps1": "1",
        MDM / "intune" / "windows" / "Remediate-Detect.ps1": "1",
    }
    for path, exit_code in entrypoints.items():
        entry = _text(path).split("# region DefenseClaw MDM shared helpers", 1)[0]
        guard = "if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {"
        assert guard in entry, path
        assert entry.index(guard) < entry.index("Set-StrictMode"), path
        assert f"exit {exit_code}" in entry.split(guard, 1)[1], path


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("os_dir", ["linux", "macos"])
@pytest.mark.parametrize("name", UNIX_SCRIPTS)
def test_unix_scripts_parse_and_lint(os_dir: str, name: str) -> None:
    path = MDM / os_dir / name
    assert os.access(path, os.X_OK), f"{path} must be executable"
    assert _text(path).startswith("#!/bin/sh\n")
    for shell in ("sh", "dash", "bash"):
        if shutil.which(shell):
            subprocess.run([shell, "-n", str(path)], check=True)
    if shutil.which("shellcheck"):
        subprocess.run(["shellcheck", "-s", "sh", "-S", "warning", str(path)], check=True)


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("os_dir", ["linux", "macos"])
def test_same_version_package_reinstalls_when_a_required_binary_is_damaged(tmp_path: Path, os_dir: str) -> None:
    wrapper = _text(MDM / os_dir / "defenseclaw-enterprise.sh")
    helpers = ["dc_is_sha256", "dc_sha256"]
    if "dc_recorded_binary_sha256()" in wrapper:
        helpers.append("dc_recorded_binary_sha256")
    helpers.append("dc_binaries_damaged")
    functions = "\n".join(_shell_function(wrapper, name) for name in helpers)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    names = ("defenseclaw-gateway", "defenseclaw-hook", "defenseclaw-sensor-helper")
    for name in names:
        path = bin_dir / name
        path.write_bytes(b"binary")
        path.chmod(0o755)
    record = tmp_path / "deployment.json"
    record.write_text(json.dumps({
        "files": {str(bin_dir / name): hashlib.sha256(b"binary").hexdigest() for name in names}
    }, indent=2), encoding="utf-8")

    def damaged() -> bool:
        script = (
            f"DC_SCRIPT_OS={'darwin' if os_dir == 'macos' else 'linux'}\n"
            f"DC_GATEWAY='{bin_dir / 'defenseclaw-gateway'}'\n"
            f"DC_DEPLOYMENT_RECORD='{record}'\n"
            f"{functions}\ndc_binaries_damaged"
        )
        result = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=10)
        assert result.returncode in (0, 1), result.stderr
        return result.returncode == 0

    assert not damaged(), os_dir
    hook = bin_dir / "defenseclaw-hook"
    for contents, mode in ((b"replaced", 0o755), (b"binary", 0o644), (b"", 0o755)):
        hook.write_bytes(contents)
        hook.chmod(mode)
        assert damaged(), (os_dir, contents, mode)
    for name in names:
        path = bin_dir / name
        path.write_bytes(b"")
        path.chmod(0o755)
        assert damaged(), (os_dir, name, "empty")
        path.unlink()
        assert damaged(), (os_dir, name, "missing")
        path.write_bytes(b"binary")
        path.chmod(0o755)


def test_unix_wrapper_never_passes_credentials_on_the_command_line() -> None:
    text = _text(MDM / "linux" / "defenseclaw-enterprise.sh")
    assert 'enterprise secret set --name "$DC_SECRET_NAME" --from-stdin --lock-wait 10m --json "$@" >' in text
    # The value reaches the lifecycle through a pipe, never a staged file
    # that a killed run would leave behind (GAP-0632).
    assert "printf '%s' \"$secret_data\" |" in text
    assert '$DC_STAGE/secret"' not in text
    assert "--from-file" not in text
    # The inline-config block warns against credentials and there is no
    # inline-secret setting.
    assert "DC_SECRET_VALUE" not in text
    assert "Never put credentials here" in text


# GAP-0335: a signed bundle binds each credential value, and secret set
# changes a credential the confirmed bundle signs only to a value a newer
# signed bundle signs. The wrapper stores a credential it delivers with a
# bundle together with that bundle (--bundle), and without one as before. A
# gateway before 1.0.4 (no secret_set_bundle in --version-json) takes no
# --bundle and stores the credential as before.
@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("os_dir", ["linux", "macos"])
@pytest.mark.parametrize("bundle", ["", "/stage/policy.dcbundle"])
@pytest.mark.parametrize("binds", [True, False])
def test_unix_wrapper_stores_a_credential_with_the_bundle_it_delivers(tmp_path: Path, os_dir: str, bundle: str, binds: bool) -> None:
    wrapper = _text(MDM / os_dir / "defenseclaw-enterprise.sh")
    functions = "\n".join(_shell_function(wrapper, name) for name in (
        "dc_json_escape", "dc_print_result", "dc_log", "dc_fail_result",
        "dc_secret_json_error", "dc_secret_set_bundle", "dc_store_secret",
    ))
    log = tmp_path / "calls.log"
    gateway = tmp_path / "gateway"
    member = ',"secret_set_bundle":true' if binds else ""
    version = '{"schema_version":1,"name":"defenseclaw-gateway","version":"1.0.x","management_contract":1' + member + "}"
    gateway.write_text(
        "#!/bin/sh\n"
        f"if [ \"$1\" = --version-json ]; then echo '{version}'; exit 0; fi\n"
        f"cat >/dev/null\necho \"$*\" >>'{log}'\necho '{{\"ok\":true}}'\n",
        encoding="utf-8",
    )
    gateway.chmod(0o755)
    script = (
        f'DC_ACTION=ensure DC_SCRIPT_OS={"darwin" if os_dir == "macos" else "linux"}\n'
        f'DC_STAGE="{tmp_path}" DC_LOG="" DC_FORMAT=json DC_EXIT_FAILURE=1\n'
        f"DC_SECRET_NAME=test-key secret_data=placeholder bundle='{bundle}'\n"
        f'{functions}\ndc_store_secret "{gateway}"\n'
    )
    result = subprocess.run(["sh", "-c", script], env={"PATH": os.environ["PATH"]}, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    want = "enterprise secret set --name test-key --from-stdin --lock-wait 10m --json"
    if bundle and binds:
        want += f" --bundle {bundle}"
    assert log.read_text(encoding="utf-8").splitlines() == [want]


def test_windows_wrapper_stores_a_bundled_credential_before_the_apply() -> None:
    text = _text(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1")
    first = text.index("Set-WrapperSecret -Extra @('--bundle', $bundle)")
    guard = text.rindex("if ($secret -and $bundle -and -not $SetupPath", 0, first)
    # Only a CLI that reports secret_set_bundle (1.0.4 and later) gets --bundle.
    probe = text.rindex("(Test-WrapperSecretSetBundle -Cli $installedDeployment.Cli)", guard, first)
    assert "$document.secret_set_bundle -eq $true" in text
    lifecycle = text.index("$arguments = @('enterprise', 'windows', $normalizedAction")
    after = text.index("if ($exitCode -eq 0 -and $secret -and -not $secretStored)")
    assert guard < probe < first < lifecycle < after


# Loop round 2 review (Windows consolidation): the wrapper stores a credential
# a new bundle signs (secret set --bundle, which restarts the gateway) before
# the lifecycle applies that bundle. When the lifecycle failed, or the run
# stopped first, the old bundle stayed confirmed with the new credential, so
# its signed value no longer matched. The release branch stored the
# credential only after a successful lifecycle. The wrapper now journals the
# stored value first and puts it back unless the lifecycle succeeded: after a
# failure, after a launch failure, and at the start of the next ensure after
# an interrupted run. The CLI decides each put-back (it stores only a value
# the confirmed bundle signs), so a bundle confirmed after all keeps its
# value. The fake CLI below has the CLI's rules.
_ROTATION_PROBE = r"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
$script:LogPath = $null
$script:root = '__ROOT__'
$SecretName = 'ai-defense-api-key'
$secret = Join-Path $script:root 'staged-secret'
$bundle = Join-Path $script:root 'policy.dcbundle'
$script:DefenseClawAdminSids = @()
function Get-WrapperProgramData { return (Join-Path $script:root 'ProgramData') }
# The ACL reads the journal checks rely on: a link, or a path listed in
# $script:untrusted, is not administrator-only; folders get no descriptor.
$script:untrusted = @()
function Test-DefenseClawAdminOnlyItem {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
    return ($script:untrusted -notcontains [System.IO.Path]::GetFullPath($Path))
}
function Test-WrapperAdminOnlyAncestors { param([string]$Path) return $true }
function New-WrapperAdminOnlyDirectory { param([string]$Path) [void][System.IO.Directory]::CreateDirectory($Path) }
function Get-DefenseClawInstalledDeployment { return [pscustomobject]@{ Cli = 'defenseclaw.exe' } }
function Write-WrapperLog { param([string]$Message) }

# The fake CLI: the confirmed bundle signs $script:confirmed (a value, or
# $null for "references no credential"), the delivered bundle signs
# $script:delivered, and the installed config uses the credential when
# $script:inUse is set.
$script:calls = @()
$script:failNext = ''
function Invoke-DefenseClawNative {
    param([string]$FilePath, [string[]]$ArgumentList = @(), [string]$StandardInputPath = '', [int]$TimeoutSeconds = 0)
    $line = $ArgumentList -join ' '
    $script:calls += $line
    $stored = Get-WrapperStoredSecretPath -Name $SecretName
    $refuse = { param($code) [pscustomobject]@{ ExitCode = 1603; StdErr = ''; StdOut = (@{ schema_version = 1; errors = @(@{ code = $code; message = $code }) } | ConvertTo-Json -Compress -Depth 4) } }
    if ($script:failNext) { $code = $script:failNext; $script:failNext = ''; return (& $refuse $code) }
    if ($ArgumentList[2] -eq 'set') {
        $value = [System.IO.File]::ReadAllText($StandardInputPath)
        $current = if (Test-Path -LiteralPath $stored) { [System.IO.File]::ReadAllText($stored) } else { $null }
        if ($value -ne $current) {
            $signed = $null -eq $script:confirmed -or $value -eq $script:confirmed
            if (-not $signed -and $ArgumentList -contains '--bundle') { $signed = $value -eq $script:delivered }
            if (-not $signed) { return (& $refuse 'secret_ref_mismatch') }
            [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $stored))
            [System.IO.File]::WriteAllText($stored, $value)
        }
        return [pscustomobject]@{ ExitCode = 0; StdErr = ''; StdOut = '{"ok":true}' }
    }
    if ($ArgumentList[2] -eq 'remove') {
        if ($script:inUse) { return (& $refuse 'credential_in_use') }
        Remove-Item -LiteralPath $stored -Force -ErrorAction SilentlyContinue
        return [pscustomobject]@{ ExitCode = 0; StdErr = ''; StdOut = '{"ok":true}' }
    }
    throw "unexpected call $line"
}

__FUNCTIONS__

function Reset-Device($Stored) {
    Remove-Item -LiteralPath (Join-Path $script:root 'ProgramData') -Recurse -Force -ErrorAction SilentlyContinue
    $script:untrusted = @()
    if ($null -ne $Stored) {
        $path = Get-WrapperStoredSecretPath -Name $SecretName
        [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $path))
        [System.IO.File]::WriteAllText($path, $Stored)
    }
    [System.IO.File]::WriteAllText($secret, 'new-key')
    $script:calls = @()
}
function Get-Stored {
    $path = Get-WrapperStoredSecretPath -Name $SecretName
    if (Test-Path -LiteralPath $path) { return [System.IO.File]::ReadAllText($path) }
    return '<none>'
}
function Get-Journal { return @(Get-ChildItem -LiteralPath (Get-WrapperRotationJournal) -Force -File -ErrorAction SilentlyContinue).Count }
# Rotate is the wrapper's step before the lifecycle; it returns the failure.
function Rotate {
    Save-WrapperSecretJournal -Name $SecretName
    return (Set-WrapperSecret -Extra @('--bundle', $bundle))
}
$out = [ordered]@{}

# 1. The lifecycle fails: the old value goes back, the journal goes.
Reset-Device 'old-key'; $script:confirmed = 'old-key'; $script:delivered = 'new-key'; $script:inUse = $true
$failure = Rotate
$out.rotated = "$($null -eq $failure) $(Get-Stored)"
Undo-WrapperSecretRotation -Cli 'defenseclaw.exe'
$out.failed = "$(Get-Stored) $(Get-Journal)"

# 2. The lifecycle succeeds: the new value stays, the journal goes, no put-back.
Reset-Device 'old-key'; $script:confirmed = 'old-key'
[void](Rotate)
$script:confirmed = 'new-key'
[void](Complete-WrapperSecretJournal -Name $SecretName)
$out.succeeded = "$(Get-Stored) $(Get-Journal) $(@($script:calls).Count)"

# 3. The run stops after the rotation: the next ensure puts the old value back.
Reset-Device 'old-key'; $script:confirmed = 'old-key'
[void](Rotate)
$problems = @(Complete-WrapperSecretJournal -Cli 'defenseclaw.exe' -Restore)
$out.interrupted = "$(Get-Stored) $(Get-Journal) $($problems.Count)"

# 4. The run stops after the lifecycle confirmed the new bundle: the CLI
#    refuses the old value, which the confirmed bundle no longer signs.
Reset-Device 'old-key'; $script:confirmed = 'old-key'
[void](Rotate)
$script:confirmed = 'new-key'
$problems = @(Complete-WrapperSecretJournal -Cli 'defenseclaw.exe' -Restore)
$out.confirmed = "$(Get-Stored) $(Get-Journal) $($problems.Count)"

# 5. No credential was stored and the old config does not use it: a failed
#    lifecycle removes it again.
Reset-Device $null; $script:confirmed = $null; $script:inUse = $false
[void](Rotate)
$out.absentRotated = Get-Stored
Undo-WrapperSecretRotation -Cli 'defenseclaw.exe'
$out.absentFailed = "$(Get-Stored) $(Get-Journal)"

# 6. ... and once the new config uses it, the next ensure keeps it.
Reset-Device $null; $script:confirmed = $null; $script:inUse = $false
[void](Rotate)
$script:inUse = $true
[void](Complete-WrapperSecretJournal -Cli 'defenseclaw.exe' -Restore)
$out.absentConfirmed = "$(Get-Stored) $(Get-Journal)"

# 7. A put-back the CLI cannot do now stays journaled, and the next ensure
#    finishes it.
Reset-Device 'old-key'; $script:confirmed = 'old-key'; $script:inUse = $true
[void](Rotate)
$script:failNext = 'lifecycle_busy'
$problems = @(Complete-WrapperSecretJournal -Cli 'defenseclaw.exe' -Restore)
$out.busy = "$(Get-Stored) $(Get-Journal) $($problems.Count)"
$problems = @(Complete-WrapperSecretJournal -Cli 'defenseclaw.exe' -Restore)
$out.busyRetried = "$(Get-Stored) $(Get-Journal) $($problems.Count)"

# 8. A second rotation before the first settled keeps the first journal
#    entry: it holds the value the confirmed bundle signs.
Reset-Device 'old-key'; $script:confirmed = 'old-key'
[void](Rotate)
[System.IO.File]::WriteAllText($secret, 'newer-key'); $script:delivered = 'newer-key'
[void](Rotate)
Undo-WrapperSecretRotation -Cli 'defenseclaw.exe'
$out.twice = "$(Get-Stored) $(Get-Journal)"
$script:delivered = 'new-key'

# 9. The CLI refuses the rotation itself: nothing changed, nothing is put back.
Reset-Device 'old-key'; $script:confirmed = 'old-key'; $script:delivered = 'other-key'
$failure = Rotate
[void](Complete-WrapperSecretJournal -Name $SecretName)
$out.refused = "$($failure.Code) $(Get-Stored) $(Get-Journal) $(@($script:calls).Count)"

# 10. Nothing is installed any more: the journal goes with nothing put back.
Reset-Device 'old-key'; $script:confirmed = 'old-key'; $script:delivered = 'new-key'
[void](Rotate)
$script:calls = @()
[void](Complete-WrapperSecretJournal -Cli '' -Restore)
$out.uninstalled = "$(Get-Journal) $(@($script:calls).Count)"

# Loop round 1 (rc.7). 11. A put-back refused secret_ref_unbound (the
#     confirmed bundle signs only the name) proves nothing: it stays
#     journaled and is reported.
Reset-Device 'old-key'; $script:confirmed = 'old-key'; $script:delivered = 'new-key'; $script:inUse = $true
[void](Rotate)
$script:failNext = 'secret_ref_unbound'
$problems = @(Complete-WrapperSecretJournal -Cli 'defenseclaw.exe' -Restore)
$out.unbound = "$(Get-Stored) $(Get-Journal) $($problems.Count)"

# 12. An entry another account planted (a config-only device, so nothing
#     binds the credential): with the journal folder, the folder above it or
#     the entry not administrator-only, the entry is never read, put back or
#     removed, and no rotation journals beside it.
foreach ($case in @('folder', 'parent', 'entry')) {
    Reset-Device 'old-key'; $script:confirmed = $null; $script:inUse = $true
    $journal = Get-WrapperRotationJournal
    [void][System.IO.Directory]::CreateDirectory($journal)
    $planted = Join-Path $journal $SecretName
    [System.IO.File]::WriteAllText($planted, 'attacker-key')
    $script:untrusted = @(switch ($case) {
        'folder' { [System.IO.Path]::GetFullPath($journal) }
        'parent' { [System.IO.Path]::GetFullPath((Split-Path -Parent $journal)) }
        'entry' { [System.IO.Path]::GetFullPath($planted) }
    })
    $problems = @(Complete-WrapperSecretJournal -Cli 'defenseclaw.exe' -Restore)
    $journaled = try { Save-WrapperSecretJournal -Name $SecretName; 'journaled' } catch { 'refused' }
    $out["untrusted_$case"] = "$(Get-Stored) $([System.IO.File]::ReadAllText($planted)) $(@($script:calls).Count) $($problems.Count) $journaled"
}

# 13. A folder where an entry belongs is not an entry either.
Reset-Device 'old-key'; $script:confirmed = $null
$planted = Join-Path (Get-WrapperRotationJournal) $SecretName
[void][System.IO.Directory]::CreateDirectory($planted)
$problems = @(Complete-WrapperSecretJournal -Cli 'defenseclaw.exe' -Restore)
$journaled = try { Save-WrapperSecretJournal -Name $SecretName; 'journaled' } catch { 'refused' }
$out.folderEntry = "$(Get-Stored) $(Test-Path -LiteralPath $planted -PathType Container) $(@($script:calls).Count) $($problems.Count) $journaled"

# 14. Nor is a link to a file elsewhere (where this account can make one).
Reset-Device 'old-key'; $script:confirmed = $null
$journal = Get-WrapperRotationJournal
[void][System.IO.Directory]::CreateDirectory($journal)
$target = Join-Path $script:root 'attacker-file'
[System.IO.File]::WriteAllText($target, 'attacker-key')
$linked = try { [void](New-Item -ItemType SymbolicLink -Path (Join-Path $journal $SecretName) -Target $target -ErrorAction Stop); $true } catch { $false }
$problems = @(Complete-WrapperSecretJournal -Cli 'defenseclaw.exe' -Restore)
$out.linkEntry = "$linked $(Get-Stored) $([System.IO.File]::ReadAllText($target)) $(@($script:calls).Count) $($problems.Count) $(Test-Path -LiteralPath (Join-Path $journal $SecretName))"
$out | ConvertTo-Json -Compress
"""


def _any_pwsh7() -> str | None:
    # PowerShell 7 on Windows, or pwsh on Linux and macOS: the probes use no
    # Windows-only API.
    candidates = [shutil.which("pwsh.exe"), shutil.which("pwsh")]
    program_files = os.environ.get("ProgramFiles")
    if program_files:
        candidates.append(str(Path(program_files) / "PowerShell" / "7" / "pwsh.exe"))
    return next((c for c in candidates if c and Path(c).is_file()), None)


_ROTATION_FUNCTIONS = ("Get-WrapperSecretErrorCode", "Set-WrapperSecret", "Get-WrapperRotationJournal",
                       "Get-WrapperStoredSecretPath", "Initialize-WrapperRotationJournal", "Test-WrapperJournalEntry",
                       "Save-WrapperSecretJournal", "Remove-WrapperJournalEntry", "Complete-WrapperSecretJournal",
                       "Undo-WrapperSecretRotation")


def _rotation_functions(*names: str) -> str:
    text = _text(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1")
    functions = []
    for name in names:
        start = text.index(f"function {name} {{")
        functions.append(text[start : text.index("\n}\n", start) + 3])
    return "\n".join(functions)


@pytest.mark.skipif(_any_pwsh7() is None and os.name != "nt", reason="needs PowerShell 7")
def test_windows_wrapper_puts_back_a_rotated_credential_unless_the_lifecycle_confirms_it(tmp_path: Path) -> None:
    engine = _any_pwsh7()
    assert engine, "Windows CI must provide PowerShell 7"
    probe = tmp_path / "rotation-probe.ps1"
    probe.write_text(
        _ROTATION_PROBE.replace("__ROOT__", str(tmp_path).replace("'", "''"))
        .replace("__FUNCTIONS__", _rotation_functions(*_ROTATION_FUNCTIONS)),
        encoding="utf-8",
    )
    result = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(probe)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = json.loads(result.stdout.strip().splitlines()[-1])
    assert out == {
        "rotated": "True new-key",
        "failed": "old-key 0",
        "succeeded": "new-key 0 1",
        "interrupted": "old-key 0 0",
        "confirmed": "new-key 0 0",
        "absentRotated": "new-key",
        "absentFailed": "<none> 0",
        "absentConfirmed": "new-key 0",
        "busy": "new-key 1 1",
        "busyRetried": "old-key 0 0",
        "twice": "old-key 0",
        "refused": "secret_ref_mismatch old-key 0 1",
        "uninstalled": "0 0",
        "unbound": "new-key 1 1",
        "untrusted_folder": "old-key attacker-key 0 1 refused",
        "untrusted_parent": "old-key attacker-key 0 1 refused",
        "untrusted_entry": "old-key attacker-key 0 1 refused",
        "folderEntry": "old-key True 0 1 refused",
        "linkEntry": out["linkEntry"],
    }, out
    # Where this account can make a link, it is refused and left in place.
    linked = "True old-key attacker-key 0 1 True"
    assert out["linkEntry"] in (linked, "False old-key attacker-key 0 0 False"), out
    assert os.name == "nt" or out["linkEntry"] == linked, out


def test_windows_wrapper_settles_the_credential_journal_around_the_lifecycle() -> None:
    # The order the probe above relies on: an earlier run's journal is
    # settled before anything changes, the stored value is journaled before
    # the rotation, and the lifecycle's outcome settles it (launch failure,
    # failure, success).
    text = _text(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1")
    main = text[text.index("$staging = New-WrapperStaging"):]
    resume = main.index("if ($normalizedAction -eq 'ensure') { Resume-WrapperSecretJournal }")
    lock = main.index("[void](Enter-WrapperRotationLock -Create)", resume)
    journal = main.index("Save-WrapperSecretJournal -Name $SecretName", lock)
    rotate = main.index("$failure = Set-WrapperSecret -Extra @('--bundle', $bundle)")
    armed = main.index("$script:RotationCli = $installedDeployment.Cli")
    lifecycle = main.index("$arguments = @('enterprise', 'windows', $normalizedAction")
    disarmed = main.index("$script:RotationCli = ''", lifecycle)
    settle = main.index("[void](Complete-WrapperSecretJournal -Name $SecretName)", disarmed)
    undo = main.index("Undo-WrapperSecretRotation -Cli $installedDeployment.Cli", settle)
    assert resume < lock < journal < rotate < armed < lifecycle < disarmed < settle < undo
    body = main[main.index("function Resume-WrapperSecretJournal {"):]
    body = body[: body.index("\n}\n")]
    assert body.index("Enter-WrapperRotationLock") < body.index("Complete-WrapperSecretJournal -Cli $cli -Restore")


# Continuation 2, loop round 1 (Windows consolidation, GAP-1095): the
# credential rotation is part of the bundle apply's transaction. Windows: an
# exit between the rotation and the settle (mdm_not_installed after the
# rotation, a lifecycle with no result, a launch failure) went through
# Exit-Wrapper, which did not put the old value back, so that failed ensure
# left the new value with the old bundle until the next ensure.
_EXIT_PROBE_TAIL = r"""
function ConvertTo-DefenseClawResultJson { param($Action, $ExitCode, $Code, $Message) return "{""code"":""$Code""}" }
function Remove-WrapperStaging { }
$script:ResultAction = 'ensure'
$script:RotationCli = ''
Reset-Device 'old-key'; $script:confirmed = 'old-key'; $script:delivered = 'new-key'; $script:inUse = $true
[void](Rotate)
[Console]::Error.WriteLine("ROTATED=$(Get-Stored)")
if ('__CASE__' -eq 'armed') { $script:RotationCli = 'defenseclaw.exe' }
if ('__CASE__' -eq 'settled') { $script:RotationCli = ''; $script:confirmed = 'new-key'; [void](Complete-WrapperSecretJournal -Name $SecretName) }
Exit-Wrapper 1603 'mdm_not_installed' 'the deployment is not installed'
"""



@pytest.mark.skipif(_any_pwsh7() is None, reason="needs PowerShell 7")
@pytest.mark.parametrize(("case", "stored", "journal"), [("armed", "old-key", 0), ("settled", "new-key", 0)])
def test_windows_wrapper_exit_puts_back_a_credential_rotated_before_the_lifecycle(
    tmp_path: Path, case: str, stored: str, journal: int,
) -> None:
    engine = _any_pwsh7()
    prefix = _ROTATION_PROBE[: _ROTATION_PROBE.index("$out = [ordered]@{}")]
    probe = tmp_path / "exit-probe.ps1"
    probe.write_text(
        (prefix + _EXIT_PROBE_TAIL.replace("__CASE__", case))
        .replace("__ROOT__", str(tmp_path).replace("'", "''"))
        .replace("__FUNCTIONS__", _rotation_functions(*_ROTATION_FUNCTIONS, "Exit-Wrapper")),
        encoding="utf-8",
    )
    result = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(probe)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    # 1603, or 1603 mod 256 where exit codes are 8 bits (pwsh on Linux).
    assert result.returncode in (1603, 1603 % 256), result.stdout + result.stderr
    assert "ROTATED=new-key" in result.stderr, result.stderr
    assert result.stdout.strip().splitlines()[-1] == '{"code":"mdm_not_installed"}', result.stdout
    store = tmp_path / "ProgramData"
    secret = next(path for path in store.rglob("*") if path.is_file() and path.name.endswith("ai-defense-api-key")
                  and "rotation" not in str(path))
    assert secret.read_text(encoding="utf-8") == stored
    entries = [path for path in store.rglob("*") if path.is_file() and "rotation" in str(path)]
    assert len(entries) == journal, entries


# Loop round 1 (rc.7), finding 1: two wrapper runs shared the journal with
# no lock. Run A journaled the old value; run B's resume put that value back
# (still stored, so the CLI took it) and deleted the entry; A then stored the
# new value, its lifecycle failed, and nothing was left to put back. Every
# ensure now holds rotation.lock from its resume to its exit.
_LOCK_PROBE_TAIL = r"""
function ConvertTo-DefenseClawResultJson { param($Action, $ExitCode, $Code, $Message) return "{""code"":""$Code""}" }
function Remove-WrapperStaging { }
$script:ResultAction = 'ensure'
$script:RotationCli = ''
$script:RotationLock = $null
$script:ExitBusy = 1618
$script:RotationLockWaitSeconds = 1
$script:confirmed = 'old-key'; $script:delivered = 'new-key'; $script:inUse = $true
if ('__ROLE__' -eq 'b') {
    # Run B: a concurrent ensure settles what an earlier run left.
    Resume-WrapperSecretJournal
    [Console]::Out.WriteLine("resumed $(Get-Stored) $(Get-Journal) $(@($script:calls).Count)")
    exit 0
}
# Run A journals the old value and pauses before it stores the new one.
Reset-Device 'old-key'
[void](Enter-WrapperRotationLock -Create)
Save-WrapperSecretJournal -Name $SecretName
$b = @(& '__ENGINE__' -NoLogo -NoProfile -NonInteractive -File '__CHILD__' 2>&1 | ForEach-Object { "$_" })
"B1=$LASTEXITCODE $($b | Where-Object { $_ -match '^(\{|resumed)' } | Select-Object -Last 1) $(Get-Stored) $(Get-Journal)"
"LOG1=$($b -join ' | ')"
# A goes on: it stores the new value, its lifecycle fails, the put-back finds its entry.
$failure = Set-WrapperSecret -Extra @('--bundle', $bundle)
Undo-WrapperSecretRotation -Cli 'defenseclaw.exe'
"A=$($null -eq $failure) $(Get-Stored) $(Get-Journal)"
# A exits (its hold goes): the next ensure runs.
$script:RotationLock.Dispose(); $script:RotationLock = $null
$b = @(& '__ENGINE__' -NoLogo -NoProfile -NonInteractive -File '__CHILD__' 2>&1 | ForEach-Object { "$_" })
"B2=$LASTEXITCODE $($b | Where-Object { $_ -match '^(\{|resumed)' } | Select-Object -Last 1)"
"LOG2=$($b -join ' | ')"
"""


@pytest.mark.skipif(_any_pwsh7() is None, reason="needs PowerShell 7")
def test_windows_wrapper_holds_the_credential_journal_until_its_rotation_settles(tmp_path: Path) -> None:
    engine = _any_pwsh7()
    assert engine
    prefix = _ROTATION_PROBE[: _ROTATION_PROBE.index("$out = [ordered]@{}")]
    functions = _rotation_functions(*_ROTATION_FUNCTIONS, "Exit-Wrapper", "Enter-WrapperRotationLock",
                                    "Resume-WrapperSecretJournal")
    child = tmp_path / "run-b.ps1"
    parent = tmp_path / "run-a.ps1"
    for path, role in ((child, "b"), (parent, "a")):
        path.write_text(
            (prefix + _LOCK_PROBE_TAIL.replace("__ROLE__", role))
            .replace("__ROOT__", str(tmp_path).replace("'", "''"))
            .replace("__ENGINE__", engine.replace("'", "''"))
            .replace("__CHILD__", str(child).replace("'", "''"))
            .replace("__FUNCTIONS__", functions),
            encoding="utf-8",
        )
    result = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(parent)],
        capture_output=True, text=True, timeout=180, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    lines = {line.split("=", 1)[0]: line.split("=", 1)[1] for line in result.stdout.splitlines() if "=" in line[:3]}
    # B waits for A's hold, then gives up busy (1618, or 1618 mod 256 on
    # Linux) with A's entry and the stored value untouched.
    assert lines.get("B1") in ('1618 {"code":"lifecycle_busy"} old-key 1', '82 {"code":"lifecycle_busy"} old-key 1'), result.stdout + result.stderr
    # A's failed lifecycle still finds its entry and puts the old value back.
    assert lines.get("A") == "True old-key 0", result.stdout + result.stderr
    # Once A is gone, B runs: nothing is left to settle.
    assert lines.get("B2") == "0 resumed old-key 0 0", result.stdout + result.stderr


def test_windows_wrapper_every_exit_after_the_rotation_settles_it() -> None:
    # Every exit between the rotation and the settle goes through
    # Exit-Wrapper (no bare exit), and the launch failure needs no extra put
    # back: Exit-Wrapper does it.
    text = _text(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1")
    main = text[text.index("$staging = New-WrapperStaging"):]
    armed = main.index("$script:RotationCli = $installedDeployment.Cli")
    disarmed = main.index("$script:RotationCli = ''", armed)
    window = main[armed:disarmed]
    assert not re.search(r"^\s*exit\b", window, re.MULTILINE), window
    assert "Undo-WrapperSecretRotation" not in window
    exit_wrapper = text[text.index("function Exit-Wrapper {"):]
    exit_wrapper = exit_wrapper[: exit_wrapper.index("\n}\n")]
    assert exit_wrapper.index("Undo-WrapperSecretRotation -Cli $rotationCli") < exit_wrapper.index("exit $ExitCode")


# GAP-1095: the Linux and macOS kit also stores a credential with the bundle
# it came with (secret set --bundle) before ensure and bundle apply. A failed
# or interrupted run left the new value with the still-confirmed bundle.
# The kit now keeps the old value in memory and puts it back (secret set, or
# secret remove when none was stored) on every exit but a successful bundle
# apply; the gateway decides, as on Windows. The fake gateway has its rules.
_FAKE_SECRET_GATEWAY = r"""#!/bin/sh
printf '%s\n' "$*" >>"$FAKE/calls"
if [ "$1" = --version-json ]; then echo '{"secret_set_bundle":true}'; exit 0; fi
store="$SECRETS/$5"
refuse() { printf '{"schema_version":2,"ok":false,"errors":[{"code":"%s","message":"%s refused"}]}\n' "$1" "$1"; exit 1; }
case "$3" in
set)
    value=$(cat)
    current=""
    [ ! -f "$store" ] || current=$(cat "$store")
    if [ ! -f "$store" ] || [ "$value" != "$current" ]; then
        signed=0
        if [ ! -f "$FAKE/confirmed" ] || [ "$value" = "$(cat "$FAKE/confirmed")" ]; then signed=1; fi
        case " $* " in *" --bundle "*) [ "$value" != "$(cat "$FAKE/delivered")" ] || signed=1 ;; esac
        [ "$signed" = 1 ] || refuse secret_ref_mismatch
        mkdir -p "$SECRETS"
        printf '%s\n' "$value" >"$store"
    fi
    echo '{"schema_version":2,"ok":true,"errors":[]}'
    exit 0 ;;
remove)
    [ ! -f "$FAKE/in_use" ] || refuse credential_in_use
    rm -f "$store"
    echo '{"schema_version":2,"ok":true,"errors":[]}'
    exit 0 ;;
esac
exit 2
"""

_SECRET_ROTATION_FUNCTIONS = ("dc_secret_json_error", "dc_secret_set_bundle", "dc_read_stored_secret",
                              "dc_save_secret_previous", "dc_restore_secret", "dc_store_secret",
                              "dc_restore_anchors", "dc_cleanup")


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("os_dir", ["linux", "macos"])
@pytest.mark.parametrize(
    ("case", "previous", "confirmed", "delivered", "in_use", "then", "stored", "puts_back"),
    [
        # The bundle apply (or the ensure before it) fails: the old value goes back.
        ("failed", "old-key", "old-key", "new-key", False, "exit 1", "old-key", "set"),
        # The MDM stops the run (TERM) after the rotation.
        ("cancelled", "old-key", "old-key", "new-key", False, "kill -TERM $$; sleep 5", "old-key", "set"),
        # The bundle apply succeeded: the new value stays, nothing is put back.
        ("applied", "old-key", "old-key", "new-key", False, "applied", "new-key", ""),
        # The run failed after the new bundle was confirmed: the gateway refuses the old value.
        ("confirmed", "old-key", "old-key", "new-key", False, "echo new-key >\"$FAKE/confirmed\"; exit 1", "new-key", "set"),
        # No credential was stored before: a failed run removes it again ...
        ("absent", None, None, "new-key", False, "exit 1", None, "remove"),
        # ... unless the installed config now uses it.
        ("absent-in-use", None, None, "new-key", True, "exit 1", "new-key", "remove"),
        # The gateway refused the rotation: nothing changed, nothing is put back.
        ("refused", "old-key", "old-key", "other-key", False, "exit 0", "old-key", ""),
    ],
)
def test_unix_wrapper_puts_back_a_rotated_credential_unless_its_bundle_applies(
    tmp_path: Path, os_dir: str, case: str, previous: str | None, confirmed: str | None, delivered: str,
    in_use: bool, then: str, stored: str | None, puts_back: str,
) -> None:
    wrapper = _text(MDM / os_dir / "defenseclaw-enterprise.sh")
    functions = "\n".join(_shell_function(wrapper, name) for name in _SECRET_ROTATION_FUNCTIONS)
    fake, secrets, stage = tmp_path / "fake", tmp_path / "secrets", tmp_path / "stage"
    for folder in (fake, secrets, stage):
        folder.mkdir()
    gateway = tmp_path / "gateway"
    gateway.write_text(_FAKE_SECRET_GATEWAY, encoding="utf-8")
    gateway.chmod(0o755)
    if previous is not None:
        (secrets / "ai-key").write_text(previous + "\n", encoding="utf-8")
    if confirmed is not None:
        (fake / "confirmed").write_text(confirmed, encoding="utf-8")
    (fake / "delivered").write_text(delivered, encoding="utf-8")
    if in_use:
        (fake / "in_use").write_text("", encoding="utf-8")
    after = 'DC_SECRET_ROTATED=0 DC_SECRET_PREVIOUS=""; exit 0' if then == "applied" else then
    script = f"""set -eu
DC_ACTION=ensure DC_STAGE="{stage}" DC_LOG="{tmp_path / 'kit.log'}" DC_EXIT_FAILURE=1 DC_MAX_SECRET_BYTES=16384
DC_SECRETS_DIR="{secrets}" DC_SECRET_NAME=ai-key DC_SECRET_ROTATED=0 DC_SECRET_PREVIOUS="" DC_SECRET_PREVIOUS_SET=0
DC_SECRET_GATEWAY="" DC_CHILD="" DC_ANCHORS_SOURCE="" DC_ANCHORS_CHANGED=0
dc_log() {{ printf '%s\\n' "$1" >>"$DC_LOG"; }}
dc_fail_result() {{ echo "fail $1 $2 $3"; exit "$1"; }}
{functions}
trap dc_cleanup EXIT
trap 'dc_fail_result 1 mdm_cancelled cancelled' HUP INT TERM
bundle="{tmp_path / 'policy.dcbundle'}" secret_data=new-key
dc_store_secret "{gateway}"
echo "rotated=$(cat "$DC_SECRETS_DIR/ai-key")"
{after}
"""
    result = subprocess.run(["sh", "-c", script], env={"PATH": os.environ["PATH"], "FAKE": str(fake), "SECRETS": str(secrets)},
                            capture_output=True, text=True, timeout=30)
    out = result.stdout + result.stderr
    calls = (fake / "calls").read_text(encoding="utf-8").splitlines()
    rotations = [call for call in calls if " --bundle " in call]
    assert len(rotations) == 1, (calls, out)
    if case == "refused":
        assert "secret_ref_mismatch" in out and "rotated" not in out, out
    else:
        assert "rotated=new-key" in out, out
    put_back = [call.split()[2] for call in calls if call.startswith("enterprise secret") and " --bundle " not in call]
    assert put_back == ([puts_back] if puts_back else []), (calls, out)
    secret = secrets / "ai-key"
    assert (secret.read_text(encoding="utf-8").strip() if secret.exists() else None) == stored, out
    assert not stage.exists(), "the stage is removed after the put-back"
    if case in ("confirmed", "absent-in-use"):
        assert "kept the delivered value of credential ai-key" in (tmp_path / "kit.log").read_text(encoding="utf-8")


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_wrapper_does_not_rotate_a_credential_that_is_a_link(tmp_path: Path) -> None:
    wrapper = _text(MDM / "linux" / "defenseclaw-enterprise.sh")
    functions = "\n".join(_shell_function(wrapper, name) for name in _SECRET_ROTATION_FUNCTIONS)
    fake, secrets, stage = tmp_path / "fake", tmp_path / "secrets", tmp_path / "stage"
    for folder in (fake, secrets, stage):
        folder.mkdir()
    (tmp_path / "elsewhere").write_text("old-key\n", encoding="utf-8")
    (secrets / "ai-key").symlink_to(tmp_path / "elsewhere")
    (fake / "delivered").write_text("new-key", encoding="utf-8")
    gateway = tmp_path / "gateway"
    gateway.write_text(_FAKE_SECRET_GATEWAY, encoding="utf-8")
    gateway.chmod(0o755)
    script = f"""set -eu
DC_ACTION=ensure DC_STAGE="{stage}" DC_LOG="" DC_EXIT_FAILURE=1 DC_MAX_SECRET_BYTES=16384
DC_SECRETS_DIR="{secrets}" DC_SECRET_NAME=ai-key DC_SECRET_ROTATED=0 DC_SECRET_PREVIOUS="" DC_SECRET_PREVIOUS_SET=0
DC_SECRET_GATEWAY="" DC_CHILD="" DC_ANCHORS_SOURCE="" DC_ANCHORS_CHANGED=0
dc_log() {{ :; }}
dc_fail_result() {{ echo "fail $1 $2 $3"; exit "$1"; }}
{functions}
trap dc_cleanup EXIT
bundle="{tmp_path / 'policy.dcbundle'}" secret_data=new-key
dc_store_secret "{gateway}"
"""
    result = subprocess.run(["sh", "-c", script], env={"PATH": os.environ["PATH"], "FAKE": str(fake), "SECRETS": str(secrets)},
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 1 and "fail 1 mdm_secret_failed" in result.stdout, result.stdout + result.stderr
    assert (fake / "calls").read_text(encoding="utf-8").splitlines() == ["--version-json"]
    assert (tmp_path / "elsewhere").read_text(encoding="utf-8") == "old-key\n"


def test_unix_wrapper_settles_the_rotated_credential_with_the_bundle_apply() -> None:
    # dc_main: the success branch of the bundle apply keeps the stored value
    # (and only it), the failure branch puts it back, and every other exit
    # does so in dc_cleanup before the stage goes.
    for os_dir in ("linux", "macos"):
        text = _text(MDM / os_dir / "defenseclaw-enterprise.sh")
        main = _shell_function(text, "dc_main")
        apply = main.index('bundle apply --bundle "$bundle" --reason mdm --lock-wait 10m')
        success = main.index('DC_SECRET_ROTATED=0 DC_SECRET_PREVIOUS=""', apply)
        failure = main.index("dc_restore_secret || true", success)
        assert main.index('if [ "$status" = 0 ]; then', apply) < success < main.index("else", success) < failure
        assert main.count("DC_SECRET_ROTATED=0") == 1
        cleanup = _shell_function(text, "dc_cleanup")
        assert cleanup.index("dc_restore_secret || true") < cleanup.index('rm -rf "$DC_STAGE"')
        store = _shell_function(text, "dc_store_secret")
        assert store.index('set -- --bundle "$bundle"') < store.index('dc_save_secret_previous "$gateway"') < store.index("enterprise secret set")


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("os_dir", ["linux", "macos"])
@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        ("", 'credential is empty (check "value" < 1)'),
        ("gateway unavailable", "gateway unavailable"),
    ],
)
def test_unix_wrapper_secret_refusal_carries_gateway_reason(
    tmp_path: Path, os_dir: str, stderr: str, expected: str
) -> None:
    wrapper = _text(MDM / os_dir / "defenseclaw-enterprise.sh")
    functions = "\n".join(_shell_function(wrapper, name) for name in (
        "dc_json_escape", "dc_print_result", "dc_log", "dc_fail_result",
        "dc_secret_json_error", "dc_store_secret",
    ))
    gateway = tmp_path / "gateway"
    gateway.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$DC_TEST_DOCUMENT"\n'
        'if [ -n "$DC_TEST_STDERR" ]; then printf "%s\\n" "$DC_TEST_STDERR" >&2; fi\n'
        'exit 2\n',
        encoding="utf-8",
    )
    gateway.chmod(0o755)
    document = {"errors": [{"code": "secret_value_invalid", "message": 'credential is empty (check "value" < 1)'}]}
    script = (
        f'DC_ACTION=ensure DC_SCRIPT_OS={"darwin" if os_dir == "macos" else "linux"}\n'
        f'DC_STAGE="{tmp_path}" DC_LOG="" DC_FORMAT=json DC_EXIT_FAILURE=1\n'
        'DC_SECRET_NAME=test-key secret_data=placeholder\n'
        f'{functions}\ndc_store_secret "{gateway}"\n'
    )
    result = subprocess.run(
        ["sh", "-c", script],
        env={"PATH": os.environ["PATH"], "DC_TEST_DOCUMENT": json.dumps(document).replace("<", "\\u003c"), "DC_TEST_STDERR": stderr},
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 2, result.stderr
    output = json.loads(result.stdout)
    assert output["errors"] == [{
        "code": "mdm_secret_failed",
        "message": f"storing credential 'test-key' failed, so the config was not applied: {expected}",
    }]


def _run(args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, input=stdin, capture_output=True, text=True, env={}, timeout=60)


def _host_os_dir() -> str:
    return "macos" if os.uname().sysname == "Darwin" else "linux"


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_wrapper_failures_are_schema_results() -> None:
    validator = _schema_validator()
    host = _host_os_dir()
    other = "linux" if host == "macos" else "macos"
    wrapper = str(MDM / host / "defenseclaw-enterprise.sh")
    cases = [
        ([wrapper, "--action", "bogus"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--source", "/nonexistent.deb"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--sha256", "xyz"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--config-stdin", "--secret-name", "k", "--secret-stdin"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--secret-name", "Bad_Name", "--secret-stdin"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--action", "status", "--config-stdin"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--action", "verify", "--trust-anchor-file", "/a.json"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--bundle-file", "b.dcbundle"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--refuse-capability-loss"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--source-url", "http://example.com/x.tar.gz", "--sha256", "0" * 64], 2 if os.geteuid() == 0 else 1, None),
        ([str(MDM / other / "defenseclaw-enterprise.sh")], 2, "mdm_wrong_platform"),
    ]
    if os.geteuid() != 0:
        cases.append(([wrapper], 1, "mdm_not_root"))
        cases.append(([str(MDM / host / "uninstall.sh")], 1, "mdm_not_root"))
    for args, code, error in cases:
        result = _run(args)
        assert result.returncode == code, (args, result.stdout, result.stderr)
        documents = [line for line in result.stdout.splitlines() if line.strip()]
        assert len(documents) == 1, (args, result.stdout)
        document = json.loads(documents[0])
        errors = sorted(validator.iter_errors(document), key=str)
        assert not errors, (args, [e.message for e in errors])
        assert document["exit_code"] == code
        assert document["platform"] == ("darwin" if host == "macos" else "linux") or error == "mdm_wrong_platform"
        if error:
            assert [e["code"] for e in document["errors"]] == [error], (args, document)


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_macos_wrapper_jamf_format_wraps_success_and_failure(tmp_path: Path) -> None:
    wrapper = _text(MDM / "macos" / "defenseclaw-enterprise.sh")
    functions = "\n".join(_shell_function(wrapper, name) for name in (
        "dc_json_escape", "dc_print_result", "dc_fail_result", "dc_parse_args", "dc_emit_result",
    ))
    result_file = tmp_path / "result.json"
    result_file.write_text('{"ok":true,"message":"A < B & C > D"}\n', encoding="utf-8")
    setup = (
        'DC_ACTION=ensure DC_SCRIPT_OS=darwin DC_FORMAT=json DC_LOG="" DC_EXIT_INVALID=2\n'
        'dc_log() { :; }\n'
        f'{functions}\n'
        'dc_parse_args --format jamf\n'
        '[ "$DC_FORMAT" = jamf ] || exit 9\n'
    )
    success = subprocess.run(
        ["sh", "-c", setup + f'DC_RESULT="{result_file}"\ndc_emit_result\n'],
        capture_output=True, text=True, timeout=10,
    )
    assert success.returncode == 0, success.stderr
    assert json.loads(ET.fromstring(success.stdout).text or "") == json.loads(result_file.read_text())
    failure = subprocess.run(
        ["sh", "-c", setup + 'dc_fail_result 2 mdm_invalid_arguments "A < B & C > D"\n'],
        capture_output=True, text=True, timeout=10,
    )
    assert failure.returncode == 2, failure.stderr
    document = json.loads(ET.fromstring(failure.stdout).text or "")
    assert document["errors"][0] == {"code": "mdm_invalid_arguments", "message": "A < B & C > D"}


@pytest.mark.skipif(os.name != "posix", reason="POSIX file descriptors")
@pytest.mark.parametrize("name", UNIX_SCRIPTS)
def test_intune_repeated_file_descriptor_is_not_an_argument(name: str) -> None:
    path = MDM / _host_os_dir() / name
    descriptor = os.open(path, os.O_RDONLY)
    try:
        script = f"/proc/self/fd/{descriptor}"
        result = subprocess.run(["sh", script, script], pass_fds=(descriptor,), capture_output=True, text=True, timeout=30)
    finally:
        os.close(descriptor)
    assert "unknown argument" not in result.stderr + result.stdout


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("os_dir", ["linux", "macos"])
def test_unix_wrapper_creates_a_traversable_log_directory(os_dir: str, tmp_path: Path) -> None:
    # The wrapper runs under umask 077. On macOS its log parent
    # /Library/Logs/Cisco also holds the gateway's own log, which launchd opens
    # as the service account; a 0700 parent kept the gateway from starting.
    layout = _shell_function(_text(MDM / os_dir / "defenseclaw-enterprise.sh"), "dc_layout")
    log = tmp_path / "Logs" / "Cisco" / "DefenseClaw" / "mdm-wrapper.log"
    script = f"umask 077\nDC_SCRIPT_OS=darwin\nDC_LOG='{log}'\n{layout}\ndc_layout\n"
    result = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    for directory in (log.parent.parent, log.parent):
        assert directory.stat().st_mode & 0o777 == 0o755, directory


def test_bundle_detection_contract_names_the_public_receipt_and_private_state() -> None:
    contract = _text(MDM / "contract" / "detection.md")
    assert "<etc>/bundles/receipt.json" in contract
    assert "any local user can read" in contract
    assert "`bundle-state.json` and private receipts stay under the `0700`" in contract
    assert "noninheriting read and execute ACEs" in contract


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize(
    ("http", "code", "reason"),
    [(302, 0, "redirected (HTTP 302)"), (404, 22, "HTTP 404"), (0, 5, "proxy lookup failed (curl exit 5)")],
)
def test_unix_download_reports_status_without_url_query(
    http: int, code: int, reason: str, tmp_path: Path
) -> None:
    curl = tmp_path / "curl"
    curl.write_text(
        "#!/bin/sh\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  case \"$1\" in\n"
        "    -D) header=$2; shift 2 ;;\n"
        "    -o) output=$2; shift 2 ;;\n"
        "    *) shift ;;\n"
        "  esac\n"
        "done\n"
        "printf 'HTTP/2 %s\\n' \"$DC_TEST_HTTP\" >\"$header\"\n"
        ": >\"$output\"\n"
        "exit \"$DC_TEST_CODE\"\n",
        encoding="utf-8",
    )
    curl.chmod(0o755)
    download = _shell_function(_text(MDM / "linux" / "defenseclaw-enterprise.sh"), "dc_download")
    script = (
        f'DC_STAGE="{tmp_path}"\nDC_HTTPS_PROXY=""\n{download}\n'
        f'dc_download "https://example.test/a.deb?sig=private" "{tmp_path / "a.deb"}" '
        '|| printf "%s\\n" "$DC_DOWNLOAD_ERROR"\n'
    )
    env = {"PATH": f"{tmp_path}:/usr/bin:/bin", "DC_TEST_HTTP": str(http), "DC_TEST_CODE": str(code)}
    result = subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True, check=True)
    assert reason in result.stdout and "private" not in result.stdout + result.stderr


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_lifecycle_retries_only_busy(tmp_path: Path) -> None:
    retry = _shell_function(_text(MDM / "linux" / "defenseclaw-enterprise.sh"), "dc_run_lifecycle_retry")
    script = f'''DC_TEST_COUNT="{tmp_path / "count"}"
dc_log() {{ :; }}
sleep() {{ :; }}
dc_run_lifecycle() {{
    count=$(cat "$DC_TEST_COUNT" 2>/dev/null || echo 0)
    count=$((count + 1))
    echo "$count" >"$DC_TEST_COUNT"
    [ "$count" -ge 2 ] || return 75
}}
{retry}
dc_run_lifecycle_retry ignored
'''
    result = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
    assert result.returncode == 0 and (tmp_path / "count").read_text().strip() == "2"


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_detect_busy_is_a_retry_signal() -> None:
    report = _shell_function(_text(MDM / "linux" / "detect.sh"), "dc_report")
    result = subprocess.run(["sh", "-c", f'DC_FORMAT=exit\n{report}\ndc_report 0 busy busy'], capture_output=True, text=True)
    assert result.returncode == 75 and "busy" in result.stderr


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_detect_reports_an_interrupted_package_unhealthy(tmp_path: Path) -> None:
    # A power loss in the postinst left dpkg half-configured while the
    # services ran, and detect --require-healthy still reported healthy, so
    # Intune never ran the wrapper and apt stayed blocked (GAP-0930).
    check = _shell_function(_text(MDM / "linux" / "detect.sh"), "dc_package_interrupted")
    stub = tmp_path / "dpkg-query"
    stub.write_text('#!/bin/sh\nprintf "%s" "$DC_TEST_STATUS"\n', encoding="utf-8")
    stub.chmod(0o755)
    for status, interrupted in (("install ok half-configured", True), ("install ok installed", False)):
        env = {"PATH": f"{tmp_path}:/usr/bin:/bin", "DC_TEST_STATUS": status}
        result = subprocess.run(
            ["sh", "-c", f"DC_SCRIPT_OS=linux\n{check}\ndc_package_interrupted"], capture_output=True, text=True, env=env
        )
        assert result.returncode == 0 and ("half-configured" in result.stdout) == interrupted, (status, result.stdout)


_PACKAGE_TOOL_STUBS = {
    # Each stub answers the queries dc_install_package makes and records any
    # install in $DC_TEST_LOG.
    "dpkg-deb": """case "$3" in Package) echo defenseclaw-enterprise ;; Version) echo "$DC_TEST_VERSION" ;; Architecture) echo amd64 ;; esac""",
    "dpkg": """case "$1" in --print-architecture) echo amd64 ;; -i) echo "dpkg -i" >>"$DC_TEST_LOG" ;; esac""",
    "dpkg-query": "exit 1",
    "rpm": """case "$1" in
    -qp) case "$3" in *NAME*) echo defenseclaw-enterprise ;; *ARCH*) echo x86_64 ;; *) echo "$DC_TEST_VERSION" ;; esac ;;
    --eval) echo x86_64 ;;
    -q) exit 1 ;;
    -U) echo "rpm -U" >>"$DC_TEST_LOG" ;;
esac""",
    "pkgutil": """case "$1" in
    --expand) mkdir -p "$3" && printf '<pkg-ref id="com.cisco.defenseclaw.enterprise" version="%s" onConclusion="none">x.pkg</pkg-ref>\\n' "$DC_TEST_VERSION" >"$3/Distribution" ;;
    *) exit 1 ;;
esac""",
    "installer": 'echo "installer -pkg" >>"$DC_TEST_LOG"',
}


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize(
    ("source", "package_version", "pin", "installs"),
    [
        ("defenseclaw-enterprise.deb", "1.5.0", "1.4.0", False),
        ("defenseclaw-enterprise.deb", "1.4.0", "v1.4.0", True),
        ("defenseclaw-enterprise.deb", "1:1.4.0~rc1-1", "1.4.0-rc1", True),
        ("defenseclaw-enterprise.deb", "1.0.901~SNAPSHOT-d03042625", "1.0.901-SNAPSHOT-d03042625", True),
        ("defenseclaw-enterprise.deb", "1.4.0~rc1", "1.4.0", False),
        ("defenseclaw-enterprise.rpm", "1.5.0-1", "1.4.0", False),
        ("defenseclaw-enterprise.rpm", "1.4.0~rc1-1", "1.4.0-rc1", True),
        ("defenseclaw-enterprise.pkg", "1.5.0", "1.4.0", False),
        ("defenseclaw-enterprise.pkg", "1.4.0-rc1", "1.4.0", False),
        ("defenseclaw-enterprise.pkg", "1.4.0", "1.4.0", True),
        ("defenseclaw-enterprise.deb", "1.5.0", "", True),
    ],
)
def test_unix_wrapper_checks_the_product_version_before_the_package_manager(
    source: str, package_version: str, pin: str, installs: bool, tmp_path: Path
) -> None:
    # The package's maintainer scripts apply the deployment as soon as the
    # package manager installs it, so a --product-version mismatch must stop
    # the wrapper before dpkg, rpm or installer runs.
    text = _text(MDM / "linux" / "defenseclaw-enterprise.sh")
    functions = "\n".join(
        _shell_function(text, name)
        for name in ("dc_busy_output", "dc_require_product_version", "dc_package_release_version", "dc_install_package")
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in _PACKAGE_TOOL_STUBS.items():
        stub = bin_dir / name
        stub.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
        stub.chmod(0o755)
    log = tmp_path / "install.log"
    script = f"""
DC_SCRIPT_OS={"darwin" if source.endswith(".pkg") else "linux"}
DC_EXIT_FAILURE=1 DC_EXIT_INVALID=2 DC_EXIT_BUSY=75
DC_LINUX_PACKAGE=defenseclaw-enterprise DC_MACOS_PACKAGE_ID=com.cisco.defenseclaw.enterprise
DC_PRODUCT_VERSION='{pin}' DC_STAGE='{tmp_path}' DC_STAGED_SOURCE='{tmp_path / source}'
dc_fail_result() {{ echo "FAIL $2: $3"; exit "$1"; }}
dc_log() {{ :; }}
dc_extract_payload() {{ :; }}
{functions}
dc_install_package
echo installed-ok
"""
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "DC_TEST_VERSION": package_version, "DC_TEST_LOG": str(log)}
    for shell in ("sh", "bash"):
        if log.exists():
            log.unlink()
        result = subprocess.run([shell, "-c", script], env=env, capture_output=True, text=True, timeout=30)
        if installs:
            assert result.returncode == 0 and "installed-ok" in result.stdout, (shell, result.stdout, result.stderr)
            assert log.exists(), (shell, "the package manager did not run")
        else:
            assert result.returncode == 1, (shell, result.stdout, result.stderr)
            assert "FAIL mdm_version_mismatch" in result.stdout, (shell, result.stdout)
            assert not log.exists(), (shell, "the package manager ran before the version check", log.read_text())



# GAP-0890: an interrupted rpm upgrade can leave two versions installed, and
# `rpm -q --qf` then prints both run together. The same-version repair never
# matched, so rpm -U ran without --replacepkgs and failed "already installed".
@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_wrapper_repairs_an_rpm_left_with_two_installed_versions(tmp_path: Path) -> None:
    text = _text(MDM / "linux" / "defenseclaw-enterprise.sh")
    functions = "\n".join(
        _shell_function(text, name)
        for name in ("dc_busy_output", "dc_require_product_version", "dc_package_release_version", "dc_install_package")
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    rpm = bin_dir / "rpm"
    rpm.write_text(
        """#!/bin/sh
case "$1" in
    -qp) case "$3" in *NAME*) echo defenseclaw-enterprise ;; *ARCH*) echo x86_64 ;; *) echo 1.0.4101-1 ;; esac ;;
    --eval) echo x86_64 ;;
    -q) [ "$2" = --qf ] && printf '1.0.3602-1\\n1.0.4101-1\\n'; exit 0 ;;
    -U) case " $* " in *" --replacepkgs "*) echo "rpm -U --replacepkgs" >>"$DC_TEST_LOG" ;; *) echo "package is already installed" >&2; exit 1 ;; esac ;;
esac
""",
        encoding="utf-8",
    )
    rpm.chmod(0o755)
    log = tmp_path / "install.log"
    script = f"""
DC_SCRIPT_OS=linux DC_EXIT_FAILURE=1 DC_EXIT_INVALID=2 DC_EXIT_BUSY=75
DC_LINUX_PACKAGE=defenseclaw-enterprise DC_PRODUCT_VERSION=''
DC_STAGE='{tmp_path}' DC_STAGED_SOURCE='{tmp_path / "defenseclaw-enterprise.rpm"}'
dc_fail_result() {{ echo "FAIL $2: $3"; exit "$1"; }}
dc_log() {{ :; }}
dc_extract_payload() {{ :; }}
dc_binaries_damaged() {{ return 0; }}
dc_package_step() {{ echo "step $1 -> $2"; }}
{functions}
dc_install_package
echo installed-ok
"""
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "DC_TEST_LOG": str(log)}
    result = subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0 and "installed-ok" in result.stdout, (result.stdout, result.stderr)
    assert "step 1.0.4101 -> 1.0.4101" in result.stdout, result.stdout
    assert log.read_text(encoding="utf-8").strip() == "rpm -U --replacepkgs"

# GAP-0030: a --staging-dir folder that does not exist exited 1 with no
# result and "DC_TRUST_ACL: unbound variable" (set -u): the check skipped
# dc_trusted_path, which is what set the variable. Both twins run their own
# settings and state block and the real dc_stage_parent; a stub stat makes an
# existing folder read as another account's on either host.
@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("os_dir", ["linux", "macos"])
@pytest.mark.parametrize("shell", ["sh", "bash"])
@pytest.mark.parametrize("case", ["missing", "untrusted"])
def test_unix_wrapper_refuses_a_bad_custom_staging_dir_with_a_result(os_dir: str, shell: str, case: str, tmp_path: Path) -> None:
    if shutil.which(shell) is None:
        pytest.skip(f"{shell} is not installed")
    validator = _schema_validator()
    text = _text(MDM / os_dir / "defenseclaw-enterprise.sh")
    header = text[text.index("set -eu\n"):text.index("dc_platform() {")]
    functions = "\n".join(_shell_function(text, name) for name in (
        "dc_json_escape", "dc_print_result", "dc_fail_result", "dc_log", "dc_stat_uid", "dc_stat_mode",
        "dc_acl_write_entry", "dc_trusted_path", "dc_stage_parent"))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stat = bin_dir / "stat"
    stat.write_text("#!/bin/sh\necho 501\n", encoding="utf-8")  # owned by another account
    stat.chmod(0o755)
    staging = tmp_path / "mdm-stage"
    if case == "untrusted":
        staging.mkdir()
    script = f"""{header}
PATH='{bin_dir}':$PATH
DC_STAGING_DIR='{staging}'
{functions}
dc_stage_parent
echo staged
"""
    result = subprocess.run([shell, "-c", script], capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"}, timeout=30)
    assert result.returncode == 1 and result.stderr == "", (result.stdout, result.stderr)
    documents = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(documents) == 1, result.stdout
    document = json.loads(documents[0])
    assert not sorted(validator.iter_errors(document), key=str), document
    assert document["exit_code"] == 1 and document["platform"] == ("darwin" if os_dir == "macos" else "linux")
    assert [e["code"] for e in document["errors"]] == ["mdm_staging_untrusted"], document
    message = document["errors"][0]["message"]
    if case == "missing":
        assert f"the staging folder {staging} does not exist" in message and "mkdir -m 0700" in message, message
    else:
        assert f"the staging folder {staging} is not a root-owned directory that only root can write" in message, message


# GAP-0752: on a CIS host (/tmp and /var/tmp noexec) the payload's gateway
# could not run from the wrapper's /var/tmp staging folder, and the result was
# mdm_lifecycle_no_result with the shell's "Permission denied". The wrapper
# now stages in a root-only folder of its own and names a noexec mount.
@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_wrapper_names_a_noexec_staging_mount(tmp_path: Path) -> None:
    text = _text(MDM / "linux" / "defenseclaw-enterprise.sh")
    assert "DC_STAGE_PARENT=/var/lib/defenseclaw-mdm" in text
    functions = "\n".join(_shell_function(text, name) for name in ("dc_noexec_mount", "dc_extract_payload"))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    findmnt = bin_dir / "findmnt"
    findmnt.write_text("#!/bin/sh\necho '/var/tmp rw,nosuid,nodev,noexec,relatime'\n", encoding="utf-8")
    findmnt.chmod(0o755)
    source = tmp_path / "src"
    source.mkdir()
    gateway = source / "defenseclaw-gateway"
    gateway.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    gateway.chmod(0o644)  # what a noexec mount makes of an executable
    archive = tmp_path / "payload.tar.gz"
    subprocess.run(["tar", "-czf", str(archive), "-C", str(source), "defenseclaw-gateway"], check=True)
    stage = tmp_path / "stage"
    stage.mkdir()
    script = f"""
DC_SCRIPT_OS=linux DC_EXIT_FAILURE=1 DC_STAGE='{stage}' DC_STAGED_SOURCE='{archive}'
dc_fail_result() {{ echo "FAIL $2: $3"; exit "$1"; }}
chown() {{ :; }}
{functions}
dc_extract_payload
echo extracted
"""
    result = subprocess.run(["sh", "-c", script], env={"PATH": f"{bin_dir}:/usr/bin:/bin"}, capture_output=True, text=True, timeout=30)
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert "FAIL mdm_staging_noexec" in result.stdout and "/var/tmp is mounted noexec" in result.stdout, result.stdout


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("failure", ["disk_full", "downgrade", "busy", "empty_busy", "empty_free", "late_busy"])
def test_macos_wrapper_names_why_the_package_step_failed(failure: str, tmp_path: Path) -> None:
    # The Installer only says "The upgrade failed": a full data volume is
    # refused before it runs (GAP-0539), and a refused downgrade reports the
    # result the preinstall wrote, naming both versions (GAP-0538). The
    # wrapper exits with that result's code: a postinstall that timed out on
    # the lifecycle lock reports 75, which the MDM retries (GAP-1413). The
    # Installer stops that postinstall at 10 minutes, before the lifecycle
    # writes its result: the wrapper waits for it, and when it stays empty
    # reports lifecycle_busy (75) while the lock is still held.
    text = _text(MDM / "macos" / "defenseclaw-enterprise.sh")
    functions = "\n".join(
        _shell_function(text, name)
        for name in ("dc_busy_output", "dc_require_product_version", "dc_require_free_space",
                     "dc_lifecycle_lock_held", "dc_package_script_result", "dc_install_package")
    )
    stubs = dict(_PACKAGE_TOOL_STUBS)
    stubs["pkgutil"] = """case "$1" in
    --expand) mkdir -p "$3/x.pkg" && printf '<pkg-ref id="com.cisco.defenseclaw.enterprise" version="1.0.2" onConclusion="none">x.pkg</pkg-ref>\\n' >"$3/Distribution"
        echo '<payload numberOfFiles="4" installKBytes="300000"/>' >"$3/x.pkg/PackageInfo" ;;
    *) exit 1 ;;
esac"""
    stubs["df"] = 'printf "Filesystem 1024-blocks Used Available Capacity Mounted\\n/dev/disk3 9000000 8000000 %s 90%% /\\n" "$DC_TEST_FREE"'
    stubs["installer"] = """echo "installer -pkg" >>"$DC_TEST_LOG"
: >"$DC_TEST_RESULT"
[ -z "$DC_TEST_DOCUMENT" ] || printf '%s\\n' "$DC_TEST_DOCUMENT" >"$DC_TEST_RESULT"
echo "installer: The upgrade failed."
exit 1"""
    # The lifecycle writes its result while the wrapper waits.
    stubs["sleep"] = '[ -z "$DC_TEST_LATE" ] || printf "%s\\n" "$DC_TEST_LATE" >"$DC_TEST_RESULT"'
    stubs["perl"] = '[ "$DC_TEST_LOCK" = held ]'  # the non-blocking lock probe
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in stubs.items():
        stub = bin_dir / name
        stub.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
        stub.chmod(0o755)
    log, result_file = tmp_path / "install.log", tmp_path / "last-package-result.json"
    (tmp_path / "lifecycle.lock").write_text("", encoding="utf-8")
    script = f"""
DC_SCRIPT_OS=darwin
DC_EXIT_FAILURE=1 DC_EXIT_INVALID=2 DC_EXIT_BUSY=75
DC_LINUX_PACKAGE=defenseclaw-enterprise DC_MACOS_PACKAGE_ID=com.cisco.defenseclaw.enterprise
DC_PRODUCT_VERSION='' DC_STAGE='{tmp_path}' DC_STAGED_SOURCE='{tmp_path / "defenseclaw-enterprise.pkg"}'
DC_INSTALL_ROOT='{tmp_path / "opt" / "cisco" / "defenseclaw"}' DC_PACKAGE_RESULT='{result_file}' DC_RESULT=''
dc_fail_result() {{ echo "FAIL $2: $3"; exit "$1"; }}
dc_log() {{ :; }}
dc_extract_payload() {{ :; }}
dc_emit_result() {{ cat "$DC_RESULT"; }}
{functions}
dc_install_package
echo installed-ok
"""
    free = "150000" if failure == "disk_full" else "9000000"
    busy = failure in ("busy", "late_busy")
    code, message = ("lifecycle_busy", "another lifecycle run holds the lock") if busy else (
        "downgrade_refused", "DefenseClaw 1.0.3 is installed; refusing to downgrade to 1.0.2")
    document = json.dumps({"ok": False, "errors": [{"code": code, "message": message}],
                           "exit_code": 75 if busy else 1}, indent=2)
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "DC_TEST_FREE": free, "DC_TEST_LOG": str(log),
           "DC_TEST_RESULT": str(result_file), "DC_TEST_LOCK": "held" if failure == "empty_busy" else "",
           "DC_TEST_DOCUMENT": "" if failure.startswith(("empty", "late")) else document,
           "DC_TEST_LATE": document if failure == "late_busy" else ""}
    result = subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True, timeout=30)
    expected_rc = 1 if failure in ("disk_full", "downgrade", "empty_free") else 75
    assert result.returncode == expected_rc, (result.stdout, result.stderr)
    if busy:
        assert "lifecycle_busy" in result.stdout and "FAIL" not in result.stdout, result.stdout
        return
    if failure.startswith("empty"):
        expected = "FAIL lifecycle_busy" if failure == "empty_busy" else "FAIL mdm_package_result_empty"
        assert expected in result.stdout, result.stdout
        return
    if failure == "disk_full":
        assert "FAIL mdm_disk_full" in result.stdout and "MB is free" in result.stdout, result.stdout
        assert not log.exists(), "the installer ran on a full volume"
    else:
        assert "downgrade_refused" in result.stdout and "refusing to downgrade to 1.0.2" in result.stdout, result.stdout


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("source", ["defenseclaw-enterprise.rpm", "defenseclaw-enterprise.deb"])
@pytest.mark.parametrize("applied", [False, True])
def test_linux_wrapper_reports_the_postinstall_result_when_no_deployment_came_up(
    source: str, applied: bool, tmp_path: Path
) -> None:
    # The deb/rpm postinstall never fails the package transaction. When its
    # lifecycle run rolled back (units shipped group-writable, GAP-0108)
    # there was no deployment record, so every binary read as damaged and
    # the wrapper reported mdm_binaries_damaged. It now reports the result
    # the postinstall wrote, which names the unit files and their mode; a
    # postinstall that succeeded leaves the wrapper's own checks in charge.
    text = _text(MDM / "linux" / "defenseclaw-enterprise.sh")
    functions = "\n".join(
        _shell_function(text, name)
        for name in ("dc_busy_output", "dc_require_product_version", "dc_package_release_version", "dc_package_step",
                     "dc_lifecycle_lock_held", "dc_package_script_result", "dc_package_apply_failed",
                     "dc_install_package")
    )
    message = ("unit files the package installed are writable by group or other: "
               "/usr/lib/systemd/system/defenseclaw-gateway.service (0664)")
    document = json.dumps({"ok": applied, "errors": [] if applied else [{"code": "verify_failed", "message": message}],
                           "exit_code": 0 if applied else 1}, indent=2)
    stubs = dict(_PACKAGE_TOOL_STUBS)
    # The package manager runs the postinstall, which writes its result.
    stubs["rpm"] = stubs["rpm"].replace('-U) echo "rpm -U" >>"$DC_TEST_LOG" ;;',
                                        '-U) printf "%s\\n" "$DC_TEST_DOCUMENT" >"$DC_TEST_RESULT" ;;')
    stubs["dpkg"] = stubs["dpkg"].replace('-i) echo "dpkg -i" >>"$DC_TEST_LOG" ;;',
                                          '-i) printf "%s\\n" "$DC_TEST_DOCUMENT" >"$DC_TEST_RESULT" ;;')
    assert stubs["rpm"] != _PACKAGE_TOOL_STUBS["rpm"] and stubs["dpkg"] != _PACKAGE_TOOL_STUBS["dpkg"]
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in stubs.items():
        stub = bin_dir / name
        stub.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
        stub.chmod(0o755)
    result_file = tmp_path / "last-package-result.json"
    script = f"""
DC_SCRIPT_OS=linux
DC_EXIT_FAILURE=1 DC_EXIT_INVALID=2 DC_EXIT_BUSY=75
DC_LINUX_PACKAGE=defenseclaw-enterprise DC_MACOS_PACKAGE_ID=com.cisco.defenseclaw.enterprise
DC_PRODUCT_VERSION='' DC_STAGE='{tmp_path}' DC_STAGED_SOURCE='{tmp_path / source}'
DC_PACKAGE_RESULT='{result_file}' DC_RESULT='' DC_PACKAGE_ACTION=''
dc_fail_result() {{ echo "FAIL $2: $3"; exit "$1"; }}
dc_log() {{ :; }}
dc_extract_payload() {{ :; }}
dc_emit_result() {{ cat "$DC_RESULT"; }}
{functions}
dc_install_package
dc_package_apply_failed
echo own-checks
"""
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "DC_TEST_VERSION": "1.5.0", "DC_TEST_LOG": str(tmp_path / "log"),
           "DC_TEST_RESULT": str(result_file), "DC_TEST_DOCUMENT": document}
    for shell in ("sh", "bash"):
        result_file.unlink(missing_ok=True)
        result = subprocess.run([shell, "-c", script], env=env, capture_output=True, text=True, timeout=30)
        assert result_file.is_file(), (shell, result.stdout, result.stderr)
        if applied:
            assert result.returncode == 0, (shell, result.stdout, result.stderr)
            assert result.stdout.strip() == "own-checks", (shell, result.stdout)
            continue
        assert result.returncode == 1, (shell, result.stdout, result.stderr)
        assert "own-checks" not in result.stdout, (shell, result.stdout)
        assert json.loads(result.stdout)["errors"][0]["message"] == message, (shell, result.stdout)


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("os_dir", ["linux", "macos"])
@pytest.mark.parametrize("applied", [False, True])
def test_wrapper_main_reports_the_package_result_instead_of_binaries_damaged(
    os_dir: str, applied: bool, tmp_path: Path
) -> None:
    # dc_main itself, in both copies: when this run installed the package and
    # its postinstall did not bring a deployment up, every binary reads as
    # damaged, and the dc_binaries_damaged branch must report the result the
    # postinstall wrote instead of mdm_binaries_damaged (GAP-0108). After a
    # postinstall that succeeded the branch still reports mdm_binaries_damaged,
    # which proves the run reached it.
    text = _text(MDM / os_dir / "defenseclaw-enterprise.sh").rstrip()
    entry = '\ndc_main "$@"'
    assert text.endswith(entry)
    message = ("unit files the package installed are writable by group or other: "
               "/usr/lib/systemd/system/defenseclaw-gateway.service (0664)")
    document = json.dumps({"ok": applied, "errors": [] if applied else [{"code": "verify_failed", "message": message}],
                           "exit_code": 0 if applied else 1}, indent=2)
    result_file = tmp_path / "last-package-result.json"
    stage_parent = tmp_path / "stage"
    stage_parent.mkdir()
    # Stand-ins for the root, platform and package-manager steps; the
    # branch and dc_package_apply_failed run as shipped.
    overrides = f"""
dc_layout() {{
    DC_GATEWAY='{tmp_path}/bin/defenseclaw-gateway'
    DC_PACKAGE_RESULT='{result_file}'
    DC_OS_GROUP=linux
    DC_LOG=''
}}
dc_parse_args() {{ DC_SOURCE='{tmp_path}/defenseclaw-enterprise.rpm'; }}
dc_platform() {{ echo "$DC_SCRIPT_OS"; }}
dc_validate_args() {{ :; }}
id() {{ echo 0; }}
dc_stage_parent() {{ DC_STAGE_PARENT='{stage_parent}'; }}
dc_sweep_stages() {{ :; }}
dc_stat_uid() {{ echo 0; }}
dc_stage_source() {{ :; }}
dc_install_package() {{
    : >"$DC_STAGE/package.started"
    printf '%s\\n' "$DC_TEST_DOCUMENT" >"$DC_PACKAGE_RESULT"
    dc_package_step "" 1.5.0
}}
dc_trusted_path() {{ return 0; }}
dc_binaries_damaged() {{ return 0; }}
dc_main
"""
    script = text[: -len(entry)] + "\n" + overrides
    env = {"PATH": "/usr/bin:/bin", "DC_TEST_DOCUMENT": document}
    for shell in ("sh", "bash"):
        result_file.unlink(missing_ok=True)
        result = subprocess.run([shell, "-c", script], env=env, capture_output=True, text=True, timeout=30)
        assert result_file.is_file(), (shell, result.stdout, result.stderr)
        assert result.returncode == 1, (shell, result.stdout, result.stderr)
        error = json.loads(result.stdout)["errors"][0]
        if applied:
            assert error["code"] == "mdm_binaries_damaged", (shell, result.stdout)
            continue
        assert "mdm_binaries_damaged" not in result.stdout, (shell, result.stdout)
        assert error == {"code": "verify_failed", "message": message}, (shell, result.stdout)


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("os_dir", ["linux", "macos"])
def test_linux_wrapper_layout_reads_the_result_the_postinstall_writes(os_dir: str, tmp_path: Path) -> None:
    # dc_package_apply_failed reads DC_PACKAGE_RESULT: unless the Linux layout
    # names the file packaging/linux/postinstall.sh writes, the wrapper falls
    # back to mdm_binaries_damaged (GAP-0108).
    postinstall = _text(ROOT / "packaging" / "linux" / "postinstall.sh")
    state = re.findall(r"^state=(\S+)$", postinstall, re.MULTILINE)
    # The result is written to a temporary file and renamed into place
    # (w4-unix-obs: a full disk never erases the last result).
    written = set(re.findall(r'(?:>|mv -fT "\$result_tmp" )"\$state/([^"]+\.json)"', postinstall))
    assert len(state) == 1 and len(written) == 1, (state, written)
    expected = f"{state[0]}/{written.pop()}"
    assert expected == "/var/lib/defenseclaw-enterprise/last-package-result.json"
    text = _text(MDM / os_dir / "defenseclaw-enterprise.sh")
    script = f"""
DC_SCRIPT_OS=linux DC_LOG='{tmp_path}/mdm.log' DC_PACKAGE_RESULT=''
{_shell_function(text, "dc_layout")}
dc_layout
printf '%s\\n' "$DC_PACKAGE_RESULT"
"""
    for shell in ("sh", "bash"):
        result = subprocess.run([shell, "-c", script], env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True,
                                timeout=30)
        assert result.returncode == 0, (shell, result.stdout, result.stderr)
        assert result.stdout == f"{expected}\n", (shell, result.stdout)


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_detect_formats_without_an_installation() -> None:
    if os.geteuid() == 0 and Path("/opt/defenseclaw/bin/defenseclaw-gateway").exists():
        pytest.skip("a deployment is installed on this host")
    detect = str(MDM / _host_os_dir() / "detect.sh")
    result = _run([detect])
    assert result.returncode == 1 and result.stdout == ""
    value = "not-installed" if os.geteuid() == 0 else "unknown"
    assert _run([detect, "--format", "value"]).stdout == f"{value}\n"
    assert _run([detect, "--format", "jamf"]).stdout == f"<result>{value}</result>\n"
    assert _run([detect, "--format", "yaml"]).returncode == 2


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_detect_rejects_malformed_minimum_version() -> None:
    detect = str(MDM / _host_os_dir() / "detect.sh")
    for value in ("", "abc", "1.x.0"):
        result = _run([detect, "--min-version", value])
        assert result.returncode == 2 and not result.stdout


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="requires a standard user")
def test_unix_detect_standard_user_reports_unknown() -> None:
    detect = str(MDM / _host_os_dir() / "detect.sh")
    assert _run([detect, "--format", "value"]).stdout == "unknown\n"


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_detect_reads_top_level_fields_of_the_indented_lifecycle_result() -> None:
    # The lifecycle prints indented JSON; detect.sh must read the top-level
    # "installed" and version fields from it, and a nested "ok" must never
    # answer for the top-level one.
    text = _text(MDM / "linux" / "detect.sh")
    functions = "\n".join(_shell_function(text, name) for name in ("dc_json_top", "dc_json_field", "dc_json_true"))
    indented = json.dumps({
        "schema_version": 2, "ok": False, "installed": True, "installed_version": "1.2.3",
        "services": [{"name": "gateway", "ok": True}], "errors": [{"code": "x", "message": "a \"quoted\" : value"}],
    }, indent=2)
    script = functions + """
doc=$(cat)
dc_json_true "$doc" installed && echo installed
dc_json_true "$doc" ok && echo ok-true
echo "version=$(dc_json_field "$doc" installed_version)"
"""
    for shell in ("sh", "dash", "bash"):
        if not shutil.which(shell):
            continue
        result = subprocess.run([shell, "-c", script], input=indented, capture_output=True, text=True, check=True)
        assert result.stdout.splitlines() == ["installed", "version=1.2.3"], (shell, result.stdout)


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("platform", ["linux", "macos"])
def test_unix_detect_requires_complete_security_for_health(tmp_path: Path, platform: str) -> None:
    gateway = tmp_path / "gateway"
    state = tmp_path / "verify.json"
    gateway.write_text(
        '#!/bin/sh\ncase "$*" in\n'
        f'  "enterprise {platform} status --json") echo \'{{"installed":true,"installed_version":"9.9.9"}}\' ;;\n'
        f'  "enterprise {platform} verify --json") cat "{state}" ;;\n'
        '  *) exit 9 ;;\nesac\n',
        encoding="ascii",
    )
    gateway.chmod(0o755)
    source = _text(MDM / platform / "detect.sh")
    source = source.replace('[ "$(dc_platform)" = "$DC_SCRIPT_OS" ]', '[ 1 = 1 ]', 1)
    source = source.replace('[ "$(id -u)" = 0 ]', '[ 1 = 1 ]', 1)
    source = source.replace('dc_trusted_path "$gateway" ||', '[ -f "$gateway" ] ||', 1)
    original = ("gateway=/opt/defenseclaw/bin/defenseclaw-gateway group=linux" if platform == "linux"
                else "gateway=/opt/cisco/defenseclaw/bin/defenseclaw-gateway group=macos")
    assert original in source
    source = source.replace(original, f'gateway="{gateway}" group={platform}', 1)
    detect = tmp_path / "detect.sh"
    detect.write_text(source, encoding="ascii")
    for complete, expected in ((False, "unhealthy"), (True, "9.9.9")):
        state.write_text(json.dumps({"ok": True, "security_complete": complete}), encoding="ascii")
        result = subprocess.run(["sh", str(detect), "--require-healthy", "--format", "value"],
                                capture_output=True, text=True)
        assert (result.returncode, result.stdout) == (0, expected + "\n"), (platform, complete, result)


_NOT_READY = json.dumps(
    {
        "schema_version": 1, "action": "verify", "ok": False, "exit_code": 1, "mode": "consume", "ready_for": "enforce",
        "ready": False, "kernel_policy": "sha256:08b71155b713",
        "checks": [
            {"id": "tetragon.installed", "status": "pass", "message": "Tetragon is installed", "fix": []},
            {"id": "tetragon.keep_sensors_on_exit", "status": "fail", "message": "keeps sensors", "fix": ["echo false"]},
            {"id": "kernel.bpf_lsm", "status": "fail", "message": "no \"bpf\"", "fix": []},
        ],
        "users": [{"uid": 1001, "state": "fail", "covered_hours": 1, "needed_hours": 168, "percent": 0,
                   "ready": False, "reset": False, "measuring": True, "hits": []}],
        "approve": {"state": "missing", "digest": "sha256:08b71155b713", "enforce_ack": "", "ready_users": 0, "users": 1},
        "next": [], "errors": [],
    },
    indent=2,
)


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_detect_requires_tetragon_readiness_in_each_format(tmp_path: Path) -> None:
    # --require-tetragon MODE maps `tetragon verify --ready-for MODE --json`
    # to the exit, value and jamf formats; value names the first failing
    # check. A gateway that prints no report counts as not ready.
    text = _text(MDM / "linux" / "detect.sh")
    names = ("dc_json_top", "dc_json_field", "dc_json_true", "dc_report", "dc_first_failing_check", "dc_require_tetragon")
    functions = "\n".join(_shell_function(text, name) for name in names)
    script = functions + '\nDC_FORMAT=$1\ndc_require_tetragon "$2" enforce\necho ready\n'
    reports = {"not-ready": _NOT_READY, "ready": json.dumps({"ok": True, "ready": True, "checks": []}, indent=2), "none": ""}
    gateways = {}
    for name, report in reports.items():
        (tmp_path / f"{name}.json").write_text(report, encoding="utf-8")
        gateway = tmp_path / f"gateway-{name}"
        gateway.write_text(
            '#!/bin/sh\n[ "$*" = "enterprise linux tetragon verify --ready-for enforce --json" ] || exit 9\n'
            f'cat "{tmp_path / f"{name}.json"}"\n[ "{name}" = ready ] || exit 1\n',
            encoding="utf-8",
        )
        gateway.chmod(0o755)
        gateways[name] = str(gateway)
    for shell in ("sh", "dash", "bash"):
        if not shutil.which(shell):
            continue

        def run(fmt: str, name: str, shell: str = shell) -> subprocess.CompletedProcess[str]:
            return subprocess.run([shell, "-c", script, "detect", fmt, gateways[name]], capture_output=True, text=True)

        value = run("value", "not-ready")
        assert (value.returncode, value.stdout) == (0, "tetragon-not-ready:tetragon.keep_sensors_on_exit\n"), shell
        jamf = run("jamf", "not-ready")
        assert jamf.stdout == "<result>tetragon-not-ready:tetragon.keep_sensors_on_exit</result>\n", shell
        failed = run("exit", "not-ready")
        assert failed.returncode == 1 and failed.stdout == "", shell
        assert "not ready for Tetragon mode enforce (tetragon.keep_sensors_on_exit)" in failed.stderr, shell
        assert "tetragon verify --ready-for enforce" in failed.stderr, shell
        assert run("value", "none").stdout == "tetragon-not-ready:unknown\n", shell
        ready = run("value", "ready")
        assert (ready.returncode, ready.stdout) == (0, "ready\n"), shell


_ANCHORS_FUNCTIONS = ("dc_sha256", "dc_anchors_dir", "dc_anchors_verb", "dc_run_anchors_verb", "dc_put_anchors",
                      "dc_install_anchors", "dc_restore_anchors")
# The installed gateway, as the wrapper sees it: --version-json, and
# `enterprise bundle anchors install` installing STUB_DEST (or printing
# STUB_REPLY and exiting STUB_EXIT). Each call and the mode of the file
# --file names go to STUB_LOG.
_STUB_GATEWAY = """#!/bin/sh
printf '%s\\n' "$*" >>"$STUB_LOG"
if [ "$1" = --version-json ]; then
    [ "$STUB_VERSION" != fail ] || { echo 'Error: unknown flag: --version-json' >&2; exit 1; }
    printf '%s\\n' "$STUB_VERSION"
    exit 0
fi
[ "$1 $2 $3 $4 $5" = "enterprise bundle anchors install --file" ] && [ "$7 $8 $9" = "--lock-wait 10m --json" ] || exit 2
ls -l "$6" | cut -c1-10 >>"$STUB_LOG"
if [ -n "${STUB_REPLY:-}" ]; then
    cat "$STUB_REPLY"
    echo "${STUB_STDERR:-}" >&2
    exit "$STUB_EXIT"
fi
if [ -f "$STUB_DEST" ] && cmp -s "$6" "$STUB_DEST"; then
    result=unchanged
elif [ -f "$STUB_DEST" ]; then
    result=replaced
else
    result=installed
fi
[ "$result" = unchanged ] || { cp "$6" "$STUB_DEST"; chmod 0644 "$STUB_DEST"; }
printf '{\\n  "schema_version": 1,\\n  "command": "anchors install",\\n  "ok": true,\\n  "result": "%s",\\n  "anchors": "%s",\\n  "warnings": [],\\n  "errors": []\\n}\\n' "$result" "$STUB_DEST"
"""
_VERSION_CONTRACT = ('{"schema_version":1,"name":"defenseclaw-gateway","version":"1.0.3","commit":"0123456789",'
                     '"built":"2026-10-30T18:00:00Z","management_contract":1}')
# What 1.0.2 and earlier print: no management_contract member.
_VERSION_BEFORE = '{"schema_version":1,"name":"defenseclaw-gateway","version":"1.0.2","commit":"0123456789","built":"x"}'


def _anchors_harness(tmp_path: Path, body: str) -> tuple[Path, Path, Path, str]:
    """The wrapper's anchor functions with a stub gateway; returns stage, anchors, log and the script."""
    text = _text(MDM / "linux" / "defenseclaw-enterprise.sh")
    assert text.replace("DC_SCRIPT_OS=linux #", "DC_SCRIPT_OS=darwin #", 1) == _text(MDM / "macos" / "defenseclaw-enterprise.sh")
    functions = "\n".join(_shell_function(text, name) for name in _ANCHORS_FUNCTIONS)
    (tmp_path / "etc").mkdir()
    stage = tmp_path / "stage"
    stage.mkdir()
    gateway = tmp_path / "bin" / "defenseclaw-gateway"
    gateway.parent.mkdir()
    gateway.write_text(_STUB_GATEWAY, encoding="utf-8")
    gateway.chmod(0o755)
    anchors = tmp_path / "etc" / "trust" / "bundle-anchors.json"
    script = f"""DC_SCRIPT_OS=linux DC_STAGE="{stage}" DC_ANCHORS="{anchors}" DC_GATEWAY="${{T_GATEWAY:-{gateway}}}"
DC_EXIT_FAILURE=1 DC_TRUST_ACL="" DC_CHILD="" DC_ANCHORS_PREVIOUS="" DC_ANCHORS_CHANGED=0
DC_ANCHORS_VERB=0 DC_ANCHORS_SOURCE="" DC_ANCHORS_RESULT=""
dc_log() {{ :; }}
dc_fail_result() {{ echo "fail $1 $2 $3"; exit "$1"; }}
chown() {{ :; }}
dc_trusted_path() {{ [ "${{T_UNTRUSTED:-0}}" = 0 ]; }}
{functions}
{body}
"""
    return stage, anchors, tmp_path / "gateway.log", script


def _anchors_env(log: Path, anchors: Path, **values: str) -> dict[str, str]:
    return dict(os.environ, STUB_LOG=str(log), STUB_DEST=str(anchors), **values)


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("writer", ["command", "shell"])
def test_unix_wrapper_restores_the_trust_anchor_file_after_a_failed_apply(tmp_path: Path, writer: str) -> None:
    # The wrapper installs the anchor file before the bundle apply; a failed
    # apply puts back the file it replaced (or removes the one it added), and
    # an identical file is not rewritten. F7: an installed gateway with
    # management_contract 1 does both with `enterprise bundle anchors
    # install`; an older one gets the wrapper's own writer.
    stage, anchors, log, script = _anchors_harness(tmp_path, """dc_install_anchors "$DC_STAGE/$1.json"
echo "changed=$DC_ANCHORS_CHANGED verb=$DC_ANCHORS_VERB"
[ "$2" = keep ] || dc_restore_anchors""")
    for name, body in (("old", '{"v": 1}'), ("new", '{"v": 2}')):
        (stage / f"{name}.json").write_text(body, encoding="utf-8")
    version = _VERSION_CONTRACT if writer == "command" else _VERSION_BEFORE
    verb = int(writer == "command")

    def run(name: str, then: str) -> tuple[str, list[str]]:
        log.unlink(missing_ok=True)
        result = subprocess.run(["sh", "-c", script, "t", name, then], capture_output=True, text=True, timeout=10,
                                env=_anchors_env(log, anchors, STUB_VERSION=version))
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout, log.read_text(encoding="utf-8").splitlines()

    def installs(calls: list[str]) -> list[str]:
        return [call.split(" --file ")[1] for call in calls if call.startswith("enterprise bundle anchors install")]

    out, calls = run("new", "restore")
    assert out == f"changed=1 verb={verb}\n" and not anchors.exists()
    out, calls = run("old", "keep")
    assert out == f"changed=1 verb={verb}\n" and anchors.read_text() == '{"v": 1}'
    assert oct(anchors.stat().st_mode & 0o777) == "0o644" and oct(anchors.parent.stat().st_mode & 0o777) == "0o755"
    out, calls = run("old", "restore")
    assert out == f"changed=0 verb={verb}\n" and anchors.read_text() == '{"v": 1}'
    out, calls = run("new", "restore")
    assert out == f"changed=1 verb={verb}\n" and anchors.read_text() == '{"v": 1}'
    assert sorted(p.name for p in anchors.parent.iterdir()) == ["bundle-anchors.json"]
    if writer == "shell":
        assert calls == ["--version-json"]
        return
    # The install and the restore: a private root-only copy in the trust
    # folder (the command refuses a source in a sticky or linked folder),
    # with the contract's argv; the copy is gone afterwards.
    source = f"{anchors.parent}/.bundle-anchors.json.mdm-source-"
    assert calls[0] == "--version-json" and len(installs(calls)) == 2, calls
    for call in installs(calls):
        assert call.startswith(source) and call.endswith(" --lock-wait 10m --json"), call
    assert [line for line in calls if re.fullmatch(r"-[rwx-]{9}", line)] == ["-rw-------", "-rw-------"], calls


# A lifecycle result that changed nothing (GAP-0034 tests).
_NOOP_ENSURE_RESULT = {
    "schema_version": 2, "ok": True, "action": "ensure", "noop": True, "noop_reason": "already_applied",
    "profile": "standalone", "platform": "linux", "product_version": "1.0.3", "installed_version": "1.0.3",
    "installed": True, "transaction_pending": False, "services": [],
    "readiness": {"gateway": True, "guardian": True, "enumerator": True, "sensor_helper": True},
    "inspection": {"local": "active", "ai_defense": "disabled"}, "machine_policy": {},
    "enrollment": {"targets": 0, "pending": 0, "failed": 0, "exempt": 0},
    "coverage_complete": True, "security_complete": True, "errors": [],
}


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("reason", ["already_applied", "compliant"])
def test_unix_wrapper_result_reports_the_trust_anchors_it_installed(tmp_path: Path, reason: str) -> None:
    # GAP-0034 (twin of the Windows finding): a kit run that installed other
    # trust anchors, then found the confirmed bundle already applied (or,
    # without a bundle, the deployment compliant), printed the lifecycle's
    # "noop": true. It changed the device, so it is not a no-op, and changes
    # names the anchor file. An unchanged anchor file keeps the no-op.
    text = _text(MDM / "linux" / "defenseclaw-enterprise.sh")
    functions = "\n".join(_shell_function(text, name) for name in ("dc_json_escape", "dc_annotate_anchors_step"))
    anchors = tmp_path / "trust" / "bundle-anchors.json"
    base = dict(_NOOP_ENSURE_RESULT, noop_reason=reason)
    validator = _schema_validator()

    def run(changed: str, previous: str, changes: list[str] | None = None) -> dict:
        document = dict(base)
        if changes is not None:
            document["changes"] = changes
        document["exit_code"] = 0
        result = tmp_path / "result.json"
        result.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        script = f"""DC_STAGE="{tmp_path}" DC_RESULT="{result}" DC_ANCHORS="{anchors}"
DC_ANCHORS_CHANGED={changed} DC_ANCHORS_PREVIOUS="{previous}"
{functions}
dc_annotate_anchors_step
cat "$DC_RESULT"
"""
        completed = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=10)
        assert completed.returncode == 0, completed.stdout + completed.stderr
        out = json.loads(completed.stdout)
        assert not sorted(validator.iter_errors(out), key=str), out
        return out

    rotated = run("1", str(tmp_path / "previous.json"))
    assert rotated["noop"] is False and "noop_reason" not in rotated, rotated
    assert rotated["changes"] == [f"replaced the trust anchors in {anchors}"], rotated
    first = run("1", "", changes=["restarted the gateway"])
    assert first["noop"] is False and "noop_reason" not in first, first
    assert first["changes"] == [f"installed trust anchors in {anchors}", "restarted the gateway"], first
    unchanged = run("0", "")
    assert unchanged["noop"] is True and unchanged["noop_reason"] == reason and "changes" not in unchanged, unchanged


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("os_dir", ["linux", "macos"])
@pytest.mark.parametrize("previous", [False, True])
@pytest.mark.parametrize("applied", [True, False])
def test_unix_wrapper_main_keeps_and_reports_the_anchors_of_a_confirmed_apply(
    tmp_path: Path, os_dir: str, previous: bool, applied: bool
) -> None:
    # dc_main itself, in both copies, with a bundle and a trust anchor file:
    # after the bundle apply succeeds the run commits the anchors (the EXIT
    # trap's anchor restore must not undo them) and the result still names
    # them although the apply found the bundle already applied (GAP-0034).
    # A failed apply puts back the as-found file, which shows the restore is
    # wired to the same run.
    text = _text(MDM / os_dir / "defenseclaw-enterprise.sh").rstrip()
    entry = '\ndc_main "$@"'
    assert text.endswith(entry)
    gateway = tmp_path / "bin" / "defenseclaw-gateway"
    gateway.parent.mkdir()
    apply_stub = (
        'if [ "$1 $2 $3" = "enterprise bundle apply" ]; then\n'
        '    printf \'%s\\n\' "$*" >>"$STUB_LOG"\n'
        '    cat "$STUB_APPLY"\n'
        '    exit "$STUB_APPLY_EXIT"\n'
        'fi\n'
    )
    gateway.write_text(_STUB_GATEWAY.replace("#!/bin/sh\n", "#!/bin/sh\n" + apply_stub, 1), encoding="utf-8")
    gateway.chmod(0o755)
    anchors = tmp_path / "etc" / "trust" / "bundle-anchors.json"
    staged_anchors = tmp_path / "new-anchors.json"
    staged_anchors.write_text('{"v": 2}', encoding="utf-8")
    bundle = tmp_path / "policy.dcbundle"
    bundle.write_bytes(b"signed bundle stand-in")
    stage_parent = tmp_path / "stage"
    stage_parent.mkdir()
    document = dict(_NOOP_ENSURE_RESULT, exit_code=0) if applied else dict(
        _NOOP_ENSURE_RESULT, ok=False, noop=False, noop_reason=None, exit_code=1,
        errors=[{"code": "bundle_apply_failed", "message": "the bundle did not apply"}])
    document = {key: value for key, value in document.items() if value is not None}
    reply = tmp_path / "apply.json"
    reply.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    log = tmp_path / "gateway.log"
    # Stand-ins for the root, platform and trust steps; the anchor install,
    # the bundle apply, the annotation and the EXIT trap run as shipped.
    overrides = f"""
dc_layout() {{
    DC_GATEWAY='{gateway}'
    DC_ANCHORS='{anchors}'
    DC_PACKAGE_RESULT='{tmp_path}/last-package-result.json'
    DC_OS_GROUP=linux
    DC_LOG=''
}}
dc_parse_args() {{ DC_BUNDLE_FILE='{bundle}'; DC_TRUST_ANCHOR_FILE='{staged_anchors}'; }}
dc_platform() {{ echo "$DC_SCRIPT_OS"; }}
dc_validate_args() {{ :; }}
id() {{ echo 0; }}
dc_stage_parent() {{ DC_STAGE_PARENT='{stage_parent}'; }}
dc_sweep_stages() {{ :; }}
dc_stat_uid() {{ echo 0; }}
dc_trusted_path() {{ return 0; }}
dc_binaries_damaged() {{ return 1; }}
chown() {{ :; }}
dc_main
"""
    script = text[: -len(entry)] + "\n" + overrides
    env = _anchors_env(log, anchors, STUB_VERSION=_VERSION_CONTRACT, STUB_APPLY=str(reply),
                       STUB_APPLY_EXIT="0" if applied else "1")
    validator = _schema_validator()
    for shell in ("sh", "bash"):
        log.unlink(missing_ok=True)
        shutil.rmtree(anchors.parent.parent, ignore_errors=True)
        anchors.parent.mkdir(parents=True)
        if previous:
            anchors.write_text('{"v": 1}', encoding="utf-8")
        result = subprocess.run([shell, "-c", script], env=env, capture_output=True, text=True, timeout=30)
        out = json.loads(result.stdout)
        assert not sorted(validator.iter_errors(out), key=str), (shell, out)
        calls = log.read_text(encoding="utf-8").splitlines()
        installs = [call for call in calls if call.startswith("enterprise bundle anchors install")]
        applies = [call for call in calls if call.startswith("enterprise bundle apply")]
        assert len(applies) == 1 and applies[0].startswith(f"enterprise bundle apply --bundle {stage_parent}/"), (shell, calls)
        assert not list(stage_parent.iterdir()), (shell, result.stderr)
        if not applied:
            assert result.returncode == 1 and out["ok"] is False, (shell, result.stdout, result.stderr)
            if previous:
                assert anchors.read_text(encoding="utf-8") == '{"v": 1}' and len(installs) == 2, (shell, calls)
            else:
                assert not anchors.exists() and len(installs) == 1, (shell, calls)
            continue
        assert result.returncode == 0, (shell, result.stdout, result.stderr)
        verb = "replaced the trust anchors in" if previous else "installed trust anchors in"
        assert out["noop"] is False and "noop_reason" not in out, (shell, out)
        assert out["changes"] == [f"{verb} {anchors}"], (shell, out)
        # Committed: one install, no restore, and the new file in place.
        assert len(installs) == 1, (shell, calls)
        assert anchors.read_text(encoding="utf-8") == '{"v": 2}', shell


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize(("version", "untrusted", "missing", "expected"), [
    (_VERSION_CONTRACT, False, False, "verb"),
    (_VERSION_CONTRACT.replace('"management_contract":1', '"management_contract":2'), False, False, "verb"),
    (_VERSION_CONTRACT.replace(':1}', ': 1 }'), False, False, "verb"),
    (_VERSION_BEFORE, False, False, "shell"),
    (_VERSION_CONTRACT.replace('"management_contract":1', '"management_contract":0'), False, False, "shell"),
    ("fail", False, False, "shell"),
    ("not json", False, False, "shell"),
    (_VERSION_CONTRACT, True, False, "shell"),
    (_VERSION_CONTRACT, False, True, "shell"),
])
def test_unix_wrapper_probes_the_installed_gateway_for_the_anchors_command(
    tmp_path: Path, version: str, untrusted: bool, missing: bool, expected: str
) -> None:
    # The probe is --version-json (management_contract 1 or later) on the
    # installed, root-owned gateway; a build without the member, an older
    # build without the flag, an untrusted or missing binary get the writer.
    _, anchors, log, script = _anchors_harness(tmp_path, "if dc_anchors_verb; then echo verb; else echo shell; fi")
    env = _anchors_env(log, anchors, STUB_VERSION=version, T_UNTRUSTED=str(int(untrusted)))
    if missing:
        env["T_GATEWAY"] = str(tmp_path / "bin" / "absent")
    result = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=10, env=env)
    assert (result.returncode, result.stdout) == (0, expected + "\n"), result.stderr


def _anchors_examples() -> list[dict]:
    return json.loads(_text(MDM / "contract" / "anchors-install.schema.json"))["examples"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("case", ["anchor_invalid", "anchor_insecure", "lifecycle_busy", "no_json", "crash"])
def test_unix_wrapper_reports_an_anchors_command_refusal(tmp_path: Path, case: str) -> None:
    # A refusal of `enterprise bundle anchors install` is mdm_anchor_install_failed
    # with the command's exit code (1 refused, 75 busy, anything else 1) and
    # its errors[0].code, or its stderr when it printed no JSON. Nothing is
    # written: the installed file stays, the private copy is removed, and the
    # wrapper does not fall back to its own writer.
    stage, anchors, log, script = _anchors_harness(tmp_path, 'dc_install_anchors "$DC_STAGE/new.json"; echo installed')
    (stage / "new.json").write_text('{"v": 2}', encoding="utf-8")
    anchors.parent.mkdir()
    anchors.write_text('{"v": 1}', encoding="utf-8")
    refusals = {example["errors"][0]["code"]: example for example in _anchors_examples() if not example["ok"]}
    busy = dict(refusals["anchor_invalid"], errors=[{"code": "lifecycle_busy", "message": "another lifecycle run holds the lock"}])
    reply, code, stderr = {
        "anchor_invalid": (refusals["anchor_invalid"], 1, ""),
        "anchor_insecure": (refusals["anchor_insecure"], 1, ""),
        "lifecycle_busy": (busy, 75, ""),
        "no_json": (None, 1, "Error: unknown flag: --lock-wait"),
        "crash": (None, 3, "panic: boom"),
    }[case]
    reply_file = tmp_path / "reply.json"
    reply_file.write_text(json.dumps(reply, indent=2) + "\n" if reply else "", encoding="utf-8")
    env = _anchors_env(log, anchors, STUB_VERSION=_VERSION_CONTRACT, STUB_REPLY=str(reply_file),
                       STUB_EXIT=str(code), STUB_STDERR=stderr)
    result = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=10, env=env)
    prefix = "enterprise bundle anchors install did not install the trust anchor file"
    expected = {
        "anchor_invalid": (1, f"{prefix} (anchor_invalid): {refusals['anchor_invalid']['errors'][0]['message']}"),
        "anchor_insecure": (1, f"{prefix} (anchor_insecure): {refusals['anchor_insecure']['errors'][0]['message']}"),
        "lifecycle_busy": (75, f"{prefix} (lifecycle_busy): another lifecycle run holds the lock"),
        "no_json": (1, f"{prefix}: Error: unknown flag: --lock-wait"),
        "crash": (1, f"{prefix}: panic: boom"),
    }[case]
    assert (result.returncode, result.stdout.strip()) == (expected[0], f"fail {expected[0]} mdm_anchor_install_failed {expected[1]}")
    assert anchors.read_text() == '{"v": 1}'
    assert sorted(p.name for p in anchors.parent.iterdir()) == ["bundle-anchors.json"]


_PARITY_BUNDLE_CONFIG = """config_version: 9
deployment_mode: managed_enterprise
guardrail:
  enabled: true
  mode: action
  block_at: HIGH
  rule_pack: p2int
  custom_packs:
    p2int:
      path: policies/guardrail/p2int
      digest: sha256:{digest}
  connectors:
    claudecode:
      enabled: true
"""
_PARITY_DIGEST = "8" * 64


def _parity_bundle(path: Path, config: str, packs: tuple[str, ...] = ("p2int",), pin: str | None = None) -> Path:
    """A .dcbundle (tar.gz) with manifest.json, config.yaml and one rule file per pack."""
    import io
    import tarfile

    raw = config.encode("utf-8")
    files = [{"path": "config.yaml", "sha256": pin or hashlib.sha256(raw).hexdigest(), "size": len(raw)}]
    members = {"config.yaml": raw}
    for pack in packs:
        rule = f"rules: [{pack}]\n".encode()
        name = f"policies/guardrail/{pack}/rules/marker.yaml"
        files.append({"path": name, "sha256": hashlib.sha256(rule).hexdigest(), "size": len(rule)})
        members[name] = rule
    manifest = json.dumps({"schema_version": 1, "version": 1, "files": files}, indent=2).encode()
    with tarfile.open(path, "w:gz") as archive:
        for name, data in (("manifest.json", manifest), ("manifest.sig", b"sig"), *members.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def _parity_script() -> str:
    text = _text(MDM / "linux" / "defenseclaw-enterprise.sh")
    names = ("dc_sha256", "dc_guardrail_block", "dc_custom_pack_path", "dc_top_block", "dc_plain_bytes",
             "dc_plain_yaml", "dc_check_base_config")
    return "DC_SCRIPT_OS=linux\n" + "\n".join(_shell_function(text, name) for name in names) + '''
DC_STAGE=$1
reason=$(dc_check_base_config "$2" "$3") || { echo "refused: $reason"; exit 1; }
echo ok
'''


@pytest.mark.skipif(os.name != "posix" or shutil.which("sha256sum") is None, reason="POSIX shell scripts; needs sha256sum")
@pytest.mark.parametrize("shell", [s for s in ("sh", "bash", "dash") if shutil.which(s)])
def test_unix_wrapper_base_config_must_carry_the_bundle_guardrail_policy(tmp_path: Path, shell: str) -> None:
    # GAP-0090: a base config delivered with a signed bundle is what the
    # hooks answer under until the bundle applies, so its guardrail block must
    # be the bundle's, apart from where each custom pack is preinstalled.
    bundle_config = _PARITY_BUNDLE_CONFIG.format(digest=_PARITY_DIGEST)
    bundle = _parity_bundle(tmp_path / "v1.dcbundle", bundle_config)
    base_ok = bundle_config.replace("path: policies/guardrail/p2int", 'path: "/Library/Application Support/DefenseClaw-RulePacks/p2int"')

    def check(base: str, bundle_path: Path = bundle) -> str:
        stage = tmp_path / "stage"
        stage.mkdir(exist_ok=True)
        config = tmp_path / "base.yaml"
        config.write_bytes(base.encode("utf-8"))
        result = subprocess.run([shell, "-c", _parity_script(), "t", str(stage), str(config), str(bundle_path)],
                                capture_output=True, text=True, timeout=30)
        return result.stdout.strip() + (f" rc={result.returncode}" if result.returncode not in (0, 1) else "")

    assert check(base_ok) == "ok", shell
    assert check(base_ok.replace("\n", "\r\n")) == "ok", shell
    assert check(base_ok.replace('"/Library', "'/Library").replace('p2int"', "p2int'")) == "ok", shell
    assert check("# administrator copy\n" + base_ok + "ai_discovery:\n  enabled: true\n") == "ok", shell
    # The live1 Linux base: claudecode protected with HIGH but no pack.
    no_pack = bundle_config.replace("  rule_pack: p2int\n", "").split("  custom_packs:\n")[0] + (
        "  connectors:\n    claudecode:\n      enabled: true\n")
    assert check(no_pack) == "refused: the base config must select the bundle rule pack p2int", shell
    assert check(base_ok.replace("block_at: HIGH", "block_at: CRITICAL")).startswith(
        "refused: the base config guardrail: block differs from the signed bundle's"), shell
    assert check(base_ok.replace("mode: action", "mode: observe")).startswith(
        "refused: the base config guardrail: block differs"), shell
    assert check(base_ok.replace(_PARITY_DIGEST, "9" * 64)).startswith(
        "refused: the base config guardrail: block differs"), shell
    assert check(base_ok.replace("      enabled: true\n", "      enabled: true\n    codex: {}\n")).startswith(
        "refused: the base config guardrail: block differs"), shell
    assert check(bundle_config) == (
        "refused: the base config must name an absolute, preinstalled path for bundle rule pack p2int"), shell
    assert check(base_ok.replace("    p2int:\n", "    other:\n")) == "refused: the base config must define custom_packs.p2int", shell
    assert check(base_ok + "guardrail:\n  enabled: false\n") == (
        "refused: the base config and the bundle config must each have one plain guardrail: block"), shell
    assert check(base_ok.replace("guardrail:\n", "")) == (
        "refused: the base config and the bundle config must each have one plain guardrail: block"), shell
    tampered = _parity_bundle(tmp_path / "tampered.dcbundle", bundle_config, pin="0" * 64)
    assert check(base_ok, tampered) == "refused: the bundle config.yaml does not match the signed manifest files[] pin", shell
    relative = _parity_bundle(tmp_path / "relative.dcbundle", bundle_config.replace("policies/guardrail/p2int", "/opt/p2int"))
    assert check(base_ok, relative) == (
        "refused: the bundle config.yaml must name policies/guardrail/p2int as custom_packs.p2int.path"), shell
    (tmp_path / "junk.dcbundle").write_bytes(b"not a bundle")
    assert check(base_ok, tmp_path / "junk.dcbundle") == "refused: the bundle has no readable manifest.json"
    # The 256 KiB cap holds even when the oversized config.yaml matches its pin.
    padded = bundle_config + "# " + "x" * 262144 + "\n"
    padded_bundle = _parity_bundle(tmp_path / "padded.dcbundle", padded)
    assert check(padded.replace("path: policies/guardrail/p2int", "path: /etc/dc-packs/p2int"), padded_bundle) == (
        "refused: the bundle config.yaml is larger than 262144 bytes"), shell
    # A pack folder name that is not a plain name is refused as such.
    odd_bundle = _parity_bundle(tmp_path / "odd.dcbundle", bundle_config, packs=("p2int", "p2;int"))
    assert check(base_ok, odd_bundle) == "refused: the bundle names a rule pack folder that is not a plain name", shell
    # custom_packs ends where the guardrail block's next key starts.
    assert check(base_ok.replace("    p2int:\n", "    other:\n").replace(
        "  connectors:\n", "  connectors:\n    p2int:\n      path: /etc/dc-packs/p2int\n")) == (
        "refused: the base config must define custom_packs.p2int"), shell
    # Blank lines that end the guardrail block are not part of it.
    assert check(base_ok + "\n\n" + "ai_discovery:\n  enabled: true\n") == "ok", shell
    # A full-line comment, even at column 0, does not end the guardrail
    # block: the keys after it are compared, and comments are not.
    commented = _parity_bundle(tmp_path / "commented.dcbundle", bundle_config.replace("  connectors:\n", "# agents\n  connectors:\n"))
    commented_base = base_ok.replace("  connectors:\n", "# agents\n  connectors:\n")
    assert check(commented_base, commented) == "ok", shell
    assert check(commented_base.replace("      enabled: true\n", "      enabled: false\n"), commented).startswith(
        "refused: the base config guardrail: block differs"), shell
    assert check(base_ok.replace("  connectors:\n", "  # agents\n  connectors:\n")) == "ok", shell
    # A bundle on a built-in pack needs an identical guardrail block.
    builtin = "guardrail:\n  enabled: true\n  mode: action\n  block_at: HIGH\n  rule_pack: default\n"
    builtin_bundle = _parity_bundle(tmp_path / "builtin.dcbundle", "config_version: 9\n" + builtin, packs=())
    assert check("config_version: 9\n" + builtin, builtin_bundle) == "ok", shell
    assert check("config_version: 9\n" + builtin.replace("HIGH", "MEDIUM"), builtin_bundle).startswith(
        "refused: the base config guardrail: block differs"), shell
    # Every pack the bundle ships is compared.
    two = bundle_config.replace("  connectors:\n", "    extra:\n      path: policies/guardrail/extra\n  connectors:\n")
    two_bundle = _parity_bundle(tmp_path / "two.dcbundle", two, packs=("p2int", "extra"))
    two_base = two.replace("policies/guardrail/p2int", "/etc/dc-packs/p2int").replace("policies/guardrail/extra", "/etc/dc-packs/extra")
    assert check(two_base, two_bundle) == "ok", shell
    assert check(two_base.replace("/etc/dc-packs/extra", "packs/extra"), two_bundle) == (
        "refused: the base config must name an absolute, preinstalled path for bundle rule pack extra"), shell


_HOOK_MODE_REFUSAL = {
    "claude_code": "claude_code.mode overrides the guardrail mode for Claude Code",
    "codex": "codex.mode overrides the guardrail mode for Codex",
    "connector_hooks": "connector_hooks.<connector>.mode overrides the guardrail mode for that connector",
    "application_protection": "it sets the guardrail policy of automatically protected agents",
}


@pytest.mark.skipif(os.name != "posix" or shutil.which("sha256sum") is None, reason="POSIX shell scripts; needs sha256sum")
@pytest.mark.parametrize("shell", [s for s in ("sh", "bash", "dash") if shutil.which(s)])
def test_unix_wrapper_base_config_must_carry_the_bundle_hook_modes(tmp_path: Path, shell: str) -> None:
    # GAP-0090 verify r1: hookModeForConfig takes claude_code.mode,
    # codex.mode and connector_hooks.<c>.mode before the guardrail mode, and
    # application_protection is part of the guardrail policy, so a base
    # config with the bundle's exact guardrail block but its own value for
    # any of them gave 6 marker ALLOW live. Those blocks must be the bundle's,
    # or absent from both.
    bundle_config = _PARITY_BUNDLE_CONFIG.format(digest=_PARITY_DIGEST)
    bundle = _parity_bundle(tmp_path / "v1.dcbundle", bundle_config)
    base_ok = bundle_config.replace("path: policies/guardrail/p2int", "path: /etc/dc-packs/p2int")

    def check(base: str, bundle_path: Path = bundle) -> str:
        stage = tmp_path / "stage"
        stage.mkdir(exist_ok=True)
        config = tmp_path / "base.yaml"
        config.write_bytes(base.encode("utf-8"))
        result = subprocess.run([shell, "-c", _parity_script(), "t", str(stage), str(config), str(bundle_path)],
                                capture_output=True, text=True, timeout=30)
        return result.stdout.strip() + (f" rc={result.returncode}" if result.returncode not in (0, 1) else "")

    def refused(key: str) -> str:
        return (f"refused: the base config {key}: block differs from the signed bundle's ({_HOOK_MODE_REFUSAL[key]}); "
                f"use the bundle's {key}: block, or leave it out of both")

    assert check(base_ok) == "ok", shell
    rows = {
        "claude_code": ("claude_code: {mode: observe}\n", "claude_code:\n  enabled: true\n  mode: observe\n",
                        '"claude_code":\n  mode: observe\n', "'claude_code' : {mode: observe}\n"),
        "codex": ("codex:\n  mode: observe\n", "codex: {mode: observe}\n"),
        "connector_hooks": ("connector_hooks:\n  claudecode:\n    mode: observe\n",
                            "connector_hooks: {claudecode: {mode: observe}}\n"),
        "application_protection": ("application_protection:\n  enabled: true\n  guardrail:\n    mode: observe\n",
                                   "application_protection: {enabled: true}\n"),
    }
    for key, blocks in rows.items():
        for block in blocks:
            assert check(base_ok + block) == refused(key), (shell, block)
    # The key is found at the top of a file with a byte order mark and CRLF.
    assert check("\ufeffclaude_code: {mode: observe}\r\n" + base_ok) == refused("claude_code"), shell
    # The same blocks in both pass; comments, blank lines and CRLF do not count.
    modes = ("claude_code:\n  enabled: true\n  mode: action\ncodex:\n  mode: action\n"
             "connector_hooks:\n  claudecode:\n    mode: action\napplication_protection:\n  enabled: false\n")
    modes_bundle = _parity_bundle(tmp_path / "modes.dcbundle", bundle_config + modes)
    with_modes = base_ok + "# hook modes, copied from the bundle\n" + modes.replace(
        "  enabled: true\n  mode: action\ncodex", "  enabled: true\n  # as in the bundle\n\n# note\n  mode: action\n\ncodex")
    assert check(with_modes, modes_bundle) == "ok", shell
    assert check(with_modes.replace("\n", "\r\n"), modes_bundle) == "ok", shell
    # A block the bundle sets and the base config leaves out is refused too.
    assert check(base_ok, modes_bundle) == refused("claude_code"), shell
    assert check(with_modes.replace("codex:\n  mode: action\n", ""), modes_bundle) == refused("codex"), shell
    assert check(with_modes.replace("    mode: action\n", "    mode: observe\n"), modes_bundle) == refused("connector_hooks"), shell
    assert check(with_modes.replace("  enabled: false\n", "  enabled: true\n"), modes_bundle) == (
        refused("application_protection")), shell


_NOT_PLAIN = ("is not a plain top-level key; write each top-level key in lowercase letters, digits and underscores, "
              "plain or in quotes, without an escape, tag, anchor, alias, merge key, complex key or {...} or [...]")
_OPEN_QUOTE = "leaves a quoted value open; end each quoted value on the line it starts on"
_OPEN_FLOW = "leaves a {...} or [...] open; end each one on the line it starts on"


def _other_letters(key: str) -> str:
    return f"writes the top-level key {key} in other letters; write it in lowercase"


@pytest.mark.skipif(os.name != "posix" or shutil.which("sha256sum") is None, reason="POSIX shell scripts; needs sha256sum")
@pytest.mark.parametrize("shell", [s for s in ("sh", "bash", "dash") if shutil.which(s)])
def test_unix_wrapper_base_config_must_be_written_plainly(tmp_path: Path, shell: str) -> None:
    # GAP-0090 verify r2: the compare finds a key by its text. The product's
    # loader also read "claude_code":, !!str claude_code: and
    # ? claude_code as claude_code (5-6 marker ALLOW live), and a quoted value
    # that runs on to the next line hid the whole guardrail block.
    bundle_config = _PARITY_BUNDLE_CONFIG.format(digest=_PARITY_DIGEST)
    bundle = _parity_bundle(tmp_path / "v1.dcbundle", bundle_config)
    base_ok = bundle_config.replace("path: policies/guardrail/p2int", "path: /etc/dc-packs/p2int")
    after = base_ok.count("\n") + 1
    head, rest = base_ok.split("guardrail:\n")
    guardrail = "guardrail:\n" + rest

    def check(base: str) -> str:
        stage = tmp_path / "stage"
        stage.mkdir(exist_ok=True)
        config = tmp_path / "base.yaml"
        config.write_bytes(base.encode("utf-8"))
        result = subprocess.run([shell, "-c", _parity_script(), "t", str(stage), str(config), str(bundle)],
                                capture_output=True, text=True, timeout=30)
        return result.stdout.strip() + (f" rc={result.returncode}" if result.returncode not in (0, 1) else "")

    def refused(line: int, why: str) -> str:
        return f"refused: the base config line {line} {why}"

    for block in ('"claude\\u005fcode":\n  mode: observe\n', "!!str claude_code: {mode: observe}\n",
                  "? claude_code\n: {mode: observe}\n", "&cc claude_code: {mode: observe}\n",
                  "<<: {claude_code: {mode: observe}}\n", "*cc : {mode: observe}\n", "...\n",
                  "---\nclaude_code: {mode: observe}\n"):
        assert check(base_ok + block) == refused(after, _NOT_PLAIN), (shell, block)
    assert check("{config_version: 9}\n") == refused(1, _NOT_PLAIN), shell
    assert check("%YAML 1.2\n---\n" + base_ok) == refused(1, _NOT_PLAIN), shell
    assert check(base_ok + "Claude_Code: {mode: observe}\n") == refused(after, _other_letters("claude_code")), shell
    assert check(base_ok + '"CODEX":\n  mode: observe\n') == refused(after, _other_letters("codex")), shell
    assert check(base_ok.replace("guardrail:\n", "Guardrail:\n")) == refused(3, _other_letters("guardrail")), shell
    # A quoted value or a [...] that runs on hides the guardrail block from
    # the loader (it reads tenant_id "t guardrail: enabled: true ...").
    assert check(head + 'tenant_id: "t\n' + guardrail + 'workspace_id: w"\n') == refused(3, _OPEN_QUOTE), shell
    assert check(head + "tenant_id: 't\n" + guardrail + "workspace_id: w'\n") == refused(3, _OPEN_QUOTE), shell
    assert check(head + 'tenant_id: "t\\"\n' + guardrail + 'workspace_id: w"\n') == refused(3, _OPEN_QUOTE), shell
    assert check(head + "tenant_id: [t,\n" + guardrail + "workspace_id: w]\n") == refused(3, _OPEN_FLOW), shell
    # Lines of a block scalar are skipped only while they are deeper than the
    # key (or the - item) that owns it.
    nested = head + 'ai_discovery:\n  items:\n    - note: |\n        say "hi\n      other: "t\n' + guardrail + 'w: v"\n'
    assert check(nested) == refused(7, _OPEN_QUOTE), shell
    dashes = head + 'ai_discovery:\n  items:\n  - - |\n      text\n    - "t\n' + guardrail + 'w: v"\n'
    assert check(dashes) == refused(7, _OPEN_QUOTE), shell
    # Plain spellings, comments, one-line quoted values and flows, plain
    # values with quote characters and block scalars all pass.
    plain = (base_ok + "# it's \"fine\n" + '"ai_discovery":\n  enabled: true\n' + "scanners:\n"
             "  note: it's a \"plain\" value # with a 'comment\n  url: http://127.0.0.1:1/x\n"
             "  tags: [a, 'b', \"c\\\"d\", {e: 'f'}]\n  text: |\n    say \"hi\n    it's: 'open\n\n"
             "  more: >-\n    a \"b\n  'quoted': 'it''s'\n  list:\n  - |\n    x \"y\n  - z\n")
    assert check(plain) == "ok", shell
    assert check("---\n" + base_ok) == "ok", shell
    assert check("\ufeff" + base_ok) == "ok", shell


def _not_ascii(what: str) -> str:
    return f"has {what}; write the base config in plain ASCII with LF or CRLF line ends"


_LONE_CR = "a carriage return (CR) that is not followed by a line feed (LF)"


@pytest.mark.skipif(os.name != "posix" or shutil.which("sha256sum") is None, reason="POSIX shell scripts; needs sha256sum")
@pytest.mark.parametrize("shell", [s for s in ("sh", "bash", "dash") if shutil.which(s)])
def test_unix_wrapper_base_config_must_be_plain_ascii(tmp_path: Path, shell: str) -> None:
    # GAP-0090 verify r3: the loader also starts a new line at a lone CR, NEL,
    # LS and PS, but the text checks split only at LF, so a top-level key
    # after one passed the compare (6 marker ALLOW live), and a comment line
    # ending in CR could open a quote that hides the guardrail block. Every
    # byte must be printable ASCII or LF, a CR only before an LF, and a byte
    # order mark only first.
    bundle_config = _PARITY_BUNDLE_CONFIG.format(digest=_PARITY_DIGEST)
    bundle = _parity_bundle(tmp_path / "v1.dcbundle", bundle_config)
    base_ok = bundle_config.replace("path: policies/guardrail/p2int", "path: /etc/dc-packs/p2int").encode()
    after = base_ok.count(b"\n") + 1
    head, rest = base_ok.split(b"guardrail:\n")
    guardrail = b"guardrail:\n" + rest
    hidden = b"claude_code: {mode: observe}\n"

    def check(base: bytes, prelude: str = "") -> str:
        stage = tmp_path / "stage"
        stage.mkdir(exist_ok=True)
        config = tmp_path / "base.yaml"
        config.write_bytes(base)
        result = subprocess.run([shell, "-c", prelude + _parity_script(), "t", str(stage), str(config), str(bundle)],
                                capture_output=True, text=True, timeout=30)
        return result.stdout.strip() + (f" rc={result.returncode}" if result.returncode not in (0, 1) else "")

    def refused(line: int, what: str) -> str:
        return f"refused: the base config line {line} {_not_ascii(what)}"

    rows = {
        b"ai_discovery:\n  enabled: true\r" + hidden: (after + 1, _LONE_CR),
        b"# administrator note\r" + hidden: (after, _LONE_CR),
        b"ai_discovery:\n  enabled: true\xc2\x85" + hidden: (after + 1, "a NEL (U+0085) line break"),
        b"ai_discovery:\n  enabled: true\xe2\x80\xa8" + hidden: (after + 1, "an LS (U+2028) line break"),
        b"ai_discovery:\n  enabled: true\xe2\x80\xa9" + hidden: (after + 1, "a PS (U+2029) line break"),
        b"ai_discovery:\n  enabled: true\x00\n": (after + 1, "a NUL byte"),
        b"ai_discovery:\n  enabled:\ttrue\n": (after + 1, "a tab"),
        b"\tclaude_code: {mode: observe}\n": (after, "a tab"),
        b"ai_discovery:\n  enabled: true\x0b\n": (after + 1, "a vertical tab"),
        b"ai_discovery:\n  enabled: true\x0c\n": (after + 1, "a form feed"),
        b"ai_discovery:\n  enabled: true\x7f\n": (after + 1, "a control character (0x7F)"),
        "# caf\u00e9\n".encode(): (after, "a non-ASCII byte (0xC3)"),
        b"\xef\xbb\xbf# a second byte order mark\n": (after, "a byte order mark that is not at the start of the file"),
        b"ai_discovery:\n  enabled: true\r": (after + 1, _LONE_CR),
        b"# cut off \xe2\x80": (after, "a non-ASCII byte (0xE2)"),
    }
    for extra, (line, what) in rows.items():
        assert check(base_ok + extra) == refused(line, what), (shell, extra)
        # The first fault is the one named.
        assert check(base_ok + extra + b"\t\x00\n") == refused(line, what), (shell, extra)
    # A comment line that ends in CR opens a quote the loader reads as
    # tenant_id "t guardrail: ...", hiding the guardrail block.
    assert check(head + b"# note\rtenant_id: \"t\n" + guardrail + b"workspace_id: w\"\n") == refused(3, _LONE_CR), shell
    assert check(b"\xef\xbb" + base_ok) == refused(1, "a non-ASCII byte (0xEF)"), shell
    # Plain ASCII with LF or CRLF, with or without a byte order mark, passes.
    assert check(base_ok) == "ok", shell
    assert check(base_ok.replace(b"\n", b"\r\n")) == "ok", shell
    assert check(b"\xef\xbb\xbf" + base_ok) == "ok", shell
    assert check(b"\xef\xbb\xbf" + base_ok.replace(b"\n", b"\r\n")) == "ok", shell
    # A file od does not read in full is refused.
    assert check(base_ok, prelude="od() { :; }\n") == "refused: the base config could not be read byte by byte", shell


@pytest.mark.skipif(os.name != "posix" or shutil.which("sha256sum") is None, reason="POSIX shell scripts; needs sha256sum")
def test_unix_wrapper_applies_the_base_config_before_the_anchors_and_the_bundle(tmp_path: Path) -> None:
    # GAP-0090: with a base config and a bundle, the wrapper refuses a
    # mismatch before the package step, applies the base config before the
    # trust anchors (so the hooks never answer under a weaker policy), and
    # skips it once the device is in bundle mode.
    text = _text(MDM / "linux" / "defenseclaw-enterprise.sh")
    names = ("dc_sha256", "dc_guardrail_block", "dc_custom_pack_path", "dc_top_block", "dc_plain_bytes",
             "dc_plain_yaml", "dc_check_base_config", "dc_main")
    bundle_config = _PARITY_BUNDLE_CONFIG.format(digest=_PARITY_DIGEST)
    bundle = _parity_bundle(tmp_path / "v1.dcbundle", bundle_config)
    good = tmp_path / "base.yaml"
    good.write_text(bundle_config.replace("policies/guardrail/p2int", "/etc/dc-packs/p2int"), encoding="utf-8")
    weak = tmp_path / "weak.yaml"
    weak.write_text(bundle_config.replace("block_at: HIGH", "block_at: CRITICAL").replace(
        "policies/guardrail/p2int", "/etc/dc-packs/p2int"), encoding="utf-8")
    # GAP-0090 verify r3: a key after a lone CR is a top-level key for the loader.
    hidden = tmp_path / "hidden.yaml"
    hidden.write_bytes(good.read_bytes() + b"ai_discovery:\n  enabled: true\rclaude_code: {mode: observe}\n")
    (tmp_path / "anchors.json").write_text('{"schema_version": 1}\n', encoding="utf-8")
    calls = tmp_path / "calls.log"
    script = "\n".join(_shell_function(text, name) for name in names) + f'''
DC_SCRIPT_OS=linux DC_ACTION=ensure DC_EXIT_FAILURE=1 DC_EXIT_INVALID=2 DC_REFUSE_CAPABILITY_LOSS=0
DC_MAX_CONFIG_BYTES=1048576 DC_MAX_BUNDLE_BYTES=4194304 DC_MAX_ANCHORS_BYTES=65536 DC_MAX_SECRET_BYTES=16384
DC_CONFIG_STDIN=0 DC_SECRET_STDIN=0 DC_SECRET_NAME="" DC_SOURCE_URL="" DC_TRUST_ACL=""
DC_SOURCE=/staged/defenseclaw-enterprise.rpm DC_CONFIG_FILE="" DC_BUNDLE_FILE={bundle}
DC_T_CONFIG=$1 DC_T_VIA=$3
case "$DC_T_VIA" in
    file) DC_CONFIG_FILE=$DC_T_CONFIG ;;
    stdin) DC_CONFIG_STDIN=1 ;;
esac
DC_TRUST_ANCHOR_FILE={tmp_path / "anchors.json"} DC_ANCHORS=$2 DC_GATEWAY=/opt/defenseclaw/bin/defenseclaw-gateway
DC_OS_GROUP=linux DC_PRODUCT_VERSION="" DC_RESULT=""
call() {{ printf '%s\\n' "$*" >>"{calls}"; }}
dc_layout() {{ :; }}; dc_log() {{ :; }}; dc_parse_args() {{ :; }}; dc_validate_args() {{ :; }}
dc_platform() {{ echo linux; }}; id() {{ echo 0; }}; dc_stat_uid() {{ echo 0; }}
dc_stage_parent() {{ DC_STAGE_PARENT={tmp_path}; }}; dc_sweep_stages() {{ :; }}
dc_stage_file() {{ cp "$1" "$2"; }}; dc_read_bounded() {{ cat >"$1"; }}
dc_inline_config() {{ [ "$DC_T_VIA" != inline ] || cat "$DC_T_CONFIG"; }}
dc_inline_bundle() {{ :; }}; dc_inline_trust_anchors() {{ :; }}
dc_trusted_path() {{ :; }}; dc_binaries_damaged() {{ return 1; }}
dc_stage_source() {{ :; }}; dc_install_package() {{ call package; }}
dc_run_lifecycle_retry() {{ shift; call "$@"; }}
dc_install_anchors() {{ call anchors; }}; dc_restore_anchors() {{ call restore; }}
dc_annotate_package_step() {{ :; }}; dc_annotate_anchors_step() {{ :; }}; dc_emit_result() {{ :; }}
dc_fail_result() {{ call "fail $2"; exit "$1"; }}
dc_cleanup() {{ rm -rf "$DC_STAGE"; }}; dc_stop_child() {{ :; }}
dc_main
'''

    # PATH without tar: every other command the stubs leave to the system.
    no_tar = tmp_path / "no-tar-bin"
    no_tar.mkdir()
    for folder in dict.fromkeys(os.environ.get("PATH", "").split(os.pathsep)):
        if not folder or not os.path.isdir(folder):
            continue
        for name in os.listdir(folder):
            target = no_tar / name
            if name not in ("tar", "gtar", "bsdtar") and not target.exists() and os.access(os.path.join(folder, name), os.X_OK):
                target.symlink_to(os.path.join(folder, name))

    def run(config: Path, anchors: str = "absent", via: str = "file", path: str | None = None) -> tuple[int, list[str]]:
        calls.unlink(missing_ok=True)
        installed = tmp_path / "etc-trust-bundle-anchors.json"
        installed.unlink(missing_ok=True)
        if anchors == "present":
            installed.write_text("{}", encoding="utf-8")
        elif anchors == "dangling":
            installed.symlink_to(tmp_path / "missing-anchors.json")
        env = dict(os.environ, PATH=path) if path else None
        with config.open("rb") as stdin:
            result = subprocess.run(["sh", "-c", script, "t", str(config), str(installed), via],
                                    stdin=stdin, capture_output=True, text=True, timeout=60, env=env)
        lines = calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []
        return result.returncode, [line.split(" --config=")[0] + (" --config" if "--config=" in line else "")
                                   for line in lines]

    # --config-file, --config-stdin and the inline config are all checked and
    # applied before the anchors (the Intune scripts use the inline config).
    for via in ("file", "stdin", "inline"):
        code, order = run(good, via=via)
        assert code == 0, (via, order)
        assert order[:3] == ["package", "linux ensure --reason mdm --lock-wait 10m --config", "anchors"], (via, order)
        assert len(order) == 4 and order[3].startswith("bundle apply --bundle "), (via, order)
        assert order[3].endswith(" --reason mdm --lock-wait 10m"), (via, order)
        code, order = run(weak, via=via)
        assert (code, order) == (2, ["fail mdm_base_config_mismatch"]), (via, order)
        code, order = run(hidden, via=via)
        assert (code, order) == (2, ["fail mdm_base_config_mismatch"]), (via, order)
        code, order = run(good, via=via, path=str(no_tar))
        assert (code, order) == (1, ["fail mdm_tar_missing"]), (via, order)
    # In bundle mode (anchors installed, even as a link) the base config is not used.
    for anchors in ("present", "dangling"):
        code, order = run(good, anchors=anchors)
        assert code == 0 and order[:2] == ["package", "anchors"] and order[2].startswith("bundle apply"), (anchors, order)
        assert not any("ensure" in line for line in order), (anchors, order)


def test_bundle_capability_loss_flag_reaches_apply() -> None:
    for platform in ("linux", "macos"):
        script = _text(MDM / platform / "defenseclaw-enterprise.sh")
        assert "--refuse-capability-loss) DC_REFUSE_CAPABILITY_LOSS=1" in script
        assert 'bundle apply --bundle "$bundle" --reason mdm --refuse-capability-loss' in script
    wrapper = _text(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1")
    assert "REFUSECAPABILITYLOSS=1" in wrapper
    assert "'--refuse-capability-loss'" in wrapper


_BUNDLE_ID = "b-01JABCDEFGHJKMNPQRSTVWXYZ0"


def _bundle_status(state: str, applied: bool, error_code: str = "") -> str:
    receipt = {"bundle_id": _BUNDLE_ID, "version": 12, "state": state}
    if error_code:
        receipt["error_code"] = error_code
    return json.dumps({
        "schema_version": 1, "command": "status", "ok": True, "bundle_mode": True,
        "current": {"bundle_id": _BUNDLE_ID, "version": 12, "manifest_sha256": "ab", "dir": "v12-b-01JABC"},
        "last_good": None, "floor": 12,
        "last_receipt": {"receipt_id": "r-1", "bundle_id": "b-other", "version": 99, "state": "confirmed"},
        "bundle": receipt, "gateway_checked": True, "applied": applied, "warnings": [], "errors": [],
    }, indent=2)


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_detect_bundle_requirement_and_status(tmp_path: Path) -> None:
    # --require-bundle reads the confirmed current bundle and the gateway
    # check of `enterprise bundle status`, never the nested last receipt;
    # --bundle-status prints "<id> <version> <state>" in every format.
    text = _text(MDM / "linux" / "detect.sh")
    names = ("dc_json_top", "dc_json_field", "dc_json_true", "dc_json_object", "dc_bundle_line", "dc_report",
             "dc_bundle_status", "dc_require_bundle")
    functions = "\n".join(_shell_function(text, name) for name in names)
    script = functions + '''
DC_FORMAT=$1 DC_BUNDLE_STATUS=0
if [ "$3" = status ]; then DC_BUNDLE_STATUS=1; dc_bundle_status "$2"; fi
dc_require_bundle "$2" "$3"
dc_report 1 1.2.3 ""
'''
    docs = {
        "confirmed": _bundle_status("confirmed", True),
        "unenforced": _bundle_status("confirmed", False),
        "failed": _bundle_status("failed", True, "signature_invalid"),
        "replay": json.dumps({**json.loads(_bundle_status("failed", True, "version_not_newer")),
                              "last_receipt": {"receipt_id": "r-current", "bundle_id": _BUNDLE_ID,
                                               "version": 12, "state": "confirmed"},
                              "last_refusal": {"receipt_id": "r-replay", "bundle_id": "b-older",
                                               "version": 11, "error_code": "version_not_newer",
                                               "time": "2026-10-13T06:16:41Z"}}),
        "empty": json.dumps({"ok": True, "current": None, "bundle": None, "applied": False}),
        "refused": json.dumps({"ok": False, "errors": [{"code": "not_root"}]}),
    }
    gateways = {}
    for name, doc in docs.items():
        (tmp_path / f"{name}.json").write_text(doc, encoding="utf-8")
        gateway = tmp_path / f"gateway-{name}"
        gateway.write_text(
            '#!/bin/sh\n[ "$*" = "enterprise bundle status --json" ] || exit 9\n'
            f'cat "{tmp_path / f"{name}.json"}"\n',
            encoding="utf-8",
        )
        gateway.chmod(0o755)
        gateways[name] = str(gateway)
    for shell in ("sh", "dash", "bash"):
        if not shutil.which(shell):
            continue

        def run(fmt: str, name: str, want: str, shell: str = shell) -> subprocess.CompletedProcess[str]:
            return subprocess.run([shell, "-c", script, "detect", fmt, gateways[name], want], capture_output=True, text=True)

        ok = run("exit", "confirmed", "12")
        assert (ok.returncode, ok.stdout) == (0, f"DefenseClaw Enterprise 1.2.3, policy bundle {_BUNDLE_ID} version 12\n"), shell
        assert run("exit", "confirmed", _BUNDLE_ID).returncode == 0, shell
        assert run("value", "confirmed", "11").stdout == "1.2.3\n", shell
        for name, want, value in (
            ("confirmed", "13", "bundle-outdated"), ("confirmed", "b-01JABCDEFGHJKMNPQRSTVWXYZ1", "bundle-mismatch"),
            ("unenforced", "12", "bundle-not-enforced"), ("empty", "1", "bundle-missing"), ("refused", "1", "bundle-missing"),
        ):
            assert run("value", name, want).stdout == f"{value}\n", (shell, name, want)
            failed = run("exit", name, want)
            assert failed.returncode == 1 and failed.stdout == "" and failed.stderr, (shell, name, want)
        for name, line in (
            ("confirmed", f"{_BUNDLE_ID} 12 confirmed"), ("unenforced", f"{_BUNDLE_ID} 12 not-enforced"),
            ("replay", f"{_BUNDLE_ID} 12 confirmed"),
            ("failed", f"{_BUNDLE_ID} 12 failed:signature_invalid"), ("empty", "none 0 none"), ("refused", "none 0 unknown"),
        ):
            for fmt, out in (("exit", line), ("value", line), ("jamf", f"<result>{line}</result>")):
                status = run(fmt, name, "status")
                assert (status.returncode, status.stdout) == (0, f"{out}\n"), (shell, name, fmt)
    detect = str(MDM / _host_os_dir() / "detect.sh")
    for args in (["--require-bundle", "b-lower"], ["--require-bundle", ""], ["--bundle-status", "--require-healthy"]):
        bad = _run([detect, *args])
        assert bad.returncode == 2 and bad.stderr, args
    if os.geteuid() != 0:
        assert _run([detect, "--bundle-status", "--format", "jamf"]).stdout == "<result>none 0 unknown</result>\n"


@pytest.mark.parametrize("platform", ["linux", "macos"])
@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_detect_keeps_product_version_with_required_bundle(tmp_path: Path, platform: str) -> None:
    gateway = tmp_path / "gateway"
    gateway.write_text(
        '#!/bin/sh\ncase "$*" in\n'
        f'  "enterprise {platform} status --json") echo \'{{"installed":true,"installed_version":"9.9.9"}}\' ;;\n'
        f'  "enterprise bundle status --json") echo \'{{"current":{{"bundle_id":"{_BUNDLE_ID}","version":1}},"applied":true}}\' ;;\n'
        '  *) exit 9 ;;\nesac\n',
        encoding="ascii",
    )
    gateway.chmod(0o755)
    source = _text(MDM / platform / "detect.sh")
    source = source.replace('[ "$(dc_platform)" = "$DC_SCRIPT_OS" ]', '[ 1 = 1 ]', 1)
    source = source.replace('[ "$(id -u)" = 0 ]', '[ 1 = 1 ]', 1)
    original = ("gateway=/opt/defenseclaw/bin/defenseclaw-gateway group=linux" if platform == "linux"
                else "gateway=/opt/cisco/defenseclaw/bin/defenseclaw-gateway group=macos")
    assert original in source
    source = source.replace(original, f'gateway="{gateway}" group={platform}', 1)
    source = source.replace('dc_trusted_path "$gateway" ||', '[ -f "$gateway" ] ||', 1)
    detect = tmp_path / "detect.sh"
    detect.write_text(source, encoding="ascii")
    result = subprocess.run(["sh", str(detect), "--require-bundle", "1"], capture_output=True, text=True)
    assert (result.returncode, result.stdout, result.stderr) == (
        0, f"DefenseClaw Enterprise 9.9.9, policy bundle {_BUNDLE_ID} version 1\n", ""
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_detect_can_require_running_sessions_protected(tmp_path: Path) -> None:
    source = _text(MDM / "linux" / "detect.sh")
    names = ("dc_json_top", "dc_json_object", "dc_report", "dc_require_sessions_protected")
    functions = "\n".join(_shell_function(source, name) for name in names)
    script = functions + '\nDC_FORMAT=$1 DC_BUNDLE_STATUS=0\ndc_require_sessions_protected "$2"\n'
    for count, expected in ((0, 0), (2, 1)):
        gateway = tmp_path / f"gateway-{count}"
        gateway.write_text(
            '#!/bin/sh\n[ "$*" = "enterprise bundle status --json" ] || exit 9\n'
            f"printf '%s\\n' '{json.dumps({'ok': True, 'sessions_restart_required': {'state': 'known', 'count': count, 'entries': []}})}'\n",
            encoding="utf-8",
        )
        gateway.chmod(0o755)
        for shell in ("sh", "dash", "bash"):
            if shutil.which(shell):
                result = subprocess.run([shell, "-c", script, "detect", "exit", str(gateway)], capture_output=True, text=True)
                assert result.returncode == expected, (shell, count, result)
                if count:
                    assert "sessions-need-restart" in result.stderr
    detect = str(MDM / _host_os_dir() / "detect.sh")
    assert _run([detect, "--require-sessions-protected", "--bundle-status"]).returncode == 2


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_detect_require_tetragon_arguments() -> None:
    linux, macos = str(MDM / "linux" / "detect.sh"), str(MDM / "macos" / "detect.sh")
    bad = _run([linux, "--require-tetragon", "audit"])
    assert bad.returncode == 2 and "consume, observe or enforce" in bad.stderr
    # Tetragon runs on Linux only; the macOS copy refuses the flag.
    refused = _run([macos, "--require-tetragon", "enforce", "--format", "value"])
    assert refused.returncode == 2 and "Linux only" in refused.stderr and refused.stdout == ""
    assert "--require-tetragon consume|observe|enforce" in _run([linux, "--help"]).stdout


def test_windows_shared_helpers_never_trust_environment_paths() -> None:
    region = _shared_region(_text(WINDOWS_SHARED[0]))
    code = "\n".join(line for line in region.splitlines() if not line.lstrip().startswith("#"))
    assert "$env:ProgramFiles" not in code and "$env:SystemRoot" not in code
    assert "[Microsoft.Win32.RegistryView]::Registry64" in region
    assert "$env:PSModulePath = Join-Path $PSHOME 'Modules'" in region
    for variable in ("DOTNET_", "COMPLUS_", "CORECLR_", "COR_PROFILER", "PSMODULEPATH"):
        assert variable in region


def test_windows_shared_helpers_start_the_cli_outside_the_install() -> None:
    # GAP-1684: a CLI started with its working directory in InstallRoot\bin
    # holds that folder open, so the uninstall could not retire InstallRoot
    # and failed 1603 halfway, on every retry too.
    region = _shared_region(_text(WINDOWS_SHARED[0]))
    assert "$info.WorkingDirectory = [System.Environment]::SystemDirectory" in region
    assert "GetDirectoryName($FilePath)" not in region


def test_intune_package_resolves_output_before_using_dotnet_paths() -> None:
    script = _text(MDM / "intune" / "windows" / "New-DefenseClawIntunePackage.ps1")
    assert script.index("$OutputDirectory = [IO.Path]::GetFullPath") < script.index("$content = Join-Path")


def test_intune_package_rejects_inline_key_before_copying_setup() -> None:
    script = _text(MDM / "intune" / "windows" / "New-DefenseClawIntunePackage.ps1")
    assert script.index("if ($configText -match") < script.index("New-Item -ItemType Directory -Path $content")


def test_intune_package_requires_current_config_version(tmp_path: Path) -> None:
    script = MDM / "intune" / "windows" / "New-DefenseClawIntunePackage.ps1"
    source = _text(script)
    pwsh = os.environ.get("DEFENSECLAW_TEST_PWSH") or shutil.which("pwsh") or shutil.which("pwsh.exe")
    if not pwsh:
        pytest.skip("PowerShell is unavailable")
    setup = tmp_path / "Setup.exe"
    setup.write_bytes(b"fixture setup")
    pin = hashlib.sha256(setup.read_bytes()).hexdigest()
    config = tmp_path / "config.yaml"

    def build(version: str) -> subprocess.CompletedProcess[str]:
        config.write_text(version, encoding="utf-8")
        return subprocess.run(
            [pwsh, "-NoProfile", "-File", str(script), "-SetupPath", str(setup),
             "-Sha256", pin, "-ConfigPath", str(config), "-OutputDirectory", str(tmp_path / "out")],
            capture_output=True, text=True, timeout=30,
        )

    old = build("# config_version: 9\n  config_version: 9\nconfig_version: 8\n")
    assert old.returncode != 0
    assert "config_version 8" in old.stderr and "Setup migrates it on install" in old.stderr
    assert not (tmp_path / "out" / "content").exists()
    current = build("config_version: 9\n")
    assert current.returncode == 0, current.stderr
    content = tmp_path / "out" / "content"
    pins = json.loads((content / "intune-package.json").read_text(encoding="utf-8"))
    assert pins["config_sha256"] == hashlib.sha256(config.read_bytes()).hexdigest()
    assert "Setup migrates it on install" in source


@pytest.mark.parametrize(
    ("config_bytes", "accepted", "error_text"),
    [
        (b"config_version: 9\r\n", True, ""),
        (b"\xef\xbb\xbfconfig_version: 9\r\n", True, ""),
        (b"config_version: 8\r\n", False, "config_version 8"),
    ],
)
def test_intune_package_config_version_with_crlf(
    tmp_path: Path, config_bytes: bytes, accepted: bool, error_text: str,
) -> None:
    pwsh = os.environ.get("DEFENSECLAW_TEST_PWSH") or shutil.which("pwsh") or shutil.which("pwsh.exe")
    if not pwsh:
        pytest.skip("PowerShell is unavailable")
    setup = tmp_path / "Setup.exe"
    setup.write_bytes(b"fixture setup")
    config = tmp_path / "config.yaml"
    config.write_bytes(config_bytes)
    output = tmp_path / "out"
    result = subprocess.run(
        [pwsh, "-NoProfile", "-File", str(MDM / "intune/windows/New-DefenseClawIntunePackage.ps1"),
         "-SetupPath", str(setup), "-Sha256", hashlib.sha256(setup.read_bytes()).hexdigest(),
         "-ConfigPath", str(config), "-OutputDirectory", str(output)],
        capture_output=True, text=True, timeout=30,
    )
    if accepted:
        assert result.returncode == 0, result.stderr
        pins = json.loads((output / "content/intune-package.json").read_text(encoding="utf-8"))
        assert pins["config_sha256"] == hashlib.sha256(config_bytes).hexdigest()
    else:
        assert result.returncode != 0
        assert error_text in result.stderr and "Setup migrates it on install" in result.stderr
        assert not (output / "content").exists()


def test_intune_config_change_docs_explain_the_version_pin() -> None:
    page = _text(ROOT / "docs-site/content/docs/enterprise/mdm/intune/windows.mdx")
    section = page.split("**Change the config.**", 1)[1].split("**Roll back.**", 1)[0]
    assert "config_version: 9" in section
    assert "packager\nrefuses a missing or older version" in section
    assert "installed hash would differ from the hash pinned" in section


def test_posix_kit_modules_skip_on_windows() -> None:
    modules = (
        "test_mdm_kit_cancel.py",
        "test_mdm_kit_config_origin.py",
        "test_mdm_kit_deb_downgrade.py",
        "test_mdm_kit_primary_group.py",
        "test_mdm_kit_secret_nul.py",
        "test_mdm_kit_staging_full.py",
        "test_identity_kit_entra_fg13.py",
    )
    for name in modules:
        source = _text(ROOT / "cli/tests" / name)
        assert 'pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")' in source, name


# PowerShell 7 / .NET Core only constructs that break Windows PowerShell 5.1.
PS7_ONLY = [
    (re.compile(r"\?\?"), "null-coalescing ??"),
    (re.compile(r"\?\.[A-Za-z]"), "null-conditional ?."),
    (re.compile(r"\)\s*(&&|\|\|)\s*"), "pipeline chain operators"),
    (re.compile(r"ForEach-Object\s+-Parallel"), "ForEach-Object -Parallel"),
    (re.compile(r"\bToHexString\b"), "[Convert]::ToHexString"),
    (re.compile(r"\bIsPathFullyQualified\b"), "Path.IsPathFullyQualified"),
    (re.compile(r"\]::HashData\("), "static HashData"),
    (re.compile(r"FileSystemAclExtensions"), "FileSystemAclExtensions"),
    (re.compile(r"\bProcessPath\b"), "Environment.ProcessPath"),
    (re.compile(r"\$\w+\.ArgumentList\b"), "ProcessStartInfo.ArgumentList"),
    (re.compile(r"^#Requires -Version 7", re.MULTILINE), "#Requires 7"),
]


# The reference rule-pack app scripts run before DefenseClaw is installed, so
# they carry their own helper region, not the MDM shared one.
RULE_PACK_51 = [
    MDM / "intune" / "windows" / "Install-DefenseClawRulePack.ps1",
    MDM / "intune" / "windows" / "Detect-DefenseClawRulePack.ps1",
]


@pytest.mark.parametrize("path", WINDOWS_51 + RULE_PACK_51, ids=lambda p: p.name)
def test_intune_facing_windows_scripts_run_in_powershell_51(path: Path) -> None:
    text = _text(path)
    for pattern, label in PS7_ONLY:
        assert not pattern.search(text), f"{path.name} uses {label}, which Windows PowerShell 5.1 lacks"
    assert "Set-StrictMode -Version 2.0" in text


def test_generic_windows_wrapper_requires_powershell_7() -> None:
    text = _text(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1")
    assert "#Requires -Version 7.4" in text
    for guard in (
        "unsupported_architecture",
        "powershell_constrained_language",
        "loader_environment_present",
        "powershell7_untrusted",
        "mdm_not_elevated",
    ):
        assert guard in text
    # Credentials only through stdin or an administrator-only file.
    assert "'--from-stdin'" in text and "-StandardInputPath $secret" in text
    assert "-RequireAdminOnly" in text


def _pwsh7() -> str | None:
    candidates = [shutil.which("pwsh.exe")]
    program_files = os.environ.get("ProgramFiles")
    if program_files:
        candidates.append(str(Path(program_files) / "PowerShell" / "7" / "pwsh.exe"))
    return next((c for c in candidates if c and Path(c).is_file()), None)


_ANCESTOR_PROBE = r"""
$ErrorActionPreference = 'Stop'
__FUNCTIONS__
function New-ProbeDirectory([string]$Path, [string]$Sddl) {
    $security = [System.Security.AccessControl.DirectorySecurity]::new()
    $security.SetSecurityDescriptorSddlForm($Sddl)
    [System.IO.FileSystemAclExtensions]::Create([System.IO.DirectoryInfo]::new($Path), $security)
}
function New-ProbeFile([string]$Path) {
    [System.IO.File]::WriteAllText($Path, "deployment_mode: managed_enterprise`n")
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
    Set-Acl -LiteralPath $Path -AclObject $acl
}
$adminOnly = 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
$root = Join-Path ([Environment]::GetFolderPath('Windows')) ('Temp\dc-mdm-ancestors-' + [Guid]::NewGuid().ToString('N'))
try {
    New-ProbeDirectory $root $adminOnly
    New-ProbeDirectory (Join-Path $root 'good') $adminOnly
    New-ProbeFile (Join-Path $root 'good\config.yaml')
    # Authenticated Users may modify (and so rename) this folder; the file in
    # it is still administrator-only.
    New-ProbeDirectory (Join-Path $root 'open') 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1301bf;;;AU)'
    New-ProbeFile (Join-Path $root 'open\config.yaml')
    $null = New-Item -ItemType Junction -Path (Join-Path $root 'link') -Target (Join-Path $root 'good')
    # Whether the folders above the probe root are themselves administrator-only.
    $result = [ordered]@{ host = [bool](Test-WrapperAdminOnlyAncestors -Path (Join-Path $root 'probe')) }
    foreach ($name in 'good', 'open', 'link') {
        $file = Join-Path $root "$name\config.yaml"
        $result[$name] = [ordered]@{
            item = [bool](Test-DefenseClawAdminOnlyItem -Path $file)
            ancestors = [bool](Test-WrapperAdminOnlyAncestors -Path $file)
        }
    }
    $result | ConvertTo-Json -Compress
} finally {
    $link = Join-Path $root 'link'
    if (Test-Path -LiteralPath $link) { [System.IO.Directory]::Delete($link) }
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
"""


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL behaviour")
def test_generic_windows_wrapper_checks_every_folder_above_config_and_secret(tmp_path: Path) -> None:
    # An account that can rename a folder above an administrator-only config
    # can swap the file between the ACL check and the copy, so the wrapper
    # checks the whole chain like the Unix dc_trusted_path.
    engine = _pwsh7()
    assert engine, "Windows CI must provide PowerShell 7"
    text = _text(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1")
    start = text.index("function Test-WrapperAdminOnlyAncestors {")
    ancestors = text[start : text.index("\nfunction Copy-WrapperInput", start)]
    probe = tmp_path / "ancestor-probe.ps1"
    probe.write_text(_ANCESTOR_PROBE.replace("__FUNCTIONS__", _shared_region(text) + "\n" + ancestors), encoding="utf-8")
    result = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(probe)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    verdicts = json.loads(result.stdout.strip().splitlines()[-1])
    assert verdicts["good"]["item"] and verdicts["open"]["item"], verdicts
    if not verdicts["host"]:
        pytest.skip("a folder above the probe root is not administrator-only on this host")
    assert verdicts["good"]["ancestors"] is True, verdicts
    assert verdicts["open"]["ancestors"] is False, verdicts
    assert verdicts["link"]["ancestors"] is False, verdicts


def test_generic_windows_wrapper_untrusted_input_repair_is_scoped() -> None:
    text = _text(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1")
    repair = text[text.index("function Get-WrapperUntrustedInputFix {") :
                  text.index("\nfunction Copy-WrapperInput", text.index("function Get-WrapperUntrustedInputFix {"))]
    assert "/T /C" not in repair
    assert "trusted copy in a new administrator-only folder dedicated to DefenseClaw" in text


_REMEDIATION_PROBE = r"""
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
__FUNCTIONS__
$guardianDown = '{"errors":[{"code":"lifecycle_error","message":"guardian not running"}],"services":[' +
    '{"name":"DefenseClawGateway","kind":"gateway","state":"running","required":true},' +
    '{"name":"DefenseClawHookGuardian","kind":"guardian","state":"stopped","start_mode":"disabled","required":true},' +
    '{"name":"DefenseClawHookEnumerator","kind":"enumerator","state":"running","required":true},' +
    '{"name":"DefenseClawSensorHelper","kind":"sensor_helper","state":"running","required":true}]}'
$gatewayDown = $guardianDown.Replace('"DefenseClawGateway","kind":"gateway","state":"running"', '"DefenseClawGateway","kind":"gateway","state":"stopped"')
$busy = '{"errors":[{"code":"lifecycle_busy","message":"another run"}],"services":[]}'
@{
    detect = (Format-DefenseClawVerifyFailure -Json $guardianDown)
    busy = ($null -eq (Format-DefenseClawVerifyFailure -Json $busy))
    fix = @(Get-DefenseClawStoppedSideServices -Json $guardianDown)
    fix_gateway_down = @(Get-DefenseClawStoppedSideServices -Json $gatewayDown).Count
} | ConvertTo-Json -Compress
"""


@pytest.mark.skipif(os.name != "nt", reason="runs the Intune remediation helpers")
def test_intune_remediation_names_the_stopped_service_and_restarts_only_it(tmp_path: Path) -> None:
    # GAP-0574: Detect named only lifecycle_error, and Fix re-applied the
    # whole deployment for a stopped guardian, so every user's hooks failed
    # closed for 99 seconds. Detect names the service; Fix starts only the
    # stopped guardian or enumerator while the gateway runs.
    engine = shutil.which("powershell.exe") or _pwsh7()
    assert engine, "Windows CI must provide Windows PowerShell 5.1 or PowerShell 7"
    functions = []
    for name, function in (("Remediate-Detect.ps1", "Format-DefenseClawVerifyFailure"),
                           ("Remediate-Fix.ps1", "Get-DefenseClawStoppedSideServices")):
        text = _text(MDM / "intune" / "windows" / name)
        start = text.index(f"function {function} {{")
        functions.append(text[start : text.index("\ntry {", start)])
    probe = tmp_path / "remediation-probe.ps1"
    probe.write_text(_REMEDIATION_PROBE.replace("__FUNCTIONS__", "\n".join(functions)), encoding="utf-8")
    result = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(probe)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    verdicts = json.loads(result.stdout.strip().splitlines()[-1])
    assert "DefenseClawHookGuardian is stopped (start disabled)" in verdicts["detect"], verdicts
    assert verdicts["busy"] is True, verdicts
    assert verdicts["fix"] == ["DefenseClawHookGuardian"] or verdicts["fix"] == "DefenseClawHookGuardian", verdicts
    assert verdicts["fix_gateway_down"] == 0, verdicts


@pytest.mark.skipif(os.name != "nt", reason="runs the Windows wrapper")
def test_generic_windows_wrapper_refuses_a_product_version_pin_for_a_staged_setup(tmp_path: Path) -> None:
    # Setup takes no version pin; a -ProductVersion given with -SetupPath
    # used to be accepted and silently ignored.
    engine = _pwsh7()
    assert engine, "Windows CI must provide PowerShell 7"
    result = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1"),
         "-SetupPath", str(tmp_path / "DefenseClawSetup-Enterprise-Standalone-x64.exe"), "-Sha256", "0" * 64,
         "-ProductVersion", "1.4.0"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    document = json.loads([line for line in result.stdout.splitlines() if line.startswith("{")][-1])
    codes = [error["code"] for error in document["errors"]]
    host_refusals = {"mdm_not_elevated", "powershell7_untrusted", "unsupported_architecture", "powershell_constrained_language", "loader_environment_present"}
    if host_refusals.intersection(codes):
        pytest.skip(f"this host cannot run the wrapper: {document['errors'][0]['message']}")
    assert result.returncode == 1639, result.stdout
    assert codes == ["mdm_invalid_arguments"], document
    assert "-ProductVersion applies only to the installed CLI" in document["errors"][0]["message"], document


_PUBLIC_TEXT_PROBE = r"""
$ErrorActionPreference = 'Stop'
__FUNCTION__
$staged = 'C:\Windows\Temp\defenseclaw-mdm-0123456789abcdef0123456789abcdef\config.yaml'
$doc = [ordered]@{
    schema_version = 2
    next_step = "Next step: run DefenseClaw Setup as LocalSystem: DefenseClawSetup-Enterprise-Standalone-x64.exe /ensure CONFIG=$staged JSON=1."
    config = $staged
} | ConvertTo-Json -Compress
[ordered]@{
    plain = ConvertTo-WrapperPublicText -Text $doc -Staged $staged -Public 'C:\Staging\config.yaml'
    spaced = ConvertTo-WrapperPublicText -Text $doc -Staged $staged -Public 'C:\Admin Configs\config.yaml'
    stdin = ConvertTo-WrapperPublicText -Text $doc -Staged $staged -Public ''
    raw = ConvertTo-WrapperPublicText -Text "failed; CONFIG=$staged JSON=1" -Staged $staged -Public 'C:\Staging\config.yaml'
} | ConvertTo-Json -Compress
"""


@pytest.mark.skipif(os.name != "nt", reason="runs PowerShell 7")
def test_generic_windows_wrapper_names_the_administrators_config_in_its_result(tmp_path: Path) -> None:
    engine = _pwsh7()
    assert engine, "Windows CI must provide PowerShell 7"
    text = _text(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1")
    start = text.index("function ConvertTo-WrapperPublicText {")
    function = text[start : text.index("\nfunction Write-LifecycleResult", start)]
    probe = tmp_path / "public-text-probe.ps1"
    probe.write_text(_PUBLIC_TEXT_PROBE.replace("__FUNCTION__", function), encoding="utf-8")
    result = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(probe)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = json.loads(result.stdout.strip().splitlines()[-1])
    plain = json.loads(out["plain"])
    assert "/ensure CONFIG=C:\\Staging\\config.yaml JSON=1" in plain["next_step"], plain
    assert plain["config"] == "C:\\Staging\\config.yaml", plain
    assert "defenseclaw-mdm-" not in out["plain"], out["plain"]
    spaced = json.loads(out["spaced"])
    assert '/ensure CONFIG="C:\\Admin Configs\\config.yaml" JSON=1' in spaced["next_step"], spaced
    stdin = json.loads(out["stdin"])
    assert "/ensure CONFIG=<config.yaml> JSON=1" in stdin["next_step"], stdin
    assert out["raw"] == "failed; CONFIG=C:\\Staging\\config.yaml JSON=1", out["raw"]


def test_windows_scripts_never_concatenate_into_an_argument_list() -> None:
    # PowerShell's comma operator binds tighter than +, so
    # @('/' + $action, 'JSON=1') is the single argument "/ensure JSON=1". The
    # generic wrapper built its Setup command line that way, and Setup refused
    # every -SetupPath run with "unexpected positional argument" (exit 1639).
    pattern = re.compile(r"@\(\s*'[^']*'\s*\+\s*\$\w+\s*,")
    for path in sorted((MDM / "windows").glob("*.ps1")) + sorted((MDM / "intune" / "windows").glob("*.ps1")):
        assert not pattern.search(_text(path)), path.name
    assert "$arguments = @(('/' + $normalizedAction), 'JSON=1')" in _text(
        MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1"
    )


@pytest.mark.skipif(os.name == "nt", reason="the release jobs run the signing helpers with bash on Linux and macOS")
def test_signing_helpers_refuse_without_credentials(tmp_path: Path) -> None:
    sign = MDM / "signing" / "authenticode-sign.sh"
    target = tmp_path / "file.exe"
    target.write_bytes(b"MZ")
    result = subprocess.run(["bash", str(sign), str(target)], capture_output=True, text=True,
                            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
    assert result.returncode != 0 and "AUTHENTICODE_PFX" in result.stderr
    builder = ROOT / "packaging" / "windows" / "standalone" / "build-setup.sh"
    result = subprocess.run(["bash", str(builder), "--version", "1.0.0", "--payload-dir", str(tmp_path),
                             "--sign-command", str(sign)], capture_output=True, text=True)
    assert result.returncode == 1 and "exclusive" in result.stderr
    for path in (sign, MDM / "signing" / "build-macos-release.sh"):
        if shutil.which("shellcheck"):
            subprocess.run(["shellcheck", "-S", "warning", str(path)], check=True)


@pytest.mark.skipif(os.name == "nt", reason="the release jobs run the signing helpers with bash on Linux and macOS")
@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")
def test_signing_helper_prints_the_pfx_thumbprint(tmp_path: Path) -> None:
    # #1280: build-setup.sh takes the signer pin as --expected-signer-sha256;
    # --thumbprint prints it from the PFX without signing anything.
    key, cert, pfx = tmp_path / "key.pem", tmp_path / "cert.pem", tmp_path / "test.pfx"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=DefenseClaw thumbprint test", "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "pkcs12", "-export", "-inkey", str(key), "-in", str(cert), "-out", str(pfx),
                    "-passout", "pass:"], check=True, capture_output=True)
    der = subprocess.run(["openssl", "x509", "-in", str(cert), "-outform", "DER"], check=True, capture_output=True).stdout
    result = subprocess.run(["bash", str(MDM / "signing" / "authenticode-sign.sh"), "--thumbprint"],
                            capture_output=True, text=True,
                            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "AUTHENTICODE_PFX": str(pfx)})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == hashlib.sha256(der).hexdigest()


@pytest.mark.skipif(os.name == "nt", reason="the release jobs run build-setup.sh with bash on Linux")
def test_signed_standalone_build_runs_on_linux_with_osslsigncode(tmp_path: Path) -> None:
    # #1280: the signed channels no longer need a Windows build host; on Linux
    # and macOS they need osslsigncode, checked before any build work.
    tools = tmp_path / "bin"
    tools.mkdir()
    (tools / "uname").symlink_to(shutil.which("uname"))
    builder = ROOT / "packaging" / "windows" / "standalone" / "build-setup.sh"
    sign = MDM / "signing" / "authenticode-sign.sh"
    result = subprocess.run(
        [shutil.which("bash"), str(builder), "--version", "1.0.0", "--sign-command", str(sign),
         "--signing-type", "DEV", "--expected-signer-sha256", "ab" * 32],
        capture_output=True, text=True, env={"PATH": str(tools)},
    )
    assert result.returncode == 1, result.stderr
    assert "need osslsigncode 2.5 or later" in result.stderr
    assert "Windows build host" not in result.stderr


# The macOS app job needs these five for every release (release.yaml).
_MACOS_APP_SECRETS = {
    "MACOS_DEVELOPER_ID_P12_BASE64": "cDEy",
    "MACOS_DEVELOPER_ID_P12_PASSWORD": "password",
    "MACOS_NOTARY_KEY_BASE64": "a2V5",
    "MACOS_NOTARY_KEY_ID": "key-id",
    "MACOS_NOTARY_ISSUER_ID": "issuer-id",
}


@pytest.mark.skipif(os.name == "nt", reason="the release job runs the pkg builder with bash on macOS")
@pytest.mark.parametrize(
    ("secrets", "code", "message"),
    [
        ({}, 0, "::notice title=Unsigned macOS enterprise package::"),
        # The app's secrets alone do not ask for a signed pkg.
        (_MACOS_APP_SECRETS, 0, "::notice title=Unsigned macOS enterprise package::"),
        (
            {"MACOS_INSTALLER_SIGNING_IDENTITY": "Developer ID Installer: Example"},
            1,
            "MACOS_INSTALLER_SIGNING_IDENTITY needs MACOS_DEVELOPER_ID_P12_BASE64 and MACOS_SIGNING_IDENTITY",
        ),
        (
            {**_MACOS_APP_SECRETS, "MACOS_INSTALLER_SIGNING_IDENTITY": "Developer ID Installer: Example"},
            1,
            "MACOS_INSTALLER_SIGNING_IDENTITY needs MACOS_DEVELOPER_ID_P12_BASE64 and MACOS_SIGNING_IDENTITY",
        ),
        ({"MACOS_INSTALLER_P12_BASE64": "cDEy"}, 1, "MACOS_INSTALLER_P12_BASE64 is set without"),
        ({"MACOS_NOTARY_KEY_BASE64": "a2V5"}, 1, "Set all three MACOS_NOTARY_* secrets or none of them"),
    ],
)
def test_macos_enterprise_pkg_is_signed_only_with_its_installer_identity(
    tmp_path: Path, secrets: dict[str, str], code: int, message: str
) -> None:
    script = tmp_path / "packaging" / "mdm" / "signing" / "build-macos-release.sh"
    script.parent.mkdir(parents=True)
    shutil.copy2(MDM / "signing" / "build-macos-release.sh", script)
    builder = tmp_path / "scripts" / "build-macos-enterprise-pkg.sh"
    builder.parent.mkdir()
    builder.write_text(
        "#!/usr/bin/env bash\nset -eu\n"
        'while [ "$#" -gt 0 ]; do case "$1" in --version) v=$2; shift ;; --dist-dir) d=$2; shift ;; esac; shift; done\n'
        ': > "$d/defenseclaw-enterprise-$v-darwin-arm64.pkg"\n',
        encoding="utf-8",
    )
    builder.chmod(0o755)
    out = tmp_path / "out"
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "RUNNER_TEMP": str(tmp_path), **secrets}
    result = subprocess.run(
        ["bash", str(script), "1.2.3", str(out)], env=env, capture_output=True, text=True, timeout=60
    )
    assert result.returncode == code, result.stdout + result.stderr
    assert message in result.stdout + result.stderr
    assert (out / "defenseclaw-enterprise-1.2.3-darwin-arm64.pkg").is_file() == (code == 0)


def test_remediate_fix_does_not_report_a_missing_scanner_runtime_as_healthy() -> None:
    """GAP-0631: the installed CLI's ensure succeeds with a
    scanner_runtime_unavailable warning while verify keeps failing; the
    remediation reports it as not repaired, exits 1603 and keeps the warning's
    text, which names Setup /repair."""

    text = (MDM / "intune" / "windows" / "Remediate-Fix.ps1").read_text(encoding="utf-8")
    block = text.split("$code = $run.ExitCode", 1)[1].split("$line =", 1)[0]
    assert "$_.code -eq 'scanner_runtime_unavailable'" in block
    assert block.index("$code = 1603") < block.index("$recovered =")
    assert "not repaired (scanner_runtime_unavailable)" in block


# Timeout and recovery wiring of the Windows MDM scripts (formerly
# packaging/mdm/intune/windows/test_remediate_timeout.py, which pytest never
# collected: testpaths is cli/tests).
def test_native_helper_has_a_bounded_process_and_pipe_wait_in_every_upload() -> None:
    # The copies are identical (test_copied_helpers_are_identical); check one.
    helper = _shared_region(_text(WINDOWS_SHARED[0]))
    assert "$process.WaitForExit($TimeoutSeconds * 1000)" in helper
    assert "taskkill.exe" in helper and "/T /F" in helper
    assert "[System.Threading.Tasks.Task]::WaitAll(" in helper
    assert "$process.WaitForExit()" not in helper


def test_remediation_bounds_ensure_and_restores_start_modes_on_failure() -> None:
    script = (MDM / "intune" / "windows" / "Remediate-Fix.ps1").read_text()
    assert "Get-DefenseClawRemediationStartModes" in script
    assert "Restore-DefenseClawRemediationStartModes -PriorModes $priorModes" in script
    assert "$modes[$name] = if ($mode -in @(2, 3)) { $mode } else { -1 }" in script
    assert "if ([int]$PriorModes[$name] -notin @(2, 3)) { continue }" in script
    assert "if ($current -ne 4) { continue }" in script
    assert "$committed = [bool]$ensureDocument.ok -and -not [bool]$ensureDocument.transaction_pending" in script
    # A parsed ensure report is the lifecycle's decision: only an ensure that
    # ended without one has its startup modes put back.
    assert "if (-not $committed -and $null -eq $ensureDocument -and ($ensureFailure -or" in script
    assert "$run.ExitCode -notin @(0, 3010, 1618)" in script
    assert "4 { 'disabled' }" not in script
    assert "-TimeoutSeconds 840 -ArgumentList @(" in script
    assert "startup-mode restore failed" in script
    assert "_.code -eq 'startup_mode_restore_failed'" in script


def test_standalone_installer_binds_native_output_to_the_process_deadline() -> None:
    module = (MDM.parent / "windows" / "DefenseClawEnterprise.psm1").read_text()
    native = module.split("function Invoke-DefenseClawProcess {", 1)[1].split(
        "function Invoke-DefenseClawNative {", 1
    )[0]
    assert "if (Test-DefenseClawStandaloneProfile)" in native
    assert "[Threading.Tasks.Task]::WaitAll(" in native
    assert "native process output timed out" in native
    assert "DC_LIFECYCLE_PHASE:" in module
    assert "transaction quiesce stop services" in module


# #1298: after a Linux MDM purge an empty root-only /var/lib/defenseclaw-mdm
# (the wrapper's staging folder) stayed. A purge removes it when it is empty
# and root's own directory; anything else stays.
@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize(
    ("purge", "platform", "owner", "content", "removed"),
    [
        ("1", "linux", "0", "", True),
        ("1", "linux", "0", "defenseclaw-mdm.abc123", False),
        ("0", "linux", "0", "", False),
        ("1", "darwin", "0", "", False),
        ("1", "linux", "501", "", False),
        ("1", "linux", "0", "symlink", False),
    ],
)
def test_unix_uninstall_purge_removes_the_empty_staging_folder(
    tmp_path: Path, purge: str, platform: str, owner: str, content: str, removed: bool
) -> None:
    function = _shell_function(_text(MDM / "linux" / "uninstall.sh"), "dc_remove_stage_parent")
    parent = tmp_path / "defenseclaw-mdm"
    if content == "symlink":
        (tmp_path / "elsewhere").mkdir()
        parent.symlink_to(tmp_path / "elsewhere")
    else:
        parent.mkdir(mode=0o700)
        if content:
            (parent / content).mkdir()
    script = f"""DC_PURGE={purge}
DC_SCRIPT_OS={platform}
DC_LINUX_STAGE_PARENT="{parent}"
dc_log() {{ :; }}
dc_stat_uid() {{ echo {owner}; }}
{function}
dc_remove_stage_parent
"""
    result = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert (not os.path.lexists(parent)) is removed
    if content == "symlink":
        assert (tmp_path / "elsewhere").is_dir()


def test_unix_uninstall_removes_the_staging_folder_after_the_package_and_without_a_gateway() -> None:
    text = _text(MDM / "linux" / "uninstall.sh")
    assert text.count("\ndc_remove_stage_parent\n") + text.count("    dc_remove_stage_parent\n") == 2
    assert 'DC_LINUX_STAGE_PARENT=/var/lib/defenseclaw-mdm' in text
    assert "DC_STAGE_PARENT=/var/lib/defenseclaw-mdm" in _text(MDM / "linux" / "defenseclaw-enterprise.sh")
