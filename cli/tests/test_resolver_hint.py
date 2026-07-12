# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from defenseclaw.resolver_hint import authenticated_resolver_instructions


def test_authenticated_resolver_hint_is_copy_pasteable_and_fail_closed() -> None:
    output = authenticated_resolver_instructions("0.8.5")

    assert (
        "https://github.com/cisco-ai-defense/defenseclaw/releases/download/0.8.5/"
        in output
    )
    assert "defenseclaw-upgrade.sh" in output
    assert "defenseclaw-upgrade.ps1" in output
    assert "checksums.txt.sig" in output
    assert "checksums.txt.pem" in output
    assert "cosign verify-blob" in output
    assert "release.yaml@refs/heads/main" in output
    assert "https://token.actions.githubusercontent.com" in output
    assert "Get-FileHash" in output
    assert "Invoke-WebRequest" in output and "-UseBasicParsing" in output
    assert "sha256sum" in output and "shasum -a 256" in output
    assert "--proto-redir '=https'" in output
    assert "DefenseClaw upgrade resolver complete v1" in output
    assert "raw.githubusercontent.com" not in output
    assert "upgrade.sh | bash" not in output
    assert "--version" not in output

    windows = output.split("Windows PowerShell:\n", 1)[1]
    create = windows.index("New-Item -ItemType Directory -Path $d")
    protect = windows.index("$directoryAcl.SetAccessRuleProtection($true, $false)")
    apply_acl = windows.index("Set-Acl -LiteralPath $d")
    validate_acl = windows.index(
        "Resolver temporary directory owner/DACL validation failed before download"
    )
    fetch = windows.index("Invoke-WebRequest")
    assert create < protect < apply_acl < validate_acl < fetch
    assert "[Security.Principal.WindowsIdentity]::GetCurrent().User" in windows
    assert "S-1-5-18" in windows
    assert "$verifiedAcl.AreAccessRulesProtected" in windows
    assert "[IO.FileAttributes]::ReparsePoint" in windows
    assert "$checksumRows" in windows
    assert "$matches" not in windows

    posix = output.split("POSIX:\n", 1)[1].split("\nWindows PowerShell:", 1)[0]
    completed = subprocess.run(
        ["bash", "-n"],
        input=posix,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize("shell_name", ("pwsh", "powershell.exe"))
def test_windows_resolver_secures_and_validates_temp_dir_before_fetch(
    shell_name: str,
    tmp_path: Path,
) -> None:
    if os.name != "nt" or (shell := shutil.which(shell_name)) is None:
        pytest.skip(f"{shell_name} native Windows contract")

    output = authenticated_resolver_instructions("0.8.5")
    windows = output.split("Windows PowerShell:\n", 1)[1]
    probe = r"""
function global:cosign {}
function global:Invoke-WebRequest {
  [CmdletBinding()]
  param(
    [string]$Uri,
    [string]$OutFile,
    [switch]$UseBasicParsing
  )
  $current = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $acl = Get-Acl -LiteralPath $d -ErrorAction Stop
  $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  $rules = @($acl.GetAccessRules(
    $true,
    $false,
    [Security.Principal.SecurityIdentifier]
  ))
  $allowed = @($current, 'S-1-5-18')
  $expectedRuleCount = if ($current -eq 'S-1-5-18') { 1 } else { 2 }
  if (-not $acl.AreAccessRulesProtected -or
      $owner -ne $current -or
      $rules.Count -ne $expectedRuleCount) {
    throw '__resolver_dacl_invalid_at_fetch__'
  }
  foreach ($rule in $rules) {
    if ($allowed -notcontains $rule.IdentityReference.Value -or
        $rule.IsInherited -or
        $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {
      throw '__resolver_dacl_invalid_at_fetch__'
    }
  }
  throw '__resolver_dacl_verified_before_fetch__'
}
"""
    environment = os.environ.copy()
    environment["TEMP"] = str(tmp_path)
    environment["TMP"] = str(tmp_path)
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-Command", "-"],
        input=probe + windows,
        text=True,
        capture_output=True,
        check=False,
        env=environment,
        timeout=30,
    )

    diagnostic = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "__resolver_dacl_verified_before_fetch__" in diagnostic
    assert "__resolver_dacl_invalid_at_fetch__" not in diagnostic
    assert not list(tmp_path.glob("defenseclaw-upgrade-*"))


@pytest.mark.parametrize("value", ("v0.8.5", "../0.8.5", "0.8", "00.8.5"))
def test_authenticated_resolver_hint_rejects_unsafe_versions(value: str) -> None:
    with pytest.raises(ValueError, match="canonical"):
        authenticated_resolver_instructions(value)
