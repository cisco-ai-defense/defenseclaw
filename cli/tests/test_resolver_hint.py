# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

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
    POSIX_AUTHENTICATED_BOOTSTRAP_PATH,
    POSIX_AUTHENTICATED_CHILD_ENV_PREFIX_PATTERN,
    POSIX_AUTHENTICATED_CHILD_ENV_REMOVALS,
    POSIX_AUTHENTICATED_CHILD_FUNCTION_ENV_PATTERN,
    WINDOWS_RESOLVER_BANNER,
    authenticated_resolver_instructions,
)


def _bash_executable() -> str:
    """Return Git Bash on Windows instead of the WindowsApps WSL alias."""

    if os.name != "nt":
        return shutil.which("bash") or "bash"

    candidates: list[Path] = []
    git = shutil.which("git")
    if git:
        candidates.append(Path(git).resolve().parent.parent / "bin" / "bash.exe")
    for variable in ("ProgramFiles", "ProgramFiles(x86)", "LocalAppData"):
        root = os.environ.get(variable)
        if root:
            candidates.append(Path(root) / "Git" / "bin" / "bash.exe")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    pytest.skip("Git Bash is required for the POSIX resolver syntax contract on Windows")


def test_authenticated_resolver_hint_is_copy_pasteable_and_fail_closed() -> None:
    output = authenticated_resolver_instructions("0.8.5")

    assert "https://github.com/cisco-ai-defense/defenseclaw/releases/download/0.8.5/" in output
    assert "defenseclaw-upgrade.sh" in output
    assert "defenseclaw-upgrade.ps1" in output
    assert "checksums.txt.sig" in output
    assert "checksums.txt.pem" in output
    assert "cosign verify-blob" in output
    assert "release.yaml@refs/heads/main" in output
    assert "https://token.actions.githubusercontent.com" in output
    assert "Microsoft.PowerShell.Utility\\Get-FileHash" in output
    assert "Microsoft.PowerShell.Utility\\Invoke-WebRequest" in output
    assert "-UseBasicParsing" in output
    assert "sha256sum" in output and "shasum -a 256" in output
    assert "--proto-redir '=https'" in output
    assert "DefenseClaw upgrade resolver complete v1" in output
    assert "unset VERSION" in output
    assert "raw.githubusercontent.com" not in output
    assert "upgrade.sh | bash" not in output
    assert "--version" not in output

    windows = output.split("Windows PowerShell:\n", 1)[1]
    assert WINDOWS_RESOLVER_BANNER in windows
    assert "Preflight refusal only" not in windows
    create = windows.index("[IO.Directory]::CreateDirectory($d)")
    protect = windows.index("$directoryAcl.SetAccessRuleProtection($true, $false)")
    apply_acl = windows.index("Set-Acl -LiteralPath $d")
    validate_acl = windows.index("Resolver temporary directory owner/DACL validation failed before download")
    fetch = windows.index("Microsoft.PowerShell.Utility\\Invoke-WebRequest")
    assert create < protect < apply_acl < validate_acl < fetch
    assert "[Security.Principal.WindowsIdentity]::GetCurrent().User" in windows
    assert "S-1-5-18" in windows
    assert "$verifiedAcl.AreAccessRulesProtected" in windows
    assert "[IO.FileAttributes]::ReparsePoint" in windows
    assert "$checksumRows" in windows
    assert "$matches" not in windows
    assert "Get-Command cosign" not in windows
    assert "& cosign " not in windows
    assert f"$cosignVersion = '{COSIGN_BOOTSTRAP_VERSION}'" in windows
    assert f"$cosignExpectedSha256 = '{COSIGN_BOOTSTRAP_SHA256[('windows', 'amd64')]}'" in windows
    assert ("'https://github.com/sigstore/cosign/releases/download/v' + $cosignVersion + '/' + $cosignAsset") in windows
    cosign_fetch = windows.index("Microsoft.PowerShell.Utility\\Invoke-WebRequest -Uri $cosignUrl")
    cosign_digest = windows.index("$cosignActualSha256 -ne $cosignExpectedSha256")
    resolver_fetch = windows.index("foreach ($name in @('defenseclaw-upgrade.ps1', 'checksums.txt'")
    cosign_execute = windows.index("& $cosign verify-blob")
    assert cosign_fetch < cosign_digest < resolver_fetch < cosign_execute
    assert "Downloaded Cosign digest mismatch." in windows
    assert "[Environment]::GetEnvironmentVariables().Keys" in windows
    assert "'^(COSIGN|SIGSTORE|TUF)_'" in windows

    posix = output.split("POSIX:\n", 1)[1].split("\nWindows PowerShell:", 1)[0]
    assert "command -v cosign" not in posix
    assert f"sigstore/cosign/releases/download/v{COSIGN_BOOTSTRAP_VERSION}/" in posix
    cosign_fetch = posix.index('--output "$cosign_bin"')
    cosign_digest = posix.index('if [ "$cosign_actual" != "$cosign_sha" ]; then')
    cosign_execute = posix.index('"$cosign_bin" verify-blob')
    assert cosign_fetch < cosign_digest < cosign_execute
    assert "Downloaded Cosign digest mismatch." in posix
    for bounded_option in (
        "--connect-timeout 30",
        "--max-time 300",
        "--speed-limit 1024",
        "--speed-time 60",
    ):
        assert posix.count(bounded_option) == 2
    assert "--max-filesize 209715200" in posix
    assert "--max-filesize 4194304" in posix
    assert posix.index("unset VERSION") < posix.index(
        '/bin/bash --noprofile --norc -p "$d/defenseclaw-upgrade.sh" --yes'
    )
    completed = subprocess.run(
        [_bash_executable(), "-n"],
        input=posix,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_windows_resolver_hint_pins_builtin_modules_and_qualified_cmdlets() -> None:
    output = authenticated_resolver_instructions("0.8.5")
    windows = output.split("Windows PowerShell:\n", 1)[1]

    for variable, module in (
        ("managementModule", "Microsoft.PowerShell.Management"),
        ("securityModule", "Microsoft.PowerShell.Security"),
        ("utilityModule", "Microsoft.PowerShell.Utility"),
    ):
        assert f"'{module}', '{module}.psd1'" in windows
        assert (f"Microsoft.PowerShell.Core\\Import-Module ${variable} -Force -ErrorAction Stop") in windows
    for command, module in (
        ("Invoke-WebRequest", "Microsoft.PowerShell.Utility"),
        ("Get-FileHash", "Microsoft.PowerShell.Utility"),
        ("Get-Content", "Microsoft.PowerShell.Management"),
        ("Get-Item", "Microsoft.PowerShell.Management"),
        ("Remove-Item", "Microsoft.PowerShell.Management"),
        ("Get-Acl", "Microsoft.PowerShell.Security"),
        ("Set-Acl", "Microsoft.PowerShell.Security"),
        ("Where-Object", "Microsoft.PowerShell.Utility"),
        ("Select-Object", "Microsoft.PowerShell.Utility"),
    ):
        assert f"{module}\\{command}" in windows
        assert re.search(rf"(?m)^\s*{re.escape(command)}(?:\s|$)", windows) is None

    assert "Join-Path" not in windows
    assert "New-Object" not in windows
    assert windows.count("-MaximumRedirection 5") == 2
    assert windows.count("-TimeoutSec 300") == 2
    assert "$cosignItem.Length -gt 209715200" in windows
    assert "$assetItem.Length -gt 4194304" in windows


def test_posix_resolver_hint_clears_trust_overrides_before_network_access() -> None:
    output = authenticated_resolver_instructions("0.8.5")
    posix = output.split("POSIX:\n", 1)[1].split("\nWindows PowerShell:", 1)[0]

    removals = f"unset {' '.join(POSIX_AUTHENTICATED_CHILD_ENV_REMOVALS)}"
    prefix_sweep = f"'s/^(({POSIX_AUTHENTICATED_CHILD_ENV_PREFIX_PATTERN})[A-Za-z0-9_%]*)=.*/\\1/p'"
    function_sweep = f"'s/^({POSIX_AUTHENTICATED_CHILD_FUNCTION_ENV_PATTERN})=.*/\\1/p'"
    assert removals in posix
    assert prefix_sweep in posix
    assert function_sweep in posix
    assert f"PATH='{POSIX_AUTHENTICATED_BOOTSTRAP_PATH}'" in posix
    assert "/bin/bash --noprofile --norc -p <<'DEFENSECLAW_AUTHENTICATED_RESOLVER'" in posix
    assert posix.index(removals) < posix.index("curl --fail")
    assert posix.index(prefix_sweep) < posix.index("curl --fail")
    assert posix.count('"$@" /bin/bash --noprofile --norc -p') == 2

    preamble = posix.split("  umask 077\n", 1)[0]
    probe = (
        f"{preamble}"
        "  if type resolver_hint_poison >/dev/null 2>&1; then\n"
        "    exit 91\n"
        "  fi\n"
        '  "$@"\n'
        ")\n"
        "DEFENSECLAW_AUTHENTICATED_RESOLVER\n"
    )
    environment = os.environ.copy()
    environment.update(
        {
            "SSL_CERT_FILE": "/poisoned/ssl-cert.pem",
            "SSL_CERT_DIR": "/poisoned/ssl-certs",
            "REQUESTS_CA_BUNDLE": "/poisoned/requests-ca.pem",
            "CURL_CA_BUNDLE": "/poisoned/curl-ca.pem",
            "BASH_ENV": "/poisoned/bash-env",
            "PYTHONPATH": "/poisoned/python",
            "COSIGN_FUTURE_TRUST_OVERRIDE": "poisoned",
            "DYLD_FUTURE_LOADER_OVERRIDE": "poisoned",
            "LD_FUTURE_LOADER_OVERRIDE": "poisoned",
            "SIGSTORE_FUTURE_TRUST_OVERRIDE": "poisoned",
            "TUF_FUTURE_TRUST_OVERRIDE": "poisoned",
            "BASH_FUNC_resolver_hint_poison%%": "() { return 91; }",
            "PRESERVED_OPERATOR_VALUE": "yes",
        }
    )
    completed = subprocess.run(
        [_bash_executable()],
        input=probe,
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr
    exported_names = {line.partition("=")[0] for line in completed.stdout.splitlines() if "=" in line}
    assert "PRESERVED_OPERATOR_VALUE" in exported_names
    assert {
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "BASH_ENV",
        "PYTHONPATH",
    }.isdisjoint(exported_names)
    assert not any(
        name.startswith(("BASH_FUNC_", "COSIGN_", "DYLD_", "LD_", "SIGSTORE_", "TUF_")) for name in exported_names
    )


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
  throw '__ambient_network_spoof_used__'
}
function global:Get-FileHash {
  throw '__ambient_digest_spoof_used__'
}
function global:Get-Content {
  throw '__ambient_content_spoof_used__'
}
"""
    environment = os.environ.copy()
    environment["TEMP"] = str(tmp_path)
    environment["TMP"] = str(tmp_path)
    trusted_fetch = "    Microsoft.PowerShell.Utility\\Invoke-WebRequest -Uri $cosignUrl"
    assert trusted_fetch in windows
    instrumented = windows.replace(
        trusted_fetch,
        "    throw '__resolver_dacl_verified_before_fetch__'\n" + trusted_fetch,
        1,
    )
    script = tmp_path / f"resolver-{shell_name.replace('.', '-')}.ps1"
    script.write_text(probe + instrumented, encoding="utf-8")
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
        timeout=30,
    )

    diagnostic = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "__resolver_dacl_verified_before_fetch__" in diagnostic
    assert "__ambient_network_spoof_used__" not in diagnostic
    assert "__ambient_digest_spoof_used__" not in diagnostic
    assert "__ambient_content_spoof_used__" not in diagnostic
    assert not list(tmp_path.glob("defenseclaw-upgrade-*"))


@pytest.mark.parametrize("value", ("v0.8.5", "../0.8.5", "0.8", "00.8.5"))
def test_authenticated_resolver_hint_rejects_unsafe_versions(value: str) -> None:
    with pytest.raises(ValueError, match="canonical"):
        authenticated_resolver_instructions(value)
