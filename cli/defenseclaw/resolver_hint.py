# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Authenticated bootstrap instructions for the release-owned upgrader."""

from __future__ import annotations

import re

DEFAULT_REPOSITORY = "cisco-ai-defense/defenseclaw"
RESOLVER_COMPLETENESS_MARKER = "# DefenseClaw upgrade resolver complete v1"
COSIGN_BOOTSTRAP_VERSION = "2.6.3"
_COSIGN_DARWIN_AMD64_SHA256 = "5715d61dd00a9b6dcb344de14910b434145855b7f82690b94183c553ac1b68be"
_COSIGN_DARWIN_ARM64_SHA256 = "ff497a698f125f3130b04f000b2cb0dd163bcaf00b5e776ef536035e6d0b3f3e"
_COSIGN_LINUX_AMD64_SHA256 = "7c78a7f2efc00088bd788a758db6e0928e79f3e0eb83eb5d3c499ed98da4c4f4"
_COSIGN_LINUX_ARM64_SHA256 = "b7c23659a50a59fd8eec44b87188e9062157d0c87796cac7b38727e5390c4917"
_VERSION_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def authenticated_resolver_instructions(
    version: str,
    *,
    repository: str = DEFAULT_REPOSITORY,
) -> str:
    """Return copy/pasteable commands that verify the resolver before execution."""

    if not _VERSION_RE.fullmatch(version):
        raise ValueError("resolver version must be canonical X.Y.Z")
    if not _REPOSITORY_RE.fullmatch(repository):
        raise ValueError("resolver repository must be owner/name")

    asset_base = f"https://github.com/{repository}/releases/download/{version}"
    identity = (
        f"https://github.com/{repository}/.github/workflows/"
        "release.yaml@refs/heads/main"
    )
    issuer = "https://token.actions.githubusercontent.com"
    marker = RESOLVER_COMPLETENESS_MARKER

    return (
        "POSIX:\n"
        "(\n"
        "  set -eu\n"
        "  unset VERSION\n"
        "  umask 077\n"
        '  d="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-upgrade.XXXXXX")"\n'
        "  trap 'rm -rf \"$d\"' EXIT\n"
        '  cosign_bin="$(command -v cosign || true)"\n'
        '  if [ -z "$cosign_bin" ]; then\n'
        '    platform="$(uname -s | tr \'[:upper:]\' \'[:lower:]\')/$(uname -m)"\n'
        '    case "$platform" in\n'
        "      darwin/x86_64) cosign_asset='cosign-darwin-amd64'; "
        f"cosign_sha='{_COSIGN_DARWIN_AMD64_SHA256}' ;;\n"
        "      darwin/arm64) cosign_asset='cosign-darwin-arm64'; "
        f"cosign_sha='{_COSIGN_DARWIN_ARM64_SHA256}' ;;\n"
        "      linux/x86_64|linux/amd64) cosign_asset='cosign-linux-amd64'; "
        f"cosign_sha='{_COSIGN_LINUX_AMD64_SHA256}' ;;\n"
        "      linux/aarch64|linux/arm64) cosign_asset='cosign-linux-arm64'; "
        f"cosign_sha='{_COSIGN_LINUX_ARM64_SHA256}' ;;\n"
        "      *) echo 'Unsupported platform for automatic Cosign verification.' >&2; exit 1 ;;\n"
        "    esac\n"
        '    cosign_bin="$d/$cosign_asset"\n'
        "    curl --fail --silent --show-error --location \\\n"
        "      --proto '=https' --proto-redir '=https' --tlsv1.2 \\\n"
        "      --max-filesize 209715200 --output \"$cosign_bin\" \\\n"
        f"      'https://github.com/sigstore/cosign/releases/download/v{COSIGN_BOOTSTRAP_VERSION}/'$cosign_asset\n"
        '    if command -v sha256sum >/dev/null; then\n'
        '      cosign_actual="$(sha256sum "$cosign_bin" | awk \'{print $1}\')"\n'
        "    else\n"
        '      cosign_actual="$(shasum -a 256 "$cosign_bin" | awk \'{print $1}\')"\n'
        "    fi\n"
        '    [ "$cosign_actual" = "$cosign_sha" ]\n'
        '    chmod 700 "$cosign_bin"\n'
        '  fi\n'
        "  for name in defenseclaw-upgrade.sh checksums.txt checksums.txt.sig "
        "checksums.txt.pem; do\n"
        f"    curl --fail --silent --show-error --location --proto '=https' "
        f"--proto-redir '=https' --tlsv1.2 "
        f"--output \"$d/$name\" '{asset_base}/'$name\n"
        "  done\n"
        "  \"$cosign_bin\" verify-blob --certificate \"$d/checksums.txt.pem\" "
        "--signature \"$d/checksums.txt.sig\" \\\n"
        f"    --certificate-identity '{identity}' \\\n"
        f"    --certificate-oidc-issuer '{issuer}' \"$d/checksums.txt\"\n"
        "  line=\"$(grep -E '^[0-9a-f]{64}  defenseclaw-upgrade[.]sh$' "
        "\"$d/checksums.txt\")\"\n"
        "  [ \"$(printf '%s\\n' \"$line\" | wc -l | tr -d ' ')\" = 1 ]\n"
        "  expected=\"${line%% *}\"\n"
        "  if command -v sha256sum >/dev/null; then\n"
        "    actual=\"$(sha256sum \"$d/defenseclaw-upgrade.sh\" | awk '{print $1}')\"\n"
        "  else\n"
        "    actual=\"$(shasum -a 256 \"$d/defenseclaw-upgrade.sh\" | awk '{print $1}')\"\n"
        "  fi\n"
        "  [ \"$actual\" = \"$expected\" ]\n"
        f"  [ \"$(tail -n 1 \"$d/defenseclaw-upgrade.sh\")\" = '{marker}' ]\n"
        "  bash -n \"$d/defenseclaw-upgrade.sh\"\n"
        "  bash \"$d/defenseclaw-upgrade.sh\" --yes\n"
        ")\n"
        "Windows PowerShell:\n"
        "# Preflight refusal only: no 0.8.4 Windows bridge binaries were published.\n"
        "& {\n"
        "  $ErrorActionPreference = 'Stop'\n"
        "  $securityModule = Join-Path $PSHOME "
        "'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1'\n"
        "  Import-Module $securityModule -ErrorAction Stop\n"
        "  $d = Join-Path ([IO.Path]::GetTempPath()) "
        "('defenseclaw-upgrade-' + [Guid]::NewGuid().ToString('N'))\n"
        "  [void](New-Item -ItemType Directory -Path $d)\n"
        "  try {\n"
        "    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User\n"
        "    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')\n"
        "    $directoryAcl = New-Object Security.AccessControl.DirectorySecurity\n"
        "    $directoryAcl.SetOwner($current)\n"
        "    $directoryAcl.SetAccessRuleProtection($true, $false)\n"
        "    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `\n"
        "      [Security.AccessControl.InheritanceFlags]::ObjectInherit\n"
        "    foreach ($sid in @($current, $system)) {\n"
        "      $rule = New-Object Security.AccessControl.FileSystemAccessRule(\n"
        "        $sid,\n"
        "        [Security.AccessControl.FileSystemRights]::FullControl,\n"
        "        $inheritance,\n"
        "        [Security.AccessControl.PropagationFlags]::None,\n"
        "        [Security.AccessControl.AccessControlType]::Allow\n"
        "      )\n"
        "      [void]$directoryAcl.AddAccessRule($rule)\n"
        "    }\n"
        "    Set-Acl -LiteralPath $d -AclObject $directoryAcl -ErrorAction Stop\n"
        "    $directoryItem = Get-Item -LiteralPath $d -Force -ErrorAction Stop\n"
        "    $verifiedAcl = Get-Acl -LiteralPath $d -ErrorAction Stop\n"
        "    $verifiedRules = @($verifiedAcl.GetAccessRules(\n"
        "      $true, $false, [Security.Principal.SecurityIdentifier]))\n"
        "    $allowedSids = @($current.Value, $system.Value) | Select-Object -Unique\n"
        "    $invalidRule = @($verifiedRules | Where-Object {\n"
        "      $allowedSids -notcontains $_.IdentityReference.Value -or `\n"
        "      $_.IsInherited -or `\n"
        "      $_.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or `\n"
        "      $_.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or `\n"
        "      $_.InheritanceFlags -ne $inheritance -or `\n"
        "      $_.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None\n"
        "    }).Count -ne 0\n"
        "    if (-not $directoryItem.PSIsContainer -or `\n"
        "        ($directoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or `\n"
        "        -not $verifiedAcl.AreAccessRulesProtected -or `\n"
        "        $verifiedAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $current.Value -or `\n"
        "        $verifiedRules.Count -ne $allowedSids.Count -or $invalidRule) {\n"
        "      throw 'Resolver temporary directory owner/DACL validation failed before download.'\n"
        "    }\n"
        "    [void](Get-Command cosign -ErrorAction Stop)\n"
        "    foreach ($name in @('defenseclaw-upgrade.ps1', 'checksums.txt', "
        "'checksums.txt.sig', 'checksums.txt.pem')) {\n"
        f"      Invoke-WebRequest -Uri ('{asset_base}/' + $name) "
        "-OutFile (Join-Path $d $name) -UseBasicParsing -ErrorAction Stop\n"
        "    }\n"
        "    & cosign verify-blob --certificate (Join-Path $d 'checksums.txt.pem') "
        "--signature (Join-Path $d 'checksums.txt.sig') `\n"
        f"      --certificate-identity '{identity}' `\n"
        f"      --certificate-oidc-issuer '{issuer}' (Join-Path $d 'checksums.txt')\n"
        "    if ($LASTEXITCODE -ne 0) { throw 'Resolver checksum signature is invalid.' }\n"
        "    $checksumRows = @(Get-Content -LiteralPath (Join-Path $d 'checksums.txt') | "
        "Where-Object { $_ -match '^[0-9a-f]{64}  defenseclaw-upgrade[.]ps1$' })\n"
        "    if ($checksumRows.Count -ne 1) { throw 'Resolver checksum entry is missing or duplicated.' }\n"
        "    $expected = ($checksumRows[0] -split '\\s+', 2)[0]\n"
        "    $r = Join-Path $d 'defenseclaw-upgrade.ps1'\n"
        "    $actual = (Get-FileHash -LiteralPath $r -Algorithm SHA256).Hash.ToLowerInvariant()\n"
        "    if ($actual -ne $expected) { throw 'Resolver checksum does not match.' }\n"
        f"    if ((Get-Content -LiteralPath $r -Tail 1) -ne '{marker}') {{\n"
        "      throw 'Downloaded DefenseClaw resolver is incomplete.'\n"
        "    }\n"
        "    [void][scriptblock]::Create((Get-Content -LiteralPath $r -Raw))\n"
        "    & $r -Yes\n"
        "  } finally {\n"
        "    Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue\n"
        "  }\n"
        "}"
    )
