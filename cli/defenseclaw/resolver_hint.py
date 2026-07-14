# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Authenticated bootstrap instructions for the release-owned upgrader."""

from __future__ import annotations

import re

DEFAULT_REPOSITORY = "cisco-ai-defense/defenseclaw"
RESOLVER_COMPLETENESS_MARKER = "# DefenseClaw upgrade resolver complete v1"
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
        "  umask 077\n"
        '  d="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-upgrade.XXXXXX")"\n'
        "  trap 'rm -rf \"$d\"' EXIT\n"
        "  command -v cosign >/dev/null\n"
        "  for name in defenseclaw-upgrade.sh checksums.txt checksums.txt.sig "
        "checksums.txt.pem; do\n"
        f"    curl --fail --silent --show-error --location --proto '=https' "
        f"--proto-redir '=https' --tlsv1.2 "
        f"--output \"$d/$name\" '{asset_base}/'$name\n"
        "  done\n"
        "  cosign verify-blob --certificate \"$d/checksums.txt.pem\" "
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
        "& {\n"
        "  $ErrorActionPreference = 'Stop'\n"
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
        "    $accessSection = [Security.AccessControl.AccessControlSections]::Access\n"
        "    if (-not $directoryItem.PSIsContainer -or `\n"
        "        ($directoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or `\n"
        "        -not $verifiedAcl.AreAccessRulesProtected -or `\n"
        "        $verifiedAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $current.Value -or `\n"
        "        $verifiedAcl.GetSecurityDescriptorSddlForm($accessSection) -cne `\n"
        "          $directoryAcl.GetSecurityDescriptorSddlForm($accessSection)) {\n"
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
