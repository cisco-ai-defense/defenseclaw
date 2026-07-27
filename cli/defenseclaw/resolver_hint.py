# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Authenticated bootstrap instructions for the release-owned upgrader."""

from __future__ import annotations

import re

DEFAULT_REPOSITORY = "cisco-ai-defense/defenseclaw"
RESOLVER_COMPLETENESS_MARKER = "# DefenseClaw upgrade resolver complete v1"
COSIGN_BOOTSTRAP_VERSION = "2.6.3"
COSIGN_BOOTSTRAP_SHA256 = {
    ("darwin", "amd64"): "5715d61dd00a9b6dcb344de14910b434145855b7f82690b94183c553ac1b68be",
    ("darwin", "arm64"): "ff497a698f125f3130b04f000b2cb0dd163bcaf00b5e776ef536035e6d0b3f3e",
    ("linux", "amd64"): "7c78a7f2efc00088bd788a758db6e0928e79f3e0eb83eb5d3c499ed98da4c4f4",
    ("linux", "arm64"): "b7c23659a50a59fd8eec44b87188e9062157d0c87796cac7b38727e5390c4917",
    ("windows", "amd64"): "2264ea5867077b9e070161648e8c18544decac351f5f3a7edaea43c233ce2e36",
}
WINDOWS_RESOLVER_BANNER = (
    "# Authenticated resolver bootstrap; requires Windows resolver assets in the selected release."
)
AUTHENTICATED_CA_OVERRIDE_ENV = (
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
)
AUTHENTICATED_CHILD_ENV_REMOVALS = (
    "VERSION",
    "GODEBUG",
    "GOFLAGS",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONINSPECT",
    "PYTHONSTARTUP",
    "PYTHONUSERBASE",
    "PYTHONWARNINGS",
    "PYTHONBREAKPOINT",
    "PERL5OPT",
    "PERL5DB",
    "PERL5LIB",
    "PERLLIB",
    "BASH_ENV",
    "ENV",
    "CDPATH",
    "GLOBIGNORE",
    "BASH_COMPAT",
    "POSIXLY_CORRECT",
    "PROMPT_COMMAND",
    "BASH_XTRACEFD",
    "IFS",
    "DEFENSECLAW_UPGRADE_ALLOW_UNVERIFIED",
    *AUTHENTICATED_CA_OVERRIDE_ENV,
    "SIGSTORE_ROOT_FILE",
    "SIGSTORE_REKOR_PUBLIC_KEY",
    "SIGSTORE_CT_LOG_PUBLIC_KEY_FILE",
    "SIGSTORE_TSA_CERTIFICATE_FILE",
    "TUF_ROOT",
    "TUF_MIRROR",
    "TUF_ROOT_JSON",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_PROFILE",
    "LD_USE_LOAD_BIAS",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FALLBACK_FRAMEWORK_PATH",
    "DYLD_PRINT_APIS",
    "DYLD_PRINT_BINDINGS",
    "DYLD_PRINT_INITIALIZERS",
    "DYLD_PRINT_LIBRARIES",
    "DYLD_PRINT_LIBRARIES_POST_LAUNCH",
    "DYLD_PRINT_OPTS",
    "DYLD_PRINT_REBASINGS",
    "DYLD_PRINT_RPATHS",
    "DYLD_PRINT_SEGMENTS",
    "DYLD_PRINT_STATISTICS",
)
AUTHENTICATED_CHILD_READONLY_ENV_REMOVALS = ("SHELLOPTS", "BASHOPTS")
AUTHENTICATED_CHILD_ENV_PREFIX_REMOVALS = (
    "COSIGN_",
    "DYLD_",
    "LD_",
    "SIGSTORE_",
    "TUF_",
)
AUTHENTICATED_CHILD_FUNCTION_ENV_PREFIX = "BASH_FUNC_"
POSIX_AUTHENTICATED_CHILD_ENV_REMOVALS = AUTHENTICATED_CHILD_ENV_REMOVALS
POSIX_AUTHENTICATED_CHILD_ENV_PREFIX_PATTERN = "|".join(AUTHENTICATED_CHILD_ENV_PREFIX_REMOVALS)
POSIX_AUTHENTICATED_CHILD_FUNCTION_ENV_PATTERN = f"{AUTHENTICATED_CHILD_FUNCTION_ENV_PREFIX}[A-Za-z_][A-Za-z0-9_]*%%"
POSIX_AUTHENTICATED_BOOTSTRAP_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
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
    identity = f"https://github.com/{repository}/.github/workflows/release.yaml@refs/heads/main"
    issuer = "https://token.actions.githubusercontent.com"
    marker = RESOLVER_COMPLETENESS_MARKER

    return (
        "POSIX:\n"
        "/usr/bin/env -u BASH_ENV -u ENV -u SHELLOPTS -u BASHOPTS \\\n"
        "  /bin/bash --noprofile --norc -p <<'DC_AUTHENTICATED_RESOLVER'\n"
        "(\n"
        "  set -eu\n"
        '  operator_path="${PATH:-/usr/bin:/bin:/usr/sbin:/sbin}"\n'
        f"  PATH='{POSIX_AUTHENTICATED_BOOTSTRAP_PATH}'\n"
        "  export PATH\n"
        f"  unset {' '.join(POSIX_AUTHENTICATED_CHILD_ENV_REMOVALS)}\n"
        "  set -- /usr/bin/env -u SHELLOPTS -u BASHOPTS\n"
        '  trust_names="$(/usr/bin/env | /usr/bin/sed -E -n \\\n'
        f"    's/^(({POSIX_AUTHENTICATED_CHILD_ENV_PREFIX_PATTERN})"
        "[A-Za-z0-9_%]*)=.*/\\1/p')\"\n"
        "  for trust_name in $trust_names; do\n"
        '    set -- "$@" -u "$trust_name"\n'
        "  done\n"
        "  unset trust_name trust_names\n"
        '  function_env_names="$(/usr/bin/env | /usr/bin/sed -E -n \\\n'
        f"    's/^({POSIX_AUTHENTICATED_CHILD_FUNCTION_ENV_PATTERN})=.*/\\1/p')\"\n"
        "  for function_env_name in $function_env_names; do\n"
        '    set -- "$@" -u "$function_env_name"\n'
        "  done\n"
        "  unset function_env_name function_env_names\n"
        "  umask 077\n"
        '  d="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-upgrade.XXXXXX")"\n'
        "  trap 'rm -rf \"$d\"' EXIT\n"
        "  platform=\"$(uname -s | tr '[:upper:]' '[:lower:]')/$(uname -m)\"\n"
        '  case "$platform" in\n'
        "    darwin/x86_64) cosign_asset='cosign-darwin-amd64'; "
        f"cosign_sha='{COSIGN_BOOTSTRAP_SHA256[('darwin', 'amd64')]}' ;;\n"
        "    darwin/arm64) cosign_asset='cosign-darwin-arm64'; "
        f"cosign_sha='{COSIGN_BOOTSTRAP_SHA256[('darwin', 'arm64')]}' ;;\n"
        "    linux/x86_64|linux/amd64) cosign_asset='cosign-linux-amd64'; "
        f"cosign_sha='{COSIGN_BOOTSTRAP_SHA256[('linux', 'amd64')]}' ;;\n"
        "    linux/aarch64|linux/arm64) cosign_asset='cosign-linux-arm64'; "
        f"cosign_sha='{COSIGN_BOOTSTRAP_SHA256[('linux', 'arm64')]}' ;;\n"
        "    *) echo 'Unsupported platform for automatic Cosign verification.' >&2; exit 1 ;;\n"
        "  esac\n"
        '  cosign_bin="$d/$cosign_asset"\n'
        "  curl --fail --silent --show-error --location \\\n"
        "    --proto '=https' --proto-redir '=https' --tlsv1.2 \\\n"
        "    --connect-timeout 30 --max-time 300 \\\n"
        "    --speed-limit 1024 --speed-time 60 \\\n"
        '    --max-filesize 209715200 --output "$cosign_bin" \\\n'
        f"      'https://github.com/sigstore/cosign/releases/download/v{COSIGN_BOOTSTRAP_VERSION}/'$cosign_asset\n"
        "  if command -v sha256sum >/dev/null; then\n"
        '    cosign_actual="$("$@" sha256sum "$cosign_bin" | "$@" awk \'{print $1}\')"\n'
        "  else\n"
        '    cosign_actual="$("$@" shasum -a 256 "$cosign_bin" | "$@" awk \'{print $1}\')"\n'
        "  fi\n"
        '  if [ "$cosign_actual" != "$cosign_sha" ]; then\n'
        "    echo 'Downloaded Cosign digest mismatch.' >&2\n"
        "    exit 1\n"
        "  fi\n"
        '  chmod 700 "$cosign_bin"\n'
        "  for name in defenseclaw-upgrade.sh checksums.txt checksums.txt.sig "
        "checksums.txt.pem; do\n"
        f"    curl --fail --silent --show-error --location --proto '=https' "
        f"--proto-redir '=https' --tlsv1.2 "
        f"--connect-timeout 30 --max-time 300 "
        f"--speed-limit 1024 --speed-time 60 --max-filesize 4194304 "
        f"--output \"$d/$name\" '{asset_base}/'$name\n"
        "  done\n"
        '  "$@" "$cosign_bin" verify-blob --certificate "$d/checksums.txt.pem" '
        '--signature "$d/checksums.txt.sig" \\\n'
        f"    --certificate-identity '{identity}' \\\n"
        f"    --certificate-oidc-issuer '{issuer}' \"$d/checksums.txt\"\n"
        "  line=\"$(grep -E '^[0-9a-f]{64}  defenseclaw-upgrade[.]sh$' "
        '"$d/checksums.txt")"\n'
        "  [ \"$(printf '%s\\n' \"$line\" | wc -l | tr -d ' ')\" = 1 ]\n"
        '  expected="${line%% *}"\n'
        "  if command -v sha256sum >/dev/null; then\n"
        '    actual="$("$@" sha256sum "$d/defenseclaw-upgrade.sh" | "$@" awk \'{print $1}\')"\n'
        "  else\n"
        '    actual="$("$@" shasum -a 256 "$d/defenseclaw-upgrade.sh" | "$@" awk \'{print $1}\')"\n'
        "  fi\n"
        '  [ "$actual" = "$expected" ]\n'
        f'  [ "$(tail -n 1 "$d/defenseclaw-upgrade.sh")" = \'{marker}\' ]\n'
        '  PATH="$operator_path" "$@" /bin/bash --noprofile --norc -p '
        '-n "$d/defenseclaw-upgrade.sh" < /dev/null\n'
        '  PATH="$operator_path" "$@" /bin/bash --noprofile --norc -p '
        '"$d/defenseclaw-upgrade.sh" --yes < /dev/null\n'
        ")\n"
        "DC_AUTHENTICATED_RESOLVER\n"
        "Windows PowerShell:\n"
        f"{WINDOWS_RESOLVER_BANNER}\n"
        "& {\n"
        "  $ErrorActionPreference = 'Stop'\n"
        "  $moduleRoot = [IO.Path]::Combine($PSHOME, 'Modules')\n"
        "  $managementModule = [IO.Path]::Combine(\n"
        "    $moduleRoot, 'Microsoft.PowerShell.Management', "
        "'Microsoft.PowerShell.Management.psd1'\n"
        "  )\n"
        "  $securityModule = [IO.Path]::Combine(\n"
        "    $moduleRoot, 'Microsoft.PowerShell.Security', "
        "'Microsoft.PowerShell.Security.psd1'\n"
        "  )\n"
        "  $utilityModule = [IO.Path]::Combine(\n"
        "    $moduleRoot, 'Microsoft.PowerShell.Utility', "
        "'Microsoft.PowerShell.Utility.psd1'\n"
        "  )\n"
        "  Microsoft.PowerShell.Core\\Import-Module "
        "$managementModule -Force -ErrorAction Stop\n"
        "  Microsoft.PowerShell.Core\\Import-Module "
        "$securityModule -Force -ErrorAction Stop\n"
        "  Microsoft.PowerShell.Core\\Import-Module "
        "$utilityModule -Force -ErrorAction Stop\n"
        "  $d = [IO.Path]::Combine([IO.Path]::GetTempPath(), "
        "('defenseclaw-upgrade-' + [Guid]::NewGuid().ToString('N')))\n"
        f"  $cosignVersion = '{COSIGN_BOOTSTRAP_VERSION}'\n"
        "  $cosignAsset = 'cosign-windows-amd64.exe'\n"
        f"  $cosignExpectedSha256 = '{COSIGN_BOOTSTRAP_SHA256[('windows', 'amd64')]}'\n"
        "  $cosignUrl = "
        "'https://github.com/sigstore/cosign/releases/download/v' + "
        "$cosignVersion + '/' + $cosignAsset\n"
        "  [void][IO.Directory]::CreateDirectory($d)\n"
        "  try {\n"
        "    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User\n"
        "    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')\n"
        "    $directoryAcl = [Security.AccessControl.DirectorySecurity]::new()\n"
        "    $directoryAcl.SetOwner($current)\n"
        "    $directoryAcl.SetAccessRuleProtection($true, $false)\n"
        "    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `\n"
        "      [Security.AccessControl.InheritanceFlags]::ObjectInherit\n"
        "    foreach ($sid in @($current, $system)) {\n"
        "      $rule = [Security.AccessControl.FileSystemAccessRule]::new(\n"
        "        $sid,\n"
        "        [Security.AccessControl.FileSystemRights]::FullControl,\n"
        "        $inheritance,\n"
        "        [Security.AccessControl.PropagationFlags]::None,\n"
        "        [Security.AccessControl.AccessControlType]::Allow\n"
        "      )\n"
        "      [void]$directoryAcl.AddAccessRule($rule)\n"
        "    }\n"
        "    Microsoft.PowerShell.Security\\Set-Acl "
        "-LiteralPath $d -AclObject $directoryAcl -ErrorAction Stop\n"
        "    $directoryItem = Microsoft.PowerShell.Management\\Get-Item "
        "-LiteralPath $d -Force -ErrorAction Stop\n"
        "    $verifiedAcl = Microsoft.PowerShell.Security\\Get-Acl "
        "-LiteralPath $d -ErrorAction Stop\n"
        "    $verifiedRules = @($verifiedAcl.GetAccessRules(\n"
        "      $true, $false, [Security.Principal.SecurityIdentifier]))\n"
        "    $allowedSids = @($current.Value, $system.Value) | "
        "Microsoft.PowerShell.Utility\\Select-Object -Unique\n"
        "    $invalidRule = @($verifiedRules | Microsoft.PowerShell.Utility\\Where-Object {\n"
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
        "    foreach ($trustName in @([Environment]::GetEnvironmentVariables().Keys)) {\n"
        "      if ([string]$trustName -match '^(COSIGN|SIGSTORE|TUF)_') {\n"
        "        [Environment]::SetEnvironmentVariable(\n"
        "          [string]$trustName,\n"
        "          $null,\n"
        "          [EnvironmentVariableTarget]::Process\n"
        "        )\n"
        "      }\n"
        "    }\n"
        "    foreach ($exactTrustName in @('VERSION', 'GODEBUG', 'GOFLAGS')) {\n"
        "      [Environment]::SetEnvironmentVariable(\n"
        "        $exactTrustName, $null, [EnvironmentVariableTarget]::Process\n"
        "      )\n"
        "    }\n"
        "    if ($PSVersionTable.PSEdition -eq 'Desktop') {\n"
        "      [Net.ServicePointManager]::SecurityProtocol = "
        "[Net.SecurityProtocolType]::Tls12\n"
        "    }\n"
        "    $cosign = [IO.Path]::Combine($d, $cosignAsset)\n"
        "    Microsoft.PowerShell.Utility\\Invoke-WebRequest "
        "-Uri $cosignUrl -OutFile $cosign -UseBasicParsing "
        "-MaximumRedirection 5 -TimeoutSec 300 -ErrorAction Stop\n"
        "    $cosignItem = Microsoft.PowerShell.Management\\Get-Item "
        "-LiteralPath $cosign -Force -ErrorAction Stop\n"
        "    if ($cosignItem.PSIsContainer -or `\n"
        "        ($cosignItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or `\n"
        "        $cosignItem.Length -le 0 -or $cosignItem.Length -gt 209715200) {\n"
        "      throw 'Downloaded Cosign has an invalid file type or size.'\n"
        "    }\n"
        "    $cosignActualSha256 = (\n"
        "      Microsoft.PowerShell.Utility\\Get-FileHash "
        "-LiteralPath $cosign -Algorithm SHA256\n"
        "    ).Hash.ToLowerInvariant()\n"
        "    if ($cosignActualSha256 -ne $cosignExpectedSha256) {\n"
        "      throw 'Downloaded Cosign digest mismatch.'\n"
        "    }\n"
        "    foreach ($name in @('defenseclaw-upgrade.ps1', 'checksums.txt', "
        "'checksums.txt.sig', 'checksums.txt.pem')) {\n"
        "      $assetPath = [IO.Path]::Combine($d, $name)\n"
        f"      Microsoft.PowerShell.Utility\\Invoke-WebRequest -Uri ('{asset_base}/' + $name) "
        "-OutFile $assetPath -UseBasicParsing -MaximumRedirection 5 "
        "-TimeoutSec 300 -ErrorAction Stop\n"
        "      $assetItem = Microsoft.PowerShell.Management\\Get-Item "
        "-LiteralPath $assetPath -Force -ErrorAction Stop\n"
        "      if ($assetItem.PSIsContainer -or `\n"
        "          ($assetItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or `\n"
        "          $assetItem.Length -le 0 -or $assetItem.Length -gt 4194304) {\n"
        "        throw ('Downloaded release proof has an invalid file type or size: ' + $name)\n"
        "      }\n"
        "    }\n"
        "    & $cosign verify-blob "
        "--certificate ([IO.Path]::Combine($d, 'checksums.txt.pem')) "
        "--signature ([IO.Path]::Combine($d, 'checksums.txt.sig')) `\n"
        f"      --certificate-identity '{identity}' `\n"
        f"      --certificate-oidc-issuer '{issuer}' "
        "([IO.Path]::Combine($d, 'checksums.txt'))\n"
        "    if ($LASTEXITCODE -ne 0) { throw 'Resolver checksum signature is invalid.' }\n"
        "    $checksumRows = @(\n"
        "      Microsoft.PowerShell.Management\\Get-Content "
        "-LiteralPath ([IO.Path]::Combine($d, 'checksums.txt')) |\n"
        "        Microsoft.PowerShell.Utility\\Where-Object "
        "{ $_ -match '^[0-9a-f]{64}  defenseclaw-upgrade[.]ps1$' }\n"
        "    )\n"
        "    if ($checksumRows.Count -ne 1) { throw 'Resolver checksum entry is missing or duplicated.' }\n"
        "    $expected = ($checksumRows[0] -split '\\s+', 2)[0]\n"
        "    $r = [IO.Path]::Combine($d, 'defenseclaw-upgrade.ps1')\n"
        "    $actual = (Microsoft.PowerShell.Utility\\Get-FileHash "
        "-LiteralPath $r -Algorithm SHA256).Hash.ToLowerInvariant()\n"
        "    if ($actual -ne $expected) { throw 'Resolver checksum does not match.' }\n"
        f"    if ((Microsoft.PowerShell.Management\\Get-Content "
        f"-LiteralPath $r -Tail 1) -ne '{marker}') {{\n"
        "      throw 'Downloaded DefenseClaw resolver is incomplete.'\n"
        "    }\n"
        "    [void][scriptblock]::Create((Microsoft.PowerShell.Management\\Get-Content "
        "-LiteralPath $r -Raw))\n"
        "    & $r -Yes\n"
        "  } finally {\n"
        "    Microsoft.PowerShell.Management\\Remove-Item "
        "-LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue\n"
        "  }\n"
        "}"
    )
