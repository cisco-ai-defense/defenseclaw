# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#Requires -Version 7.4
<#
.SYNOPSIS
    Builds the Intune Win32 app content for the DefenseClaw standalone
    deployment and prints the values to enter in the Intune admin center.

.DESCRIPTION
    Run on an administrator workstation. Verifies DefenseClawSetup-Enterprise-Standalone-x64.exe
    (hash-pinned against -Sha256, which you take from the release's
    cosign-verified checksums.txt, and/or Authenticode against
    -AllowedSigners), copies it with config.yaml, a signed policy
    bundle with optional trust anchors, or both (the single app) into a content folder, writes intune-package.json with the SHA-256 pins
    the launcher re-checks on the device, and, when -IntuneWinAppUtil is
    given, wraps the folder into a .intunewin.

    Never put credentials in config.yaml: the Win32 app content is not secret
    storage. Deliver the AI Defense key separately (see the Intune on Windows page in the docs).
    Single app (recommended): -ConfigPath with -BundlePath and -TrustAnchorPath
    builds one app. On a new device Setup stages the install from config.yaml
    with every service stopped, then applies the signed bundle and starts the
    services on it; nothing runs on config.yaml. On an installed device the
    same app applies the bundle only, so later bundle versions are new
    versions of this app (no app dependency).

    Bundle-only app (devices installed with the earlier two-app recipe until
    they move to the single app): -BundlePath without -ConfigPath. It needs
    an installed base deployment. -BaseConfigPath names
    the config packaged in that base app; its guardrail policy must match the
    signed bundle, apart from the custom pack's installed path. Install that
    pack before the base app with a rule-pack app built from
    Install-DefenseClawRulePack.ps1; the script prints a Prerequisite line for
    every such pack. Verify the bundle offline with
    defenseclaw-gateway enterprise bundle verify before packaging it.
    The base config's claude_code, codex, connector_hooks and
    application_protection blocks (the hook modes) must equal the bundle's,
    or be absent from both. The packager compares the configs as text, so the
    base config must be plain ASCII with LF or CRLF line endings, write each
    top-level key plainly in lowercase and end each quoted value and each
    {...} or [...] on the line where it starts.

.EXAMPLE
    ./New-DefenseClawIntunePackage.ps1 -SetupPath .\DefenseClawSetup-Enterprise-Standalone-x64.exe -Sha256 <pin> `
        -ConfigPath .\config.yaml -OutputDirectory .\out -IntuneWinAppUtil C:\Tools\IntuneWinAppUtil.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SetupPath,
    [string]$Sha256 = '',
    [ValidateSet('HashPinned', 'Authenticode')][string]$TrustMode = 'HashPinned',
    [string[]]$AllowedSigners = @(),
    [string]$ConfigPath = '',
    [string]$BundlePath = '',
    [string]$BaseConfigPath = '',
    [string]$TrustAnchorPath = '',
    [string]$RequireBundle = '',
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$IntuneWinAppUtil = '',
    [string]$ProductVersion = ''
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
if (-not [IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = Join-Path (Get-Location).ProviderPath $OutputDirectory
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)

if ($BundlePath -and $ConfigPath -and $BaseConfigPath) { throw '-BaseConfigPath is only for a bundle-only app: the single app (-ConfigPath with -BundlePath) never runs on config.yaml, so it is not compared with the bundle' }
if ($BundlePath -and -not $ConfigPath -and -not $BaseConfigPath) { throw '-BaseConfigPath is required with -BundlePath alone (a bundle-only app for a device installed with the two-app recipe): the base CONFIG= must enforce the signed bundle rule pack. For a new deployment build the single app with -ConfigPath and -BundlePath' }
if ($BaseConfigPath -and -not $BundlePath) { throw '-BaseConfigPath needs -BundlePath' }
if ($TrustAnchorPath -and -not $BundlePath) { throw '-TrustAnchorPath needs -BundlePath: the kit installs trust anchors together with a signed bundle' }
if ($BundlePath -and -not $RequireBundle) { throw '-RequireBundle is required with -BundlePath for the bundle app detection rule' }
if ($RequireBundle -and -not $BundlePath) { throw '-RequireBundle needs -BundlePath' }
if ($RequireBundle -and $RequireBundle -cnotmatch '^(?:[1-9][0-9]{0,18}|b-[0-9A-HJKMNP-TV-Z]{26})$') { throw '-RequireBundle must be a positive version number or bundle id' }
if ($ProductVersion -and $ProductVersion -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.+-]+)?$') { throw '-ProductVersion must be a valid version' }
if ($BundlePath) {
    $BundlePath = (Resolve-Path -LiteralPath $BundlePath).ProviderPath
    $bundleItem = Get-Item -LiteralPath $BundlePath -Force
    if (-not ($bundleItem -is [IO.FileInfo]) -or ($bundleItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw '-BundlePath must be a regular file' }
    if ($bundleItem.Length -lt 1 -or $bundleItem.Length -gt 4MB) { throw '-BundlePath must contain 1 to 4194304 bytes' }
}
if ($TrustAnchorPath) {
    $TrustAnchorPath = (Resolve-Path -LiteralPath $TrustAnchorPath).ProviderPath
    $anchorItem = Get-Item -LiteralPath $TrustAnchorPath -Force
    if (-not ($anchorItem -is [IO.FileInfo]) -or ($anchorItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw '-TrustAnchorPath must be a regular file' }
    if ($anchorItem.Length -gt 64KB) { throw '-TrustAnchorPath exceeds 65536 bytes' }
    $anchorText = Get-Content -LiteralPath $TrustAnchorPath -Raw
    if ($anchorText -match '-----BEGIN [A-Z ]*PRIVATE KEY-----') { throw '-TrustAnchorPath contains a private key' }
    try { $anchorJson = $anchorText | ConvertFrom-Json -ErrorAction Stop } catch { throw '-TrustAnchorPath must contain a JSON object with schema_version 1' }
    if ($null -eq $anchorJson -or $anchorJson -isnot [pscustomobject] -or $null -eq $anchorJson.PSObject.Properties['schema_version'] -or $anchorJson.schema_version -isnot [long] -or $anchorJson.schema_version -ne 1) { throw '-TrustAnchorPath must contain a JSON object with schema_version 1' }
}

function Get-TopLevelBlock {
    # Every top-level <Key>: block of a config (the key plain or quoted),
    # without blank and full-line comment lines; '' when there is none.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [Parameter(Mandatory)][string]$Key)
    $inside = $false
    $found = @()
    foreach ($line in ($Text.TrimStart([char]0xFEFF) -split "`n")) {
        $line = $line.TrimEnd([char]13)
        if ($line -match '^[ \t]*(#|$)') { continue }
        if (-not $line.StartsWith(' ')) {
            $inside = $line -cmatch ('^(' + $Key + '|"' + $Key + '"|''' + $Key + ''')[ \t]*:([ \t]|$)')
        }
        if ($inside) { $found += $line }
    }
    return ($found -join "`n")
}

function Get-BaseConfigSpellingProblem {
    # Get-GuardrailBlock and Get-TopLevelBlock find a key by its text. The
    # product's loader also reads "claude\u005fcode":, !!str claude_code: and
    # ? claude_code as claude_code, and takes a line that continues a quoted
    # value or a {...} or [...] as part of that value even when the line
    # starts in column 1, so a base config written that way passed the
    # compare and still set a hook mode or hid its guardrail block (GAP-0090
    # verify r2). The loader also starts a new line at a lone CR, NEL, LS and
    # PS, so a key after one was hidden from these checks, which split lines
    # only at LF (GAP-0090 verify r3). So first every byte of the file must be
    # printable ASCII or LF, a CR may come only right before an LF and a UTF-8
    # byte order mark only first; the bytes are read raw, so the check does
    # not depend on how PowerShell decodes the file. Returns why the config is
    # not plain enough to compare, or ''. The Unix wrappers' dc_plain_bytes
    # and dc_plain_yaml apply the same rules.
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)
    $first = 0
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) { $first = 3 }
    $number = 1
    for ($i = $first; $i -lt $Bytes.Length; $i++) {
        $b = $Bytes[$i]
        if ($b -eq 10) { $number++; continue }
        if (($b -ge 0x20 -and $b -le 0x7E) -or ($b -eq 13 -and $i + 1 -lt $Bytes.Length -and $Bytes[$i + 1] -eq 10)) { continue }
        $next = @(1, 2 | ForEach-Object { if ($i + $_ -lt $Bytes.Length) { [int]$Bytes[$i + $_] } else { -1 } })
        $what = if ($b -eq 0) { 'a NUL byte' }
        elseif ($b -eq 9) { 'a tab' }
        elseif ($b -eq 11) { 'a vertical tab' }
        elseif ($b -eq 12) { 'a form feed' }
        elseif ($b -eq 13) { 'a carriage return (CR) that is not followed by a line feed (LF)' }
        elseif ($b -lt 0x80) { 'a control character (0x{0:X2})' -f $b }
        elseif ($b -eq 0xC2 -and $next[0] -eq 0x85) { 'a NEL (U+0085) line break' }
        elseif ($b -eq 0xE2 -and $next[0] -eq 0x80 -and $next[1] -eq 0xA8) { 'an LS (U+2028) line break' }
        elseif ($b -eq 0xE2 -and $next[0] -eq 0x80 -and $next[1] -eq 0xA9) { 'a PS (U+2029) line break' }
        elseif ($b -eq 0xEF -and $next[0] -eq 0xBB -and $next[1] -eq 0xBF) { 'a byte order mark that is not at the start of the file' }
        else { 'a non-ASCII byte (0x{0:X2})' -f $b }
        return "line $number has $what; write the base config in plain ASCII with LF or CRLF line ends"
    }
    $Text = [Text.Encoding]::ASCII.GetString($Bytes, $first, $Bytes.Length - $first)
    $compared = @('guardrail', 'claude_code', 'codex', 'connector_hooks', 'application_protection')
    $block = -1
    $top = $false
    $number = 0
    foreach ($raw in ($Text -split "`n")) {
        $number++
        $line = $raw.TrimEnd([char]13)
        $n = $line.Length
        $indent = $n - $line.TrimStart(' ').Length
        if ($block -ge 0) {
            if ($line -match '^ *$' -or $indent -gt $block) { continue }
            $block = -1
        }
        if ($line -match '^ *(#|$)') { continue }
        if ($indent -eq 0) {
            if ($line -ceq '---' -and -not $top) { $top = $true; continue }
            $top = $true
            if ($line -cnotmatch '^([a-z0-9_]+|"[a-z0-9_]+"|''[a-z0-9_]+'') *:( |$)') {
                $key = ($line -replace ' *:.*$', '').Trim([char[]]@('"', "'"))
                if ($compared -contains $key -and $key -cne $key.ToLowerInvariant()) {
                    return "line $number writes the top-level key $($key.ToLowerInvariant()) in other letters; write it in lowercase"
                }
                return "line $number is not a plain top-level key; write each top-level key in lowercase letters, digits and underscores, plain or in quotes, without an escape, tag, anchor, alias, merge key, complex key or {...} or [...]"
            }
        }
        # A single-quoted '' reads as the end of one quoted value and the
        # start of the next, which ends on the same line either way.
        $i = $indent; $depth = 0; $owner = $indent; $start = $indent
        while ($i -lt $n) {
            $c = $line[$i]
            $spaced = $i + 1 -ge $n -or $line[$i + 1] -eq ' '
            if ($c -eq ' ') { $i++; continue }
            if ($c -eq '#') { break }
            if ($c -eq '"' -or $c -eq "'") {
                $j = $i + 1
                while ($j -lt $n -and $line[$j] -ne $c) {
                    if ($c -eq '"' -and $line[$j] -eq '\') { $j++ }
                    $j++
                }
                if ($j -ge $n) { return "line $number leaves a quoted value open; end each quoted value on the line it starts on" }
                $start = $i; $i = $j + 1; continue
            }
            if ('{['.Contains($c)) { $depth++; $i++; continue }
            if ('}]'.Contains($c) -and $depth -gt 0) { $depth--; $i++; continue }
            if ($c -eq ',' -and $depth -gt 0) { $i++; continue }
            if ($c -eq ':' -and ($spaced -or $depth -gt 0)) { $owner = $start; $i++; continue }
            if ('-?'.Contains($c) -and $spaced) { $owner = $i; $i++; continue }
            if ('|>'.Contains($c) -and $depth -eq 0) { $block = $owner; break }
            if ('!&*'.Contains($c)) {
                while ($i -lt $n -and -not ' ,{}[]'.Contains($line[$i])) { $i++ }
                continue
            }
            $start = $i
            for (; $i -lt $n; $i++) {
                $c = $line[$i]
                if ($c -eq ':' -and ($depth -gt 0 -or $i + 1 -ge $n -or $line[$i + 1] -eq ' ')) { break }
                if ($depth -gt 0 -and ',{}[]'.Contains($c)) { break }
                if ($c -eq '#' -and $line[$i - 1] -eq ' ') { break }
            }
        }
        if ($block -lt 0 -and $depth -gt 0) { return "line $number leaves a {...} or [...] open; end each one on the line it starts on" }
    }
    return ''
}

function Get-GuardrailBlock {
    param([Parameter(Mandatory)][string]$Text)
    $lines = ($Text -replace "`r`n", "`n") -split "`n"
    $blocks = @()
    for ($i = 0; $i -lt $lines.Length; $i++) {
        if ($lines[$i] -ceq 'guardrail:') { $blocks += $i }
    }
    if ($blocks.Count -ne 1) { throw 'base and bundle configs must each have one plain guardrail: block' }
    $start = $blocks[0]
    $end = $start + 1
    # A full-line comment, even at column 0, does not end the mapping in
    # YAML: the keys after it are still guardrail keys, so the block runs on
    # across it and leaves comment lines out of the compare.
    while ($end -lt $lines.Length -and ($lines[$end] -eq '' -or $lines[$end] -match '^ ' -or $lines[$end] -match '^#')) { $end++ }
    return (@($lines[$start..($end - 1)] | Where-Object { $_ -notmatch '^\s*#' }) -join "`n").TrimEnd([char]10)
}

function Get-CustomPackPath {
    # guardrail.custom_packs.<Pack>.path of a Get-GuardrailBlock block, as
    # its line index and unquoted value, or $null.
    param([Parameter(Mandatory)][AllowEmptyString()][string[]]$Lines, [Parameter(Mandatory)][string]$Pack)
    $inPacks = $false
    $inPack = $false
    for ($i = 0; $i -lt $Lines.Length; $i++) {
        $line = $Lines[$i]
        if ($line -ceq '  custom_packs:') { $inPacks = $true; $inPack = $false; continue }
        if ($inPacks -and $line -match '^ {0,3}\S') { $inPacks = $false }
        if (-not $inPacks) { continue }
        if ($line -cmatch '^    ([^\s:]+):\s*$') { $inPack = ($Matches[1] -ceq $Pack); continue }
        if ($inPack -and $line -cmatch '^      path:\s*(?<value>\S.*?)\s*$') {
            return @{ Index = $i; Value = $Matches['value'].Trim([char[]]@('"', "'")) }
        }
    }
    return $null
}

function Get-PreinstalledPackPath {
    # guardrail.custom_packs entries of a config whose path is an absolute
    # folder outside the DefenseClaw install tree: Setup does not deliver
    # them, so the device needs them before the base app runs.
    param([AllowEmptyString()][string]$Text)
    if (-not $Text) { return @() }
    try { $lines = @((Get-GuardrailBlock -Text $Text) -split "`n") } catch { return @() }
    $found = @()
    $inPacks = $false
    $pack = ''
    foreach ($line in $lines) {
        if ($line -ceq '  custom_packs:') { $inPacks = $true; $pack = ''; continue }
        if ($inPacks -and $line -match '^ {0,3}\S') { $inPacks = $false }
        if (-not $inPacks) { continue }
        if ($line -cmatch '^    ([^\s:]+):\s*$') { $pack = $Matches[1]; continue }
        if ($pack -and $line -cmatch '^      path:\s*(?<value>\S.*?)\s*$') {
            $value = $Matches['value'].Trim([char[]]@('"', "'"))
            if ($value -match '^[A-Za-z]:\\' -and $value -notmatch '^[A-Za-z]:\\(Program Files|ProgramData)\\Cisco\\DefenseClaw(\\|$)') {
                $found += [pscustomobject]@{ Name = $pack; Path = $value }
            }
        }
    }
    return $found
}

if ($BundlePath -and $BaseConfigPath) {
    # Raw bytes: Get-Content would decode them (as ANSI in Windows PowerShell).
    $baseBytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $BaseConfigPath).ProviderPath)
    $spelling = Get-BaseConfigSpellingProblem -Bytes $baseBytes
    if ($spelling) { throw "base CONFIG= $spelling" }
    $baseText = [Text.Encoding]::UTF8.GetString($baseBytes).TrimStart([char]0xFEFF)
    if ($baseText -match '(?im)^\s*api_key\s*:\s*\S') { throw 'base config contains an inline api_key' }
    $file = [IO.File]::OpenRead($BundlePath)
    try {
        $gzip = [IO.Compression.GZipStream]::new($file, [IO.Compression.CompressionMode]::Decompress)
        try {
            $tar = [System.Formats.Tar.TarReader]::new($gzip)
            try {
                $entries = @{}
                $entryCount = 0
                $expandedBytes = [long]0
                while ($null -ne ($entry = $tar.GetNextEntry())) {
                    $entryCount++
                    $expandedBytes += [long]$entry.Length
                    if ($entryCount -gt 512 -or $expandedBytes -gt 16MB) {
                        throw 'bundle exceeds the entry or expanded-size limit'
                    }
                    if ($entry.Name -notin @('manifest.json', 'config.yaml')) { continue }
                    if ($entries.ContainsKey($entry.Name) -or $entry.Length -gt 262144 -or $null -eq $entry.DataStream) {
                        throw "bundle $($entry.Name) is duplicate or invalid"
                    }
                    $buffer = [IO.MemoryStream]::new()
                    $entry.DataStream.CopyTo($buffer)
                    $entries[$entry.Name] = $buffer.ToArray()
                    $buffer.Dispose()
                }
            } finally { $tar.Dispose() }
        } finally { $gzip.Dispose() }
    } finally { $file.Dispose() }
    if (-not $entries.ContainsKey('manifest.json') -or -not $entries.ContainsKey('config.yaml')) {
        throw 'bundle must contain manifest.json and config.yaml'
    }
    $manifest = [Text.Encoding]::UTF8.GetString($entries['manifest.json']) | ConvertFrom-Json
    $configEntry = @($manifest.files | Where-Object { $_.path -ceq 'config.yaml' })
    $configHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($entries['config.yaml'])).ToLowerInvariant()
    if ($configEntry.Count -ne 1 -or $configEntry[0].sha256 -cne $configHash) {
        throw 'bundle config.yaml does not match the signed manifest files[] pin'
    }
    $packs = @($manifest.files | Where-Object { $_.path -match '^policies/guardrail/([^/]+)/' } |
        ForEach-Object { [regex]::Match($_.path, '^policies/guardrail/([^/]+)/').Groups[1].Value } | Sort-Object -Unique)
    $bundleBlock = Get-GuardrailBlock -Text ([Text.Encoding]::UTF8.GetString($entries['config.yaml']))
    $baseBlock = Get-GuardrailBlock -Text $baseText
    $bundleLines = @($bundleBlock -split "`n")
    $baseLines = @($baseBlock -split "`n")
    $selected = @($bundleLines | Where-Object { $_ -cmatch '^  rule_pack: ' })
    if ($selected.Count -eq 1 -and $baseLines -cnotcontains $selected[0]) {
        throw "base CONFIG= must select the bundle rule pack $($selected[0].Substring(13).Trim())"
    }
    # The base block may differ from the bundle's only where each custom pack
    # is installed: the bundle names policies/guardrail/<pack> inside itself,
    # the base an absolute, preinstalled directory. A bundle without custom
    # packs needs an identical block.
    foreach ($packName in $packs) {
        $bundlePack = Get-CustomPackPath -Lines $bundleLines -Pack $packName
        $basePack = Get-CustomPackPath -Lines $baseLines -Pack $packName
        if ($null -eq $bundlePack -or $bundlePack.Value -cne "policies/guardrail/$packName") {
            throw "bundle config.yaml must name policies/guardrail/$packName as custom_packs.$packName.path"
        }
        if ($null -eq $basePack) { throw "base CONFIG= must define custom_packs.$packName" }
        if ($basePack.Value -notmatch '^[A-Za-z]:\\') {
            throw "base CONFIG= must name an absolute, preinstalled path for bundle rule pack $packName"
        }
        $baseLines[$basePack.Index] = $bundleLines[$bundlePack.Index]
    }
    if (($baseLines -join "`n") -cne $bundleBlock) {
        throw "base CONFIG= guardrail policy differs from the signed bundle's; use the same policy source and change only custom_packs.<pack>.path"
    }
    # The hooks take claude_code.mode, codex.mode and
    # connector_hooks.<connector>.mode before the guardrail mode, and
    # application_protection sets the guardrail policy of automatically
    # protected agents, so these blocks must be the bundle's too, or absent
    # from both (GAP-0090). No other key is compared.
    $bundleText = [Text.Encoding]::UTF8.GetString($entries['config.yaml'])
    foreach ($key in 'claude_code', 'codex', 'connector_hooks', 'application_protection') {
        if ((Get-TopLevelBlock -Text $baseText -Key $key) -cne (Get-TopLevelBlock -Text $bundleText -Key $key)) {
            throw "base CONFIG= ${key}: block differs from the signed bundle's (it sets hook modes or the guardrail policy the hooks answer under); use the bundle's ${key}: block, or leave it out of both"
        }
    }
}

$setup = (Resolve-Path -LiteralPath $SetupPath).ProviderPath
$pin = $Sha256.Trim().ToLowerInvariant()
$actual = (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash.ToLowerInvariant()
if ($TrustMode -eq 'HashPinned' -and -not $pin) { throw 'hash-pinned trust requires -Sha256 (from the cosign-verified checksums.txt)' }
if ($pin -and $pin -ne $actual) { throw "Setup SHA-256 $actual does not match -Sha256 $pin" }
$signers = @($AllowedSigners | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
if ($TrustMode -eq 'Authenticode') {
    if ($signers.Count -eq 0) { throw 'Authenticode trust requires -AllowedSigners (SHA-256 thumbprints of the signer certificate)' }
    $signature = Get-AuthenticodeSignature -LiteralPath $setup
    if ($signature.Status -ne 'Valid') { throw "Setup Authenticode status is $($signature.Status)" }
    $thumbprint = ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($signature.SignerCertificate.RawData))).ToLowerInvariant()
    if ($signers -notcontains $thumbprint) { throw "Setup is signed by certificate $thumbprint, which is not in -AllowedSigners" }
}

$configText = ''
if ($ConfigPath) {
    $configText = Get-Content -LiteralPath $ConfigPath -Raw
    if ($configText -match '(?im)^\s*api_key\s*:\s*\S') { throw 'config.yaml contains an inline api_key; the standalone profile rejects it and the package must not carry credentials' }
    $configVersion = [regex]::Match($configText, '(?m)^config_version[ \t]*:[ \t]*([0-9]+)[ \t]*(?:#[^\r\n]*)?\r?$')
    if (-not $configVersion.Success) {
        throw 'config.yaml has no top-level config_version; re-author it as config_version 9 (see packaging/identity/entra/admin-config.windows.example.yaml) before packaging'
    }
    $versionNumber = [int]::Parse($configVersion.Groups[1].Value)
    if ($versionNumber -lt 9) {
        throw "config.yaml is config_version $versionNumber. Setup migrates it on install, so the detection hash would never match. Re-author it as config_version 9 (see packaging/identity/entra/admin-config.windows.example.yaml) before packaging"
    }
}

$content = Join-Path $OutputDirectory 'content'
if (Test-Path -LiteralPath $content) { throw "$content already exists; use an empty -OutputDirectory" }
New-Item -ItemType Directory -Path $content -Force | Out-Null
Copy-Item -LiteralPath $setup -Destination (Join-Path $content 'DefenseClawSetup-Enterprise-Standalone-x64.exe')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Install-DefenseClawIntune.ps1') -Destination $content
$configPin = ''
if ($ConfigPath) {
    Copy-Item -LiteralPath $ConfigPath -Destination (Join-Path $content 'config.yaml')
    $configPin = (Get-FileHash -LiteralPath (Join-Path $content 'config.yaml') -Algorithm SHA256).Hash.ToLowerInvariant()
}
$bundlePin = ''
$anchorPin = ''
if ($BundlePath) {
    Copy-Item -LiteralPath $BundlePath -Destination (Join-Path $content 'policy.dcbundle')
    $bundlePin = (Get-FileHash -LiteralPath (Join-Path $content 'policy.dcbundle') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($TrustAnchorPath) {
        Copy-Item -LiteralPath $TrustAnchorPath -Destination (Join-Path $content 'bundle-anchors.json')
        $anchorPin = (Get-FileHash -LiteralPath (Join-Path $content 'bundle-anchors.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$pins = [ordered]@{
    schema_version  = 1
    setup_sha256    = $actual
    config_sha256   = $configPin
    bundle_sha256   = $bundlePin
    trust_anchors_sha256 = $anchorPin
    trust_mode      = $(if ($TrustMode -eq 'Authenticode') { 'authenticode' } else { 'hash_pinned' })
    allowed_signers = $signers
    product_version = $ProductVersion
}
[IO.File]::WriteAllText((Join-Path $content 'intune-package.json'), ($pins | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))

if ($BundlePath) {
    $detectSource = Join-Path $PSScriptRoot '..\..\windows\detect.ps1'
    if (-not (Test-Path -LiteralPath $detectSource -PathType Leaf)) { throw 'packaging/mdm/windows/detect.ps1 not found next to the kit' }
    $detectText = Get-Content -LiteralPath $detectSource -Raw
    $bundleDefault = "[string]`$RequireBundle = ''"
    if (([regex]::Matches($detectText, [regex]::Escape($bundleDefault))).Count -ne 1) { throw 'detect.ps1 changed; update the packager' }
    $detectText = $detectText.Replace($bundleDefault, "[string]`$RequireBundle = '$RequireBundle'")
    if ($ProductVersion) {
        $versionDefault = "[string]`$MinimumVersion = ''"
        if (([regex]::Matches($detectText, [regex]::Escape($versionDefault))).Count -ne 1) { throw 'detect.ps1 changed; update the packager' }
        $detectText = $detectText.Replace($versionDefault, "[string]`$MinimumVersion = '$ProductVersion'")
    }
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'detect-bundle.ps1'), $detectText, [Text.UTF8Encoding]::new($false))
}

if ($IntuneWinAppUtil) {
    & $IntuneWinAppUtil -c $content -s 'Install-DefenseClawIntune.ps1' -o $OutputDirectory -q
    if ($LASTEXITCODE -ne 0) { throw "IntuneWinAppUtil exited $LASTEXITCODE" }
}

$version = if ($ProductVersion) { $ProductVersion } else { '<the release version>' }
# A pack the base config names outside the install tree must be on the device
# before Setup runs, or Setup refuses CONFIG= with 1639 (GAP-0109).
$packHint = ''
$preinstalled = @(Get-PreinstalledPackPath -Text $(if ($BaseConfigPath) { $baseText } else { $configText }))
if ($preinstalled.Count -gt 0) {
    $packHint = "Prerequisite:      the base config names rule pack(s) that this app does not deliver: " +
        (($preinstalled | ForEach-Object { "$($_.Name) at $($_.Path)" }) -join '; ') + "`n" +
        "                   Deliver each first with a rule-pack Win32 app built from Install-DefenseClawRulePack.ps1 (it grants NT SERVICE\DefenseClawGateway`n" +
        "                   Read & execute on the pack and its parent folder; detection Detect-DefenseClawRulePack.ps1), and make that app a dependency of the`n" +
        "                   base app (Automatically install: Yes). Without the pack, or if the gateway cannot read it, Setup refuses CONFIG= with 1639."
}
if ($BundlePath -and $ConfigPath) {
@"
Win32 app content: $content
Install command:   %SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Install-DefenseClawIntune.ps1
                   (runs Setup /ensure CONFIG= BUNDLE= TRUSTANCHORS=: a new device installs with the services stopped and starts them on the
                   signed bundle; if the bundle is not applied Setup removes the staged install and the app fails, so Intune retries it whole)
Uninstall command: powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Install-DefenseClawIntune.ps1 -Uninstall
Install behavior:  System
Return codes:      0 Success, 1707 Success, 3010 Soft reboot, 1641 Hard reboot, 1618 Retry (defaults; 1603 and 1639 report Failed)
Requirements:      x64 only; Windows 10 22H2 or later; dependency: PowerShell 7.4+ (x64 MSI) Win32 app
Dependency:        none on another DefenseClaw app
Supersedence:      a later bundle version is a new version of this app (supersede it; Uninstall previous version: No)
Detection rule:    Custom script $(Join-Path $OutputDirectory 'detect-bundle.ps1'), Run script as 32-bit process on 64-bit clients: No
Pins:              config.yaml sha256 $configPin; policy.dcbundle sha256 $bundlePin; bundle-anchors.json sha256 $(if ($anchorPin) { $anchorPin } else { 'none' })
Moving from two apps: assign this app to devices that run the base app and the bundle app, then remove both assignments
                   (on an installed device this app applies the bundle only).
"@
    if ($packHint) { $packHint }
    return
}
if ($BundlePath) {
@"
Win32 app content: $content
Install command:   %SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Install-DefenseClawIntune.ps1
Uninstall command: cmd.exe /c exit 0
                   (a policy bundle is not uninstalled: roll back with a new, higher signed version; remove DefenseClaw with the base app's uninstall)
Install behavior:  System
Return codes:      0 Success, 1707 Success, 3010 Soft reboot, 1641 Hard reboot, 1618 Retry (defaults; 1603 and 1639 report Failed)
Requirements:      x64 only; Windows 10 22H2 or later
Dependency:        the DefenseClaw base app (built with -ConfigPath), Automatically install: Yes. Setup cannot take a bundle on the first install.
Base policy:       -BaseConfigPath $BaseConfigPath, sha256 $((Get-FileHash -LiteralPath $BaseConfigPath -Algorithm SHA256).Hash.ToLowerInvariant())
                   (it must equal config_sha256 in the base app's intune-package.json; its custom rule packs must already be installed on the device)
Supersedence:      supersede the previous bundle app; Uninstall previous version: No
Detection rule:    Custom script $(Join-Path $OutputDirectory 'detect-bundle.ps1'), Run script as 32-bit process on 64-bit clients: No
Pins:              policy.dcbundle sha256 $bundlePin; bundle-anchors.json sha256 $(if ($anchorPin) { $anchorPin } else { 'none' })
Setup:             build each bundle package with the Setup of the release the devices run (an older Setup is refused: downgrade_refused)
"@
    if ($packHint) { $packHint }
    return
}
@"
Win32 app content: $content
Install command:   %SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Install-DefenseClawIntune.ps1
Uninstall command: powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Install-DefenseClawIntune.ps1 -Uninstall
                   (runs Setup /uninstall JSON=1; while a program runs from the install folder it retries, then exits 1618 so Intune retries)
Install behavior:  System
Return codes:      0 Success, 1707 Success, 3010 Soft reboot, 1641 Hard reboot, 1618 Retry (defaults; 1603 and 1639 report Failed)
Requirements:      x64 only; Windows 10 22H2 or later; dependency: PowerShell 7.4+ (x64 MSI) Win32 app
Detection rule:    Registry, HKEY_LOCAL_MACHINE\SOFTWARE\Cisco\DefenseClaw\Enterprise, value ProductVersion,
                   Version comparison, Greater than or equal to $version, 32-bit app on 64-bit clients: No
Purge twin:        the same uninstall command with -Purge (Setup PURGE=1; assign as Uninstall when purging)
Bundle mode:       once a device takes signed bundles, do not assign a package built with -ConfigPath alone to it again (Setup refuses it with bundle_required); build the single app (-ConfigPath with -BundlePath) instead.
"@
if ($packHint) { $packHint }
