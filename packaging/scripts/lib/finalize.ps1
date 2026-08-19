# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# finalize.ps1 — PowerShell mirror of packaging/scripts/lib/finalize.sh.
# Optional post-signing helper for AVC's Windows pipeline; see the sh
# sibling for the full rationale and docs/specs/002-windows-avc-packaging/
# design.md § Decisions.
#
# USAGE
#   ./finalize.ps1 -SetupExe out/DefenseClawSetup-Enterprise-x64.exe `
#                  -Provenance out/DefenseClawSetup-Enterprise-x64.exe.provenance.json
#
# Exit codes: 0 ok, 2 usage, 6 io/parse error.

#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SetupExe,
    [Parameter(Mandatory)][string]$Provenance
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function DefenseClaw-Die {
    param([int]$Code, [string]$Message)
    [Console]::Error.WriteLine("finalize: $Message")
    exit $Code
}

if (-not (Test-Path -LiteralPath $SetupExe -PathType Leaf)) {
    DefenseClaw-Die -Code 6 -Message "setup-exe not found: $SetupExe"
}
if (-not (Test-Path -LiteralPath $Provenance -PathType Leaf)) {
    DefenseClaw-Die -Code 6 -Message "provenance not found: $Provenance"
}

$hash = (Get-FileHash -LiteralPath $SetupExe -Algorithm SHA256).Hash.ToLowerInvariant()
$size = (Get-Item -LiteralPath $SetupExe).Length

# .sha256 sidecar: sha256sum(1) format so downstream verifiers on
# Linux runners can consume it. LF endings — no CRLF drift.
$baseName = [IO.Path]::GetFileName($SetupExe)
$sidecarPath = "$SetupExe.sha256"
$sidecar = "$hash  $baseName`n"
[IO.File]::WriteAllText($sidecarPath, $sidecar, [Text.UTF8Encoding]::new($false))

# In-place edit of provenance.json. ConvertTo-Json in PowerShell has
# unstable key ordering across .NET versions; we reach for Python via
# python3 if present (matches finalize.sh path) or fall back to a
# hand-serialized rewrite that preserves the byte-stable ordering
# windows-repro-manifest emits.
$python = Get-Command python3 -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python -ErrorAction SilentlyContinue }

if ($python) {
    $script = @"
import json, sys
path, sha, size = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(path, "r", encoding="utf-8") as f:
    doc = json.load(f)
doc["setup_sha256"] = sha
doc["setup_size"]   = size
with open(path, "w", encoding="utf-8", newline="\n") as f:
    json.dump(doc, f, sort_keys=True, indent=2, ensure_ascii=False)
    f.write("\n")
"@
    $tempScript = [IO.Path]::GetTempFileName() + '.py'
    try {
        [IO.File]::WriteAllText($tempScript, $script, [Text.UTF8Encoding]::new($false))
        & $python.Source $tempScript $Provenance $hash $size
        if ($LASTEXITCODE -ne 0) {
            DefenseClaw-Die -Code 6 -Message "python provenance rewrite failed (exit=$LASTEXITCODE)"
        }
    } finally {
        Remove-Item -LiteralPath $tempScript -Force -ErrorAction SilentlyContinue
    }
} else {
    # Fallback: hand-roll a byte-stable JSON writer. Only the fields
    # windows-repro-manifest emits are supported; anything else is a
    # bug on the pipeline side and we exit rather than silently drop.
    $raw = Get-Content -LiteralPath $Provenance -Raw
    $doc = $raw | ConvertFrom-Json -AsHashtable
    $doc['setup_sha256'] = $hash
    $doc['setup_size']   = [long]$size
    $sortedKeys = $doc.Keys | Sort-Object
    $lines = @('{')
    for ($i = 0; $i -lt $sortedKeys.Count; $i++) {
        $k = $sortedKeys[$i]
        $v = $doc[$k]
        $valLiteral = if ($null -eq $v) { 'null' }
            elseif ($v -is [bool]) { if ($v) { 'true' } else { 'false' } }
            elseif ($v -is [int] -or $v -is [long] -or $v -is [double]) { "$v" }
            else { ($v | ConvertTo-Json -Compress -Depth 32) }
        $suffix = if ($i -lt $sortedKeys.Count - 1) { ',' } else { '' }
        $lines += "  `"$k`": $valLiteral$suffix"
    }
    $lines += '}'
    $out = ($lines -join "`n") + "`n"
    [IO.File]::WriteAllText($Provenance, $out, [Text.UTF8Encoding]::new($false))
}

Microsoft.PowerShell.Utility\Write-Host "finalize: setup_sha256=$hash size=$size -> $Provenance + $sidecarPath"
