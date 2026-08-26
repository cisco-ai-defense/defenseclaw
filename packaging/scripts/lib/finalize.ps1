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

function Invoke-DefenseClawDie {
    param([int]$Code, [string]$Message)
    [Console]::Error.WriteLine("finalize: $Message")
    exit $Code
}

if (-not (Test-Path -LiteralPath $SetupExe -PathType Leaf)) {
    Invoke-DefenseClawDie -Code 6 -Message "setup-exe not found: $SetupExe"
}
if (-not (Test-Path -LiteralPath $Provenance -PathType Leaf)) {
    Invoke-DefenseClawDie -Code 6 -Message "provenance not found: $Provenance"
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
    # Pass the script on stdin instead of writing it to a temp file.
    # A predictable path (`GetTempFileName() + '.py'`) in the shared
    # temp dir would be readable + potentially writable by other users
    # on a build host; a race between our write and our exec would
    # execute the attacker's code as the pipeline user. Stdin has no
    # such surface. See CR spec-002:PRRT_kwDORuAK-s6af8jf.
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
    # `python - <args>` reads the script from stdin; positional args
    # after `-` become sys.argv[1..].
    $script | & $python.Source '-' $Provenance $hash "$size"
    if ($LASTEXITCODE -ne 0) {
        Invoke-DefenseClawDie -Code 6 -Message "python provenance rewrite failed (exit=$LASTEXITCODE)"
    }
} else {
    # No python3/python on PATH. A hand-rolled ConvertTo-Json fallback
    # cannot guarantee byte parity with windows-repro-manifest's
    # emitter (PowerShell's JSON writer differs on integer widening,
    # null shape, and nested map ordering across .NET versions). Fail
    # loudly instead of silently emitting drift; the AVC pipeline can
    # install python and re-run, or run the sh sibling. See CR
    # spec-002:PRRT_kwDORuAK-s6af8jo.
    Invoke-DefenseClawDie -Code 6 -Message "finalize.ps1 requires python3 (or python) on PATH so provenance.json stays byte-identical to windows-repro-manifest's emitter output. Install python and rerun, or use finalize.sh."
}

Microsoft.PowerShell.Utility\Write-Host "finalize: setup_sha256=$hash size=$size -> $Provenance + $sidecarPath"
