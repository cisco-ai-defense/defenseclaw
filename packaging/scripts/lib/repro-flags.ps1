# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# repro-flags.ps1 — PowerShell mirror of packaging/scripts/lib/repro-flags.sh.
# Sourced by assemble.ps1 (Workstream A2). Semantically identical to the
# bash version; both are constrained by scripts/check-repro-flags-parity.sh
# so a change to one MUST land in the other.
#
# See docs/specs/001-windows-deterministic-build/design.md § Components and
# the bash file for the full rationale, including why GOTOOLCHAIN is pinned
# here rather than in go.mod.
#
# USAGE
#   . packaging/scripts/lib/repro-flags.ps1
#   $env:SOURCE_DATE_EPOCH = '1234567890'
#   $env:DEFENSECLAW_BUILDID = 'defenseclaw-enterprise-setup-abcdef...'
#   Invoke-DefenseClawReproPreflight
#   Invoke-DefenseClawReproBuild `
#       -Output 'out/DefenseClawSetup-Enterprise-x64.exe' `
#       -Package './cmd/defenseclaw-enterprise-setup'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The six AVC-confirmed envs. Values are declared here, not passed in,
# so a caller cannot accidentally change one to a non-reproducible
# setting. SOURCE_DATE_EPOCH and DEFENSECLAW_BUILDID are per-build and
# MUST be set by the caller before running preflight/build.
$env:GOFLAGS      = '-trimpath -buildvcs=false -mod=vendor'
$env:GOTOOLCHAIN  = 'go1.26.4'
$env:CGO_ENABLED  = '0'
$env:GOOS         = 'windows'
$env:GOARCH       = 'amd64'

# Names of the six required per-build envs; used by both preflight and
# the parity lint (scripts/check-repro-flags-parity.sh) so adding /
# removing an env here is caught in one place.
$script:DefenseClawReproRequiredEnvs = @(
    'GOFLAGS',
    'GOTOOLCHAIN',
    'CGO_ENABLED',
    'GOOS',
    'GOARCH',
    'SOURCE_DATE_EPOCH',
    'DEFENSECLAW_BUILDID'
)

# Required-exact-value map: mirror of _repro_expected_value in the bash
# library. A caller can rewrite any of these after sourcing this file
# and before invoking preflight; each fixed-value check below compares
# against the literal required value so mutations are caught, not
# silently accepted.
$script:DefenseClawReproExpectedValues = @{
    GOFLAGS     = '-trimpath -buildvcs=false -mod=vendor'
    GOTOOLCHAIN = 'go1.26.4'
    CGO_ENABLED = '0'
    GOOS        = 'windows'
    GOARCH      = 'amd64'
}

function Invoke-DefenseClawReproPreflight {
    <#
    .SYNOPSIS
    Asserts every required reproducibility env is set to a well-formed value.
    Emits one diagnostic per missing/malformed/mismatched env and returns
    non-zero.
    #>
    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($name in $script:DefenseClawReproRequiredEnvs) {
        $val = [Environment]::GetEnvironmentVariable($name, 'Process')
        if ([string]::IsNullOrEmpty($val)) {
            $missing.Add("$name is unset or empty")
            continue
        }
        # SOURCE_DATE_EPOCH and DEFENSECLAW_BUILDID are per-build inputs
        # supplied by the caller; every other required env is a fixed
        # literal defined by DefenseClawReproExpectedValues above.
        if ($name -eq 'SOURCE_DATE_EPOCH' -or $name -eq 'DEFENSECLAW_BUILDID') {
            continue
        }
        if ($script:DefenseClawReproExpectedValues.ContainsKey($name)) {
            $expected = $script:DefenseClawReproExpectedValues[$name]
            if ($val -cne $expected) {
                $missing.Add("$name must be '$expected' (got: '$val')")
            }
        }
    }
    $sde = [Environment]::GetEnvironmentVariable('SOURCE_DATE_EPOCH', 'Process')
    if (-not [string]::IsNullOrEmpty($sde) -and $sde -notmatch '^[1-9][0-9]*$') {
        $missing.Add("SOURCE_DATE_EPOCH must be a positive integer (got: '$sde')")
    }
    if ($missing.Count -gt 0) {
        foreach ($line in $missing) {
            [Console]::Error.WriteLine("repro-flags preflight: $line")
        }
        throw 'repro-flags preflight: required env(s) missing or malformed'
    }
}

function Invoke-DefenseClawReproBuild {
    <#
    .SYNOPSIS
    Invokes `go build` with the exact flag list the AVC reproducibility
    contract requires. Callers pass output path and package path only;
    every other flag is fixed here.

    NOTE: `go build` itself has no `-buildid` flag; the build ID is a
    link-time argument passed via `-ldflags`. Passing `-buildid=...`
    directly to `go build` fails with "flag provided but not defined:
    -buildid". Always route DEFENSECLAW_BUILDID through -ldflags.
    #>
    param(
        [Parameter(Mandatory)][string]$Output,
        [Parameter(Mandatory)][string]$Package
    )
    Invoke-DefenseClawReproPreflight
    $buildid = [Environment]::GetEnvironmentVariable('DEFENSECLAW_BUILDID', 'Process')
    & go build `
        -mod=vendor `
        -trimpath `
        -buildvcs=false `
        "-ldflags=-buildid=$buildid" `
        -o $Output `
        $Package
    if ($LASTEXITCODE -ne 0) {
        throw "go build failed (exit=$LASTEXITCODE)"
    }
}
