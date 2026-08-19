# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# file-hash.ps1 — reusable SHA-256 hex helper.
#
# Dot-source this file; it exports `Get-FileHashHex` and no side effects.
# Used by packaging/scripts/lib/assemble.ps1 during the AVC-driven Windows
# managed-enterprise Setup assembly step (see
# docs/specs/002-windows-avc-packaging/design.md § Components).
#
# The output is the lowercase 64-character hex digest; this is the same
# shape cmd/windows-repro-manifest, cmd/defenseclaw-enterprise-setup, and
# stageEnterprisePayload compare against, so a mismatch anywhere is a
# byte-level mismatch, not a formatting drift.

#Requires -Version 7.0

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-FileHashHex {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Path
    )
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
