# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

function Assert-DefenseClawBinaryIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedName,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit,
        [int]$TimeoutSeconds = 30
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "DefenseClaw identity input is missing: $Path"
    }
    if ($ExpectedVersion -notmatch '^\d+\.\d+\.\d+(?:-[A-Za-z0-9_.-]+)?$') {
        throw "Invalid expected DefenseClaw version: $ExpectedVersion"
    }
    if ($ExpectedCommit -cnotmatch '^[0-9a-f]{40}$') {
        throw "Invalid expected DefenseClaw source commit: $ExpectedCommit"
    }
    if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 120) {
        throw "Invalid DefenseClaw identity timeout: $TimeoutSeconds"
    }

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = [IO.Path]::GetFullPath($Path)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    [void]$start.ArgumentList.Add('--version-json')
    $process = [Diagnostics.Process]::Start($start)
    if ($null -eq $process) {
        throw "Could not start DefenseClaw identity input: $Path"
    }
    try {
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill($true) } catch {}
            $process.WaitForExit()
            throw "DefenseClaw identity input timed out: $Path"
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "DefenseClaw identity input exited $($process.ExitCode): $($stderr.Trim())"
        }
    } finally {
        $process.Dispose()
    }

    if ([Text.Encoding]::UTF8.GetByteCount($stdout) -gt 4096) {
        throw "DefenseClaw identity output is too large: $Path"
    }
    try {
        $document = [Text.Json.JsonDocument]::Parse($stdout)
    } catch {
        throw "DefenseClaw identity output is not one JSON document: $Path"
    }
    try {
        $root = $document.RootElement
        if ($root.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
            throw "DefenseClaw identity output is not a JSON object: $Path"
        }
        $properties = @($root.EnumerateObject() | ForEach-Object { $_.Name })
        $required = @('schema_version', 'name', 'version', 'commit')
        $allowed = @($required + 'built')
        foreach ($name in $required) {
            if ($name -notin $properties) {
                throw "DefenseClaw identity output is missing $name`: $Path"
            }
        }
        foreach ($name in $properties) {
            if ($name -notin $allowed) {
                throw "DefenseClaw identity output has unexpected field $name`: $Path"
            }
        }
        if ($properties.Count -ne (@($properties | Select-Object -Unique)).Count) {
            throw "DefenseClaw identity output has duplicate fields: $Path"
        }
        if ($root.GetProperty('schema_version').GetInt32() -ne 1) {
            throw "DefenseClaw identity schema mismatch: $Path"
        }
        $actualName = $root.GetProperty('name').GetString()
        $actualVersion = $root.GetProperty('version').GetString()
        $actualCommit = $root.GetProperty('commit').GetString()
        if ($actualName -cne $ExpectedName) {
            throw "DefenseClaw binary identity mismatch: $actualName != $ExpectedName"
        }
        if ($actualVersion -cne $ExpectedVersion) {
            throw "DefenseClaw binary version mismatch: $actualVersion != $ExpectedVersion"
        }
        if ($actualCommit -cnotmatch '^[0-9a-f]{40}$') {
            throw "DefenseClaw binary reported an invalid source commit: $actualCommit"
        }
        if ($actualCommit -cne $ExpectedCommit) {
            throw "DefenseClaw binary source commit mismatch: $actualCommit != $ExpectedCommit"
        }
        return [pscustomobject]@{
            name = $actualName
            version = $actualVersion
            commit = $actualCommit
        }
    } finally {
        $document.Dispose()
    }
}
