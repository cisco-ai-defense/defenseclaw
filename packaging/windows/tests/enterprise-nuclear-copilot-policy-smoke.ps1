# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# The Secure Client purge removes DefenseClaw's GitHub Copilot drop-in and
# then the ownership record the guardian keeps for it in the lifecycle
# folder's machine-policy store, and the store once it is empty. The record
# stays while the drop-in does, and nothing else in the lifecycle folder (the
# shared lifecycle lock, another scope's receipt, a file in the store that is
# not the record) is touched. The helper is loaded from the module by AST and
# the purge's delete primitive is a stand-in, so the smoke runs unelevated
# and also under pwsh off Windows.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    [IO.Path]::Combine($PSScriptRoot, '..', 'DefenseClawEnterprise.psm1')
)
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($modulePath, [ref]$null, [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) {
    throw "module does not parse: $(@($parseErrors)[0])"
}
$definitions = @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Remove-DefenseClawNuclearCopilotPolicy'
        }, $true))
if ($definitions.Count -ne 1) {
    throw 'expected exactly one Remove-DefenseClawNuclearCopilotPolicy in the module'
}
. ([scriptblock]::Create($definitions[0].Extent.Text))

# Stand-in for the purge's delete: the paths in $script:Stuck stay, as a file
# held open without a restart deletion would; the paths in $script:Scheduled
# stay too but count as removed, as a held file queued for deletion at the
# restart does. Like the real one it returns '' for a path that is already gone.
$script:Stuck = @()
$script:Scheduled = @()
$script:Removed = [Collections.Generic.List[string]]::new()
function Remove-DefenseClawNuclearPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Role,
        [Parameter(Mandatory)][ref]$RebootRequired,
        [switch]$AcceptScheduledDelete
    )
    if (-not $AcceptScheduledDelete) {
        throw "the purge must accept a restart deletion for $Role"
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        return ''
    }
    if ($script:Stuck -contains $Path) {
        return "$Role could not be removed: $Path"
    }
    if ($script:Scheduled -contains $Path) {
        $RebootRequired.Value = $true
        return ''
    }
    Remove-Item -LiteralPath $Path -Recurse -Force
    $script:Removed.Add($Path)
    return ''
}

$root = [IO.Path]::Combine([IO.Path]::GetTempPath(), "dc-nuclear-copilot-$([guid]::NewGuid().ToString('N'))")
$policyDir = [IO.Path]::Combine($root, 'ProgramData', 'GitHub', 'Copilot', 'policy.d')
$lifecycle = [IO.Path]::Combine($root, 'ProgramData', 'Cisco', 'Cisco Secure Client', 'DefenseClaw-Lifecycle')
$store = [IO.Path]::Combine($lifecycle, 'machine-policy')
$dropIn = [IO.Path]::Combine($policyDir, '90-defenseclaw.json')
$record = [IO.Path]::Combine($store, 'copilot.json')
$lock = [IO.Path]::Combine($lifecycle, 'lifecycle.lock')
$otherReceipt = [IO.Path]::Combine($lifecycle, 'purge-intent-0123456789abcdef.json')
# Siblings that share a prefix with the folders the purge may touch.
$storeSibling = [IO.Path]::Combine("$store.bak", 'copilot.json')
$policySibling = [IO.Path]::Combine("$policyDir.bak", '90-defenseclaw.json')

function New-Fixture {
    param([switch]$NoDropIn, [string[]]$StoreExtras = @())
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
    [void][IO.Directory]::CreateDirectory($policyDir)
    [void][IO.Directory]::CreateDirectory($store)
    if (-not $NoDropIn) {
        [IO.File]::WriteAllText($dropIn, '{"version":1,"hooks":{}}')
    }
    [IO.File]::WriteAllText($record, '{"schema_version":1,"connector":"copilot"}')
    [IO.File]::WriteAllText($lock, '')
    [IO.File]::WriteAllText($otherReceipt, '{}')
    foreach ($sibling in @($storeSibling, $policySibling)) {
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($sibling))
        [IO.File]::WriteAllText($sibling, '{}')
    }
    foreach ($extra in $StoreExtras) {
        [IO.File]::WriteAllText([IO.Path]::Combine($store, $extra), '{}')
    }
    $script:Stuck = @()
    $script:Scheduled = @()
    $script:Removed.Clear()
}

function Invoke-Purge {
    param([string]$LifecycleDirectory = $lifecycle)
    $result = [pscustomobject]@{
        Incomplete     = [Collections.Generic.List[string]]::new()
        Warnings       = [Collections.Generic.List[string]]::new()
        RebootRequired = $false
    }
    $reboot = $false
    Remove-DefenseClawNuclearCopilotPolicy `
        -CopilotPolicyDirectory $policyDir `
        -LifecycleDirectory $LifecycleDirectory `
        -RebootRequired ([ref]$reboot) `
        -Incomplete $result.Incomplete `
        -Warnings $result.Warnings
    $result.RebootRequired = $reboot
    return $result
}

function Assert-State {
    param([string]$Case, [string[]]$Gone, [string[]]$Present)
    foreach ($path in $Gone) {
        if (Test-Path -LiteralPath $path) {
            throw "${Case}: $path survived"
        }
    }
    foreach ($path in $Present) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw "${Case}: $path was removed"
        }
    }
    foreach ($path in @($storeSibling, $policySibling)) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw "${Case}: $path, a sibling of a folder the purge cleans, was removed"
        }
    }
    $ignoreCase = [StringComparison]::OrdinalIgnoreCase
    $separator = [IO.Path]::DirectorySeparatorChar
    foreach ($path in $script:Removed) {
        if (-not ($path.StartsWith($policyDir + $separator, $ignoreCase) -or
                [string]::Equals($path, $store, $ignoreCase) -or
                $path.StartsWith($store + $separator, $ignoreCase))) {
            throw "${Case}: removed $path, outside the Copilot policy folder and the machine-policy store"
        }
    }
}

try {
    # The installed state after the uninstall's own teardown: the drop-in,
    # its record, the lock and another scope's receipt.
    New-Fixture
    $result = Invoke-Purge
    Assert-State 'full purge' -Gone @($dropIn, $record, $store) -Present @($policyDir, $lock, $otherReceipt)
    if ($result.Incomplete.Count -ne 0 -or $result.Warnings.Count -ne 0 -or $result.RebootRequired) {
        throw "full purge reported incomplete=[$($result.Incomplete -join '; ')] warnings=[$($result.Warnings -join '; ')]"
    }

    # The drop-in is already gone (the Go teardown removed it, a guardian
    # publish rewrote only the record): the record still goes.
    New-Fixture -NoDropIn
    $result = Invoke-Purge
    Assert-State 'record without drop-in' -Gone @($record, $store) -Present @($lock, $otherReceipt)
    if ($result.Incomplete.Count -ne 0 -or $result.Warnings.Count -ne 0) {
        throw 'a record without its drop-in was not removed cleanly'
    }

    # Something else in the store keeps it; the record still goes.
    New-Fixture -StoreExtras @('copilot.json.tmp-1')
    $result = Invoke-Purge
    Assert-State 'store with another file' -Gone @($dropIn, $record) -Present @($store, [IO.Path]::Combine($store, 'copilot.json.tmp-1'), $lock)
    if ($result.Warnings.Count -ne 0 -or $result.Incomplete.Count -ne 0) {
        throw 'a non-empty store was reported as a leftover'
    }

    # A drop-in that stays keeps its record and makes the purge incomplete.
    New-Fixture
    $script:Stuck = @($dropIn)
    $result = Invoke-Purge
    Assert-State 'drop-in stays' -Present @($dropIn, $record, $store, $lock)
    if ($result.Incomplete.Count -ne 1 -or $result.Incomplete[0] -notlike "*$dropIn*") {
        throw "a drop-in that stayed was not reported incomplete: [$($result.Incomplete -join '; ')]"
    }

    # A drop-in whose deletion is only queued for the restart keeps its
    # record: should the restart not delete it, a later uninstall still finds
    # it by the record. That is a warning; the next purge removes the record.
    New-Fixture
    $script:Scheduled = @($dropIn)
    $result = Invoke-Purge
    Assert-State 'drop-in queued for the restart' -Present @($dropIn, $record, $store, $lock)
    if ($result.Incomplete.Count -ne 0 -or $result.Warnings.Count -ne 1 -or
        $result.Warnings[0] -notlike "*$record*" -or -not $result.RebootRequired) {
        throw "a drop-in queued for the restart did not keep its record with one warning: incomplete=[$($result.Incomplete -join '; ')] warnings=[$($result.Warnings -join '; ')] reboot=$($result.RebootRequired)"
    }

    # A record that stays is a warning, not an incomplete purge.
    New-Fixture
    $script:Stuck = @($record)
    $result = Invoke-Purge
    Assert-State 'record stays' -Gone @($dropIn) -Present @($record, $store)
    if ($result.Incomplete.Count -ne 0 -or $result.Warnings.Count -ne 1) {
        throw "a record that stayed was not a single warning: incomplete=[$($result.Incomplete -join '; ')] warnings=[$($result.Warnings -join '; ')]"
    }

    # A lifecycle folder outside the purge's safe roots is passed as '' and
    # nothing in it is touched.
    New-Fixture
    $result = Invoke-Purge -LifecycleDirectory ''
    Assert-State 'no lifecycle folder' -Gone @($dropIn) -Present @($record, $store, $lock)
    if ($result.Incomplete.Count -ne 0 -or $result.Warnings.Count -ne 0) {
        throw "no lifecycle folder reported incomplete=[$($result.Incomplete -join '; ')] warnings=[$($result.Warnings -join '; ')]"
    }
}
finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}

Microsoft.PowerShell.Utility\Write-Output 'nuclear copilot policy smoke passed'
