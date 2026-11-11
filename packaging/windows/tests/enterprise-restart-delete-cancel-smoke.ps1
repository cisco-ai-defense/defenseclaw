# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# A purge that meets a held file queues it for deletion at the next restart.
# A successful Install, Upgrade or Repair before that restart writes the same
# paths again, so it cancels exactly those deletes: delete entries (empty
# destination) for DefenseClaw's own paths. Renames, other programs' entries,
# look-alike paths and a per-user install's files stay, in order, and a list
# that is not made of pairs is left alone. The selection helpers are loaded
# from the module by AST, so the smoke runs unelevated and also under pwsh
# off Windows; the registry write is exercised on Windows by the lifecycle.

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
foreach ($name in @(
        'ConvertFrom-DefenseClawPendingRenameSource',
        'Test-DefenseClawRestartDeleteInScope',
        'Select-DefenseClawRestartDeleteEntries'
    )) {
    $definitions = @($ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $name
            }, $true))
    if ($definitions.Count -ne 1) {
        throw "expected exactly one $name in the module"
    }
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}

$installRoot = 'C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw'
$stateRoot = 'C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw'
$lifecycle = 'C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Lifecycle'
$scope = [pscustomobject]@{
    Roots          = [string[]]@(
        $installRoot,
        $stateRoot,
        $lifecycle,
        'C:\ProgramData\GitHub\Copilot\DefenseClaw',
        'C:\Users\dev\.defenseclaw\hooks',
        'C:\Users\dev\.defenseclaw\hook_contract_lock.json'
    )
    Files          = [string[]]@(
        'C:\Program Files\ClaudeCode\managed-settings.d\90-defenseclaw.json',
        'C:\ProgramData\OpenAI\Codex\requirements.toml',
        'C:\ProgramData\Cursor\hooks.json',
        'C:\ProgramData\GitHub\Copilot\policy.d\90-defenseclaw.json'
    )
    SidecarFolders = [string[]]@(
        'C:\Program Files\ClaudeCode\managed-settings.d',
        'C:\ProgramData\OpenAI\Codex',
        'C:\ProgramData\Cursor'
    )
}

function Assert-Selection {
    param(
        [string]$Case,
        [AllowEmptyCollection()][AllowEmptyString()][string[]]$Entries,
        [AllowEmptyCollection()][AllowEmptyString()][string[]]$ExpectedKept,
        [AllowEmptyCollection()][string[]]$ExpectedCancelled
    )
    $selection = Select-DefenseClawRestartDeleteEntries -Entries $Entries -Scope $scope
    $kept = @($selection.Kept)
    $cancelled = @($selection.Cancelled)
    if (($kept -join '|') -cne (@($ExpectedKept) -join '|') -or $kept.Count -ne @($ExpectedKept).Count) {
        throw "${Case}: kept [$($kept -join ' ; ')], expected [$(@($ExpectedKept) -join ' ; ')]"
    }
    if (($cancelled -join '|') -cne (@($ExpectedCancelled) -join '|') -or $cancelled.Count -ne @($ExpectedCancelled).Count) {
        throw "${Case}: cancelled [$($cancelled -join ' ; ')], expected [$(@($ExpectedCancelled) -join ' ; ')]"
    }
}

# The entries a held-file purge left on a test host, between another
# program's: every DefenseClaw delete goes, the other program's stay in order.
$edge = '*1\??\C:\Program Files (x86)\Microsoft\Edge\Temp\old_msedge.exe'
Assert-Selection -Case 'held-file purge' -Entries @(
    $edge, '',
    "*1\??\$lifecycle", '',
    "*1\??\$installRoot\bin\defenseclaw-hook.exe", '',
    "*1\??\$installRoot\bin", '',
    "*1\??\$installRoot", '',
    '*1\??\C:\Program Files\ClaudeCode\managed-settings.d\90-defenseclaw.json', '',
    '*1\??\C:\ProgramData\Cursor\hooks.json', '',
    '\??\C:\Windows\Temp\other.tmp', ''
) -ExpectedKept @($edge, '', '\??\C:\Windows\Temp\other.tmp', '') -ExpectedCancelled @(
    $lifecycle,
    "$installRoot\bin\defenseclaw-hook.exe",
    "$installRoot\bin",
    $installRoot,
    'C:\Program Files\ClaudeCode\managed-settings.d\90-defenseclaw.json',
    'C:\ProgramData\Cursor\hooks.json'
)

# A rename inside the scope is not a delete; it stays.
$rename = @("\??\$stateRoot\etc\config.yaml.new", "!\??\$stateRoot\etc\config.yaml")
Assert-Selection -Case 'rename' -Entries $rename -ExpectedKept $rename -ExpectedCancelled @()

# Look-alikes and other shapes stay: a sibling sharing the prefix, a path that
# climbs out with .., a UNC path, a source without the \??\ prefix, a file
# deeper than a sidecar folder, and a per-user install's file.
$others = @(
    "\??\$installRoot-old\bin\defenseclaw-hook.exe", '',
    "\??\$lifecycle-old\x.json", '',
    "\??\$installRoot\..\..\..\Windows\x.dll", '',
    '\??\UNC\server\share\DefenseClaw\x', '',
    "$installRoot\bin\defenseclaw.exe", '',
    '\??\C:\ProgramData\Cursor\sub\.defenseclaw-managed-hooks.state', '',
    '\??\C:\ProgramData\Cursor\settings.json', '',
    '\??\C:\Users\dev\.defenseclaw\config.yaml', ''
)
Assert-Selection -Case 'look-alikes' -Entries $others -ExpectedKept $others -ExpectedCancelled @()

# Case does not matter, a sidecar folder's .defenseclaw-managed-* files and a
# profile's managed runtime entries are DefenseClaw's.
Assert-Selection -Case 'case and sidecars' -Entries @(
    '\??\c:\program files\cisco\cisco secure client\defenseclaw\BIN\defenseclaw-gateway.exe', '',
    '\??\C:\ProgramData\Cursor\.defenseclaw-managed-hooks.state', '',
    '\??\C:\ProgramData\GitHub\Copilot\DefenseClaw\enrollment\S-1-5-21-1.json', '',
    '\??\C:\ProgramData\GitHub\Copilot\policy.d\90-defenseclaw.json', '',
    '\??\C:\Users\dev\.defenseclaw\hooks\.hookcfg', '',
    '\??\C:\Users\dev\.defenseclaw\hook_contract_lock.json', ''
) -ExpectedKept @() -ExpectedCancelled @(
    'c:\program files\cisco\cisco secure client\defenseclaw\BIN\defenseclaw-gateway.exe',
    'C:\ProgramData\Cursor\.defenseclaw-managed-hooks.state',
    'C:\ProgramData\GitHub\Copilot\DefenseClaw\enrollment\S-1-5-21-1.json',
    'C:\ProgramData\GitHub\Copilot\policy.d\90-defenseclaw.json',
    'C:\Users\dev\.defenseclaw\hooks\.hookcfg',
    'C:\Users\dev\.defenseclaw\hook_contract_lock.json'
)

# The backup an upgrade renamed a running image to and queued for deletion
# is never written again, so its delete stays.
$backups = @(
    "\??\$installRoot\bin\defenseclaw-hook.exe.backup.0123456789abcdef0123456789ABCDEF", '',
    "*1\??\$stateRoot\etc\policy.json.backup.fedcba9876543210fedcba9876543210", ''
)
Assert-Selection -Case 'replacement backups' -Entries ($backups + @(
        "\??\$installRoot\bin\defenseclaw-hook.exe", ''
    )) -ExpectedKept $backups -ExpectedCancelled @("$installRoot\bin\defenseclaw-hook.exe")

# A list that is not made of pairs is not understood, so nothing changes.
$odd = @("\??\$installRoot\bin\defenseclaw-hook.exe", '', '\??\C:\x')
Assert-Selection -Case 'odd list' -Entries $odd -ExpectedKept $odd -ExpectedCancelled @()

Assert-Selection -Case 'empty list' -Entries @() -ExpectedKept @() -ExpectedCancelled @()

'restart delete cancel smoke passed'
