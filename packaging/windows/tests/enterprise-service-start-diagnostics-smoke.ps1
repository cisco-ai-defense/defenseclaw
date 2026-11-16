# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# A service that fails to start must be reported with SCM's exit codes, and
# its dependencies' codes, instead of Start-Service's bare "Cannot start
# service X". The helpers are pure string assembly over sc.exe queryex output,
# so they are loaded from the module by AST and run against canned output; the
# module itself is not imported (its init requires a Windows machine root).

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Combine, not a backslash literal, so the smoke also runs under pwsh off Windows.
$modulePath = [IO.Path]::GetFullPath(
    [IO.Path]::Combine($PSScriptRoot, '..', 'DefenseClawEnterprise.psm1')
)
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($modulePath, [ref]$null, [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) {
    throw "module does not parse: $(@($parseErrors)[0])"
}
foreach ($name in @(
        'Get-DefenseClawServiceStartFailureMessage',
        'Get-DefenseClawServiceExitCodes',
        'Get-DefenseClawWin32ErrorCode'
    )) {
    $definition = $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
    if ($null -eq $definition) {
        throw "module does not define $name"
    }
    . ([scriptblock]::Create($definition.Extent.Text))
}

$script:ScExe = 'sc.exe'
# Real sc.exe queryex layout for the field case: the broker exited with a
# service-specific error, so the gateway that depends on it reports 1068.
$script:Queryex = @{
    'DefenseClawGateway'    = @(
        '',
        'SERVICE_NAME: DefenseClawGateway',
        '        TYPE               : 10  WIN32_OWN_PROCESS',
        '        STATE              : 1  STOPPED',
        '        WIN32_EXIT_CODE    : 1068  (0x42c)',
        '        SERVICE_EXIT_CODE  : 0  (0x0)',
        '        CHECKPOINT         : 0x0',
        '        WAIT_HINT          : 0x0',
        '        PID                : 0',
        '        FLAGS              :'
    )
    'DefenseClawCMIDBroker' = @(
        'SERVICE_NAME: DefenseClawCMIDBroker',
        '        TYPE               : 10  WIN32_OWN_PROCESS',
        '        STATE              : 1  STOPPED',
        '        WIN32_EXIT_CODE    : 1066  (0x42a)',
        '        SERVICE_EXIT_CODE  : 1  (0x1)'
    )
}
function Invoke-DefenseClawNative {
    param($File, $Arguments, [switch]$Capture)
    $serviceName = [string]$Arguments[1]
    if (-not $script:Queryex.ContainsKey($serviceName)) {
        throw "sc.exe exited 1060 while running 'queryex $serviceName'"
    }
    return $script:Queryex[$serviceName]
}

function Assert-Contains([string]$Text, [string]$Expected) {
    if (-not $Text.Contains($Expected)) {
        throw "expected '$Expected' in: $Text"
    }
}

$gateway = [pscustomobject]@{
    ServicesDependedOn = @([pscustomobject]@{ ServiceName = 'DefenseClawCMIDBroker' })
}
# Start-Service wraps StartService's Win32 error; that is where 1068 lives when
# the gateway never ran, so sc.exe can still show an older exit code.
$startError = [InvalidOperationException]::new(
    "Cannot start service DefenseClawGateway on computer '.'.",
    [ComponentModel.Win32Exception]::new(1068)
)
$code = Get-DefenseClawWin32ErrorCode -Exception ([Exception]::new('outer', $startError))
if ($code -ne 1068) {
    throw "Win32 error from the exception chain = $code, want 1068"
}
if ($null -ne (Get-DefenseClawWin32ErrorCode -Exception ([Exception]::new('no win32')))) {
    throw 'an exception chain without a Win32Exception produced an error code'
}
$message = Get-DefenseClawServiceStartFailureMessage `
    -Name 'DefenseClawGateway' `
    -Service $gateway `
    -Cause $startError.Message `
    -StartError $code
Assert-Contains $message 'service DefenseClawGateway failed to start: START_ERROR=1068'
Assert-Contains $message 'STATE=STOPPED WIN32_EXIT_CODE=1068'
Assert-Contains $message 'SERVICE_EXIT_CODE=0'
Assert-Contains $message '[dependency DefenseClawCMIDBroker: STATE=STOPPED WIN32_EXIT_CODE=1066'
Assert-Contains $message 'SERVICE_EXIT_CODE=1]'
Assert-Contains $message "(Cannot start service DefenseClawGateway on computer '.'.)"

# A service with no dependencies, and a query that fails, still produce a
# message instead of throwing over the original failure.
$plain = Get-DefenseClawServiceStartFailureMessage -Name 'DefenseClawCMIDBroker' -Service $null
Assert-Contains $plain 'service DefenseClawCMIDBroker failed to start: STATE=STOPPED WIN32_EXIT_CODE=1066'
if ($plain.Contains('[dependency')) {
    throw "a service without dependencies listed one: $plain"
}
$missing = Get-DefenseClawServiceStartFailureMessage -Name 'DefenseClawMissing' -Service $null
Assert-Contains $missing 'service DefenseClawMissing failed to start: exit codes unavailable'

'service start diagnostics smoke passed'
