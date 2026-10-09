# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Portable regression coverage for the production service-logon wrappers.
# Parse and extract their exact definitions instead of importing the module:
# no Windows registry, SCM, or local security policy is modified by this test.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    [IO.Path]::Combine($PSScriptRoot, '..', 'DefenseClawEnterprise.psm1')
)
$parseTokens = $null
$parseErrors = $null
$moduleAst = [Management.Automation.Language.Parser]::ParseFile(
    $modulePath, [ref]$parseTokens, [ref]$parseErrors
)
if (@($parseErrors).Count -ne 0) {
    throw "enterprise-service-logon-smoke: module parser errors: $($parseErrors.Message -join '; ')"
}
$functionDefinitions = @($moduleAst.FindAll(
    { param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] },
    $true
))

function Get-ProductionFunction {
    param([Parameter(Mandatory)][string]$Name)
    $matches = @($functionDefinitions | Where-Object { $_.Name -ceq $Name })
    if ($matches.Count -ne 1) {
        throw "enterprise-service-logon-smoke: expected one production $Name definition, found $($matches.Count)"
    }
    return $matches[0]
}

function Assert-LogonTest {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "enterprise-service-logon-smoke: $Message"
    }
}

function Get-ExpectedFailure {
    param([Parameter(Mandatory)][scriptblock]$Body)
    try {
        & $Body | Out-Null
    }
    catch {
        return $_.Exception
    }
    throw 'enterprise-service-logon-smoke: expected a terminating exception'
}

# Compile the exact embedded production C# as well as the behavioral fake.
# Extracting its AST value avoids evaluating the Windows-only initializer;
# only its randomized namespace interpolation is replaced. Compilation loads
# no Windows library and invokes no P/Invoke entry point.
$nativeInitializer = Get-ProductionFunction -Name 'Initialize-DefenseClawNativeSecurity'
$productionSources = @($nativeInitializer.Body.FindAll(
    {
        param($node)
        $node -is [Management.Automation.Language.ExpandableStringExpressionAst] -and
            $node.Value.Contains('public static class NativeSecurity')
    },
    $true
))
Assert-LogonTest ($productionSources.Count -eq 1) 'expected one exact embedded production NativeSecurity source'
$productionNamespace = 'DefenseClaw.ServiceLogonProductionSmoke_' + [Guid]::NewGuid().ToString('N')
$productionSource = [string]$productionSources[0].Value
Assert-LogonTest ($productionSource.Contains('$nativeNamespace')) 'production source lost its randomized namespace placeholder'
$productionSource = $productionSource.Replace('$nativeNamespace', $productionNamespace)
$productionTypes = @(Microsoft.PowerShell.Utility\Add-Type `
    -TypeDefinition $productionSource -Language CSharp -PassThru -ErrorAction Stop)
$productionNativeTypes = @($productionTypes | Where-Object {
    $_.Name -ceq 'NativeSecurity' -and $_.Namespace -ceq $productionNamespace
})
Assert-LogonTest ($productionNativeTypes.Count -eq 1) 'production C# did not return the exact NativeSecurity type'
$productionNativeType = $productionNativeTypes[0]
# The invalid authority is rejected before SecurityIdentifier construction or
# LSA access, so this production guard can safely execute on macOS too.
$invalidSIDFailure = Get-ExpectedFailure {
    [void]$productionNativeType::EnsureServiceLogonRight('S-1-5-18')
}
Assert-LogonTest (
    $invalidSIDFailure.InnerException -is [ArgumentException] -and
    $invalidSIDFailure.ToString().Contains('requires an NT SERVICE SID')
) 'production native guard must reject SYSTEM before any Windows API access'

# Each invocation gets a unique type, so repeating the harness in one host
# never accidentally reuses a fake from an earlier run.
$fakeNamespace = 'DefenseClaw.ServiceLogonSmoke_' + [Guid]::NewGuid().ToString('N')
$fakeTypes = @(Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
namespace $fakeNamespace
{
    public static class NativeSecurityStub
    {
        public static string Mode;
        public static string LastSID;
        public static int Calls;
        public static void Reset(string mode)
        {
            Mode = mode;
            LastSID = null;
            Calls = 0;
        }
        public static bool EnsureServiceLogonRight(string sid)
        {
            LastSID = sid;
            Calls++;
            switch (Mode)
            {
                case "added": return true;
                case "already": return false;
                case "denied":
                    throw new Win32Exception(5, "Acceso denegado; message is not an English error classifier");
                case "unexpected":
                    throw new Win32Exception(1385, "unexpected LSA provisioning error");
                case "other":
                    throw new InvalidOperationException("native helper programming failure");
                default: throw new InvalidOperationException("unrecognized test mode");
            }
        }
    }
}
"@ -Language CSharp -PassThru -ErrorAction Stop)
$script:LogonNativeType = @($fakeTypes | Where-Object { $_.Name -ceq 'NativeSecurityStub' })[0]
$script:LogonIdentityFailure = $null
$script:LogonCompilerFailure = $null
$script:LogonIdentityCalls = 0
$script:LogonCompilerCalls = 0
$script:LogonRequestedGateway = $null
$script:LogonGatewayName = 'DefenseClawGatewaySmoke_ServiceLogon'
$script:LogonGatewaySID = 'S-1-5-80-11111-22222-33333-44444-55555'

# Execute exact production bodies. Mock only their Windows identity and
# interop initialization boundaries, keeping exceptions on either side of
# the narrow production catch distinguishable.
foreach ($name in @(
    'Get-DefenseClawWin32ErrorCode',
    'Set-DefenseClawGatewayServiceLogonRight',
    'New-DefenseClawServiceStartException'
)) {
    $definition = Get-ProductionFunction -Name $name
    . ([scriptblock]::Create($definition.Extent.Text))
}
$identityDefinition = Get-ProductionFunction -Name 'Get-DefenseClawGatewayLogonIdentity'
# Its platform boundary is mocked below, but the production identity contract
# is still pinned: registry ObjectName, exact virtual account, and service SID.
foreach ($fragment in @(
    'Assert-DefenseClawServiceName',
    'Microsoft.PowerShell.Management\Get-ItemPropertyValue',
    'ObjectName',
    'NT SERVICE\$GatewayServiceName',
    '[StringComparison]::OrdinalIgnoreCase',
    'Get-DefenseClawServiceSID'
)) {
    Assert-LogonTest ($identityDefinition.Extent.Text.Contains($fragment)) "production identity helper omitted $fragment"
}

function Get-DefenseClawGatewayLogonIdentity {
    param([Parameter(Mandatory)][string]$GatewayServiceName)
    $script:LogonIdentityCalls++
    $script:LogonRequestedGateway = $GatewayServiceName
    if ($null -ne $script:LogonIdentityFailure) {
        throw $script:LogonIdentityFailure
    }
    return [pscustomobject]@{
        account = "NT SERVICE\$GatewayServiceName"
        sid = $script:LogonGatewaySID
    }
}

function Initialize-DefenseClawNativeSecurity {
    $script:LogonCompilerCalls++
    if ($null -ne $script:LogonCompilerFailure) {
        throw $script:LogonCompilerFailure
    }
    return $script:LogonNativeType
}

function Reset-LogonProbe {
    param([string]$Mode)
    $script:LogonIdentityFailure = $null
    $script:LogonCompilerFailure = $null
    $script:LogonIdentityCalls = 0
    $script:LogonCompilerCalls = 0
    $script:LogonRequestedGateway = $null
    $script:LogonNativeType::Reset($Mode)
}

foreach ($case in @(
    @{ mode = 'added'; outcome = 'added'; warnings = 0 },
    @{ mode = 'already'; outcome = 'already_granted'; warnings = 0 },
    @{ mode = 'denied'; outcome = 'policy_access_denied'; warnings = 1 }
)) {
    Reset-LogonProbe -Mode $case.mode
    $output = @(Set-DefenseClawGatewayServiceLogonRight `
        -GatewayServiceName $script:LogonGatewayName 3>&1)
    $warnings = @($output | Where-Object { $_ -is [Management.Automation.WarningRecord] })
    $results = @($output | Where-Object { $_ -isnot [Management.Automation.WarningRecord] })
    Assert-LogonTest ($results.Count -eq 1) "$($case.mode): expected exactly one result"
    Assert-LogonTest ($results[0].outcome -ceq $case.outcome) "$($case.mode): incorrect outcome"
    Assert-LogonTest ($results[0].account -ceq "NT SERVICE\$script:LogonGatewayName") "$($case.mode): lost exact virtual account"
    Assert-LogonTest ($results[0].sid -ceq $script:LogonGatewaySID) "$($case.mode): lost exact gateway SID"
    Assert-LogonTest ($script:LogonNativeType::LastSID -ceq $script:LogonGatewaySID) "$($case.mode): native call did not receive validated SID"
    Assert-LogonTest ($script:LogonNativeType::LastSID -cne 'S-1-5-80-0') 'ALL SERVICES must not receive the grant'
    Assert-LogonTest ($script:LogonNativeType::Calls -eq 1) "$($case.mode): expected one native operation"
    Assert-LogonTest ($script:LogonIdentityCalls -eq 1 -and $script:LogonCompilerCalls -eq 1) "$($case.mode): skipped prerequisite boundary"
    Assert-LogonTest ($script:LogonRequestedGateway -ceq $script:LogonGatewayName) "$($case.mode): identity was resolved for another service"
    Assert-LogonTest ($warnings.Count -eq $case.warnings) "$($case.mode): unexpected warning disposition"
}

Reset-LogonProbe -Mode 'unexpected'
$failure = Get-ExpectedFailure {
    Set-DefenseClawGatewayServiceLogonRight -GatewayServiceName $script:LogonGatewayName
}
Assert-LogonTest ((Get-DefenseClawWin32ErrorCode -Exception $failure) -eq 1385) 'unexpected native error was swallowed or lost'
Reset-LogonProbe -Mode 'other'
$failure = Get-ExpectedFailure {
    Set-DefenseClawGatewayServiceLogonRight -GatewayServiceName $script:LogonGatewayName
}
Assert-LogonTest ($failure.ToString().Contains('native helper programming failure')) 'unexpected non-Win32 error was swallowed'

foreach ($boundary in @('identity', 'compiler')) {
    Reset-LogonProbe -Mode 'added'
    $prerequisiteFailure = [ComponentModel.Win32Exception]::new(5, "$boundary failed before LSA mutation")
    if ($boundary -ceq 'identity') {
        $script:LogonIdentityFailure = $prerequisiteFailure
    }
    else {
        $script:LogonCompilerFailure = $prerequisiteFailure
    }
    $failure = Get-ExpectedFailure {
        Set-DefenseClawGatewayServiceLogonRight -GatewayServiceName $script:LogonGatewayName
    }
    Assert-LogonTest ((Get-DefenseClawWin32ErrorCode -Exception $failure) -eq 5) "$boundary access denied was swallowed"
    Assert-LogonTest ($script:LogonNativeType::Calls -eq 0) "$boundary failure reached native provisioning"
    if ($boundary -ceq 'identity') {
        Assert-LogonTest ($script:LogonCompilerCalls -eq 0) 'identity failure reached compilation'
    }
}

# Error classification follows exception metadata through wrappers. It must
# work when localized text neither names the right nor includes its number.
foreach ($code in @(5, 1069, 1385)) {
    $native = [ComponentModel.Win32Exception]::new($code, 'lokalisierte Meldung ohne Fehlernummer')
    $nested = [InvalidOperationException]::new(
        'outer wrapper', [InvalidOperationException]::new('inner wrapper', $native)
    )
    Assert-LogonTest ((Get-DefenseClawWin32ErrorCode -Exception $native) -eq $code) "direct Win32 $code was not classified"
    Assert-LogonTest ((Get-DefenseClawWin32ErrorCode -Exception $nested) -eq $code) "nested Win32 $code was not classified"
}

foreach ($code in @(1069, 1385)) {
    $original = [ComponentModel.Win32Exception]::new($code, 'mensaje localizado')
    $diagnostic = New-DefenseClawServiceStartException `
        -Name $script:LogonGatewayName `
        -GatewayServiceSID $script:LogonGatewaySID `
        -Exception $original
    Assert-LogonTest ($diagnostic -is [InvalidOperationException]) "$code did not produce an actionable gateway exception"
    Assert-LogonTest ([Object]::ReferenceEquals($diagnostic.InnerException, $original)) "$code diagnostic lost the original inner exception"
    foreach ($fragment in @($script:LogonGatewayName, "NT SERVICE\$script:LogonGatewayName", $script:LogonGatewaySID, [string]$code, 'SeServiceLogonRight')) {
        Assert-LogonTest ($diagnostic.Message.IndexOf($fragment, [StringComparison]::OrdinalIgnoreCase) -ge 0) "$code diagnostic omitted $fragment"
    }
    Assert-LogonTest ($diagnostic.Message -match 'deny') "$code diagnostic omitted deny-right guidance"
    Assert-LogonTest ($diagnostic.Message -match 'GPO|Group Policy') "$code diagnostic omitted central policy guidance"
    $generic = New-DefenseClawServiceStartException `
        -Name 'DefenseClawHookGuardian' -GatewayServiceSID '' -Exception $original
    Assert-LogonTest ([Object]::ReferenceEquals($generic, $original)) 'generic service without gateway SID must preserve its original exception'
}

$unrelated = [ComponentModel.Win32Exception]::new(5, 'unrelated service access failure')
$preserved = New-DefenseClawServiceStartException `
    -Name $script:LogonGatewayName `
    -GatewayServiceSID $script:LogonGatewaySID `
    -Exception $unrelated
Assert-LogonTest ([Object]::ReferenceEquals($preserved, $unrelated)) 'unrelated native service error must preserve its original exception'
$textOnly = [InvalidOperationException]::new('service logon failed 1069 SeServiceLogonRight')
$preserved = New-DefenseClawServiceStartException `
    -Name $script:LogonGatewayName `
    -GatewayServiceSID $script:LogonGatewaySID `
    -Exception $textOnly
Assert-LogonTest ([Object]::ReferenceEquals($preserved, $textOnly)) 'diagnostics must not classify message text as a native error code'
$nestedOriginal = [InvalidOperationException]::new(
    'Start-Service wrapper', [ComponentModel.Win32Exception]::new(1069, 'localized')
)
$nestedDiagnostic = New-DefenseClawServiceStartException `
    -Name $script:LogonGatewayName `
    -GatewayServiceSID $script:LogonGatewaySID `
    -Exception $nestedOriginal
Assert-LogonTest ([Object]::ReferenceEquals($nestedDiagnostic.InnerException, $nestedOriginal)) 'nested service diagnostic must retain the complete original chain'

# Bind the permission mutation to the validated install/upgrade/repair
# transaction, including NoStart installs. Restore and service configuration
# helpers must not silently change machine user-rights policy.
$installLike = Get-ProductionFunction -Name 'Invoke-DefenseClawInstallLikeLifecycle'
$provisionCalls = @($moduleAst.FindAll(
    {
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Set-DefenseClawGatewayServiceLogonRight'
    },
    $true
))
Assert-LogonTest ($provisionCalls.Count -eq 1) 'expected exactly one lifecycle provisioning call'
$provisionCall = $provisionCalls[0]
Assert-LogonTest (
    $provisionCall.Extent.StartOffset -gt $installLike.Extent.StartOffset -and
    $provisionCall.Extent.EndOffset -lt $installLike.Extent.EndOffset
) 'provisioning call must belong to Install/Upgrade/Repair lifecycle'
$staticAssertions = @($installLike.Body.FindAll(
    {
        param($node)
        if ($node -isnot [Management.Automation.Language.CommandAst] -or
            $node.GetCommandName() -cne 'Assert-DefenseClawEnterpriseDeployment') {
            return $false
        }
        foreach ($element in $node.CommandElements) {
            if ($element -is [Management.Automation.Language.CommandParameterAst] -and
                $element.ParameterName -ceq 'ServicingTransaction') {
                return $true
            }
        }
        return $false
    },
    $true
))
Assert-LogonTest ($staticAssertions.Count -eq 1) 'expected exactly one static servicing deployment assertion'
$activationBranches = @($installLike.Body.FindAll(
    {
        param($node)
        $node -is [Management.Automation.Language.IfStatementAst] -and
            $node.Clauses.Count -gt 0 -and
            $node.Clauses[0].Item1.Extent.Text -match '^\s*-not\s+\$NoStart\s*$'
    },
    $true
))
Assert-LogonTest ($activationBranches.Count -eq 1) 'expected exactly one NoStart activation gate'
Assert-LogonTest ($staticAssertions[0].Extent.EndOffset -lt $provisionCall.Extent.StartOffset) 'service-logon provisioning must follow validated static deployment'
Assert-LogonTest ($provisionCall.Extent.EndOffset -lt $activationBranches[0].Extent.StartOffset) 'NoStart must provision the right before skipping activation'
foreach ($definition in $functionDefinitions) {
    if ($definition.Name -notmatch 'Rollback|^Restore-|^Set-DefenseClawManagedServices') {
        continue
    }
    $grantCalls = @($definition.Body.FindAll(
        {
            param($node)
            if ($node -is [Management.Automation.Language.CommandAst]) {
                return $node.GetCommandName() -ceq 'Set-DefenseClawGatewayServiceLogonRight'
            }
            if ($node -is [Management.Automation.Language.InvokeMemberExpressionAst]) {
                return $node.Member.Extent.Text -ceq 'EnsureServiceLogonRight'
            }
            return $false
        },
        $true
    ))
    Assert-LogonTest ($grantCalls.Count -eq 0) "$($definition.Name) must not change service-logon policy"
}

'enterprise-service-logon-smoke OK'
