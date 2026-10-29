# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# A redirected ConsoleHost renders warning records on stdout. The CLI forwards
# the installer's stdout verbatim and Setup parses stdout and stderr combined,
# so with -Json every lifecycle and cleanup advisory must reach the report's
# warnings array instead of the console. Extract the installer's actual call,
# catch, warning merge and output statements and run them in a child host;
# the lifecycle module is a fixture, so nothing on the machine changes.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-JsonWarningsTest {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "enterprise-installer-json-warnings-smoke: $Message"
    }
}

$modulePath = [IO.Path]::GetFullPath(
    [IO.Path]::Combine($PSScriptRoot, '..', 'DefenseClawEnterprise.psm1')
)
$moduleTokens = $null
$moduleErrors = $null
$moduleAst = [Management.Automation.Language.Parser]::ParseFile(
    $modulePath, [ref]$moduleTokens, [ref]$moduleErrors
)
Assert-JsonWarningsTest (@($moduleErrors).Count -eq 0) 'module has parser errors'
# A real nested advisory: the warning starts two calls below the lifecycle
# entry point, the way the trust and ACL self-heal advisories do.
$advisoryFunction = @($moduleAst.FindAll(
    {
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Write-DefenseClawTrustAdvisory'
    },
    $true
))
$advisoryMarker = @($moduleAst.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.AssignmentStatementAst] -and
        $_.Left.Extent.Text -ceq '$script:TrustAdvisoryMarker'
})
Assert-JsonWarningsTest ($advisoryFunction.Count -eq 1) 'expected one trust advisory writer'
Assert-JsonWarningsTest ($advisoryMarker.Count -eq 1) 'expected one trust advisory marker'

$installerPath = [IO.Path]::GetFullPath(
    [IO.Path]::Combine($PSScriptRoot, '..', 'install-enterprise.ps1')
)
$installerTokens = $null
$installerErrors = $null
$installerAst = [Management.Automation.Language.Parser]::ParseFile(
    $installerPath, [ref]$installerTokens, [ref]$installerErrors
)
Assert-JsonWarningsTest (@($installerErrors).Count -eq 0) 'installer has parser errors'
$installerIfs = @($installerAst.FindAll(
    { param($node) $node -is [Management.Automation.Language.IfStatementAst] },
    $true
))
$invocation = @($installerIfs | Where-Object {
    $_.Clauses[0].Item1.Extent.Text -ceq '$Json' -and
        $_.Extent.Text.Contains('DefenseClawEnterprise\Invoke-DefenseClawEnterpriseLifecycle')
})
$warningMerge = @($installerIfs | Where-Object {
    $_.Clauses[0].Item1.Extent.Text -ceq '$Json' -and
        $_.Extent.Text.Contains('foreach ($warning in @($lifecycleWarnings))')
})
$cleanupWarning = @($installerIfs | Where-Object {
    $_.Clauses[0].Item1.Extent.Text -ceq '$Json' -and
        $_.Extent.Text.Contains('$jsonWarnings += $cleanupDetail')
})
$outputBoundary = @($installerAst.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.IfStatementAst] -and
        $_.Clauses[0].Item1.Extent.Text -ceq '-not [string]::IsNullOrWhiteSpace($failureMessage)'
})
$exitBoundary = @($installerAst.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.IfStatementAst] -and
        $_.Clauses[0].Item1.Extent.Text -ceq '$exitCode -ne 0'
})
foreach ($fragment in @($invocation, $warningMerge, $cleanupWarning, $outputBoundary, $exitBoundary)) {
    Assert-JsonWarningsTest ($fragment.Count -eq 1) 'expected one exact installer JSON boundary fragment'
}
$mainTry = @($installerAst.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.TryStatementAst] -and
        $_.Extent.Text.Contains('DefenseClawEnterprise\Invoke-DefenseClawEnterpriseLifecycle')
})
Assert-JsonWarningsTest ($mainTry.Count -eq 1 -and $mainTry[0].CatchClauses.Count -eq 1) 'installer catch boundary changed'
$initialization = @()
foreach ($variable in @('$result', '$failureMessage', '$exitCode', '$lifecycleWarnings', '$jsonWarnings')) {
    $assignments = @($installerAst.EndBlock.Statements | Where-Object {
        $_ -is [Management.Automation.Language.AssignmentStatementAst] -and
            $_.Left.Extent.Text -ceq $variable
    })
    Assert-JsonWarningsTest ($assignments.Count -eq 1) "installer initialization changed for $variable"
    $initialization += $assignments[0].Extent.Text
}

$fixtureModule = @'
param([string]$Case)
$script:JSONProbeCase = $Case
__PRODUCTION_ADVISORY__
function Test-DefenseClawJSONProbeAncestor {
    Write-DefenseClawTrustAdvisory -Path 'C:\Program Files\Cisco' -Reason 'isolated owner advisory'
}
function Invoke-DefenseClawEnterpriseLifecycle {
    [CmdletBinding()]
    param()
    Microsoft.PowerShell.Utility\Write-Warning 'unrelated lifecycle advisory'
    Test-DefenseClawJSONProbeAncestor
    if ($script:JSONProbeCase -ceq 'failure') { throw 'isolated activation failure' }
    [pscustomobject]@{
        schema_version = 1
        ok = $true
        action = 'install'
        warnings = @('existing result advisory')
        gateway_service_state = $null
        guardian_service_state = $null
        gateway_ready = $null
        guardian_ready = $null
    }
}
Export-ModuleMember -Function Invoke-DefenseClawEnterpriseLifecycle
'@
$fixtureModule = $fixtureModule.Replace(
    '__PRODUCTION_ADVISORY__',
    ($advisoryMarker[0].Extent.Text + "`n" + $advisoryFunction[0].Extent.Text)
)
$probeSource = @(
    '[CmdletBinding()] param([switch]$Json, [string]$ProbeCase)',
    "Set-StrictMode -Version Latest; `$ErrorActionPreference = 'Stop'",
    '$fixtureModule = New-Module -Name DefenseClawEnterprise -ArgumentList $ProbeCase -ScriptBlock {',
    $fixtureModule,
    '}; Import-Module $fixtureModule -Force',
    ($initialization -join "`n"),
    '$arguments = @{}; $Action = ''Install''',
    'try {',
    $invocation[0].Extent.Text,
    '} catch {',
    $mainTry[0].CatchClauses[0].Body.Extent.Text.Trim().TrimStart('{').TrimEnd('}'),
    '}',
    'if ($ProbeCase -ceq ''cleanup'') { $cleanupDetail = ''isolated bootstrap cleanup advisory'';',
    $cleanupWarning[0].Extent.Text,
    '}',
    $warningMerge[0].Extent.Text,
    $outputBoundary[0].Extent.Text,
    $exitBoundary[0].Extent.Text
) -join "`n"

$outputTempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$outputLeaf = 'DefenseClaw-InstallerJSON-' + [Guid]::NewGuid().ToString('N')
$expectedOutputRoot = [IO.Path]::GetFullPath([IO.Path]::Combine($outputTempParent, $outputLeaf))
$outputRoot = $expectedOutputRoot
[void][IO.Directory]::CreateDirectory($outputRoot)
try {
    $probePath = [IO.Path]::Combine($outputRoot, 'installer-json-host-probe.ps1')
    [IO.File]::WriteAllText($probePath, $probeSource, [Text.UTF8Encoding]::new($false))
    $enginePath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    foreach ($case in @('success', 'failure', 'cleanup', 'text')) {
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $enginePath
        $start.Arguments = (
            '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
            $probePath + '" -ProbeCase ' + $case
        )
        if ($case -cne 'text') { $start.Arguments += ' -Json' }
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $child = [Diagnostics.Process]::new()
        $child.StartInfo = $start
        try {
            Assert-JsonWarningsTest ($child.Start()) "$case`: JSON host probe failed to start"
            $stdoutTask = $child.StandardOutput.ReadToEndAsync()
            $stderrTask = $child.StandardError.ReadToEndAsync()
            if (-not $child.WaitForExit(60000)) {
                $child.Kill()
                throw "enterprise-installer-json-warnings-smoke: $case JSON host exceeded its bounded timeout"
            }
            $child.WaitForExit()
            $stdout = [string]$stdoutTask.GetAwaiter().GetResult()
            $stderr = [string]$stderrTask.GetAwaiter().GetResult()
            $expectedExit = if ($case -ceq 'failure') { 1 } else { 0 }
            Assert-JsonWarningsTest ($child.ExitCode -eq $expectedExit) "$case`: unexpected exit $($child.ExitCode), stdout=$stdout stderr=$stderr"
        }
        finally { $child.Dispose() }
        if ($case -ceq 'text') {
            # Without -Json the console keeps showing the advisories.
            Assert-JsonWarningsTest ($stdout.Contains('WARNING:') -and $stdout.Contains('managed_trust_ancestor_advisory')) 'non-JSON advisory is no longer visible'
            continue
        }
        # Match Setup's combined-output boundary too. Any host-rendered warning
        # on either channel makes this complete JSON parse fail.
        $report = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ($stdout + $stderr) -ErrorAction Stop
        $warnings = @($report.warnings)
        Assert-JsonWarningsTest (@($warnings | Where-Object { $_ -match '^managed_trust_ancestor_advisory: ancestor C:\\Program Files\\Cisco .*isolated owner advisory$' }).Count -eq 1) "$case`: nested advisory was not preserved exactly once"
        Assert-JsonWarningsTest (@($warnings | Where-Object { $_ -ceq 'unrelated lifecycle advisory' }).Count -eq 1) "$case`: lifecycle warning was lost"
        if ($case -ceq 'failure') {
            Assert-JsonWarningsTest (-not $report.ok -and $report.error -ceq 'isolated activation failure') 'failure JSON lost its causal error'
            Assert-JsonWarningsTest ($warnings.Count -eq 2) 'failure JSON warning count is incorrect'
        }
        else {
            Assert-JsonWarningsTest ($report.ok -and @($warnings | Where-Object { $_ -ceq 'existing result advisory' }).Count -eq 1) "$case`: existing structured warning was lost"
            $expectedWarnings = if ($case -ceq 'cleanup') { 4 } else { 3 }
            Assert-JsonWarningsTest ($warnings.Count -eq $expectedWarnings) "$case`: unexpected warning count"
            if ($case -ceq 'cleanup') {
                Assert-JsonWarningsTest ($warnings -contains 'isolated bootstrap cleanup advisory') 'cleanup warning was not preserved in JSON'
            }
        }
    }
}
finally {
    $cleanupRoot = [IO.Path]::GetFullPath($outputRoot)
    if (-not [string]::Equals($cleanupRoot, $expectedOutputRoot, [StringComparison]::Ordinal) -or
        -not [string]::Equals([IO.Path]::GetDirectoryName($cleanupRoot), $outputTempParent, [StringComparison]::Ordinal) -or
        [IO.Path]::GetFileName($cleanupRoot) -cne $outputLeaf -or
        $outputLeaf -cnotmatch '^DefenseClaw-InstallerJSON-[a-f0-9]{32}$') {
        throw 'enterprise-installer-json-warnings-smoke: refusing cleanup outside the exact temporary fixture root'
    }
    if ([IO.Directory]::Exists($cleanupRoot)) { [IO.Directory]::Delete($cleanupRoot, $true) }
}

'enterprise-installer-json-warnings-smoke OK'
