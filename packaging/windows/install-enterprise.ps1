# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Production interactive administrators enter through the signed defenseclaw
# CLI. That launcher supplies a strict environment before PowerShell/CLR
# startup; a script cannot retroactively neutralize profiler, startup-hook, or
# loader variables already consumed by its host process. Direct invocation of
# this file is therefore supported only from a trusted LocalSystem endpoint-
# management startup context. The one-shot isolation below protects all
# compiler and module-analysis activity after script execution begins.

[CmdletBinding()]
param(
    [ValidateSet('Install', 'Upgrade', 'Repair', 'Reconcile', 'Recover', 'Status', 'Verify', 'Uninstall')]
    [string]$Action = 'Install',

    [string]$BrokerBinary,
    [string]$ProviderLibrary,
    [string]$GatewayBinary,
    [string]$ACPBinary,
    [string]$HookBinary,
    [string]$SensorHelperBinary,
    [string]$PolicyCompiler,
    [string]$CLIBinary,
    [string]$NativeCleanupBinary,
    [string]$Config,
    [string]$Manifest,

    # QA-friendly shorthand: when -Mode + -Connector are supplied and
    # -Config / -Manifest are empty, the installer renders a minimal
    # managed_enterprise config.yaml and per-user targets.yaml into the
    # protected bootstrap staging directory before the module import,
    # then continues the lifecycle as if those paths had been supplied
    # directly. Mirrors the macOS install.sh --mode/--connector
    # shorthand and the render_config / render_targets_manifest helpers
    # in packaging/macos/lib/installer_lib.sh.
    #
    # -Mode is passed verbatim to guardrail.mode; -Connector is a
    # comma-separated list whose first entry becomes guardrail.connector
    # (primary) and every entry becomes both a targets.yaml row (one per
    # eligible interactive-user profile) and a guardrail.connectors map entry.
    # An Install/Upgrade/Repair that will start services renders every current
    # eligible profile. Rows with WTSActive sessions are immediate; enabled
    # rows for disconnected profiles carry `deferred: true` so Guardian can
    # leave their first reconcile pending until the exact user token exists.
    # A managed connector whose installed version cannot be verified is still
    # enabled, without agent_version (best-effort hook contract); only a
    # connector Windows managed mode cannot hook stays disabled. -NoStart
    # keeps the full planned manifest non-deferred because it makes no
    # activation/readiness claim in this transaction.
    # Both are mutually exclusive with -Config / -Manifest and -DeferredConfig.
    [ValidateSet('', 'observe', 'action')]
    [string]$Mode = '',
    [string]$Connector = '',

    [string]$InstallRoot,
    [string]$StateRoot,
    [string]$GatewayServiceName = 'DefenseClawGateway',
    [string]$GuardianServiceName = 'DefenseClawHookGuardian',
    [string]$CertificationCodexHome,
    [switch]$CoreHardeningCertification,

    [switch]$NoStart,
    # -Purge removes managed state during uninstall. When a
    # committed StateRoot exists, the ordinary state-root authenticated
    # purge runs. If only an exact canonical machine footprint survives,
    # recovery is limited to this invocation's exact service identities and
    # install-root inode through a no-follow helper. It never infers ownership
    # of user runtimes, shared connector configuration, or another scope from
    # a DefenseClaw-like name.
    [switch]$Purge,
    [switch]$AllowUnsigned,
    [switch]$AttestAgentApplicationControl,
    [switch]$AttestClaudeEffectivePolicy,
    # Stages an installed but disabled deployment with protected placeholder
    # policy. Activation is allowed only through a later Repair that supplies
    # BOTH authenticated Config and Manifest inputs; direct file-drop/start is
    # deliberately not an activation contract.
    [switch]$DeferredConfig,
    [int]$SelfUninstallCallerPID,
    # Protected parent directory for the installer's one-shot bootstrap
    # environment. When set (the outer signed DefenseClawSetup EXE passes
    # its own protected %ProgramData%\DefenseClaw-Enterprise-Setup-<hex>\scratch
    # path here), the bootstrap directory is created inside it INSTEAD of
    # C:\Windows\Temp — which on Azure-AD-joined hosts carries an Allow ACE
    # for the interactive AAD principal with Delete/DeleteSubdirectoriesAndFiles
    # rights, failing the module's later trusted-ancestor walk on rendered
    # config/targets YAML. Empty falls back to C:\Windows\Temp for
    # direct-caller compatibility on stock Windows.
    [string]$BootstrapParent = '',
    [switch]$Json,

    # Enterprise profile. SecureClient (default) is the Cisco Secure Client
    # deployment and behaves exactly as before. Standalone is deployable by
    # any MDM: vendor-neutral roots under Program Files\Cisco\DefenseClaw and
    # ProgramData\Cisco\DefenseClaw, no CMID credential broker, PowerShell 7.
    [ValidateSet('SecureClient', 'Standalone')]
    [string]$EnterpriseProfile = 'SecureClient',
    # Standalone-only payload trust (see the module's
    # Initialize-DefenseClawStandalonePayloadTrust).
    [ValidateSet('Authenticode', 'HashPinned')]
    [string]$TrustMode = 'Authenticode',
    [string]$PayloadManifest,
    # Comma-separated SHA-256 signer certificate thumbprints. A string, not
    # an array, because -File invocation passes arrays as one literal token.
    [string]$AllowedSigners = '',
    [string]$ProductVersion
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($EnterpriseProfile -ceq 'Standalone') {
    # The standalone lifecycle runs only on the engine, bitness, and
    # language mode it is certified for. Each refusal names a stable code an
    # MDM wrapper can report. The Secure Client path is unchanged.
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw (
            'powershell7_required: the standalone enterprise lifecycle requires ' +
            'PowerShell 7 (pwsh.exe, x64); Windows PowerShell ' +
            "$($PSVersionTable.PSVersion) is not supported"
        )
    }
    if (-not [Environment]::Is64BitProcess) {
        throw (
            'powershell_32bit_host: run the standalone enterprise lifecycle from ' +
            'a 64-bit process; 32-bit MDM agents must launch it through ' +
            '%WINDIR%\sysnative'
        )
    }
    $osArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    if ($osArchitecture -cne 'X64') {
        throw "unsupported_architecture: the standalone enterprise lifecycle requires Windows x64 (found $osArchitecture)"
    }
    if ($ExecutionContext.SessionState.LanguageMode -ne
        [Management.Automation.PSLanguageMode]::FullLanguage) {
        throw (
            'powershell_constrained_language: the standalone enterprise ' +
            'lifecycle compiles protected native helpers and requires ' +
            'FullLanguage mode; allow the DefenseClaw signer in the WDAC or ' +
            'AppLocker script policy'
        )
    }
}
elseif ($TrustMode -cne 'Authenticode' -or
    -not [string]::IsNullOrWhiteSpace($PayloadManifest) -or
    -not [string]::IsNullOrWhiteSpace($AllowedSigners) -or
    -not [string]::IsNullOrWhiteSpace($ProductVersion)) {
    throw 'payload trust modes, allowed signers, and product version recording apply only to -EnterpriseProfile Standalone'
}

# Everything below uses .NET types that a constrained language session cannot
# reach, and the first failure would leave the caller without a JSON verdict.
# This guard uses only cmdlets, hashtables and ConvertTo-Json, names the policy
# that constrained this host, and reports it in the standard failure shape. It
# follows the standalone host guards above, whose stable refusal codes MDM
# wrappers report.
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    $defenseClawLanguageMode = [string]$ExecutionContext.SessionState.LanguageMode
    $defenseClawLanguagePolicies = @()
    try {
        $defenseClawLockdown = Microsoft.PowerShell.Management\Get-ItemProperty `
            -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' `
            -Name '__PSLockdownPolicy' `
            -ErrorAction Stop
        if ("$($defenseClawLockdown.__PSLockdownPolicy)" -ne '') {
            $defenseClawLanguagePolicies += 'ps_lockdown_policy'
        }
    }
    catch {
    }
    try {
        $defenseClawAppLocker = Microsoft.PowerShell.Management\Get-ItemProperty `
            -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script' `
            -Name 'EnforcementMode' `
            -ErrorAction Stop
        if ("$($defenseClawAppLocker.EnforcementMode)" -eq '1') {
            $defenseClawLanguagePolicies += 'applocker'
        }
    }
    catch {
    }
    try {
        $defenseClawDeviceGuard = CimCmdlets\Get-CimInstance `
            -Namespace 'root\Microsoft\Windows\DeviceGuard' `
            -ClassName 'Win32_DeviceGuard' `
            -ErrorAction Stop
        if ("$($defenseClawDeviceGuard.UsermodeCodeIntegrityPolicyEnforcementStatus)" -eq '2') {
            $defenseClawLanguagePolicies += 'wdac'
        }
    }
    catch {
    }
    if ($defenseClawLanguagePolicies.Count -eq 0) {
        $defenseClawLanguagePolicies += 'unknown'
    }
    $defenseClawLanguageFailure = (
        'defenseclaw_prereq check="powershell_language_mode" ' +
        'language_mode="{0}" policy="{1}" ' +
        'remedy="allow the signed DefenseClaw installer scripts to run in FullLanguage mode"'
    ) -f $defenseClawLanguageMode, ($defenseClawLanguagePolicies -join ',')
    if ($Json) {
        # An ordered hashtable, not a custom-object cast: constrained language
        # refuses that conversion.
        [ordered]@{
            schema_version = 1
            ok = $false
            action = ([string]$Action).ToLowerInvariant()
            error = $defenseClawLanguageFailure
            errors = @($defenseClawLanguageFailure)
        } | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 6 -Compress
    }
    else {
        Microsoft.PowerShell.Utility\Write-Error `
            -ErrorAction Continue `
            -Message (
                'DefenseClaw Windows enterprise {0} failed: {1}' -f
                ([string]$Action).ToLowerInvariant(),
                $defenseClawLanguageFailure
            )
    }
    exit 1
}

function ConvertTo-DefenseClawTrustedMachineRoot {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($Value) -or
        $Value -match '[\x00-\x1f%]' -or
        -not [IO.Path]::IsPathRooted($Value)) {
        throw "trusted $Label root is empty, relative, or contains an invalid character"
    }
    $full = [IO.Path]::GetFullPath($Value).TrimEnd('\')
    $driveRoot = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($driveRoot) -or
        $driveRoot -notmatch '^[A-Za-z]:\\$' -or
        $full.StartsWith('\\') -or
        $full.StartsWith('//') -or
        $full.StartsWith('\\?\') -or
        $full.StartsWith('\\.\') -or
        -not [IO.Directory]::Exists($full)) {
        throw "trusted $Label root is not an existing canonical local directory: $full"
    }
    return $full
}

function Get-DefenseClawTrustedMachineRoots {
    # Environment.GetFolderPath can return an empty string when PowerShell is
    # launched with the deliberately reduced native-bootstrap environment.
    # Resolve machine roots from fixed HKLM registration plus the Win32-backed
    # Environment.SystemDirectory property, without consulting process HOME,
    # profile, ProgramFiles, ProgramData, SystemRoot, or windir variables.
    $windows = ConvertTo-DefenseClawTrustedMachineRoot `
        -Value ([IO.Path]::GetDirectoryName([Environment]::SystemDirectory)) `
        -Label 'Windows'
    $base = $null
    $shell = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64
        )
        $currentVersion = $base.OpenSubKey(
            'SOFTWARE\Microsoft\Windows\CurrentVersion',
            $false
        )
        if ($null -eq $currentVersion) {
            throw 'trusted Program Files machine registration is missing'
        }
        try {
            $programFilesRaw = [string]$currentVersion.GetValue(
                'ProgramFilesDir',
                $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
        } finally {
            $currentVersion.Dispose()
        }
        $shell = $base.OpenSubKey(
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
            $false
        )
        if ($null -eq $shell) {
            throw 'trusted ProgramData machine registration is missing'
        }
        $programDataRaw = [string]$shell.GetValue(
            'Common AppData',
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
    } finally {
        if ($null -ne $shell) { $shell.Dispose() }
        if ($null -ne $base) { $base.Dispose() }
    }
    return [pscustomobject]@{
        Windows = $windows
        ProgramFiles = ConvertTo-DefenseClawTrustedMachineRoot `
            -Value $programFilesRaw `
            -Label 'Program Files'
        ProgramData = ConvertTo-DefenseClawTrustedMachineRoot `
            -Value $programDataRaw `
            -Label 'ProgramData'
    }
}

function Get-DefenseClawBootstrapProfileRoots {
    <#
        Bootstrap copy of the module's Get-DefenseClawProfileRoots, needed
        before the module is trusted and imported. The pytest contract keeps
        the two in lockstep.
    #>
    param(
        [ValidateSet('SecureClient', 'Standalone')]
        [string]$ForProfile = $EnterpriseProfile
    )
    $vendor = if ($ForProfile -ceq 'Standalone') { 'Cisco' } else { 'Cisco\Cisco Secure Client' }
    return @{
        InstallRoot = [IO.Path]::Combine($trustedProgramFiles, "$vendor\DefenseClaw")
        StateRoot = [IO.Path]::Combine($trustedProgramData, "$vendor\DefenseClaw")
        CertificationInstallBase = [IO.Path]::Combine($trustedProgramFiles, "$vendor\DefenseClaw-Cert")
        CertificationStateBase = [IO.Path]::Combine($trustedProgramData, "$vendor\DefenseClaw-Cert")
    }
}

# A host whose machine-root registration is broken must still get the
# standard failure verdict, not a bare PowerShell error with no JSON.
try {
    $trustedMachineRoots = Get-DefenseClawTrustedMachineRoots
    $trustedWindows = [string]$trustedMachineRoots.Windows
    $trustedProgramFiles = [string]$trustedMachineRoots.ProgramFiles
    $trustedProgramData = [string]$trustedMachineRoots.ProgramData
    $bootstrapProfileRoots = Get-DefenseClawBootstrapProfileRoots
    $InstallRoot = if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
        [string]$bootstrapProfileRoots.InstallRoot
    } else { $InstallRoot }
    $StateRoot = if ([string]::IsNullOrWhiteSpace($StateRoot)) {
        [string]$bootstrapProfileRoots.StateRoot
    } else { $StateRoot }
    $trustedSystem32 = [IO.Path]::Combine($trustedWindows, 'System32')
    [Environment]::SetEnvironmentVariable('SystemRoot', $trustedWindows, 'Process')
    [Environment]::SetEnvironmentVariable('windir', $trustedWindows, 'Process')
    [Environment]::SetEnvironmentVariable('ProgramFiles', $trustedProgramFiles, 'Process')
    [Environment]::SetEnvironmentVariable('ProgramData', $trustedProgramData, 'Process')
    # Pin module resolution to the running engine's own module directory so an
    # ambient PSModulePath cannot inject a substitute module.
    $trustedEngineModules = [IO.Path]::Combine($PSHOME, 'Modules')
    if (-not [IO.Directory]::Exists($trustedEngineModules)) {
        throw "trusted engine module directory is missing: $trustedEngineModules"
    }
    [Environment]::SetEnvironmentVariable('PSModulePath', $trustedEngineModules, 'Process')
    [Environment]::SetEnvironmentVariable(
        'PATH',
        (@(
            $trustedSystem32,
            $trustedWindows,
            ([IO.Path]::Combine($trustedSystem32, 'Wbem')),
            ([IO.Path]::Combine($trustedSystem32, 'WindowsPowerShell\v1.0'))
        ) -join [IO.Path]::PathSeparator),
        'Process'
    )
}
catch {
    $defenseClawRootFailure = [string]$_.Exception.Message
    if ($Json) {
        [pscustomobject]@{
            schema_version = 1
            ok = $false
            action = ([string]$Action).ToLowerInvariant()
            error = $defenseClawRootFailure
            errors = @($defenseClawRootFailure)
        } | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 6 -Compress
    }
    else {
        Microsoft.PowerShell.Utility\Write-Error `
            -ErrorAction Continue `
            -Message (
                'DefenseClaw Windows enterprise {0} failed: {1}' -f
                ([string]$Action).ToLowerInvariant(),
                $defenseClawRootFailure
            )
    }
    exit 1
}

$script:DefenseClawBootstrapPathProbe = $null
# Drift the bootstrap accepts before the module is imported. Write-Warning
# would reach stdout ahead of the JSON verdict, so these lines go into the
# error text on failure and, on success, into an existing warnings[] or to
# stderr; the success JSON never gains a field.
$script:DefenseClawBootstrapResilienceEvents =
    [Collections.Generic.List[string]]::new()
$script:DefenseClawBootstrapAdminEquivalentMembers = $null
$script:DefenseClawBootstrapAdminMembershipUnknown = $false

# Same line format as the module and the Go components: marker, then
# key="value" fields in key order, values quoted like Go's strconv.Quote.
function Format-DefenseClawBootstrapResilienceEvent {
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'defenseclaw_repair',
            'defenseclaw_accept',
            'defenseclaw_skip',
            'defenseclaw_boundary',
            'defenseclaw_prereq',
            'defenseclaw_recover',
            'defenseclaw_degraded'
        )]
        [string]$Marker,
        [hashtable]$Fields = @{}
    )
    $line = [Text.StringBuilder]::new($Marker)
    $keys = [string[]]@(
        $Fields.Keys | Microsoft.PowerShell.Core\ForEach-Object { [string]$_ }
    )
    [Array]::Sort($keys, [StringComparer]::Ordinal)
    foreach ($key in $keys) {
        $value = [string]$Fields[$key]
        $quoted = [Text.StringBuilder]::new($value.Length + 2)
        [void]$quoted.Append('"')
        foreach ($character in $value.ToCharArray()) {
            switch ($character) {
                '\' { [void]$quoted.Append('\\'); continue }
                '"' { [void]$quoted.Append('\"'); continue }
                "`n" { [void]$quoted.Append('\n'); continue }
                "`r" { [void]$quoted.Append('\r'); continue }
                "`t" { [void]$quoted.Append('\t'); continue }
                default {
                    if ([int]$character -lt 0x20 -or [int]$character -eq 0x7f) {
                        [void]$quoted.AppendFormat(
                            [Globalization.CultureInfo]::InvariantCulture,
                            '\x{0:x2}',
                            [int]$character
                        )
                    }
                    else {
                        [void]$quoted.Append($character)
                    }
                }
            }
        }
        [void]$quoted.Append('"')
        [void]$line.Append(' ').Append($key).Append('=').Append($quoted.ToString())
    }
    return $line.ToString()
}

# Mirrors the module's strict pin (DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS):
# set, the bootstrap's advisory trust verdicts are fatal again.
function Test-DefenseClawBootstrapStrictAncestors {
    $raw = [Environment]::GetEnvironmentVariable(
        'DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS',
        'Process'
    )
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $false
    }
    return ([string]$raw).Trim().ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
}

function Add-DefenseClawBootstrapResilienceEvent {
    param(
        [Parameter(Mandatory)][string]$Marker,
        [hashtable]$Fields = @{}
    )
    $line = Format-DefenseClawBootstrapResilienceEvent -Marker $Marker -Fields $Fields
    if (-not $script:DefenseClawBootstrapResilienceEvents.Contains($line) -and
        $script:DefenseClawBootstrapResilienceEvents.Count -lt 256) {
        $script:DefenseClawBootstrapResilienceEvents.Add($line)
    }
}

# Names the policy that stopped Add-Type from compiling. Only numeric codes and
# error IDs are read, never localized text: 1260 is AppLocker or Software
# Restriction Policies, 4551 is WDAC or Smart App Control, 225 is Defender or
# an ASR rule, ScriptContainedMaliciousContent is AMSI, and, for Add-Type only,
# 112 or another IOException means the compiler's temporary directory is
# unusable. Any other check keeps its own error for an IOException.
function Get-DefenseClawBootstrapAddTypeFailure {
    param(
        [Parameter(Mandatory)]$ErrorRecord,
        [string]$Check = 'powershell_add_type',
        # The blocked file; empty names the compiler Add-Type runs.
        [string]$Path = ''
    )
    $policy = ''
    $win32 = ''
    $ioFailure = $false
    $ids = @()
    if ($null -ne $ErrorRecord.PSObject.Properties['FullyQualifiedErrorId']) {
        $ids += [string]$ErrorRecord.FullyQualifiedErrorId
    }
    $exception = $ErrorRecord
    if ($null -ne $ErrorRecord.PSObject.Properties['Exception']) {
        $exception = $ErrorRecord.Exception
    }
    for ($depth = 0; $null -ne $exception -and $depth -lt 12; $depth++) {
        if ($null -ne $exception.PSObject.Properties['ErrorRecord'] -and
            $null -ne $exception.ErrorRecord) {
            $ids += [string]$exception.ErrorRecord.FullyQualifiedErrorId
        }
        $codes = @()
        if ($exception -is [ComponentModel.Win32Exception]) {
            $codes += [int64]$exception.NativeErrorCode
        }
        $codes += [int64]([int64]$exception.HResult -band 0xffffffffL)
        foreach ($code in $codes) {
            switch ($code) {
                1260 { $win32 = '1260'; $policy = 'applocker_or_srp' }
                2147943660 { $win32 = '1260'; $policy = 'applocker_or_srp' } # 0x800704EC
                4551 { $win32 = '4551'; $policy = 'wdac_or_smart_app_control' }
                2147946951 { $win32 = '4551'; $policy = 'wdac_or_smart_app_control' } # 0x800711C7
                225 { $win32 = '225'; $policy = 'defender_or_asr' }
                2147942625 { $win32 = '225'; $policy = 'defender_or_asr' } # 0x800700E1
                112 { if ($policy -eq '') { $win32 = '112'; $ioFailure = $true } }
                2147942512 { if ($policy -eq '') { $win32 = '112'; $ioFailure = $true } } # 0x80070070
            }
        }
        if ($exception -is [IO.IOException]) {
            $ioFailure = $true
        }
        $exception = $exception.InnerException
    }
    if ($policy -eq '' -and
        @($ids | Microsoft.PowerShell.Core\Where-Object {
                $_ -like '*ScriptContainedMaliciousContent*'
            }).Count -gt 0) {
        $policy = 'amsi'
    }
    if ($policy -eq '' -and $ioFailure -and $Check -ceq 'powershell_add_type') {
        $policy = 'compiler_temp_unusable'
    }
    if ($policy -eq '') {
        return $null
    }
    $compiler = $Path
    if ([string]::IsNullOrWhiteSpace($compiler)) {
        try {
            $compiler = [IO.Path]::Combine(
                [Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory(),
                'csc.exe'
            )
        }
        catch {
            $compiler = 'csc.exe'
        }
    }
    $fields = @{
        check  = $Check
        path   = $compiler
        policy = $policy
        win32  = $win32
    }
    $logEvent = Get-DefenseClawBootstrapPolicyBlockEvent -Policy $policy
    if (-not [string]::IsNullOrWhiteSpace($logEvent)) {
        $fields['event'] = $logEvent
    }
    return (Format-DefenseClawBootstrapResilienceEvent `
        -Marker defenseclaw_prereq `
        -Fields $fields)
}

# Best effort: the most recent matching block in the last two minutes, named by
# log and event ID. Never throws and never decides the verdict.
function Get-DefenseClawBootstrapPolicyBlockEvent {
    param([string]$Policy)
    $candidates = switch ($Policy) {
        'applocker_or_srp' {
            @(
                @('Microsoft-Windows-AppLocker/EXE and DLL', 8004),
                @('Application', 866)
            )
        }
        'wdac_or_smart_app_control' {
            @(, @('Microsoft-Windows-CodeIntegrity/Operational', 3077))
        }
        'defender_or_asr' {
            @(
                @('Microsoft-Windows-Windows Defender/Operational', 1121),
                @('Microsoft-Windows-Windows Defender/Operational', 1116)
            )
        }
        default { @() }
    }
    foreach ($candidate in @($candidates)) {
        try {
            $found = @(Microsoft.PowerShell.Diagnostics\Get-WinEvent `
                -FilterHashtable @{
                    LogName   = [string]$candidate[0]
                    Id        = [int]$candidate[1]
                    StartTime = [DateTime]::Now.AddMinutes(-2)
                } `
                -MaxEvents 1 `
                -ErrorAction Stop)
            if ($found.Count -gt 0) {
                return ('{0} {1}' -f $candidate[0], $candidate[1])
            }
        }
        catch {
        }
    }
    return ''
}

function Initialize-DefenseClawBootstrapNativePath {
    if ($null -ne $script:DefenseClawBootstrapPathProbe) {
        return $script:DefenseClawBootstrapPathProbe
    }
    # Add-Type is reached only after New-DefenseClawBootstrapEnvironment has
    # pinned every compiler/cache/home path to a capability-named protected
    # directory. The unpredictable namespace also prevents an ambient session
    # from preloading a class with the name trusted by this invocation.
    $nativeNamespace =
        'DefenseClaw.Windows.Bootstrap_' + [Guid]::NewGuid().ToString('N')
    # A compiler blocked by application control fails here; name the policy
    # from its numeric code so the verdict says what to allow.
    try {
        $compiledTypes = @(Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace $nativeNamespace
{
    public static class NativePath
    {
        private enum WTSConnectState
        {
            Active = 0,
            Connected = 1,
            ConnectQuery = 2,
            Shadow = 3,
            Disconnected = 4,
            Idle = 5,
            Listen = 6,
            Reset = 7,
            Down = 8,
            Init = 9
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WTSSessionInfo
        {
            public int SessionId;
            public IntPtr WindowStationName;
            public WTSConnectState State;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetDriveTypeW(string rootPathName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumeInformationW(
            string rootPathName,
            StringBuilder volumeName,
            int volumeNameSize,
            out uint volumeSerialNumber,
            out uint maximumComponentLength,
            out uint fileSystemFlags,
            StringBuilder fileSystemName,
            int fileSystemNameSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumeNameForVolumeMountPointW(
            string volumeMountPoint,
            StringBuilder volumeName,
            int bufferLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumePathNamesForVolumeNameW(
            string volumeName,
            [Out] char[] volumePathNames,
            uint bufferLength,
            out uint returnLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint QueryDosDeviceW(
            string deviceName,
            [Out] char[] targetPath,
            int maximumLength);

        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WTSEnumerateSessionsW(
            IntPtr server,
            int reserved,
            int version,
            out IntPtr sessions,
            out int count);

        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WTSQuerySessionInformationW(
            IntPtr server,
            int sessionId,
            int informationClass,
            out IntPtr buffer,
            out int bytesReturned);

        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr memory);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WTSQueryUserToken(int sessionId, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(
            IntPtr token,
            int tokenInformationClass,
            IntPtr tokenInformation,
            int tokenInformationLength,
            out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetLocalGroupGetMembers(
            string serverName,
            string localGroupName,
            int level,
            out IntPtr buffer,
            int preferredMaximumLength,
            out int entriesRead,
            out int totalEntries,
            ref IntPtr resumeHandle);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);

        // Direct members of the local group with the given (localized) name,
        // as SIDs. Level 0 returns only the member SID.
        public static string[] GetLocalGroupMemberSIDs(string groupName)
        {
            const int ERROR_MORE_DATA = 234;
            const int MAX_PREFERRED_LENGTH = -1;
            if (String.IsNullOrWhiteSpace(groupName))
                throw new ArgumentException("local group name is required", "groupName");
            List<string> members = new List<string>();
            IntPtr resume = IntPtr.Zero;
            while (true)
            {
                IntPtr buffer;
                int read;
                int total;
                int status = NetLocalGroupGetMembers(
                    null,
                    groupName,
                    0,
                    out buffer,
                    MAX_PREFERRED_LENGTH,
                    out read,
                    out total,
                    ref resume);
                try
                {
                    if (status != 0 && status != ERROR_MORE_DATA)
                        throw new Win32Exception(
                            status,
                            "NetLocalGroupGetMembers failed for " + groupName);
                    for (int index = 0; index < read; index++)
                    {
                        IntPtr sid = Marshal.ReadIntPtr(
                            buffer,
                            index * IntPtr.Size);
                        if (sid != IntPtr.Zero)
                            members.Add(new SecurityIdentifier(sid).Value);
                    }
                }
                finally
                {
                    if (buffer != IntPtr.Zero)
                        NetApiBufferFree(buffer);
                }
                if (status != ERROR_MORE_DATA)
                    break;
            }
            return members.ToArray();
        }

        private static string QueryDevice(string deviceName)
        {
            char[] target = new char[32768];
            uint length = QueryDosDeviceW(deviceName, target, target.Length);
            if (length == 0)
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "QueryDosDevice failed for " + deviceName);
            List<string> targets = ParseMultiString(
                target,
                checked((int)length),
                "QueryDosDevice " + deviceName);
            if (targets.Count != 1 ||
                String.IsNullOrEmpty(targets[0]) ||
                !targets[0].StartsWith(
                    @"\Device\",
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "QueryDosDevice returned a malformed or multi-target mapping for " +
                    deviceName);
            return targets[0];
        }

        private static List<string> ParseMultiString(
            char[] buffer,
            int length,
            string operation)
        {
            if (length <= 0 || length > buffer.Length)
                throw new InvalidOperationException(
                    operation + " returned an invalid length");
            List<string> values = new List<string>();
            int start = 0;
            bool terminated = false;
            for (int index = 0; index < length; index++)
            {
                if (buffer[index] != '\0')
                    continue;
                if (index == start)
                {
                    terminated = true;
                    break;
                }
                values.Add(new string(buffer, start, index - start));
                start = index + 1;
            }
            if (!terminated || values.Count == 0)
                throw new InvalidOperationException(
                    operation + " returned a malformed MULTI_SZ value");
            return values;
        }

        private static string QuerySessionText(
            int sessionId,
            int informationClass,
            string field)
        {
            IntPtr buffer = IntPtr.Zero;
            int bytesReturned = 0;
            try
            {
                if (!WTSQuerySessionInformationW(
                        IntPtr.Zero,
                        sessionId,
                        informationClass,
                        out buffer,
                        out bytesReturned))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "WTSQuerySessionInformation failed for session " +
                        sessionId + " " + field);
                if (buffer == IntPtr.Zero || bytesReturned <= 2)
                    return String.Empty;
                return Marshal.PtrToStringUni(buffer) ?? String.Empty;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    WTSFreeMemory(buffer);
            }
        }

        public static bool IsInteractiveUserSID(SecurityIdentifier sid)
        {
            if (sid == null)
                return false;
            string value = sid.Value;
            int componentCount = value.Split('-').Length;
            return (value.StartsWith(
                        "S-1-5-21-",
                        StringComparison.OrdinalIgnoreCase) &&
                    componentCount >= 8) ||
                (value.StartsWith(
                        "S-1-12-1-",
                        StringComparison.OrdinalIgnoreCase) &&
                    componentCount == 8);
        }

        public static string[] GetActiveSessionSIDs()
        {
            return GetActiveSessionSIDs(false);
        }

        // Session accounts (DOMAIN\user) whose name did not translate on the
        // last GetActiveSessionSIDs call: those the session token resolved,
        // and those neither resolved. The caller resolves the second set
        // locally or leaves those users to the Guardian.
        public static string[] LastTokenFallbackSessionAccounts = new string[0];
        public static string[] LastUnresolvedSessionAccounts = new string[0];
        // What was tried for each account in either set: its session, the
        // name lookup error and the session token result.
        public static Dictionary<string, string> LastSessionResolutionDetail =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // The name lookup asks LSA, which forwards a domain account to a
        // domain controller when its SID is not cached: on a domain laptop
        // off VPN or with a broken trust it fails. The session's own token
        // carries the SID with no lookup; reading it needs SeTcbPrivilege,
        // which Setup has when it runs as LocalSystem (the AVC custom
        // action). A session neither resolves is reported, never fatal.
        private static SecurityIdentifier ResolveSessionUserSID(
            int sessionId,
            string domain,
            string user,
            List<string> tokenFallbacks,
            List<string> unresolved,
            Dictionary<string, string> details)
        {
            string label = String.IsNullOrEmpty(domain) ? user : domain + "\\" + user;
            string lookupError;
            try
            {
                NTAccount account = String.IsNullOrEmpty(domain)
                    ? new NTAccount(user)
                    : new NTAccount(domain, user);
                return (SecurityIdentifier)account.Translate(
                    typeof(SecurityIdentifier));
            }
            catch (IdentityNotMappedException ex) { lookupError = ex.GetType().Name + ": " + ex.Message; }
            catch (SystemException ex) { lookupError = ex.GetType().Name + ": " + ex.Message; }
            string tokenResult;
            SecurityIdentifier fromToken = SessionTokenUserSID(sessionId, out tokenResult);
            details[label] = "session " + sessionId +
                "; name lookup failed (" + lookupError + ")" +
                "; session token: " + tokenResult;
            if (fromToken != null)
            {
                tokenFallbacks.Add(label);
                return fromToken;
            }
            unresolved.Add(label);
            return null;
        }

        private static string Win32ErrorText(string call)
        {
            int code = Marshal.GetLastWin32Error();
            return call + " failed (Win32 " + code + ": " + new Win32Exception(code).Message + ")";
        }

        private static SecurityIdentifier SessionTokenUserSID(int sessionId, out string result)
        {
            IntPtr token;
            if (!WTSQueryUserToken(sessionId, out token) || token == IntPtr.Zero)
            {
                result = Win32ErrorText("WTSQueryUserToken");
                return null;
            }
            IntPtr buffer = IntPtr.Zero;
            try
            {
                const int tokenUser = 1;
                int needed;
                GetTokenInformation(token, tokenUser, IntPtr.Zero, 0, out needed);
                if (needed <= 0 || needed > 4096)
                {
                    result = "GetTokenInformation reported a TokenUser size of " + needed + " bytes";
                    return null;
                }
                buffer = Marshal.AllocHGlobal(needed);
                if (!GetTokenInformation(token, tokenUser, buffer, needed, out needed))
                {
                    result = Win32ErrorText("GetTokenInformation");
                    return null;
                }
                IntPtr sidPointer = Marshal.ReadIntPtr(buffer);
                if (sidPointer == IntPtr.Zero)
                {
                    result = "the token has no user SID";
                    return null;
                }
                SecurityIdentifier sid = new SecurityIdentifier(sidPointer);
                result = "resolved " + sid.Value;
                return sid;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);
                CloseHandle(token);
            }
        }

        // includeEntra admits Microsoft Entra ID user SIDs (S-1-12-1-...)
        // for the standalone profile; the parameterless Secure Client form
        // keeps the historical S-1-5-21 filter exactly.
        public static string[] GetActiveSessionSIDs(bool includeEntra)
        {
            IntPtr sessions = IntPtr.Zero;
            int count = 0;
            if (!WTSEnumerateSessionsW(
                    IntPtr.Zero,
                    0,
                    1,
                    out sessions,
                    out count))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "WTSEnumerateSessions failed");
            try
            {
                if (count < 0 || count > 4096 ||
                    (count > 0 && sessions == IntPtr.Zero))
                    throw new InvalidOperationException(
                        "WTSEnumerateSessions returned an invalid session set");
                int size = Marshal.SizeOf(typeof(WTSSessionInfo));
                HashSet<string> active = new HashSet<string>(
                    StringComparer.OrdinalIgnoreCase);
                List<string> tokenFallbacks = new List<string>();
                List<string> unresolved = new List<string>();
                Dictionary<string, string> details = new Dictionary<string, string>(
                    StringComparer.OrdinalIgnoreCase);
                for (int index = 0; index < count; index++)
                {
                    IntPtr pointer = new IntPtr(
                        sessions.ToInt64() + checked(index * size));
                    WTSSessionInfo row = (WTSSessionInfo)Marshal.PtrToStructure(
                        pointer,
                        typeof(WTSSessionInfo));
                    if (row.State != WTSConnectState.Active)
                        continue;
                    // WTSUserName=5 and WTSDomainName=7.
                    string user = QuerySessionText(
                        row.SessionId,
                        5,
                        "user name").Trim();
                    if (String.IsNullOrEmpty(user))
                        throw new InvalidOperationException(
                            "WTS Active session " + row.SessionId +
                            " has no user name");
                    string domain = QuerySessionText(
                        row.SessionId,
                        7,
                        "domain name").Trim();
                    SecurityIdentifier sid = ResolveSessionUserSID(
                        row.SessionId,
                        domain,
                        user,
                        tokenFallbacks,
                        unresolved,
                        details);
                    if (sid != null && IsInteractiveUserSID(sid))
                        active.Add(sid.Value);
                }
                LastTokenFallbackSessionAccounts = tokenFallbacks.ToArray();
                LastSessionResolutionDetail = details;
                LastUnresolvedSessionAccounts = unresolved.ToArray();
                List<string> ordered = new List<string>(active);
                ordered.Sort(StringComparer.OrdinalIgnoreCase);
                return ordered.ToArray();
            }
            finally
            {
                if (sessions != IntPtr.Zero)
                    WTSFreeMemory(sessions);
            }
        }

        public static uint GetDriveType(string root)
        {
            return GetDriveTypeW(root);
        }

        public static string GetFileSystem(string root)
        {
            StringBuilder volume = new StringBuilder(261);
            StringBuilder fileSystem = new StringBuilder(261);
            uint serial;
            uint maximumComponentLength;
            uint flags;
            if (!GetVolumeInformationW(
                root,
                volume,
                volume.Capacity,
                out serial,
                out maximumComponentLength,
                out flags,
                fileSystem,
                fileSystem.Capacity))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetVolumeInformation failed for " + root);
            return fileSystem.ToString();
        }

        public static void AssertCanonicalDriveRoot(string root, string drive)
        {
            if (String.IsNullOrEmpty(root) ||
                root.Length != 3 ||
                !Char.IsLetter(root[0]) ||
                root[1] != ':' ||
                root[2] != '\\' ||
                !String.Equals(
                    drive,
                    root.Substring(0, 2),
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "bootstrap path root is not a canonical DOS drive root: " + root);

            StringBuilder volumeName = new StringBuilder(261);
            if (!GetVolumeNameForVolumeMountPointW(
                root,
                volumeName,
                volumeName.Capacity))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetVolumeNameForVolumeMountPoint failed for " + root);
            string volume = volumeName.ToString();
            if (!volume.StartsWith(
                    @"\\?\Volume{",
                    StringComparison.OrdinalIgnoreCase) ||
                !volume.EndsWith(@"}\", StringComparison.Ordinal) ||
                volume.Length <= 13)
                throw new InvalidOperationException(
                    "bootstrap path volume identity is not canonical: " + volume);
            Guid volumeGuid;
            string volumeGuidText =
                volume.Substring(11, volume.Length - 13);
            if (!Guid.TryParseExact(volumeGuidText, "D", out volumeGuid) ||
                !String.Equals(
                    volume,
                    @"\\?\Volume{" + volumeGuid.ToString("D") + @"}\",
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "bootstrap path volume GUID identity is malformed: " + volume);

            string volumeDeviceName =
                volume.Substring(4, volume.Length - 5);
            string driveTarget = QueryDevice(drive);
            string globalDriveTarget = QueryDevice(@"Global\" + drive);
            string volumeTarget = QueryDevice(volumeDeviceName);
            if (!String.Equals(
                    driveTarget,
                    globalDriveTarget,
                    StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(
                    driveTarget,
                    volumeTarget,
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "bootstrap DOS drive target differs from its global authoritative volume");

            char[] paths = new char[32768];
            uint required;
            if (!GetVolumePathNamesForVolumeNameW(
                volume,
                paths,
                (uint)paths.Length,
                out required))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetVolumePathNamesForVolumeName failed for " + volume);

            List<string> mountPaths = ParseMultiString(
                paths,
                checked((int)required),
                "GetVolumePathNamesForVolumeName " + volume);
            int rootMatches = 0;
            foreach (string path in mountPaths)
            {
                if (String.Equals(path, root, StringComparison.OrdinalIgnoreCase))
                    rootMatches++;
            }
            if (rootMatches != 1)
                throw new InvalidOperationException(
                    "bootstrap DOS drive root is not registered with Mount Manager");
        }
    }
}
"@ -Language CSharp -PassThru -ErrorAction Stop)
    }
    catch {
        $classified = Get-DefenseClawBootstrapAddTypeFailure -ErrorRecord $_
        if (-not [string]::IsNullOrWhiteSpace($classified)) {
            throw $classified
        }
        throw
    }
    $expectedTypeName = "$nativeNamespace.NativePath"
    $nativeType = @(
        $compiledTypes | Microsoft.PowerShell.Core\Where-Object {
            $_.FullName -ceq $expectedTypeName
        }
    )
    if ($nativeType.Count -ne 1) {
        throw "could not bind exact generated bootstrap native path type $expectedTypeName"
    }
    $script:DefenseClawBootstrapPathProbe = $nativeType[0]
    return $script:DefenseClawBootstrapPathProbe
}

function Assert-DefenseClawBootstrapUnsignedCertificationScope {
    param(
        [Parameter(Mandatory)][string]$LifecycleAction,
        [Parameter(Mandatory)][string]$RequestedInstallRoot,
        [Parameter(Mandatory)][string]$RequestedStateRoot,
        [Parameter(Mandatory)][string]$RequestedGatewayServiceName,
        [Parameter(Mandatory)][string]$RequestedGuardianServiceName,
        [string]$RequestedCertificationCodexHome
    )
    $prefix = '-AllowUnsigned is restricted to exact disposable DefenseClaw certification scope'
    if ($LifecycleAction -notin @(
        'Install',
        'Upgrade',
        'Repair',
        'Reconcile',
        'Recover',
        'Status',
        'Verify',
        'Uninstall'
    )) {
        throw "$prefix; action is outside the enterprise lifecycle"
    }
    if ($RequestedGatewayServiceName -cnotmatch '^DefenseClawCertGateway_([a-f0-9]{10})$') {
        throw "$prefix; gateway service name is outside the certification namespace"
    }
    $runID = [string]$Matches[1]
    $expectedGuardian = "DefenseClawCertGuardian_$runID"
    if ($RequestedGuardianServiceName -cne $expectedGuardian) {
        throw "$prefix; guardian service name must be exactly $expectedGuardian"
    }

    foreach ($entry in @(
        @('InstallRoot', $RequestedInstallRoot),
        @('StateRoot', $RequestedStateRoot),
        @('CertificationCodexHome', $RequestedCertificationCodexHome)
    )) {
        if ([string]::IsNullOrWhiteSpace([string]$entry[1]) -or
            ([string]$entry[1]).Contains('"') -or
            ([string]$entry[1]) -match '[\x00-\x1f]') {
            throw "$prefix; $($entry[0]) is empty or invalid"
        }
    }

    $install = [IO.Path]::GetFullPath($RequestedInstallRoot).TrimEnd('\')
    $state = [IO.Path]::GetFullPath($RequestedStateRoot).TrimEnd('\')
    $expectedInstall = [IO.Path]::Combine(
        [string]$bootstrapProfileRoots.CertificationInstallBase,
        $runID
    ).TrimEnd('\')
    $expectedState = [IO.Path]::Combine(
        [string]$bootstrapProfileRoots.CertificationStateBase,
        $runID
    ).TrimEnd('\')
    if (-not [string]::Equals(
        $install,
        $expectedInstall,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$prefix; InstallRoot must be exactly $expectedInstall"
    }
    if (-not [string]::Equals(
        $state,
        $expectedState,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$prefix; StateRoot must be exactly $expectedState"
    }

    $certificationHome = [IO.Path]::GetFullPath(
        $RequestedCertificationCodexHome
    ).TrimEnd('\')
    if (-not [IO.Path]::IsPathRooted($certificationHome) -or
        $certificationHome.StartsWith('\\') -or
        $certificationHome.StartsWith('//') -or
        $certificationHome.StartsWith('\\?\') -or
        $certificationHome.StartsWith('\\.\') -or
        ($certificationHome.Length -gt 2 -and
            $certificationHome.Substring(2).Contains(':')) -or
        [IO.Path]::GetFileName($certificationHome) -cne
            ".codex-defenseclaw-cert-$runID") {
        throw "$prefix; CertificationCodexHome must be the exact local run-scoped directory"
    }
    $certificationHomeExists = Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $certificationHome `
        -PathType Container
    $allowMissingCertificationHome = $LifecycleAction -in @(
        'Status',
        'Verify',
        'Recover'
    )
    if (-not $certificationHomeExists -and
        -not $allowMissingCertificationHome) {
        throw "$prefix; CertificationCodexHome must be an existing directory"
    }
    if ((Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $certificationHome) -and
        -not $certificationHomeExists) {
        throw "$prefix; CertificationCodexHome must be a directory when present"
    }

    $nativePathType = Initialize-DefenseClawBootstrapNativePath
    $driveRoot = [IO.Path]::GetPathRoot($certificationHome)
    $driveID = $driveRoot.TrimEnd('\')
    $driveType = $nativePathType::GetDriveType($driveRoot)
    $fileSystem = $nativePathType::GetFileSystem($driveRoot)
    $nativePathType::AssertCanonicalDriveRoot($driveRoot, $driveID)
    if ([int]$driveType -ne 3 -or
        -not [string]::Equals(
            $fileSystem,
            'NTFS',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "$prefix; CertificationCodexHome must be on local fixed NTFS without redirection"
    }
    $current = if ($certificationHomeExists) {
        $certificationHome
    }
    else {
        [IO.Path]::GetDirectoryName($certificationHome)
    }
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        $item = Microsoft.PowerShell.Management\Get-Item `
            -LiteralPath $current `
            -Force `
            -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$prefix; CertificationCodexHome path contains a reparse point: $current"
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrWhiteSpace($parent) -or
            $parent.Equals($current, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $current = $parent
    }
    # Recheck at the last use boundary so a per-logon DOS device cannot be
    # retargeted between the initial volume authorization and path traversal.
    $nativePathType::AssertCanonicalDriveRoot($driveRoot, $driveID)
}

function Assert-DefenseClawBootstrapLifecycleScope {
    param(
        [Parameter(Mandatory)][string]$LifecycleAction,
        [Parameter(Mandatory)][string]$RequestedInstallRoot,
        [Parameter(Mandatory)][string]$RequestedStateRoot,
        [Parameter(Mandatory)][string]$RequestedGatewayServiceName,
        [Parameter(Mandatory)][string]$RequestedGuardianServiceName,
        [bool]$AllowUnsignedLifecycle
    )
    $install = [IO.Path]::GetFullPath($RequestedInstallRoot).TrimEnd('\')
    $state = [IO.Path]::GetFullPath($RequestedStateRoot).TrimEnd('\')
    $certificationMatch = [Text.RegularExpressions.Regex]::Match(
        $RequestedGatewayServiceName,
        '^DefenseClawCertGateway_([a-f0-9]{10})$',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if ($certificationMatch.Success) {
        $runID = [string]$certificationMatch.Groups[1].Value
        $expectedGuardian = "DefenseClawCertGuardian_$runID"
        if ($RequestedGuardianServiceName -cne $expectedGuardian) {
            throw (
                'certification service names must use the same exact run ' +
                "identifier; guardian must be $expectedGuardian"
            )
        }
        $expectedInstall = [IO.Path]::Combine(
            [string]$bootstrapProfileRoots.CertificationInstallBase,
            $runID
        ).TrimEnd('\')
        $expectedState = [IO.Path]::Combine(
            [string]$bootstrapProfileRoots.CertificationStateBase,
            $runID
        ).TrimEnd('\')
        if (-not [string]::Equals(
                $install,
                $expectedInstall,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not [string]::Equals(
                $state,
                $expectedState,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw (
                'certification services require exact run-scoped managed ' +
                "roots: $expectedInstall ; $expectedState"
            )
        }
        if ($LifecycleAction -in @('Install', 'Upgrade', 'Repair') -and
            -not $AllowUnsignedLifecycle) {
            throw (
                'certification-scoped Install, Upgrade, or Repair requires ' +
                '-AllowUnsigned'
            )
        }
        return
    }
    if ($RequestedGuardianServiceName -cmatch
        '^DefenseClawCertGuardian_[a-f0-9]{10}$') {
        throw 'certification guardian service requires its exact certification gateway peer'
    }
    if ($RequestedGatewayServiceName -cne 'DefenseClawGateway' -or
        $RequestedGuardianServiceName -cne 'DefenseClawHookGuardian') {
        throw (
            'non-certification enterprise lifecycle requires exact ' +
            'production service names: DefenseClawGateway ; ' +
            'DefenseClawHookGuardian'
        )
    }
    $expectedInstall = ([string]$bootstrapProfileRoots.InstallRoot).TrimEnd('\')
    $expectedState = ([string]$bootstrapProfileRoots.StateRoot).TrimEnd('\')
    if (-not [string]::Equals(
            $install,
            $expectedInstall,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            $state,
            $expectedState,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw (
            'non-certification enterprise lifecycle requires exact ' +
            "production roots: $expectedInstall ; $expectedState"
        )
    }
}

function ConvertTo-DefenseClawBootstrapSID {
    param([Parameter(Mandatory)]$Identity)
    if ($Identity -is [Security.Principal.SecurityIdentifier]) {
        return $Identity.Value
    }
    $text = [string]$Identity
    if ($text.StartsWith('S-', [StringComparison]::OrdinalIgnoreCase)) {
        return [Security.Principal.SecurityIdentifier]::new($text).Value
    }
    try {
        return [Security.Principal.NTAccount]::new($text).Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    }
    catch {
        return "UNRESOLVED:$text"
    }
}

$script:DefenseClawBootstrapCoreTrustedSIDs = @(
    'S-1-5-18',
    'S-1-5-32-544',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
)

# An administrator principal outside SYSTEM, Administrators and
# TrustedInstaller: the built-in Administrator account, Domain Admins,
# Enterprise Admins, or a direct member of local Administrators. It can already
# do anything an owner can, so owner drift to one is accepted and logged, the
# same rule the module and the Go components apply.
function Test-DefenseClawBootstrapAdminEquivalentSID {
    param([AllowEmptyString()][string]$SID)
    if ([string]::IsNullOrWhiteSpace($SID)) {
        return $false
    }
    if ($SID -cmatch '^S-1-5-21-[0-9-]+-(500|512|519)$') {
        return $true
    }
    if ($null -eq $script:DefenseClawBootstrapAdminEquivalentMembers) {
        $members = @()
        try {
            $groupName = [Security.Principal.SecurityIdentifier]::new(
                'S-1-5-32-544'
            ).Translate([Security.Principal.NTAccount]).Value
            $groupName = $groupName.Substring($groupName.LastIndexOf('\') + 1)
            $nativePathType = Initialize-DefenseClawBootstrapNativePath
            $members = @($nativePathType::GetLocalGroupMemberSIDs($groupName))
        }
        catch {
            $members = @()
        }
        $script:DefenseClawBootstrapAdminEquivalentMembers = [string[]]$members
    }
    return ($SID -in $script:DefenseClawBootstrapAdminEquivalentMembers)
}

# One trust rule for every path the bootstrap must trust before the module is
# imported. The leaf is strict: a null DACL, an untrusted owner or an untrusted
# principal with the leaf's unsafe rights is fatal. Ancestors belong to the
# operating system or the platform installer; their owner and ACL verdicts are
# advisory, accepted and logged. Structure (reparse points, object type) is
# checked by the callers and is always fatal. SIDs are read directly, so no
# account name round-trip can turn an unresolvable principal into a verdict.
function Assert-DefenseClawBootstrapTrustedPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][bool]$Leaf,
        [switch]$LeafWriteLike
    )
    $acl = Microsoft.PowerShell.Security\Get-Acl `
        -LiteralPath $Path `
        -ErrorAction Stop
    $findings = [Collections.Generic.List[string]]::new()
    $accessSDDL = $acl.GetSecurityDescriptorSddlForm(
        [Security.AccessControl.AccessControlSections]::Access
    )
    if ([string]::IsNullOrWhiteSpace($accessSDDL) -or
        -not $accessSDDL.StartsWith(
            'D:',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        $findings.Add("$Subject has an absent or null DACL: $Path")
    }
    $ownerSID = ''
    try {
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier])
        if ($null -ne $owner) {
            $ownerSID = [string]$owner.Value
        }
    }
    catch {
        $ownerSID = ''
    }
    if ($ownerSID -notin $script:DefenseClawBootstrapCoreTrustedSIDs) {
        if (Test-DefenseClawBootstrapAdminEquivalentSID -SID $ownerSID) {
            Add-DefenseClawBootstrapResilienceEvent `
                -Marker defenseclaw_accept `
                -Fields @{
                    path   = $Path
                    reason = "owner $ownerSID is an administrator principal"
                }
        }
        else {
            $findings.Add("$Subject has untrusted owner $ownerSID`: $Path")
        }
    }
    $strictWriteLike = $Leaf -and $LeafWriteLike
    foreach ($rule in @($acl.GetAccessRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]
        ))) {
        if ($rule.AccessControlType -ne
            [Security.AccessControl.AccessControlType]::Allow -or
            (([int]$rule.PropagationFlags -band
                [int][Security.AccessControl.PropagationFlags]::InheritOnly) -ne
                0)) {
            continue
        }
        $sid = [string]$rule.IdentityReference.Value
        if ($sid -in $script:DefenseClawBootstrapCoreTrustedSIDs) {
            continue
        }
        $unsafe = if ($strictWriteLike) {
            Test-DefenseClawBootstrapWriteLikeRights -Rights $rule.FileSystemRights
        }
        else {
            Test-DefenseClawBootstrapReplacementRights -Rights $rule.FileSystemRights
        }
        if ($unsafe) {
            $kind = if ($strictWriteLike) { 'write-like' } else { 'replacement' }
            $findings.Add(
                "untrusted principal $sid has $kind access to $Subject`: $Path"
            )
        }
    }
    if ($findings.Count -eq 0) {
        return
    }
    if ($Leaf) {
        throw $findings[0]
    }
    foreach ($finding in $findings) {
        Add-DefenseClawBootstrapResilienceEvent `
            -Marker defenseclaw_accept `
            -Fields @{
                path   = $Path
                reason = "ancestor drift is advisory: $finding"
            }
    }
}

function Test-DefenseClawBootstrapReplacementRights {
    param([Parameter(Mandatory)][Security.AccessControl.FileSystemRights]$Rights)
    $replacement = [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles `
        -bor [Security.AccessControl.FileSystemRights]::Delete `
        -bor [Security.AccessControl.FileSystemRights]::ChangePermissions `
        -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    $value = [uint64]([int64]$Rights -band 0xffffffffL)
    return (($Rights -band $replacement) -ne 0 -or
        ($value -band [uint64]0x50000000) -ne 0)
}

function Test-DefenseClawBootstrapWriteLikeRights {
    param([Parameter(Mandatory)][Security.AccessControl.FileSystemRights]$Rights)
    $writeLike = [Security.AccessControl.FileSystemRights]::WriteData `
        -bor [Security.AccessControl.FileSystemRights]::AppendData `
        -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes `
        -bor [Security.AccessControl.FileSystemRights]::WriteAttributes `
        -bor [Security.AccessControl.FileSystemRights]::Delete `
        -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles `
        -bor [Security.AccessControl.FileSystemRights]::ChangePermissions `
        -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    $value = [uint64]([int64]$Rights -band 0xffffffffL)
    return (($Rights -band $writeLike) -ne 0 -or
        ($value -band [uint64]0x50000000) -ne 0)
}

$script:DefenseClawBootstrapEnvironmentNames = @(
    'TEMP',
    'TMP',
    'TMPDIR',
    'LOCALAPPDATA',
    'APPDATA',
    'USERPROFILE',
    'HOME',
    'HOMEDRIVE',
    'HOMEPATH',
    'XDG_CACHE_HOME',
    'XDG_CONFIG_HOME',
    'XDG_DATA_HOME',
    'DOTNET_CLI_HOME',
    'NUGET_PACKAGES',
    'PSModuleAnalysisCachePath'
)

function Get-DefenseClawBootstrapDirectorySecurity {
    param(
        [Parameter(Mandatory)][IO.DirectoryInfo]$Directory,
        [Parameter(Mandatory)]
        [Security.AccessControl.AccessControlSections]$Sections
    )
    if ($PSVersionTable.PSEdition -eq 'Core') {
        return [IO.FileSystemAclExtensions]::GetAccessControl(
            $Directory,
            $Sections
        )
    }
    return $Directory.GetAccessControl($Sections)
}

function Get-DefenseClawBootstrapFileSecurity {
    param(
        [Parameter(Mandatory)][IO.FileInfo]$File,
        [Parameter(Mandatory)]
        [Security.AccessControl.AccessControlSections]$Sections
    )
    if ($PSVersionTable.PSEdition -eq 'Core') {
        return [IO.FileSystemAclExtensions]::GetAccessControl($File, $Sections)
    }
    return $File.GetAccessControl($Sections)
}

function New-DefenseClawBootstrapDirectorySecurity {
    param(
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier]$CurrentSID,
        [Parameter(Mandatory)][bool]$Elevated
    )
    $systemSID = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSID =
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    if ($Elevated) {
        $security.SetOwner($administratorsSID)
        $security.SetGroup($administratorsSID)
    }
    else {
        $security.SetOwner($CurrentSID)
        $security.SetGroup($CurrentSID)
    }
    $accessSIDs = [Collections.Generic.List[
        Security.Principal.SecurityIdentifier
    ]]::new()
    $accessSIDs.Add($systemSID)
    $accessSIDs.Add($administratorsSID)
    if (-not $Elevated) {
        $accessSIDs.Add($CurrentSID)
    }
    foreach ($sid in $accessSIDs) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            (
                [Security.AccessControl.InheritanceFlags]::ContainerInherit `
                    -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit
            ),
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
    }
    return $security
}

function Get-DefenseClawBootstrapSecuritySDDL {
    param(
        [Parameter(Mandatory)]
        [Security.AccessControl.FileSystemSecurity]$Security
    )
    $sections = [Security.AccessControl.AccessControlSections]::Owner `
        -bor [Security.AccessControl.AccessControlSections]::Group `
        -bor [Security.AccessControl.AccessControlSections]::Access
    return $Security.GetSecurityDescriptorSddlForm($sections)
}

function Assert-DefenseClawBootstrapExternalParentTrust {
    # Called only when the caller passed a non-empty -BootstrapParent. The
    # outer signed DefenseClawSetup EXE hands its own protected
    # %ProgramData%\DefenseClaw-Enterprise-Setup-<hex>\scratch path here
    # (SDDL O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)); this validator
    # rejects a parent that grants an untrusted principal replacement rights
    # or has an untrusted owner, so an attacker cannot redirect the bootstrap
    # into a directory they can retake. Reparse points anywhere in the chain
    # are fatal; owner and ACL drift on the ancestors is accepted and logged,
    # the same rule the module's Assert-DefenseClawTrustedAncestor applies.
    param([Parameter(Mandatory)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path.Contains('"') -or
        $Path -match '[\x00-\x1f]') {
        throw '-BootstrapParent is empty or contains an invalid character'
    }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not [IO.Path]::IsPathRooted($full) -or
        $full.StartsWith('\\') -or
        $full.StartsWith('//') -or
        $full.StartsWith('\\?\') -or
        $full.StartsWith('\\.\') -or
        ($full.Length -gt 2 -and $full.Substring(2).Contains(':'))) {
        throw "-BootstrapParent must be an absolute local Win32 drive path: $full"
    }
    if (-not [IO.Directory]::Exists($full)) {
        throw "-BootstrapParent directory does not exist: $full"
    }
    $attributes = [IO.File]::GetAttributes($full)
    if (($attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
        ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "-BootstrapParent must be a real non-reparse directory: $full"
    }

    $nativePathType = Initialize-DefenseClawBootstrapNativePath
    $driveRoot = [IO.Path]::GetPathRoot($full)
    $driveID = $driveRoot.TrimEnd('\')
    $driveType = $nativePathType::GetDriveType($driveRoot)
    $fileSystem = $nativePathType::GetFileSystem($driveRoot)
    $nativePathType::AssertCanonicalDriveRoot($driveRoot, $driveID)
    if ([int]$driveType -ne 3 -or
        -not [string]::Equals(
            $fileSystem,
            'NTFS',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "-BootstrapParent must be on a local fixed NTFS volume: $full"
    }

    $chain = [Collections.Generic.List[string]]::new()
    $current = $full
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        $chain.Add($current)
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrWhiteSpace($parent) -or
            [string]::Equals(
                $parent,
                $current,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            break
        }
        $current = $parent
    }
    # Structure first across the whole chain, so a junction fails as such even
    # when a higher ancestor carries advisory drift.
    for ($index = $chain.Count - 1; $index -ge 0; $index--) {
        $candidate = $chain[$index]
        $item = Microsoft.PowerShell.Management\Get-Item `
            -LiteralPath $candidate `
            -Force `
            -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "-BootstrapParent path contains a reparse point: $candidate"
        }
        if (-not $item.PSIsContainer) {
            throw "-BootstrapParent path ancestor is not a directory: $candidate"
        }
    }
    # The supplied parent itself is strict: nobody else may delete, rename or
    # re-ACL the capability directory created inside it. Its ancestors are the
    # operating system's and are advisory.
    for ($index = $chain.Count - 1; $index -ge 0; $index--) {
        Assert-DefenseClawBootstrapTrustedPath `
            -Path $chain[$index] `
            -Subject '-BootstrapParent path' `
            -Leaf ($index -eq 0)
    }
    $nativePathType::AssertCanonicalDriveRoot($driveRoot, $driveID)
    return $full
}

function Set-DefenseClawBootstrapDirectorySecurity {
    param(
        [Parameter(Mandatory)][IO.DirectoryInfo]$Directory,
        [Parameter(Mandatory)]
        [Security.AccessControl.DirectorySecurity]$Security
    )
    if ($PSVersionTable.PSEdition -eq 'Core') {
        [IO.FileSystemAclExtensions]::SetAccessControl($Directory, $Security)
        return
    }
    $Directory.SetAccessControl($Security)
}

# Compares a one-shot bootstrap directory with the descriptor it was created
# with. Boundary is fatal, Repair is fixed by one re-stamp, Accept is logged.
function Get-DefenseClawBootstrapOneShotRootDrift {
    param(
        [Parameter(Mandatory)]
        [Security.AccessControl.FileSystemSecurity]$Actual,
        [Parameter(Mandatory)]
        [Security.AccessControl.FileSystemSecurity]$Expected
    )
    $repair = [Collections.Generic.List[string]]::new()
    $accept = [Collections.Generic.List[string]]::new()
    $boundary = ''
    $expectedOwner = [string]$Expected.GetOwner(
        [Security.Principal.SecurityIdentifier]
    ).Value
    $allowedOwners = @('S-1-5-18', 'S-1-5-32-544', $expectedOwner)
    $expectedAccess = @(
        @($Expected.GetAccessRules(
                $true,
                $true,
                [Security.Principal.SecurityIdentifier]
            )) |
            Microsoft.PowerShell.Core\ForEach-Object {
                [string]$_.IdentityReference.Value
            }
    )
    $ownerSID = ''
    try {
        $owner = $Actual.GetOwner([Security.Principal.SecurityIdentifier])
        if ($null -ne $owner) {
            $ownerSID = [string]$owner.Value
        }
    }
    catch {
        $ownerSID = ''
    }
    if ($ownerSID -notin $allowedOwners) {
        $boundary = "untrusted owner $ownerSID"
    }
    elseif ($ownerSID -cne $expectedOwner) {
        $accept.Add("owner is $ownerSID instead of $expectedOwner")
    }
    $accessSDDL = $Actual.GetSecurityDescriptorSddlForm(
        [Security.AccessControl.AccessControlSections]::Access
    )
    if ([string]::IsNullOrWhiteSpace($accessSDDL) -or
        -not $accessSDDL.StartsWith(
            'D:',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        $repair.Add('the DACL is absent or null')
    }
    if (-not $Actual.AreAccessRulesProtected) {
        $repair.Add('the DACL is not protected from inheritance')
    }
    $fullControl = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($rule in @($Actual.GetAccessRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]
        ))) {
        $sid = [string]$rule.IdentityReference.Value
        if ($rule.AccessControlType -ne
            [Security.AccessControl.AccessControlType]::Allow) {
            $accept.Add("extra deny entry for $sid")
            continue
        }
        if ($sid -in $expectedAccess) {
            if ((([int64]$rule.FileSystemRights -band 0x1F01FF) -eq 0x1F01FF) -and
                -not $rule.IsInherited) {
                [void]$fullControl.Add($sid)
            }
            continue
        }
        if (Test-DefenseClawBootstrapWriteLikeRights -Rights $rule.FileSystemRights) {
            $repair.Add("untrusted principal $sid has write-like access")
        }
        else {
            $accept.Add("extra read entry for $sid")
        }
    }
    foreach ($sid in $expectedAccess) {
        if (-not $fullControl.Contains($sid)) {
            $repair.Add("expected principal $sid lacks full control")
        }
    }
    return [pscustomobject]@{
        Boundary = $boundary
        Repair = @($repair.ToArray())
        Accept = @($accept.ToArray())
    }
}

function Assert-DefenseClawBootstrapOneShotRoot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]
        [Security.AccessControl.DirectorySecurity]$ExpectedSecurity,
        [Parameter(Mandatory)][string]$ExpectedParent,
        [switch]$RequireEmpty
    )
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $expectedParentFull =
        [IO.Path]::GetFullPath($ExpectedParent).TrimEnd('\')
    if (-not [string]::Equals(
            [IO.Path]::GetDirectoryName($full),
            $expectedParentFull,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [IO.Path]::GetFileName($full) -cnotmatch
            '^DefenseClaw-Bootstrap-[a-f0-9]{32}$') {
        throw "bootstrap environment is outside its exact protected parent scope ($expectedParentFull): $full"
    }
    if (-not [IO.Directory]::Exists($full)) {
        throw "bootstrap environment directory is missing: $full"
    }
    $attributes = [IO.File]::GetAttributes($full)
    if (($attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
        ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "bootstrap environment is not a regular non-reparse directory: $full"
    }
    $sections = [Security.AccessControl.AccessControlSections]::Owner `
        -bor [Security.AccessControl.AccessControlSections]::Group `
        -bor [Security.AccessControl.AccessControlSections]::Access
    $expectedSDDL = Get-DefenseClawBootstrapSecuritySDDL `
        -Security $ExpectedSecurity
    # Judged by meaning, not by exact SDDL: a protected DACL, an allowed owner
    # and no writer outside the expected principals. Extra read or deny
    # entries (an EDR or a backup agent stamping its own ACE) are accepted and
    # logged. An unprotected DACL, a foreign writer or a missing expected entry
    # gets one re-stamp and a re-check. A foreign owner is never re-stamped:
    # it means someone else created this capability directory.
    for ($pass = 0; $pass -lt 2; $pass++) {
        $actual = Get-DefenseClawBootstrapDirectorySecurity `
            -Directory ([IO.DirectoryInfo]::new($full)) `
            -Sections $sections
        $drift = Get-DefenseClawBootstrapOneShotRootDrift `
            -Actual $actual `
            -Expected $ExpectedSecurity
        if (-not [string]::IsNullOrEmpty($drift.Boundary)) {
            throw (
                'bootstrap environment security descriptor mismatch: ' +
                "$full; $($drift.Boundary); got " +
                (Get-DefenseClawBootstrapSecuritySDDL -Security $actual) +
                "; expected $expectedSDDL"
            )
        }
        if ($drift.Repair.Count -eq 0) {
            foreach ($reason in $drift.Accept) {
                Add-DefenseClawBootstrapResilienceEvent `
                    -Marker defenseclaw_accept `
                    -Fields @{ path = $full; reason = $reason }
            }
            break
        }
        if ($pass -eq 1) {
            throw (
                'bootstrap environment security descriptor mismatch: ' +
                "$full; $($drift.Repair[0]) after re-stamp; got " +
                (Get-DefenseClawBootstrapSecuritySDDL -Security $actual) +
                "; expected $expectedSDDL"
            )
        }
        Set-DefenseClawBootstrapDirectorySecurity `
            -Directory ([IO.DirectoryInfo]::new($full)) `
            -Security $ExpectedSecurity
        Add-DefenseClawBootstrapResilienceEvent `
            -Marker defenseclaw_repair `
            -Fields @{ path = $full; reason = $drift.Repair[0] }
    }
    if ($RequireEmpty) {
        $enumerator = [IO.Directory]::EnumerateFileSystemEntries(
            $full
        ).GetEnumerator()
        try {
            if ($enumerator.MoveNext()) {
                throw "new bootstrap environment was not empty: $full"
            }
        }
        finally {
            $enumerator.Dispose()
        }
    }
    return $full
}

# A file the installer renders inherits the bootstrap directory's DACL but
# takes the creator's default owner, which a "created by Administrators group
# members" policy makes the administrator's own account. The module trusts
# only SYSTEM, Administrators or TrustedInstaller owners on policy inputs, so
# an elevated installer names Administrators explicitly.
function Set-DefenseClawBootstrapRenderedFileOwner {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Context
    )
    if (-not [bool]$Context.Elevated) {
        return
    }
    $file = [IO.FileInfo]::new($Path)
    $security = Get-DefenseClawBootstrapFileSecurity `
        -File $file `
        -Sections ([Security.AccessControl.AccessControlSections]::Owner)
    $administrators =
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $owner = $security.GetOwner([Security.Principal.SecurityIdentifier])
    if ($null -ne $owner -and [string]$owner.Value -ceq $administrators.Value) {
        return
    }
    $security.SetOwner($administrators)
    if ($PSVersionTable.PSEdition -eq 'Core') {
        [IO.FileSystemAclExtensions]::SetAccessControl($file, $security)
    }
    else {
        $file.SetAccessControl($security)
    }
}

function Test-DefenseClawBootstrapPathExists {
    param([Parameter(Mandatory)][string]$Path)
    try {
        [void][IO.File]::GetAttributes($Path)
        return $true
    }
    catch {
        # Windows PowerShell 5.1 wraps failures from static .NET method calls
        # in MethodInvocationException. Treat only a missing path anywhere in
        # that inner-exception chain as absent; every other error remains a
        # fail-closed cleanup failure.
        if (Test-DefenseClawBootstrapMissingPathError -Exception $_.Exception) {
            return $false
        }
        throw
    }
}

function Assert-DefenseClawBootstrapCleanupEntry {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string[]]$AllowedAccessSIDs,
        [Parameter(Mandatory)][string[]]$AllowedOwnerSIDs,
        [Parameter(Mandatory)][bool]$Directory
    )
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if (-not [string]::Equals(
            $full,
            $rootFull,
            [StringComparison]::OrdinalIgnoreCase
        ) -and
        -not $full.StartsWith(
            $rootFull + '\',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "refusing bootstrap cleanup outside exact capability root: $full"
    }
    try {
        $attributes = [IO.File]::GetAttributes($full)
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "refusing bootstrap cleanup through a reparse point: $full"
        }
        $isDirectory =
            ($attributes -band [IO.FileAttributes]::Directory) -ne 0
        if ($isDirectory -ne $Directory) {
            throw "bootstrap cleanup object type changed: $full"
        }
        $sections = [Security.AccessControl.AccessControlSections]::Owner `
            -bor [Security.AccessControl.AccessControlSections]::Access
        $security = if ($Directory) {
            Get-DefenseClawBootstrapDirectorySecurity `
                -Directory ([IO.DirectoryInfo]::new($full)) `
                -Sections $sections
        }
        else {
            Get-DefenseClawBootstrapFileSecurity `
                -File ([IO.FileInfo]::new($full)) `
                -Sections $sections
        }
        $accessSDDL = $security.GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::Access
        )
        if ([string]::IsNullOrWhiteSpace($accessSDDL) -or
            -not $accessSDDL.StartsWith(
                'D:',
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "refusing bootstrap cleanup of an object with a null DACL: $full"
        }
        $ownerSID = $security.GetOwner(
            [Security.Principal.SecurityIdentifier]
        ).Value
        if ($ownerSID -notin $AllowedOwnerSIDs) {
            throw "refusing bootstrap cleanup of untrusted owner $ownerSID`: $full"
        }
        $rules = $security.GetAccessRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]
        )
        foreach ($rule in $rules) {
            if ($rule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow) {
                continue
            }
            $sid = ConvertTo-DefenseClawBootstrapSID `
                -Identity $rule.IdentityReference
            if ($sid -notin $AllowedAccessSIDs) {
                throw "refusing bootstrap cleanup of untrusted access by $sid`: $full"
            }
        }
        return $full
    }
    catch {
        # Compiler/toolchain scratch entries may retire themselves between the
        # directory enumeration and this authenticated inspection. Absence is
        # already the desired cleanup state; every other error still aborts.
        if (Test-DefenseClawBootstrapMissingPathError -Exception $_.Exception) {
            return $null
        }
        if (Test-DefenseClawBootstrapRetiredCompilerScratch `
                -Path $full `
                -Root $rootFull `
                -Exception $_.Exception) {
            return $null
        }
        throw
    }
}

function Test-DefenseClawBootstrapMissingPathError {
    # A .NET method failure reaches PowerShell wrapped in a
    # MethodInvocationException, so match on the inner chain, not the outer type.
    param([Parameter(Mandatory)]$Exception)
    $current = $Exception
    while ($null -ne $current) {
        if ($current -is [IO.FileNotFoundException] -or
            $current -is [IO.DirectoryNotFoundException]) {
            return $true
        }
        $current = $current.InnerException
    }
    return $false
}

function Test-DefenseClawBootstrapAccessDeniedError {
    # A .NET method failure reaches PowerShell wrapped in a
    # MethodInvocationException, so match on the inner chain, not the outer type.
    param([Parameter(Mandatory)]$Exception)
    $current = $Exception
    while ($null -ne $current) {
        if ($current -is [UnauthorizedAccessException]) {
            return $true
        }
        $current = $current.InnerException
    }
    return $false
}

function Complete-DefenseClawBootstrapCompilerScratch {
    # Windows PowerShell 5.1 Add-Type compiles through CodeDom into a randomly
    # named scratch folder under TEMP, which is pinned to the one-shot root,
    # and retires that folder only from a finalizer. A finalizer that retired
    # the folder in the middle of the exact cleanup walk failed the cleanup
    # with Access denied on that folder (Windows Native CI, Python shard 8,
    # 5.1 race worker). A collection queues those finalizers now. It never
    # waits for them: GC.WaitForPendingFinalizers can block for good in
    # PowerShell when a pending finalizer needs the pipeline thread.
    [GC]::Collect()
}

function Test-DefenseClawBootstrapRetiredCompilerScratch {
    # True only when an entry below the root that answered Access denied is
    # gone within a bounded wait (it was the compiler scratch retiring
    # through its finalizer). An entry that is still there when the wait ends
    # keeps the fail-closed refusal of the caller.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)]$Exception
    )
    if ([string]::Equals(
            [IO.Path]::GetFullPath($Path).TrimEnd('\'),
            [IO.Path]::GetFullPath($Root).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not (Test-DefenseClawBootstrapAccessDeniedError -Exception $Exception)) {
        return $false
    }
    $wait = [Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        Complete-DefenseClawBootstrapCompilerScratch
        try {
            [void][IO.File]::GetAttributes($Path)
        }
        catch {
            if (Test-DefenseClawBootstrapMissingPathError -Exception $_.Exception) {
                return $true
            }
            if (-not (Test-DefenseClawBootstrapAccessDeniedError -Exception $_.Exception)) {
                return $false
            }
        }
        if ($wait.ElapsedMilliseconds -ge 3000) {
            return $false
        }
        [Threading.Thread]::Sleep(50)
    }
}

function Get-DefenseClawBootstrapEntryAttributes {
    # Returns $null when the entry is already gone. TEMP is redirected into the
    # bootstrap tree, so entries can vanish between enumeration and inspection.
    param([Parameter(Mandatory)][string]$Path)
    try {
        return [IO.File]::GetAttributes($Path)
    }
    catch {
        if (Test-DefenseClawBootstrapMissingPathError -Exception $_.Exception) {
            return $null
        }
        throw
    }
}

function Remove-DefenseClawBootstrapEnvironment {
    param([Parameter(Mandatory)]$Context)
    $root = Assert-DefenseClawBootstrapOneShotRoot `
        -Path ([string]$Context.Path) `
        -ExpectedSecurity $Context.Security `
        -ExpectedParent ([string]$Context.BootstrapParent)
    Complete-DefenseClawBootstrapCompilerScratch
    $directories = [Collections.Generic.List[string]]::new()
    $files = [Collections.Generic.List[string]]::new()
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        $validatedDirectory = Assert-DefenseClawBootstrapCleanupEntry `
            -Path $directory `
            -Root $root `
            -AllowedAccessSIDs $Context.AllowedAccessSIDs `
            -AllowedOwnerSIDs $Context.AllowedOwnerSIDs `
            -Directory $true
        if ($null -eq $validatedDirectory) {
            continue
        }
        $directories.Add($directory)
        $enumerator = $null
        try {
            $enumerator = [IO.Directory]::EnumerateFileSystemEntries(
                $directory
            ).GetEnumerator()
            while ($enumerator.MoveNext()) {
                $entry = [IO.Path]::GetFullPath([string]$enumerator.Current)
                $attributes = Get-DefenseClawBootstrapEntryAttributes -Path $entry
                if ($null -eq $attributes) {
                    continue
                }
                if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne
                    0) {
                    throw "refusing bootstrap cleanup through a reparse point: $entry"
                }
                if (($attributes -band [IO.FileAttributes]::Directory) -ne
                    0) {
                    $pending.Push($entry)
                }
                else {
                    $validatedEntry = Assert-DefenseClawBootstrapCleanupEntry `
                        -Path $entry `
                        -Root $root `
                        -AllowedAccessSIDs $Context.AllowedAccessSIDs `
                        -AllowedOwnerSIDs $Context.AllowedOwnerSIDs `
                        -Directory $false
                    if ($null -eq $validatedEntry) {
                        continue
                    }
                    $files.Add($entry)
                }
            }
        }
        catch {
            if (-not (Test-DefenseClawBootstrapMissingPathError `
                    -Exception $_.Exception) -and
                -not (Test-DefenseClawBootstrapRetiredCompilerScratch `
                    -Path $directory `
                    -Root $root `
                    -Exception $_.Exception)) {
                throw
            }
        }
        finally {
            if ($null -ne $enumerator) {
                $enumerator.Dispose()
            }
        }
    }
    foreach ($file in $files) {
        [IO.File]::Delete($file)
    }
    $orderedDirectories = @(
        $directories | Microsoft.PowerShell.Utility\Sort-Object {
            $_.Length
        } -Descending
    )
    foreach ($directory in $orderedDirectories) {
        try {
            [IO.Directory]::Delete($directory, $false)
        }
        catch {
            if (-not (Test-DefenseClawBootstrapMissingPathError -Exception $_.Exception)) {
                throw
            }
        }
    }
    if (Test-DefenseClawBootstrapPathExists -Path $root) {
        throw "bootstrap environment remains after exact cleanup: $root"
    }
}

function Restore-DefenseClawBootstrapEnvironment {
    param([Parameter(Mandatory)]$Context)
    foreach ($name in $script:DefenseClawBootstrapEnvironmentNames) {
        [Environment]::SetEnvironmentVariable(
            $name,
            $Context.OriginalEnvironment[$name],
            'Process'
        )
    }
}

function New-DefenseClawBootstrapEnvironment {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity.User) {
        throw 'could not resolve the current Windows identity for bootstrap isolation'
    }
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $elevated = $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    $security = New-DefenseClawBootstrapDirectorySecurity `
        -CurrentSID $identity.User `
        -Elevated $elevated
    $allowedAccessSIDs = [Collections.Generic.List[string]]::new()
    $allowedAccessSIDs.Add('S-1-5-18')
    $allowedAccessSIDs.Add('S-1-5-32-544')
    if (-not $elevated) {
        $allowedAccessSIDs.Add($identity.User.Value)
    }
    $allowedOwnerSIDs = [Collections.Generic.List[string]]::new()
    $allowedOwnerSIDs.Add('S-1-5-18')
    $allowedOwnerSIDs.Add('S-1-5-32-544')
    $allowedOwnerSIDs.Add($identity.User.Value)

    # Resolve the protected bootstrap parent. When the outer signed
    # DefenseClawSetup EXE passes -BootstrapParent (a protected
    # %ProgramData%\DefenseClaw-Enterprise-Setup-<hex>\scratch directory it
    # created and locked down to SYSTEM+Administrators only), route the
    # bootstrap into it. Falling back to C:\Windows\Temp is retained for
    # direct-caller compatibility on stock Windows, but on Azure-AD-joined
    # hosts C:\Windows\Temp carries an Allow ACE for the interactive AAD
    # principal with replacement rights, so the trusted-ancestor walk on
    # the rendered YAML content fails later; direct callers on those hosts
    # MUST pass -BootstrapParent.
    if (-not [string]::IsNullOrWhiteSpace($BootstrapParent)) {
        $resolvedBootstrapParent = Assert-DefenseClawBootstrapExternalParentTrust `
            -Path $BootstrapParent
    }
    else {
        $resolvedBootstrapParent = [IO.Path]::GetFullPath(
            [IO.Path]::Combine($trustedWindows, 'Temp')
        ).TrimEnd('\')
    }
    foreach ($trustedDirectory in @($trustedWindows, $resolvedBootstrapParent)) {
        if (-not [IO.Directory]::Exists($trustedDirectory)) {
            throw "trusted bootstrap parent directory is missing: $trustedDirectory"
        }
        $attributes = [IO.File]::GetAttributes($trustedDirectory)
        if (($attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
            ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "trusted bootstrap parent is not a regular directory: $trustedDirectory"
        }
    }

    $path = $null
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        for ($attempt = 0; $attempt -lt 8; $attempt++) {
            $bytes = [byte[]]::new(16)
            $random.GetBytes($bytes)
            $capability = [BitConverter]::ToString($bytes).Replace(
                '-',
                ''
            ).ToLowerInvariant()
            $candidate = [IO.Path]::Combine(
                $resolvedBootstrapParent,
                "DefenseClaw-Bootstrap-$capability"
            )
            if (Test-DefenseClawBootstrapPathExists -Path $candidate) {
                continue
            }
            $directory = [IO.DirectoryInfo]::new($candidate)
            try {
                if ($PSVersionTable.PSEdition -eq 'Core') {
                    [IO.FileSystemAclExtensions]::Create($directory, $security)
                }
                else {
                    $directory.Create($security)
                }
            }
            catch [IO.IOException] {
                if (Test-DefenseClawBootstrapPathExists -Path $candidate) {
                    continue
                }
                throw
            }
            $path = Assert-DefenseClawBootstrapOneShotRoot `
                -Path $candidate `
                -ExpectedSecurity $security `
                -ExpectedParent $resolvedBootstrapParent `
                -RequireEmpty
            break
        }
    }
    finally {
        $random.Dispose()
    }
    if ([string]::IsNullOrWhiteSpace($path)) {
        throw 'could not create a collision-free protected bootstrap environment'
    }

    $originalEnvironment = @{}
    foreach ($name in $script:DefenseClawBootstrapEnvironmentNames) {
        $originalEnvironment[$name] =
            [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    $volume = [IO.Path]::GetPathRoot($path).TrimEnd('\')
    $homePath = $path.Substring($volume.Length)
    $context = [pscustomobject]@{
        Path = $path
        Security = $security
        Elevated = $elevated
        CurrentSID = $identity.User.Value
        AllowedAccessSIDs = $allowedAccessSIDs.ToArray()
        AllowedOwnerSIDs = $allowedOwnerSIDs.ToArray()
        OriginalEnvironment = $originalEnvironment
        BootstrapParent = $resolvedBootstrapParent
    }
    try {
        foreach ($name in @(
            'TEMP',
            'TMP',
            'TMPDIR',
            'LOCALAPPDATA',
            'APPDATA',
            'USERPROFILE',
            'HOME',
            'XDG_CACHE_HOME',
            'XDG_CONFIG_HOME',
            'XDG_DATA_HOME',
            'DOTNET_CLI_HOME',
            'NUGET_PACKAGES'
        )) {
            [Environment]::SetEnvironmentVariable($name, $path, 'Process')
        }
        [Environment]::SetEnvironmentVariable(
            'HOMEDRIVE',
            $volume,
            'Process'
        )
        [Environment]::SetEnvironmentVariable(
            'HOMEPATH',
            $homePath,
            'Process'
        )
        [Environment]::SetEnvironmentVariable(
            'PSModuleAnalysisCachePath',
            'NUL',
            'Process'
        )
        [void](Assert-DefenseClawBootstrapOneShotRoot `
            -Path $path `
            -ExpectedSecurity $security `
            -ExpectedParent $resolvedBootstrapParent `
            -RequireEmpty)
        return $context
    }
    catch {
        $originalFailure = $_.Exception.Message
        $cleanupFailure = $null
        try {
            # The original map is complete before the first mutation. Restore
            # unconditionally so an exception halfway through environment
            # pinning cannot leave a partially redirected installer process.
            Restore-DefenseClawBootstrapEnvironment -Context $context
        }
        catch {
            $cleanupFailure = "environment restore failed: $($_.Exception.Message)"
        }
        try {
            Remove-DefenseClawBootstrapEnvironment -Context $context
        }
        catch {
            $detail = "protected directory cleanup failed: $($_.Exception.Message)"
            if ($null -eq $cleanupFailure) {
                $cleanupFailure = $detail
            }
            else {
                $cleanupFailure += "; $detail"
            }
        }
        if ($null -ne $cleanupFailure) {
            throw "$originalFailure; $cleanupFailure"
        }
        throw
    }
}

$script:DefenseClawBootstrapModuleHandle = $null

function Close-DefenseClawBootstrapModuleHandle {
    if ($null -ne $script:DefenseClawBootstrapModuleHandle) {
        try {
            $script:DefenseClawBootstrapModuleHandle.Dispose()
        }
        finally {
            $script:DefenseClawBootstrapModuleHandle = $null
        }
    }
}

function Assert-DefenseClawBootstrapModuleTrust {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AllowUnsignedModule,
        # Standalone HashPinned: the module's exact SHA-256 from the
        # administrator's payload manifest admits an unsigned module.
        [string]$PinnedSHA256,
        # Standalone Authenticode: optional SHA-256 signer thumbprint pins.
        [string[]]$AllowedSignerSHA256 = @()
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path.Contains('"') -or
        $Path -match '[\x00-\x1f]') {
        throw "invalid DefenseClaw enterprise installer module path: $Path"
    }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.Path]::IsPathRooted($full) -or
        $full.StartsWith('\\') -or
        $full.StartsWith('//') -or
        $full.StartsWith('\\?\') -or
        $full.StartsWith('\\.\') -or
        ($full.Length -gt 2 -and $full.Substring(2).Contains(':'))) {
        throw "DefenseClaw enterprise installer module must use an absolute local Win32 path: $full"
    }

    $nativePathType = Initialize-DefenseClawBootstrapNativePath
    $driveRoot = [IO.Path]::GetPathRoot($full)
    $driveID = $driveRoot.TrimEnd('\')
    $driveType = $nativePathType::GetDriveType($driveRoot)
    $fileSystem = $nativePathType::GetFileSystem($driveRoot)
    $nativePathType::AssertCanonicalDriveRoot($driveRoot, $driveID)
    if ([int]$driveType -ne 3 -or
        -not [string]::Equals($fileSystem, 'NTFS', [StringComparison]::OrdinalIgnoreCase)) {
        throw "DefenseClaw enterprise installer module must be on a local fixed NTFS volume without subst or redirection: $full"
    }

    $chain = [Collections.Generic.List[string]]::new()
    $current = $full
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        $chain.Add($current)
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrWhiteSpace($parent) -or
            [string]::Equals($parent, $current, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $current = $parent
    }

    # Inspect object type and reparse state across the complete chain before
    # ACL evaluation. This makes a junction/symlink fail as such even when a
    # higher ancestor is independently untrusted.
    for ($index = $chain.Count - 1; $index -ge 0; $index--) {
        $candidate = $chain[$index]
        $item = Microsoft.PowerShell.Management\Get-Item `
            -LiteralPath $candidate `
            -Force `
            -ErrorAction Stop
        $leaf = $index -eq 0
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "DefenseClaw enterprise installer module path contains a reparse point: $candidate"
        }
        if ($leaf) {
            if ($item.PSIsContainer) {
                throw "DefenseClaw enterprise installer module is not a regular file: $candidate"
            }
        }
        elseif (-not $item.PSIsContainer) {
            throw "DefenseClaw enterprise installer module ancestor is not a directory: $candidate"
        }
    }

    # Pin the module from this check until Import-Module returns: a handle
    # that shares only read access keeps every writer, rename and delete out,
    # so the bytes judged below are the bytes PowerShell imports.
    Close-DefenseClawBootstrapModuleHandle
    try {
        $script:DefenseClawBootstrapModuleHandle = [IO.FileStream]::new(
            $full,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
    }
    catch {
        throw "DefenseClaw enterprise installer module could not be pinned for import: $full; $($_.Exception.Message)"
    }

    # The module file is strict; its ancestors are advisory (see
    # Assert-DefenseClawBootstrapTrustedPath).
    for ($index = $chain.Count - 1; $index -ge 0; $index--) {
        Assert-DefenseClawBootstrapTrustedPath `
            -Path $chain[$index] `
            -Subject 'DefenseClaw enterprise installer module path' `
            -Leaf ($index -eq 0) `
            -LeafWriteLike
    }

    if (-not $AllowUnsignedModule) {
        $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
            -LiteralPath $full `
            -ErrorAction Stop
        $hashAdmitted = $false
        if (-not [string]::IsNullOrWhiteSpace($PinnedSHA256) -and
            $signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
            $actual = (Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $full `
                -Algorithm SHA256).Hash.ToLowerInvariant()
            $hashAdmitted = $actual -ceq $PinnedSHA256.ToLowerInvariant()
            if (-not $hashAdmitted) {
                throw "DefenseClaw enterprise installer module SHA-256 does not match the pinned payload manifest: $full"
            }
        }
        if (-not $hashAdmitted -and
            $signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
            # Secure Client, outside the strict pin: only NotTrusted is
            # advisory, and only for a module signed by the same certificate
            # as this running installer: NotTrusted means the signature's hash
            # verified and only the chain to a trusted root failed (an offline
            # host that lacks the signing root), and the matching signer
            # proves the module came from the same signed artifact set.
            # UnknownError, HashMismatch, NotSigned and every other status
            # stay fatal for this elevated import; the leaf ACL check proves
            # only who can write the file now, not where it came from. The
            # standalone profile admits only a valid signature or its pin.
            $signerMatches = $false
            if ($EnterpriseProfile -cne 'Standalone' -and
                $signature.Status -eq [Management.Automation.SignatureStatus]::NotTrusted -and
                $null -ne $signature.SignerCertificate) {
                try {
                    $self = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
                        -LiteralPath $PSCommandPath `
                        -ErrorAction Stop
                    $selfHashVerified = $self.Status -eq [Management.Automation.SignatureStatus]::Valid -or
                        $self.Status -eq [Management.Automation.SignatureStatus]::NotTrusted
                    $signerMatches = $selfHashVerified -and
                        $null -ne $self.SignerCertificate -and
                        [string]::Equals(
                            [string]$self.SignerCertificate.Thumbprint,
                            [string]$signature.SignerCertificate.Thumbprint,
                            [StringComparison]::OrdinalIgnoreCase
                        )
                }
                catch {
                    $signerMatches = $false
                }
            }
            if ((Test-DefenseClawBootstrapStrictAncestors) -or -not $signerMatches) {
                throw "DefenseClaw enterprise installer module Authenticode signature is not valid ($($signature.Status)): $full; use -AllowUnsigned only for protected controlled test staging"
            }
            Add-DefenseClawBootstrapResilienceEvent `
                -Marker defenseclaw_boundary `
                -Fields @{
                    path   = $full
                    label  = 'DefenseClaw enterprise installer module'
                    reason = "Authenticode chain is not trusted on this host ($($signature.Status)); signer matches the installer"
                }
        }
        if (-not $hashAdmitted -and @($AllowedSignerSHA256).Count -gt 0) {
            $sha256 = [Security.Cryptography.SHA256]::Create()
            try {
                $thumbprint = ([BitConverter]::ToString(
                    $sha256.ComputeHash($signature.SignerCertificate.RawData)
                )).Replace('-', '').ToLowerInvariant()
            }
            finally {
                $sha256.Dispose()
            }
            if ($thumbprint -notin @($AllowedSignerSHA256)) {
                throw "DefenseClaw enterprise installer module signer is not an allowed signer: $full"
            }
        }
    }
    # Keep the mount-manager authorization adjacent to the import boundary.
    $nativePathType::AssertCanonicalDriveRoot($driveRoot, $driveID)
    return $full
}

function Get-DefenseClawBootstrapRecordedModulePin {
    <#
        Standalone only. Returns the module SHA-256 a hash-pinned standalone
        deployment recorded in its deployment metadata, or '' when there is
        no such trusted record. The metadata must pass the same local-NTFS,
        no-reparse, administrator-owned chain as the module itself, and the
        running installer must be byte-identical to the one the deployment
        recorded, so the pin admits only the payload already installed.
        A trusted record that does not parse (or is too large to be one)
        leaves its path and reason in
        $script:DefenseClawBootstrapUnreadableRecord, so the caller names
        the damaged record instead of the module signature (GAP-0164).
    #>
    param(
        [Parameter(Mandatory)][string]$MetadataPath,
        [Parameter(Mandatory)][string]$InstallerPath
    )
    $script:DefenseClawBootstrapUnreadableRecord = ''
    try {
        if (-not [IO.File]::Exists($MetadataPath)) {
            return ''
        }
        $metadataFull = Assert-DefenseClawBootstrapModuleTrust `
            -Path $MetadataPath `
            -AllowUnsignedModule
        $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $metadataFull -Force
        if ([int64]$item.Length -gt 1048576) {
            $script:DefenseClawBootstrapUnreadableRecord = "$metadataFull (it is larger than 1 MiB)"
            return ''
        }
        $text = Microsoft.PowerShell.Management\Get-Content `
            -LiteralPath $metadataFull `
            -Raw
        $metadata = $null
        $reason = 'it is not a JSON object'
        try {
            $metadata = $text | Microsoft.PowerShell.Utility\ConvertFrom-Json
        }
        catch {
            $reason = ([string]$_.Exception.Message -replace '\s+', ' ').Trim()
        }
        # [pscustomobject] is [psobject], which also matches $null and a
        # wrapped number: test the parsed object's own type.
        if ($metadata -isnot [Management.Automation.PSCustomObject]) {
            $script:DefenseClawBootstrapUnreadableRecord = "$metadataFull ($reason)"
            return ''
        }
        $trust = $metadata.PSObject.Properties['trust_mode']
        $recordedProfile = $metadata.PSObject.Properties['profile']
        $hashes = $metadata.PSObject.Properties['hashes']
        if ($null -eq $trust -or [string]$trust.Value -cne 'hash_pinned' -or
            $null -eq $recordedProfile -or [string]$recordedProfile.Value -cne 'standalone' -or
            $null -eq $hashes -or $null -eq $hashes.Value) {
            return ''
        }
        $module = $hashes.Value.PSObject.Properties['module']
        $installer = $hashes.Value.PSObject.Properties['installer']
        if ($null -eq $module -or [string]$module.Value -cnotmatch '^[0-9a-f]{64}$' -or
            $null -eq $installer -or [string]$installer.Value -cnotmatch '^[0-9a-f]{64}$') {
            return ''
        }
        $running = (Microsoft.PowerShell.Utility\Get-FileHash `
            -LiteralPath $InstallerPath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($running -cne [string]$installer.Value) {
            return ''
        }
        return [string]$module.Value
    }
    catch {
        # An unreadable or untrusted record admits nothing; the Authenticode
        # requirement then applies unchanged.
        return ''
    }
}

# ---------------------------------------------------------------------------
# QA shorthand renderer helpers (-Mode / -Connector). Mirror the macOS
# install.sh render_config + render_targets_manifest heredocs
# (packaging/macos/lib/installer_lib.sh:1061, :1336) closely enough for the
# resulting config.yaml + targets.yaml to satisfy the Windows lifecycle's
# managed_enterprise trust check. Kept minimal on purpose: only the fields
# the running gateway requires are emitted; the rest come from the Go
# config loader's defaults, so a mismatch between platforms cannot open a
# per-key drift regression during a QA install.
# ---------------------------------------------------------------------------

# Windows managed_enterprise supports only connectors with a complete native
# reconcile, trusted-runtime, rollback, and teardown lifecycle. Cursor uses its
# documented machine enterprise hook source while retaining per-user scoped
# DefenseClaw runtime and credentials. The Secure Client profile also manages
# GitHub Copilot (the Copilot CLI and the GitHub Copilot app, which runs the
# same CLI) through Copilot's policy.d machine policy.
$script:DefenseClawSupportedConnectors = @('codex', 'cursor', 'claudecode', 'amp', 'copilot')
$script:DefenseClawWindowsManagedEnterpriseSupportedConnectors = @('codex', 'claudecode', 'cursor')
if ($EnterpriseProfile -cne 'Standalone') {
    $script:DefenseClawWindowsManagedEnterpriseSupportedConnectors += 'copilot'
}

function ConvertTo-DefenseClawConnectorList {
    param([Parameter(Mandatory)][string]$Connector)
    $raw = $Connector -split ','
    $normalized = [Collections.Generic.List[string]]::new()
    foreach ($entry in $raw) {
        $trimmed = $entry.Trim().ToLowerInvariant()
        if ([string]::IsNullOrEmpty($trimmed)) { continue }
        if ($trimmed -notin $script:DefenseClawSupportedConnectors) {
            throw "-Connector entry '$trimmed' is not a recognised connector; expected one or more of: $($script:DefenseClawSupportedConnectors -join ', ')"
        }
        if ($trimmed -notin $script:DefenseClawWindowsManagedEnterpriseSupportedConnectors) {
            throw "-Connector entry '$trimmed' is not supported on Windows managed_enterprise; supported: $($script:DefenseClawWindowsManagedEnterpriseSupportedConnectors -join ', ')."
        }
        if ($normalized -notcontains $trimmed) {
            $normalized.Add($trimmed) | Microsoft.PowerShell.Core\Out-Null
        }
    }
    if ($normalized.Count -eq 0) {
        throw "-Connector produced no valid entries after trimming and deduplication: $Connector"
    }
    return $normalized.ToArray()
}

function Get-DefenseClawRenderedEnterpriseConfig {
    # Emit a minimal managed_enterprise config.yaml body. This is
    # intentionally NARROWER than the macOS render_config output —
    # data_dir, device_key_file, observability.local.path,
    # judge_bodies_path, and cisco_ai_defense.endpoint are all left to
    # the Windows Go loader's defaults so they land under the
    # canonical %ProgramData%\Cisco\Cisco Secure Client\DefenseClaw
    # tree without hard-coding drive letters here. env_config.json
    # remains the AVC-supplied endpoint override (see the packaging
    # doc); operators who need a non-default endpoint drop that
    # overlay after install and the gateway picks it up dynamically.
    # rule_pack_dir is the exception: omitting the key activates the
    # runtime-v8 data-dir migration, which points at an external policy
    # directory the Windows payload does not ship. An explicit empty
    # scalar selects the gateway's validated embedded rule-pack defaults.
    param(
        [Parameter(Mandatory)][string]$Mode,
        [Parameter(Mandatory)][string[]]$Connectors,
        [ValidateSet('SecureClient', 'Standalone')]
        [string]$ForProfile = 'SecureClient'
    )
    $standalone = $ForProfile -ceq 'Standalone'
    $primary = $Connectors[0]
    $sb = [Text.StringBuilder]::new()
    [void]$sb.AppendLine('config_version: 8')
    [void]$sb.AppendLine('deployment_mode: managed_enterprise')
    if ($standalone) {
        # The standalone profile's local policy engine decides; AI Defense is
        # added later only through a protected credential.
        [void]$sb.AppendLine('enterprise:')
        [void]$sb.AppendLine('  profile: standalone')
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('observability:')
    [void]$sb.AppendLine('  defaults:')
    [void]$sb.AppendLine('    redaction_profile: sensitive')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('gateway:')
    [void]$sb.AppendLine('  api_bind: 127.0.0.1')
    [void]$sb.AppendLine('  api_port: 18970')
    [void]$sb.AppendLine('  watcher:')
    [void]$sb.AppendLine('    enabled: false')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('guardrail:')
    [void]$sb.AppendLine('  enabled: true')
    [void]$sb.AppendLine('  rule_pack_dir: ""')
    [void]$sb.AppendLine("  mode: $Mode")
    if ($standalone) {
        [void]$sb.AppendLine('  scanner_mode: local')
    }
    else {
        [void]$sb.AppendLine('  scanner_mode: both')
    }
    [void]$sb.AppendLine('  detection_strategy: regex_only')
    [void]$sb.AppendLine('  judge:')
    [void]$sb.AppendLine('    enabled: false')
    [void]$sb.AppendLine("  connector: $primary")
    if ($Connectors.Count -gt 1) {
        [void]$sb.AppendLine('  connectors:')
        foreach ($c in $Connectors) {
            [void]$sb.AppendLine("    ${c}:")
            [void]$sb.AppendLine('      enabled: true')
            [void]$sb.AppendLine("      mode: $Mode")
        }
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('ai_discovery:')
    [void]$sb.AppendLine('  enabled: true')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('asset_policy:')
    [void]$sb.AppendLine('  enabled: false')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('application_protection:')
    [void]$sb.AppendLine('  enabled: false')
    return $sb.ToString()
}

function Test-DefenseClawInteractiveUserSID {
    param(
        [AllowNull()]
        [Security.Principal.SecurityIdentifier]$SID
    )

    if ($null -eq $SID) { return $false }
    $value = $SID.Value
    $componentCount = $value.Split('-').Length
    return ($value.StartsWith(
            'S-1-5-21-',
            [StringComparison]::OrdinalIgnoreCase
        ) -and $componentCount -ge 8) -or
        ($value.StartsWith(
            'S-1-12-1-',
            [StringComparison]::OrdinalIgnoreCase
        ) -and $componentCount -eq 8)
}

# The SIDs of the signed-in interactive users. A session whose account name
# does not translate (a domain account with no LSA answer, as on a domain
# laptop off VPN) is resolved from its session token when Setup runs as
# LocalSystem, else from the one ProfileList profile whose folder is named
# after the user (user, or user.DOMAIN...). A session neither resolves is
# left out and logged: its rows stay deferred and the Guardian enrolls the
# user once it reads the session. No lookup failure stops the install.
function Get-DefenseClawActiveSessionSIDs {
    param([string]$EnterpriseProfile)

    $native = Initialize-DefenseClawBootstrapNativePath
    $sids = [Collections.Generic.List[string]]::new()
    foreach ($sid in @($native::GetActiveSessionSIDs($EnterpriseProfile -ceq 'Standalone'))) {
        $sids.Add([string]$sid)
    }
    $fallbacks = @($native::LastTokenFallbackSessionAccounts)
    $unresolved = @($native::LastUnresolvedSessionAccounts)
    $detail = {
        param([string]$Account)
        if ($native::LastSessionResolutionDetail.ContainsKey($Account)) {
            return [string]$native::LastSessionResolutionDetail[$Account]
        }
        return 'no detail recorded'
    }
    # The standalone profile and strict mode resolve a signed-in account only
    # through the name lookup, as before; Secure Client falls back to the
    # session token and then to a single matching ProfileList folder.
    if (($EnterpriseProfile -ceq 'Standalone') -or (Test-DefenseClawBootstrapStrictAncestors)) {
        $refused = @($fallbacks) + @($unresolved)
        if ($refused.Count -gt 0) {
            $account = [string]$refused[0]
            throw ("signed-in account $account did not translate to a SID: $(& $detail $account). " +
                'Expected: the name lookup returns its SID. The standalone profile and strict mode do not ' +
                'fall back to the session token or the profile folder; restore the domain trust (or connect ' +
                'to the corporate network) and run Setup again.')
        }
        return $sids.ToArray()
    }
    foreach ($account in $fallbacks) {
        Add-DefenseClawBootstrapResilienceEvent `
            -Marker defenseclaw_accept `
            -Fields @{
                account = [string]$account
                detail  = (& $detail ([string]$account))
                reason  = 'signed-in account did not translate; using the SID from its session token'
            }
    }
    if ($unresolved.Count -eq 0) {
        return $sids.ToArray()
    }
    $profiles = [Collections.Generic.List[psobject]]::new()
    $rootKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    foreach ($sub in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $rootKey -ErrorAction SilentlyContinue)) {
        try {
            $profileSID = [Security.Principal.SecurityIdentifier]::new($sub.PSChildName)
            $image = (Microsoft.PowerShell.Management\Get-ItemProperty -LiteralPath $sub.PSPath `
                -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath
        }
        catch { continue }
        if (-not (Test-DefenseClawInteractiveUserSID -SID $profileSID) -or
            [string]::IsNullOrWhiteSpace($image)) {
            continue
        }
        $leaf = [IO.Path]::GetFileName(
            [Environment]::ExpandEnvironmentVariables([string]$image).TrimEnd('\')
        )
        $profiles.Add([pscustomobject]@{ SID = $profileSID.Value; Leaf = $leaf })
    }
    foreach ($account in $unresolved) {
        $parts = ([string]$account).Split('\')
        $user = $parts[-1]
        $domain = if ($parts.Count -gt 1) { $parts[0] } else { '' }
        # Windows names a profile folder after the user, or user.DOMAIN when
        # that name is taken, with a .000-style suffix on a further collision.
        $pattern = '^' + [regex]::Escape($user) + '$'
        $expected = "a ProfileList folder named $user"
        if (-not [string]::IsNullOrEmpty($domain)) {
            $pattern = '^' + [regex]::Escape($user) + '(\.' + [regex]::Escape($domain) + '(\.\d{3})?)?$'
            $expected = "exactly one ProfileList folder named $user, $user.$domain or $user.$domain.NNN"
        }
        $found = @($profiles | Microsoft.PowerShell.Core\Where-Object {
            [regex]::IsMatch([string]$_.Leaf, $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        })
        # A folder whose SID resolves offline (every local account does) names
        # a known account; unless that is this account, the folder is not its.
        $found = @($found | Microsoft.PowerShell.Core\Where-Object {
            try {
                $owner = ([Security.Principal.SecurityIdentifier]::new([string]$_.SID)).Translate(
                    [Security.Principal.NTAccount]).Value
                return [string]::Equals($owner, [string]$account, [StringComparison]::OrdinalIgnoreCase)
            }
            catch {
                return $true
            }
        })
        if ($found.Count -eq 1) {
            $sids.Add([string]$found[0].SID)
            Add-DefenseClawBootstrapResilienceEvent `
                -Marker defenseclaw_accept `
                -Fields @{
                    account = [string]$account
                    sid     = [string]$found[0].SID
                    detail  = (& $detail ([string]$account))
                    reason  = "signed-in account did not translate; matched its ProfileList profile folder $($found[0].Leaf)"
                }
            continue
        }
        $foundText = if ($found.Count -eq 0) {
            "none of $($profiles.Count) interactive profile folders matched"
        }
        else {
            ((@($found | Microsoft.PowerShell.Utility\Select-Object -First 5 | Microsoft.PowerShell.Core\ForEach-Object { "$($_.Leaf)=$($_.SID)" })) -join ', ')
        }
        Add-DefenseClawBootstrapResilienceEvent `
            -Marker defenseclaw_degraded `
            -Fields @{
                account  = [string]$account
                detail   = (& $detail ([string]$account))
                expected = $expected
                found    = $foundText
                reason   = "signed-in account did not translate and matched $($found.Count) profile folders; the Guardian enrolls it later"
            }
    }
    return @($sids | Microsoft.PowerShell.Utility\Sort-Object -Unique)
}

function Select-DefenseClawActiveInteractiveUserProfiles {
    param(
        [AllowEmptyCollection()][object[]]$Profiles = @(),
        [AllowEmptyCollection()][string[]]$ActiveSessionSIDs = @()
    )

    $active = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($rawSID in @($ActiveSessionSIDs)) {
        if ([string]::IsNullOrWhiteSpace([string]$rawSID)) { continue }
        try {
            $candidate = [Security.Principal.SecurityIdentifier]::new(
                ([string]$rawSID).Trim()
            )
        }
        catch { continue }
        if (Test-DefenseClawInteractiveUserSID -SID $candidate) {
            [void]$active.Add($candidate.Value)
        }
    }
    $selected = [Collections.Generic.List[object]]::new()
    foreach ($profile in @($Profiles)) {
        if ($null -eq $profile -or
            $null -eq $profile.PSObject.Properties['SID']) {
            continue
        }
        $rawProfileSID = ([string]$profile.SID).Trim()
        try {
            $profileSID = [Security.Principal.SecurityIdentifier]::new(
                $rawProfileSID
            )
        }
        catch { continue }
        if ((Test-DefenseClawInteractiveUserSID -SID $profileSID) -and
            $active.Contains($profileSID.Value)) {
            $selected.Add($profile)
        }
    }
    return $selected.ToArray()
}

function Get-DefenseClawEligibleInteractiveUserProfiles {
    param(
        [switch]$RequireActiveSession,
        [string[]]$ActiveSessionSIDs
    )

    if (-not $RequireActiveSession -and
        $PSBoundParameters.ContainsKey('ActiveSessionSIDs')) {
        throw 'ActiveSessionSIDs requires RequireActiveSession'
    }
    if ($RequireActiveSession -and
        -not $PSBoundParameters.ContainsKey('ActiveSessionSIDs')) {
        $ActiveSessionSIDs = @(Get-DefenseClawActiveSessionSIDs -EnterpriseProfile $EnterpriseProfile)
    }

    # Walk HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
    # and return one PSCustomObject per eligible local/domain or Microsoft Entra
    # ID interactive user with a resolvable on-disk ProfileImagePath. The
    # account name comes from the SID when it translates, else from the
    # profile folder name.
    $rootKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $out = [Collections.Generic.List[psobject]]::new()
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $rootKey)) {
        return $out.ToArray()
    }
    foreach ($sub in Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $rootKey -ErrorAction SilentlyContinue) {
        $sid = $sub.PSChildName
        try {
            $profileSID = [Security.Principal.SecurityIdentifier]::new($sid)
        }
        catch { continue }
        if (-not (Test-DefenseClawInteractiveUserSID -SID $profileSID)) { continue }
        $image = $null
        try {
            $image = (Microsoft.PowerShell.Management\Get-ItemProperty -LiteralPath $sub.PSPath `
                -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath
        }
        catch { continue }
        if ([string]::IsNullOrWhiteSpace($image)) { continue }
        $image = [Environment]::ExpandEnvironmentVariables($image)
        if (-not [IO.Directory]::Exists($image)) { continue }
        # The account name is cosmetic (the row is keyed by SID). Secure
        # Client: a domain laptop off VPN cannot translate a domain SID, and
        # that profile must still be hooked, so it falls back to the profile
        # folder name and logs it. The standalone profile keys enrollment by
        # SID and home and falls back only for a Microsoft Entra ID account,
        # which may not translate while the device is offline; it skips other
        # untranslatable SIDs.
        $account = $null
        try {
            $account = [string]$profileSID.Translate(
                [Security.Principal.NTAccount]
            ).Value
        }
        catch {
            if ($EnterpriseProfile -ceq 'Standalone' -and
                -not $sid.StartsWith('S-1-12-1-', [StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
            $account = $null
        }
        if ([string]::IsNullOrWhiteSpace($account)) {
            $account = [IO.Path]::GetFileName(
                ([IO.Path]::GetFullPath($image)).TrimEnd('\')
            )
            if ($EnterpriseProfile -cne 'Standalone') {
                Add-DefenseClawBootstrapResilienceEvent `
                    -Marker defenseclaw_accept `
                    -Fields @{
                        sid    = $sid
                        path   = $image
                        reason = 'profile SID did not translate to an account; using the profile folder name'
                    }
            }
        }
        if ([string]::IsNullOrWhiteSpace($account)) { continue }
        $userName = $account
        $backslash = $account.IndexOf('\')
        if ($backslash -ge 0) { $userName = $account.Substring($backslash + 1) }
        $out.Add([pscustomobject]@{
            SID = $sid
            NTAccount = $account
            UserName = $userName
            UserHome = ([IO.Path]::GetFullPath($image)).TrimEnd('\')
        }) | Microsoft.PowerShell.Core\Out-Null
    }
    if ($RequireActiveSession) {
        # Keep this low-level active-only query available to callers that need
        # it. The shorthand renderer intentionally enumerates the complete
        # finite profile set instead, then uses the same selector to distinguish
        # immediate rows from authenticated deferred rows.
        return @(
            Select-DefenseClawActiveInteractiveUserProfiles `
                -Profiles $out.ToArray() `
                -ActiveSessionSIDs $ActiveSessionSIDs
        )
    }
    return $out.ToArray()
}

function ConvertTo-DefenseClawConnectorMetadataVersion {
    param([AllowNull()][object]$Value)

    if ($Value -isnot [string]) { return '' }
    $version = ([string]$Value).Trim()
    if ($version.Length -eq 0 -or $version.Length -gt 128 -or
        $version -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$') {
        return ''
    }
    return $version
}

function Test-DefenseClawConnectorMetadataPath {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Path,
        [switch]$Directory
    )

    try {
        $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
        $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
        $driveRoot = [IO.Path]::GetPathRoot($full)
        if ([string]::IsNullOrWhiteSpace($rootFull) -or
            [string]::IsNullOrWhiteSpace($driveRoot) -or
            $driveRoot -cnotmatch '^[A-Za-z]:\\$' -or
            $full.StartsWith('\\') -or
            $full.StartsWith('//') -or
            $full.StartsWith('\\?\') -or
            $full.StartsWith('\\.\') -or
            -not $full.StartsWith(
                $rootFull + '\',
                [StringComparison]::OrdinalIgnoreCase
            )) {
            return $false
        }

        $current = $full
        while ($true) {
            $attributes = [IO.File]::GetAttributes($current)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $false
            }
            if ([string]::Equals(
                    $current,
                    $full,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                $isDirectory =
                    ($attributes -band [IO.FileAttributes]::Directory) -ne 0
                if ($isDirectory -ne [bool]$Directory) { return $false }
            }
            if ([string]::Equals(
                    $current,
                    $rootFull,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                break
            }
            $parent = [IO.Path]::GetDirectoryName($current)
            if ([string]::IsNullOrWhiteSpace($parent) -or
                [string]::Equals(
                    $parent,
                    $current,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                return $false
            }
            $current = $parent.TrimEnd('\')
        }
        return $true
    }
    catch {
        return $false
    }
}

function Get-DefenseClawConnectorJsonMetadataVersion {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Path,
        [string[]]$ExpectedNames = @()
    )

    if (-not (Test-DefenseClawConnectorMetadataPath `
            -Root $Root -Path $Path)) {
        return ''
    }

    # Package metadata belongs to the target user and is therefore evidence,
    # not trusted code. Read a bounded UTF-8 JSON document and constrain the
    # only value that crosses into targets.yaml. Never invoke a user-installed
    # executable from this elevated installer merely to obtain --version.
    $stream = $null
    try {
        $stream = [IO.FileStream]::new(
            [IO.Path]::GetFullPath($Path),
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        )
        $maximumBytes = 1MB
        $buffer = [byte[]]::new($maximumBytes + 1)
        $total = 0
        while ($total -lt $buffer.Length) {
            $read = $stream.Read($buffer, $total, $buffer.Length - $total)
            if ($read -eq 0) { break }
            $total += $read
        }
        if ($total -eq 0 -or $total -gt $maximumBytes) { return '' }
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $document = Microsoft.PowerShell.Utility\ConvertFrom-Json `
            -InputObject ($utf8.GetString($buffer, 0, $total))
        if ($null -eq $document) { return '' }
        $nameProperty = $document.PSObject.Properties['name']
        $versionProperty = $document.PSObject.Properties['version']
        if ($null -eq $versionProperty -or
            $versionProperty.Value -isnot [string]) {
            return ''
        }
        if ($ExpectedNames.Count -gt 0) {
            if ($null -eq $nameProperty -or
                $nameProperty.Value -isnot [string] -or
                ([string]$nameProperty.Value) -cnotin $ExpectedNames) {
                return ''
            }
        }
        return ConvertTo-DefenseClawConnectorMetadataVersion `
            -Value $versionProperty.Value
    }
    catch {
        return ''
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function ConvertTo-DefenseClawClaudeWinGetVersion {
    param([AllowNull()][object]$Value)

    if ($Value -isnot [string]) { return '' }
    $version = ([string]$Value).Trim()
    if ($version.Length -eq 0 -or $version.Length -gt 64 -or
        $version -cnotmatch '^([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.([0-9]+))?$') {
        return ''
    }
    if ($Matches[4] -and $Matches[4] -cne '0') { return '' }
    try {
        $parsed = [Version]::new(
            [int]$Matches[1],
            [int]$Matches[2],
            [int]$Matches[3]
        )
    }
    catch {
        return ''
    }
    return ConvertTo-DefenseClawConnectorMetadataVersion `
        -Value $parsed.ToString(3)
}

function Test-DefenseClawClaudeWinGetIdentity {
    param(
        [AllowNull()][object]$SignatureStatus,
        [AllowNull()][object]$SignerSimpleName,
        [AllowNull()][object]$ProductName,
        [AllowNull()][object]$OriginalFilename,
        [AllowNull()][object]$FileVersion
    )

    if ([string]$SignatureStatus -cne 'Valid' -or
        [string]$SignerSimpleName -cnotin @('Anthropic PBC', 'Anthropic, PBC') -or
        [string]$ProductName -cne 'Claude Code') {
        return ''
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$OriginalFilename) -and
        [string]$OriginalFilename -cne 'claude.exe') {
        return ''
    }
    return ConvertTo-DefenseClawClaudeWinGetVersion -Value $FileVersion
}

function Get-DefenseClawClaudeWinGetExecutableVersion {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Path
    )

    if ([IO.Path]::GetFileName($Path) -cne 'claude.exe' -or
        -not (Test-DefenseClawConnectorMetadataPath `
            -Root $Root -Path $Path)) {
        return ''
    }

    # The WinGet package directory is user-owned and therefore only a hint.
    # Hold the executable open without write/delete sharing while its path,
    # Authenticode identity, PE identity, and version are inspected. Never run
    # a user-owned executable from this elevated installer to obtain --version.
    $stream = $null
    try {
        $full = [IO.Path]::GetFullPath($Path)
        $stream = [IO.FileStream]::new(
            $full,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $maximumBytes = 512MB
        if ($stream.Length -le 0 -or $stream.Length -gt $maximumBytes) {
            return ''
        }
        if (-not (Test-DefenseClawConnectorMetadataPath `
                -Root $Root -Path $full)) {
            return ''
        }

        $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
            -LiteralPath $full `
            -ErrorAction Stop
        if ($signature.Status -ne
            [Management.Automation.SignatureStatus]::Valid -or
            $null -eq $signature.SignerCertificate) {
            return ''
        }
        $signer = $signature.SignerCertificate.GetNameInfo(
            [Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
            $false
        )
        $identity = [Diagnostics.FileVersionInfo]::GetVersionInfo($full)
        if ($null -eq $identity) { return '' }
        $version = Test-DefenseClawClaudeWinGetIdentity `
            -SignatureStatus $signature.Status `
            -SignerSimpleName $signer `
            -ProductName $identity.ProductName `
            -OriginalFilename $identity.OriginalFilename `
            -FileVersion $identity.FileVersion
        if ([string]::IsNullOrWhiteSpace($version)) { return '' }

        # Revalidate the complete ancestor chain while the no-delete-share
        # handle is still held so a candidate cannot be replaced mid-probe.
        if (-not (Test-DefenseClawConnectorMetadataPath `
                -Root $Root -Path $full)) {
            return ''
        }
        return $version
    }
    catch {
        return ''
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Get-DefenseClawClaudeWinGetMetadataVersion {
    param(
        [Parameter(Mandatory)][string]$UserHome,
        [scriptblock]$ExecutableVersionReader
    )

    try {
        $userHomeFull = [IO.Path]::GetFullPath($UserHome).TrimEnd('\')
        $packageRoot = [IO.Path]::Combine(
            $userHomeFull,
            'AppData\Local\Microsoft\WinGet\Packages'
        )
    }
    catch {
        return ''
    }
    if (-not (Test-DefenseClawConnectorMetadataPath `
            -Root $userHomeFull -Path $packageRoot -Directory)) {
        return ''
    }

    if ($null -eq $ExecutableVersionReader) {
        $ExecutableVersionReader = {
            param([string]$Root, [string]$Path)
            Get-DefenseClawClaudeWinGetExecutableVersion `
                -Root $Root -Path $Path
        }
    }

    $versions = [Collections.Generic.List[Version]]::new()
    $examined = 0
    $matched = 0
    try {
        foreach ($directory in [IO.Directory]::EnumerateDirectories(
                $packageRoot,
                'Anthropic.ClaudeCode_Microsoft.Winget.Source_*',
                [IO.SearchOption]::TopDirectoryOnly
            )) {
            $examined++
            if ($examined -gt 256) { return '' }
            $leaf = [IO.Path]::GetFileName($directory)
            if ($leaf -cnotmatch
                '^Anthropic\.ClaudeCode_Microsoft\.Winget\.Source_[0-9A-Za-z]{1,64}$') {
                continue
            }
            $matched++
            if ($matched -gt 32 -or
                -not (Test-DefenseClawConnectorMetadataPath `
                    -Root $packageRoot -Path $directory -Directory)) {
                return ''
            }
            $executable = [IO.Path]::Combine($directory, 'claude.exe')
            if (-not (Test-DefenseClawConnectorMetadataPath `
                    -Root $packageRoot -Path $executable)) {
                continue
            }
            $version = & $ExecutableVersionReader $packageRoot $executable
            $normalized = ConvertTo-DefenseClawClaudeWinGetVersion `
                -Value $version
            if ([string]::IsNullOrWhiteSpace($normalized)) { continue }
            try {
                $versions.Add([Version]::Parse($normalized))
            }
            catch {
                continue
            }
        }
    }
    catch {
        return ''
    }
    if ($versions.Count -eq 0) { return '' }
    return [string]($versions | Microsoft.PowerShell.Utility\Sort-Object -Descending | Microsoft.PowerShell.Utility\Select-Object -First 1)
}

function ConvertTo-DefenseClawCodexWinGetVersion {
    param([AllowNull()][object]$Value)

    if ($Value -isnot [string]) { return '' }
    $version = ([string]$Value).Trim()
    if ($version.Length -eq 0 -or $version.Length -gt 64) {
        return ''
    }
    # Do not depend on PowerShell's automatic $Matches variable here.
    # `-cnotmatch` does not provide stable capture state across PowerShell
    # editions, and a stale capture would make a valid signed PE fail closed.
    $versionMatch = [regex]::Match(
        $version,
        '^([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.([0-9]+))?$',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $versionMatch.Success) { return '' }
    if ($versionMatch.Groups[4].Success -and
        $versionMatch.Groups[4].Value -cne '0') {
        return ''
    }
    try {
        $parsed = [Version]::new(
            [int]$versionMatch.Groups[1].Value,
            [int]$versionMatch.Groups[2].Value,
            [int]$versionMatch.Groups[3].Value
        )
    }
    catch {
        return ''
    }
    return ConvertTo-DefenseClawConnectorMetadataVersion `
        -Value $parsed.ToString(3)
}

function Read-DefenseClawCodexPEBytes {
    param(
        [Parameter(Mandatory)][IO.Stream]$Stream,
        [Parameter(Mandatory)][ValidateRange(1, 1048576)][int]$Count
    )

    $buffer = [byte[]]::new($Count)
    $total = 0
    while ($total -lt $Count) {
        $read = $Stream.Read($buffer, $total, $Count - $total)
        if ($read -eq 0) {
            throw 'unexpected end of Codex PE metadata'
        }
        $total += $read
    }
    # Prevent PowerShell's pipeline from unrolling byte arrays.
    Microsoft.PowerShell.Utility\Write-Output -NoEnumerate $buffer
}

function Get-DefenseClawCodexWinGetEmbeddedVersion {
    param([Parameter(Mandatory)][IO.Stream]$Stream)

    if (-not $Stream.CanRead -or -not $Stream.CanSeek) { return '' }
    try {
        if (-not [BitConverter]::IsLittleEndian) { return '' }
        $streamLength = [uint64]$Stream.Length
        if ($streamLength -le 0 -or $streamLength -gt 512MB) { return '' }

        # Authenticode deliberately excludes the certificate table and some PE
        # header fields from its digest. Parse the PE and scan only raw section
        # bytes, which are covered by the verified signature; never accept a
        # version marker injected into certificate padding or an unsigned tail.
        [void]$Stream.Seek(0, [IO.SeekOrigin]::Begin)
        [byte[]]$dos = Read-DefenseClawCodexPEBytes -Stream $Stream -Count 64
        if ($dos[0] -ne 0x4d -or $dos[1] -ne 0x5a) { return '' }
        $peOffset = [uint64][BitConverter]::ToUInt32($dos, 60)
        if ($peOffset -lt 64 -or $peOffset -gt 1MB -or
            $peOffset + 24 -gt $streamLength) {
            return ''
        }
        [void]$Stream.Seek([int64]$peOffset, [IO.SeekOrigin]::Begin)
        [byte[]]$signature = Read-DefenseClawCodexPEBytes `
            -Stream $Stream -Count 4
        if ($signature[0] -ne 0x50 -or $signature[1] -ne 0x45 -or
            $signature[2] -ne 0 -or $signature[3] -ne 0) {
            return ''
        }
        [byte[]]$coff = Read-DefenseClawCodexPEBytes -Stream $Stream -Count 20
        if ([BitConverter]::ToUInt16($coff, 0) -ne 0x8664) { return '' }
        $sectionCount = [uint32][BitConverter]::ToUInt16($coff, 2)
        $optionalSize = [uint32][BitConverter]::ToUInt16($coff, 16)
        if ($sectionCount -lt 1 -or $sectionCount -gt 96 -or
            $optionalSize -lt 152 -or $optionalSize -gt 4096) {
            return ''
        }
        [byte[]]$optional = Read-DefenseClawCodexPEBytes `
            -Stream $Stream -Count ([int]$optionalSize)
        if ([BitConverter]::ToUInt16($optional, 0) -ne 0x20b -or
            [BitConverter]::ToUInt32($optional, 108) -lt 5) {
            return ''
        }
        $sizeOfHeaders = [uint64][BitConverter]::ToUInt32($optional, 60)
        $certificateOffset = [uint64][BitConverter]::ToUInt32($optional, 144)
        $certificateSize = [uint64][BitConverter]::ToUInt32($optional, 148)
        $sectionTableEnd = (
            $peOffset + 24 + $optionalSize +
            ([uint64]$sectionCount * 40)
        )
        $certificateEnd = $certificateOffset + $certificateSize
        if ($sizeOfHeaders -lt $sectionTableEnd -or
            $sizeOfHeaders -gt $streamLength -or
            $certificateOffset -lt $sizeOfHeaders -or
            $certificateOffset % 8 -ne 0 -or
            $certificateSize -lt 8 -or
            $certificateSize % 8 -ne 0 -or
            $certificateEnd -ne $streamLength) {
            return ''
        }

        $sections = [Collections.Generic.List[object]]::new()
        $totalSectionBytes = [uint64]0
        for ($index = 0; $index -lt $sectionCount; $index++) {
            [byte[]]$sectionHeader = Read-DefenseClawCodexPEBytes `
                -Stream $Stream -Count 40
            $rawSize = [uint64][BitConverter]::ToUInt32($sectionHeader, 16)
            $rawOffset = [uint64][BitConverter]::ToUInt32($sectionHeader, 20)
            if ($rawSize -eq 0) { continue }
            $rawEnd = $rawOffset + $rawSize
            if ($rawEnd -lt $rawOffset -or
                $rawOffset -lt $sizeOfHeaders -or
                $rawEnd -gt $certificateOffset) {
                return ''
            }
            $totalSectionBytes += $rawSize
            if ($totalSectionBytes -gt 512MB) { return '' }
            $sections.Add([pscustomobject]@{
                Offset = $rawOffset
                Length = $rawSize
            })
        }
        if ($sections.Count -eq 0) { return '' }
        $ordered = @($sections | Microsoft.PowerShell.Utility\Sort-Object -Property Offset)
        $previousEnd = [uint64]0
        foreach ($signedSection in $ordered) {
            if ([uint64]$signedSection.Offset -lt $previousEnd) { return '' }
            $previousEnd = (
                [uint64]$signedSection.Offset +
                [uint64]$signedSection.Length
            )
        }

        $buffer = [byte[]]::new(1MB)
        $ascii = [Text.Encoding]::ASCII
        $sawCodexCLI = $false
        $versions = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal
        )
        foreach ($signedSection in $ordered) {
            [void]$Stream.Seek(
                [int64][uint64]$signedSection.Offset,
                [IO.SeekOrigin]::Begin
            )
            $remaining = [uint64]$signedSection.Length
            $carry = ''
            while ($remaining -gt 0) {
                $readLength = if ($remaining -gt $buffer.Length) {
                    $buffer.Length
                }
                else {
                    [int]$remaining
                }
                $read = $Stream.Read($buffer, 0, $readLength)
                if ($read -le 0) { return '' }
                $remaining -= [uint64]$read
                $text = $carry + $ascii.GetString($buffer, 0, $read)
                if ($text.IndexOf(
                        'codex-cli',
                        [StringComparison]::Ordinal
                    ) -ge 0) {
                    $sawCodexCLI = $true
                }
                foreach ($match in [regex]::Matches(
                        $text,
                        'buildversion: ([0-9]{1,10}\.[0-9]{1,10}\.[0-9]{1,10}(?:\.[0-9]{1,10})?)',
                        [Text.RegularExpressions.RegexOptions]::CultureInvariant
                    )) {
                    $normalized = ConvertTo-DefenseClawCodexWinGetVersion `
                        -Value $match.Groups[1].Value
                    if ([string]::IsNullOrWhiteSpace($normalized)) { return '' }
                    [void]$versions.Add($normalized)
                    if ($versions.Count -gt 1) { return '' }
                }
                $carryLength = [Math]::Min(256, $text.Length)
                $carry = $text.Substring($text.Length - $carryLength)
            }
        }
        if (-not $sawCodexCLI -or $versions.Count -ne 1) { return '' }
        return [string]($versions | Microsoft.PowerShell.Utility\Select-Object -First 1)
    }
    catch {
        return ''
    }
}

function Test-DefenseClawCodexWinGetIdentity {
    param(
        [AllowNull()][object]$SignatureStatus,
        [AllowNull()][object]$SignerSimpleName,
        [AllowNull()][object]$ProductName,
        [AllowNull()][object]$OriginalFilename,
        [AllowNull()][object]$FileVersion,
        [AllowNull()][object]$EmbeddedVersion
    )

    if ([string]$SignatureStatus -cne 'Valid' -or
        [string]$SignerSimpleName -cne 'OpenAI OpCo, LLC') {
        return ''
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$ProductName) -and
        [string]$ProductName -cnotin @('Codex', 'Codex CLI')) {
        return ''
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$OriginalFilename) -and
        [string]$OriginalFilename -cne 'codex-x86_64-pc-windows-msvc.exe') {
        return ''
    }
    $embedded = ConvertTo-DefenseClawCodexWinGetVersion `
        -Value $EmbeddedVersion
    if ([string]::IsNullOrWhiteSpace($embedded)) { return '' }
    if (-not [string]::IsNullOrWhiteSpace([string]$FileVersion)) {
        $file = ConvertTo-DefenseClawCodexWinGetVersion -Value $FileVersion
        if ([string]::IsNullOrWhiteSpace($file) -or $file -cne $embedded) {
            return ''
        }
    }
    return $embedded
}

function Test-DefenseClawConnectorMetadataTargetIsLocalAdmin {
    param([Parameter(Mandatory)][string]$ExpectedSID)

    # RID -500 is the built-in Administrator account (both on domain-joined
    # workstations and standalone hosts). Its token is always
    # BUILTIN\Administrators-owning by default, so any file it creates is
    # stamped with SID S-1-5-32-544 as owner. Match on the well-known RID
    # pattern first so the common QA case (logged in as local Administrator)
    # never pays for a CIM query.
    #
    # Anchor the pattern to the canonical shape: S-1-5-21 (domain identifier
    # authority) followed by exactly three non-empty numeric sub-authorities
    # (the machine or domain identifier) and then the terminal -500 RID.
    # A wider `[0-9-]+` sub-pattern would match e.g. `S-1-5-21---500` or
    # `S-1-5-21-1-500` (only one sub-authority), neither of which is a real
    # built-in Administrator SID.
    if ($ExpectedSID -cmatch '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-500$') {
        return $true
    }
    try {
        # Direct-membership walk of the local Administrators group
        # (SID S-1-5-32-544). Nested groups are deliberately NOT expanded —
        # a transitively-nested group containing Administrators must not
        # silently widen owner-acceptance. Any CIM query failure returns
        # $false so we never widen acceptance based on incomplete data.
        #
        # A domain-joined host off its network can stall the group walk; it
        # is bounded, and a timeout or failure is "unknown": the
        # Administrators-owner relaxation is skipped (logged once) and every
        # later call skips the query instead of waiting again.
        if ($script:DefenseClawBootstrapAdminMembershipUnknown) {
            return $false
        }
        $adminGroup = CimCmdlets\Get-CimInstance `
            -ClassName Win32_Group `
            -Filter "SID='S-1-5-32-544' AND LocalAccount=True" `
            -OperationTimeoutSec 15 `
            -ErrorAction Stop
        if ($null -eq $adminGroup) { return $false }
        $members = CimCmdlets\Get-CimAssociatedInstance `
            -InputObject $adminGroup `
            -Association Win32_GroupUser `
            -OperationTimeoutSec 15 `
            -ErrorAction Stop
        foreach ($member in $members) {
            if ([string]::Equals(
                    [string]$member.SID,
                    $ExpectedSID,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                return $true
            }
        }
    }
    catch {
        $script:DefenseClawBootstrapAdminMembershipUnknown = $true
        Add-DefenseClawBootstrapResilienceEvent `
            -Marker defenseclaw_skip `
            -Fields @{
                check  = 'local_administrators_membership'
                reason = "membership query failed or timed out; Administrators-owned agent files are not attributed to the user: $($_.Exception.Message)"
            }
        return $false
    }
    return $false
}

function Test-DefenseClawConnectorMetadataOwnerIdentity {
    param(
        [Parameter(Mandatory)][string]$ExpectedSID,
        [Parameter(Mandatory)]$ActualOwner
    )

    try {
        $expected = [Security.Principal.SecurityIdentifier]::new(
            $ExpectedSID
        ).Value
        $actual = ConvertTo-DefenseClawBootstrapSID -Identity $ActualOwner
        if ([string]::Equals(
                $actual,
                $expected,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            return $true
        }
        # Windows stamps files created by an elevated-admin token with owner
        # BUILTIN\Administrators (SID S-1-5-32-544) rather than the user's
        # own SID. Every admin-owned WinGet install (`winget install ...`
        # from an elevated prompt) lands with Administrators-owned files,
        # so the strict "owner must equal target SID" check refuses to
        # detect Codex/etc. installed by any admin target — including
        # the built-in Administrator RID -500 that QA uses. Accept
        # Administrators as a valid owner iff the target SID is itself a
        # member of the local Administrators group; the file is then
        # functionally owned by the target. Regular non-admin users keep
        # the strict target-SID-only check.
        #
        # See docs/WINDOWS-ENTERPRISE-THREAT-MODEL.md § "Elevated target
        # relaxation" for the parallel runtime-side softening. A determined
        # admin attacker can always defeat DefenseClaw through uninstall or
        # direct hook-file edits — refusing to detect their tools does not
        # raise the trust boundary, it only denies inspection to legitimate
        # admin QA + admin-managed helpdesk workflows.
        if ([string]::Equals(
                $actual,
                'S-1-5-32-544',
                [StringComparison]::OrdinalIgnoreCase
            ) -and
            (Test-DefenseClawConnectorMetadataTargetIsLocalAdmin `
                -ExpectedSID $expected)) {
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}

function Test-DefenseClawConnectorMetadataOwner {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedSID
    )

    try {
        $acl = Microsoft.PowerShell.Security\Get-Acl `
            -LiteralPath ([IO.Path]::GetFullPath($Path)) `
            -ErrorAction Stop
        return Test-DefenseClawConnectorMetadataOwnerIdentity `
            -ExpectedSID $ExpectedSID -ActualOwner $acl.Owner
    }
    catch {
        return $false
    }
}

function Get-DefenseClawCodexWinGetExecutableVersion {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$OwnerSID
    )

    if ([IO.Path]::GetFileName($Path) -cne
            'codex-x86_64-pc-windows-msvc.exe' -or
        -not (Test-DefenseClawConnectorMetadataPath `
            -Root $Root -Path $Path)) {
        return ''
    }

    # The user-owned package directory is only a candidate hint. Keep the
    # exact executable open without write/delete sharing while validating its
    # owner, Authenticode signer, optional PE identity, and signed embedded
    # build provenance. Never execute it from this elevated installer.
    $stream = $null
    try {
        $full = [IO.Path]::GetFullPath($Path)
        $stream = [IO.FileStream]::new(
            $full,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        if ($stream.Length -le 0 -or $stream.Length -gt 512MB -or
            -not (Test-DefenseClawConnectorMetadataOwner `
                -Path $full -ExpectedSID $OwnerSID) -or
            -not (Test-DefenseClawConnectorMetadataPath `
                -Root $Root -Path $full)) {
            return ''
        }

        $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
            -LiteralPath $full `
            -ErrorAction Stop
        if ($signature.Status -ne
            [Management.Automation.SignatureStatus]::Valid -or
            $null -eq $signature.SignerCertificate) {
            return ''
        }
        $signer = $signature.SignerCertificate.GetNameInfo(
            [Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
            $false
        )
        $identity = [Diagnostics.FileVersionInfo]::GetVersionInfo($full)
        if ($null -eq $identity) { return '' }
        $embedded = Get-DefenseClawCodexWinGetEmbeddedVersion -Stream $stream
        $version = Test-DefenseClawCodexWinGetIdentity `
            -SignatureStatus $signature.Status `
            -SignerSimpleName $signer `
            -ProductName $identity.ProductName `
            -OriginalFilename $identity.OriginalFilename `
            -FileVersion $identity.FileVersion `
            -EmbeddedVersion $embedded
        if ([string]::IsNullOrWhiteSpace($version)) { return '' }

        if (-not (Test-DefenseClawConnectorMetadataOwner `
                -Path $full -ExpectedSID $OwnerSID) -or
            -not (Test-DefenseClawConnectorMetadataPath `
                -Root $Root -Path $full)) {
            return ''
        }
        return $version
    }
    catch {
        return ''
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Get-DefenseClawCodexWinGetMetadataVersion {
    param(
        [Parameter(Mandatory)][string]$UserHome,
        [Parameter(Mandatory)][AllowEmptyString()][string]$OwnerSID,
        [scriptblock]$ExecutableVersionReader,
        [scriptblock]$OwnerValidator,
        [ref]$CandidateObserved
    )

    if ($null -ne $CandidateObserved) { $CandidateObserved.Value = $false }
    try {
        $userHomeFull = [IO.Path]::GetFullPath($UserHome).TrimEnd('\')
        $packageRoot = [IO.Path]::Combine(
            $userHomeFull,
            'AppData\Local\Microsoft\WinGet\Packages'
        )
    }
    catch {
        return ''
    }
    $packageRootPresent = $false
    try {
        [void][IO.File]::GetAttributes($packageRoot)
        $packageRootPresent = $true
    }
    catch [IO.FileNotFoundException] {
        return ''
    }
    catch [IO.DirectoryNotFoundException] {
        return ''
    }
    catch {
        if ($null -ne $CandidateObserved) {
            $CandidateObserved.Value = $true
        }
        return ''
    }
    if (-not $packageRootPresent -or
        -not (Test-DefenseClawConnectorMetadataPath `
            -Root $userHomeFull -Path $packageRoot -Directory)) {
        # An existing but unsafe/unreadable WinGet root is evidence, not
        # absence. Prevent the caller from substituting a minimum version.
        if ($null -ne $CandidateObserved) {
            $CandidateObserved.Value = $true
        }
        return ''
    }

    if ($null -eq $ExecutableVersionReader) {
        $ExecutableVersionReader = {
            param([string]$Root, [string]$Path, [string]$ExpectedOwnerSID)
            Get-DefenseClawCodexWinGetExecutableVersion `
                -Root $Root -Path $Path -OwnerSID $ExpectedOwnerSID
        }
    }
    if ($null -eq $OwnerValidator) {
        $OwnerValidator = {
            param([string]$Path, [string]$ExpectedOwnerSID)
            Test-DefenseClawConnectorMetadataOwner `
                -Path $Path -ExpectedSID $ExpectedOwnerSID
        }
    }

    $versions = [Collections.Generic.List[Version]]::new()
    $examined = 0
    $matched = 0
    $invalidCandidate = $false
    try {
        foreach ($directory in [IO.Directory]::EnumerateDirectories(
                $packageRoot,
                'OpenAI.Codex_Microsoft.Winget.Source_*',
                [IO.SearchOption]::TopDirectoryOnly
            )) {
            $examined++
            if ($null -ne $CandidateObserved) {
                $CandidateObserved.Value = $true
            }
            if ($examined -gt 256) { return '' }
            $leaf = [IO.Path]::GetFileName($directory)
            if ($leaf -cnotmatch
                '^OpenAI\.Codex_Microsoft\.Winget\.Source_[0-9A-Za-z]{1,64}$') {
                $invalidCandidate = $true
                continue
            }
            $matched++
            if ($matched -gt 32 -or
                [string]::IsNullOrWhiteSpace($OwnerSID) -or
                -not (Test-DefenseClawConnectorMetadataPath `
                    -Root $packageRoot -Path $directory -Directory) -or
                -not (& $OwnerValidator $directory $OwnerSID)) {
                $invalidCandidate = $true
                continue
            }
            $executable = [IO.Path]::Combine(
                $directory,
                'codex-x86_64-pc-windows-msvc.exe'
            )
            if (-not (Test-DefenseClawConnectorMetadataPath `
                    -Root $packageRoot -Path $executable) -or
                -not (& $OwnerValidator $executable $OwnerSID)) {
                $invalidCandidate = $true
                continue
            }
            $version = & $ExecutableVersionReader `
                $packageRoot $executable $OwnerSID
            $normalized = ConvertTo-DefenseClawCodexWinGetVersion `
                -Value $version
            if ([string]::IsNullOrWhiteSpace($normalized)) {
                $invalidCandidate = $true
                continue
            }
            try {
                $versions.Add([Version]::Parse($normalized))
            }
            catch {
                $invalidCandidate = $true
            }
        }
    }
    catch {
        if ($null -ne $CandidateObserved) {
            $CandidateObserved.Value = $true
        }
        return ''
    }
    if ($invalidCandidate -or $versions.Count -eq 0) { return '' }
    return [string]($versions | Microsoft.PowerShell.Utility\Sort-Object -Descending | Microsoft.PowerShell.Utility\Select-Object -First 1)
}

function Get-DefenseClawConnectorMetadataVersion {
    param(
        [Parameter(Mandatory)][string]$Connector,
        [Parameter(Mandatory)][string]$UserHome,
        [string]$OwnerSID,
        [ref]$NativeCandidateObserved
    )

    if ($null -ne $NativeCandidateObserved) {
        $NativeCandidateObserved.Value = $false
    }

    try {
        $userHomeFull = [IO.Path]::GetFullPath($UserHome).TrimEnd('\')
    }
    catch {
        return ''
    }
    if (-not [IO.Directory]::Exists($userHomeFull)) { return '' }

    if ($Connector -eq 'cursor') {
        foreach ($candidate in @(
            [pscustomobject]@{
                Root = $userHomeFull
                Path = [IO.Path]::Combine(
                    $userHomeFull,
                    'AppData\Local\Programs\cursor\resources\app\package.json'
                )
            },
            [pscustomobject]@{
                Root = $trustedProgramFiles
                Path = [IO.Path]::Combine(
                    $trustedProgramFiles,
                    'Cursor\resources\app\package.json'
                )
            }
        )) {
            # Cursor's exact application-bundle path is the identity boundary;
            # upstream package names have varied, so do not key this probe on
            # an unstable JSON name field.
            $version = Get-DefenseClawConnectorJsonMetadataVersion `
                -Root $candidate.Root -Path $candidate.Path
            if (-not [string]::IsNullOrWhiteSpace($version)) {
                return $version
            }
        }
        return ''
    }

    $package = switch ($Connector) {
        'codex' { '@openai\codex'; break }
        'claudecode' { '@anthropic-ai\claude-code'; break }
        'amp' { '@ampcode\cli'; break }
        'copilot' { '@github\copilot'; break }
        default { return '' }
    }
    $expectedName = $package -replace '\\', '/'
    foreach ($prefix in @(
        'AppData\Roaming\npm\node_modules',
        '.npm-global\node_modules',
        '.npm-global\lib\node_modules',
        '.local\lib\node_modules'
    )) {
        $candidate = [IO.Path]::Combine(
            $userHomeFull,
            $prefix,
            $package,
            'package.json'
        )
        $version = Get-DefenseClawConnectorJsonMetadataVersion `
            -Root $userHomeFull `
            -Path $candidate `
            -ExpectedNames @($expectedName)
        if (-not [string]::IsNullOrWhiteSpace($version)) {
            return $version
        }
    }

    $machinePackage = [IO.Path]::Combine(
        $trustedProgramFiles,
        'nodejs\node_modules',
        $package,
        'package.json'
    )
    $version = Get-DefenseClawConnectorJsonMetadataVersion `
        -Root $trustedProgramFiles `
        -Path $machinePackage `
        -ExpectedNames @($expectedName)
    if (-not [string]::IsNullOrWhiteSpace($version)) { return $version }

    if ($Connector -eq 'copilot') {
        return Get-DefenseClawCopilotAppCLIMetadataVersion `
            -UserHome $userHomeFull
    }

    if ($Connector -eq 'codex') {
        $codexCandidateObserved = $false
        $version = Get-DefenseClawCodexWinGetMetadataVersion `
            -UserHome $userHomeFull `
            -OwnerSID $OwnerSID `
            -CandidateObserved ([ref]$codexCandidateObserved)
        if ($codexCandidateObserved -and
            $null -ne $NativeCandidateObserved) {
            $NativeCandidateObserved.Value = $true
        }
        if (-not [string]::IsNullOrWhiteSpace($version)) {
            return $version
        }
        return ''
    }

    if ($Connector -eq 'claudecode') {
        $version = Get-DefenseClawClaudeWinGetMetadataVersion `
            -UserHome $userHomeFull
        if (-not [string]::IsNullOrWhiteSpace($version)) {
            return $version
        }

        foreach ($relativeExtensionRoot in @(
            '.cursor\extensions',
            '.vscode\extensions'
        )) {
            $extensionRoot = [IO.Path]::Combine(
                $userHomeFull,
                $relativeExtensionRoot
            )
            if (-not (Test-DefenseClawConnectorMetadataPath `
                    -Root $userHomeFull `
                    -Path $extensionRoot `
                    -Directory)) {
                continue
            }
            $examined = 0
            foreach ($extension in [IO.Directory]::EnumerateDirectories(
                    $extensionRoot,
                    'anthropic.claude-code-*',
                    [IO.SearchOption]::TopDirectoryOnly
                )) {
                $examined++
                if ($examined -gt 256) { break }
                $candidate = [IO.Path]::Combine($extension, 'package.json')
                $version = Get-DefenseClawConnectorJsonMetadataVersion `
                    -Root $userHomeFull `
                    -Path $candidate `
                    -ExpectedNames @('claude-code')
                if (-not [string]::IsNullOrWhiteSpace($version)) {
                    return $version
                }
            }
        }
    }
    return ''
}

function Get-DefenseClawCopilotAppCLIMetadataVersion {
    <#
        The GitHub Copilot app (not Microsoft Copilot) runs the Copilot CLI it
        keeps under %LOCALAPPDATA%\github-copilot-sdk\cli\<version>\copilot.exe.
        Return the newest such release whose copilot.exe exists, read from
        its folder name; nothing in the profile is executed.
    #>
    param([Parameter(Mandatory)][string]$UserHome)

    $root = [IO.Path]::Combine($UserHome, 'AppData\Local\github-copilot-sdk\cli')
    if (-not (Test-DefenseClawConnectorMetadataPath `
            -Root $UserHome -Path $root -Directory)) {
        return ''
    }
    $best = ''
    $bestVersion = $null
    $entries = @(
        [IO.Directory]::EnumerateDirectories($root) |
            Microsoft.PowerShell.Utility\Select-Object -First 64
    )
    foreach ($entry in $entries) {
        $name = [IO.Path]::GetFileName($entry)
        if ($name -cnotmatch '^([0-9]+\.[0-9]+\.[0-9]+)(?:-[0-9]+)?$') { continue }
        $release = $Matches[1]
        if (-not (Test-DefenseClawConnectorMetadataPath `
                -Root $UserHome `
                -Path ([IO.Path]::Combine($entry, 'copilot.exe')))) {
            continue
        }
        $parsed = [version]$release
        if ($null -eq $bestVersion -or $parsed -gt $bestVersion) {
            $best = $release
            $bestVersion = $parsed
        }
    }
    return $best
}

function Resolve-DefenseClawConnectorMetadataVersion {
    param(
        [AllowNull()][object]$DiscoveredVersion,
        [AllowNull()][object]$MinimumVersion,
        [bool]$NativeCandidateObserved,
        [bool]$DiscoveryFailed
    )

    $version = ConvertTo-DefenseClawConnectorMetadataVersion `
        -Value $DiscoveredVersion
    if (-not [string]::IsNullOrWhiteSpace($version)) { return $version }
    if ($NativeCandidateObserved -or $DiscoveryFailed) { return '' }
    return ConvertTo-DefenseClawConnectorMetadataVersion -Value $MinimumVersion
}

function Get-DefenseClawRenderedEnterpriseTargets {
    param(
        [Parameter(Mandatory)][string[]]$Connectors,
        [object[]]$Profiles,
        [string[]]$ActiveSessionSIDs,
        [switch]$DeferInactiveProfiles,
        [ValidateSet('SecureClient', 'Standalone')]
        [string]$ForProfile = 'SecureClient'
    )
    if (-not $DeferInactiveProfiles -and
        $PSBoundParameters.ContainsKey('ActiveSessionSIDs')) {
        throw 'ActiveSessionSIDs requires DeferInactiveProfiles'
    }
    $sb = [Text.StringBuilder]::new()
    [void]$sb.AppendLine('version: 1')
    [void]$sb.AppendLine('targets:')
    $users = @(
        if ($PSBoundParameters.ContainsKey('Profiles')) {
            $Profiles
        }
        else {
            Get-DefenseClawEligibleInteractiveUserProfiles
        }
    )
    if ($users.Count -eq 0) {
        # An empty manifest is valid YAML. This finite-profile shorthand
        # transaction simply has no current eligible users to enroll.
        return $sb.ToString()
    }
    $activeProfiles = @()
    if ($DeferInactiveProfiles) {
        if (-not $PSBoundParameters.ContainsKey('ActiveSessionSIDs')) {
            $ActiveSessionSIDs = @(Get-DefenseClawActiveSessionSIDs -EnterpriseProfile $EnterpriseProfile)
        }
        $activeProfiles = @(
            Select-DefenseClawActiveInteractiveUserProfiles `
                -Profiles $users `
                -ActiveSessionSIDs $ActiveSessionSIDs
        )
    }
    $activeProfileSIDs = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($activeProfile in $activeProfiles) {
        [void]$activeProfileSIDs.Add(([string]$activeProfile.SID).Trim())
    }
    # When no agent metadata exists yet (the common state on managed
    # rollouts where AVC pushes DefenseClaw first), the standalone profile
    # uses the exact minimum as a bootstrap placeholder: its manifest
    # validator refuses an enabled target without an agent_version that meets
    # the connector's Windows minimum (see
    # requireWindowsEnterpriseManagedAgentVersion in
    # internal/enterprisehooks/install_windows.go). Secure Client never
    # writes the placeholder. It enables its row without agent_version, which
    # the manifest accepts and which selects the best-effort hook contract,
    # and the enumerator records the real version once it finds the agent.
    # A placeholder there is not evidence of any installed agent, and while
    # the host is not verified as Secure Client the enumerator keeps the
    # recorded version, so a placeholder below the hook contract floor would
    # leave the row unhookable. A detected native package whose
    # identity/version cannot be authenticated never receives the fallback.
    # A valid below-minimum version remains exact.
    $script:DefenseClawWindowsAgentVersionMinimum = @{
        'codex'      = '0.131.0'
        'claudecode' = '2.1.152'
        'cursor'     = '1.7.0'
        'copilot'    = '1.0.18'
    }
    foreach ($u in $users) {
        $deferTarget = (
            $DeferInactiveProfiles -and
            -not $activeProfileSIDs.Contains(([string]$u.SID).Trim())
        )
        foreach ($c in $Connectors) {
            $version = ''
            $nativeCandidateObserved = $false
            $metadataDiscoveryFailed = $false
            try {
                $version = Get-DefenseClawConnectorMetadataVersion `
                    -Connector $c `
                    -UserHome ([string]$u.UserHome) `
                    -OwnerSID ([string]$u.SID) `
                    -NativeCandidateObserved ([ref]$nativeCandidateObserved)
            }
            catch {
                # Unexpected discovery errors must not turn an unverified
                # installed native package into a certified minimum version.
                $version = ''
                $metadataDiscoveryFailed = $true
            }
            $minimumVersion = if (
                $ForProfile -ceq 'Standalone' -and
                $script:DefenseClawWindowsAgentVersionMinimum.ContainsKey($c)
            ) {
                $script:DefenseClawWindowsAgentVersionMinimum[$c]
            }
            else {
                ''
            }
            $version = Resolve-DefenseClawConnectorMetadataVersion `
                -DiscoveredVersion $version `
                -MinimumVersion $minimumVersion `
                -NativeCandidateObserved $nativeCandidateObserved `
                -DiscoveryFailed $metadataDiscoveryFailed
            [void]$sb.AppendLine("  - user: `"$($u.UserName -replace '"','\"')`"")
            [void]$sb.AppendLine("    user_home: `"$($u.UserHome -replace '"','\"' -replace '\\','\\')`"")
            [void]$sb.AppendLine("    sid: `"$($u.SID)`"")
            [void]$sb.AppendLine("    connector: `"$c`"")
            $bestEffortConnector = $ForProfile -cne 'Standalone' -and
                $c -cin $script:DefenseClawWindowsManagedEnterpriseSupportedConnectors
            if ([string]::IsNullOrWhiteSpace($version) -and
                -not $bestEffortConnector) {
                # Not a Windows managed connector (nothing can hook it), or a
                # standalone row the manifest would refuse without a version.
                [void]$sb.AppendLine('    enabled: false')
            }
            else {
                if (-not [string]::IsNullOrWhiteSpace($version)) {
                    [void]$sb.AppendLine("    agent_version: `"$version`"")
                }
                else {
                    # An installed agent whose version or signature could
                    # not be verified is still hooked: an empty version
                    # selects the best-effort hook contract. A row written
                    # disabled here would stay disabled forever, because
                    # the Guardian enumerator keeps the previous row's
                    # enabled state.
                    Add-DefenseClawBootstrapResilienceEvent `
                        -Marker defenseclaw_accept `
                        -Fields @{
                            connector = $c
                            sid       = [string]$u.SID
                            reason    = 'agent version could not be verified; enabling the target with the best-effort hook contract'
                        }
                }
                [void]$sb.AppendLine('    enabled: true')
                if ($deferTarget) {
                    [void]$sb.AppendLine('    deferred: true')
                }
            }
        }
    }
    return $sb.ToString()
}

function Add-DefenseClawLifecycleFailureEvidence {
    <#
        A failed standalone lifecycle attaches what it knows about recovery to
        its exception: whether the transaction is still pending, each managed-
        hook lifecycle step recovery ran with the Setup's verified gateway,
        why it declined to, and what the rollback of a failed first install
        could not remove. Copy exactly those fields onto the failure
        document. The Secure Client lifecycle attaches none of them, so its
        failure document is unchanged.
    #>
    param(
        [Parameter(Mandatory)][psobject]$Document,
        [AllowNull()][Collections.IDictionary]$Evidence
    )
    if ($null -eq $Evidence) {
        return
    }
    foreach ($field in @(
        @('DefenseClaw.TransactionPending', 'transaction_pending'),
        @('DefenseClaw.RecoveryGatewayRuns', 'recovery_gateway_runs'),
        @('DefenseClaw.RecoveryGatewayRefusal', 'recovery_gateway_refusal'),
        @('DefenseClaw.RollbackLeftovers', 'rollback_leftovers')
    )) {
        if ($Evidence.Contains([string]$field[0])) {
            Microsoft.PowerShell.Utility\Add-Member `
                -InputObject $Document `
                -MemberType NoteProperty `
                -Name ([string]$field[1]) `
                -Value $Evidence[[string]$field[0]] `
                -Force
        }
    }
}

$bootstrapEnvironment = $null
$result = $null
$failureMessage = $null
$failureEvidence = $null
$exitCode = 0
try {
    if ($DeferredConfig -and $Action -ne 'Install') {
        throw '-DeferredConfig is valid only with Install'
    }
    if ($DeferredConfig -and
        (-not [string]::IsNullOrWhiteSpace($Config) -or
            -not [string]::IsNullOrWhiteSpace($Manifest))) {
        throw '-DeferredConfig cannot be combined with -Config or -Manifest'
    }
    $bootstrapEnvironment = New-DefenseClawBootstrapEnvironment
    $modulePath = [IO.Path]::GetFullPath(
        [IO.Path]::Combine($PSScriptRoot, 'DefenseClawEnterprise.psm1')
    )
    Assert-DefenseClawBootstrapLifecycleScope `
        -LifecycleAction $Action `
        -RequestedInstallRoot $InstallRoot `
        -RequestedStateRoot $StateRoot `
        -RequestedGatewayServiceName $GatewayServiceName `
        -RequestedGuardianServiceName $GuardianServiceName `
        -AllowUnsignedLifecycle ([bool]$AllowUnsigned)
    if ($SelfUninstallCallerPID -lt 0 -or
        ($SelfUninstallCallerPID -gt 0 -and $Action -ne 'Uninstall')) {
        throw '-SelfUninstallCallerPID is valid only as a positive PID with Uninstall'
    }
    if ($AllowUnsigned) {
        Assert-DefenseClawBootstrapUnsignedCertificationScope `
            -LifecycleAction $Action `
            -RequestedInstallRoot $InstallRoot `
            -RequestedStateRoot $StateRoot `
            -RequestedGatewayServiceName $GatewayServiceName `
            -RequestedGuardianServiceName $GuardianServiceName `
            -RequestedCertificationCodexHome $CertificationCodexHome
    }
    elseif (-not [string]::IsNullOrWhiteSpace($CertificationCodexHome)) {
        throw '-CertificationCodexHome requires -AllowUnsigned for every lifecycle action'
    }
    if ($CoreHardeningCertification -and
        $Action -notin @('Install', 'Upgrade', 'Repair', 'Recover')) {
        throw '-CoreHardeningCertification is valid only with Install, Upgrade, Repair, or Recover'
    }
    if ($CoreHardeningCertification -and
        (-not $AllowUnsigned -or
            [string]::IsNullOrWhiteSpace($CertificationCodexHome))) {
        throw '-CoreHardeningCertification requires -AllowUnsigned and -CertificationCodexHome'
    }
    if ($CoreHardeningCertification -and
        ($AttestAgentApplicationControl -or
            $AttestClaudeEffectivePolicy)) {
        throw (
            '-CoreHardeningCertification cannot be combined with production ' +
            'application-control or Claude-policy attestations'
        )
    }
    # -Mode / -Connector shorthand handling. Validated + rendered BEFORE
    # the module import so a bad grammar surfaces the error at the
    # bootstrap boundary rather than deep inside the transaction. The
    # rendered YAML lands in the bootstrap environment's protected
    # SYSTEM/Administrators-only directory (same path Setup.exe uses for
    # its embedded payload staging), so the module reads them under the
    # same trust invariants as an operator-supplied -Config / -Manifest.
    $modeSupplied = -not [string]::IsNullOrWhiteSpace($Mode)
    $connectorSupplied = -not [string]::IsNullOrWhiteSpace($Connector)
    if ($modeSupplied -xor $connectorSupplied) {
        throw '-Mode and -Connector must be supplied together (they are the QA shorthand pair)'
    }
    if ($modeSupplied -and (-not [string]::IsNullOrWhiteSpace($Config) -or
            -not [string]::IsNullOrWhiteSpace($Manifest))) {
        throw '-Mode / -Connector are mutually exclusive with -Config / -Manifest'
    }
    if ($modeSupplied -and [bool]$DeferredConfig) {
        throw '-Mode / -Connector cannot be combined with -DeferredConfig'
    }
    if ($modeSupplied -and $Action -ne 'Install' -and $Action -ne 'Upgrade' -and $Action -ne 'Repair') {
        throw '-Mode / -Connector are valid only with Install, Upgrade, or Repair'
    }
    if ($DeferredConfig) {
        # Use a real, valid managed-enterprise policy and an empty target set so
        # the ordinary authenticated install transaction can establish every
        # machine artifact and ACL. All services remain disabled. A later
        # Repair with both real inputs performs target preparation and the
        # guardian-first service activation transaction.
        $renderRoot = $bootstrapEnvironment.Path
        $deferredConnectors = @('codex')
        $deferredConfigPath = [IO.Path]::Combine(
            $renderRoot, 'deferred-config-placeholder.yaml'
        )
        $deferredManifestPath = [IO.Path]::Combine(
            $renderRoot, 'deferred-targets-placeholder.yaml'
        )
        [IO.File]::WriteAllText(
            $deferredConfigPath,
            (Get-DefenseClawRenderedEnterpriseConfig `
                -Mode observe -Connectors $deferredConnectors),
            [Text.UTF8Encoding]::new($false)
        )
        [IO.File]::WriteAllText(
            $deferredManifestPath,
            (Get-DefenseClawRenderedEnterpriseTargets `
                -Connectors $deferredConnectors -Profiles @() `
                -ForProfile $EnterpriseProfile),
            [Text.UTF8Encoding]::new($false)
        )
        foreach ($renderedPath in @($deferredConfigPath, $deferredManifestPath)) {
            Set-DefenseClawBootstrapRenderedFileOwner `
                -Path $renderedPath `
                -Context $bootstrapEnvironment
        }
        $Config = $deferredConfigPath
        $Manifest = $deferredManifestPath
    }
    if ($modeSupplied) {
        $renderedConnectors = ConvertTo-DefenseClawConnectorList -Connector $Connector
        $renderedConfigBody = Get-DefenseClawRenderedEnterpriseConfig `
            -Mode $Mode -Connectors $renderedConnectors `
            -ForProfile $EnterpriseProfile
        $renderedManifestBody = Get-DefenseClawRenderedEnterpriseTargets `
            -Connectors $renderedConnectors `
            -DeferInactiveProfiles:($Action -in @(
                    'Install', 'Upgrade', 'Repair'
                ) -and -not $NoStart) `
            -ForProfile $EnterpriseProfile
        $renderRoot = $bootstrapEnvironment.Path
        $renderedConfigPath = [IO.Path]::Combine($renderRoot, 'rendered-config.yaml')
        $renderedManifestPath = [IO.Path]::Combine($renderRoot, 'rendered-targets.yaml')
        [IO.File]::WriteAllText(
            $renderedConfigPath, $renderedConfigBody, [Text.UTF8Encoding]::new($false)
        )
        [IO.File]::WriteAllText(
            $renderedManifestPath, $renderedManifestBody, [Text.UTF8Encoding]::new($false)
        )
        foreach ($renderedPath in @($renderedConfigPath, $renderedManifestPath)) {
            Set-DefenseClawBootstrapRenderedFileOwner `
                -Path $renderedPath `
                -Context $bootstrapEnvironment
        }
        $Config = $renderedConfigPath
        $Manifest = $renderedManifestPath
    }
    $bootstrapPinnedModuleSHA256 = ''
    $script:DefenseClawBootstrapUnreadableRecord = ''
    if ($EnterpriseProfile -ceq 'Standalone' -and $TrustMode -ceq 'HashPinned') {
        if ([string]::IsNullOrWhiteSpace($PayloadManifest)) {
            throw '-TrustMode HashPinned requires -PayloadManifest'
        }
        # The manifest is the trust anchor for the unsigned module, so it must
        # pass the same local-NTFS, no-reparse, administrator-owned chain.
        $manifestFull = Assert-DefenseClawBootstrapModuleTrust `
            -Path $PayloadManifest `
            -AllowUnsignedModule
        $manifestDocument = Microsoft.PowerShell.Management\Get-Content `
            -LiteralPath $manifestFull `
            -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
        $moduleEntry = $null
        if ($null -ne $manifestDocument.PSObject.Properties['files']) {
            $moduleEntry = $manifestDocument.files.PSObject.Properties['DefenseClawEnterprise.psm1']
        }
        if ($null -eq $moduleEntry -or
            ([string]$moduleEntry.Value) -cnotmatch '^[0-9A-Fa-f]{64}$') {
            throw 'payload SHA-256 manifest does not pin DefenseClawEnterprise.psm1'
        }
        $bootstrapPinnedModuleSHA256 = [string]$moduleEntry.Value
    }
    elseif ($EnterpriseProfile -ceq 'Standalone' -and
        $TrustMode -ceq 'Authenticode' -and
        [string]::IsNullOrWhiteSpace($PayloadManifest) -and
        $Action -cne 'Install' -and
        -not $AllowUnsigned) {
        # Nothing keeps a payload manifest after a hash-pinned install, so the
        # installed CLI (Add/Remove Programs, MDM detect and uninstall
        # scripts) arrives here with no pin. Admit the installed module by the
        # digest the deployment's protected metadata recorded; the module then
        # re-admits the rest of its installed payload the same way.
        $bootstrapPinnedModuleSHA256 = Get-DefenseClawBootstrapRecordedModulePin `
            -MetadataPath ([IO.Path]::Combine($StateRoot, 'install', 'deployment.json')) `
            -InstallerPath $PSCommandPath
    }
    $bootstrapAllowedSigners = @()
    if ($EnterpriseProfile -ceq 'Standalone') {
        foreach ($signer in @(([string]$AllowedSigners).Split(','))) {
            $value = ([string]$signer).Trim().ToLowerInvariant()
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                if ($value -cnotmatch '^[0-9a-f]{64}$') {
                    throw "allowed signer must be a SHA-256 certificate thumbprint: $signer"
                }
                $bootstrapAllowedSigners += $value
            }
        }
    }
    try {
        $modulePath = Assert-DefenseClawBootstrapModuleTrust `
            -Path $modulePath `
            -AllowUnsignedModule:$AllowUnsigned `
            -PinnedSHA256 $bootstrapPinnedModuleSHA256 `
            -AllowedSignerSHA256 $bootstrapAllowedSigners
    }
    catch {
        $rejection = [string]$_.Exception.Message
        if (-not [string]::IsNullOrEmpty($script:DefenseClawBootstrapUnreadableRecord) -and
            $rejection.Contains('Authenticode signature is not valid')) {
            # The module of a hash-pinned deployment is unsigned: only the
            # digest in its deployment record admits it. A damaged record is
            # the cause, not the signature, and Setup /repair rebuilds it from
            # its own payload (GAP-0164), as the module says for ensure.
            throw ("DefenseClaw enterprise installer rejected its module before import: " +
                "could not read the installed deployment metadata $($script:DefenseClawBootstrapUnreadableRecord), " +
                'which holds the digest this deployment admits its installed module by; nothing was changed. ' +
                'Run Setup /repair to rebuild it: the installed release''s DefenseClawSetup-Enterprise-Standalone-x64.exe /repair JSON=1, ' +
                'as LocalSystem or from an elevated prompt')
        }
        throw "DefenseClaw enterprise installer rejected its module before import: $rejection"
    }
    # This is the last path-identity check before PowerShell opens the module.
    $importRoot = [IO.Path]::GetPathRoot($modulePath)
    $importDrive = $importRoot.TrimEnd('\')
    $bootstrapNativePath = Initialize-DefenseClawBootstrapNativePath
    $bootstrapNativePath::AssertCanonicalDriveRoot(
        $importRoot,
        $importDrive
    )
    try {
        Microsoft.PowerShell.Core\Import-Module `
            -Name $modulePath `
            -Force `
            -ErrorAction Stop
    }
    catch {
        # AMSI or a code-integrity policy can refuse the module itself; name
        # it from the error ID or code rather than from localized text.
        $classified = Get-DefenseClawBootstrapAddTypeFailure `
            -ErrorRecord $_ `
            -Check 'powershell_module_import' `
            -Path $modulePath
        if (-not [string]::IsNullOrWhiteSpace($classified)) {
            throw $classified
        }
        throw
    }
    finally {
        Close-DefenseClawBootstrapModuleHandle
    }

    $arguments = @{
        Action = $Action
        BrokerBinary = $BrokerBinary
        ProviderLibrary = $ProviderLibrary
        GatewayBinary = $GatewayBinary
        ACPBinary = $ACPBinary
        HookBinary = $HookBinary
        SensorHelperBinary = $SensorHelperBinary
        PolicyCompiler = $PolicyCompiler
        CLIBinary = $CLIBinary
        NativeCleanupBinary = $NativeCleanupBinary
        Config = $Config
        Manifest = $Manifest
        InstallRoot = $InstallRoot
        StateRoot = $StateRoot
        GatewayServiceName = $GatewayServiceName
        GuardianServiceName = $GuardianServiceName
        CertificationCodexHome = $CertificationCodexHome
        CoreHardeningCertification = [bool]$CoreHardeningCertification
        NoStart = [bool]$NoStart
        Purge = [bool]$Purge
        AttestAgentApplicationControl = [bool]$AttestAgentApplicationControl
        AttestClaudeEffectivePolicy = [bool]$AttestClaudeEffectivePolicy
        SelfUninstallCallerPID = $SelfUninstallCallerPID
        # The exact service/root/CODEX_HOME grammar scopes this relaxation for
        # every certification lifecycle action, including pre-install Status.
        AllowUnsigned = [bool]$AllowUnsigned
        # Marks the protected installed metadata as awaiting a complete Repair;
        # the module keeps every managed service disabled until then.
        DeferredConfig = [bool]$DeferredConfig
        InstallerSource = $PSCommandPath
        ModuleSource = $modulePath
        EnterpriseProfile = $EnterpriseProfile
    }
    if ($EnterpriseProfile -ceq 'Standalone') {
        $arguments['TrustMode'] = $TrustMode
        $arguments['PayloadManifest'] = $PayloadManifest
        $arguments['AllowedSigners'] = [string[]]$bootstrapAllowedSigners
        $arguments['ProductVersion'] = $ProductVersion
        # The launching CLI's protected temp folder, which the purge's stale
        # temp sweep must keep (GAP-1853); TEMP now points at the bootstrap.
        $arguments['LauncherTemp'] = [string]$bootstrapEnvironment.OriginalEnvironment['TEMP']
        # Setup /uninstall FORCE=1 (enterprise windows uninstall --force), the
        # last resort that removes the deployment without reading its pending
        # transaction (Invoke-DefenseClawForcedUninstallPreparation). The CLI
        # asks for it in the strict environment it builds for the standalone
        # engine, not with a parameter: the parameter set above is the command
        # line of the Secure Client installer and stays unchanged. Cleared here
        # so no child process inherits it.
        $forcedUninstallRequest = [Environment]::GetEnvironmentVariable('DEFENSECLAW_STANDALONE_FORCED_UNINSTALL', 'Process')
        [Environment]::SetEnvironmentVariable('DEFENSECLAW_STANDALONE_FORCED_UNINSTALL', $null, 'Process')
        if ($Action -eq 'Uninstall' -and $forcedUninstallRequest -ceq '1') {
            $arguments['Force'] = $true
        }
        # An ensure that found the deployment compliant asks its Verify, the
        # same way, to collect old managed runtime generations (GAP-0211).
        $collectRequest = [Environment]::GetEnvironmentVariable('DEFENSECLAW_STANDALONE_COLLECT_RUNTIME_GENERATIONS', 'Process')
        [Environment]::SetEnvironmentVariable('DEFENSECLAW_STANDALONE_COLLECT_RUNTIME_GENERATIONS', $null, 'Process')
        if ($Action -eq 'Verify' -and $collectRequest -ceq '1') {
            $arguments['CollectRuntimeGenerations'] = $true
        }
    }
    $result = DefenseClawEnterprise\Invoke-DefenseClawEnterpriseLifecycle @arguments
    # A kit rotation journal the uninstall kept or left is named in the
    # result, so the Setup and CLI JSON carry it (GAP-1913).
    if ($Action -eq 'Uninstall' -and $null -ne $result -and
        $null -ne (Microsoft.PowerShell.Core\Get-Command -Name 'DefenseClawEnterprise\Get-DefenseClawMdmRotationJournalKept' -ErrorAction SilentlyContinue)) {
        $journalKept = [string](DefenseClawEnterprise\Get-DefenseClawMdmRotationJournalKept)
        if (-not [string]::IsNullOrWhiteSpace($journalKept)) {
            $result |
                Microsoft.PowerShell.Utility\Add-Member `
                    -MemberType NoteProperty `
                    -Name mdm_rotation_journal_kept `
                    -Value $journalKept `
                    -Force
        }
    }
    if ($null -ne $result.PSObject.Properties['ok'] -and -not [bool]$result.ok) {
        $exitCode = 1
    }
}
catch {
    $failureMessage = $_.Exception.Message
    $failureEvidence = $_.Exception.Data
    $exitCode = 1
}
finally {
    try {
        Close-DefenseClawBootstrapModuleHandle
    }
    catch {
    }
    if ($null -ne $bootstrapEnvironment) {
        $cleanupFailures = [Collections.Generic.List[string]]::new()
        # Restore TEMP/TMP and cache env vars BEFORE the tree they still
        # point into gets removed. Otherwise any temp file created during
        # the enumeration window of Remove-DefenseClawBootstrapEnvironment
        # can trip Directory.Delete or its final leftover-check. The
        # failure path inside New-DefenseClawBootstrapEnvironment already
        # uses this safer order.
        try {
            Restore-DefenseClawBootstrapEnvironment `
                -Context $bootstrapEnvironment
        }
        catch {
            $cleanupFailures.Add(
                "bootstrap environment restore failed: $($_.Exception.Message)"
            )
        }
        try {
            Remove-DefenseClawBootstrapEnvironment `
                -Context $bootstrapEnvironment
        }
        catch {
            $cleanupFailures.Add(
                "protected bootstrap cleanup failed: $($_.Exception.Message)"
            )
        }
        if ($cleanupFailures.Count -gt 0) {
            $cleanupDetail = $cleanupFailures -join '; '
            if ([string]::IsNullOrWhiteSpace($failureMessage)) {
                # Leave the action's own exit code alone: tidying our temp tree
                # is not part of its outcome, and ok:false already set the code.
                Microsoft.PowerShell.Utility\Write-Warning -Message $cleanupDetail
            }
            else {
                $failureMessage += "; $cleanupDetail"
                $exitCode = 1
            }
        }
    }
}

# Drift the bootstrap accepted before the module took over travels in the
# verdict: appended to errors[] on failure, and on success to a warnings[]
# the result already carries. A result without one keeps its exact shape;
# the events go to stderr, which Setup keeps off its JSON stdout.
$bootstrapResilienceEvents = @($script:DefenseClawBootstrapResilienceEvents.ToArray())
if (-not [string]::IsNullOrWhiteSpace($failureMessage)) {
    if ($Json) {
        $failureDocument = [pscustomobject]@{
            schema_version = 1
            ok = $false
            action = $Action.ToLowerInvariant()
            error = $failureMessage
            errors = @(@($failureMessage) + $bootstrapResilienceEvents)
        }
        Add-DefenseClawLifecycleFailureEvidence `
            -Document $failureDocument `
            -Evidence $failureEvidence
        $failureDocument | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 6 -Compress
    }
    else {
        Microsoft.PowerShell.Utility\Write-Error `
            -ErrorAction Continue `
            -Message (
                "DefenseClaw Windows enterprise {0} failed: {1}" -f
                $Action.ToLowerInvariant(),
                $failureMessage
            )
    }
}
elseif ($Json) {
    if ($bootstrapResilienceEvents.Count -gt 0 -and $null -ne $result) {
        $warningsProperty = $result.PSObject.Properties['warnings']
        if ($null -ne $warningsProperty -and $null -ne $warningsProperty.Value) {
            $result | Microsoft.PowerShell.Utility\Add-Member `
                -MemberType NoteProperty `
                -Name warnings `
                -Value @(@($warningsProperty.Value) + $bootstrapResilienceEvents) `
                -Force
        }
        else {
            foreach ($bootstrapEvent in $bootstrapResilienceEvents) {
                [Console]::Error.WriteLine([string]$bootstrapEvent)
            }
        }
    }
    $result | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 12 -Compress
}
else {
    $resultState = if ($null -ne $result -and
        $null -ne $result.PSObject.Properties['ok'] -and
        -not [bool]$result.ok) {
        'INCOMPLETE'
    }
    else {
        'OK'
    }
    Microsoft.PowerShell.Utility\Write-Host (
        "DefenseClaw Windows enterprise {0}: {1}" -f
        $Action.ToLowerInvariant(), $resultState
    )
    foreach ($line in $bootstrapResilienceEvents) {
        Microsoft.PowerShell.Utility\Write-Warning -Message ([string]$line)
    }
    # Not every action's result carries every field; StrictMode throws on a
    # missing property, so each one is read through PSObject.Properties.
    $summaryValue = {
        param([string]$Name)
        if ($null -eq $result) {
            return $null
        }
        $property = $result.PSObject.Properties[$Name]
        if ($null -eq $property) {
            return $null
        }
        return $property.Value
    }
    if ($resultState -eq 'INCOMPLETE') {
        foreach ($message in @(& $summaryValue 'errors')) {
            if (-not [string]::IsNullOrWhiteSpace([string]$message)) {
                Microsoft.PowerShell.Utility\Write-Warning -Message ([string]$message)
            }
        }
    }
    $gatewayServiceState = & $summaryValue 'gateway_service_state'
    if ($null -ne $gatewayServiceState) {
        Microsoft.PowerShell.Utility\Write-Host (
            "  Gateway service: {0}" -f $gatewayServiceState
        )
    }
    $guardianServiceState = & $summaryValue 'guardian_service_state'
    if ($null -ne $guardianServiceState) {
        Microsoft.PowerShell.Utility\Write-Host (
            "  Guardian service: {0}" -f $guardianServiceState
        )
    }
    $gatewayReady = & $summaryValue 'gateway_ready'
    if ($null -ne $gatewayReady) {
        Microsoft.PowerShell.Utility\Write-Host (
            "  Gateway health probe: {0}" -f $gatewayReady
        )
    }
    if ([bool](& $summaryValue 'self_uninstall_cleanup_pending')) {
        Microsoft.PowerShell.Utility\Write-Host (
            '  Installed CLI cleanup: pending until this CLI process exits'
        )
    }
    $deferredRetirement = & $summaryValue 'install_root_retirement_deferred'
    if (-not [string]::IsNullOrWhiteSpace([string]$deferredRetirement)) {
        Microsoft.PowerShell.Utility\Write-Warning -Message (
            'Install folder cleanup is pending: ' + [string]$deferredRetirement
        )
    }
    if ([bool](& $summaryValue 'cached_enterprise_clients_require_reload')) {
        Microsoft.PowerShell.Utility\Write-Host (
            '  Enterprise clients already running during uninstall must reload'
        )
    }
    $guardianReady = & $summaryValue 'guardian_ready'
    if ($null -ne $guardianReady) {
        Microsoft.PowerShell.Utility\Write-Host (
            "  Guardian coverage: {0}" -f $guardianReady
        )
    }
}
if ($exitCode -ne 0) {
    exit $exitCode
}
