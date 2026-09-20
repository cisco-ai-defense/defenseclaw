#Requires -Version 7.4
[CmdletBinding()]
param(
    [ValidateSet('run', 'restore')]
    [string]$Operation = 'run',
    [string]$WorkspaceRoot = '',
    [string]$StateRoot = '',
    [string]$ResultsPath = '',
    [string]$ArtifactPath = '',
    [string]$PackagedSetupPath = '',
    [string]$ExpectedPackagedSetupSHA256 = '',
    [string]$ExpectedPackagedSetupProvenanceSHA256 = '',
    [string]$ExpectedPackageSourceCommit = '',
    [string]$ExpectedHarnessSourceCommit = '',
    [string]$ExpectedPackageRunID = '',
    [string]$ExpectedPackageArtifactID = '',
    [string]$ExpectedPackageArtifactDigest = '',
    [string]$ExpectedWorkflowRepository = '',
    [string]$AgentPath = '',
    [string]$ExpectedAgentVersion = '1.0.77',
    [string]$BaselineManifestPath = '',
    [string]$ExpectedBaselineManifestSHA256 = '',
    [string]$ExpectedLocalProtectedCopilotAuthorizerSHA256 = '',
    [switch]$NoRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:LocalAuthorizerPath = [IO.Path]::GetFullPath($PSCommandPath)
$script:LocalDerivedFingerprintNames = @('active_connector', 'hook_contract_lock')
$script:LocalExpectedFingerprintNames = @(
    'install_state', 'active_connector', 'hook_contract_lock', 'config',
    'watchdog_state', 'claude_settings', 'codex_config',
    'codex_managed_config', 'codex_hooks', 'cursor_hooks',
    'omnigent_config', 'copilot_hook', 'maintenance_setup'
)
$script:LocalExpectedRoster = @(
    'claudecode|action|closed|True|manual',
    'codex|observe|open|True|manual',
    'cursor|action|closed|True|manual',
    'omnigent|observe|open|True|manual'
)
$script:LocalCapability = ''
$script:LocalCapabilitySHA256 = ''
$script:LocalTransactionPath = ''
$script:LocalRestoreCapabilityRecord = $null

function Initialize-LocalWindowsNativeSupport {
    if ($null -ne ('DefenseClaw.CopilotLocalNative' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace DefenseClaw {
    public static class CopilotLocalNative {
        private const uint FileReadAttributes = 0x00000080;
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint FileShareDelete = 0x00000004;
        private const uint OpenExisting = 3;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const int SystemBootEnvironmentInformation = 90;
        private const int ProcessTelemetryIdInformation = 64;
        private const int ProcessTelemetryBufferSize = 64 << 10;

        [StructLayout(LayoutKind.Sequential)]
        private struct SystemBootEnvironmentInformationValue {
            internal Guid BootIdentifier;
            internal uint FirmwareType;
            internal ulong BootFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessTelemetryIdInformationValue {
            internal uint HeaderSize;
            internal uint ProcessID;
            internal ulong ProcessStartKey;
            internal ulong CreateTime;
            internal ulong CreateInterruptTime;
            internal ulong CreateUnbiasedInterruptTime;
            internal ulong ProcessSequenceNumber;
            internal ulong SessionCreateTime;
            internal uint SessionID;
            internal uint BootID;
            internal uint ImageChecksum;
            internal uint ImageTimeDateStamp;
            internal uint UserSIDOffset;
            internal uint ImagePathOffset;
            internal uint PackageNameOffset;
            internal uint RelativeAppNameOffset;
            internal uint CommandLineOffset;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(
            SafeFileHandle file,
            StringBuilder path,
            uint pathLength,
            uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetShortPathNameW(
            string longPath,
            StringBuilder shortPath,
            uint pathLength);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentProcessId();

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(
            int informationClass,
            ref SystemBootEnvironmentInformationValue information,
            uint informationLength,
            out uint returnLength);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(
            IntPtr process,
            int informationClass,
            IntPtr information,
            uint informationLength,
            out uint returnLength);

        public static string GetFinalPath(string path) {
            using (SafeFileHandle handle = CreateFileW(
                path,
                FileReadAttributes,
                FileShareRead | FileShareWrite | FileShareDelete,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics,
                IntPtr.Zero)) {
                if (handle.IsInvalid) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                int capacity = 512;
                while (true) {
                    StringBuilder result = new StringBuilder(capacity);
                    uint length = GetFinalPathNameByHandleW(
                        handle, result, (uint)result.Capacity, 0);
                    if (length == 0) {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    if (length < result.Capacity) {
                        string value = result.ToString();
                        if (value.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) {
                            return @"\\" + value.Substring(8);
                        }
                        if (value.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)) {
                            return value.Substring(4);
                        }
                        return value;
                    }
                    capacity = checked((int)length + 1);
                }
            }
        }

        public static string GetShortPath(string path) {
            int capacity = 512;
            while (true) {
                StringBuilder result = new StringBuilder(capacity);
                uint length = GetShortPathNameW(path, result, (uint)result.Capacity);
                if (length == 0) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                if (length < result.Capacity) {
                    return result.ToString();
                }
                capacity = checked((int)length + 1);
            }
        }

        public static string GetBootEnvironmentIdentifier() {
            SystemBootEnvironmentInformationValue information =
                new SystemBootEnvironmentInformationValue();
            uint returned;
            int status = NtQuerySystemInformation(
                SystemBootEnvironmentInformation,
                ref information,
                (uint)Marshal.SizeOf<SystemBootEnvironmentInformationValue>(),
                out returned);
            if (status != 0) {
                throw new InvalidOperationException(
                    "NtQuerySystemInformation failed with NTSTATUS 0x" +
                    unchecked((uint)status).ToString("x8"));
            }
            if (returned != 0 &&
                returned < Marshal.SizeOf<SystemBootEnvironmentInformationValue>()) {
                throw new InvalidOperationException(
                    "Windows boot-environment response was truncated");
            }
            return information.BootIdentifier.ToString("D").ToLowerInvariant();
        }

        public static uint GetProcessTelemetryBootID() {
            IntPtr buffer = Marshal.AllocHGlobal(ProcessTelemetryBufferSize);
            try {
                uint returned;
                int status = NtQueryInformationProcess(
                    GetCurrentProcess(),
                    ProcessTelemetryIdInformation,
                    buffer,
                    ProcessTelemetryBufferSize,
                    out returned);
                if (status != 0) {
                    throw new InvalidOperationException(
                        "NtQueryInformationProcess failed with NTSTATUS 0x" +
                        unchecked((uint)status).ToString("x8"));
                }
                int fixedSize = Marshal.SizeOf<ProcessTelemetryIdInformationValue>();
                if (returned < fixedSize || returned > ProcessTelemetryBufferSize) {
                    throw new InvalidOperationException(
                        "Windows process-telemetry response length is invalid");
                }
                ProcessTelemetryIdInformationValue information =
                    Marshal.PtrToStructure<ProcessTelemetryIdInformationValue>(buffer);
                if (information.HeaderSize < fixedSize ||
                    information.HeaderSize > returned ||
                    information.ProcessID != GetCurrentProcessId()) {
                    throw new InvalidOperationException(
                        "Windows process-telemetry identity is invalid");
                }
                return information.BootID;
            } finally {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }
}
'@
}

function Clear-LocalAmbientCredentials {
    # Blank inherited token credentials without ever reading or logging them.
    Remove-Item Env:GH_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:COPILOT_GITHUB_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:DC_COPILOT_LOCAL_CAPABILITY -ErrorAction SilentlyContinue
}

function New-LocalCapability {
    $bytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    $script:LocalCapability = [Convert]::ToHexString($bytes).ToLowerInvariant()
    $script:LocalCapabilitySHA256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes($script:LocalCapability)
        )
    ).ToLowerInvariant()
}

function Clear-LocalCapability {
    $script:LocalCapability = ''
    Remove-Item Env:DC_COPILOT_LOCAL_CAPABILITY -ErrorAction SilentlyContinue
}

function Get-LocalCapabilityEntropy {
    return [Text.Encoding]::UTF8.GetBytes(
        "$ExpectedLocalProtectedCopilotAuthorizerSHA256`n$ExpectedBaselineManifestSHA256"
    )
}

function New-LocalRestoreCapabilityFile(
    [string]$TransactionRoot,
    [string]$NamePrefix
) {
    $plain = [Convert]::ToHexString(
        [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    ).ToLowerInvariant()
    $plainBytes = [Text.Encoding]::UTF8.GetBytes($plain)
    $ciphertext = [Security.Cryptography.ProtectedData]::Protect(
        $plainBytes, (Get-LocalCapabilityEntropy),
        [Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    $path = Join-Path $TransactionRoot "$NamePrefix.restore.cap"
    if (Test-Path -LiteralPath $path) {
        throw 'protected local restore capability path already exists'
    }
    [IO.File]::WriteAllBytes($path, $ciphertext)
    Assert-LocalPlainPath $path $TransactionRoot
    return [pscustomobject]@{
        Path = [IO.Path]::GetFullPath($path)
        PlainSHA256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($plainBytes)
        ).ToLowerInvariant()
        CiphertextSHA256 = Get-LocalSHA256 $path
    }
}

function Use-LocalRestoreCapability([object]$Transaction) {
    $path = [IO.Path]::GetFullPath([string]$Transaction.restore_capability_path)
    $transactionRoot = Split-Path -Parent $script:LocalTransactionPath
    Assert-LocalPlainPath $path $transactionRoot
    if ((Get-LocalSHA256 $path) -cne
        [string]$Transaction.restore_capability_ciphertext_sha256) {
        throw 'protected local restore capability ciphertext drifted'
    }
    try {
        $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect(
            [IO.File]::ReadAllBytes($path), (Get-LocalCapabilityEntropy),
            [Security.Cryptography.DataProtectionScope]::CurrentUser
        )
    } catch {
        throw 'protected local restore capability is not decryptable by the authenticated current SID'
    }
    $plain = [Text.Encoding]::UTF8.GetString($plainBytes)
    $digest = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($plainBytes)
    ).ToLowerInvariant()
    if ($plain -cnotmatch '^[0-9a-f]{64}$' -or
        $digest -cne [string]$Transaction.restore_capability_sha256) {
        throw 'protected local restore capability plaintext identity is invalid'
    }
    $script:LocalCapability = $plain
    $script:LocalCapabilitySHA256 = $digest
}

function Get-LocalSHA256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-LocalCanonicalPath([string]$Path) {
    Initialize-LocalWindowsNativeSupport
    $fullPath = [IO.Path]::GetFullPath($Path)
    $existing = $fullPath
    while (-not (Test-Path -LiteralPath $existing)) {
        $parent = Split-Path -Parent $existing
        if ([string]::IsNullOrWhiteSpace($parent) -or
            [string]::Equals($parent, $existing, [StringComparison]::OrdinalIgnoreCase)) {
            throw "protected local path has no canonical existing ancestor: $fullPath"
        }
        $existing = $parent
    }
    $canonical = [DefenseClaw.CopilotLocalNative]::GetFinalPath($existing)
    if (-not [string]::Equals($existing, $fullPath,
            [StringComparison]::OrdinalIgnoreCase)) {
        $relative = [IO.Path]::GetRelativePath($existing, $fullPath)
        if ([IO.Path]::IsPathRooted($relative) -or
            $relative -eq '..' -or $relative.StartsWith('..\')) {
            throw 'protected local canonical path reconstruction escaped its existing ancestor'
        }
        $canonical = Join-Path $canonical $relative
    }
    return [IO.Path]::GetFullPath($canonical).TrimEnd('\')
}

function Get-LocalShortPathAlias([string]$Path) {
    Initialize-LocalWindowsNativeSupport
    return [IO.Path]::GetFullPath(
        [DefenseClaw.CopilotLocalNative]::GetShortPath(
            [IO.Path]::GetFullPath($Path)
        )
    )
}

function Test-LocalPathWithin([string]$Path, [string]$Root) {
    $fullPath = Get-LocalCanonicalPath $Path
    $rootInput = if ($Root -match '^[A-Za-z]:$') { "$Root\" } else { $Root }
    $fullRoot = Get-LocalCanonicalPath $rootInput
    return $fullPath.StartsWith($fullRoot + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Assert-LocalExactPath([string]$Actual, [string]$Expected, [string]$Context) {
    if ([string]::IsNullOrWhiteSpace($Actual) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath($Actual).TrimEnd('\'),
            [IO.Path]::GetFullPath($Expected).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "$Context path identity mismatch"
    }
}

function Assert-LocalRootsDisjoint([string[]]$Roots) {
    $resolved = @($Roots | ForEach-Object {
        Get-LocalCanonicalPath $_
    })
    for ($left = 0; $left -lt $resolved.Count; $left++) {
        for ($right = $left + 1; $right -lt $resolved.Count; $right++) {
            if ([string]::Equals($resolved[$left], $resolved[$right],
                    [StringComparison]::OrdinalIgnoreCase) -or
                (Test-LocalPathWithin $resolved[$left] $resolved[$right]) -or
                (Test-LocalPathWithin $resolved[$right] $resolved[$left])) {
                throw 'local protected Copilot workspace/state/package/baseline roots must be pairwise disjoint'
            }
        }
    }
}

function Assert-LocalPlainPath(
    [string]$Path,
    [string]$AllowedRoot,
    [switch]$Directory,
    [switch]$AllowAbsent
) {
    $fullPath = [IO.Path]::GetFullPath($Path)
    $fullRoot = [IO.Path]::GetFullPath($AllowedRoot).TrimEnd('\')
    if (-not (Test-LocalPathWithin $fullPath $fullRoot) -and
        -not ([string]::Equals($fullPath.TrimEnd('\'), $fullRoot,
            [StringComparison]::OrdinalIgnoreCase))) {
        throw "protected local path escapes its explicit custody root: '$fullPath' outside '$fullRoot'"
    }
    if (-not (Test-Path -LiteralPath $fullPath)) {
        if (-not $AllowAbsent) { throw "protected local path is missing: $fullPath" }
        $ancestor = Split-Path -Parent $fullPath
        while (-not [string]::IsNullOrWhiteSpace($ancestor) -and
            -not (Test-Path -LiteralPath $ancestor)) {
            $ancestor = Split-Path -Parent $ancestor
        }
        if ([string]::IsNullOrWhiteSpace($ancestor)) {
            throw "protected local path has no existing custody ancestor: $fullPath"
        }
        $current = Get-Item -LiteralPath $ancestor -Force
    } else {
        $current = Get-Item -LiteralPath $fullPath -Force
    }
    if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "protected local path is a reparse point: $fullPath"
    }
    $targetExists = Test-Path -LiteralPath $fullPath
    if ($targetExists -and $Directory -and -not $current.PSIsContainer) {
        throw "protected local path is not a directory: $fullPath"
    }
    if ($targetExists -and -not $Directory -and $current.PSIsContainer) {
        throw "protected local path is not a file: $fullPath"
    }
    while ($null -ne $current -and
        (Test-LocalPathWithin $current.FullName $fullRoot)) {
        if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "protected local ancestor is a reparse point: $($current.FullName)"
        }
        $parentPath = Split-Path -Parent $current.FullName
        if ([string]::IsNullOrWhiteSpace($parentPath)) { break }
        $current = Get-Item -LiteralPath $parentPath -Force
    }
}

function Get-LocalFileFingerprint([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "baseline fingerprint target is not a plain file: $Path"
    }
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group -bor
        [Security.AccessControl.AccessControlSections]::Access
    $security = [IO.FileSystemAclExtensions]::GetAccessControl($item, $sections)
    return [pscustomobject]@{
        Path = [IO.Path]::GetFullPath($Path)
        Exists = $true
        Length = [long]$item.Length
        Attributes = [int]$item.Attributes
        SHA256 = Get-LocalSHA256 $Path
        Owner = [string]$security.GetOwner([Security.Principal.NTAccount])
        SDDL = $security.GetSecurityDescriptorSddlForm($sections)
    }
}

function Assert-LocalFileFingerprint(
    [object]$Expected,
    [string]$Context
) {
    $path = [IO.Path]::GetFullPath([string]$Expected.path)
    if (-not [bool]$Expected.exists) {
        if (Test-Path -LiteralPath $path) {
            throw "$Context expected an absent path"
        }
        return
    }
    $actual = Get-LocalFileFingerprint $path
    foreach ($pair in @(
        @('Length', 'length'), @('Attributes', 'attributes'),
        @('SHA256', 'sha256'), @('Owner', 'owner'), @('SDDL', 'sddl')
    )) {
        if ([string]$actual.($pair[0]) -cne [string]$Expected.($pair[1])) {
            throw "$Context changed $($pair[1])"
        }
    }
}

function Restore-LocalDerivedFingerprint([object]$Baseline, [string]$Name) {
    if ($Name -notin $script:LocalDerivedFingerprintNames) {
        throw 'only authenticated runtime-derived fingerprints may be restored from sealed copies'
    }
    $expected = $Baseline.fingerprints.$Name
    $copy = $Baseline.copies.$Name
    if (-not [bool]$expected.exists -or -not [bool]$copy.exists) {
        throw "runtime-derived sealed copy is absent: $Name"
    }
    $path = [IO.Path]::GetFullPath([string]$expected.path)
    $copyPath = [IO.Path]::GetFullPath([string]$copy.path)
    $before = Get-LocalFileFingerprint $path
    foreach ($pair in @(@('Attributes', 'attributes'), @('Owner', 'owner'),
        @('SDDL', 'sddl'))) {
        if ([string]$before.($pair[0]) -cne [string]$expected.($pair[1])) {
            throw "runtime-derived security/attribute custody drifted before byte recovery: $Name"
        }
    }
    [IO.File]::WriteAllBytes($path, [IO.File]::ReadAllBytes($copyPath))
    [IO.File]::SetAttributes($path, [IO.FileAttributes][int]$expected.attributes)
    Assert-LocalFileFingerprint $expected "sealed runtime-derived recovery $Name"
}

function Read-LocalJson([string]$Path, [string]$Context) {
    try {
        return [IO.File]::ReadAllText($Path) | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "$Context is invalid JSON: $($_.Exception.Message)"
    }
}

function Assert-LocalPackageProvenance([string]$SetupPath) {
    $provenancePath = "$SetupPath.provenance.json"
    $packageRoot = Split-Path -Parent ([IO.Path]::GetFullPath($SetupPath))
    Assert-LocalPlainPath $provenancePath $packageRoot
    $provenance = Read-LocalJson $provenancePath 'exact packaged Setup provenance'
    if ([int]$provenance.schema_version -ne 1 -or
        [string]$provenance.artifact -cne 'DefenseClawSetup-x64.exe' -or
        [string]$provenance.artifact_sha256 -cne (Get-LocalSHA256 $SetupPath) -or
        [string]$provenance.source_commit -cne $ExpectedPackageSourceCommit -or
        [string]$provenance.distribution_flavor -cne 'oss') {
        throw 'packaged Setup provenance does not bind the exact OSS artifact/source bytes'
    }
    return [pscustomobject]@{
        Path = [IO.Path]::GetFullPath($provenancePath)
        SHA256 = Get-LocalSHA256 $provenancePath
    }
}

function Assert-LocalBaselineManifestDocument(
    [object]$Manifest,
    [string]$ManifestPath,
    [string]$ManifestSHA256,
    [switch]$VerifyCopies
) {
    foreach ($field in @(
        'schema_version', 'kind', 'package_source_commit', 'hitl_claimed',
        'roster', 'opencode_active', 'doctor', 'processes', 'fingerprints', 'copies'
    )) {
        if ($null -eq $Manifest.PSObject.Properties[$field]) {
            throw "sealed baseline manifest is missing $field"
        }
    }
    if ($ManifestSHA256 -cnotmatch '^[0-9a-f]{64}$' -or
        (Get-LocalSHA256 $ManifestPath) -cne $ManifestSHA256 -or
        [int]$Manifest.schema_version -ne 1 -or
        [string]$Manifest.kind -cne 'copilot-four-connector-sealed-current' -or
        [string]$Manifest.package_source_commit -cne $ExpectedPackageSourceCommit -or
        [bool]$Manifest.hitl_claimed -or [bool]$Manifest.opencode_active) {
        throw 'sealed baseline identity, source, HITL, or OpenCode gate is invalid'
    }
    $roster = @($Manifest.roster | ForEach-Object { [string]$_ })
    if (($roster -join "`n") -cne ($script:LocalExpectedRoster -join "`n")) {
        throw 'sealed baseline does not contain the exact four-connector roster/modes'
    }
    if ([int]$Manifest.doctor.pass -ne 70 -or [int]$Manifest.doctor.fail -ne 0) {
        throw 'sealed baseline Doctor gate is not 70 pass / 0 fail'
    }
    if (@($Manifest.processes).Count -ne 2) {
        throw 'sealed baseline process topology is not the authenticated two-process topology'
    }
    $fingerprintNames = @($Manifest.fingerprints.PSObject.Properties.Name)
    $copyNames = @($Manifest.copies.PSObject.Properties.Name)
    if (($fingerprintNames | Sort-Object) -join "`n" -cne
            (($script:LocalExpectedFingerprintNames | Sort-Object) -join "`n") -or
        ($copyNames | Sort-Object) -join "`n" -cne
            (($script:LocalExpectedFingerprintNames | Sort-Object) -join "`n")) {
        throw 'sealed baseline has an incomplete or expanded fingerprint/copy inventory'
    }
    $baselineRoot = Split-Path -Parent ([IO.Path]::GetFullPath($ManifestPath))
    foreach ($name in $script:LocalExpectedFingerprintNames) {
        $fingerprint = $Manifest.fingerprints.$name
        $copy = $Manifest.copies.$name
        if ($null -eq $fingerprint -or $null -eq $copy -or
            [bool]$fingerprint.exists -ne [bool]$copy.exists) {
            throw "sealed baseline copy binding is invalid: $name"
        }
        if (-not [bool]$fingerprint.exists) { continue }
        if ([string]$fingerprint.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$copy.sha256 -cne [string]$fingerprint.sha256 -or
            [long]$copy.length -ne [long]$fingerprint.length -or
            [string]::IsNullOrWhiteSpace([string]$fingerprint.sddl)) {
            throw "sealed baseline fingerprint/copy metadata is invalid: $name"
        }
        $copyPath = [IO.Path]::GetFullPath([string]$copy.path)
        if (-not (Test-LocalPathWithin $copyPath $baselineRoot)) {
            throw "sealed baseline copy escapes the manifest root: $name"
        }
        if ($VerifyCopies) {
            Assert-LocalPlainPath $copyPath $baselineRoot
            $item = Get-Item -LiteralPath $copyPath -Force
            if ([long]$item.Length -ne [long]$copy.length -or
                (Get-LocalSHA256 $copyPath) -cne [string]$copy.sha256) {
                throw "sealed baseline protected copy drifted: $name"
            }
        }
    }
    return $Manifest
}

function Get-LocalRoster([object]$Status) {
    return @($Status.connectors | ForEach-Object {
        '{0}|{1}|{2}|{3}|{4}' -f
            [string]$_.name, [string]$_.mode, [string]$_.fail_mode,
            [bool]$_.enabled, [string]$_.source
    })
}

function Assert-LocalStatusDocument(
    [object]$Status,
    [bool]$GatewayRunning,
    [string]$Context
) {
    if ([bool]$Status.sidecar.running -ne $GatewayRunning) {
        throw "$Context sidecar state is not $GatewayRunning"
    }
    $roster = Get-LocalRoster $Status
    if (($roster -join "`n") -cne ($script:LocalExpectedRoster -join "`n") -or
        @($Status.connectors | Where-Object { [string]$_.name -ceq 'opencode' }).Count -ne 0) {
        throw "$Context changed the exact four-connector roster or exposed OpenCode"
    }
}

function Get-LocalProcessRows {
    return @(Get-CimInstance Win32_Process -Filter (
        "Name='defenseclaw-gateway.exe' OR " +
        "Name='defenseclaw-watchdog.exe' OR Name='defenseclaw-hook.exe'"
    ) | ForEach-Object {
        [pscustomobject]@{
            Name = [string]$_.Name
            PID = [uint32]$_.ProcessId
            Path = [string]$_.ExecutablePath
        }
    })
}

function Wait-LocalProcessAbsence([int]$TimeoutSeconds = 45) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $rows = @(Get-LocalProcessRows)
        if ($rows.Count -eq 0) { return }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'protected local quiesce did not reach exact gateway/watchdog/hook process absence'
}

function Assert-LocalListenerAbsent {
    $listeners = @(Get-NetTCPConnection -LocalAddress '127.0.0.1' `
        -LocalPort 18970 -State Listen -ErrorAction SilentlyContinue)
    if ($listeners.Count -ne 0) {
        throw 'protected local quiesce left the DefenseClaw loopback listener active'
    }
}

function Assert-LocalAuditExclusive([string]$AuditPath) {
    $stream = $null
    try {
        $stream = [IO.File]::Open($AuditPath, [IO.FileMode]::Open,
            [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    } catch {
        throw "protected local quiesce cannot take exclusive audit.db custody: $($_.Exception.Message)"
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Get-LocalCustodyMappings([object]$Manifest, [string]$BaselineSHA256) {
    $prefix = $BaselineSHA256.Substring(0, 12)
    $installRoot = Split-Path -Parent (Split-Path -Parent `
        ([string]$Manifest.fingerprints.install_state.path))
    $dataRoot = Split-Path -Parent ([string]$Manifest.fingerprints.config.path)
    $maintenance = [string]$Manifest.fingerprints.maintenance_setup.path
    $localRoot = Split-Path -Parent (Split-Path -Parent $maintenance)
    $hookPath = [string]$Manifest.fingerprints.copilot_hook.path
    $profile = Split-Path -Parent $dataRoot
    $programs = Split-Path -Parent $installRoot
    $localParent = Split-Path -Parent $localRoot
    $copilotHome = Split-Path -Parent (Split-Path -Parent $hookPath)
    return @(
        [pscustomobject]@{
            Name = 'copilot_hook'; Source = $hookPath
            Destination = Join-Path $copilotHome "defenseclaw-hook.copilot-custody-$prefix.json"
        },
        [pscustomobject]@{
            Name = 'data_root'; Source = $dataRoot
            Destination = Join-Path $profile ".defenseclaw.copilot-custody-$prefix"
        },
        [pscustomobject]@{
            Name = 'install_root'; Source = $installRoot
            Destination = Join-Path $programs "DefenseClaw.copilot-custody-$prefix"
        },
        [pscustomobject]@{
            Name = 'local_root'; Source = $localRoot
            Destination = Join-Path $localParent "DefenseClaw.copilot-custody-$prefix"
        }
    )
}

function Set-LocalExactEnvironment([object]$Baseline) {
    $installRoot = Split-Path -Parent (Split-Path -Parent `
        ([string]$Baseline.fingerprints.install_state.path))
    $dataRoot = Split-Path -Parent ([string]$Baseline.fingerprints.config.path)
    $copilotHome = Split-Path -Parent (Split-Path -Parent `
        ([string]$Baseline.fingerprints.copilot_hook.path))
    $env:DEFENSECLAW_INSTALL_ROOT = $installRoot
    $env:DEFENSECLAW_HOME = $dataRoot
    $env:DEFENSECLAW_CONFIG = [string]$Baseline.fingerprints.config.path
    $env:DEFENSECLAW_GATEWAY_BIN = Join-Path $installRoot `
        'bin\defenseclaw-gateway.exe'
    $env:COPILOT_HOME = $copilotHome
    # The accepted local lane proves the existing OS credential-store session.
    # It must never silently substitute an ambient token credential.
    Clear-LocalAmbientCredentials
}

function Assert-LocalCustodyMappings([object[]]$Mappings) {
    $sources = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $destinations = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($mapping in $Mappings) {
        $source = [IO.Path]::GetFullPath([string]$mapping.Source)
        $destination = [IO.Path]::GetFullPath([string]$mapping.Destination)
        if (-not $sources.Add($source) -or -not $destinations.Add($destination) -or
            [IO.Path]::GetPathRoot($source) -cne [IO.Path]::GetPathRoot($destination) -or
            [string]::Equals($source, $destination, [StringComparison]::OrdinalIgnoreCase) -or
            (Test-Path -LiteralPath $destination)) {
            throw 'protected local custody mapping is duplicate, cross-volume, occupied, or self-referential'
        }
        $allowedRoot = [IO.Path]::GetPathRoot($source)
        Assert-LocalPlainPath $source $allowedRoot -Directory:([string]$mapping.Name -cne 'copilot_hook')
        $parent = Split-Path -Parent $destination
        Assert-LocalPlainPath $parent $allowedRoot -Directory
    }
}

function Assert-LocalProtectedRootsOutsideCustody(
    [string[]]$ProtectedRoots,
    [object[]]$Mappings
) {
    foreach ($rootValue in $ProtectedRoots) {
        $root = Get-LocalCanonicalPath $rootValue
        foreach ($mapping in $Mappings) {
            foreach ($custodyPath in @(
                [string]$mapping.Source, [string]$mapping.Destination
            )) {
                $custody = Get-LocalCanonicalPath $custodyPath
                if ([string]::Equals($root, $custody,
                        [StringComparison]::OrdinalIgnoreCase) -or
                    (Test-LocalPathWithin $root $custody) -or
                    (Test-LocalPathWithin $custody $root)) {
                    throw 'protected local source/state/package/baseline root overlaps live custody'
                }
            }
        }
    }
}

function New-LocalTransactionDocument(
    [object]$Baseline,
    [object[]]$Mappings,
    [string]$TransactionPath
) {
    return [ordered]@{
        schema_version = 1
        kind = 'copilot-local-protected-transaction'
        phase = 'armed'
        hitl_claimed = $false
        created_at_utc = [DateTime]::UtcNow.ToString('o')
        current_user_sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        inner_capability_sha256 = $script:LocalCapabilitySHA256
        restore_capability_path = $script:LocalRestoreCapabilityRecord.Path
        restore_capability_sha256 = $script:LocalRestoreCapabilityRecord.PlainSHA256
        restore_capability_ciphertext_sha256 =
            $script:LocalRestoreCapabilityRecord.CiphertextSHA256
        authorizer_path = $script:LocalAuthorizerPath
        authorizer_sha256 = $ExpectedLocalProtectedCopilotAuthorizerSHA256
        baseline_manifest_path = [IO.Path]::GetFullPath($BaselineManifestPath)
        baseline_manifest_sha256 = $ExpectedBaselineManifestSHA256
        transaction_path = [IO.Path]::GetFullPath($TransactionPath)
        package_source_commit = $ExpectedPackageSourceCommit
        harness_source_commit = $ExpectedHarnessSourceCommit
        package_run_id = $ExpectedPackageRunID
        package_artifact_id = $ExpectedPackageArtifactID
        package_artifact_digest = $ExpectedPackageArtifactDigest
        workflow_repository = $ExpectedWorkflowRepository
        setup_path = [IO.Path]::GetFullPath($PackagedSetupPath)
        setup_sha256 = Get-LocalSHA256 $PackagedSetupPath
        expected_setup_sha256 = $ExpectedPackagedSetupSHA256
        setup_provenance_path = $script:LocalPackageProvenance.Path
        setup_provenance_sha256 = $script:LocalPackageProvenance.SHA256
        expected_setup_provenance_sha256 = $ExpectedPackagedSetupProvenanceSHA256
        agent_path = [IO.Path]::GetFullPath($AgentPath)
        agent_version = $ExpectedAgentVersion
        agent_binary_sha256 = $script:CopilotClientSHA256
        inner_harness_path = $script:WindowsLiveHarnessPath
        inner_harness_sha256 = $script:CopilotHarnessSHA256
        state_root = [IO.Path]::GetFullPath($StateRoot)
        results_path = [IO.Path]::GetFullPath($ResultsPath)
        artifact_path = [IO.Path]::GetFullPath($ArtifactPath)
        baseline_roster = @($Baseline.roster)
        custody = @($Mappings | ForEach-Object {
            [ordered]@{
                name = [string]$_.Name
                source = [IO.Path]::GetFullPath([string]$_.Source)
                destination = [IO.Path]::GetFullPath([string]$_.Destination)
                moved = $false
            }
        })
        deferred_cleanup_transaction_id = ''
        uninstall_boot_identifier = ''
        deferred_cleanup_run_command_sha256 = ''
        pre_restart_fingerprints_verified = $false
        post_restart_runtime_fingerprints = [ordered]@{}
        completed_at_utc = ''
    }
}

function Assert-LocalTransactionDocument(
    [object]$Transaction,
    [string]$TransactionPath,
    [object]$Baseline
) {
    foreach ($field in @(
        'schema_version', 'kind', 'phase', 'hitl_claimed', 'current_user_sid',
        'inner_capability_sha256',
        'restore_capability_path', 'restore_capability_sha256',
        'restore_capability_ciphertext_sha256',
        'authorizer_path', 'authorizer_sha256', 'baseline_manifest_path',
        'baseline_manifest_sha256', 'transaction_path', 'package_source_commit',
        'harness_source_commit', 'package_run_id', 'package_artifact_id',
        'package_artifact_digest', 'workflow_repository', 'setup_path',
        'setup_sha256', 'expected_setup_sha256', 'setup_provenance_path',
        'setup_provenance_sha256', 'expected_setup_provenance_sha256',
        'agent_path', 'agent_version', 'agent_binary_sha256',
        'inner_harness_path', 'inner_harness_sha256', 'state_root',
        'results_path', 'artifact_path', 'baseline_roster', 'custody',
        'deferred_cleanup_transaction_id', 'uninstall_boot_identifier',
        'deferred_cleanup_run_command_sha256',
        'pre_restart_fingerprints_verified', 'post_restart_runtime_fingerprints',
        'completed_at_utc'
    )) {
        if ($null -eq $Transaction.PSObject.Properties[$field]) {
            throw "protected local transaction is missing $field"
        }
    }
    if ([int]$Transaction.schema_version -ne 1 -or
        [string]$Transaction.kind -cne 'copilot-local-protected-transaction' -or
        [bool]$Transaction.hitl_claimed -or
        [string]$Transaction.inner_capability_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Transaction.restore_capability_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Transaction.restore_capability_ciphertext_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Transaction.phase -notin @(
            'armed', 'quiesced', 'custody', 'harness-complete',
            'awaiting-reboot', 'restored-prestart', 'restored'
        )) {
        throw 'protected local transaction schema, phase, or HITL claim is invalid'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    foreach ($pair in @(
        @([string]$Transaction.current_user_sid, $identity.User.Value),
        @([string]$Transaction.authorizer_path, $script:LocalAuthorizerPath),
        @([string]$Transaction.authorizer_sha256, $ExpectedLocalProtectedCopilotAuthorizerSHA256),
        @([string]$Transaction.baseline_manifest_path, [IO.Path]::GetFullPath($BaselineManifestPath)),
        @([string]$Transaction.baseline_manifest_sha256, $ExpectedBaselineManifestSHA256),
        @([string]$Transaction.transaction_path, [IO.Path]::GetFullPath($TransactionPath)),
        @([string]$Transaction.package_source_commit, $ExpectedPackageSourceCommit),
        @([string]$Transaction.harness_source_commit, $ExpectedHarnessSourceCommit),
        @([string]$Transaction.package_run_id, $ExpectedPackageRunID),
        @([string]$Transaction.package_artifact_id, $ExpectedPackageArtifactID),
        @([string]$Transaction.package_artifact_digest, $ExpectedPackageArtifactDigest),
        @([string]$Transaction.workflow_repository, $ExpectedWorkflowRepository),
        @([string]$Transaction.setup_path, [IO.Path]::GetFullPath($PackagedSetupPath)),
        @([string]$Transaction.setup_sha256, (Get-LocalSHA256 $PackagedSetupPath)),
        @([string]$Transaction.expected_setup_sha256, $ExpectedPackagedSetupSHA256),
        @([string]$Transaction.setup_provenance_path, $script:LocalPackageProvenance.Path),
        @([string]$Transaction.setup_provenance_sha256, $script:LocalPackageProvenance.SHA256),
        @([string]$Transaction.expected_setup_provenance_sha256, $ExpectedPackagedSetupProvenanceSHA256),
        @([string]$Transaction.agent_path, [IO.Path]::GetFullPath($AgentPath)),
        @([string]$Transaction.agent_version, $ExpectedAgentVersion),
        @([string]$Transaction.agent_binary_sha256, $script:CopilotClientSHA256),
        @([string]$Transaction.inner_harness_path, $script:WindowsLiveHarnessPath),
        @([string]$Transaction.inner_harness_sha256, $script:CopilotHarnessSHA256),
        @([string]$Transaction.state_root, [IO.Path]::GetFullPath($StateRoot)),
        @([string]$Transaction.results_path, [IO.Path]::GetFullPath($ResultsPath)),
        @([string]$Transaction.artifact_path, [IO.Path]::GetFullPath($ArtifactPath))
    )) {
        if ($pair[0] -cne $pair[1]) {
            throw 'protected local transaction provenance, path, or identity mismatch'
        }
    }
    if ((@($Transaction.baseline_roster) -join "`n") -cne
        ($script:LocalExpectedRoster -join "`n")) {
        throw 'protected local transaction roster binding is invalid'
    }
    $restoreCapabilityPath = [IO.Path]::GetFullPath(
        [string]$Transaction.restore_capability_path)
    $transactionRoot = Split-Path -Parent ([IO.Path]::GetFullPath($TransactionPath))
    if (-not (Test-LocalPathWithin $restoreCapabilityPath $transactionRoot) -or
        (Get-LocalSHA256 $restoreCapabilityPath) -cne
            [string]$Transaction.restore_capability_ciphertext_sha256) {
        throw 'protected local transaction restore capability path/ciphertext binding is invalid'
    }
    $expectedMappings = @(Get-LocalCustodyMappings $Baseline `
        $ExpectedBaselineManifestSHA256)
    $custody = @($Transaction.custody)
    if ($custody.Count -ne $expectedMappings.Count) {
        throw 'protected local transaction custody inventory is incomplete or expanded'
    }
    for ($index = 0; $index -lt $expectedMappings.Count; $index++) {
        $actual = $custody[$index]
        $expected = $expectedMappings[$index]
        if ([string]$actual.name -cne [string]$expected.Name -or
            [string]$actual.source -cne [IO.Path]::GetFullPath([string]$expected.Source) -or
            [string]$actual.destination -cne [IO.Path]::GetFullPath([string]$expected.Destination) -or
            $actual.moved -isnot [bool]) {
            throw 'protected local transaction custody path or move-state binding is invalid'
        }
    }
    if ([string]$Transaction.phase -ceq 'awaiting-reboot' -and
        ([string]$Transaction.deferred_cleanup_transaction_id -cnotmatch '^[0-9a-f]{32}$' -or
         [string]$Transaction.uninstall_boot_identifier -cnotmatch
            '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or
         [string]$Transaction.deferred_cleanup_run_command_sha256 -cnotmatch
            '^[0-9a-f]{64}$')) {
        throw 'protected local awaiting-reboot transaction lacks exact Setup cleanup authority'
    }
}

function Write-LocalTransaction([object]$Transaction, [string]$Path) {
    $temporary = "$Path.$PID.tmp"
    if (Test-Path -LiteralPath $temporary) {
        throw 'protected local transaction temporary path already exists'
    }
    [IO.File]::WriteAllText($temporary,
        ($Transaction | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            [IO.File]::Replace($temporary, $Path, $null, $true)
        } else {
            [IO.File]::Move($temporary, $Path)
        }
    } finally {
        if (Test-Path -LiteralPath $temporary) { [IO.File]::Delete($temporary) }
    }
}

function Invoke-LocalExactCommand(
    [string]$FilePath,
    [string[]]$Arguments,
    [int[]]$AllowedExitCodes = @(0),
    [int]$TimeoutSeconds = 120,
    [string]$LogName = 'local-command.log'
) {
    return Invoke-NativeProcess -FilePath $FilePath -ArgumentList $Arguments `
        -AllowedExitCodes $AllowedExitCodes -TimeoutSeconds $TimeoutSeconds `
        -LogPath (Join-Path $script:LogRoot $LogName)
}

function Get-LocalBaselineStatus([object]$Baseline, [string]$Context) {
    $installRoot = Split-Path -Parent (Split-Path -Parent `
        ([string]$Baseline.fingerprints.install_state.path))
    $cli = Join-Path $installRoot 'bin\defenseclaw.exe'
    $result = Invoke-LocalExactCommand $cli @('status', '--json') @(0) 60 `
        "baseline-status-$Context.log"
    $status = $result.StdOut | ConvertFrom-Json -ErrorAction Stop
    Assert-LocalStatusDocument $status $true $Context
    return $status
}

function Assert-LocalDoctor([object]$Baseline, [string]$Context) {
    $installRoot = Split-Path -Parent (Split-Path -Parent `
        ([string]$Baseline.fingerprints.install_state.path))
    $cli = Join-Path $installRoot 'bin\defenseclaw.exe'
    $result = Invoke-LocalExactCommand $cli @('doctor', '--json-output') @(0, 1) 180 `
        "baseline-doctor-$Context.log"
    $report = $result.StdOut | ConvertFrom-Json -ErrorAction Stop
    $checks = @($report.checks)
    $pass = @($checks | Where-Object { [string]$_.status -ceq 'pass' }).Count
    $fail = @($checks | Where-Object { [string]$_.status -ceq 'fail' }).Count
    if ($pass -ne [int]$Baseline.doctor.pass -or $fail -ne 0 -or $result.ExitCode -ne 0) {
        throw "$Context Doctor gate is not the sealed 70 pass / 0 fail state"
    }
}

function Assert-LocalLiveBaseline([object]$Baseline, [string]$Context) {
    foreach ($name in $script:LocalExpectedFingerprintNames) {
        Assert-LocalFileFingerprint $Baseline.fingerprints.$name "$Context $name"
    }
    $null = Get-LocalBaselineStatus $Baseline $Context
    Assert-LocalDoctor $Baseline $Context
    $rows = @(Get-LocalProcessRows)
    if ($rows.Count -ne @($Baseline.processes).Count -or
        @($rows | Where-Object { $_.Name -cne 'defenseclaw-gateway.exe' }).Count -ne 0) {
        throw "$Context process topology is not the sealed two-gateway-image topology"
    }
    $listeners = @(Get-NetTCPConnection -LocalAddress '127.0.0.1' `
        -LocalPort 18970 -State Listen -ErrorAction SilentlyContinue)
    if ($listeners.Count -ne 1) {
        throw "$Context loopback listener topology is not exact"
    }
}

function Invoke-LocalInnerHarness([ValidateSet('run', 'cleanup')][string]$InnerOperation) {
    if ($script:LocalCapability -cnotmatch '^[0-9a-f]{64}$' -or
        $script:LocalCapabilitySHA256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'protected local inner launch lacks its bounded script-scope capability'
    }
    $transactionSHA256 = Get-LocalSHA256 $script:LocalTransactionPath
    $arguments = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $script:WindowsLiveHarnessPath,
        '-Layer', 'live', '-Connector', 'copilot', '-Operation', $InnerOperation,
        '-WorkspaceRoot', $WorkspaceRoot, '-StateRoot', $StateRoot,
        '-ResultsPath', $ResultsPath, '-ArtifactPath', $ArtifactPath,
        '-ProtectedCopilotRunner', '-LocalProtectedCopilotRunner',
        '-LocalProtectedCopilotAuthorizerPath', $script:LocalAuthorizerPath,
        '-ExpectedLocalProtectedCopilotAuthorizerSHA256',
            $ExpectedLocalProtectedCopilotAuthorizerSHA256,
        '-LocalProtectedCopilotTransactionPath', $script:LocalTransactionPath,
        '-ExpectedLocalProtectedCopilotTransactionSHA256', $transactionSHA256,
        '-ExpectedLocalProtectedCopilotCapabilitySHA256',
            $script:LocalCapabilitySHA256,
        '-PackagedSetupPath', $PackagedSetupPath,
        '-ExpectedPackageSourceCommit', $ExpectedPackageSourceCommit,
        '-ExpectedHarnessSourceCommit', $ExpectedHarnessSourceCommit,
        '-ExpectedPackageRunID', $ExpectedPackageRunID,
        '-ExpectedPackageArtifactID', $ExpectedPackageArtifactID,
        '-ExpectedPackageArtifactDigest', $ExpectedPackageArtifactDigest,
        '-ExpectedWorkflowRepository', $ExpectedWorkflowRepository,
        '-AgentPath', $AgentPath, '-ExpectedAgentVersion', $ExpectedAgentVersion
    )
    if ($InnerOperation -eq 'cleanup') {
        $arguments += '-PreserveProtectedCopilotRunInputs'
    }
    $pwsh = (Get-Command 'pwsh.exe' -CommandType Application -ErrorAction Stop).Source
    $innerExitCode = $null
    try {
        $env:DC_COPILOT_LOCAL_CAPABILITY = $script:LocalCapability
        & $pwsh @arguments
        $innerExitCode = $LASTEXITCODE
    } finally {
        Remove-Item Env:DC_COPILOT_LOCAL_CAPABILITY -ErrorAction SilentlyContinue
    }
    if ($innerExitCode -ne 0) {
        throw "protected local inner Copilot $InnerOperation failed with exit $innerExitCode"
    }
}

function Set-LocalAwaitingReboot(
    [object]$Baseline,
    [object]$Transaction,
    [string]$TransactionPath
) {
    $paths = Get-ProtectedCopilotPackagePaths
    $record = Assert-ProtectedCopilotDeferredCleanupPending $paths
    $runCommandDigest = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes([string]$record.run_command)
        )
    ).ToLowerInvariant()
    Use-LocalRestoreCapability $Transaction
    $Transaction.inner_capability_sha256 = $script:LocalCapabilitySHA256
    $Transaction.deferred_cleanup_transaction_id = [string]$record.transaction_id
    $Transaction.uninstall_boot_identifier = [string]$record.uninstall_boot_identifier
    $Transaction.deferred_cleanup_run_command_sha256 = $runCommandDigest
    $Transaction.phase = 'awaiting-reboot'
    Write-LocalTransaction $Transaction $TransactionPath
    $persisted = Read-LocalJson $TransactionPath `
        'protected awaiting-reboot transaction'
    Assert-LocalTransactionDocument $persisted $TransactionPath $Baseline
    # Decrypt and verify once more after the durable transaction is sealed.
    Use-LocalRestoreCapability $persisted
    return $persisted
}

function Test-LocalDeferredRunValueAbsent {
    $runKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
        'Software\Microsoft\Windows\CurrentVersion\Run', $false)
    if ($null -eq $runKey) { return $true }
    try {
        return $null -eq $runKey.GetValue(
            'DefenseClawDeferredUninstallCleanup', $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    } finally {
        $runKey.Dispose()
    }
}

function New-LocalWindowsBootIdentifier(
    [string]$EnvironmentIdentifier,
    [uint32]$TelemetryBootID
) {
    $environmentIdentifier = $EnvironmentIdentifier.ToLowerInvariant()
    if ($environmentIdentifier -cnotmatch
        '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
        throw 'Windows returned an invalid boot-environment identifier'
    }
    $domain = [Text.Encoding]::UTF8.GetBytes(
        "DefenseClaw deferred cleanup boot identity v1`0")
    $environmentBytes = [Text.Encoding]::UTF8.GetBytes($environmentIdentifier)
    $encodedBootID = [BitConverter]::GetBytes([uint32]$telemetryBootID)
    if (-not [BitConverter]::IsLittleEndian) {
        [Array]::Reverse($encodedBootID)
    }
    $material = [IO.MemoryStream]::new()
    try {
        $material.Write($domain, 0, $domain.Length)
        $material.Write($environmentBytes, 0, $environmentBytes.Length)
        $material.Write($encodedBootID, 0, $encodedBootID.Length)
        $digest = [Security.Cryptography.SHA256]::HashData($material.ToArray())
    } finally {
        $material.Dispose()
    }
    $encoded = [Convert]::ToHexString($digest[0..15]).ToLowerInvariant()
    $identifier = $encoded.Substring(0, 8) + '-' +
        $encoded.Substring(8, 4) + '-' + $encoded.Substring(12, 4) + '-' +
        $encoded.Substring(16, 4) + '-' + $encoded.Substring(20, 12)
    if ($identifier -cnotmatch
        '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
        throw 'derived Windows boot identifier is invalid'
    }
    return $identifier
}

function Get-LocalWindowsBootIdentifier {
    Initialize-LocalWindowsNativeSupport
    return New-LocalWindowsBootIdentifier `
        ([DefenseClaw.CopilotLocalNative]::GetBootEnvironmentIdentifier()) `
        ([DefenseClaw.CopilotLocalNative]::GetProcessTelemetryBootID())
}

function Assert-LocalBootTransition(
    [string]$CurrentBootIdentifier,
    [string]$UninstallBootIdentifier
) {
    $pattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    if ($CurrentBootIdentifier -cnotmatch $pattern -or
        $UninstallBootIdentifier -cnotmatch $pattern) {
        throw 'protected local boot-transition identity is invalid'
    }
    if ($CurrentBootIdentifier -ceq $UninstallBootIdentifier) {
        throw 'post-login restoration requires the genuine Windows restart recorded by exact Setup'
    }
}

function Assert-LocalDeferredCleanupCompleted([object]$Transaction) {
    if ([string]$Transaction.phase -cne 'awaiting-reboot') {
        throw 'post-login restoration requires an authenticated awaiting-reboot transaction'
    }
    Assert-LocalBootTransition (Get-LocalWindowsBootIdentifier) `
        ([string]$Transaction.uninstall_boot_identifier)
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        $remaining = @($Transaction.custody | Where-Object {
            Test-Path -LiteralPath ([string]$_.source)
        })
        if ($remaining.Count -eq 0 -and (Test-LocalDeferredRunValueAbsent)) {
            Wait-LocalProcessAbsence 3
            Assert-LocalListenerAbsent
            return
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'official boot-gated Setup cleanup has not removed all fresh paths and its exact Run value'
}

function Restore-LocalBaseline(
    [object]$Baseline,
    [object]$Transaction,
    [string]$TransactionPath
) {
    $paths = Get-ProtectedCopilotPackagePaths
    $installCustody = @($Transaction.custody | Where-Object {
        [string]$_.name -ceq 'install_root'
    })
    if ($installCustody.Count -ne 1) {
        throw 'protected local transaction lacks one install-root custody binding'
    }
    if ([string]$Transaction.phase -ceq 'awaiting-reboot') {
        Assert-LocalDeferredCleanupCompleted $Transaction
    }
    $baselineInstallInCustody = Test-Path -LiteralPath `
        ([string]$installCustody[0].destination)
    if ($baselineInstallInCustody -and
        ((Test-Path -LiteralPath (Get-ProtectedCopilotCleanupManifestPath)) -or
         (Test-Path -LiteralPath $paths.InstallRoot) -or
         (Test-Path -LiteralPath $paths.DataRoot) -or
         (Test-Path -LiteralPath $paths.MaintenancePath))) {
        Invoke-LocalInnerHarness cleanup
    }
    $exactGateway = Join-Path (Split-Path -Parent (Split-Path -Parent `
        ([string]$Baseline.fingerprints.install_state.path))) 'bin\defenseclaw-gateway.exe'
    if (Test-Path -LiteralPath $exactGateway -PathType Leaf) {
        Invoke-LocalExactCommand $exactGateway @('stop') @(0, 1) 60 `
            'baseline-restore-stop.log' | Out-Null
    }
    Wait-LocalProcessAbsence
    Assert-LocalListenerAbsent

    $custody = @($Transaction.custody)
    for ($index = $custody.Count - 1; $index -ge 0; $index--) {
        $entry = $custody[$index]
        $source = [IO.Path]::GetFullPath([string]$entry.source)
        $destination = [IO.Path]::GetFullPath([string]$entry.destination)
        if (Test-Path -LiteralPath $destination) {
            if (Test-Path -LiteralPath $source) {
                throw "baseline restoration destination and source are both occupied: $($entry.name)"
            }
            Move-Item -LiteralPath $destination -Destination $source
        } elseif ([bool]$entry.moved -and -not (Test-Path -LiteralPath $source)) {
            throw "baseline restoration lost both custody and original path: $($entry.name)"
        }
    }
    if ([bool]$Transaction.pre_restart_fingerprints_verified) {
        foreach ($name in $script:LocalDerivedFingerprintNames) {
            try {
                Assert-LocalFileFingerprint $Baseline.fingerprints.$name `
                    "retry pre-restart baseline $name"
            } catch {
                Restore-LocalDerivedFingerprint $Baseline $name
            }
        }
    }
    foreach ($name in $script:LocalExpectedFingerprintNames) {
        Assert-LocalFileFingerprint $Baseline.fingerprints.$name `
            "pre-restart baseline restoration $name"
    }
    $Transaction.pre_restart_fingerprints_verified = $true
    $Transaction.phase = 'restored-prestart'
    Write-LocalTransaction $Transaction $TransactionPath

    $gateway = Join-Path (Split-Path -Parent (Split-Path -Parent `
        ([string]$Baseline.fingerprints.install_state.path))) 'bin\defenseclaw-gateway.exe'
    try {
        Invoke-LocalExactCommand $gateway @('start') @(0) 90 `
            'baseline-restore-start.log' | Out-Null
        Invoke-LocalExactCommand $gateway @('watchdog', 'start') @(0) 90 `
            'baseline-restore-watchdog-start.log' | Out-Null
        $deadline = [DateTime]::UtcNow.AddSeconds(90)
        do {
            try {
                $null = Get-LocalBaselineStatus $Baseline 'restored'
                break
            } catch {
                if ([DateTime]::UtcNow -ge $deadline) { throw }
                Start-Sleep -Milliseconds 500
            }
        } while ($true)
        Assert-LocalDoctor $Baseline 'restored'
        $rows = @(Get-LocalProcessRows)
        if ($rows.Count -ne @($Baseline.processes).Count -or
            @($rows | Where-Object { $_.Name -cne 'defenseclaw-gateway.exe' }).Count -ne 0) {
            throw 'restored baseline did not recover the two-gateway-image process topology'
        }
    } catch {
        $healthFailure = $_.Exception
        try {
            Invoke-LocalExactCommand $gateway @('stop') @(0, 1) 60 `
                'baseline-restore-health-failure-stop.log' | Out-Null
            Wait-LocalProcessAbsence
            Assert-LocalListenerAbsent
            foreach ($name in $script:LocalDerivedFingerprintNames) {
                Restore-LocalDerivedFingerprint $Baseline $name
            }
            foreach ($name in $script:LocalExpectedFingerprintNames) {
                Assert-LocalFileFingerprint $Baseline.fingerprints.$name `
                    "failed-health stopped restoration $name"
            }
        } catch {
            throw "baseline health restoration failed and stopped recovery also failed: $($_.Exception.Message)"
        }
        throw "baseline bytes/security were restored but supported restart health failed; services are stopped for authenticated -Operation restore: $($healthFailure.Message)"
    }
    foreach ($name in $script:LocalExpectedFingerprintNames) {
        if ($name -notin $script:LocalDerivedFingerprintNames) {
            Assert-LocalFileFingerprint $Baseline.fingerprints.$name `
                "post-restart static baseline restoration $name"
        }
    }
    foreach ($name in $script:LocalDerivedFingerprintNames) {
        $actual = Get-LocalFileFingerprint ([string]$Baseline.fingerprints.$name.path)
        $runtimeFingerprint = [ordered]@{
            path = $actual.Path; length = $actual.Length; attributes = $actual.Attributes
            sha256 = $actual.SHA256; owner = $actual.Owner; sddl = $actual.SDDL
        }
        if ($Transaction.post_restart_runtime_fingerprints -is
            [Collections.Specialized.OrderedDictionary]) {
            $Transaction.post_restart_runtime_fingerprints[$name] = $runtimeFingerprint
        } else {
            $Transaction.post_restart_runtime_fingerprints | Add-Member `
                -NotePropertyName $name -NotePropertyValue $runtimeFingerprint -Force
        }
    }
    $Transaction.phase = 'restored'
    $Transaction.completed_at_utc = [DateTime]::UtcNow.ToString('o')
    Write-LocalTransaction $Transaction $TransactionPath
}

function Invoke-LocalProtectedCopilot {
    $requestedOperation = $Operation
    Clear-LocalAmbientCredentials
    if (-not $IsWindows -or
        [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
            [Runtime.InteropServices.Architecture]::X64) {
        throw 'local protected Copilot entry requires native Windows x64 PowerShell'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.IsSystem -or
        ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'local protected Copilot entry requires the current non-elevated user SID'
    }
    foreach ($value in @(
        $WorkspaceRoot, $StateRoot, $ResultsPath, $ArtifactPath,
        $PackagedSetupPath, $ExpectedPackagedSetupSHA256,
        $ExpectedPackagedSetupProvenanceSHA256, $ExpectedPackageSourceCommit,
        $ExpectedHarnessSourceCommit, $ExpectedPackageRunID,
        $ExpectedPackageArtifactID, $ExpectedPackageArtifactDigest,
        $ExpectedWorkflowRepository, $AgentPath, $ExpectedAgentVersion,
        $BaselineManifestPath, $ExpectedBaselineManifestSHA256,
        $ExpectedLocalProtectedCopilotAuthorizerSHA256
    )) {
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw 'local protected Copilot entry requires every explicit identity and path'
        }
    }
    if ($ExpectedLocalProtectedCopilotAuthorizerSHA256 -cnotmatch '^[0-9a-f]{64}$' -or
        (Get-LocalSHA256 $script:LocalAuthorizerPath) -cne
            $ExpectedLocalProtectedCopilotAuthorizerSHA256) {
        throw 'local protected Copilot authorizer does not match its explicit SHA-256'
    }
    if ($ExpectedPackagedSetupSHA256 -cnotmatch '^[0-9a-f]{64}$' -or
        $ExpectedPackagedSetupProvenanceSHA256 -cnotmatch '^[0-9a-f]{64}$' -or
        (Get-LocalSHA256 $PackagedSetupPath) -cne $ExpectedPackagedSetupSHA256 -or
        (Get-LocalSHA256 "$PackagedSetupPath.provenance.json") -cne
            $ExpectedPackagedSetupProvenanceSHA256) {
        throw 'local protected Copilot package/provenance bytes do not match both explicit SHA-256 identities'
    }
    foreach ($path in @($StateRoot, $PackagedSetupPath, $AgentPath,
        $BaselineManifestPath, $ResultsPath, $ArtifactPath)) {
        if ([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($path)) -cne 'D:\') {
            throw 'local protected Copilot custody, package, client, results, and baseline paths must be D:-rooted'
        }
    }
    foreach ($path in @($ResultsPath, $ArtifactPath)) {
        if (-not (Test-LocalPathWithin $path $StateRoot)) {
            throw 'local protected Copilot results and artifacts must remain below StateRoot'
        }
    }
    $innerHarness = Join-Path ([IO.Path]::GetFullPath($WorkspaceRoot)) `
        'scripts\live-connector-e2e\run-windows.ps1'
    Assert-LocalExactPath $script:LocalAuthorizerPath `
        (Join-Path ([IO.Path]::GetFullPath($WorkspaceRoot)) `
            'scripts\live-connector-e2e\run-copilot-local.ps1') `
        'local protected authorizer'
    Assert-LocalPlainPath $script:LocalAuthorizerPath $WorkspaceRoot
    Assert-LocalPlainPath $innerHarness $WorkspaceRoot
    Assert-LocalPlainPath $WorkspaceRoot ([IO.Path]::GetPathRoot($WorkspaceRoot)) -Directory
    Assert-LocalPlainPath $ResultsPath $StateRoot -AllowAbsent
    Assert-LocalPlainPath $ArtifactPath $StateRoot -Directory -AllowAbsent
    Assert-LocalPlainPath (Join-Path $StateRoot 'logs') $StateRoot -Directory -AllowAbsent

    . $innerHarness -Layer live -Connector copilot -Operation run `
        -WorkspaceRoot $WorkspaceRoot -StateRoot $StateRoot `
        -ResultsPath $ResultsPath -ArtifactPath $ArtifactPath `
        -ProtectedCopilotRunner -LocalProtectedCopilotRunner `
        -LocalProtectedCopilotAuthorizerPath $script:LocalAuthorizerPath `
        -ExpectedLocalProtectedCopilotAuthorizerSHA256 `
            $ExpectedLocalProtectedCopilotAuthorizerSHA256 `
        -PackagedSetupPath $PackagedSetupPath `
        -ExpectedPackageSourceCommit $ExpectedPackageSourceCommit `
        -ExpectedHarnessSourceCommit $ExpectedHarnessSourceCommit `
        -ExpectedPackageRunID $ExpectedPackageRunID `
        -ExpectedPackageArtifactID $ExpectedPackageArtifactID `
        -ExpectedPackageArtifactDigest $ExpectedPackageArtifactDigest `
        -ExpectedWorkflowRepository $ExpectedWorkflowRepository `
        -AgentPath $AgentPath -ExpectedAgentVersion $ExpectedAgentVersion -NoRun

    Assert-ProtectedPackageArtifactRoot $StateRoot
    $packageRoot = Split-Path -Parent $PackagedSetupPath
    Assert-ProtectedPackageArtifactRoot $packageRoot
    $baselineRoot = Split-Path -Parent ([IO.Path]::GetFullPath($BaselineManifestPath))
    Assert-ProtectedPackageArtifactRoot $baselineRoot
    Assert-LocalRootsDisjoint @($WorkspaceRoot, $StateRoot, $packageRoot, $baselineRoot)
    foreach ($root in @($WorkspaceRoot, $StateRoot, $packageRoot, $baselineRoot)) {
        Assert-LocalPlainPath $root ([IO.Path]::GetPathRoot($root)) -Directory
    }
    if ($ExpectedPackageRunID -cnotmatch '^[1-9][0-9]*$' -or
        $ExpectedPackageArtifactID -cnotmatch '^[1-9][0-9]*$' -or
        $ExpectedPackageArtifactDigest -cnotmatch '^sha256:[0-9a-f]{64}$' -or
        $ExpectedPackageSourceCommit -cnotmatch '^[0-9a-f]{40}$' -or
        $ExpectedHarnessSourceCommit -cnotmatch '^[0-9a-f]{40}$' -or
        $ExpectedWorkflowRepository -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
        throw 'local protected Copilot package/run/artifact/source/repository identity is invalid'
    }
    $script:CopilotAuthorizationMode = 'local-powershell'
    $script:CopilotLocalAuthorizerPath = $script:LocalAuthorizerPath
    $script:CopilotLocalAuthorizerSHA256 =
        $ExpectedLocalProtectedCopilotAuthorizerSHA256
    $script:CopilotPackageRunID = $ExpectedPackageRunID
    $script:CopilotPackageArtifactID = $ExpectedPackageArtifactID
    $script:CopilotPackageArtifactDigest = $ExpectedPackageArtifactDigest
    Assert-ProtectedCopilotSourceCheckout
    $script:PackagedSetupExecutable = Assert-ExactPackagedSetup `
        $PackagedSetupPath $ExpectedPackageSourceCommit
    $script:ExpectedPackagedSourceCommit = $ExpectedPackageSourceCommit
    $script:LocalPackageProvenance = Assert-LocalPackageProvenance $PackagedSetupPath
    Assert-ProtectedCopilotClient
    $script:ResultsPath = [IO.Path]::GetFullPath($ResultsPath)
    $script:ArtifactPath = [IO.Path]::GetFullPath($ArtifactPath)
    $script:LogRoot = Join-Path ([IO.Path]::GetFullPath($StateRoot)) 'logs'
    [IO.Directory]::CreateDirectory($script:LogRoot) | Out-Null

    Assert-LocalPlainPath $BaselineManifestPath $baselineRoot
    $baseline = Read-LocalJson $BaselineManifestPath 'sealed baseline manifest'
    $baseline = Assert-LocalBaselineManifestDocument $baseline $BaselineManifestPath `
        $ExpectedBaselineManifestSHA256 -VerifyCopies
    Set-LocalExactEnvironment $baseline
    $transactionRoot = Join-Path $baselineRoot 'transactions'
    if (-not (Test-Path -LiteralPath $transactionRoot)) {
        Protect-TestDirectory $transactionRoot
    }
    Assert-ProtectedPackageArtifactRoot $transactionRoot
    $transactionPath = Join-Path $transactionRoot (
        "copilot-local-$($ExpectedLocalProtectedCopilotAuthorizerSHA256.Substring(0, 16)).json"
    )

    if ($requestedOperation -eq 'restore') {
        Assert-LocalPlainPath $transactionPath $transactionRoot
        $transaction = Read-LocalJson $transactionPath 'protected local transaction'
        Assert-LocalTransactionDocument $transaction $transactionPath $baseline
        $script:LocalTransactionPath = $transactionPath
        if ([string]$transaction.phase -ceq 'restored') {
            foreach ($name in $script:LocalExpectedFingerprintNames) {
                if ($name -notin $script:LocalDerivedFingerprintNames) {
                    Assert-LocalFileFingerprint $baseline.fingerprints.$name `
                        "already-restored static baseline $name"
                }
            }
            $null = Get-LocalBaselineStatus $baseline 'already-restored'
            Assert-LocalDoctor $baseline 'already-restored'
            $rows = @(Get-LocalProcessRows)
            $listeners = @(Get-NetTCPConnection -LocalAddress '127.0.0.1' `
                -LocalPort 18970 -State Listen -ErrorAction SilentlyContinue)
            if ($rows.Count -ne @($baseline.processes).Count -or
                @($rows | Where-Object {
                    $_.Name -cne 'defenseclaw-gateway.exe'
                }).Count -ne 0 -or $listeners.Count -ne 1) {
                throw 'already-restored runtime process/listener topology drifted'
            }
            foreach ($name in $script:LocalDerivedFingerprintNames) {
                $recorded = $transaction.post_restart_runtime_fingerprints.$name
                if ($null -eq $recorded) {
                    throw "already-restored transaction lacks runtime fingerprint: $name"
                }
                $actual = Get-LocalFileFingerprint `
                    ([string]$baseline.fingerprints.$name.path)
                foreach ($pair in @(
                    @('Path', 'path'), @('Length', 'length'),
                    @('Attributes', 'attributes'), @('SHA256', 'sha256'),
                    @('Owner', 'owner'), @('SDDL', 'sddl')
                )) {
                    if ([string]$actual.($pair[0]) -cne
                        [string]$recorded.($pair[1])) {
                        throw "already-restored runtime fingerprint drifted: $name.$($pair[1])"
                    }
                }
            }
            return
        }
        Use-LocalRestoreCapability $transaction
        $transaction.inner_capability_sha256 = $script:LocalCapabilitySHA256
        Write-LocalTransaction $transaction $transactionPath
        Restore-LocalBaseline $baseline $transaction $transactionPath
        return
    }
    if (Test-Path -LiteralPath $transactionPath) {
        throw 'a protected local transaction already exists; authenticate and run -Operation restore first'
    }
    Assert-LocalLiveBaseline $baseline 'preflight'
    $mappings = @(Get-LocalCustodyMappings $baseline $ExpectedBaselineManifestSHA256)
    Assert-LocalCustodyMappings $mappings
    Assert-LocalProtectedRootsOutsideCustody `
        @($WorkspaceRoot, $StateRoot, $packageRoot, $baselineRoot) $mappings
    New-LocalCapability
    $script:LocalRestoreCapabilityRecord = New-LocalRestoreCapabilityFile `
        $transactionRoot "copilot-local-$($ExpectedLocalProtectedCopilotAuthorizerSHA256.Substring(0, 16))"
    $transaction = New-LocalTransactionDocument $baseline $mappings $transactionPath
    $script:LocalTransactionPath = $transactionPath
    Write-LocalTransaction $transaction $transactionPath

    $restorationFailure = $null
    $awaitingReboot = $false
    try {
        $gateway = Join-Path (Split-Path -Parent (Split-Path -Parent `
            ([string]$baseline.fingerprints.install_state.path))) `
            'bin\defenseclaw-gateway.exe'
        Invoke-LocalExactCommand $gateway @('stop') @(0, 1) 60 `
            'baseline-quiesce-stop.log' | Out-Null
        Wait-LocalProcessAbsence
        Assert-LocalListenerAbsent
        Assert-LocalAuditExclusive (Join-Path (Split-Path -Parent `
            ([string]$baseline.fingerprints.config.path)) 'audit.db')
        $transaction.phase = 'quiesced'
        Write-LocalTransaction $transaction $transactionPath

        for ($index = 0; $index -lt $mappings.Count; $index++) {
            if (@(Get-LocalProcessRows).Count -ne 0) {
                throw 'a DefenseClaw hook or sidecar process restarted during protected custody'
            }
            Move-Item -LiteralPath $mappings[$index].Source `
                -Destination $mappings[$index].Destination
            $transaction.custody[$index].moved = $true
            Write-LocalTransaction $transaction $transactionPath
        }
        Wait-LocalProcessAbsence 3
        Assert-LocalListenerAbsent
        $transaction.phase = 'custody'
        Write-LocalTransaction $transaction $transactionPath

        Invoke-LocalInnerHarness run
        $transaction = Set-LocalAwaitingReboot $baseline $transaction $transactionPath
        $awaitingReboot = $true
    } finally {
        if (-not $awaitingReboot) {
            # A late inner failure may still have crossed exact Setup's
            # authenticated reboot gate. Preserve recoverable custody instead
            # of attempting an impossible same-boot move-back.
            try {
                $paths = Get-ProtectedCopilotPackagePaths
                if (Test-Path -LiteralPath $paths.MaintenancePath -PathType Leaf) {
                    $transaction = Set-LocalAwaitingReboot `
                        $baseline $transaction $transactionPath
                    $awaitingReboot = $true
                }
            } catch {
                # If pending authority is not exact, the ordinary authenticated
                # restoration attempt below remains the only allowed path.
            }
        }
        if (-not $awaitingReboot) {
            try {
                Restore-LocalBaseline $baseline $transaction $transactionPath
            } catch {
                $restorationFailure = $_.Exception
            }
        }
        if ($null -ne $restorationFailure) { throw $restorationFailure }
    }
    if ($awaitingReboot) {
        Write-Output (
            'COPILOT_PHASE1_COMPLETE_AWAITING_AUTHORIZED_WINDOWS_RESTART ' +
            "transaction=$transactionPath"
        )
    }
}

if (-not $NoRun) {
    try {
        Invoke-LocalProtectedCopilot
    } finally {
        Clear-LocalCapability
    }
}
