# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

[CmdletBinding()]
param()

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot `
        '..\DefenseClawEnterprise.psm1')
)
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name $modulePath `
    -Force `
    -PassThru `
    -ErrorAction Stop

$serviceSID = 'S-1-5-80-1-2-3-4-5'
$expected = [ordered]@{
    InstallDirectory = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
    InstallFile = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)'
    ServiceInstallDirectory = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;$serviceSID)"
    ServiceInstallFile = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;$serviceSID)"
    StateDirectory = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;$serviceSID)"
    AdminDirectory = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    AdminFile = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
    ConfigDirectory = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;$serviceSID)"
    ConfigFile = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;$serviceSID)"
    MachinePolicyFile = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)'
    RuntimeDirectory = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;$serviceSID)"
    RuntimeFile = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;$serviceSID)"
    RuntimeSecretFile = "O:$serviceSID" + "G:BAD:P(A;;RC;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;$serviceSID)"
    AuthorizationDirectory = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;$serviceSID)"
    AuthorizationFile = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;$serviceSID)"
    LogDirectory = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    GatewayLogDirectory = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;$serviceSID)"
    # FileSystemAccessRule adds Synchronize (0x100000) to explicit allow
    # rules. ListDirectory | Traverse is therefore serialized as 0x100021.
    # CommonAcl then canonicalizes equal-priority allow ACEs by SID, placing
    # Authenticated Users before SYSTEM, Administrators, and the service SID.
    ManagedIPCDirectory = "O:BAG:BAD:P(A;;0x100021;;;AU)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;$serviceSID)"
}
$directoryKinds = @(
    'InstallDirectory',
    'ServiceInstallDirectory',
    'StateDirectory',
    'AdminDirectory',
    'ConfigDirectory',
    'RuntimeDirectory',
    'AuthorizationDirectory',
    'LogDirectory',
    'GatewayLogDirectory',
    'ManagedIPCDirectory'
)

$observed = & $module {
    param($Cases, $Directories, $GatewaySID)
    $sections = [Security.AccessControl.AccessControlSections]::All
    foreach ($entry in $Cases.GetEnumerator()) {
        $kind = [string]$entry.Key
        $security = New-DefenseClawCanonicalPathAcl `
            -IsDirectory ($kind -in $Directories) `
            -Kind $kind `
            -GatewayServiceSID $GatewaySID
        [pscustomobject]@{
            kind = $kind
            protected = [bool]$security.AreAccessRulesProtected
            sddl = $security.GetSecurityDescriptorSddlForm($sections)
        }
    }
} $expected $directoryKinds $serviceSID

foreach ($row in $observed) {
    if (-not [bool]$row.protected -or
        [string]$row.sddl -cne [string]$expected[[string]$row.kind]) {
        throw (
            "canonical ACL descriptor mismatch for $($row.kind): " +
            "expected=$($expected[[string]$row.kind]) observed=$($row.sddl)"
        )
    }
}
if ($observed.Count -ne $expected.Count) {
    throw 'canonical ACL smoke did not exercise every managed path kind'
}

foreach ($mismatch in @(
    [pscustomobject]@{ directory = $true; kind = 'AdminFile' },
    [pscustomobject]@{ directory = $false; kind = 'AdminDirectory' }
)) {
    $rejected = & $module {
        param($IsDirectory, $Kind, $GatewaySID)
        try {
            New-DefenseClawCanonicalPathAcl `
                -IsDirectory $IsDirectory `
                -Kind $Kind `
                -GatewayServiceSID $GatewaySID |
                    Microsoft.PowerShell.Core\Out-Null
            return $false
        }
        catch {
            return $_.Exception.Message -match 'does not match'
        }
    } ([bool]$mismatch.directory) ([string]$mismatch.kind) $serviceSID
    if (-not $rejected) {
        throw "canonical ACL builder accepted object-type mismatch $($mismatch.kind)"
    }
}

$adminRows = @($observed | Microsoft.PowerShell.Core\Where-Object {
    [string]$_.kind -in @(
        'AdminDirectory',
        'AdminFile',
        'LogDirectory'
    )
})
foreach ($row in $adminRows) {
    if ([string]$row.sddl -match [regex]::Escape($serviceSID) -or
        [string]$row.sddl -match ';;;BU\)') {
        throw "administrator-only ACL retained a stale explicit principal: $($row.kind)"
    }
}

# The installer writes canonical ACLs from one table and the deployment
# verifier re-asserts them from another. They are only correct together, so
# every pairing must agree on what the gateway service is granted.
$pairings = [ordered]@{
    InstallDirectory = 'Install'
    InstallFile = 'Install'
    ServiceInstallDirectory = 'ServiceInstall'
    ServiceInstallFile = 'ServiceInstall'
    StateDirectory = 'State'
    AdminDirectory = 'Admin'
    AdminFile = 'Admin'
    ConfigDirectory = 'ConfigDirectory'
    ConfigFile = 'Config'
    MachinePolicyFile = 'MachinePolicy'
    RuntimeDirectory = 'Runtime'
    RuntimeFile = 'Runtime'
    RuntimeSecretFile = 'RuntimeSecret'
    AuthorizationDirectory = 'AuthorizationDirectory'
    AuthorizationFile = 'AuthorizationFile'
    LogDirectory = 'Admin'
    GatewayLogDirectory = 'Runtime'
    ManagedIPCDirectory = 'ManagedIPCDirectory'
}
if ($pairings.Count -ne $expected.Count) {
    throw 'installer/verifier pairing table does not cover every managed path kind'
}
$pairingsChecked = & $module {
    param($Pairings, $Directories, $GatewaySID)
    $checked = 0
    foreach ($entry in $Pairings.GetEnumerator()) {
        $aclKind = [string]$entry.Key
        $rightsKind = [string]$entry.Value
        $security = New-DefenseClawCanonicalPathAcl `
            -IsDirectory ($aclKind -in $Directories) `
            -Kind $aclKind `
            -GatewayServiceSID $GatewaySID
        $granted = [Security.AccessControl.FileSystemRights]0
        foreach ($rule in $security.GetAccessRules(
            $true,
            $false,
            [Security.Principal.SecurityIdentifier]
        )) {
            if ([string]$rule.IdentityReference.Value -eq $GatewaySID -and
                $rule.AccessControlType -eq
                    [Security.AccessControl.AccessControlType]::Allow) {
                $granted = $granted -bor $rule.FileSystemRights
            }
        }
        $required = New-DefenseClawRequiredRights `
            -Kind $rightsKind `
            -GatewayServiceSID $GatewaySID
        $expectedRights = if ($required.ContainsKey($GatewaySID)) {
            [Security.AccessControl.FileSystemRights]$required[$GatewaySID]
        }
        else {
            [Security.AccessControl.FileSystemRights]0
        }
        if (($granted -band $expectedRights) -ne $expectedRights) {
            throw (
                "installer ACL kind {0} grants the gateway service {1}, " +
                "short of the {2} required by verifier rights kind {3}"
            ) -f $aclKind, $granted, $expectedRights, $rightsKind
        }
        if ($aclKind -eq 'RuntimeSecretFile') {
            $writeLikeRights = (
                [Security.AccessControl.FileSystemRights]::WriteData -bor
                [Security.AccessControl.FileSystemRights]::AppendData -bor
                [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
                [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
                [Security.AccessControl.FileSystemRights]::Delete -bor
                [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                [Security.AccessControl.FileSystemRights]::TakeOwnership
            )
            if (($granted -band $writeLikeRights) -ne 0 -or
                $expectedRights -ne
                    [Security.AccessControl.FileSystemRights]::Read) {
                throw (
                    'runtime secret grants the gateway write-like access or ' +
                    'does not pair with the read-only verifier contract'
                )
            }
        }
        # The reverse direction: a grant the verifier does not model is read by
        # its administrator-only reader allow-list as an untrusted principal.
        if ($expectedRights -eq 0 -and $granted -ne 0) {
            throw (
                "installer ACL kind {0} grants the gateway service {1}, " +
                "but verifier rights kind {2} is administrator-only"
            ) -f $aclKind, $granted, $rightsKind
        }
        $checked++
    }
    return $checked
} $pairings $directoryKinds $serviceSID
if ($pairingsChecked -ne $pairings.Count) {
    throw 'installer/verifier pairing check did not exercise every pairing'
}

# The builder declares the ACL kinds and the applier accepts them. Both sets
# must be identical and exactly what this smoke covers; a kind in only one of
# them fails at install time on parameter validation.
$kindSetsAgree = & $module {
    param($Cases)
    $validValues = {
        param($CommandName)
        $command = Microsoft.PowerShell.Core\Get-Command -Name $CommandName
        $sets = @(
            $command.Parameters['Kind'].Attributes |
                Microsoft.PowerShell.Core\Where-Object {
                    $_ -is [Management.Automation.ValidateSetAttribute]
                }
        )
        if ($sets.Count -ne 1) {
            throw "$CommandName does not declare exactly one Kind validate set"
        }
        return @($sets[0].ValidValues | Microsoft.PowerShell.Utility\Sort-Object)
    }
    $builder = & $validValues 'New-DefenseClawCanonicalPathAcl'
    $applier = & $validValues 'Set-DefenseClawPathAcl'
    $covered = @([string[]]$Cases.Keys | Microsoft.PowerShell.Utility\Sort-Object)
    if (($builder -join "`n") -cne ($applier -join "`n")) {
        throw (
            'canonical ACL kinds diverge between builder and applier: ' +
            "builder=$($builder -join ',') applier=$($applier -join ',')"
        )
    }
    if (($builder -join "`n") -cne ($covered -join "`n")) {
        throw (
            'canonical ACL smoke does not cover every declared kind: ' +
            "declared=$($builder -join ',') covered=$($covered -join ',')"
        )
    }
    return $true
} $expected
if (-not $kindSetsAgree) {
    throw 'canonical ACL kind parity check did not run'
}

# A state-root ancestor such as C:\ProgramData\Cisco is a shared vendor
# directory another product may depend on, so the traverse grant is additive:
# it must not take the owner or drop an ACE it did not add.
$ancestorCases = & $module {
    param($GatewaySID)
    $vendorDirectory = {
        param($SDDL)
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetSecurityDescriptorSddlForm($SDDL)
        return $security
    }
    $sddlOf = {
        param($Security)
        return $Security.GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::All
        )
    }
    # Administrators-owned, with a second product's ACE on it.
    $shared = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
    $granted = & $sddlOf (Add-DefenseClawStateAncestorTraverseRule `
        -Security (& $vendorDirectory $shared) `
        -GatewayServiceSID $GatewaySID)

    $twice = & $sddlOf (Add-DefenseClawStateAncestorTraverseRule `
        -Security (Add-DefenseClawStateAncestorTraverseRule `
            -Security (& $vendorDirectory $shared) `
            -GatewayServiceSID $GatewaySID) `
        -GatewayServiceSID $GatewaySID)

    # An inheritable grant collapses to the non-inherited one.
    $widened = & $sddlOf (Add-DefenseClawStateAncestorTraverseRule `
        -Security (& $vendorDirectory (
            $shared + "(A;OICI;FA;;;$GatewaySID)"
        )) `
        -GatewayServiceSID $GatewaySID)

    [pscustomobject]@{
        foreign_vendor_ace_preserved = $granted -match [regex]::Escape('(A;OICI;0x1200a9;;;BU)')
        owner_preserved = $granted.StartsWith('O:BAG:BA')
        traverse_ace_not_inherited = $granted -match [regex]::Escape("(A;;0x1200a9;;;$GatewaySID)")
        tree_not_seized = -not ($granted -match [regex]::Escape("(A;OICI;0x1200a9;;;$GatewaySID)"))
        repeat_grant_is_idempotent = $twice -ceq $granted
        widened_prior_grant_collapsed = $widened -ceq $granted
    }
} $serviceSID
foreach ($property in $ancestorCases.psobject.Properties) {
    if (-not [bool]$property.Value) {
        throw "state-root ancestor traverse grant regression failed: $($property.Name)"
    }
}

# The fixed AVC IPC directory outlives a certification scope. Purge removes
# only scope A's virtual-service SID; every ACE for another active installation
# and every shared baseline ACE must survive byte-for-byte before scope B
# installs its own canonical descriptor.
$ipcCleanupCases = & $module {
    param($ScopeASID, $ScopeBSID)
    $source = [Security.AccessControl.RawSecurityDescriptor]::new(
        (
            'O:BAG:BAD:P(A;;0x100021;;;AU)(A;;FA;;;SY)(A;;FA;;;BA)' +
            "(A;;FA;;;$ScopeASID)(A;;0x1200a9;;;$ScopeBSID)"
        )
    )
    $scopeBBefore = $null
    foreach ($ace in $source.DiscretionaryAcl) {
        if ($ace -is [Security.AccessControl.KnownAce] -and
            $null -ne $ace.SecurityIdentifier -and
            $ace.SecurityIdentifier.Value -ceq $ScopeBSID) {
            $aceBytes = [byte[]]::new($ace.BinaryLength)
            $ace.GetBinaryForm($aceBytes, 0)
            $scopeBBefore = [Convert]::ToBase64String($aceBytes)
        }
    }

    $first = Remove-DefenseClawSIDFromRawDACL `
        -Descriptor $source `
        -SID $ScopeASID
    $scopeAStillPresent = $false
    $scopeBAfter = $null
    foreach ($ace in $first.descriptor.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.KnownAce] -or
            $null -eq $ace.SecurityIdentifier) {
            continue
        }
        if ($ace.SecurityIdentifier.Value -ceq $ScopeASID) {
            $scopeAStillPresent = $true
        }
        if ($ace.SecurityIdentifier.Value -ceq $ScopeBSID) {
            $aceBytes = [byte[]]::new($ace.BinaryLength)
            $ace.GetBinaryForm($aceBytes, 0)
            $scopeBAfter = [Convert]::ToBase64String($aceBytes)
        }
    }
    $second = Remove-DefenseClawSIDFromRawDACL `
        -Descriptor $first.descriptor `
        -SID $ScopeASID

    $scopeBCanonical = New-DefenseClawCanonicalPathAcl `
        -IsDirectory $true `
        -Kind ManagedIPCDirectory `
        -GatewayServiceSID $ScopeBSID
    $scopeBCanonicalSDDL = $scopeBCanonical.GetSecurityDescriptorSddlForm(
        [Security.AccessControl.AccessControlSections]::All
    )

    $callbackDACL = [Security.AccessControl.RawAcl]::new(2, 1)
    $callbackDACL.InsertAce(
        0,
        [Security.AccessControl.CommonAce]::new(
            [Security.AccessControl.AceFlags]::None,
            [Security.AccessControl.AceQualifier]::AccessAllowed,
            [int][Security.AccessControl.FileSystemRights]::FullControl,
            [Security.Principal.SecurityIdentifier]::new($ScopeASID),
            $true,
            [byte[]]@(1, 2, 3, 4)
        )
    )
    $callbackDescriptor =
        [Security.AccessControl.RawSecurityDescriptor]::new(
            (
                [Security.AccessControl.ControlFlags](
                    [int][Security.AccessControl.ControlFlags]::DiscretionaryAclPresent -bor
                    [int][Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
                )
            ),
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),
            $null,
            $callbackDACL
        )
    $invalidTargetCases = [ordered]@{
        inherited = [Security.AccessControl.RawSecurityDescriptor]::new(
            "O:BAG:BAD:P(A;ID;FA;;;$ScopeASID)"
        )
        deny = [Security.AccessControl.RawSecurityDescriptor]::new(
            "O:BAG:BAD:P(D;;FA;;;$ScopeASID)"
        )
        narrow = [Security.AccessControl.RawSecurityDescriptor]::new(
            "O:BAG:BAD:P(A;;FR;;;$ScopeASID)"
        )
        duplicate = [Security.AccessControl.RawSecurityDescriptor]::new(
            "O:BAG:BAD:P(A;;FA;;;$ScopeASID)(A;;FA;;;$ScopeASID)"
        )
        callback = $callbackDescriptor
    }
    $invalidTargetRejected = @{}
    foreach ($invalidCase in $invalidTargetCases.GetEnumerator()) {
        $rejected = $false
        try {
            [void](Remove-DefenseClawSIDFromRawDACL `
                -Descriptor $invalidCase.Value `
                -SID $ScopeASID)
        }
        catch {
            $expectedFailure = if ([string]$invalidCase.Key -ceq 'duplicate') {
                'duplicate ACEs'
            }
            else {
                'non-canonical ACE'
            }
            $rejected = $_.Exception.Message -match $expectedFailure
        }
        $invalidTargetRejected[[string]$invalidCase.Key] = $rejected
    }

    $retiredOwnerRejected = $false
    $retiredGroupRejected = $false
    try {
        Assert-DefenseClawManagedIPCRetirementDescriptor `
            -Descriptor ([Security.AccessControl.RawSecurityDescriptor]::new(
                ("O:{0}G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)" -f $ScopeASID)
            )) `
            -Path 'ipc-owner-fixture'
    }
    catch {
        $retiredOwnerRejected = $_.Exception.Message -match 'untrusted owner'
    }
    try {
        Assert-DefenseClawManagedIPCRetirementDescriptor `
            -Descriptor ([Security.AccessControl.RawSecurityDescriptor]::new(
                ("O:BAG:{0}D:P(A;;FA;;;SY)(A;;FA;;;BA)" -f $ScopeASID)
            )) `
            -Path 'ipc-group-fixture'
    }
    catch {
        $retiredGroupRejected = $_.Exception.Message -match 'untrusted group'
    }

    [pscustomobject]@{
        exact_scope_ace_removed = (
            [int]$first.removed -eq 1 -and -not $scopeAStillPresent
        )
        unrelated_service_ace_preserved = (
            -not [string]::IsNullOrWhiteSpace($scopeBBefore) -and
            $scopeBBefore -ceq $scopeBAfter
        )
        shared_baseline_aces_preserved = (
            $first.descriptor.GetSddlForm(
                [Security.AccessControl.AccessControlSections]::All
            ) -match ';;;AU\)' -and
            $first.descriptor.GetSddlForm(
                [Security.AccessControl.AccessControlSections]::All
            ) -match ';;;SY\)' -and
            $first.descriptor.GetSddlForm(
                [Security.AccessControl.AccessControlSections]::All
            ) -match ';;;BA\)'
        )
        repeated_cleanup_is_idempotent = ([int]$second.removed -eq 0)
        inherited_target_ace_rejected = [bool]$invalidTargetRejected.inherited
        deny_target_ace_rejected = [bool]$invalidTargetRejected.deny
        narrow_target_ace_rejected = [bool]$invalidTargetRejected.narrow
        duplicate_target_aces_rejected = [bool]$invalidTargetRejected.duplicate
        callback_target_ace_rejected = [bool]$invalidTargetRejected.callback
        retired_sid_owner_rejected = $retiredOwnerRejected
        retired_sid_group_rejected = $retiredGroupRejected
        next_scope_can_be_canonical = (
            $scopeBCanonicalSDDL -match [regex]::Escape(";;;$ScopeBSID)") -and
            -not ($scopeBCanonicalSDDL -match [regex]::Escape(";;;$ScopeASID)"))
        )
    }
} $serviceSID 'S-1-5-80-6-7-8-9-10'
foreach ($property in $ipcCleanupCases.psobject.Properties) {
    if (-not [bool]$property.Value) {
        throw "managed IPC service-SID cleanup regression failed: $($property.Name)"
    }
}

$comparisonCases = & $module {
    $expectedRaw = [Security.AccessControl.RawSecurityDescriptor]::new(
        'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
    )
    $autoInheritedRaw = [Security.AccessControl.RawSecurityDescriptor]::new(
        'O:BAG:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)'
    )
    $extraRaw = [Security.AccessControl.RawSecurityDescriptor]::new(
        'O:BAG:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)'
    )
    $splitRaw = [Security.AccessControl.RawSecurityDescriptor]::new(
        'O:BAG:BAD:PAI(A;;FA;;;SY)' +
            '(A;;0x100000;;;BA)(A;;0x0f01ff;;;BA)'
    )
    [pscustomobject]@{
        auto_inherited_accepted = Test-DefenseClawExactRawDACL `
            -Actual $autoInheritedRaw `
            -Expected $expectedRaw
        extra_ace_rejected = -not (Test-DefenseClawExactRawDACL `
            -Actual $extraRaw `
            -Expected $expectedRaw)
        split_aces_rejected = -not (Test-DefenseClawExactRawDACL `
            -Actual $splitRaw `
            -Expected $expectedRaw)
    }
}
foreach ($property in $comparisonCases.psobject.Properties) {
    if (-not [bool]$property.Value) {
        throw "canonical ACL comparison regression failed: $($property.Name)"
    }
}

$runtimeAdoption = & $module {
    param($GatewaySID)
    $root = [IO.Path]::Combine(
        [IO.Path]::GetTempPath(),
        'DefenseClaw-RuntimeAcl-' + [Guid]::NewGuid().ToString('N')
    )
    try {
        [void](Microsoft.PowerShell.Management\New-Item `
            -ItemType Directory `
            -Path $root `
            -Force)
        $nested = Microsoft.PowerShell.Management\Join-Path $root 'nested'
        [void](Microsoft.PowerShell.Management\New-Item `
            -ItemType Directory `
            -Path $nested `
            -Force)
        $audit = Microsoft.PowerShell.Management\Join-Path $root 'audit.db'
        $sidecar = Microsoft.PowerShell.Management\Join-Path $nested 'audit.db-wal'
        $redactionKey = Microsoft.PowerShell.Management\Join-Path `
            $root `
            'redaction-correlation.key'
        [IO.File]::WriteAllText($audit, 'retained-audit')
        [IO.File]::WriteAllText($sidecar, 'retained-sidecar')
        # This is deterministic fixture material, never a production key. Keep
        # it in memory and expose only boolean preservation results below.
        [IO.File]::WriteAllBytes($redactionKey, [byte[]](0..31))

        # Model the administrator-only tree left by non-purge uninstall.
        foreach ($directory in @($root, $nested)) {
            Set-DefenseClawPathAcl `
                -Path $directory `
                -Kind AdminDirectory `
                -GatewayServiceSID $GatewaySID
        }
        foreach ($file in @($audit, $sidecar, $redactionKey)) {
            Set-DefenseClawPathAcl `
                -Path $file `
                -Kind AdminFile `
                -GatewayServiceSID $GatewaySID
        }

        $native = Initialize-DefenseClawNativeSecurity
        $keyIdentityBefore = ([string]$native::GetFileIdentity(
            $redactionKey
        )).ToLowerInvariant()
        $keyHashBefore = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $redactionKey `
                -Algorithm SHA256
        ).Hash
        $keyBytesBefore = [IO.File]::ReadAllBytes($redactionKey)

        Set-DefenseClawRetainedRuntimeAcls `
            -RuntimeDirectory $root `
            -GatewayServiceSID $GatewaySID
        foreach ($directory in @($root, $nested)) {
            $expectedDirectory = New-DefenseClawCanonicalPathAcl `
                -IsDirectory $true `
                -Kind RuntimeDirectory `
                -GatewayServiceSID $GatewaySID
            Assert-DefenseClawCanonicalPathAcl `
                -Path $directory `
                -Expected $expectedDirectory
        }
        foreach ($file in @($audit, $sidecar)) {
            $expectedFile = New-DefenseClawCanonicalPathAcl `
                -IsDirectory $false `
                -Kind RuntimeFile `
                -GatewayServiceSID $GatewaySID
            Assert-DefenseClawCanonicalPathAcl `
                -Path $file `
                -Expected $expectedFile
        }
        $expectedSecret = New-DefenseClawCanonicalPathAcl `
            -IsDirectory $false `
            -Kind RuntimeSecretFile `
            -GatewayServiceSID $GatewaySID
        Assert-DefenseClawCanonicalPathAcl `
            -Path $redactionKey `
            -Expected $expectedSecret

        $keyIdentityAfter = ([string]$native::GetFileIdentity(
            $redactionKey
        )).ToLowerInvariant()
        $keyHashAfter = (
            Microsoft.PowerShell.Utility\Get-FileHash `
                -LiteralPath $redactionKey `
                -Algorithm SHA256
        ).Hash
        $keyBytesAfter = [IO.File]::ReadAllBytes($redactionKey)
        $keyBytesPreserved = $keyBytesBefore.Length -eq $keyBytesAfter.Length
        if ($keyBytesPreserved) {
            for ($index = 0; $index -lt $keyBytesBefore.Length; $index++) {
                if ($keyBytesBefore[$index] -ne $keyBytesAfter[$index]) {
                    $keyBytesPreserved = $false
                    break
                }
            }
        }

        $linked = Microsoft.PowerShell.Management\Join-Path $root 'linked.db'
        $linkedAlias = Microsoft.PowerShell.Management\Join-Path $root 'linked-alias.db'
        [IO.File]::WriteAllText($linked, 'linked-runtime')
        [void](Microsoft.PowerShell.Management\New-Item `
            -ItemType HardLink `
            -Path $linkedAlias `
            -Target $linked `
            -Force)
        $descriptorBefore = [Convert]::ToBase64String(
            $native::GetFileSecurityDescriptor($linked)
        )
        $hardLinkRejected = $false
        try {
            Set-DefenseClawRetainedRuntimeAcls `
                -RuntimeDirectory $root `
                -GatewayServiceSID $GatewaySID
        }
        catch {
            $hardLinkRejected = $_.Exception.Message -match 'hard links'
        }
        $descriptorAfter = [Convert]::ToBase64String(
            $native::GetFileSecurityDescriptor($linked)
        )
        return [pscustomobject]@{
            retained_tree_adopted = $true
            single_links_enforced = (
                $native::GetRegularFileLinkCountNoFollow($audit) -eq 1 -and
                $native::GetRegularFileLinkCountNoFollow($redactionKey) -eq 1
            )
            runtime_secret_acl_exact = $true
            runtime_secret_bytes_preserved = $keyBytesPreserved
            runtime_secret_hash_preserved = (
                [string]::Equals(
                    $keyHashBefore,
                    $keyHashAfter,
                    [StringComparison]::OrdinalIgnoreCase
                )
            )
            runtime_secret_identity_preserved = (
                $keyIdentityBefore -ceq $keyIdentityAfter
            )
            hard_link_rejected = $hardLinkRejected
            hard_link_preflight_preserved_acl = (
                $descriptorBefore -ceq $descriptorAfter
            )
        }
    }
    finally {
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $root) {
            Microsoft.PowerShell.Management\Remove-Item `
                -LiteralPath $root `
                -Recurse `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }
} $serviceSID
foreach ($property in $runtimeAdoption.psobject.Properties) {
    if (-not [bool]$property.Value) {
        throw "retained runtime ACL adoption regression failed: $($property.Name)"
    }
}

$nativeIPCCleanup = & $module {
    param($ScopeASID, $ScopeBSID)
    $root = [IO.Path]::Combine(
        [IO.Path]::GetTempPath(),
        'DefenseClaw-IPCAcl-' + [Guid]::NewGuid().ToString('N')
    )
    try {
        [void](Microsoft.PowerShell.Management\New-Item `
            -ItemType Directory `
            -Path $root `
            -Force)
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetSecurityDescriptorSddlForm(
            (
                'O:BAG:BAD:P(A;;0x100021;;;AU)(A;;FA;;;SY)' +
                "(A;;FA;;;BA)(A;;FA;;;$ScopeASID)" +
                "(A;;0x1200a9;;;$ScopeBSID)"
            ),
            [Security.AccessControl.AccessControlSections]::All
        )
        Microsoft.PowerShell.Security\Set-Acl `
            -LiteralPath $root `
            -AclObject $security `
            -ErrorAction Stop

        $native = Initialize-DefenseClawNativeSecurity
        $missingPath = Microsoft.PowerShell.Management\Join-Path `
            $root `
            'missing-ipc-directory'
        $nativeAbsenceIsNull = (
            $null -eq $native::GetDirectorySecuritySnapshotNoFollowIfExists(
                $missingPath
            )
        )
        $before = $native::GetDirectorySecuritySnapshotNoFollow($root)
        $beforeDescriptor =
            [Security.AccessControl.RawSecurityDescriptor]::new(
                [byte[]]$before.SecurityDescriptor,
                0
            )
        $filtered = Remove-DefenseClawSIDFromRawDACL `
            -Descriptor $beforeDescriptor `
            -SID $ScopeASID
        $expected = [Security.AccessControl.RawSecurityDescriptor](
            $filtered.descriptor
        )
        $expectedBytes = [byte[]]::new($expected.BinaryLength)
        $expected.GetBinaryForm($expectedBytes, 0)
        $after = $native::SetDirectoryDaclNoFollow(
            $root,
            $expectedBytes,
            [string]$before.Identity
        )
        $actual = [Security.AccessControl.RawSecurityDescriptor]::new(
            [byte[]]$after.SecurityDescriptor,
            0
        )
        $scopeAPresent = $false
        $scopeBPresent = $false
        foreach ($ace in $actual.DiscretionaryAcl) {
            if ($ace -isnot [Security.AccessControl.KnownAce] -or
                $null -eq $ace.SecurityIdentifier) {
                continue
            }
            if ($ace.SecurityIdentifier.Value -ceq $ScopeASID) {
                $scopeAPresent = $true
            }
            if ($ace.SecurityIdentifier.Value -ceq $ScopeBSID) {
                $scopeBPresent = $true
            }
        }
        return [pscustomobject]@{
            identity_preserved = (
                [string]$before.Identity -ceq [string]$after.Identity
            )
            exact_filtered_dacl = Test-DefenseClawExactRawDACL `
                -Actual $actual `
                -Expected $expected
            target_removed = -not $scopeAPresent
            other_service_preserved = $scopeBPresent
            native_absence_is_null = $nativeAbsenceIsNull
        }
    }
    finally {
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $root) {
            Microsoft.PowerShell.Management\Remove-Item `
                -LiteralPath $root `
                -Recurse `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }
} $serviceSID 'S-1-5-80-6-7-8-9-10'
foreach ($property in $nativeIPCCleanup.psobject.Properties) {
    if (-not [bool]$property.Value) {
        throw "native managed IPC cleanup regression failed: $($property.Name)"
    }
}

$nativeDescriptor = & $module {
    param($Path)
    $native = Initialize-DefenseClawNativeSecurity
    [Security.AccessControl.RawSecurityDescriptor]::new(
        $native::GetFileSecurityDescriptor($Path),
        0
    )
} $modulePath
if ($null -eq $nativeDescriptor.DiscretionaryAcl) {
    throw 'native raw ACL query returned a null DACL'
}

[pscustomobject]@{
    ok = $true
    schema_version = 1
    descriptors_checked = $observed.Count
    stale_explicit_aces_retained = $false
    object_type_mismatches_rejected = $true
    auto_inherited_control_flag_accepted = $true
    ace_mismatches_rejected = $true
    native_raw_acl_query_checked = $true
    split_explicit_aces_rejected = $true
    installer_verifier_pairings_checked = $pairingsChecked
    acl_kind_sets_agree = [bool]$kindSetsAgree
    state_ancestor_grant_is_additive = $true
    managed_ipc_scope_cleanup_exact = $true
    managed_ipc_other_service_ace_preserved = $true
    managed_ipc_cleanup_idempotent = $true
    managed_ipc_next_scope_canonical = $true
    managed_ipc_native_handle_cleanup = $true
    managed_ipc_noncanonical_target_aces_rejected = $true
    managed_ipc_retired_sid_owner_group_rejected = $true
    retained_runtime_tree_adopted = $true
    retained_runtime_hard_links_rejected = $true
    retained_runtime_secret_acl_exact = $true
    retained_runtime_secret_bytes_preserved = $true
    retained_runtime_secret_hash_preserved = $true
    retained_runtime_secret_identity_preserved = $true
} | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress
