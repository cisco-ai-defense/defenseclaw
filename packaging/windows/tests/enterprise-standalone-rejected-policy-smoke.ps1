# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# GAP-1049: a standalone Repair that restores config.yaml or targets.yaml from
# Setup's approved copy keeps the replaced file as rejected-config.yaml or
# rejected-targets.yaml under the administrator-only descriptor, logs it, and
# lists it for the result. GAP-0602: the exact-DACL refusal of a record another
# account can change names that account in the shape the result rewrites.

[CmdletBinding()]
param([string]$ScratchRoot = [IO.Path]::GetTempPath())

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name ([IO.Path]::GetFullPath((Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))) `
    -Force -PassThru -ErrorAction Stop
$state = [IO.Path]::Combine($ScratchRoot, ('dc-rejected-policy-' + [Guid]::NewGuid().ToString('N')))
$configDirectory = [IO.Path]::Combine($state, 'config')
[void][IO.Directory]::CreateDirectory($configDirectory)

try {
    & $module {
        param($State, $ConfigDirectory)
        $sid = 'S-1-5-80-1-2-3-4-5'
        Set-DefenseClawPathAcl -Path $State -Kind StateDirectory -GatewayServiceSID $sid
        Set-DefenseClawPathAcl -Path $ConfigDirectory -Kind ConfigDirectory -GatewayServiceSID $sid
        $layout = @{ StateRoot = $State; ConfigDirectory = $ConfigDirectory }

        function Add-UsersWrite([string]$Path) {
            $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path
            [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($script:UsersSID),
                [Security.AccessControl.FileSystemRights]::Write,
                [Security.AccessControl.AccessControlType]::Allow))
            Microsoft.PowerShell.Security\Set-Acl -LiteralPath $Path -AclObject $acl
        }
        function Get-UsersEntries([string]$Path) {
            return @((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path).Access |
                Microsoft.PowerShell.Core\Where-Object {
                    (ConvertTo-DefenseClawSID -Identity $_.IdentityReference) -eq $script:UsersSID
                })
        }

        foreach ($case in @(
                @{ Name = 'config'; Leaf = 'config.yaml'; Kind = 'ConfigFile' },
                @{ Name = 'manifest'; Leaf = 'targets.yaml'; Kind = 'AdminFile' })) {
            $installed = [IO.Path]::Combine($ConfigDirectory, $case.Leaf)
            $kept = [IO.Path]::Combine($ConfigDirectory, 'rejected-' + $case.Leaf)
            $body = "# written by a standard user`nname: $($case.Name)`n"
            [IO.File]::WriteAllText($installed, $body)
            Set-DefenseClawPathAcl -Path $installed -Kind $case.Kind -GatewayServiceSID $sid
            Add-UsersWrite -Path $installed
            $approved = [IO.Path]::Combine($State, 'approved-' + $case.Leaf)
            [IO.File]::WriteAllText($approved, "name: approved`n")

            # Secure Client (not the standalone profile): nothing is kept.
            function Test-DefenseClawStandaloneProfile { return $false }
            $script:DefenseClawRestoredPolicyNotes = @()
            $prepared = Save-DefenseClawRejectedStandalonePolicy -Layout $layout -Name $case.Name -Path $installed -ApprovedPath $approved
            Add-DefenseClawRestoredPolicyNote -Kept $prepared
            if ($null -ne $prepared -or [IO.File]::Exists($kept) -or @($script:DefenseClawRestoredPolicyNotes).Count -ne 0) {
                throw "$($case.Leaf): the Secure Client profile kept a rejected file or noted it"
            }

            function Test-DefenseClawStandaloneProfile { return $true }
            $prepared = Save-DefenseClawRejectedStandalonePolicy -Layout $layout -Name $case.Name -Path $installed -ApprovedPath $approved
            if (@($script:DefenseClawRestoredPolicyNotes).Count -ne 0) {
                throw "$($case.Leaf): the restore was noted before it happened"
            }
            Add-DefenseClawRestoredPolicyNote -Kept $prepared
            if (-not [IO.File]::Exists($kept) -or [IO.File]::ReadAllText($kept) -ne $body) {
                throw "$($case.Leaf): the replaced bytes were not kept as $kept"
            }
            if ((Get-UsersEntries -Path $kept).Count -ne 0 -or
                (Get-DefenseClawAclOwnerSID -Acl (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $kept)) -ne $script:AdministratorsSID) {
                throw "$($case.Leaf): the kept file is not administrator-only"
            }
            if ((Get-UsersEntries -Path $installed).Count -eq 0 -or [IO.File]::ReadAllText($installed) -ne $body) {
                throw "$($case.Leaf): keeping the evidence changed the installed file"
            }
            $notes = @($script:DefenseClawRestoredPolicyNotes)
            if ($notes.Count -ne 1 -or -not $notes[0].Contains($kept) -or -not $notes[0].Contains($approved) -or
                -not $notes[0].Contains('untrusted principal')) {
                throw "$($case.Leaf): the note does not name the kept file, the approved copy and the cause: $($notes -join '|')"
            }

            # A second restore replaces the kept file with the newer bytes.
            [IO.File]::WriteAllText($installed, "# second`n")
            [void](Save-DefenseClawRejectedStandalonePolicy -Layout $layout -Name $case.Name -Path $installed -ApprovedPath $approved)
            if ([IO.File]::ReadAllText($kept) -ne "# second`n") {
                throw "$($case.Leaf): a second keep did not replace the kept file"
            }

            # Nothing installed: nothing to keep, no note.
            [IO.File]::Delete($installed)
            [IO.File]::Delete($kept)
            $script:DefenseClawRestoredPolicyNotes = @()
            $prepared = Save-DefenseClawRejectedStandalonePolicy -Layout $layout -Name $case.Name -Path $installed -ApprovedPath $approved
            Add-DefenseClawRestoredPolicyNote -Kept $prepared
            if ([IO.File]::Exists($kept) -or @($script:DefenseClawRestoredPolicyNotes).Count -ne 0) {
                throw "$($case.Leaf): a missing file was kept or noted"
            }
        }

        # GAP-0602: the exact-DACL refusal names the account the result turns into the icacls fix.
        function Test-DefenseClawStandaloneProfile { return $true }
        $record = [IO.Path]::Combine($State, 'deployment.json')
        [IO.File]::WriteAllText($record, '{}')
        Set-DefenseClawPathAcl -Path $record -Kind AdminFile -GatewayServiceSID $script:AdministratorsSID
        $expected = New-DefenseClawCanonicalPathAcl -IsDirectory:$false -Kind AdminFile -GatewayServiceSID $script:AdministratorsSID
        Assert-DefenseClawCanonicalPathAcl -Path $record -Expected $expected
        Add-UsersWrite -Path $record
        $message = ''
        try { Assert-DefenseClawCanonicalPathAcl -Path $record -Expected $expected } catch { $message = $_.Exception.Message }
        if (-not $message.StartsWith('managed path does not have the exact canonical DACL: ' + $record) -or
            -not $message.Contains('untrusted principal ' + $script:UsersSID + ' has write-like access to managed path: ' + $record)) {
            throw "the exact-DACL refusal does not name the account: '$message'"
        }
    } $state $configDirectory
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $state -Recurse -Force -ErrorAction SilentlyContinue
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-rejected-policy-smoke: OK'
