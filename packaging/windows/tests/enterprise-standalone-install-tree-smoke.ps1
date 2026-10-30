# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Standalone uninstall and the two directories a standalone install adds under
# InstallRoot: <InstallRoot>\ipc\ (the sensor helper's AF_UNIX socket, a
# reparse file on Windows) and <InstallRoot>\share\opencode\index.js
# (the managed OpenCode plugin the guardian installs from the payload). The
# install-tree walk must accept exactly those directories and their expected
# leaves, removal after the services are gone must delete only them (refusing
# links and anything else, and deleting nothing when it refuses), and the
# Secure Client allow-list must stay unchanged. Runs elevated in a short
# disposable directory (AF_UNIX paths are limited to 108 characters) under
# Windows PowerShell 5.1 and PowerShell 7; the live socket leaf needs .NET's
# AF_UNIX support, so only PowerShell 7 binds one. No service or real machine
# root is touched; the strict-ancestor rollback cases use a disposable
# protected folder under ProgramData, which they remove.

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

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

$root = [IO.Path]::Combine(
    [IO.Path]::GetFullPath($ScratchRoot),
    ('dcit-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root, [bool]$BindSocket)
        $failures = [Collections.Generic.List[string]]::new()
        $openSockets = [Collections.Generic.List[object]]::new()
        $originalProfile = Get-DefenseClawEnterpriseProfile
        $trustedBase = ''
        try {
            function New-TestLayout([string]$Name, [string]$Base = $Root) {
                $install = [IO.Path]::Combine($Base, $Name, 'DefenseClaw')
                $bin = [IO.Path]::Combine($install, 'bin')
                $libexec = [IO.Path]::Combine($install, 'libexec')
                [void][IO.Directory]::CreateDirectory($bin)
                [void][IO.Directory]::CreateDirectory($libexec)
                $gateway = [IO.Path]::Combine($bin, 'defenseclaw-gateway.exe')
                [IO.File]::WriteAllText($gateway, 'stand-in')
                return @{
                    InstallRoot = $install
                    BinDirectory = $bin
                    LibexecDirectory = $libexec
                    ManagedIPCDirectory = [IO.Path]::Combine($install, 'ipc')
                    GatewayPath = $gateway
                    BrokerPath = ''
                    ACPPath = ''
                    HookPath = ''
                    SensorHelperPath = ''
                    CLIPath = ''
                    InstallerPath = ''
                    ModulePath = ''
                }
            }
            function New-Plugin([hashtable]$Layout) {
                $directory = [IO.Path]::Combine($Layout.InstallRoot, 'share', 'opencode')
                [void][IO.Directory]::CreateDirectory($directory)
                $plugin = [IO.Path]::Combine($directory, 'index.js')
                [IO.File]::WriteAllText($plugin, '// defenseclaw-managed-opencode-plugin v1')
                return $plugin
            }
            function New-TestLink([string]$Path, [string]$Target) {
                try {
                    [void](Microsoft.PowerShell.Management\New-Item -ItemType SymbolicLink -Path $Path -Target $Target)
                    return $true
                }
                catch {
                    $failures.Add('could not create a symbolic link (the smoke must run elevated)')
                    return $false
                }
            }
            function Test-Refused([string]$Label, [scriptblock]$Action, [string]$Pattern) {
                try {
                    & $Action
                    $failures.Add("${Label}: expected a refusal")
                }
                catch {
                    if ($_.Exception.Message -notmatch $Pattern) {
                        $failures.Add("${Label}: unexpected refusal: $($_.Exception.Message)")
                    }
                }
            }
            function Test-SecureClientTreeDrift([string]$Label, [hashtable]$Layout, [string]$Pattern) {
                $prior = [Environment]::GetEnvironmentVariable('DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS', 'Process')
                try {
                    [Environment]::SetEnvironmentVariable('DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS', '1', 'Process')
                    Test-Refused "$Label (strict)" { Assert-DefenseClawManagedInstallTree -Layout $Layout } $Pattern
                    [Environment]::SetEnvironmentVariable('DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS', $null, 'Process')
                    try {
                        Assert-DefenseClawManagedInstallTree -Layout $Layout 3>$null
                    }
                    catch {
                        $failures.Add("${Label}: bulldoze posture refused: $($_.Exception.Message)")
                    }
                }
                finally {
                    [Environment]::SetEnvironmentVariable('DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS', $prior, 'Process')
                }
            }
            function Test-Accepted([string]$Label, [hashtable]$Layout) {
                try {
                    Assert-DefenseClawManagedInstallTree -Layout $Layout
                }
                catch {
                    $failures.Add("${Label} was refused: $($_.Exception.Message)")
                }
            }

            Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone

            # The ipc directory: its socket leaf is accepted and removed with it.
            $layout = New-TestLayout 'ipc'
            [void][IO.Directory]::CreateDirectory($layout.ManagedIPCDirectory)
            if ($BindSocket) {
                # Keep the socket open: .NET unlinks the socket file when a
                # bound socket is disposed, and the test needs the file the
                # way a crashed service leaves it.
                $socketPath = [IO.Path]::Combine($layout.ManagedIPCDirectory, 'sensor-helper.sock')
                $socket = [Net.Sockets.Socket]::new(
                    [Net.Sockets.AddressFamily]::Unix,
                    [Net.Sockets.SocketType]::Stream,
                    [Net.Sockets.ProtocolType]::Unspecified
                )
                $openSockets.Add($socket)
                $socket.Bind([Net.Sockets.UnixDomainSocketEndPoint]::new($socketPath))
                if (([IO.File]::GetAttributes($socketPath) -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
                    $failures.Add('stand-in socket is not a reparse file; the test would not exercise the AF_UNIX case')
                }
            }
            Test-Accepted 'standalone tree with ipc' $layout
            Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $layout
            if ([IO.Directory]::Exists($layout.ManagedIPCDirectory)) {
                $failures.Add('standalone ipc directory survived removal')
            }
            Test-Accepted 'tree without ipc' $layout
            # Removal with no ipc directory is a no-op.
            Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $layout

            # The managed OpenCode plugin: accepted and removed with its two
            # directories, leaving the rest of the tree.
            $layout = New-TestLayout 'plugin'
            $paths = Get-DefenseClawStandaloneOpenCodePluginPaths -Layout $layout
            $plugin = New-Plugin $layout
            if (-not [string]::Equals([string]$paths.PluginPath, [IO.Path]::GetFullPath($plugin), [StringComparison]::OrdinalIgnoreCase)) {
                $failures.Add("plugin path $($paths.PluginPath), want $plugin")
            }
            Test-Accepted 'standalone tree with the managed OpenCode plugin' $layout
            try {
                Assert-DefenseClawInstallTreeRetirementState -Layout $layout -AllowUnretiredAcls
            }
            catch {
                $failures.Add("committed install-tree check refused the managed OpenCode plugin before finalization: $($_.Exception.Message)")
            }
            $retiredAllowlist = Get-DefenseClawRetiredInstallTreeAllowlist `
                -Layout $layout `
                -RetiredRoot $layout.InstallRoot
            if ([string]$paths.PluginPath -in $retiredAllowlist.files -or
                [string]$paths.PluginDirectory -in $retiredAllowlist.directories -or
                [string]$paths.ShareDirectory -in $retiredAllowlist.directories) {
                $failures.Add('the retired tree still permits the managed OpenCode plugin after finalization')
            }
            Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $layout
            foreach ($gone in @($plugin, [string]$paths.PluginDirectory, [string]$paths.ShareDirectory)) {
                if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $gone) {
                    $failures.Add("$gone survived removal")
                }
            }
            if (-not [IO.Directory]::Exists($layout.BinDirectory)) {
                $failures.Add('removal touched the bin directory')
            }
            Test-Accepted 'tree without the plugin' $layout
            # Removal with nothing installed is a no-op.
            Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $layout

            # Uninstall after a V1 upgrade can reach the pre-finalization
            # boundary with the old artifact alone or both generations. Both
            # are accepted there and must be removed before retirement.
            foreach ($withCurrentPlugin in @($false, $true)) {
                $upgraded = New-TestLayout ('plugin-v1-upgrade-' + $withCurrentPlugin)
                $upgradePaths = Get-DefenseClawStandaloneOpenCodePluginPaths -Layout $upgraded
                [void][IO.Directory]::CreateDirectory([string]$upgradePaths.PluginDirectory)
                if ($withCurrentPlugin) { [void](New-Plugin $upgraded) }
                [IO.File]::WriteAllText([string]$upgradePaths.LegacyPluginPath, '// old managed bridge')
                Test-Accepted 'standalone tree with the legacy managed plugin' $upgraded
                try {
                    Assert-DefenseClawInstallTreeRetirementState -Layout $upgraded -AllowUnretiredAcls
                }
                catch {
                    $failures.Add("committed install-tree check refused the legacy OpenCode plugin before finalization: $($_.Exception.Message)")
                }
                $retiredAllowlist = Get-DefenseClawRetiredInstallTreeAllowlist `
                    -Layout $upgraded `
                    -RetiredRoot $upgraded.InstallRoot
                if ([string]$upgradePaths.LegacyPluginPath -in $retiredAllowlist.files) {
                    $failures.Add('the retired tree permits the legacy managed plugin after finalization')
                }
                Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $upgraded
                if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $upgradePaths.ShareDirectory) {
                    $failures.Add('the legacy managed OpenCode artifact survived uninstall')
                }
            }

            # GAP-0270: a 1.0.2 standalone install left lib\defenseclaw for
            # the Fleet compiler this release no longer installs. Uninstall
            # accepts the two directories only while they are empty, and a
            # Fleet-off upgrade removes them. Any content stays refused and
            # the retire deletes nothing but the old compiler.
            function Get-RetiredLib([hashtable]$Layout) {
                return [IO.Path]::Combine($Layout.InstallRoot, 'lib')
            }
            $absent = New-TestLayout 'retired-absent'
            Test-Accepted 'tree without the retired lib directories' $absent
            Remove-DefenseClawRetiredStandaloneCompiler -Layout $absent
            if (-not [IO.File]::Exists($absent.GatewayPath)) {
                $failures.Add('the retire with no lib tree touched bin')
            }

            $empty = New-TestLayout 'retired-empty'
            $emptyLib = Get-RetiredLib $empty
            $emptyChild = [IO.Path]::Combine($emptyLib, 'defenseclaw')
            [void][IO.Directory]::CreateDirectory($emptyChild)
            Test-Accepted 'tree with the empty retired lib\defenseclaw' $empty
            try {
                Assert-DefenseClawStandaloneUninstallInstallTree -Layout $empty
            }
            catch {
                $failures.Add("standalone uninstall refused the empty retired lib tree: $($_.Exception.Message)")
            }
            [IO.Directory]::Delete($emptyChild)
            Test-Accepted 'tree with only the empty retired lib' $empty
            [void][IO.Directory]::CreateDirectory($emptyChild)
            Remove-DefenseClawRetiredStandaloneCompiler -Layout $empty
            if ([IO.Directory]::Exists($emptyLib)) {
                $failures.Add('the Fleet-off retire left the empty lib tree')
            }
            if (-not [IO.File]::Exists($empty.GatewayPath)) {
                $failures.Add('the Fleet-off retire touched bin')
            }
            Test-Accepted 'tree after the Fleet-off retire' $empty

            $compiler = New-TestLayout 'retired-compiler'
            $compilerChild = [IO.Path]::Combine((Get-RetiredLib $compiler), 'defenseclaw')
            [void][IO.Directory]::CreateDirectory($compilerChild)
            [IO.File]::WriteAllText([IO.Path]::Combine($compilerChild, 'policy_compiler.py'), 'print("compiler")')
            Test-Refused 'retired lib\defenseclaw holding the old compiler (walk)' {
                Assert-DefenseClawManagedInstallTree -Layout $compiler
            } 'unexpected (file|directory) from managed install root'
            Remove-DefenseClawRetiredStandaloneCompiler -Layout $compiler
            if ([IO.Directory]::Exists((Get-RetiredLib $compiler))) {
                $failures.Add('the Fleet-off retire left the compiler or its lib tree')
            }
            Test-Accepted 'tree after retiring the old compiler' $compiler

            $kept = New-TestLayout 'retired-nonempty'
            $keptChild = [IO.Path]::Combine((Get-RetiredLib $kept), 'defenseclaw')
            [void][IO.Directory]::CreateDirectory($keptChild)
            $keptCompiler = [IO.Path]::Combine($keptChild, 'policy_compiler.py')
            $keptOther = [IO.Path]::Combine($keptChild, 'other.py')
            [IO.File]::WriteAllText($keptCompiler, 'print("compiler")')
            [IO.File]::WriteAllText($keptOther, 'print("unexpected")')
            Test-Refused 'non-empty retired lib\defenseclaw (uninstall)' {
                Assert-DefenseClawStandaloneUninstallInstallTree -Layout $kept
            } 'unexpected (file|directory) from managed install root: .*The uninstall stopped before it changed anything'
            Remove-DefenseClawRetiredStandaloneCompiler -Layout $kept
            if ([IO.File]::Exists($keptCompiler)) {
                $failures.Add('the Fleet-off retire kept the old compiler beside other content')
            }
            if (-not [IO.File]::Exists($keptOther)) {
                $failures.Add('the Fleet-off retire removed content DefenseClaw did not install')
            }
            Test-Refused 'non-empty retired lib\defenseclaw after the retire (walk)' {
                Assert-DefenseClawManagedInstallTree -Layout $kept
            } 'unexpected (file|directory) from managed install root'

            $sibling = New-TestLayout 'retired-sibling'
            $siblingDirectory = [IO.Path]::Combine((Get-RetiredLib $sibling), 'other')
            [void][IO.Directory]::CreateDirectory($siblingDirectory)
            Test-Refused 'unknown directory under the retired lib (walk)' {
                Assert-DefenseClawManagedInstallTree -Layout $sibling
            } 'unexpected directory from managed install root'
            Remove-DefenseClawRetiredStandaloneCompiler -Layout $sibling
            if (-not [IO.Directory]::Exists($siblingDirectory)) {
                $failures.Add('the Fleet-off retire removed an unknown directory under lib')
            }

            $linked = New-TestLayout 'retired-linked'
            [void][IO.Directory]::CreateDirectory((Get-RetiredLib $linked))
            $linkedTarget = [IO.Path]::Combine($Root, 'outside-lib')
            [void][IO.Directory]::CreateDirectory($linkedTarget)
            [IO.File]::WriteAllText([IO.Path]::Combine($linkedTarget, 'policy_compiler.py'), 'print("outside")')
            if (New-TestLink ([IO.Path]::Combine((Get-RetiredLib $linked), 'defenseclaw')) $linkedTarget) {
                # The walk's recorded-compiler check (GAP-0274) refuses the
                # link before the walk reaches lib.
                Test-Refused 'linked retired lib\defenseclaw (walk)' {
                    Assert-DefenseClawManagedInstallTree -Layout $linked
                } 'reparse point'
                Test-Refused 'linked retired lib\defenseclaw (retire)' {
                    Remove-DefenseClawRetiredStandaloneCompiler -Layout $linked
                } 'reparse point'
                if (-not [IO.File]::Exists([IO.Path]::Combine($linkedTarget, 'policy_compiler.py'))) {
                    $failures.Add('the Fleet-off retire followed a link out of the install tree')
                }
            }

            # GAP-0274: a Fleet-enabled 1.0.2 host keeps the compiler it
            # installed. Setup carries none, so an upgrade keeps the recorded
            # compiler in place, unchanged, and records the same hash; the
            # uninstall accepts and removes it only while it matches its
            # record and refuses a changed one before anything changes. Fleet
            # off still retires it with its directories (GAP-0270).
            $script:SmokeMetadata = $null
            function script:Get-DefenseClawDeploymentMetadata {
                param([hashtable]$Layout, [switch]$Required)
                return $script:SmokeMetadata
            }
            function New-FleetLayout([string]$Name) {
                $layout = New-TestLayout $Name
                foreach ($entry in @(
                    @('ACPPath', 'bin', 'defenseclaw-acp.exe'),
                    @('HookPath', 'bin', 'defenseclaw-hook.exe'),
                    @('SensorHelperPath', 'bin', 'defenseclaw-sensor-helper.exe'),
                    @('InstallerPath', 'libexec', 'install-enterprise.ps1'),
                    @('ModulePath', 'libexec', 'DefenseClawEnterprise.psm1')
                )) {
                    $path = [IO.Path]::Combine($layout.InstallRoot, $entry[1], $entry[2])
                    [IO.File]::WriteAllText($path, "stand-in $($entry[2])")
                    $layout[$entry[0]] = $path
                }
                $layout['CLIPath'] = [IO.Path]::Combine($layout.BinDirectory, 'defenseclaw.exe')
                $layout['Profile'] = 'Standalone'
                $layout['BrokerEnabled'] = $false
                $layout['MetadataPath'] = [IO.Path]::Combine($Root, $Name, 'deployment.json')
                $layout['CompilerLibDirectory'] = [IO.Path]::Combine($layout.InstallRoot, 'lib')
                $layout['CompilerDirectory'] = [IO.Path]::Combine($layout.InstallRoot, 'lib', 'defenseclaw')
                $layout['CompilerPath'] = [IO.Path]::Combine($layout.InstallRoot, 'lib', 'defenseclaw', 'policy_compiler.py')
                [void][IO.Directory]::CreateDirectory($layout.CompilerDirectory)
                [IO.File]::WriteAllText($layout.CompilerPath, 'print("1.0.2 compiler")')
                return $layout
            }
            function New-FleetMetadata([hashtable]$Layout, [switch]$WithoutCompiler) {
                $hashes = [ordered]@{}
                foreach ($entry in @(
                    @('gateway', $Layout.GatewayPath),
                    @('compiler', $Layout.CompilerPath),
                    @('acp', $Layout.ACPPath),
                    @('hook', $Layout.HookPath),
                    @('sensor_helper', $Layout.SensorHelperPath),
                    @('installer', $Layout.InstallerPath),
                    @('module', $Layout.ModulePath)
                )) {
                    if ($WithoutCompiler -and $entry[0] -ceq 'compiler') {
                        continue
                    }
                    $hashes[$entry[0]] = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $entry[1] -Algorithm SHA256).Hash.ToLowerInvariant()
                }
                return [pscustomobject]@{ hashes = [pscustomobject]$hashes }
            }
            function Get-CompilerHash([hashtable]$Layout) {
                return (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $Layout.CompilerPath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            # Setup replaces every payload artifact; it has no compiler.
            $setupReplaces = @('gateway', 'acp', 'hook', 'sensor_helper', 'installer', 'module', 'cli')

            # Fleet-on upgrade: the recorded compiler is kept and still matches.
            $fleetOn = New-FleetLayout 'fleet-on'
            $script:SmokeMetadata = New-FleetMetadata $fleetOn
            $recordedCompiler = [string]$script:SmokeMetadata.hashes.compiler
            $keptPath = Get-DefenseClawRecordedStandaloneCompilerPath -Layout $fleetOn
            if (-not [string]::Equals($keptPath, [IO.Path]::GetFullPath($fleetOn.CompilerPath), [StringComparison]::OrdinalIgnoreCase)) {
                $failures.Add("Fleet-on upgrade did not keep the recorded compiler: '$keptPath'")
            }
            if ((Get-DefenseClawArtifactPath -Layout $fleetOn -Name compiler) -ne $fleetOn.CompilerPath) {
                $failures.Add('the recorded compiler hash does not map to the kept compiler')
            }
            try {
                Assert-DefenseClawRecordedArtifactHashes -Metadata $script:SmokeMetadata -Layout $fleetOn -ReplacedArtifacts $setupReplaces -Action Upgrade
            }
            catch {
                $failures.Add("Fleet-on upgrade refused the recorded compiler: $($_.Exception.Message)")
            }
            if ((Get-CompilerHash $fleetOn) -cne $recordedCompiler) {
                $failures.Add('the Fleet-on upgrade checks changed the kept compiler')
            }
            # Fleet-on uninstall with the matching compiler: accepted, and the
            # retired-tree allow-list removes it with its directories.
            Test-Accepted 'Fleet-on tree with the recorded compiler' $fleetOn
            try {
                Assert-DefenseClawStandaloneUninstallInstallTree -Layout $fleetOn
                Assert-DefenseClawRecordedArtifactHashes -Metadata $script:SmokeMetadata -Layout $fleetOn -Action Uninstall
            }
            catch {
                $failures.Add("Fleet-on uninstall refused the recorded compiler: $($_.Exception.Message)")
            }
            $retiredAllowlist = Get-DefenseClawRetiredInstallTreeAllowlist -Layout $fleetOn -RetiredRoot $fleetOn.InstallRoot
            if ([IO.Path]::GetFullPath($fleetOn.CompilerPath) -notin $retiredAllowlist.files -or
                [IO.Path]::GetFullPath($fleetOn.CompilerDirectory) -notin $retiredAllowlist.directories -or
                [IO.Path]::GetFullPath($fleetOn.CompilerLibDirectory) -notin $retiredAllowlist.directories) {
                $failures.Add('the retired install tree does not remove the kept compiler and its directories')
            }

            # Fleet-on with a changed compiler: Setup, the upgrade gate and the
            # uninstall all refuse, and nothing is removed.
            [IO.File]::AppendAllText($fleetOn.CompilerPath, "`nprint('changed')")
            Test-Refused 'changed compiler (Setup keep check)' {
                Get-DefenseClawRecordedStandaloneCompilerPath -Layout $fleetOn
            } 'does not match the hash deployment metadata records for it: .*nothing was changed$'
            Test-Refused 'changed compiler (upgrade gate)' {
                Assert-DefenseClawRecordedArtifactHashes -Metadata $script:SmokeMetadata -Layout $fleetOn -ReplacedArtifacts $setupReplaces -Action Upgrade
            } 'Upgrade refuses unrecorded artifact hash drift: compiler'
            Test-Refused 'changed compiler (uninstall)' {
                Assert-DefenseClawStandaloneUninstallInstallTree -Layout $fleetOn
            } 'does not match the hash deployment metadata records for it: .*nothing was changed$'
            Test-Refused 'changed compiler (uninstall hash gate)' {
                Assert-DefenseClawRecordedArtifactHashes -Metadata $script:SmokeMetadata -Layout $fleetOn -Action Uninstall
            } 'Uninstall refuses unrecorded artifact hash drift: compiler'
            if (-not [IO.File]::Exists($fleetOn.CompilerPath)) {
                $failures.Add('a refused uninstall removed the changed compiler')
            }

            # A compiler with no record is not kept, and the uninstall refuses it.
            $unrecorded = New-FleetLayout 'fleet-unrecorded'
            $script:SmokeMetadata = New-FleetMetadata $unrecorded -WithoutCompiler
            if (-not [string]::IsNullOrEmpty((Get-DefenseClawRecordedStandaloneCompilerPath -Layout $unrecorded))) {
                $failures.Add('a compiler with no record was kept')
            }
            Test-Refused 'unrecorded compiler (uninstall)' {
                Assert-DefenseClawStandaloneUninstallInstallTree -Layout $unrecorded
            } 'unexpected (file|directory) from managed install root: .*The uninstall stopped before it changed anything'

            # Fleet off: unchanged, the retire removes even a recorded
            # compiler with its directories and leaves the rest.
            $fleetOff = New-FleetLayout 'fleet-off'
            $script:SmokeMetadata = New-FleetMetadata $fleetOff
            Remove-DefenseClawRetiredStandaloneCompiler -Layout $fleetOff
            if ([IO.Directory]::Exists($fleetOff.CompilerLibDirectory)) {
                $failures.Add('the Fleet-off retire kept the recorded compiler or its lib tree')
            }
            if (-not [IO.File]::Exists($fleetOff.GatewayPath) -or -not [IO.File]::Exists($fleetOff.ModulePath)) {
                $failures.Add('the Fleet-off retire touched other artifacts')
            }
            $script:SmokeMetadata = New-FleetMetadata $fleetOff -WithoutCompiler
            Test-Accepted 'tree after the Fleet-off retire of a recorded compiler' $fleetOff
            $script:SmokeMetadata = $null

            # Anything other than the exact leaves stays refused, and a
            # refused removal deletes nothing.
            $extra = New-TestLayout 'extra-ipc'
            [void][IO.Directory]::CreateDirectory($extra.ManagedIPCDirectory)
            $plantedIPC = [IO.Path]::Combine($extra.ManagedIPCDirectory, 'planted.txt')
            [IO.File]::WriteAllText($plantedIPC, 'x')
            Test-Refused 'unexpected ipc file (walk)' { Assert-DefenseClawManagedInstallTree -Layout $extra } 'unexpected file'
            Test-Refused 'unexpected ipc file (removal)' { Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $extra } 'unexpected managed IPC content'
            $extra = New-TestLayout 'extra-plugin'
            $extraPlugin = New-Plugin $extra
            $plantedPlugin = [IO.Path]::Combine([IO.Path]::GetDirectoryName($extraPlugin), 'planted.js')
            [IO.File]::WriteAllText($plantedPlugin, 'x')
            Test-Refused 'unexpected plugin file (walk)' { Assert-DefenseClawManagedInstallTree -Layout $extra } 'unexpected file'
            Test-Refused 'unexpected plugin file (committed check)' {
                Assert-DefenseClawInstallTreeRetirementState -Layout $extra -AllowUnretiredAcls
            } 'committed InstallRoot contains unexpected content'
            Test-Refused 'unexpected plugin file (removal)' { Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $extra } 'unexpected managed OpenCode content'
            foreach ($kept in @($plantedIPC, $plantedPlugin, $extraPlugin)) {
                if (-not [IO.File]::Exists($kept)) {
                    $failures.Add("refused removal still deleted content: $kept")
                }
            }

            # GAP-0743, GAP-0772: Windows renames but does not delete a
            # program that is running, so the copy File.Replace keeps of a
            # running defenseclaw-acp.exe stays. The upgrade still succeeds,
            # the copy is deleted at the next restart, and the uninstall
            # sweep removes what an earlier upgrade left.
            $restartDeletes = [Collections.Generic.List[string]]::new()
            function Request-DefenseClawDeleteAtRestart {
                param([string]$Path)
                $restartDeletes.Add($Path)
            }
            $busy = New-TestLayout 'busy'
            $guard = [IO.Path]::Combine($busy.BinDirectory, 'defenseclaw-acp.exe')
            [IO.File]::Copy([IO.Path]::Combine([Environment]::SystemDirectory, 'PING.EXE'), $guard)
            $busy.ACPPath = $guard
            $newer = [IO.Path]::Combine($Root, 'newer-guard.exe')
            [IO.File]::WriteAllText($newer, 'newer guard')
            $running = Microsoft.PowerShell.Management\Start-Process `
                -FilePath $guard `
                -ArgumentList @('-n', '120', '127.0.0.1') `
                -WindowStyle Hidden `
                -PassThru
            try {
                Install-DefenseClawFileAtomic -Source $newer -Destination $guard
            }
            catch {
                $failures.Add("replacing a running program failed: $($_.Exception.Message)")
            }
            finally {
                Microsoft.PowerShell.Management\Stop-Process -Id $running.Id -Force
                $running.WaitForExit()
            }
            if ([IO.File]::ReadAllText($guard) -cne 'newer guard') {
                $failures.Add('the running program was not replaced')
            }
            $copies = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $busy.BinDirectory -Force -Filter 'defenseclaw-acp.exe.backup.*')
            if ($copies.Count -ne 1 -or $restartDeletes.Count -ne 1 -or $restartDeletes[0] -ne $copies[0].FullName) {
                $failures.Add("the running program's copy was not left for deletion at restart: $($copies.Count) copies, $($restartDeletes -join ', ')")
            }
            Test-Refused 'tree with an earlier upgrade copy (walk)' { Assert-DefenseClawManagedInstallTree -Layout $busy } 'unexpected file'

            # GAP-0852: a handle that shares only read access (as an antivirus
            # scan holds a file) failed the replacement with a raw sharing
            # violation. The refusal names the held file and the retry step,
            # and the file keeps its bytes.
            $held = New-TestLayout 'held'
            $heldTarget = [IO.Path]::Combine($held.BinDirectory, 'defenseclaw-hook.exe')
            [IO.File]::WriteAllText($heldTarget, 'old hook')
            $heldSource = [IO.Path]::Combine($Root, 'newer-hook.exe')
            [IO.File]::WriteAllText($heldSource, 'newer hook')
            $handle = [IO.File]::Open($heldTarget, 'Open', 'Read', 'Read')
            try {
                Test-Refused 'replacement of a file another program holds open' {
                    Install-DefenseClawFileAtomic -Source $heldSource -Destination $heldTarget
                } ([regex]::Escape("another program holds $heldTarget open") + '.*run Setup again')
            }
            finally {
                $handle.Dispose()
            }
            if ([IO.File]::ReadAllText($heldTarget) -cne 'old hook') {
                $failures.Add('a refused replacement changed the held file')
            }
            Remove-DefenseClawStandaloneInstallTreeReplacementBackups -Layout $busy
            if (@(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $busy.BinDirectory -Force -Filter 'defenseclaw-acp.exe.backup.*').Count -ne 0) {
                $failures.Add('the uninstall sweep left the earlier upgrade copy')
            }
            Test-Accepted 'tree after the uninstall sweep' $busy

            # GAP-1190: a file DefenseClaw did not install (an administrator's
            # renamed copy of the hook) stops the standalone uninstall before
            # it changes anything, and the refusal names the file and the step.
            $renamed = New-TestLayout 'renamed'
            $away = [IO.Path]::Combine($renamed.BinDirectory, 'defenseclaw-hook.exe.away')
            [IO.File]::WriteAllText($away, 'renamed hook')
            Test-Refused 'uninstall with a renamed hook copy' {
                Assert-DefenseClawStandaloneUninstallInstallTree -Layout $renamed
            } ('unexpected file from managed install root: .*\\defenseclaw-hook\.exe\.away\. ' +
                'The uninstall stopped before it changed anything\..* move it out of .*DefenseClaw, ' +
                'then run the uninstall again$')
            if (-not [IO.File]::Exists($away)) {
                $failures.Add('the refused uninstall removed the renamed copy')
            }

            # GAP-1446: a hook guardian stopped while it restored the hook
            # (a 1.0.3 guardian during an upgrade) leaves its temporary,
            # defenseclaw-hook.exe.restore-<16 hex>, in bin. That is
            # DefenseClaw's own residue: the uninstall sweep and the next
            # replacement of the hook remove it, and the uninstall goes on.
            # Look-alike names stay unexpected content and stay in place.
            $residue = New-TestLayout 'restore-residue'
            $residue.HookPath = [IO.Path]::Combine($residue.BinDirectory, 'defenseclaw-hook.exe')
            [IO.File]::WriteAllText($residue.HookPath, 'hook')
            $temporaries = @(
                [IO.Path]::Combine($residue.BinDirectory, 'defenseclaw-hook.exe.restore-9665dbd235221f34'),
                [IO.Path]::Combine($residue.BinDirectory, 'defenseclaw-hook.exe.restore-245951e62c1a3e11')
            )
            foreach ($temporary in $temporaries) { [IO.File]::WriteAllText($temporary, 'partial hook') }
            Test-Refused 'uninstall with a guardian restore temporary (before the sweep)' {
                Assert-DefenseClawStandaloneUninstallInstallTree -Layout $residue
            } 'unexpected file from managed install root: .*defenseclaw-hook\.exe\.restore-'
            Remove-DefenseClawStandaloneInstallTreeReplacementBackups -Layout $residue
            foreach ($temporary in $temporaries) {
                if ([IO.File]::Exists($temporary)) {
                    $failures.Add("the uninstall sweep left the guardian restore temporary $temporary")
                }
            }
            try {
                Assert-DefenseClawStandaloneUninstallInstallTree -Layout $residue
            }
            catch {
                $failures.Add("uninstall after the sweep of guardian restore temporaries was refused: $($_.Exception.Message)")
            }
            foreach ($lookAlike in @(
                'defenseclaw-hook.exe.restore-9665DBD235221F34',
                'defenseclaw-hook.exe.restore-9665dbd235221f3',
                'defenseclaw-hook.exe.restore-9665dbd235221f345',
                'defenseclaw-hook.exe.restore-9665dbd235221f3g',
                'defenseclaw-hook.exe.restore-',
                'xdefenseclaw-hook.exe.restore-9665dbd235221f34'
            )) {
                $kept = New-TestLayout ('restore-lookalike-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
                $kept.HookPath = [IO.Path]::Combine($kept.BinDirectory, 'defenseclaw-hook.exe')
                [IO.File]::WriteAllText($kept.HookPath, 'hook')
                $planted = [IO.Path]::Combine($kept.BinDirectory, $lookAlike)
                [IO.File]::WriteAllText($planted, 'not ours')
                Remove-DefenseClawStandaloneInstallTreeReplacementBackups -Layout $kept
                if (-not [IO.File]::Exists($planted)) {
                    $failures.Add("the uninstall sweep removed a look-alike file $lookAlike")
                }
                Test-Refused "uninstall with the look-alike $lookAlike" {
                    Assert-DefenseClawStandaloneUninstallInstallTree -Layout $kept
                } 'unexpected file from managed install root'
            }
            # A directory with the temporary's name is not removed by the sweep.
            $dirResidue = New-TestLayout 'restore-directory'
            $dirResidue.HookPath = [IO.Path]::Combine($dirResidue.BinDirectory, 'defenseclaw-hook.exe')
            [IO.File]::WriteAllText($dirResidue.HookPath, 'hook')
            $dirTemporary = [IO.Path]::Combine($dirResidue.BinDirectory, 'defenseclaw-hook.exe.restore-0123456789abcdef')
            [void][IO.Directory]::CreateDirectory($dirTemporary)
            Remove-DefenseClawStandaloneInstallTreeReplacementBackups -Layout $dirResidue
            if (-not [IO.Directory]::Exists($dirTemporary)) {
                $failures.Add('the uninstall sweep removed a directory named like a guardian restore temporary')
            }
            # The next replacement of the hook removes them too.
            $replaced = New-TestLayout 'restore-replace'
            $replacedHook = [IO.Path]::Combine($replaced.BinDirectory, 'defenseclaw-hook.exe')
            [IO.File]::WriteAllText($replacedHook, 'old hook')
            $replacedTemporary = $replacedHook + '.restore-00112233445566ff'
            [IO.File]::WriteAllText($replacedTemporary, 'partial hook')
            $newHook = [IO.Path]::Combine($Root, 'newer-hook-1446.exe')
            [IO.File]::WriteAllText($newHook, 'newer hook')
            Install-DefenseClawFileAtomic -Source $newHook -Destination $replacedHook
            if ([IO.File]::Exists($replacedTemporary) -or [IO.File]::ReadAllText($replacedHook) -cne 'newer hook') {
                $failures.Add('the hook replacement left its guardian restore temporary')
            }

            $sibling = New-TestLayout 'sibling'
            [void](New-Plugin $sibling)
            [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($sibling.InstallRoot, 'share', 'policies'))
            Test-Refused 'unexpected share directory (walk)' { Assert-DefenseClawManagedInstallTree -Layout $sibling } 'unexpected directory'
            Test-Refused 'unexpected share directory (removal)' { Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $sibling } 'unexpected managed OpenCode content'

            $nested = New-TestLayout 'nested'
            [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($nested.ManagedIPCDirectory, 'sensor-helper.sock'))
            [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($nested.InstallRoot, 'share', 'opencode', 'index.js'))
            Test-Refused 'directory named like the socket' { Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $nested } 'unexpected managed IPC content'
            Test-Refused 'directory named like the plugin' { Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $nested } 'not a plain file'

            $target = [IO.Path]::Combine($Root, 'outside.txt')
            [IO.File]::WriteAllText($target, 'keep')
            $linkedIPC = New-TestLayout 'linked-ipc'
            [void][IO.Directory]::CreateDirectory($linkedIPC.ManagedIPCDirectory)
            if (New-TestLink ([IO.Path]::Combine($linkedIPC.ManagedIPCDirectory, 'sensor-helper.sock')) $target) {
                Test-Refused 'symbolic link named like the socket (walk)' { Assert-DefenseClawManagedInstallTree -Layout $linkedIPC } 'reparse point'
                Test-Refused 'symbolic link named like the socket (removal)' { Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $linkedIPC } 'unexpected managed IPC content'
            }
            foreach ($name in @('index.js', 'defenseclaw.js')) {
                $linkedPlugin = New-TestLayout ('linked-plugin-' + $name)
                $linkedDirectory = [IO.Path]::Combine($linkedPlugin.InstallRoot, 'share', 'opencode')
                [void][IO.Directory]::CreateDirectory($linkedDirectory)
                if (New-TestLink ([IO.Path]::Combine($linkedDirectory, $name)) $target) {
                    Test-Refused 'symbolic link named like the plugin (walk)' { Assert-DefenseClawManagedInstallTree -Layout $linkedPlugin } 'reparse point'
                    Test-Refused 'symbolic link named like the plugin (committed check)' {
                        Assert-DefenseClawInstallTreeRetirementState -Layout $linkedPlugin -AllowUnretiredAcls
                    } 'reparse point'
                    Test-Refused 'symbolic link named like the plugin (removal)' { Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $linkedPlugin } 'not a plain file'
                }
            }
            if (-not [IO.File]::Exists($target)) {
                $failures.Add('link target outside the tree was removed')
            }

            # GAP-1304: a hook process may still hold the executable when a
            # failed fresh install removes its transaction-created root. The
            # authenticated rollback gets a bounded retry after the old
            # five-second delete window, and cannot use it on another root.
            # The rollback walks the install root's ancestors strictly: only
            # SYSTEM, Administrators or TrustedInstaller may own or replace
            # them. A folder this elevated process creates in its temporary
            # directory is owned by its account (the built-in Administrator of
            # a CI runner) and inherits that account's full control, so these
            # cases run in a protected fixture under ProgramData, as a real
            # install root does.
            $trustedBase = [IO.Path]::Combine(
                $env:ProgramData,
                ('DefenseClawInstallTreeSmoke-' + [Guid]::NewGuid().ToString('N'))
            )
            [void](New-DefenseClawProtectedDirectory -Path $trustedBase)
            function New-TrustedTestLayout([string]$Name) {
                $parent = [IO.Path]::Combine($trustedBase, $Name)
                [void](New-DefenseClawProtectedDirectory -Path $parent)
                [void](New-DefenseClawProtectedDirectory -Path ([IO.Path]::Combine($parent, 'DefenseClaw')))
                return New-TestLayout $Name $trustedBase
            }
            $rollback = New-TrustedTestLayout 'rollback-held'
            $rollbackHook = [IO.Path]::Combine($rollback.BinDirectory, 'defenseclaw-hook.exe')
            $ready = [IO.Path]::Combine($Root, 'rollback-hook-held')
            [IO.File]::WriteAllText($rollbackHook, 'stand-in')
            $security = Initialize-DefenseClawNativeSecurity
            $rootSnapshot = $security::GetDirectorySecuritySnapshotNoFollowIfExists($rollback.InstallRoot)
            # Run this same smoke against the pre-fix module: it has no retry
            # parameters, and must fail on the actual held file after its
            # five old attempts. The new module gets the recorded-root guard.
            $rollbackOptions = @{}
            if ((Get-Command Remove-DefenseClawManagedTree).Parameters.ContainsKey('RetryHeldFileMilliseconds')) {
                $rollbackOptions.RetryHeldFileMilliseconds = 15000
                $rollbackOptions.ExpectedRootIdentity = [string]$rootSnapshot.Identity
                $rollbackOptions.ExpectedRootSecurityDescriptor = [byte[]]$rootSnapshot.SecurityDescriptor
            }
            $holder = Start-Job -ScriptBlock {
                param([string]$Hook, [string]$Ready)
                $stream = [IO.File]::Open($Hook, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                try {
                    [IO.File]::WriteAllText($Ready, 'held')
                    Start-Sleep -Seconds 12
                }
                finally { $stream.Dispose() }
            } -ArgumentList $rollbackHook, $ready
            try {
                $clock = [Diagnostics.Stopwatch]::StartNew()
                while (-not [IO.File]::Exists($ready) -and $clock.ElapsedMilliseconds -lt 10000) {
                    Start-Sleep -Milliseconds 100
                }
                if (-not [IO.File]::Exists($ready)) {
                    $failures.Add('the native rollback hook holder did not start')
                }
                else {
                    $priorStrict = [Environment]::GetEnvironmentVariable('DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS', 'Process')
                    try {
                        [Environment]::SetEnvironmentVariable('DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS', '1', 'Process')
                        try {
                            Remove-DefenseClawManagedTree `
                                -Path $rollback.InstallRoot `
                                -RequiredBase $trustedBase `
                                -Label 'InstallRoot' `
                                @rollbackOptions
                        }
                        catch {
                            $failures.Add("fresh-install rollback did not wait for an active hook: $($_.Exception.Message)")
                        }
                        if ([IO.Directory]::Exists($rollback.InstallRoot)) {
                            $failures.Add('fresh-install rollback left the transaction-created root after the hook exited')
                        }
                    }
                    finally {
                        [Environment]::SetEnvironmentVariable('DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS', $priorStrict, 'Process')
                    }
                }
            }
            finally {
                if ($null -ne $holder) {
                    [void](Wait-Job -Job $holder -Timeout 30)
                    if ($holder.State -eq 'Running') { Stop-Job -Job $holder }
                    Remove-Job -Job $holder -Force
                }
            }

            # GAP-1304 (r105): a hook process that runs the executable, not
            # only reads it. Windows refuses to delete a running image but
            # renames it; the restore of a fresh InstallRoot renames it
            # aside and goes on, and anywhere else the refusal stands.
            $running = New-TrustedTestLayout 'rollback-running'
            $runningHook = [IO.Path]::Combine($running.BinDirectory, 'defenseclaw-hook.exe')
            [IO.File]::Copy([IO.Path]::Combine([Environment]::SystemDirectory, 'PING.EXE'), $runningHook)
            $runner = Start-Process -FilePath $runningHook -ArgumentList '-n', '30', '127.0.0.1' -WindowStyle Hidden -PassThru
            try {
                Start-Sleep -Milliseconds 500
                $controlRefused = $false
                try {
                    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $runningHook -Force -ErrorAction Stop
                }
                catch {
                    $controlRefused = $true
                }
                if (-not $controlRefused) {
                    $failures.Add('control: a running hook executable was deleted; the GAP-1304 case did not reproduce')
                }
                elseif (-not (Get-Command Remove-DefenseClawTransactionCreatedFile -ErrorAction SilentlyContinue)) {
                    $failures.Add('fresh-install restore refuses a running hook executable (no rename-aside removal)')
                }
                else {
                    Test-Refused 'running executable outside a fresh InstallRoot' {
                        Remove-DefenseClawTransactionCreatedFile -Path $runningHook
                    } ''
                    try {
                        Remove-DefenseClawTransactionCreatedFile -Path $runningHook -InFreshInstallRoot
                    }
                    catch {
                        $failures.Add("fresh-install restore refused a running hook executable: $($_.Exception.Message)")
                    }
                    if ([IO.File]::Exists($runningHook)) {
                        $failures.Add('fresh-install restore left the running hook executable at its registered path')
                    }
                }
            }
            finally {
                if (-not $runner.HasExited) { $runner.Kill() }
                [void]$runner.WaitForExit(10000)
            }

            $otherRoot = New-TrustedTestLayout 'rollback-other-root'
            $otherSnapshot = $security::GetDirectorySecuritySnapshotNoFollowIfExists($otherRoot.InstallRoot)
            $otherOptions = @{}
            if ($rollbackOptions.Count -gt 0) {
                $otherOptions.RetryHeldFileMilliseconds = 15000
                $otherOptions.ExpectedRootIdentity = [string]$rootSnapshot.Identity
                $otherOptions.ExpectedRootSecurityDescriptor = [byte[]]$otherSnapshot.SecurityDescriptor
            }
            Test-Refused 'fresh-install rollback root identity changed' {
                Remove-DefenseClawManagedTree `
                    -Path $otherRoot.InstallRoot `
                    -RequiredBase $trustedBase `
                    -Label 'InstallRoot' `
                    @otherOptions
            } 'identity changed'
            if (-not [IO.File]::Exists($otherRoot.GatewayPath)) {
                $failures.Add('fresh-install rollback removed a root with a different identity')
            }

            # GAP-1844 / GAP-1988: Restart Manager can lag a fresh handle.
            # (a) It names no holder on the first query and the holder on a
            # later one: the rollback still waits the hook out. (b) Every
            # delete added between those queries re-checks the recorded
            # root first, and stops when that root is no longer the one the
            # transaction created.
            if ($rollbackOptions.Count -gt 0) {
                $savedHolders = ${function:Get-DefenseClawInstallRootHolders}
                $savedRetryRoot = ${function:Test-DefenseClawManagedTreeRetryRoot}
                $priorStrict = [Environment]::GetEnvironmentVariable('DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS', 'Process')
                try {
                    [Environment]::SetEnvironmentVariable('DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS', '1', 'Process')
                    foreach ($case in 'lag', 'swapped') {
                        $lag = New-TrustedTestLayout ('rollback-' + $case)
                        $lagHook = [IO.Path]::Combine($lag.BinDirectory, 'defenseclaw-hook.exe')
                        [IO.File]::WriteAllText($lagHook, 'stand-in')
                        $lagSnapshot = $security::GetDirectorySecuritySnapshotNoFollowIfExists($lag.InstallRoot)
                        $lagReady = [IO.Path]::Combine($Root, 'rollback-' + $case + '-held')
                        $script:SmokeHolderQueries = 0
                        $script:SmokeRootChecks = 0
                        $script:SmokeRootCase = $case
                        function script:Get-DefenseClawInstallRootHolders {
                            param($InstallRoot, $SelfUninstallCallerPID, $ExcludedProcessIds,
                                [switch]$FailOnQueryError, [switch]$IncludeProcessId)
                            $script:SmokeHolderQueries++
                            if ($script:SmokeRootCase -eq 'lag' -and $script:SmokeHolderQueries -ge 2) {
                                return [pscustomobject]@{ Id = 4545; Description = 'defenseclaw-hook.exe (pid 4545)' }
                            }
                            return @()
                        }
                        function script:Test-DefenseClawManagedTreeRetryRoot {
                            param($Path, $ExpectedIdentity, $ExpectedSecurityDescriptor)
                            $script:SmokeRootChecks++
                            if ($script:SmokeRootCase -eq 'swapped' -and $script:SmokeRootChecks -gt 1) {
                                return $false
                            }
                            return $true
                        }
                        $lagHolder = Start-Job -ScriptBlock {
                            param([string]$Hook, [string]$Ready, [int]$Seconds)
                            $stream = [IO.File]::Open($Hook, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                            try {
                                [IO.File]::WriteAllText($Ready, 'held')
                                Start-Sleep -Seconds $Seconds
                            }
                            finally { $stream.Dispose() }
                        } -ArgumentList $lagHook, $lagReady, $(if ($case -eq 'lag') { 9 } else { 20 })
                        try {
                            $clock = [Diagnostics.Stopwatch]::StartNew()
                            while (-not [IO.File]::Exists($lagReady) -and $clock.ElapsedMilliseconds -lt 10000) {
                                Start-Sleep -Milliseconds 100
                            }
                            if (-not [IO.File]::Exists($lagReady)) {
                                $failures.Add("the $case rollback hook holder did not start")
                                continue
                            }
                            $lagError = $null
                            try {
                                Remove-DefenseClawManagedTree `
                                    -Path $lag.InstallRoot `
                                    -RequiredBase $trustedBase `
                                    -Label 'InstallRoot' `
                                    -RetryHeldFileMilliseconds 15000 `
                                    -ExpectedRootIdentity ([string]$lagSnapshot.Identity) `
                                    -ExpectedRootSecurityDescriptor ([byte[]]$lagSnapshot.SecurityDescriptor)
                            }
                            catch { $lagError = $_ }
                            if ($case -eq 'lag') {
                                if ($null -ne $lagError -or [IO.Directory]::Exists($lag.InstallRoot)) {
                                    $failures.Add("fresh-install rollback gave up before Restart Manager named the holder (queries $script:SmokeHolderQueries): $lagError")
                                }
                            }
                            else {
                                if ($null -ne $lagError -or $script:SmokeRootChecks -ne 2 -or $script:SmokeHolderQueries -ne 1 -or
                                    -not [IO.File]::Exists($lagHook)) {
                                    $failures.Add("an added rollback delete ran without re-checking the recorded root (root checks $script:SmokeRootChecks, holder queries $script:SmokeHolderQueries, error $lagError)")
                                }
                            }
                        }
                        finally {
                            [void](Wait-Job -Job $lagHolder -Timeout 30)
                            if ($lagHolder.State -eq 'Running') { Stop-Job -Job $lagHolder }
                            Remove-Job -Job $lagHolder -Force
                            Microsoft.PowerShell.Management\Set-Item -Path function:script:Get-DefenseClawInstallRootHolders -Value $savedHolders
                            Microsoft.PowerShell.Management\Set-Item -Path function:script:Test-DefenseClawManagedTreeRetryRoot -Value $savedRetryRoot
                        }
                    }
                }
                finally {
                    [Environment]::SetEnvironmentVariable('DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS', $priorStrict, 'Process')
                }
            }

            # GAP-0942: an editor's ACP thread that runs defenseclaw-acp.exe
            # from the install folder refuses the uninstall before it changes
            # anything and names the program, account and parent; a process
            # seen only once (a hook call) and this lifecycle do not block.
            $inUse = New-TestLayout 'in-use'
            $script:SmokeProcessPasses = 0
            $acp = [IO.Path]::Combine($inUse.BinDirectory, 'defenseclaw-acp.exe')
            $hook = [IO.Path]::Combine($inUse.BinDirectory, 'defenseclaw-hook.exe')
            function script:Get-DefenseClawProcessImages {
                $script:SmokeProcessPasses++
                [pscustomobject]@{ Id = 4242; Path = $acp; UserName = 'HOST\dcw-w3a1'; Parent = 'zed' }
                [pscustomobject]@{ Id = [int]$PID; Path = $acp; UserName = ''; Parent = '' }
                if ($script:SmokeProcessPasses -eq 1) {
                    [pscustomobject]@{ Id = 4343; Path = $hook; UserName = 'HOST\dcw-w3a2'; Parent = 'claude' }
                }
            }
            $script:InstallTreeUseRecheckMilliseconds = 0
            Test-Refused 'uninstall with an open ACP thread' {
                Assert-DefenseClawStandaloneInstallTreeNotInUse -Layout $inUse -GatewayServiceName DefenseClawGateway -GuardianServiceName DefenseClawHookGuardian
            } '^uninstall_in_use: defenseclaw-acp\.exe \(pid 4242, account HOST\\dcw-w3a1, started by zed\) runs from .*nothing was changed'

            # Secure Client: the AVC IPC directory lives under InstallRoot
            # (path parity with the Go IPC resolver) and a graceful stop leaves it empty,
            # so the uninstall inventory accepts that exact directory (release
            # 26.8.4, #839) but nothing inside it beyond the layout's socket.
            # share is not accepted, and the standalone removal helpers are
            # no-ops.
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
            Assert-DefenseClawStandaloneInstallTreeNotInUse -Layout $inUse -GatewayServiceName DefenseClawGateway -GuardianServiceName DefenseClawHookGuardian
            $secureClient = New-TestLayout 'secure-client-ipc'
            [void][IO.Directory]::CreateDirectory($secureClient.ManagedIPCDirectory)
            Test-Accepted 'Secure Client empty ipc directory' $secureClient
            $secureClientStray = [IO.Path]::Combine($secureClient.ManagedIPCDirectory, 'stray.txt')
            [IO.File]::WriteAllText($secureClientStray, 'x')
            # Release 26.8.4 (#1068) bulldozes Secure Client install-tree
            # drift: an unexpected item is reported and removed with the tree
            # unless the strict trust pin is set, which restores the refusal.
            Test-SecureClientTreeDrift 'Secure Client allow-list (ipc content)' $secureClient 'unexpected file'
            [IO.File]::Delete($secureClientStray)
            Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $secureClient
            if (-not [IO.Directory]::Exists($secureClient.ManagedIPCDirectory)) {
                $failures.Add('Secure Client ipc directory was removed by the standalone helper')
            }
            # A Secure Client layout with the sensor helper admits its exact
            # socket leaf. Uninstall removes only that leaf after the service
            # is gone and leaves the ipc directory for the tree removal; a
            # link at the socket path is still refused.
            $secureClient = New-TestLayout 'scsock'
            $secureClient.SensorHelperPath = [IO.Path]::Combine($secureClient.BinDirectory, 'defenseclaw-sensor-helper.exe')
            [IO.File]::WriteAllText($secureClient.SensorHelperPath, 'stand-in')
            [void][IO.Directory]::CreateDirectory($secureClient.ManagedIPCDirectory)
            $sensorSocket = [IO.Path]::Combine($secureClient.ManagedIPCDirectory, 'sensor-helper.sock')
            if ($BindSocket) {
                $socket = [Net.Sockets.Socket]::new(
                    [Net.Sockets.AddressFamily]::Unix,
                    [Net.Sockets.SocketType]::Stream,
                    [Net.Sockets.ProtocolType]::Unspecified
                )
                $openSockets.Add($socket)
                $socket.Bind([Net.Sockets.UnixDomainSocketEndPoint]::new($sensorSocket))
            }
            else {
                # Windows PowerShell 5.1, which Setup runs, has no AF_UNIX
                # endpoint. A PowerShell 7 child binds the socket and exits
                # without closing it, leaving the reparse file a crashed
                # service leaves; without pwsh a plain file stands in.
                $pwsh = Microsoft.PowerShell.Core\Get-Command pwsh -ErrorAction SilentlyContinue
                if ($null -ne $pwsh) {
                    & $pwsh.Source -NoProfile -NonInteractive -Command (
                        "`$s=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::Unix,[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Unspecified); " +
                        "`$s.Bind([Net.Sockets.UnixDomainSocketEndPoint]::new('$sensorSocket')); [Environment]::Exit(0)"
                    )
                }
                if (-not [IO.File]::Exists($sensorSocket)) {
                    [IO.File]::WriteAllText($sensorSocket, '')
                }
            }
            Test-Accepted 'Secure Client tree with the sensor helper socket' $secureClient
            Remove-DefenseClawSecureClientSensorHelperSocket -Layout $secureClient
            if ([IO.File]::Exists($sensorSocket)) {
                $failures.Add('Secure Client sensor helper socket survived removal')
            }
            if (-not [IO.Directory]::Exists($secureClient.ManagedIPCDirectory)) {
                $failures.Add('Secure Client ipc directory was removed with the sensor helper socket')
            }
            # Removal with no socket is a no-op.
            Remove-DefenseClawSecureClientSensorHelperSocket -Layout $secureClient
            $socketTarget = [IO.Path]::Combine($Root, 'outside-socket.txt')
            [IO.File]::WriteAllText($socketTarget, 'outside')
            if (New-TestLink $sensorSocket $socketTarget) {
                Test-Refused 'Secure Client sensor helper socket link' {
                    Assert-DefenseClawManagedInstallTree -Layout $secureClient
                } 'reparse point'
                Test-Refused 'Secure Client sensor helper socket link removal' {
                    Remove-DefenseClawSecureClientSensorHelperSocket -Layout $secureClient
                } 'unexpected managed IPC content'
                if (-not [IO.File]::Exists($socketTarget)) {
                    $failures.Add('Secure Client socket link removal touched its target')
                }
                [IO.File]::Delete($sensorSocket)
            }
            if (@(Get-DefenseClawSecureClientSensorHelperSocketLeaves -Layout (New-TestLayout 'scnosock')).Count -ne 0) {
                $failures.Add('Secure Client layout without the sensor helper reported a socket leaf')
            }
            $secureClient = New-TestLayout 'secure-client-lib'
            [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($secureClient.InstallRoot, 'lib', 'defenseclaw'))
            Test-Refused 'Secure Client allow-list (retired lib)' { Assert-DefenseClawManagedInstallTree -Layout $secureClient } 'unexpected directory'
            [IO.File]::WriteAllText([IO.Path]::Combine($secureClient.InstallRoot, 'lib', 'defenseclaw', 'policy_compiler.py'), 'print("compiler")')
            if (-not [string]::IsNullOrEmpty((Get-DefenseClawRecordedStandaloneCompilerPath -Layout $secureClient))) {
                $failures.Add('Secure Client kept a Fleet compiler')
            }
            $secureClient = New-TestLayout 'secure-client-share'
            $secureClientPlugin = New-Plugin $secureClient
            Test-SecureClientTreeDrift 'Secure Client allow-list (share)' $secureClient 'unexpected directory'
            Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $secureClient
            if (-not [IO.File]::Exists($secureClientPlugin)) {
                $failures.Add('Secure Client share content was removed by the standalone helper')
            }
            if ($null -ne (Get-DefenseClawStandaloneOpenCodePluginPaths -Layout $secureClient)) {
                $failures.Add('Secure Client reported managed OpenCode plugin paths')
            }
        }
        finally {
            foreach ($open in $openSockets) {
                $open.Dispose()
            }
            if ($trustedBase) {
                Microsoft.PowerShell.Management\Remove-Item -LiteralPath $trustedBase -Recurse -Force -ErrorAction SilentlyContinue
            }
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
        }
        return , $failures
    } $root ($PSVersionTable.PSVersion.Major -ge 7)
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-install-tree-smoke: OK'
