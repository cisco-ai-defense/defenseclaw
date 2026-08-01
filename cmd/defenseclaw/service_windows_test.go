//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

func TestRunWindowsServiceIsStrictNoOpWithoutEnterpriseMarker(t *testing.T) {
	t.Setenv(windowsServiceNameEnv, "")
	originalDetector := isWindowsService
	detectorCalled := false
	isWindowsService = func() (bool, error) {
		detectorCalled = true
		return false, errors.New("ordinary CLI must not observe this detector failure")
	}
	t.Cleanup(func() { isWindowsService = originalDetector })

	executorCalled := false
	handled, code := runWindowsService(func(context.Context) int {
		executorCalled = true
		return 0
	})
	if handled || code != 0 {
		t.Fatalf("ordinary startup result = handled:%v code:%d, want strict no-op", handled, code)
	}
	if detectorCalled || executorCalled {
		t.Fatalf(
			"ordinary startup called enterprise machinery: detector=%v executor=%v",
			detectorCalled,
			executorCalled,
		)
	}
}

func TestRunWindowsServiceConsultsDetectorOnlyWithEnterpriseMarker(t *testing.T) {
	t.Setenv(windowsServiceNameEnv, defaultGatewayServiceName)
	originalDetector := isWindowsService
	detectorCalled := false
	isWindowsService = func() (bool, error) {
		detectorCalled = true
		return false, nil
	}
	t.Cleanup(func() { isWindowsService = originalDetector })

	handled, code := runWindowsService(func(context.Context) int {
		t.Fatal("non-SCM invocation ran the service executor")
		return 1
	})
	if handled || code != 0 || !detectorCalled {
		t.Fatalf(
			"marked non-SCM startup = handled:%v code:%d detector:%v",
			handled,
			code,
			detectorCalled,
		)
	}
}

func TestValidWindowsServiceNameRejectsCommandInjectionCharacters(t *testing.T) {
	for _, name := range []string{
		defaultGatewayServiceName,
		defaultGuardianServiceName,
		"DefenseClawGateway-Cert-123",
		"com.cisco.defenseclaw.gateway",
	} {
		if !validWindowsServiceName(name) {
			t.Fatalf("validWindowsServiceName(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"", "DefenseClaw Gateway", `name\other`, "name;sc.exe stop other", "\r\n"} {
		if validWindowsServiceName(name) {
			t.Fatalf("validWindowsServiceName(%q) = true, want false", name)
		}
	}
}

func TestWindowsServiceStopCancelsExecutorAndExitsCleanly(t *testing.T) {
	requests := make(chan svc.ChangeRequest, 2)
	changes := make(chan svc.Status, 8)
	executorStarted := make(chan struct{})
	handler := &defenseClawWindowsService{
		execute: func(ctx context.Context) int {
			close(executorStarted)
			<-ctx.Done()
			// Cleanup failure after an accepted administrator stop must not
			// trigger SCM recovery and race servicing.
			return 91
		},
	}
	result := make(chan struct {
		specific bool
		code     uint32
	}, 1)
	go func() {
		specific, code := handler.Execute(nil, requests, changes)
		result <- struct {
			specific bool
			code     uint32
		}{specific: specific, code: code}
	}()

	select {
	case <-executorStarted:
	case <-time.After(time.Second):
		t.Fatal("service executor did not start")
	}

	waitForServiceState(t, changes, svc.Running)
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	waitForServiceState(t, changes, svc.StopPending)

	select {
	case got := <-result:
		if got.specific || got.code != 0 {
			t.Fatalf("service stop result = specific:%v code:%d, want clean exit", got.specific, got.code)
		}
	case <-time.After(time.Second):
		t.Fatal("service did not stop after context cancellation")
	}
}

func TestWindowsServiceStartupFailureUsesFailFastRecovery(t *testing.T) {
	original := terminateWindowsService
	terminated := make(chan uint32, 1)
	terminateWindowsService = func(code uint32) { terminated <- code }
	t.Cleanup(func() { terminateWindowsService = original })

	changes := make(chan svc.Status, 2)
	handler := &defenseClawWindowsService{execute: func(context.Context) int { return 17 }}
	specific, code := handler.Execute(nil, make(chan svc.ChangeRequest), changes)
	if !specific || code != 17 {
		t.Fatalf("startup result = specific:%v code:%d, want service-specific 17", specific, code)
	}
	if state := (<-changes).State; state != svc.StartPending {
		t.Fatalf("first state = %v, want StartPending", state)
	}
	select {
	case got := <-terminated:
		if got != 17 {
			t.Fatalf("fail-fast exit = %d, want 17", got)
		}
	default:
		t.Fatal("startup failure returned without fail-fast process termination")
	}
}

func TestWindowsServiceUnexpectedRunningExitUsesFailFastRecovery(t *testing.T) {
	original := terminateWindowsService
	terminated := make(chan uint32, 1)
	terminateWindowsService = func(code uint32) { terminated <- code }
	t.Cleanup(func() { terminateWindowsService = original })

	release := make(chan struct{})
	changes := make(chan svc.Status, 4)
	handler := &defenseClawWindowsService{execute: func(context.Context) int {
		<-release
		return 0
	}}
	result := make(chan uint32, 1)
	go func() {
		_, code := handler.Execute(nil, make(chan svc.ChangeRequest), changes)
		result <- code
	}()
	waitForServiceState(t, changes, svc.Running)
	close(release)
	select {
	case code := <-terminated:
		if code != 1 {
			t.Fatalf("zero unexpected exit normalized to %d, want 1", code)
		}
	case <-time.After(time.Second):
		t.Fatal("unexpected running exit did not invoke fail-fast recovery")
	}
	select {
	case code := <-result:
		if code != 1 {
			t.Fatalf("test fallback code = %d, want 1", code)
		}
	case <-time.After(time.Second):
		t.Fatal("handler test seam did not return")
	}
}

func TestWindowsServiceStopTimeoutRemainsStoppedWithoutRecovery(t *testing.T) {
	originalTerminate := terminateWindowsService
	originalWait := windowsServiceStopWait
	terminated := make(chan uint32, 1)
	terminateWindowsService = func(code uint32) { terminated <- code }
	windowsServiceStopWait = 25 * time.Millisecond
	t.Cleanup(func() {
		terminateWindowsService = originalTerminate
		windowsServiceStopWait = originalWait
	})

	release := make(chan struct{})
	started := make(chan struct{})
	requests := make(chan svc.ChangeRequest, 1)
	changes := make(chan svc.Status, 4)
	handler := &defenseClawWindowsService{execute: func(context.Context) int {
		close(started)
		<-release
		return 73
	}}
	result := make(chan struct {
		specific bool
		code     uint32
	}, 1)
	go func() {
		specific, code := handler.Execute(nil, requests, changes)
		result <- struct {
			specific bool
			code     uint32
		}{specific: specific, code: code}
	}()
	<-started
	waitForServiceState(t, changes, svc.Running)
	requests <- svc.ChangeRequest{Cmd: svc.PreShutdown}
	waitForServiceState(t, changes, svc.StopPending)
	select {
	case got := <-result:
		if got.specific || got.code != 0 {
			t.Fatalf("stop-timeout result = specific:%v code:%d, want clean stop", got.specific, got.code)
		}
	case <-time.After(time.Second):
		t.Fatal("bounded service stop did not return")
	}
	select {
	case code := <-terminated:
		t.Fatalf("intentional stop timeout invoked crash recovery with %d", code)
	default:
	}
	close(release)
}

func TestEnterpriseServiceSDDLGrantsBuiltinUsersQueryOnly(t *testing.T) {
	module := readWindowsEnterpriseModule(t)
	match := regexp.MustCompile(`(?m)^\$script:ServiceSDDL = '([^']+)'`).FindSubmatch(module)
	if len(match) != 2 {
		t.Fatal("ServiceSDDL was not found in the Windows enterprise module")
	}
	sd, err := windows.SecurityDescriptorFromString(string(match[1]))
	if err != nil {
		t.Fatalf("SecurityDescriptorFromString: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL: %v", err)
	}
	if dacl == nil {
		t.Fatal("ServiceSDDL has a null DACL")
	}

	const (
		serviceQueryConfig         = windows.ACCESS_MASK(0x0001)
		serviceChangeConfig        = windows.ACCESS_MASK(0x0002)
		serviceQueryStatus         = windows.ACCESS_MASK(0x0004)
		serviceEnumerateDependents = windows.ACCESS_MASK(0x0008)
		serviceStart               = windows.ACCESS_MASK(0x0010)
		serviceStop                = windows.ACCESS_MASK(0x0020)
		servicePauseContinue       = windows.ACCESS_MASK(0x0040)
		serviceInterrogate         = windows.ACCESS_MASK(0x0080)
		serviceUserControl         = windows.ACCESS_MASK(0x0100)
		deleteAccess               = windows.ACCESS_MASK(0x00010000)
		readControl                = windows.ACCESS_MASK(0x00020000)
		writeDACL                  = windows.ACCESS_MASK(0x00040000)
		writeOwner                 = windows.ACCESS_MASK(0x00080000)
	)
	required := serviceQueryConfig | serviceQueryStatus | serviceEnumerateDependents |
		serviceInterrogate | readControl
	forbidden := serviceChangeConfig | serviceStart | serviceStop | servicePauseContinue |
		serviceUserControl | deleteAccess | writeDACL | writeOwner

	var usersMask windows.ACCESS_MASK
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			t.Fatalf("GetAce(%d): %v", index, err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.String() == "S-1-5-32-545" {
			usersMask |= ace.Mask
		}
	}
	if usersMask&required != required {
		t.Fatalf("Builtin Users service mask %#x lacks query-only rights %#x", usersMask, required)
	}
	if usersMask&forbidden != 0 {
		t.Fatalf("Builtin Users service mask %#x grants control rights %#x", usersMask, usersMask&forbidden)
	}
}

func TestRestrictedGatewayExecutableACLIncludesExactServiceSID(t *testing.T) {
	module := string(readWindowsEnterpriseModule(t))
	for _, contract := range []string{
		"Set-DefenseClawPathAcl -Path $Layout.InstallRoot -Kind ServiceInstallDirectory",
		"Set-DefenseClawPathAcl -Path $Layout.BinDirectory -Kind ServiceInstallDirectory",
		"Set-DefenseClawPathAcl -Path $Layout.GatewayPath -Kind ServiceInstallFile",
		"$required[$GatewayServiceSID] = [Security.AccessControl.FileSystemRights]::ReadAndExecute",
	} {
		if !strings.Contains(module, contract) {
			t.Fatalf("restricted service executable ACL contract missing %q", contract)
		}
	}
}

func TestGuardianServiceRequiredPrivilegesMatchBoundedRepairConsumer(t *testing.T) {
	module := string(readWindowsEnterpriseModule(t))
	normalized := strings.ReplaceAll(module, "\r\n", "\n")
	for _, contract := range []string{
		"'SeTcbPrivilege/SeImpersonatePrivilege/SeChangeNotifyPrivilege/SeBackupPrivilege/SeRestorePrivilege'",
		"'SeTcbPrivilege',\n",
		"'SeImpersonatePrivilege',\n",
		"'SeChangeNotifyPrivilege',\n",
		"'SeBackupPrivilege',\n",
		"'SeRestorePrivilege'\n",
	} {
		if !strings.Contains(normalized, contract) {
			t.Fatalf("guardian required-privilege contract missing %q", contract)
		}
	}
	if strings.Contains(module, "'privs', $GuardianServiceName, 'SeTakeOwnershipPrivilege") {
		t.Fatal("guardian service must not receive SeTakeOwnershipPrivilege")
	}
}

func TestTransactionRollbackValidatesServiceOwnershipBeforeMutation(t *testing.T) {
	module := string(readWindowsEnterpriseModule(t))
	start := strings.Index(module, "function Restore-DefenseClawTransaction")
	end := strings.Index(module, "function Complete-DefenseClawTransaction")
	if start < 0 || end <= start {
		t.Fatal("transaction rollback function boundaries were not found")
	}
	rollback := module[start:end]
	gatewayOwnership := strings.Index(rollback, "Assert-DefenseClawOwnedServiceOrAbsent `")
	guardianOwnership := strings.Index(
		rollback[gatewayOwnership+1:],
		"Assert-DefenseClawOwnedServiceOrAbsent `",
	)
	stop := strings.Index(rollback, "Stop-DefenseClawService -Name $name")
	if gatewayOwnership < 0 || guardianOwnership < 0 || stop < 0 {
		t.Fatal("transaction rollback ownership/mutation contract is incomplete")
	}
	guardianOwnership += gatewayOwnership + 1
	if gatewayOwnership > stop || guardianOwnership > stop {
		t.Fatal("transaction rollback can stop a service before proving ownership")
	}
}

func TestCertificationCodexHomeIsOptInAndPinnedAcrossLifecycle(t *testing.T) {
	module := string(readWindowsEnterpriseModule(t))
	normalized := strings.ReplaceAll(module, "\r\n", "\n")

	for _, contract := range []string{
		"^DefenseClawCertGateway_[a-f0-9]{10}$",
		"^DefenseClawCertGuardian_[a-f0-9]{10}$",
		"$gatewayRunID -cne $guardianRunID",
		"certification CODEX_HOME basename must be exactly",
		"certification CODEX_HOME must be on a local fixed NTFS volume",
		"Assert-DefenseClawNoReparsePath -Path $full",
		"certification_codex_home = [string]$Layout.CertificationCodexHome",
		"$metadata['certification_codex_home'] = [string]$Layout.CertificationCodexHome",
		"deployment metadata certification CODEX_HOME does not match the requested lifecycle scope",
		"$snapshotCertificationCodexHome = Resolve-DefenseClawCertificationCodexHome",
		"'CODEX_HOME'",
		"[Environment]::SetEnvironmentVariable(\n            'CODEX_HOME',",
		"[Environment]::SetEnvironmentVariable(\n            'CODEX_HOME',\n            $null,",
	} {
		if !strings.Contains(normalized, contract) {
			t.Fatalf("certification CODEX_HOME lifecycle contract missing %q", contract)
		}
	}

	resolver := windowsPowerShellFunction(t, normalized, "Resolve-DefenseClawCertificationCodexHome")
	for _, required := range []string{
		"Resolve-DefenseClawFullPath -Path $Path -MustExist",
		"[int]$logicalDisk.DriveType -ne 3",
		"[string]$logicalDisk.FileSystem",
		"'NTFS'",
	} {
		if !strings.Contains(resolver, required) {
			t.Fatalf("certification CODEX_HOME resolver missing %q", required)
		}
	}

	environment := windowsPowerShellFunction(t, normalized, "Get-DefenseClawServiceEnvironmentValues")
	if strings.Contains(environment, "CertificationCodexHome") ||
		strings.Contains(environment, "CODEX_HOME") {
		t.Fatal("SCM service environments must never receive certification CODEX_HOME")
	}
}

func TestAllowUnsignedIsRestrictedBeforeImportAndArtifactValidation(t *testing.T) {
	module := strings.ReplaceAll(string(readWindowsEnterpriseModule(t)), "\r\n", "\n")
	installer := strings.ReplaceAll(string(readWindowsEnterpriseInstaller(t)), "\r\n", "\n")

	for label, script := range map[string]string{
		"bootstrap": installer,
		"module":    module,
	} {
		for _, contract := range []string{
			"-AllowUnsigned is restricted to exact disposable DefenseClaw certification scope",
			"^DefenseClawCertGateway_([a-f0-9]{10})$",
			"DefenseClawCertGuardian_$runID",
			"'Cisco',\n        'DefenseClaw-Cert',\n        $runID",
			".codex-defenseclaw-cert-$runID",
		} {
			if !strings.Contains(script, contract) {
				t.Fatalf("%s unsigned certification gate missing %q", label, contract)
			}
		}
	}

	bootstrapGate := strings.Index(installer, "Assert-DefenseClawBootstrapUnsignedCertificationScope `")
	bootstrapTrust := strings.Index(installer, "$modulePath = Assert-DefenseClawBootstrapModuleTrust `")
	moduleImport := strings.Index(installer, "Microsoft.PowerShell.Core\\Import-Module `")
	moduleImportName := -1
	if moduleImport >= 0 {
		moduleImportName = strings.Index(installer[moduleImport:], "-Name $modulePath `")
	}
	if bootstrapGate < 0 || bootstrapTrust < 0 || moduleImport < 0 ||
		moduleImportName < 0 ||
		bootstrapGate > bootstrapTrust || bootstrapTrust > moduleImport {
		t.Fatal("bootstrap can trust/import an unsigned module before validating exact certification scope")
	}

	lifecycle := windowsPowerShellFunction(t, module, "Invoke-DefenseClawEnterpriseLifecycle")
	moduleGate := strings.Index(lifecycle, "Assert-DefenseClawUnsignedCertificationScope `")
	sourceValidation := strings.Index(lifecycle, "$sources = Get-DefenseClawLifecycleSources `")
	if moduleGate < 0 || sourceValidation < 0 || moduleGate > sourceValidation {
		t.Fatal("lifecycle can validate/install unsigned artifacts before validating exact certification scope")
	}
}

func TestWindowsCodexMachinePolicyLifecycleIsTransactionalAndFailClosed(t *testing.T) {
	module := strings.ReplaceAll(string(readWindowsEnterpriseModule(t)), "\r\n", "\n")
	installer := strings.ReplaceAll(string(readWindowsEnterpriseInstaller(t)), "\r\n", "\n")

	for _, contract := range []string{
		"OpenAI',\n            'Codex',\n            'requirements.toml'",
		".defenseclaw-managed-hooks.state",
		"codex-requirements-ownership.json",
		"codex-requirements-acl-backup.json",
		"agent-application-control-attestation.json",
		"'enterprise',\n            'windows',\n            'codex-requirements',",
		"safe_to_remove_binary",
		"managed_state_removed_or_absent",
		"restored_preimage",
		"surgical_preservation",
		"codex_machine_policy_managed",
	} {
		if !strings.Contains(module, contract) {
			t.Fatalf("Windows Codex machine-policy lifecycle missing %q", contract)
		}
	}

	transaction := windowsPowerShellFunction(t, module, "New-DefenseClawTransaction")
	for _, path := range []string{
		"$Layout.CodexMachinePolicyPath",
		"$Layout.CodexManagedHooksStatePath",
		"$Layout.CodexRequirementsOwnershipPath",
		"$Layout.CodexRequirementsAclBackupPath",
		"$Layout.CodexTrustedShellAttestationPath",
	} {
		if !strings.Contains(transaction, path) {
			t.Fatalf("lifecycle transaction omits %s", path)
		}
	}

	installLike := windowsPowerShellFunction(t, module, "Invoke-DefenseClawInstallLikeLifecycle")
	preflight := strings.Index(installLike, "Assert-DefenseClawCodexMachinePolicyFilePreflight -Layout $Layout")
	snapshot := strings.Index(installLike, "$snapshot = New-DefenseClawTransaction `")
	aclBackup := strings.Index(installLike, "Initialize-DefenseClawCodexRequirementsAclBackup `")
	firstCanonicalACL := strings.Index(installLike, "Set-DefenseClawManagedAcls `")
	reconcile := strings.Index(installLike, "-Action reconcile)")
	metadataWrite := strings.Index(installLike, "Write-DefenseClawJsonAtomic -Value $newMetadata")
	fullVerify := strings.Index(installLike, "Assert-DefenseClawEnterpriseDeployment `")
	if preflight < 0 || snapshot < 0 || preflight > snapshot {
		t.Fatal("shared Codex files can be snapshotted before preflight authentication")
	}
	if aclBackup < 0 || firstCanonicalACL < 0 || aclBackup > firstCanonicalACL {
		t.Fatal("Codex requirements ACL preimage is not captured before canonicalization")
	}
	if reconcile < 0 || metadataWrite < 0 || fullVerify < 0 ||
		reconcile > metadataWrite || metadataWrite > fullVerify {
		t.Fatal("fresh install must reconcile, publish protected metadata, then run standalone verify")
	}
	if strings.Contains(installLike[reconcile:metadataWrite], "-Action verify)") {
		t.Fatal("fresh install invokes standalone verify before deployment metadata exists")
	}

	uninstall := windowsPowerShellFunction(t, module, "Invoke-DefenseClawUninstallLifecycle")
	removePolicy := strings.Index(uninstall, "-Action remove")
	deleteGuardian := strings.Index(uninstall, "Remove-DefenseClawService -Name $GuardianServiceName")
	if removePolicy < 0 || deleteGuardian < 0 || removePolicy > deleteGuardian {
		t.Fatal("uninstall can delete managed binaries/services before proving Codex policy removal")
	}

	if !strings.Contains(installer, "[switch]$AttestAgentApplicationControl") ||
		!strings.Contains(installer, "[switch]$AttestCodexTrustedHookLauncher") ||
		strings.Contains(installer, "AttestCodexTrustedShellEnforcement") ||
		strings.Contains(installer, "AttestCodexApplicationControl") {
		t.Fatal("public installer does not expose the split application-control and Codex launcher attestations")
	}
}

func TestWindowsServicesNeverReceiveCodexHomeAndRequireBothAppControlPins(t *testing.T) {
	module := strings.ReplaceAll(string(readWindowsEnterpriseModule(t)), "\r\n", "\n")
	environment := windowsPowerShellFunction(t, module, "Get-DefenseClawServiceEnvironmentValues")
	if strings.Contains(environment, "CODEX_HOME") ||
		strings.Contains(environment, "DEFENSECLAW_WINDOWS_CODEX_TRUSTED_SHELL_ENFORCED") ||
		!strings.Contains(environment, "DEFENSECLAW_WINDOWS_CODEX_TRUSTED_HOOK_LAUNCHER_VERIFIED=1") ||
		!strings.Contains(environment, "DEFENSECLAW_WINDOWS_CODEX_APPROVED_CLIENT_ENFORCED=1") ||
		!strings.Contains(environment, "DEFENSECLAW_WINDOWS_APPROVED_AGENT_CLIENTS_ENFORCED=1") ||
		!strings.Contains(environment, "DEFENSECLAW_WINDOWS_CLAUDE_EFFECTIVE_POLICY_VERIFIED=1") {
		t.Fatal("service environment must omit CODEX_HOME and pin every application-control claim")
	}
	gatewayCommand := windowsPowerShellFunction(t, module, "Invoke-DefenseClawGatewayCommand")
	if !strings.Contains(
		gatewayCommand,
		"'CODEX_HOME',\n            $null,\n            'Process'",
	) {
		t.Fatal("elevated lifecycle helpers do not explicitly remove inherited CODEX_HOME")
	}
	lifecycle := windowsPowerShellFunction(t, module, "Invoke-DefenseClawEnterpriseLifecycle")
	if !strings.Contains(lifecycle, "Install requires -AttestAgentApplicationControl") ||
		!strings.Contains(lifecycle, "unapproved agent runtimes") {
		t.Fatal("managed install does not fail closed without broad application-control attestation")
	}
}

func TestWindowsLifecycleUsesProtectedFileLockNotSquattableGlobalObject(t *testing.T) {
	module := strings.ReplaceAll(string(readWindowsEnterpriseModule(t)), "\r\n", "\n")
	if strings.Contains(module, "Global\\Cisco.DefenseClaw.EnterpriseLifecycle") ||
		strings.Contains(module, "CreateMutexExW") ||
		strings.Contains(module, "CreateLifecycleMutex") {
		t.Fatal("enterprise lifecycle still relies on a predictable globally squattable mutex")
	}
	lock := windowsPowerShellFunction(t, module, "Enter-DefenseClawLifecycleLock")
	for _, contract := range []string{
		"$Layout.LifecycleLockPath",
		"[IO.FileMode]::CreateNew",
		"[IO.FileShare]::None",
		"Assert-DefenseClawNoReparsePath -Path $path",
		"Assert-DefenseClawPathAcl `",
	} {
		if !strings.Contains(lock, contract) {
			t.Fatalf("protected lifecycle file lock missing %q", contract)
		}
	}
	transaction := windowsPowerShellFunction(t, module, "New-DefenseClawTransaction")
	stopGuardian := strings.Index(transaction, "Stop-DefenseClawService -Name $GuardianServiceName")
	fileSnapshot := strings.Index(transaction, "$files = [Collections.Generic.List[object]]::new()")
	if stopGuardian < 0 || fileSnapshot < 0 || stopGuardian > fileSnapshot {
		t.Fatal("guardian can mutate managed files while transaction preimages are captured")
	}
}

func windowsPowerShellFunction(t *testing.T, module, name string) string {
	t.Helper()
	start := strings.Index(module, "function "+name+" {")
	if start < 0 {
		t.Fatalf("PowerShell function %s was not found", name)
	}
	remainder := module[start+len("function "+name+" {"):]
	next := strings.Index(remainder, "\nfunction ")
	if next < 0 {
		return module[start:]
	}
	return module[start : start+len("function "+name+" {")+next]
}

func readWindowsEnterpriseInstaller(t *testing.T) []byte {
	t.Helper()
	installerPath := filepath.Join("..", "..", "packaging", "windows", "install-enterprise.ps1")
	installer, err := os.ReadFile(installerPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", installerPath, err)
	}
	return installer
}

func readWindowsEnterpriseModule(t *testing.T) []byte {
	t.Helper()
	modulePath := filepath.Join("..", "..", "packaging", "windows", "DefenseClawEnterprise.psm1")
	module, err := os.ReadFile(modulePath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", modulePath, err)
	}
	return module
}

func waitForServiceState(t *testing.T, changes <-chan svc.Status, want svc.State) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case status := <-changes:
			if status.State == want {
				return
			}
		case <-deadline:
			t.Fatalf("service did not report state %v", want)
		}
	}
}
