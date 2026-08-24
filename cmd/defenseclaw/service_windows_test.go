//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
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

func TestWindowsServiceHostRedirectsLateCiscoDiagnosticToProtectedLog(t *testing.T) {
	const (
		testAPIKeyEnv       = "DEFENSECLAW_TEST_CISCO_API_KEY"
		responseMarker      = "tenant_mapping_missing"
		privatePromptMarker = "private-request-prompt-marker"
	)
	testAPIKey := strings.ReplaceAll(t.Name(), "/", "-")
	t.Setenv(testAPIKeyEnv, testAPIKey)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("X-Cisco-AI-Defense-API-Key"); got != testAPIKey {
			t.Errorf("Cisco inspect API key header=%q, want test credential", got)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusForbidden)
		_, _ = writer.Write([]byte(
			`{"code":403,"message":"Forbidden","detail":"` + responseMarker + `"}`,
		))
	}))
	t.Cleanup(server.Close)

	client := gateway.NewCiscoInspectClient(&config.CiscoAIDefenseConfig{
		Endpoint:  server.URL,
		APIKeyEnv: testAPIKeyEnv,
		TimeoutMs: 1_000,
	}, "")
	if client == nil {
		t.Fatal("Cisco inspect client is nil")
	}
	managedEnterpriseWasActive := gateway.ManagedEnterpriseActive()
	gateway.SetManagedEnterpriseActive(true)
	t.Cleanup(func() { gateway.SetManagedEnterpriseActive(managedEnterpriseWasActive) })

	serviceLogPath := filepath.Join(t.TempDir(), "gateway.log")
	t.Setenv(windowsServiceNameEnv, defaultGatewayServiceName)
	t.Setenv(windowsServiceLogEnv, serviceLogPath)

	originalDetector := isWindowsService
	originalRunner := runSCMService
	originalStdout := os.Stdout
	originalStderr := os.Stderr
	t.Cleanup(func() {
		isWindowsService = originalDetector
		runSCMService = originalRunner
		os.Stdout = originalStdout
		os.Stderr = originalStderr
	})
	isWindowsService = func() (bool, error) { return true, nil }
	runSCMService = func(name string, handler svc.Handler) error {
		if name != defaultGatewayServiceName {
			t.Errorf("SCM service name=%q, want %q", name, defaultGatewayServiceName)
		}
		requests := make(chan svc.ChangeRequest, 1)
		changes := make(chan svc.Status, 4)
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

		waitForServiceState(t, changes, svc.Running)
		requests <- svc.ChangeRequest{Cmd: svc.Stop}
		waitForServiceState(t, changes, svc.StopPending)
		select {
		case got := <-result:
			if got.specific || got.code != 0 {
				t.Errorf("SCM handler result=specific:%v code:%d, want clean stop", got.specific, got.code)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("SCM handler did not stop")
		}
		return nil
	}

	handled, code := runWindowsService(func(ctx context.Context) int {
		verdict := client.Inspect(ctx, []gateway.ChatMessage{{Role: "user", Content: privatePromptMarker}})
		if verdict != nil {
			t.Errorf("non-200 Cisco response verdict=%+v, want nil", verdict)
		}
		<-ctx.Done()
		return 0
	})
	// runWindowsService closes the log because a production host exits after
	// svc.Run returns. Restore the process streams before any test diagnostics.
	os.Stdout = originalStdout
	os.Stderr = originalStderr
	if !handled || code != 0 {
		t.Fatalf("Windows service result=handled:%v code:%d, want handled success", handled, code)
	}

	contents, err := os.ReadFile(serviceLogPath)
	if err != nil {
		t.Fatalf("read redirected gateway log: %v", err)
	}
	logText := string(contents)
	for _, expected := range []string{
		"[cisco-ai-defense] error:",
		"[gateway] error subsystem=cisco-inspect code=INVALID_RESPONSE",
		"stage=response_status",
		"http_status=403",
		"classification=permission_denied",
		`response_summary="<redacted`,
	} {
		if !strings.Contains(logText, expected) {
			t.Errorf("redirected gateway log missing %q: %q", expected, logText)
		}
	}
	for _, forbidden := range []string{privatePromptMarker, testAPIKey, responseMarker, "response_body="} {
		if strings.Contains(logText, forbidden) {
			t.Fatalf("redirected gateway log leaked private marker %q: %q", forbidden, logText)
		}
	}
	if len(contents) > 1024 {
		t.Fatalf("redirected diagnostic length=%d, want <= 1024", len(contents))
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
		"[switch]$AllowMissing",
		"-AllowMissingLeaf:(-not $exists)",
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

func TestWindowsEnterpriseModuleUsesBoundedProcessAndCanonicalJSONContracts(t *testing.T) {
	module := strings.ReplaceAll(string(readWindowsEnterpriseModule(t)), "\r\n", "\n")
	native := windowsPowerShellFunction(t, module, "Invoke-DefenseClawNative")
	gateway := windowsPowerShellFunction(t, module, "Invoke-DefenseClawGatewayCommand")
	process := windowsPowerShellFunction(t, module, "Invoke-DefenseClawProcess")
	installer := windowsPowerShellFunction(t, module, "Install-DefenseClawFileAtomic")
	writer := windowsPowerShellFunction(t, module, "Write-DefenseClawJsonAtomic")
	diagnostic := windowsPowerShellFunction(t, module, "ConvertTo-DefenseClawBoundedDiagnostic")
	guardianStatus := windowsPowerShellFunction(t, module, "Get-DefenseClawGuardianStatusReport")
	guardianWait := windowsPowerShellFunction(t, module, "Wait-DefenseClawFreshGuardianReconcile")
	services := windowsPowerShellFunction(t, module, "Set-DefenseClawManagedServices")
	requirements := windowsPowerShellFunction(t, module, "Invoke-DefenseClawCodexRequirementsCommand")
	teardown := windowsPowerShellFunction(t, module, "Invoke-DefenseClawManagedHooksTeardownCommand")
	lifecycleSnapshot := windowsPowerShellFunction(t, module, "Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand")
	teardownSchema := readWindowsManagedHooksSchemaConstant(
		t,
		"windows_managed_hooks_teardown.go",
		"windowsManagedHooksTeardownSchema",
	)
	lifecycleSchema := readWindowsManagedHooksSchemaConstant(
		t,
		"windows_managed_hooks_lifecycle.go",
		"windowsManagedHooksLifecycleSchema",
	)

	for label, body := range map[string]string{"native": native, "gateway": gateway} {
		if strings.Contains(body, "$LASTEXITCODE") ||
			!strings.Contains(body, "Invoke-DefenseClawProcess") {
			t.Fatalf("%s command still depends on ambient native exit state", label)
		}
	}
	for _, contract := range []string{
		"[Diagnostics.ProcessStartInfo]::new()",
		"$start.UseShellExecute = $false",
		"$start.RedirectStandardOutput = $true",
		"$start.RedirectStandardError = $true",
		"$process.WaitForExit($TimeoutSeconds * 1000)",
		"exit_code = [int]$process.ExitCode",
	} {
		if !strings.Contains(process, contract) {
			t.Fatalf("bounded process runner missing %q", contract)
		}
	}
	if !strings.Contains(writer, "[Text.UTF8Encoding]::new($false)") ||
		strings.Contains(writer, "Set-Content") {
		t.Fatal("atomic JSON writer is not pinned to BOM-less UTF-8")
	}
	if !strings.Contains(installer, "[IO.File]::Replace($temporary, $Destination, $backup, $true)") ||
		strings.Contains(installer, "[IO.File]::Replace($temporary, $Destination, $null, $true)") ||
		!strings.Contains(installer, "atomic replacement verification failed") ||
		!strings.Contains(installer, "-LiteralPath $backup `") ||
		strings.Contains(installer, "Move-Item -LiteralPath $temporary -Destination $Destination -Force") {
		t.Fatal("managed artifact replacement is not atomic and idempotent")
	}
	if !strings.Contains(guardianStatus, "without a valid JSON report") ||
		!strings.Contains(guardianWait, "last_status=$lastStatus") ||
		!strings.Contains(guardianWait, "PSObject.Properties['errors']") {
		t.Fatal("fresh guardian wait discards the bounded status failure diagnostic")
	}
	for _, contract := range []string{
		"[ValidateRange(64, 4096)][int]$MaxLength = 2048",
		"Bearer <redacted>",
		"$text.Substring(0, $MaxLength - 3) + '...'",
	} {
		if !strings.Contains(diagnostic, contract) {
			t.Fatalf("guardian failure diagnostic missing safety contract %q", contract)
		}
	}
	if strings.Count(services, "Assert-DefenseClawServiceImagePath") != 4 {
		t.Fatal("service creation does not immediately verify all four ImagePath values")
	}
	failureCheck := strings.Index(requirements, "if ([int]$probe.exit_code -ne 0")
	firstSuccessPath := strings.Index(requirements, "@('requirements_path'")
	if failureCheck < 0 || firstSuccessPath < 0 || failureCheck > firstSuccessPath {
		t.Fatal("Codex requirements failure is masked by success-layout validation")
	}
	teardownFailureCheck := strings.Index(teardown, "if ([int]$probe.exit_code -ne 0")
	teardownFirstSuccessPath := strings.Index(teardown, "@('manifest_path'")
	if teardownFailureCheck < 0 || teardownFirstSuccessPath < 0 ||
		teardownFailureCheck > teardownFirstSuccessPath ||
		!strings.Contains(teardown, "ConvertTo-DefenseClawBoundedDiagnostic -Value $detail") ||
		!strings.Contains(
			teardown,
			"if ([int]$report.schema_version -ne "+teardownSchema+")",
		) {
		t.Fatal("managed-hook teardown failure is masked by success-layout validation")
	}
	lifecycleFailureCheck := strings.Index(lifecycleSnapshot, "if ([int]$probe.exit_code -ne 0")
	lifecycleFirstSuccessPath := strings.Index(lifecycleSnapshot, "journal_path")
	if lifecycleFailureCheck < 0 || lifecycleFirstSuccessPath < 0 ||
		lifecycleFailureCheck > lifecycleFirstSuccessPath ||
		!strings.Contains(lifecycleSnapshot, "managed-hooks-lifecycle-snapshot") ||
		!strings.Contains(lifecycleSnapshot, "ConvertTo-DefenseClawBoundedDiagnostic -Value $detail") ||
		!strings.Contains(
			lifecycleSnapshot,
			"if ([int]$report.schema_version -ne "+lifecycleSchema+")",
		) {
		t.Fatal("managed-hook lifecycle snapshot masks failures or escapes its hidden command contract")
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
			"'Cisco',\n        'Cisco Secure Client',\n        'DefenseClaw-Cert',\n        $runID",
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
		"$Layout.AgentApplicationControlAttestationPath",
	} {
		if !strings.Contains(transaction, path) {
			t.Fatalf("lifecycle transaction omits %s", path)
		}
	}

	installLike := windowsPowerShellFunction(t, module, "Invoke-DefenseClawInstallLikeLifecycle")
	servicePreparation := windowsPowerShellFunction(t, module, "Set-DefenseClawManagedServicesForTransaction")
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
	serviceRegistration := strings.Index(servicePreparation, "Set-DefenseClawManagedServices `")
	coreACLs := strings.Index(servicePreparation, "Set-DefenseClawManagedCoreAcls `")
	if serviceRegistration < 0 || coreACLs < 0 || serviceRegistration > coreACLs ||
		!strings.Contains(servicePreparation, "-DeferAutomaticStart") {
		t.Fatal("transactional service preparation does not register disabled services before SID-dependent ACLs")
	}
	freshInstall := strings.Index(installLike, "# A clean install has no NT SERVICE identities")
	freshServices := -1
	if freshInstall >= 0 {
		freshServices = strings.Index(
			installLike[freshInstall:],
			"Set-DefenseClawManagedServicesForTransaction `",
		)
		if freshServices >= 0 {
			freshServices += freshInstall
		}
	}
	freshCapture := -1
	if freshServices >= 0 {
		freshCapture = strings.Index(
			installLike[freshServices:],
			"Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `",
		)
		if freshCapture >= 0 {
			freshCapture += freshServices
		}
	}
	if freshInstall < 0 || freshServices < 0 || freshCapture < 0 ||
		snapshot > freshServices || freshServices > freshCapture {
		t.Fatal("clean install can resolve the gateway virtual account before transaction-owned service registration")
	}
	upgradeCapture := strings.Index(
		installLike,
		"if ($Action -ne 'Install') {\n            [void](Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand `",
	)
	upgradeServices := strings.Index(
		installLike,
		"if ($Action -ne 'Install') {\n            # Upgrade/Repair deliberately capture",
	)
	if upgradeCapture < 0 || upgradeServices < 0 || upgradeCapture > upgradeServices {
		t.Fatal("upgrade/repair reconfigures services before capturing the previous hook identity")
	}

	uninstall := windowsPowerShellFunction(t, module, "Invoke-DefenseClawUninstallLifecycle")
	removePolicy := strings.Index(uninstall, "-Action remove")
	deleteGuardian := strings.Index(uninstall, "Remove-DefenseClawService -Name $GuardianServiceName")
	if removePolicy < 0 || deleteGuardian < 0 || removePolicy > deleteGuardian {
		t.Fatal("uninstall can delete managed binaries/services before proving Codex policy removal")
	}

	if !strings.Contains(installer, "[switch]$AttestAgentApplicationControl") ||
		strings.Contains(installer, "AttestCodexTrustedShellEnforcement") ||
		strings.Contains(installer, "AttestCodexApplicationControl") {
		t.Fatal("public installer does not expose the application-control attestation")
	}
}

func TestWindowsServicesNeverReceiveCodexHomeAndRequireApplicationControlPins(t *testing.T) {
	module := strings.ReplaceAll(string(readWindowsEnterpriseModule(t)), "\r\n", "\n")
	environment := windowsPowerShellFunction(t, module, "Get-DefenseClawServiceEnvironmentValues")
	if strings.Contains(environment, "CODEX_HOME") ||
		strings.Contains(environment, "DEFENSECLAW_WINDOWS_CODEX_TRUSTED_SHELL_ENFORCED") ||
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
	if strings.Contains(lifecycle, "Install requires -AttestAgentApplicationControl") ||
		strings.Contains(lifecycle, "requires -AttestAgentApplicationControl to migrate") {
		t.Fatal("optional application-control posture still blocks managed installation")
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

func TestWindowsCertificationHarnessFixesAreFailClosedAndBounded(t *testing.T) {
	harness := strings.ReplaceAll(string(readWindowsEnterpriseHarness(t)), "\r\n", "\n")
	if strings.Contains(strings.ToLower(harness), "$home =") {
		t.Fatal("certification harness assigns PowerShell's read-only HOME automatic variable")
	}

	initializer := windowsPowerShellFunction(t, harness, "Initialize-CertificationCodexHome")
	if strings.Contains(initializer, "$home =") ||
		!strings.Contains(initializer, "$certificationHome =") {
		t.Fatal("certification CODEX_HOME initializer collides with automatic HOME")
	}

	engineIDs := windowsPowerShellFunction(t, harness, "Get-ScheduledTaskEngineProcessIDs")
	removeTask := windowsPowerShellFunction(t, harness, "Remove-CertificationScheduledTask")
	if !strings.Contains(engineIDs, "Where-Object { $_ -gt 0 }") ||
		!strings.Contains(removeTask, "$taskAbsent = $true") ||
		!strings.Contains(removeTask, "[void]$script:ScheduledTasks.Remove($safeTaskName)") {
		t.Fatal("scheduled-task cleanup does not filter PID zero and retire proven-absent tracking")
	}

	tempSnapshot := windowsPowerShellFunction(t, harness, "Get-EnterprisePowerShellTempSnapshot")
	if !strings.Contains(tempSnapshot, "$script:KnownProgramData") ||
		strings.Contains(tempSnapshot, "$script:WindowsDirectory 'Temp'") {
		t.Fatal("enterprise temp monitor is not aligned with the ProgramData launcher root")
	}
	tempObservation := windowsPowerShellFunction(t, harness, "Update-EnterprisePowerShellTempObservation")
	for _, contract := range []string{
		"catch {",
		"$aclError = $_",
		"$pathExists = Test-Path",
		"-ErrorAction Stop",
		"throw $aclError",
	} {
		if !strings.Contains(tempObservation, contract) {
			t.Fatalf("enterprise temp ACL sampler missing disappearance-race contract %q", contract)
		}
	}
	attribution := windowsPowerShellFunction(t, harness, "Get-NormalModeEnterpriseAttributionSnapshot")
	for _, contract := range []string{
		"bin\\defenseclaw-gateway.exe",
		"bin\\defenseclaw-hook.exe",
		"bin\\defenseclaw.exe",
		"etc\\config.yaml",
		"install\\deployment.json",
		"last_write_utc_ticks = 0",
		"$immutableDigestPaths.Contains(",
		"sddl = [string]$row.sddl",
		"start_mode = [string]$service.start_mode",
		"start_name = [string]$service.start_name",
		"path_name = [string]$service.path_name",
	} {
		if !strings.Contains(attribution, contract) {
			t.Fatalf("normal-mode guardian attribution missing bounded contract %q", contract)
		}
	}
	if strings.Contains(attribution, "liveGuardianOutputs") ||
		strings.Contains(attribution, "state = [string]$service.state") {
		t.Fatal("normal-mode attribution still compares live guardian bytes or service runtime state")
	}

	ledgerSemantic := windowsPowerShellFunction(
		t,
		harness,
		"Get-GuardianAuthorizationSemanticSnapshot",
	)
	for _, contract := range []string{
		"Assert-PathBelow",
		"Read-CredentialedProcessOutputFile",
		"PSObject.Properties['updated_at']",
		"PSObject.Properties.Remove('updated_at')",
	} {
		if !strings.Contains(ledgerSemantic, contract) {
			t.Fatalf("guardian ledger semantic snapshot missing bounded contract %q", contract)
		}
	}
	stableLedger := windowsPowerShellFunction(
		t,
		harness,
		"Get-StableGuardianAuthorizationSemanticSnapshot",
	)
	for _, contract := range []string{
		"AddSeconds(10)",
		"Start-Sleep -Milliseconds 100",
		"Get-GuardianAuthorizationSemanticSnapshot",
		"ConvertTo-Json -Compress -Depth 8",
	} {
		if !strings.Contains(stableLedger, contract) {
			t.Fatalf("guardian ledger stabilization missing bounded contract %q", contract)
		}
	}
	if strings.Contains(harness, "$controlLedgerDigest") ||
		!strings.Contains(harness, "$controlLedgerSemantics") ||
		!strings.Contains(harness, "hostile unregister probe authorization semantics") {
		t.Fatal("denied-control attribution still relies on a raw live ledger digest")
	}

	sparseStart := windowsPowerShellFunction(t, harness, "Start-ActiveUserSparseArtifactAttack")
	for _, contract := range []string{
		"repair_observation_seconds = $RepairTimeoutSeconds",
		"if ($canonicalRecreated)",
		"$taskExecutionTimeoutSeconds = 120 + $RepairTimeoutSeconds",
		"RetainedEvidencePath = $retainedEvidence",
	} {
		if !strings.Contains(sparseStart, contract) {
			t.Fatalf("sparse recovery watcher missing synchronized evidence contract %q", contract)
		}
	}
	if strings.Contains(sparseStart, "$renamedToQuarantine -and $canonicalRecreated") {
		t.Fatal("sparse recovery still treats a lossy rename event as authoritative")
	}
	sparseStop := windowsPowerShellFunction(t, harness, "Stop-ActiveUserSparseArtifactAttack")
	for _, contract := range []string{
		"-TimeoutSeconds ($RepairTimeoutSeconds + 15)",
		"retained_evidence_path",
		"retained-sparse-recovery-evidence",
		"[int]$evidence.grow_operations -lt 2",
		"-not [bool]$evidence.final",
	} {
		if !strings.Contains(sparseStop, contract) {
			t.Fatalf("sparse final evidence validation missing contract %q", contract)
		}
	}
	if strings.Contains(sparseStop, "-not [bool]$evidence.renamed_to_quarantine") ||
		strings.Contains(sparseStop, "-not [bool]$evidence.canonical_recreated") {
		t.Fatal("sparse completion still fails on advisory watcher observations")
	}

	restore := windowsPowerShellFunction(t, harness, "Restore-ProtectedUserTreeSnapshot")
	if !strings.Contains(restore, "$($Snapshot.name)-absent-cleanup-root-acl") ||
		!strings.Contains(restore, "$descendantCleanupGrants") ||
		!strings.Contains(restore, "Assert-CleanupTreeDirectFullControl") ||
		!strings.Contains(restore, "Get-CertificationTreeEntriesNoFollow") ||
		!strings.Contains(restore, "Remove-Item `\n                -LiteralPath $safe `") {
		t.Fatal("absent user-tree baseline cannot remove the exact harness-created fixture")
	}

	liveAutoHeal := windowsPowerShellFunction(t, harness, "Test-NormalModeLiveAutoHeal")
	if strings.Contains(liveAutoHeal, ".services.name") ||
		!strings.Contains(liveAutoHeal, "Get-NormalModeServiceNames") {
		t.Fatal("normal-mode baseline diagnostics are not safe for an empty service inventory")
	}
	fingerprint := windowsPowerShellFunction(t, harness, "Get-CodexManagedHookFingerprint")
	for _, contract := range []string{
		"Microsoft\\.PowerShell\\.Management\\\\Start-Process",
		"$actualHook",
		"$expectedCanonicalHook",
		"[StringComparison]::OrdinalIgnoreCase",
	} {
		if !strings.Contains(fingerprint, contract) {
			t.Fatalf("Codex managed hook fingerprint missing %q", contract)
		}
	}

	protect := windowsPowerShellFunction(t, harness, "Protect-TreeFromRegisteredSecretLeak")
	copyEvidence := windowsPowerShellFunction(t, harness, "Copy-WorkEvidence")
	if !strings.Contains(protect, "$maximumTextFileBytes = 8MB") ||
		!strings.Contains(protect, "$maximumTotalTextBytes = 64MB") ||
		!strings.Contains(protect, "Test-CertificationEvidenceTextFile") ||
		!strings.Contains(copyEvidence, "Get-CertificationTreeEntriesNoFollow") ||
		!strings.Contains(copyEvidence, "staged-binary-digests.json") ||
		strings.Contains(copyEvidence, "Copy-Item -LiteralPath $entry.FullName -Destination $logRoot -Recurse") {
		t.Fatal("certification evidence collection is not bounded to text plus named binary digests")
	}
}

func TestWindowsCertificationTempObservationHandlesOnlyProvenDisappearance(t *testing.T) {
	harness := strings.ReplaceAll(string(readWindowsEnterpriseHarness(t)), "\r\n", "\n")
	observationFunction := windowsPowerShellFunction(
		t,
		harness,
		"Update-EnterprisePowerShellTempObservation",
	)
	root := t.TempDir()
	scriptPath := filepath.Join(t.TempDir(), "temp-observation-race.ps1")
	script := `
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
` + observationFunction + `
$root = [Environment]::GetEnvironmentVariable('DEFENSECLAW_TEMP_RACE_ROOT')
$baseline = [pscustomobject]@{ root = $root; entries = @() }
$observation = [pscustomobject]@{
    observed = $false
    path = ''
    sample_count = 0
}
$vanished = [IO.Path]::Combine(
    $root,
    'DefenseClaw-PowerShell-00000000000000000000000000000000'
)
[void][IO.Directory]::CreateDirectory($vanished)
function Get-Acl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LiteralPath)
    [IO.Directory]::Delete($LiteralPath)
    throw [InvalidOperationException]::new($LiteralPath)
}
Update-EnterprisePowerShellTempObservation $baseline $observation
if ($observation.observed) {
    throw 'vanished capability was recorded as an ACL sample'
}

$present = [IO.Path]::Combine(
    $root,
    'DefenseClaw-PowerShell-11111111111111111111111111111111'
)
[void][IO.Directory]::CreateDirectory($present)
function Get-Acl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LiteralPath)
    throw [InvalidOperationException]::new($LiteralPath)
}
$rejected = $false
try {
    Update-EnterprisePowerShellTempObservation $baseline $observation
}
catch {
    if ($_.Exception.Message -ne $present) {
        throw
    }
    $rejected = $true
}
if (-not $rejected) {
    throw 'existing capability ACL failure was incorrectly suppressed'
}
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		"powershell.exe",
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-File", scriptPath,
	)
	command.Env = append(os.Environ(), "DEFENSECLAW_TEMP_RACE_ROOT="+root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("forced PowerShell temp disappearance race failed: %v\n%s", err, output)
	}
	if ctx.Err() != nil {
		t.Fatalf("forced PowerShell temp disappearance race timed out: %v", ctx.Err())
	}
}

func TestWindowsCertificationNormalModeAttributionScopesImmutableInputs(t *testing.T) {
	harness := strings.ReplaceAll(string(readWindowsEnterpriseHarness(t)), "\r\n", "\n")
	attributionFunction := windowsPowerShellFunction(
		t,
		harness,
		"Get-NormalModeEnterpriseAttributionSnapshot",
	)
	root := t.TempDir()
	scriptPath := filepath.Join(t.TempDir(), "normal-mode-attribution.ps1")
	script := `
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function ConvertTo-CanonicalPath([string]$Path) {
    return [IO.Path]::GetFullPath($Path).TrimEnd('\')
}
` + attributionFunction + `
$root = [Environment]::GetEnvironmentVariable('DEFENSECLAW_ATTRIBUTION_ROOT')
$script:InstallRoot = [IO.Path]::Combine($root, 'install')
$script:StateRoot = [IO.Path]::Combine($root, 'state')
$script:ClaudeManagedPolicyPath = [IO.Path]::Combine($root, 'claude', 'policy.json')
$script:ClaudeManagedStatePath = [IO.Path]::Combine($root, 'claude', 'state.json')
$live = @(
    [IO.Path]::Combine($script:StateRoot, 'hook-guardian', 'targets.yaml'),
    [IO.Path]::Combine($script:StateRoot, 'hook-guardian-state', 'protected_targets.json'),
    $script:ClaudeManagedPolicyPath,
    $script:ClaudeManagedStatePath
)
$immutable = [IO.Path]::Combine($script:StateRoot, 'etc', 'config.yaml')
$rows = @(
    foreach ($path in @($live + $immutable)) {
        [pscustomobject]@{
            path = $path
            existed = $true
            kind = 'file'
            attributes = 32
            last_write_utc_ticks = 987654321
            sddl = 'O:BAG:BAD:P'
        }
    }
)
$digests = @(
    foreach ($path in @($live + $immutable)) {
        [pscustomobject]@{ path = $path; sha256 = ('hash-' + $path) }
    }
)
$snapshot = [pscustomobject]@{
    paths = $rows
    file_digests = $digests
    services = @([pscustomobject]@{
        name = 'guardian'
        state = 'Running'
        start_mode = 'Auto'
        start_name = 'LocalSystem'
        path_name = 'guardian.exe'
    })
}
$normalized = Get-NormalModeEnterpriseAttributionSnapshot $snapshot
if (@($normalized.paths).Count -ne 5) {
    throw 'attribution removed protected path identity rows'
}
foreach ($path in $live) {
    $row = @($normalized.paths | Where-Object {
        [string]::Equals([string]$_.path, $path, [StringComparison]::OrdinalIgnoreCase)
    })
    if ($row.Count -ne 1 -or
        [long]$row[0].last_write_utc_ticks -ne 0 -or
        [string]$row[0].sddl -cne 'O:BAG:BAD:P' -or
        -not [bool]$row[0].existed) {
        throw "live guardian path identity/ACL normalization is wrong: $path"
    }
    if (@($normalized.file_digests | Where-Object {
        [string]::Equals([string]$_.path, $path, [StringComparison]::OrdinalIgnoreCase)
    }).Count -ne 0) {
        throw "live guardian digest was retained: $path"
    }
}
$immutableRow = @($normalized.paths | Where-Object {
    [string]::Equals([string]$_.path, $immutable, [StringComparison]::OrdinalIgnoreCase)
})
if ($immutableRow.Count -ne 1 -or
    [long]$immutableRow[0].last_write_utc_ticks -ne 0 -or
    @($normalized.file_digests).Count -ne 1 -or
    -not [string]::Equals(
        [string]$normalized.file_digests[0].path,
        $immutable,
        [StringComparison]::OrdinalIgnoreCase
    ) -or
    @($normalized.services).Count -ne 1 -or
    $null -ne $normalized.services[0].PSObject.Properties['state'] -or
    [string]$normalized.services[0].start_name -cne 'LocalSystem') {
    throw 'attribution weakened an immutable path, digest, ACL, or service configuration check'
}
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		"powershell.exe",
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-File", scriptPath,
	)
	command.Env = append(os.Environ(), "DEFENSECLAW_ATTRIBUTION_ROOT="+root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("normal-mode guardian attribution contract failed: %v\n%s", err, output)
	}
	if ctx.Err() != nil {
		t.Fatalf("normal-mode guardian attribution contract timed out: %v", ctx.Err())
	}
}

func TestWindowsCertificationGuardianLedgerAttributionIgnoresOnlyTimestamp(t *testing.T) {
	harness := strings.ReplaceAll(string(readWindowsEnterpriseHarness(t)), "\r\n", "\n")
	semanticFunction := windowsPowerShellFunction(
		t,
		harness,
		"Get-GuardianAuthorizationSemanticSnapshot",
	)
	root := t.TempDir()
	scriptPath := filepath.Join(t.TempDir(), "guardian-ledger-attribution.ps1")
	script := `
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Assert-PathBelow([string]$Path, [string]$Root, [string]$Label) {
    $full = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    if (-not $full.StartsWith($parent, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label escaped its root"
    }
    return $full
}
function Read-CredentialedProcessOutputFile {
    param([string]$Path, [string]$Label)
    return [IO.File]::ReadAllText($Path)
}
function ConvertFrom-SingleJSONDocument([string]$Text, [string]$Label) {
    return $Text | ConvertFrom-Json -ErrorAction Stop
}
` + semanticFunction + `
$root = [Environment]::GetEnvironmentVariable('DEFENSECLAW_LEDGER_ROOT')
$script:StateRoot = [IO.Path]::Combine($root, 'state')
[IO.Directory]::CreateDirectory($script:StateRoot) | Out-Null
$path = [IO.Path]::Combine($script:StateRoot, 'protected_targets.json')
function Write-Ledger([string]$UpdatedAt, [bool]$TargetOK, [int]$Generation) {
    $document = [ordered]@{
        version = 1
        updated_at = $UpdatedAt
        ok = $TargetOK
        target_count = 1
        success_count = if ($TargetOK) { 1 } else { 0 }
        failure_count = if ($TargetOK) { 0 } else { 1 }
        generation = $Generation
        protected_targets = @([ordered]@{
            sid = 'S-1-5-21-1-2-3-1001'
            connector = 'claudecode'
            ok = $TargetOK
        })
    }
    [IO.File]::WriteAllText(
        $path,
        ($document | ConvertTo-Json -Depth 8),
        [Text.UTF8Encoding]::new($false)
    )
}
Write-Ledger '2026-08-16T10:00:00Z' $true 7
$before = Get-GuardianAuthorizationSemanticSnapshot $path
Write-Ledger '2026-08-16T10:05:00Z' $true 7
$timestampOnly = Get-GuardianAuthorizationSemanticSnapshot $path
$beforeJSON = $before | ConvertTo-Json -Compress -Depth 8
$timestampOnlyJSON = $timestampOnly | ConvertTo-Json -Compress -Depth 8
if (-not [string]::Equals($beforeJSON, $timestampOnlyJSON, [StringComparison]::Ordinal)) {
    throw 'publication timestamp changed authorization semantics'
}
if ($null -ne $timestampOnly.PSObject.Properties['updated_at'] -or
    [int]$timestampOnly.generation -ne 7) {
    throw 'semantic snapshot removed more than the publication timestamp'
}
Write-Ledger '2026-08-16T10:10:00Z' $false 8
$changed = Get-GuardianAuthorizationSemanticSnapshot $path
$changedJSON = $changed | ConvertTo-Json -Compress -Depth 8
if ([string]::Equals($beforeJSON, $changedJSON, [StringComparison]::Ordinal)) {
    throw 'authorization or future generation changes were ignored'
}
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		"powershell.exe",
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-File", scriptPath,
	)
	command.Env = append(os.Environ(), "DEFENSECLAW_LEDGER_ROOT="+root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("guardian ledger attribution contract failed: %v\n%s", err, output)
	}
	if ctx.Err() != nil {
		t.Fatalf("guardian ledger attribution contract timed out: %v", ctx.Err())
	}
}

func TestWindowsCertificationSparseCompletionRetainsAdvisoryWatcherEvidence(t *testing.T) {
	harness := strings.ReplaceAll(string(readWindowsEnterpriseHarness(t)), "\r\n", "\n")
	stopFunction := windowsPowerShellFunction(
		t,
		harness,
		"Stop-ActiveUserSparseArtifactAttack",
	)
	root := t.TempDir()
	scriptPath := filepath.Join(t.TempDir(), "sparse-completion-evidence.ps1")
	script := `
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Assert-PathBelow([string]$Path, [string]$Root, [string]$Label) {
    $full = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    if (-not $full.StartsWith($parent, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label escaped its root"
    }
    return $full
}
function Wait-Until {
    param([scriptblock]$Condition, [string]$Description, [int]$TimeoutSeconds, [int]$PollMilliseconds)
    return & $Condition
}
function Remove-CertificationScheduledTask([string]$Name) {}
function Get-FileDigest([string]$Path) { return 'payload-digest' }
function Protect-AdministratorFile([string]$Path, [string]$Label) {}
function Protect-SensitiveDisplayText([string]$Value) { return $Value }
function Get-GuardianResourceObservation { throw 'resource observation was not expected' }
function Assert-SameLiveGuardianProcess { throw 'guardian comparison was not expected' }
` + stopFunction + `
$root = [Environment]::GetEnvironmentVariable('DEFENSECLAW_SPARSE_EVIDENCE_ROOT')
$script:WorkRoot = [IO.Path]::Combine($root, 'work')
[IO.Directory]::CreateDirectory($script:WorkRoot) | Out-Null
$script:EvidenceDirectory = [IO.Path]::Combine($root, 'evidence')
[IO.Directory]::CreateDirectory($script:EvidenceDirectory) | Out-Null
$script:ActiveUserHandoffRoot = [IO.Path]::Combine($script:WorkRoot, 'handoff')
[IO.Directory]::CreateDirectory($script:ActiveUserHandoffRoot) | Out-Null
$RepairTimeoutSeconds = 1
$script:PrimarySID = 'S-1-5-21-1-2-3-1001'
$script:SparseAttackLogicalBytes = [int64]1099511627776
$script:SparseAttackMaxAllocatedBytes = [int64]1048576
$release = [IO.Path]::Combine($script:ActiveUserHandoffRoot, 'release.txt')
$evidencePath = [IO.Path]::Combine($script:ActiveUserHandoffRoot, 'evidence.json')
$payload = [IO.Path]::Combine($script:WorkRoot, 'payload.ps1')
$retained = [IO.Path]::Combine(
    $script:EvidenceDirectory,
    'logs',
    'sparse-recovery-evidence',
    'sparse-managed_token-final.json'
)
[IO.File]::WriteAllText($payload, 'fixture')
$document = [ordered]@{
    ok = $true
    final = $true
    sid = $script:PrimarySID
    path = 'C:\managed.token'
    sparse = $true
    logical_bytes = $script:SparseAttackLogicalBytes
    allocated_bytes = 4096
    grow_operations = 2
    renamed_to_quarantine = $false
    canonical_recreated = $false
    failure = ''
}
[IO.File]::WriteAllText(
    $evidencePath,
    ($document | ConvertTo-Json -Compress),
    [Text.UTF8Encoding]::new($false)
)
$attack = [pscustomobject]@{
    ReleasePath = $release
    EvidencePath = $evidencePath
    RetainedEvidencePath = $retained
    TaskName = 'fixture-task'
    PayloadPath = $payload
    PayloadSHA256 = 'payload-digest'
    Path = 'C:\managed.token'
}
$result = Stop-ActiveUserSparseArtifactAttack $attack $null
if ([bool]$result.renamed_to_quarantine -or
    [bool]$result.canonical_recreated -or
    -not (Test-Path -LiteralPath $retained -PathType Leaf)) {
    throw 'advisory watcher evidence was not retained without becoming authoritative'
}
$retainedJSON = Get-Content -LiteralPath $retained -Raw | ConvertFrom-Json -ErrorAction Stop
if ([bool]$retainedJSON.renamed_to_quarantine -or
    [bool]$retainedJSON.canonical_recreated -or
    -not [bool]$retainedJSON.final -or
    [int]$retainedJSON.grow_operations -ne 2) {
    throw 'retained sparse evidence omitted a final proof flag/value'
}
$document.grow_operations = 1
[IO.File]::WriteAllText(
    $evidencePath,
    ($document | ConvertTo-Json -Compress),
    [Text.UTF8Encoding]::new($false)
)
$rejected = $false
try {
    $null = Stop-ActiveUserSparseArtifactAttack $attack $null
}
catch {
    if ($_.Exception.Message -notmatch 'bounded grow') { throw }
    $rejected = $true
}
if (-not $rejected) {
    throw 'sparse completion accepted fewer than two bounded grow operations'
}
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		"powershell.exe",
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-File", scriptPath,
	)
	command.Env = append(os.Environ(), "DEFENSECLAW_SPARSE_EVIDENCE_ROOT="+root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("sparse completion evidence contract failed: %v\n%s", err, output)
	}
	if ctx.Err() != nil {
		t.Fatalf("sparse completion evidence contract timed out: %v", ctx.Err())
	}
}

func TestWindowsCertificationArtifactRepairDigestIsSizeBounded(t *testing.T) {
	harness := strings.ReplaceAll(
		string(readWindowsEnterpriseHarness(t)),
		"\r\n",
		"\n",
	)
	matcher := windowsPowerShellFunction(
		t,
		harness,
		"Test-BoundedArtifactSnapshotMatch",
	)
	root := t.TempDir()
	scriptPath := filepath.Join(t.TempDir(), "bounded-artifact-digest.ps1")
	script := `
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ManagedArtifactDigestMaxBytes = [int64]4194304
function Get-FileDigest { throw 'unbounded digest helper must not run' }
` + matcher + `
$root = [Environment]::GetEnvironmentVariable('DEFENSECLAW_BOUNDED_DIGEST_ROOT')
$path = [IO.Path]::Combine($root, 'managed.token')
[IO.File]::WriteAllText(
    $path,
    ("canonical" + [Environment]::NewLine),
    [Text.UTF8Encoding]::new($false)
)
$item = Get-Item -LiteralPath $path -Force
$digestStream = [IO.File]::OpenRead($path)
$digestAlgorithm = [Security.Cryptography.SHA256]::Create()
try {
    $digest = (
        [BitConverter]::ToString(
            $digestAlgorithm.ComputeHash($digestStream)
        ).Replace('-', '').ToLowerInvariant()
    )
}
finally {
    $digestAlgorithm.Dispose()
    $digestStream.Dispose()
}
$snapshot = [pscustomobject]@{
    path = $path
    length = [int64]$item.Length
    sha256 = $digest
}
if (-not (Test-BoundedArtifactSnapshotMatch $snapshot)) {
    throw 'bounded matcher rejected the canonical baseline'
}
$stream = [IO.File]::Open(
    $path,
    [IO.FileMode]::Open,
    [IO.FileAccess]::Write,
    [IO.FileShare]::ReadWrite
)
try {
    $stream.SetLength([int64]8388608)
} finally {
    $stream.Dispose()
}
$timer = [Diagnostics.Stopwatch]::StartNew()
$matched = Test-BoundedArtifactSnapshotMatch $snapshot
$timer.Stop()
if ($matched) {
    throw 'bounded matcher accepted an oversized managed artifact'
}
if ($timer.Elapsed.TotalSeconds -gt 2) {
    throw "oversized managed artifact check took $($timer.Elapsed.TotalSeconds) seconds"
}
Remove-Item -LiteralPath $path -Force
if (Test-Path -LiteralPath $path) {
    throw 'bounded digest fixture cleanup failed'
}
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		"powershell.exe",
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-File", scriptPath,
	)
	command.Env = append(
		os.Environ(),
		"DEFENSECLAW_BOUNDED_DIGEST_ROOT="+root,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("bounded artifact digest contract failed: %v\n%s", err, output)
	}
	if ctx.Err() != nil {
		t.Fatalf("bounded artifact digest contract timed out: %v", ctx.Err())
	}
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

func readWindowsManagedHooksSchemaConstant(
	t *testing.T,
	filename string,
	constant string,
) string {
	t.Helper()
	path := filepath.Join("..", "..", "internal", "cli", filename)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	pattern := regexp.MustCompile(
		`(?m)^\s*` + regexp.QuoteMeta(constant) + `\s*=\s*([0-9]+)\s*$`,
	)
	match := pattern.FindSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("could not resolve %s from %s", constant, path)
	}
	return string(match[1])
}

func readWindowsEnterpriseHarness(t *testing.T) []byte {
	t.Helper()
	harnessPath := filepath.Join("..", "..", "scripts", "test-windows-enterprise-hardening.ps1")
	harness, err := os.ReadFile(harnessPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", harnessPath, err)
	}
	return harness
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
