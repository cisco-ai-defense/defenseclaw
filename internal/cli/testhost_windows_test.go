// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// isolateTestHost keeps the package's tests off the computer's own managed
// deployment, and makes them give the same answers whoever runs them. On a
// computer that is itself managed, the per-user gateway guard read the real
// HKLM marker and refused every start, stop and restart test that did not
// stub it; and a test that reached the scanner lifecycle without its own
// runtime folder worked on the installed scanner runtime. Tests that need a
// managed computer or a runtime folder set their own.
//
// GAP-0079: the machine writers and the process identity are package
// defaults too, not something each test must remember. A bundle test that did
// not stub the marker sync wrote its fixture bundle to the real HKLM marker
// of a managed computer, and a test that did not pin the identity gave
// another answer as LocalSystem or as a standard user.
func isolateTestHost() func() {
	sandboxSeam("managedHostWindowsStandalone", &managedHostWindowsStandalone, func() (string, bool) { return "", false })
	// GAP-2572: on a managed lane host the HKLM marker key exists, so the
	// "marker present but unverified" check read it and closed every
	// per-user outage case; Secure Client and the runtime descriptor are the
	// other two machine signals the outage mode reads.
	sandboxSeam("managedHostWindowsMarkerUncertain", &managedHostWindowsMarkerUncertain, func() bool { return false })
	sandboxSeam("secureClientHost", &secureClientHost, func() bool { return false })
	pinTestProcessIdentity()
	normalizeTestTokenDefaultOwner()
	restoreTemp := isolateTestRunTemp()
	dir, err := os.MkdirTemp("", "defenseclaw-cli-test-")
	if err != nil {
		sandboxSeam("windowsScannerRuntimeDir", &windowsScannerRuntimeDir, func() (string, error) { return "", err })
		sandboxSeam("managedHostDescriptorPath", &managedHostDescriptorPath, func() string { return "" })
		isolateTestDeploymentReaders(os.TempDir())
		isolateTestRunFolders("")
		isolateTestGatewayPortClaims(filepath.Join(os.TempDir(), "defenseclaw-cli-test-no-port-claims"))
		restoreMachine := isolateTestMachineWriters("")
		return func() {
			restoreMachine()
			removeWindowsWow64Holder()
			restoreTemp()
		}
	}
	testRunTempDirs = append(testRunTempDirs, dir)
	isolateTestDeploymentReaders(dir)
	isolateTestRunFolders(dir)
	isolateTestGatewayPortClaims(filepath.Join(dir, "port-claims"))
	missingDescriptor := filepath.Join(dir, "no-runtime-descriptor")
	sandboxSeam("managedHostDescriptorPath", &managedHostDescriptorPath, func() string { return missingDescriptor })
	// Absent like on a computer without a deployment.
	runtimeDir := filepath.Join(dir, "scanners")
	sandboxSeam("windowsScannerRuntimeDir", &windowsScannerRuntimeDir, func() (string, error) { return runtimeDir, nil })
	restoreMachine := isolateTestMachineWriters(filepath.Join(dir, "lifecycle-logs"))
	return func() {
		restoreMachine()
		removeWindowsWow64Holder()
		_ = os.RemoveAll(dir)
		restoreTemp()
	}
}

// testRunTempDirs are this run's own temp folders: the folder TMP and TEMP
// name for the run (isolateTestRunTemp) and the sandbox folder isolateTestHost
// points the deployment seams at. Both are new and unique to the run, so a
// service log line that names one was written for a test (testRunMarkers).
var testRunTempDirs []string

// isolateTestRunTemp points TMP and TEMP at a new folder of this run, so
// every t.TempDir() of a run as an administrator or a standard user is in a
// folder unique to the run, and restores both after the run (GAP-0093
// review L1). The temp folder itself is not unique to the run: as
// LocalSystem it is C:\Windows\SystemTemp, which the SYSTEM services use too,
// so a guardian line that named it was taken for a test's write. Windows
// gives LocalSystem C:\Windows\SystemTemp whatever TMP says (GetTempPath2),
// so there the run's markers are its own folders only.
func isolateTestRunTemp() func() {
	root, err := os.MkdirTemp("", "defenseclaw-cli-run-")
	if err != nil {
		return func() {}
	}
	testRunTempDirs = append(testRunTempDirs, root)
	previous := map[string]*string{}
	for _, name := range []string{"TMP", "TEMP"} {
		if value, ok := os.LookupEnv(name); ok {
			previous[name] = &value
		} else {
			previous[name] = nil
		}
		_ = os.Setenv(name, root)
	}
	return func() {
		for name, value := range previous {
			if value == nil {
				_ = os.Unsetenv(name)
			} else {
				_ = os.Setenv(name, *value)
			}
		}
		_ = os.RemoveAll(root)
	}
}

// isolateTestGatewayPortClaims points the per-user gateway's API port claims
// at dir in the run's temp folder (PR #1427 stress, GAP-0079 follow-up). A
// start or restart test that reached claimGatewayAPIPort left a
// defenseclaw-api-port-<port> claim in the computer's own %ProgramData%,
// which init on every other account then skipped. When dir cannot be made,
// the claim fails rather than reach %ProgramData%. The built gateway the
// executable tests start gets the same folder through its ProgramData
// variable (executableTestEnv).
func isolateTestGatewayPortClaims(dir string) {
	_ = os.MkdirAll(dir, 0o700)
	gatewayPortClaimDir, testGatewayPortClaimDir = dir, dir
}

// testGatewayPortClaimDir is the port claim folder isolateTestHost set.
var testGatewayPortClaimDir string

// testProcessIdentityNote says which identity the package's tests run as.
const testProcessIdentityNote = "an elevated administrator that is not LocalSystem (the CI runner's identity)"

// normalizeTestTokenDefaultOwner makes the test binary's own account the
// owner of everything it creates, as the CI harness does for its elevated
// runner (scripts/windows-native-ci.ps1 Set-CurrentUserAsDefaultOwner). An
// elevated administrator's token defaults to BUILTIN\Administrators as the
// owner, so outside that harness every t.TempDir() looked foreign to the
// product's ownership checks ("safefile: refusing foreign-owned directory")
// and the watchdog, daemon and audit tests failed when an administrator ran
// the package from an elevated prompt (GAP-0079). A standard user's and
// LocalSystem's tokens already default to their own account.
func normalizeTestTokenDefaultOwner() {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT, &token); err != nil {
		return
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return
	}
	owner := struct{ Owner *windows.SID }{Owner: user.User.Sid}
	_ = windows.SetTokenInformation(token, windows.TokenOwner, (*byte)(unsafe.Pointer(&owner)), uint32(unsafe.Sizeof(owner)))
}

// pinTestProcessIdentity makes every identity seam answer as the CI runner
// does, an elevated administrator that is not LocalSystem, whatever token
// runs the tests: a standard user, LocalSystem or an elevated administrator.
// A test that needs another identity sets its own and restores it.
func pinTestProcessIdentity() {
	sandboxSeam("windowsEnterpriseIsElevated", &windowsEnterpriseIsElevated, func() bool { return true })
	sandboxSeam("windowsSecretIsElevated", &windowsSecretIsElevated, func() bool { return true })
	sandboxSeam("windowsCoworkElevated", &windowsCoworkElevated, func() bool { return true })
	sandboxSeam("windowsEnterpriseRunningAsLocalSystem", &windowsEnterpriseRunningAsLocalSystem, func() bool { return false })
	sandboxSeam("windowsClaudeSettingsCheckerIsLocalSystem", &windowsClaudeSettingsCheckerIsLocalSystem, func() bool { return false })
	sandboxSeam("enterpriseHookWindowsUserCleanupIdentity", &enterpriseHookWindowsUserCleanupIdentity, func() error { return enterprisehooks.ErrWindowsEnterpriseNotLocalSystem })
	// The enterprise hooks commands ask the token through this seam too
	// (g079 review F3): it answers as the elevated runner.
	sandboxSeam("enterpriseHooksPlatformPreflight", &enterpriseHooksPlatformPreflight, func() error { return nil })
	// The lifecycle stages in the caller's own temp folder, which every
	// identity can build, never in the computer's ProgramData. A test of the
	// ProgramData staging sets useTestTokenForStaging.
	sandboxSeam("windowsEnterpriseStagingElevated", &windowsEnterpriseStagingElevated, func() bool { return false })
}

// useTestTokenForStaging makes the lifecycle staging follow the test
// binary's own token, for a test of the elevated ProgramData staging itself.
func useTestTokenForStaging(t *testing.T) {
	t.Helper()
	saved := windowsEnterpriseStagingElevated
	t.Cleanup(func() { windowsEnterpriseStagingElevated = saved })
	windowsEnterpriseStagingElevated = testTokenIsElevated
}

// useTokenUserTempDirectory makes the unelevated staging resolve the token's
// own LocalAppData Temp folder again, for a test of that resolution itself
// (g079 review 2 R2c). The unelevated PowerShell temp only resolves the
// folder; it writes nothing there.
func useTokenUserTempDirectory(t *testing.T) {
	t.Helper()
	saved := windowsEnterpriseUserTempDirectory
	t.Cleanup(func() { windowsEnterpriseUserTempDirectory = saved })
	windowsEnterpriseUserTempDirectory = trustedWindowsEnterpriseUserTempDirectory
}

// isolateTestMachineWriters points every machine writer of the standalone
// lifecycle at a sandbox: the registry root at a throwaway HKCU key, the
// lifecycle log at logDir in the temp folder, the event log at a writer that
// takes each event and keeps none, and the bundle marker sync, service
// start-mode restore, runtime folder repair, production bin cleanup and
// Program Files\Cisco removal at no-ops. The returned function removes the
// sandbox key.
func isolateTestMachineWriters(logDir string) func() {
	sandboxSeam("windowsBundleSyncMarker", &windowsBundleSyncMarker, func(*enterprisebundle.Store) error { return nil })
	sandboxSeam("windowsEnterpriseEventWriter", &windowsEnterpriseEventWriter, func(string, uint32, string, string) error { return nil })
	sandboxSeam("windowsEnterpriseLogDirectory", &windowsEnterpriseLogDirectory, func() (string, error) {
		if logDir == "" {
			return "", errors.New("the tests have no temp folder for the lifecycle log")
		}
		return logDir, nil
	})
	sandboxSeam("windowsEnterpriseLogDirectoryEnsurer", &windowsEnterpriseLogDirectoryEnsurer, func(directory string) error { return os.MkdirAll(directory, 0o700) })
	sandboxSeam("removeEmptyWindowsEnterpriseInstallParent", &removeEmptyWindowsEnterpriseInstallParent, func() {})
	sandboxSeam("windowsEnterpriseRestoreStartModes", &windowsEnterpriseRestoreStartModes, func(*windowsEnterpriseInstallerReport) error { return nil })
	sandboxSeam("windowsEnterpriseRepairDataDirBeforePlan", &windowsEnterpriseRepairDataDirBeforePlan, func() string { return "" })
	sandboxSeam("windowsEnterpriseRemoveReplacementCopies", &windowsEnterpriseRemoveReplacementCopies, func() []string { return nil })
	// The guardian's self-heal (repairEnterpriseHookManagedInstallPlatform,
	// reached from the hook watch's reconcile under a managed cfg) heals the
	// install tree, the policy artifacts and the services' SCM descriptors
	// and registry keys. Idempotent on a healthy computer, so the registry
	// guard would not show it (GAP-0093, review 2 S2).
	sandboxSeam("enterpriseWindowsManagedInstallRepair", &enterpriseWindowsManagedInstallRepair, func(managed.ManagedInstallLayout, managed.CanonicalOptions) []managed.CanonicalResult { return nil })
	sandboxSeam("enterpriseWindowsManagedPolicyArtifactsRepair", &enterpriseWindowsManagedPolicyArtifactsRepair, func() {})
	sandboxSeam("enterpriseWindowsManagedServiceSecurityRepair", &enterpriseWindowsManagedServiceSecurityRepair, func([]string) []managed.ServiceSecurityResult { return nil })
	// The priority class is process state: a lifecycle test that lowered it
	// left every later test, and cmd.exe and the other programs they start,
	// below normal. TestWindowsLifecycleRunYieldsTheCPUToTheHooks checks the
	// real yield in a child process.
	sandboxSeam("windowsEnterpriseLifecycleYield", &windowsEnterpriseLifecycleYield, func() {})
	// The same for the sidecar, which raises its class to above normal
	// (TestSidecarAnswersAtTheHookPriorityClass checks it in a child).
	sandboxSeam("sidecarRaisePriority", &sidecarRaisePriority, func() {})
	// g079 review F1: service control of the DefenseClaw gateway and hook
	// guardian fails in tests.
	sandboxSeam("windowsEnterpriseHotConfigRestart", &windowsEnterpriseHotConfigRestart, func() (bool, error) { return false, errTestSandboxNoServiceControl })
	sandboxSeam("windowsEnterpriseHotConfigRecover", &windowsEnterpriseHotConfigRecover, func() (bool, error) { return false, errTestSandboxNoServiceControl })
	sandboxSeam("windowsEnterpriseHotConfigFailClosed", &windowsEnterpriseHotConfigFailClosed, func() error { return errTestSandboxNoServiceControl })
	sandboxSeam("windowsEnterpriseHotConfigGuardianReconcile", &windowsEnterpriseHotConfigGuardianReconcile, testSandboxGuardianReconcile)
	sandboxSeam("windowsSecretRestartGateway", &windowsSecretRestartGateway, func(func() error) (bool, error) { return false, errTestSandboxNoServiceControl })
	sandboxSeam("windowsSecretSpawnRecovery", &windowsSecretSpawnRecovery, func() (windowsSecretRecoveryControl, error) { return nil, errTestSandboxNoServiceControl })

	// One sandbox per run: the test binary's helper children (daemon probes,
	// re-executed helpers) use their parent's, which the parent removes. A
	// child that a test kills never runs its own cleanup, so a sandbox of
	// its own stayed behind in the account's HKCU.
	path, owned := os.Getenv(testMachineRegistrySandboxEnv), false
	if !strings.HasPrefix(path, testMachineRegistrySandboxPrefix) {
		path, owned = fmt.Sprintf("%s%d", testMachineRegistrySandboxPrefix, os.Getpid()), true
		_ = os.Setenv(testMachineRegistrySandboxEnv, path)
	}
	testMachineRegistrySandbox = path
	key, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	if err != nil {
		// No sandbox: an invalid root makes every machine write fail rather
		// than reach HKLM (TestPackageTestsDoNotReachTheInstalledDeployment
		// reports it).
		key = 0
	}
	windowsEnterpriseMachineRegistry, testMachineRegistrySandboxKey = key, key
	return func() {
		windowsEnterpriseMachineRegistry = 0
		if key != 0 {
			_ = key.Close()
		}
		if owned {
			_ = deleteTestRegistryTree(registry.CURRENT_USER, path)
		}
	}
}

const (
	testMachineRegistrySandboxEnv    = "DEFENSECLAW_CLI_TEST_REGISTRY_SANDBOX"
	testMachineRegistrySandboxPrefix = `Software\DefenseClaw-test-`
)

// testMachineRegistrySandbox is this run's HKCU sandbox key, and
// testMachineRegistrySandboxKey its open handle.
var (
	testMachineRegistrySandbox    string
	testMachineRegistrySandboxKey registry.Key
)

// testSandboxSeam is one package seam isolateTestHost points at the
// sandbox: its name, a reader of its value now, and the function it set.
type testSandboxSeam struct {
	name    string
	current func() uintptr
	want    uintptr
}

// testSandboxSeams is every seam isolateTestHost set.
var testSandboxSeams []testSandboxSeam

// sandboxSeam sets *seam to value and registers it, so the TestMain guard
// tells when a test left it reassigned (g079 review F2). It compares code
// pointers, so it cannot tell two values of the same function literal apart:
// a test that runs a sandbox setter such as isolateTestDeploymentReaders
// again with another folder, and does not set it back, goes unnoticed. That
// value is still a temp sandbox (g079 review 2 R2e).
func sandboxSeam[T any](name string, seam *T, value T) {
	*seam = value
	testSandboxSeams = append(testSandboxSeams, testSandboxSeam{name: name,
		current: func() uintptr { return reflect.ValueOf(*seam).Pointer() },
		want:    reflect.ValueOf(value).Pointer()})
}

// testSandboxProblems lists where the package is no longer in its sandbox:
// a registered seam that is not the function isolateTestHost set, a
// registry root that is not the HKCU sandbox key, an identity seam that no
// longer answers as pinned, a lifecycle log outside the temp folder, or a
// deployment record that reads as present.
func testSandboxProblems() []string {
	var problems []string
	for _, seam := range testSandboxSeams {
		if seam.current() != seam.want {
			problems = append(problems, "seam "+seam.name+" is not the sandbox's (a test reassigned it and did not set it back)")
		}
	}
	if testMachineRegistrySandboxKey == 0 || windowsEnterpriseMachineRegistry != testMachineRegistrySandboxKey {
		problems = append(problems, fmt.Sprintf("the machine registry root is %#x, not the HKCU sandbox %s", windowsEnterpriseMachineRegistry, testMachineRegistrySandbox))
	}
	if !windowsEnterpriseIsElevated() || !windowsSecretIsElevated() || !windowsCoworkElevated() ||
		windowsEnterpriseRunningAsLocalSystem() || windowsClaudeSettingsCheckerIsLocalSystem() ||
		!errors.Is(enterpriseHookWindowsUserCleanupIdentity(), enterprisehooks.ErrWindowsEnterpriseNotLocalSystem) ||
		enterpriseHooksPlatformPreflight() != nil || windowsEnterpriseStagingElevated() {
		problems = append(problems, "the identity seams do not answer as "+testProcessIdentityNote)
	}
	if testGatewayPortClaimDir == "" || gatewayPortClaimDir != testGatewayPortClaimDir {
		problems = append(problems, fmt.Sprintf("the gateway port claims folder is %q, not the sandbox's %q", gatewayPortClaimDir, testGatewayPortClaimDir))
	} else if rel, err := filepath.Rel(os.TempDir(), gatewayPortClaimDir); err != nil || strings.HasPrefix(rel, "..") {
		problems = append(problems, "the gateway port claims folder "+gatewayPortClaimDir+" is outside the temp folder")
	}
	if logDir, err := windowsEnterpriseLogDirectory(); err != nil {
		problems = append(problems, "the lifecycle log: "+err.Error())
	} else if rel, err := filepath.Rel(os.TempDir(), logDir); err != nil || strings.HasPrefix(rel, "..") {
		problems = append(problems, "the lifecycle log "+logDir+" is outside the temp folder")
	}
	for _, profile := range []string{managed.ProfileStandalone, managed.ProfileSecureClient} {
		if deployment, err := windowsEnterpriseDeploymentInspector(profile); err != nil || deployment.State != winpath.EnterpriseDeploymentAbsent {
			problems = append(problems, fmt.Sprintf("the %s deployment record reads as %q (%v), not absent", profile, deployment.State, err))
		}
	}
	return problems
}

// guardTestSandbox fails the run when a test left the package outside its
// sandbox for every test after it (g079 review F2).
func guardTestSandbox() func() error {
	return func() error {
		problems := testSandboxProblems()
		if len(problems) == 0 {
			return nil
		}
		return fmt.Errorf("GAP-0079: a test left the package outside its machine sandbox for the tests after it "+
			"(set each seam back in t.Cleanup):\n  %s", strings.Join(problems, "\n  "))
	}
}

// deleteTestRegistryTree removes path and everything under it.
func deleteTestRegistryTree(root registry.Key, path string) error {
	if key, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS); err == nil {
		names, _ := key.ReadSubKeyNames(-1)
		_ = key.Close()
		for _, name := range names {
			_ = deleteTestRegistryTree(root, path+`\`+name)
		}
	}
	if err := registry.DeleteKey(root, path); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

// testGuardedMachineKeys are the computer's own HKLM keys DefenseClaw
// writes: the standalone marker and its parents, the self-update policy, the
// Add/Remove Programs entry, the event log registration and the machine
// policies of the agents. The DefenseClaw services' keys are added at
// snapshot time.
var testGuardedMachineKeys = []string{
	`SOFTWARE\Cisco\DefenseClaw`,
	`SOFTWARE\Policies\Cisco\DefenseClaw`,
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CiscoDefenseClawEnterprise`,
	windowsEnterpriseEventLogParent + `\DefenseClaw`,
	windowsEnterpriseEventLogParent + `\Application\` + windowsEnterpriseEventSrc,
	`SOFTWARE\Policies\ClaudeCode`,
	`SOFTWARE\Policies\Claude`,
	`SOFTWARE\Policies\WSL`,
}

// snapshotTestMachineRegistry reads every value under the guarded HKLM keys
// and the DefenseClaw* service keys, as "key\name" = "type:hex".
func snapshotTestMachineRegistry() map[string]string {
	snapshot := map[string]string{}
	keys := append([]string(nil), testGuardedMachineKeys...)
	if services, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS); err == nil {
		names, _ := services.ReadSubKeyNames(-1)
		_ = services.Close()
		for _, name := range names {
			if strings.HasPrefix(strings.ToLower(name), "defenseclaw") {
				keys = append(keys, `SYSTEM\CurrentControlSet\Services\`+name)
			}
		}
	}
	for _, path := range keys {
		snapshotTestRegistryKey(snapshot, path)
	}
	// The empty-parent removal (removeEmptyWindowsRegistryKey) can take
	// HKLM\SOFTWARE\Cisco itself; other Cisco products own its values.
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Cisco`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		_ = key.Close()
		snapshot[`SOFTWARE\Cisco`] = "key (presence only)"
	}
	return snapshot
}

// snapshotTestMachineState adds what a test could change outside the
// registry to snapshot (g079 review F2): the run state and process of each
// DefenseClaw service, and a fingerprint (kind, size, modification time) of
// every DefenseClaw* folder under %ProgramData%\Cisco and
// %ProgramData%\Cisco\Cisco Secure Client, the DefenseClaw-* staging and dc-*-test-*
// fixture folders at the top of %ProgramData% and of the system drive,
// %WINDIR%\Logs\DefenseClaw*, %ProgramFiles%\Cisco\DefenseClaw*, and the
// token's own %LOCALAPPDATA%\DefenseClaw and lifecycle staging in its
// %LOCALAPPDATA%\Temp. While a
// DefenseClaw service runs, its data folder (its databases) and the
// lifecycle log folder are its own and are left out, and the folders it
// rewrites on its own schedule (testServiceOwnedFolders) are compared by
// meaning instead, under every identity (GAP-0093,
// testmachine_service_writes_test.go). before is the first snapshot, nil
// when this is it.
func snapshotTestMachineState(snapshot, before map[string]string) {
	running := snapshotTestServices(snapshot)
	var skip []string
	service := testServiceFolders{before: before, runMarkers: testRunMarkers()}
	if running {
		if layout, err := managed.StandaloneWindowsLayout(); err == nil {
			service.roots = testServiceOwnedFolders(layout)
			skip = append(append(skip, layout.DataDir), service.roots...)
		}
	}
	defer fingerprintTestServiceFolders(snapshot, service)
	stagingOrFixture := func(name string) bool {
		lower := strings.ToLower(name)
		return strings.HasPrefix(lower, "defenseclaw-") || strings.HasPrefix(lower, "dc-") && strings.Contains(lower, "-test-")
	}
	defenseClaw := func(name string) bool { return strings.HasPrefix(strings.ToLower(name), "defenseclaw") }
	if programData, err := winpath.TrustedProgramData(); err != nil {
		snapshot["file %ProgramData%"] = "unresolved: " + err.Error()
	} else {
		// Both profiles' DefenseClaw* folders: the state root, and its
		// siblings DefenseClaw-Lifecycle (lifecycle.lock, the spool and
		// bundle-store lock state, the lifecycle logs) and DefenseClaw-Cert
		// (g079 review 2 R2a).
		fingerprintTestEntries(snapshot, filepath.Join(programData, "Cisco"), defenseClaw, skip)
		fingerprintTestEntries(snapshot, filepath.Join(programData, "Cisco", "Cisco Secure Client"), defenseClaw, skip)
		fingerprintTestEntries(snapshot, programData, stagingOrFixture, skip)
	}
	if drive := os.Getenv("SystemDrive"); drive != "" {
		fingerprintTestEntries(snapshot, drive+`\`, func(name string) bool {
			lower := strings.ToLower(name)
			return strings.HasPrefix(lower, "dc-") && strings.Contains(lower, "-test-")
		}, skip)
	}
	if windir, err := windows.GetSystemWindowsDirectory(); err != nil {
		snapshot["file %WINDIR%"] = "unresolved: " + err.Error()
	} else if running {
		snapshot["file "+filepath.Join(windir, "Logs", "DefenseClaw")] = "left out: a DefenseClaw service runs"
	} else {
		fingerprintTestEntries(snapshot, filepath.Join(windir, "Logs"), defenseClaw, skip)
	}
	if programFiles, err := winpath.TrustedProgramFiles(); err != nil {
		snapshot["file %ProgramFiles%"] = "unresolved: " + err.Error()
	} else {
		cisco := filepath.Join(programFiles, "Cisco")
		if _, err := os.Lstat(cisco); err == nil {
			snapshot["file "+cisco] = "present"
		}
		fingerprintTestEntries(snapshot, cisco, defenseClaw, skip)
	}
	// g079 review 2 R2c: the token's own per-user DefenseClaw folder (the
	// Claude settings teardown keeps its transactions there) and the
	// lifecycle staging in its own temp folder. The sandbox stages in the
	// run's temp folder, so neither changes.
	if localAppData, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData); err != nil {
		snapshot["file %LOCALAPPDATA%"] = "unresolved: " + err.Error()
	} else {
		fingerprintTestTree(snapshot, filepath.Join(localAppData, "DefenseClaw"), skip)
		fingerprintTestEntries(snapshot, filepath.Join(localAppData, "Temp"), func(name string) bool {
			lower := strings.ToLower(name)
			return strings.HasPrefix(lower, strings.ToLower(managed.SetupInstallerStagePrefix)) ||
				strings.HasPrefix(lower, strings.ToLower(managed.SetupPowerShellTempPrefix))
		}, skip)
	}
}

// testServiceOwnedFolders are the folders of the standalone layout the
// running DefenseClaw services rewrite on their own schedule: the hook
// guardian's state (its activation receipt and protected targets), the
// guardian manifest folder (the unprotected-agent record), the
// machine-policy records and the services' logs. An idle managed computer
// changes every one of them within minutes, with no test running (GAP-0093).
func testServiceOwnedFolders(layout managed.StandaloneLayout) []string {
	return []string{
		layout.GuardianAuthDir,
		filepath.Dir(layout.ManifestPath),
		filepath.Join(layout.LifecycleDir, "machine-policy"),
		layout.LogDir,
	}
}

// testRunTempIsTheRuns reports whether the temp folder is the run's own
// (TMP was honoured: not LocalSystem).
func testRunTempIsTheRuns() bool {
	for _, dir := range testRunTempDirs {
		if strings.EqualFold(filepath.Clean(dir), filepath.Clean(os.TempDir())) {
			return true
		}
	}
	return false
}

// testRunMarkers name this test run in text it writes: its own temp
// folders (testRunTempDirs, not the shared temp folder: GAP-0093 review
// L1), its HKCU registry sandbox and its executable. A service log line
// written during the run that names one of them was written by a test.
func testRunMarkers() []string {
	executable, _ := os.Executable()
	return testRunMarkersIn(testRunTempDirs, testMachineRegistrySandbox, filepath.Base(executable), os.TempDir())
}

// testRunMarkersIn is testRunMarkers for a run's temp folders, registry
// sandbox, executable name and the process temp folder. When that temp
// folder is not one of the run's (LocalSystem: GetTempPath2 gives it
// C:\Windows\SystemTemp whatever TMP says), a t.TempDir() is
// <temp folder>\TestXxxNNN\001, which neither run folder names, so
// <temp folder>\Test is a marker too (GAP-0093, review 2 L2). The services'
// text does not contain it.
func testRunMarkersIn(runTempDirs []string, registrySandbox, executableName, osTemp string) []string {
	markers := append(append([]string{}, runTempDirs...), registrySandbox)
	if executableName != "" && executableName != "." {
		markers = append(markers, executableName)
	}
	own := false
	for _, dir := range runTempDirs {
		own = own || strings.EqualFold(filepath.Clean(dir), filepath.Clean(osTemp))
	}
	if !own && osTemp != "" {
		markers = append(markers, strings.TrimRight(osTemp, `\/`)+`\Test`)
	}
	return markers
}

// snapshotTestServices records each DefenseClaw service's state and process
// id, and reports whether any of them runs. A standard user can query them.
func snapshotTestServices(snapshot map[string]string) bool {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		snapshot["service manager"] = "unreadable: " + err.Error()
		return false
	}
	defer func() { _ = windows.CloseServiceHandle(manager) }()
	running := false
	for _, service := range winpath.EnterpriseStandaloneServices {
		name, err := windows.UTF16PtrFromString(service.Name)
		if err != nil {
			continue
		}
		handle, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			continue
		}
		if err != nil {
			snapshot["service "+service.Name] = "unreadable: " + err.Error()
			continue
		}
		var status windows.SERVICE_STATUS_PROCESS
		var needed uint32
		err = windows.QueryServiceStatusEx(handle, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed)
		_ = windows.CloseServiceHandle(handle)
		if err != nil {
			snapshot["service "+service.Name] = "unreadable: " + err.Error()
			continue
		}
		snapshot["service "+service.Name] = fmt.Sprintf("state %d pid %d", status.CurrentState, status.ProcessId)
		if status.CurrentState != windows.SERVICE_STOPPED {
			running = true
		}
	}
	return running
}

// fingerprintTestTree records root and everything under it as
// "file <path>" = "<kind> <size> <modified>", without following links;
// an unreadable folder is recorded as such. A path in skip is left out.
func fingerprintTestTree(snapshot map[string]string, root string, skip []string) {
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		for _, left := range skip {
			if left != "" && strings.EqualFold(filepath.Clean(path), filepath.Clean(left)) {
				snapshot["file "+path] = "left out: a DefenseClaw service runs"
				return filepath.SkipDir
			}
		}
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				snapshot["file "+path] = "unreadable: " + err.Error()
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			snapshot["file "+path] = "unreadable: " + err.Error()
			return nil
		}
		kind := "file"
		switch {
		case entry.IsDir():
			kind = "folder"
		case entry.Type()&fs.ModeSymlink != 0:
			kind = "link"
		case !entry.Type().IsRegular():
			kind = "other"
		}
		snapshot["file "+path] = fmt.Sprintf("%s %d %s", kind, info.Size(), info.ModTime().UTC().Format(time.RFC3339Nano))
		return nil
	})
}

// fingerprintTestEntries fingerprints each entry of parent whose name
// matches.
func fingerprintTestEntries(snapshot map[string]string, parent string, match func(string) bool, skip []string) {
	entries, err := os.ReadDir(parent)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			snapshot["file "+parent] = "unreadable: " + err.Error()
		}
		return
	}
	for _, entry := range entries {
		if match(entry.Name()) {
			fingerprintTestTree(snapshot, filepath.Join(parent, entry.Name()), skip)
		}
	}
}

func snapshotTestRegistryKey(snapshot map[string]string, path string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return
	}
	if err != nil {
		snapshot[path] = "unreadable: " + err.Error()
		return
	}
	defer key.Close()
	snapshot[path] = "key"
	names, _ := key.ReadValueNames(-1)
	for _, name := range names {
		size, kind, err := key.GetValue(name, nil)
		if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
			snapshot[path+`\`+name] = "unreadable: " + err.Error()
			continue
		}
		buffer := make([]byte, size)
		if _, _, err := key.GetValue(name, buffer); err != nil {
			snapshot[path+`\`+name] = "unreadable: " + err.Error()
			continue
		}
		snapshot[path+`\`+name] = fmt.Sprintf("%d:%s", kind, hex.EncodeToString(buffer))
	}
	subkeys, _ := key.ReadSubKeyNames(-1)
	for _, name := range subkeys {
		snapshotTestRegistryKey(snapshot, path+`\`+name)
	}
}

// testMachineSettleAttempts and testMachineSettleDelay bound how long the
// machine guard waits for a running service's writes to settle.
const (
	testMachineSettleAttempts = 3
	testMachineSettleDelay    = 2 * time.Second
)

// guardTestMachine snapshots the computer's DefenseClaw machine registry
// and, in the top-level run, its DefenseClaw services and machine folders
// before the package runs. The returned check fails the run when any test
// changed them (GAP-0079, g079 review F2). A helper child (started by a
// test, so testProcessGuardChildEnv is set) checks the registry only: it is
// short, and the parent's check after it sees what it left behind. TestMain
// calls this before guardTestProcessState sets that variable.
func guardTestMachine() func() error {
	child := os.Getenv(testProcessGuardChildEnv) != ""
	snapshot := func(before map[string]string) map[string]string {
		state := snapshotTestMachineRegistry()
		if !child {
			snapshotTestMachineState(state, before)
		}
		return state
	}
	before := snapshot(nil)
	return func() error {
		changes := diffTestMachineRegistry(before, snapshot(before))
		// GAP-0093: a running service can be between the write and the
		// rename of one of its records at the moment of the snapshot. Read
		// again once its writes have settled; a test's write stays.
		for attempt := 0; len(changes) != 0 && attempt < testMachineSettleAttempts; attempt++ {
			time.Sleep(testMachineSettleDelay)
			changes = diffTestMachineRegistry(before, snapshot(before))
		}
		if len(changes) == 0 {
			return nil
		}
		return fmt.Errorf("GAP-0079: the internal/cli tests changed the computer's own DefenseClaw machine registry, services or folders "+
			"(every machine writer must reach the test sandbox HKCU\\%s or a temp folder):\n  %s",
			testMachineRegistrySandbox, strings.Join(changes, "\n  "))
	}
}

// testProcessPriority is the CPU priority class of the test binary.
func testProcessPriority() string {
	class, err := windows.GetPriorityClass(windows.CurrentProcess())
	if err != nil {
		return "unreadable: " + err.Error()
	}
	return fmt.Sprintf("%#x", class)
}

// testProcessStartPriority is the class the test binary was started at,
// read at package initialization, before TestMain and any test runs. The
// harness decides it: a developer's shell starts normal (0x20), a CI runner
// can start below normal (0x4000). A test compares the current class with
// this one, never with a fixed class.
var testProcessStartPriority = testProcessPriority()

// testProcessClassOf is the CPU priority class of another process.
func testProcessClassOf(pid int) (uint32, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(handle)
	return windows.GetPriorityClass(handle)
}

// isolateTestDeploymentReaders makes the computer's own standalone
// deployment read as absent, as on a build box, for the whole package: its
// deployment records, its installed config (and its enterprise.trust) and
// manifest, the guardian's last pass, restores and per-user cleanup ledger,
// the enrolled connectors and targets, the unprotected-agent record, its
// agent config notices, the Amp machine folder and the discovery homes. On
// a managed lane host these added the real accounts' warnings
// (agent_settings_not_restored, guardian_repair_pending,
// hook_process_fail_open) to results a test builds from a stubbed installer
// report (GAP-2572), a secret test recorded its refused change events in the
// real change spool (GAP-0079), and a standard user could not read them at
// all. The readers that load a file read a missing one under dir, so they
// fail as they do on a computer without a deployment. A test that needs one
// of them sets its own.
func isolateTestDeploymentReaders(dir string) {
	sandboxSeam("windowsEnterpriseRecordInspector", &windowsEnterpriseRecordInspector, func(profile string) (winpath.EnterpriseDeployment, error) {
		return winpath.EnterpriseDeployment{Profile: profile, State: winpath.EnterpriseDeploymentAbsent}, nil
	})
	missing, err := managed.StandaloneWindowsLayoutForRoots(filepath.Join(dir, "no-program-files"), filepath.Join(dir, "no-program-data"))
	if err != nil {
		missing = managed.StandaloneLayout{ConfigPath: filepath.Join(dir, "no-config.yaml"),
			ManifestPath: filepath.Join(dir, "no-manifest.json"), DataDir: filepath.Join(dir, "no-data")}
	}
	// cowork-1-0-8 GAP-0093 (round 2): the one place internal/cli resolves
	// the computer's own standalone layout and trusted roots. Every non-test
	// file asks windowsManagedLayout, so this one sandbox covers the readers
	// no seam had (the lifecycle, guardian and status internals) and every
	// one a later change adds. The Secure Client profile's roots are left as
	// they are.
	missingRoots, missingRootsErr := winpath.EnterpriseRootsFor(managed.ProfileStandalone,
		filepath.Join(dir, "no-program-files"), filepath.Join(dir, "no-program-data"))
	sandboxSeam("windowsManagedLayout.standalone", &windowsManagedLayout.standalone, func() (managed.StandaloneLayout, error) { return missing, nil })
	sandboxSeam("windowsManagedLayout.roots", &windowsManagedLayout.roots, func(profile string) (winpath.EnterpriseRoots, error) {
		if profile != managed.ProfileStandalone {
			return winpath.TrustedEnterpriseRoots(profile)
		}
		return missingRoots, missingRootsErr
	})
	// cowork-1-0-8 GAP-0093 (round 3, review 2 S2): the guardian's self-heal
	// derives its install and state layout from these registrations.
	sandboxSeam("windowsManagedLayout.programRoots", &windowsManagedLayout.programRoots, func() (string, string) {
		return filepath.Join(dir, "no-program-files"), filepath.Join(dir, "no-program-data")
	})
	sandboxSeam("windowsEnterpriseInstalledConfigPath", &windowsEnterpriseInstalledConfigPath, func() (string, error) { return missing.ConfigPath, nil })
	sandboxSeam("windowsEnterpriseInstalledConfigForStatus", &windowsEnterpriseInstalledConfigForStatus, func() (*config.Config, error) {
		return loadWindowsEnterpriseStandaloneConfig(missing.ConfigPath)
	})
	sandboxSeam("windowsEnterpriseEnrolledConnectors", &windowsEnterpriseEnrolledConnectors, func() ([]string, error) { return windowsEnterpriseConfigConnectors(missing.ConfigPath) })
	sandboxSeam("windowsEnterpriseEnrolledTargets", &windowsEnterpriseEnrolledTargets, func() (map[string]bool, error) {
		if _, err := enterprisehooks.LoadManifest(missing.ManifestPath); err != nil {
			return nil, err
		}
		return map[string]bool{}, nil
	})
	sandboxSeam("windowsEnterpriseGuardianRestores", &windowsEnterpriseGuardianRestores, func() (map[string]time.Time, error) {
		return readEnterpriseHookGuardianRestores(missing.DataDir)
	})
	sandboxSeam("windowsEnterpriseUnprotectedAgentsReader", &windowsEnterpriseUnprotectedAgentsReader, func() ([]enterprisehooks.UnprotectedAgent, error) {
		return enterprisehooks.ReadWindowsUnprotectedAgents(missing.ManifestPath)
	})
	registry := connector.NewDefaultRegistry()
	sandboxSeam("windowsEnterpriseStatusV2Read", &windowsEnterpriseStatusV2Read, func() windowsEnterpriseStatusV2Inputs {
		return windowsEnterpriseStatusV2Inputs{
			configErr:     os.ErrNotExist,
			manifestErr:   os.ErrNotExist,
			machinePolicy: func(string) bool { return false },
			gatewayHealth: func() ([]byte, error) { return nil, os.ErrNotExist },
			knownConnector: func(name string) bool {
				_, ok := registry.Get(name)
				return ok
			},
		}
	})
	sandboxSeam("windowsEnterpriseGuardianStateForStatus", &windowsEnterpriseGuardianStateForStatus, func() (enterpriseHookGuardianState, bool, error) {
		return enterpriseHookGuardianState{}, false, nil
	})
	sandboxSeam("windowsEnterpriseUserCleanupsForStatus", &windowsEnterpriseUserCleanupsForStatus, func() ([]enterpriseHookUserCleanup, error) { return nil, nil })
	// The off-roster markers live in the computer's own hook runtime folder,
	// and the removed-connectors record in its guardian state folder.
	sandboxSeam("enterpriseHookWindowsOffRosterPublisher", &enterpriseHookWindowsOffRosterPublisher, func(string, bool) error { return nil })
	sandboxSeam("windowsConnectorOffRosterRead", &windowsConnectorOffRosterRead, func(string) (bool, error) { return false, nil })
	sandboxSeam("windowsEnterpriseRemovedConnectorsForStatus", &windowsEnterpriseRemovedConnectorsForStatus, func() ([]managed.RemovedConnector, error) { return nil, nil })
	sandboxSeam("windowsEnterpriseAgentSettingsNotices", &windowsEnterpriseAgentSettingsNotices, func() []string { return nil })
	sandboxSeam("windowsEnterpriseNativeOTLPNotices", &windowsEnterpriseNativeOTLPNotices, func() []string { return nil })
	sandboxSeam("windowsEnterpriseAmpMachineFolderProblems", &windowsEnterpriseAmpMachineFolderProblems, func() []string { return nil })
	sandboxSeam("windowsManagedHooksKeptUntrustedPolicyFiles", &windowsManagedHooksKeptUntrustedPolicyFiles, func() []string { return nil })
	sandboxSeam("windowsEnterpriseVendorFolderProblems", &windowsEnterpriseVendorFolderProblems, func() []enterprisepolicy.VendorFolderProblem { return nil })
	sandboxSeam("enterpriseHookWindowsUnrecordedFiles", &enterpriseHookWindowsUnrecordedFiles,
		func(enterprisepolicy.Options, []string) []enterprisepolicy.VendorFolderProblem { return nil })
	sandboxSeam("windowsEnterpriseVendorFolderHeal", &windowsEnterpriseVendorFolderHeal,
		func() ([]enterprisepolicy.ReprotectedFolder, []enterprisepolicy.VendorFolderProblem) { return nil, nil })
	sandboxSeam("windowsEnterpriseDiscoveryHomeDirs", &windowsEnterpriseDiscoveryHomeDirs, func() ([]string, error) { return nil, nil })
	// g079 review F1: the bundle store, the protected credentials and the
	// change spool of the computer's own layout, the uninstall footprint
	// (SCM services and machine roots), the Claude Code machine policy and
	// the gateway service's process. On a managed computer a secret test
	// that missed its spool stub wrote the real change spool as SYSTEM.
	sandboxSeam("windowsBundleLayout", &windowsBundleLayout, func() (managed.StandaloneLayout, error) { return missing, nil })
	sandboxSeam("windowsSecretLayout", &windowsSecretLayout, func() (managed.StandaloneLayout, error) { return missing, nil })
	// GAP-0093: the other seams that resolve the computer's own standalone
	// layout. The administrator pins (policy, audit export, enterprise
	// policy and acp) set DEFENSECLAW_CONFIG and DEFENSECLAW_HOME from
	// auditExportManagedLayout, and the command then loaded that config into
	// the package cfg and its runtime .env into the process environment. On
	// a managed computer that was the real deployment: every later test ran
	// with the real standalone config (TestSignedOutOwnerRewrittenAccount-
	// UpgradeNeedsReadableOlderLock read it), and the run ended with the
	// deployment's DEFENSECLAW_GATEWAY_TOKEN in its environment. The scan,
	// hot config and config validate layouts are the same kind of reader.
	sandboxSeam("auditExportManagedLayout", &auditExportManagedLayout, func() (managed.StandaloneLayout, error) { return missing, nil })
	sandboxSeam("managedScanWindowsLayout", &managedScanWindowsLayout, func() (managed.StandaloneLayout, error) { return missing, nil })
	sandboxSeam("windowsEnterpriseHotConfigLayout", &windowsEnterpriseHotConfigLayout, func() (managed.StandaloneLayout, error) { return missing, nil })
	sandboxSeam("configValidateLayout", &configValidateLayout, func() (managed.StandaloneLayout, error) { return missing, nil })
	spool := filepath.Join(dir, "change-spool")
	sandboxSeam("windowsChangeSpool", &windowsChangeSpool, func(managed.StandaloneLayout) (enterprisestatus.ChangeSpool, error) {
		return enterprisestatus.ChangeSpool{Dir: filepath.Join(spool, enterprisestatus.ChangeEventsDirName), StateDir: spool}, nil
	})
	sandboxSeam("windowsEnterpriseStandaloneFootprint", &windowsEnterpriseStandaloneFootprint, func() (bool, error) { return false, nil })
	sandboxSeam("windowsEnterpriseClaudeRegistryPolicyValue", &windowsEnterpriseClaudeRegistryPolicyValue, func() (string, error) { return "", nil })
	sandboxSeam("windowsBundleRestoreGatewayRunning", &windowsBundleRestoreGatewayRunning, func() bool { return false })
	sandboxSeam("windowsStandaloneGatewayPID", &windowsStandaloneGatewayPID, func() uint32 { return 0 })
	sandboxSeam("windowsSecretGatewayLive", &windowsSecretGatewayLive, func() (bool, error) { return false, nil })
	// g079 review 2 R1: the credential refusal audit reads a deployment no
	// test installed as cleanly absent. testSandboxSecretDeploymentAbsent
	// follows windowsSecretDeploymentInstalled, so a test that stubs that
	// one gets the same answer here; a test of another record state sets
	// windowsSecretDeploymentAbsent itself.
	sandboxSeam("windowsSecretDeploymentAbsent", &windowsSecretDeploymentAbsent, testSandboxSecretDeploymentAbsent)
}

// testSandboxSecretDeploymentAbsent is the sandbox's credential audit read:
// a deployment that is not installed is a clean absence, and a failed read
// is a failed read.
func testSandboxSecretDeploymentAbsent() (bool, error) {
	installed, err := windowsSecretDeploymentInstalled()
	return err == nil && !installed, err
}

// isolateTestRunFolders points the lifecycle lock and the caller's own temp
// folder at the run's temp folder dir (g079 review 2 R2b, R2c); with no dir,
// both fail.
//
// The lifecycle lock (DefenseClaw-Lifecycle\lifecycle.lock) is what the hot
// config, the bundle restore, the generation repair and the credential
// changes open with no sharing. A test that missed its stub held the
// computer's own lock, and kept the guardian and Setup out, for as long as
// it ran: interference without a write, which no fingerprint sees. In the
// sandbox it is a missing file in dir, so taking it fails as on a computer
// without a deployment.
//
// The caller's own temp folder is where an unelevated lifecycle (the
// identity the tests pin, pinTestProcessIdentity) stages its scripts
// (DefenseClaw-Installer-*) and its PowerShell temp. It was the token's own
// %LOCALAPPDATA%\Temp (for LocalSystem the system profile's), where a
// helper a test killed left its staging, out of the fingerprint's sight. In
// the sandbox it is a folder in dir that only the test account, LocalSystem
// and Administrators can change, as the real one.
func isolateTestRunFolders(dir string) {
	noDir := errors.New("the tests have no temp folder for the lifecycle lock and the staging")
	lock, userTemp, userTempErr := "", "", noDir
	if dir != "" {
		lock = filepath.Join(dir, "no-lifecycle", "lifecycle.lock")
		userTemp = filepath.Join(dir, "user-temp")
		if userTempErr = os.Mkdir(userTemp, 0o700); userTempErr == nil {
			grantTestTreeToCurrentUser(userTemp)
		}
	}
	sandboxSeam("windowsEnterpriseUserTempDirectory", &windowsEnterpriseUserTempDirectory, func() (string, error) {
		if userTempErr != nil {
			return "", userTempErr
		}
		return userTemp, nil
	})
	takeLock := func(string) (func(), error) {
		if lock == "" {
			return nil, noDir
		}
		return acquireWindowsEnterpriseLifecycleLock(lock)
	}
	sandboxSeam("windowsEnterpriseHotConfigLock", &windowsEnterpriseHotConfigLock, takeLock)
	sandboxSeam("windowsSecretLifecycleLock", &windowsSecretLifecycleLock, takeLock)
	sandboxSeam("windowsSecretLifecycleLockPath", &windowsSecretLifecycleLockPath, func() (string, error) {
		if lock == "" {
			return "", noDir
		}
		return lock, nil
	})
	// cowork-1-0-8 GAP-0094: the hook guardian's claim of config.yaml opened
	// the computer's own lifecycle.lock. An elevated run held it, and a
	// standard user, who cannot open it, never recorded a generation.
	sandboxSeam("windowsEnterpriseConfigLifecycleClaim", &windowsEnterpriseConfigLifecycleClaim, func() managedConfigOwnership {
		if lock == "" {
			return managedConfigOwnership{reason: noDir.Error()}
		}
		return claimWindowsEnterpriseConfigFromLifecycle(lock, func() (managed.StandaloneLayout, error) { return windowsEnterpriseHotConfigLayout() })
	})
}

// errTestSandboxNoServiceControl is what the gateway and guardian service
// control answers in the package's tests: a test that reaches a real stop,
// start or restart without its own stub fails, loudly, rather than acting on
// the computer's services (g079 review F1).
func testSandboxGuardianReconcile(context.Context, managed.StandaloneLayout, bool) error {
	return errTestSandboxNoServiceControl
}

// sameTestFunc reports whether two func values are the same function.
func sameTestFunc(a, b any) bool { return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer() }

// second is the error of a two-result call.
func second[T any](_ T, err error) error { return err }

var errTestSandboxNoServiceControl = errors.New("test sandbox: no service control (the test must stub the gateway or guardian service seam it reaches)")

// testTokenIsElevated reports whether the test binary's own token is
// elevated. A fixture that needs a privilege (an Administrators owner) asks
// the real token; windowsEnterpriseIsElevated answers for the product and is
// pinned (pinTestProcessIdentity).
func testTokenIsElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// requireAdministratorTestToken skips a test whose fixture, or whose product
// writer, only an administrator token can build (a BUILTIN\Administrators
// owner, or a protected admin-only object), saying why. A standard user
// cannot create them, so the test cannot give the same answer as a standard
// user (GAP-0079); the elevated CI runner, an elevated administrator and
// LocalSystem run it. A folder under C:\ProgramData alone does not need it:
// BUILTIN\Users can create one.
func requireAdministratorTestToken(t *testing.T, why string) {
	t.Helper()
	if !testTokenIsElevated() && !testRunsAsLocalSystem() {
		t.Skip("needs an administrator token: " + why)
	}
}

// grantTestTreeToCurrentUser gives the test account full control of root
// and everything under it, top down, so a fixture whose folders only
// Administrators can enter can be removed by the account that owns them.
// It never fails.
func grantTestTreeToCurrentUser(root string) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return
	}
	var grant func(string)
	grant = func(path string) {
		_ = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
		entries, err := os.ReadDir(path)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if entry.Type()&os.ModeSymlink == 0 {
				grant(filepath.Join(path, entry.Name()))
			}
		}
	}
	grant(root)
}

// skipIfLocalSystem skips a test whose fixture cannot hold when it runs as
// LocalSystem, saying why.
func skipIfLocalSystem(t *testing.T, why string) {
	t.Helper()
	if testRunsAsLocalSystem() {
		t.Skip("skipped as LocalSystem: " + why)
	}
}

func testRunsAsLocalSystem() bool {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && user != nil && user.User.Sid != nil && user.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

// The package runs with neither the computer's managed marker nor its
// installed scanner runtime in reach, managed or not, with every machine
// writer in the sandbox and the identity pinned.
func TestPackageTestsDoNotReachTheInstalledDeployment(t *testing.T) {
	// GAP-0093 review L1: the run's markers are its own folders, never the
	// shared temp folder.
	t.Logf("temp folder %s, run markers %q", os.TempDir(), testRunMarkers())
	if len(testRunTempDirs) == 0 {
		t.Fatal("the run has no temp folder of its own")
	}
	for _, marker := range testRunMarkers() {
		if strings.EqualFold(filepath.Clean(marker), filepath.Clean(os.TempDir())) && !testRunTempIsTheRuns() {
			t.Fatalf("the shared temp folder %s is a run marker", marker)
		}
	}
	if where, managed := managedHostWindowsStandalone(); managed {
		t.Fatalf("the managed-host guard reads the real deployment (%s)", where)
	}
	if managedHostWindowsMarkerUncertain() || secureClientHost() {
		t.Fatal("the outage mode reads the computer's own HKLM marker or Secure Client install")
	}
	if descriptor := managedHostDescriptorPath(); descriptor != "" {
		if rel, err := filepath.Rel(os.TempDir(), descriptor); err != nil || strings.HasPrefix(rel, "..") {
			t.Fatalf("the managed runtime descriptor %s is outside the temp folder %s", descriptor, os.TempDir())
		}
	}
	root, err := windowsScannerRuntimeDir()
	if err != nil {
		t.Fatal(err)
	}
	installed, err := managed.StandaloneWindowsScannerRuntimeDir()
	if err == nil && strings.EqualFold(filepath.Clean(root), filepath.Clean(installed)) {
		t.Fatalf("the scanner lifecycle works on the installed runtime %s", installed)
	}
	if rel, err := filepath.Rel(os.TempDir(), root); err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("scanner runtime %s is outside the temp folder %s", root, os.TempDir())
	}

	// GAP-0079: the machine writers.
	if windowsEnterpriseMachineRegistry == registry.LOCAL_MACHINE || windowsEnterpriseMachineRegistry == 0 {
		t.Fatalf("the standalone registration writes the real registry root (%#x), not the HKCU sandbox", windowsEnterpriseMachineRegistry)
	}
	logDir, err := windowsEnterpriseLogDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if rel, err := filepath.Rel(os.TempDir(), logDir); err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("the lifecycle log %s is outside the temp folder %s", logDir, os.TempDir())
	}

	// g079 review F1: the bundle store, the credentials and the change
	// spool are in the temp folder; the footprint, the Claude Code policy and
	// the gateway process read as absent.
	inTemp := func(what, path string) {
		t.Helper()
		if rel, err := filepath.Rel(os.TempDir(), path); path == "" || err != nil || strings.HasPrefix(rel, "..") {
			t.Fatalf("%s %q is outside the temp folder %s", what, path, os.TempDir())
		}
	}
	for name, read := range map[string]func() (managed.StandaloneLayout, error){
		"windowsBundleLayout": windowsBundleLayout, "windowsSecretLayout": windowsSecretLayout,
	} {
		layout, err := read()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, path := range []string{layout.ConfigDir, layout.DataDir, layout.SecretsDir, layout.LifecycleDir} {
			inTemp(name, path)
		}
		spool, err := windowsChangeSpool(layout)
		if err != nil {
			t.Fatal(err)
		}
		inTemp("the change spool", spool.Dir)
		inTemp("the change spool state", spool.StateDir)
	}
	if present, err := windowsEnterpriseStandaloneFootprint(); present || err != nil {
		t.Fatalf("the uninstall reads the computer's own footprint: %v %v", present, err)
	}
	if value, err := windowsEnterpriseClaudeRegistryPolicyValue(); value != "" || err != nil {
		t.Fatalf("the Claude Code machine policy of the computer is read: %q %v", value, err)
	}
	if windowsBundleRestoreGatewayRunning() || windowsStandaloneGatewayPID() != 0 {
		t.Fatal("the gateway service's process of the computer is read")
	}
	if live, err := windowsSecretGatewayLive(); live || err != nil {
		t.Fatalf("the gateway service's state of the computer is read: %v %v", live, err)
	}
	if absent, err := windowsSecretDeploymentAbsent(); !absent || err != nil {
		t.Fatalf("the credential refusal audit does not read the deployment as cleanly absent: %v %v", absent, err)
	}
	// g079 review 2 R2b: the lifecycle lock is the run's, in the temp
	// folder; neither lock seam takes the computer's own.
	lockPath, err := windowsSecretLifecycleLockPath()
	if err != nil {
		t.Fatal(err)
	}
	inTemp("the lifecycle lock", lockPath)
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		t.Fatal(err)
	}
	machineLock := filepath.Join(roots.LifecycleDir, "lifecycle.lock")
	for name, take := range map[string]func(string) (func(), error){
		"windowsEnterpriseHotConfigLock": windowsEnterpriseHotConfigLock, "windowsSecretLifecycleLock": windowsSecretLifecycleLock,
	} {
		if sameTestFunc(take, acquireWindowsEnterpriseLifecycleLock) {
			t.Fatalf("%s takes the computer's own lifecycle lock", name)
		}
		release, err := take(machineLock)
		if err == nil {
			release()
			t.Fatalf("%s took a lifecycle lock outside the sandbox", name)
		}
		if !strings.Contains(err.Error(), lockPath) {
			t.Fatalf("%s does not take the run's lifecycle lock %s: %v", name, lockPath, err)
		}
	}
	// cowork-1-0-8 GAP-0094: the guardian's config.yaml claim opens the
	// run's lifecycle lock, not the computer's. While the run's lock is
	// held, the claim says a run holds it.
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(lockPath); _ = os.Remove(filepath.Dir(lockPath)) })
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	held, err := tryWindowsEnterpriseLifecycleLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if owner := windowsEnterpriseConfigLifecycleClaim(); !strings.Contains(owner.reason, "holds lifecycle.lock") {
		if owner.release != nil {
			owner.release()
		}
		held()
		t.Fatalf("the guardian's config.yaml claim does not take the run's lifecycle lock %s: %+v", lockPath, owner)
	}
	held()
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if owner := windowsEnterpriseConfigLifecycleClaim(); owner.reason != "" || owner.release == nil {
		t.Fatalf("the guardian's config.yaml claim without the run's lock file: %+v", owner)
	} else {
		owner.release()
	}
	// cowork-1-0-8 GAP-0093 (round 2): the one layout source answers the
	// run's missing deployment; the Secure Client roots are the computer's.
	layout, err := windowsManagedLayout.standalone()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{layout.ConfigPath, layout.ConfigDir, layout.DataDir, layout.SecretsDir, layout.LifecycleDir,
		layout.GuardianAuthDir, layout.ManifestPath, layout.LogDir} {
		inTemp("the standalone layout", path)
	}
	standaloneRoots, err := windowsManagedLayout.roots(managed.ProfileStandalone)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{standaloneRoots.InstallRoot, standaloneRoots.StateRoot, standaloneRoots.LifecycleDir, standaloneRoots.CertificationInstallBase} {
		inTemp("the standalone roots", path)
	}
	// GAP-0093 (round 3, review 2 S2): the guardian's self-heal reads the
	// run's missing Program Files and ProgramData, and its three repairs are
	// the sandbox's no-ops, not the machine writers.
	selfHealFiles, selfHealData := windowsManagedLayout.programRoots()
	inTemp("the self-heal Program Files", selfHealFiles)
	inTemp("the self-heal ProgramData", selfHealData)
	for name, seam := range map[string][2]any{
		"enterpriseWindowsManagedInstallRepair":         {enterpriseWindowsManagedInstallRepair, managed.RepairWindowsManagedInstall},
		"enterpriseWindowsManagedPolicyArtifactsRepair": {enterpriseWindowsManagedPolicyArtifactsRepair, enterprisehooks.RepairWindowsManagedPolicyArtifacts},
		"enterpriseWindowsManagedServiceSecurityRepair": {enterpriseWindowsManagedServiceSecurityRepair, managed.RepairWindowsManagedServiceSecurity},
	} {
		if reflect.ValueOf(seam[0]).Pointer() == reflect.ValueOf(seam[1]).Pointer() {
			t.Fatalf("%s is the production repair of the computer's install, policy or services", name)
		}
	}
	if want, err := winpath.TrustedEnterpriseRoots(winpath.EnterpriseProfileSecureClient); err == nil {
		if got, err := windowsManagedLayout.roots(winpath.EnterpriseProfileSecureClient); err != nil || got != want {
			t.Fatalf("the Secure Client roots changed in the sandbox: %+v, %v; want %+v", got, err, want)
		}
	}
	// g079 review 2 R2c: the unelevated staging is in the run's temp folder.
	if sameTestFunc(windowsEnterpriseUserTempDirectory, trustedWindowsEnterpriseUserTempDirectory) {
		t.Fatal("the lifecycle stages in the token's own LocalAppData Temp folder")
	}
	userTemp, err := windowsEnterpriseUserTempDirectory()
	if err != nil {
		t.Fatal(err)
	}
	inTemp("the caller's staging temp folder", userTemp)
	// PR #1427 stress, GAP-0079 follow-up: the per-user gateway's port
	// claims are the run's, in the temp folder, in this process and in the
	// built gateway the executable tests start.
	inTemp("the gateway port claims folder", gatewayPortClaimDir)
	if strings.EqualFold(filepath.Clean(gatewayPortClaimDir), filepath.Clean(os.Getenv("ProgramData"))) {
		t.Fatalf("the gateway port claims go to the computer's ProgramData %s", gatewayPortClaimDir)
	}
	childHome := t.TempDir()
	var childProgramData []string
	for _, entry := range executableTestEnv(childHome, "gateway.exe", "start") {
		if key, value, ok := strings.Cut(entry, "="); ok && strings.EqualFold(key, "ProgramData") {
			childProgramData = append(childProgramData, value)
		}
	}
	if len(childProgramData) != 1 {
		t.Fatalf("the built gateway's ProgramData = %q, want one value in its test home", childProgramData)
	}
	inTemp("the built gateway's ProgramData", childProgramData[0])
	// Service control: first that no seam is its production function (one
	// would stop or start the computer's own gateway), then that each fails.
	for name, seam := range map[string][2]any{
		"windowsEnterpriseHotConfigRestart":           {windowsEnterpriseHotConfigRestart, restartWindowsStandaloneGateway},
		"windowsEnterpriseHotConfigRecover":           {windowsEnterpriseHotConfigRecover, startWindowsStandaloneGatewayIfStopped},
		"windowsEnterpriseHotConfigFailClosed":        {windowsEnterpriseHotConfigFailClosed, stopWindowsStandaloneGatewayFailClosed},
		"windowsEnterpriseHotConfigGuardianReconcile": {windowsEnterpriseHotConfigGuardianReconcile, nil},
		"windowsSecretRestartGateway":                 {windowsSecretRestartGateway, restartWindowsStandaloneGatewayBeforeStop},
		"windowsSecretSpawnRecovery":                  {windowsSecretSpawnRecovery, spawnWindowsSecretGatewayRecovery},
	} {
		if seam[1] != nil && reflect.ValueOf(seam[0]).Pointer() == reflect.ValueOf(seam[1]).Pointer() {
			t.Fatalf("%s is the production service control", name)
		}
	}
	if !sameTestFunc(windowsEnterpriseHotConfigGuardianReconcile, testSandboxGuardianReconcile) {
		t.Fatal("windowsEnterpriseHotConfigGuardianReconcile is not the sandbox's")
	}
	for name, err := range map[string]error{
		"windowsEnterpriseHotConfigRestart":           second(windowsEnterpriseHotConfigRestart()),
		"windowsEnterpriseHotConfigRecover":           second(windowsEnterpriseHotConfigRecover()),
		"windowsEnterpriseHotConfigFailClosed":        windowsEnterpriseHotConfigFailClosed(),
		"windowsEnterpriseHotConfigGuardianReconcile": windowsEnterpriseHotConfigGuardianReconcile(context.Background(), managed.StandaloneLayout{}, false),
		"windowsSecretRestartGateway":                 second(windowsSecretRestartGateway(func() error { return nil })),
		"windowsSecretSpawnRecovery":                  second(windowsSecretSpawnRecovery()),
	} {
		if !errors.Is(err, errTestSandboxNoServiceControl) {
			t.Fatalf("%s does not fail in the sandbox: %v", name, err)
		}
	}
	// The no-op writers (bundle marker sync, start-mode restore, runtime
	// folder repair, bin cleanup) are not called here: on a regression they
	// would change the computer. The TestMain registry guard catches them.

	// GAP-0079: the computer's own deployment record is not read.
	for _, profile := range []string{managed.ProfileStandalone, managed.ProfileSecureClient} {
		if deployment, err := windowsEnterpriseDeploymentInspector(profile); err != nil || deployment.State != winpath.EnterpriseDeploymentAbsent {
			t.Fatalf("the %s deployment record of the computer is read: %+v %v", profile, deployment, err)
		}
	}

	// GAP-0079: what the tests create is owned by the test account.
	probe := t.TempDir()
	if sd, err := windows.GetNamedSecurityInfo(probe, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION); err != nil {
		t.Fatal(err)
	} else if owner, _, err := sd.Owner(); err != nil {
		t.Fatal(err)
	} else if user, err := windows.GetCurrentProcessToken().GetTokenUser(); err != nil || !owner.Equals(user.User.Sid) {
		t.Fatalf("a test folder is owned by %v, not the test account", owner)
	}

	// g079 review F2: every seam above is registered with the TestMain
	// guard, and none has left the sandbox.
	registered := map[string]bool{}
	for _, seam := range testSandboxSeams {
		registered[seam.name] = true
	}
	for _, name := range []string{"windowsBundleLayout", "windowsSecretLayout", "windowsChangeSpool", "windowsSecretDeploymentAbsent",
		"windowsEnterpriseHotConfigLock", "windowsSecretLifecycleLock", "windowsSecretLifecycleLockPath", "windowsEnterpriseUserTempDirectory",
		"windowsEnterpriseStandaloneFootprint", "windowsEnterpriseClaudeRegistryPolicyValue",
		"windowsBundleRestoreGatewayRunning", "windowsStandaloneGatewayPID", "windowsSecretGatewayLive",
		"windowsEnterpriseHotConfigRestart", "windowsEnterpriseHotConfigRecover", "windowsEnterpriseHotConfigFailClosed",
		"windowsEnterpriseHotConfigGuardianReconcile", "windowsSecretRestartGateway", "windowsSecretSpawnRecovery",
		"enterpriseHooksPlatformPreflight", "windowsEnterpriseStagingElevated", "windowsBundleSyncMarker",
		"windowsEnterpriseLifecycleYield", "sidecarRaisePriority", "windowsEnterpriseRecordInspector",
		"windowsManagedLayout.standalone", "windowsManagedLayout.roots", "windowsEnterpriseConfigLifecycleClaim",
		"windowsManagedLayout.programRoots", "enterpriseWindowsManagedInstallRepair",
		"enterpriseWindowsManagedPolicyArtifactsRepair", "enterpriseWindowsManagedServiceSecurityRepair"} {
		if !registered[name] {
			t.Errorf("seam %s is not registered with the sandbox guard", name)
		}
	}
	if problems := testSandboxProblems(); len(problems) != 0 {
		t.Fatalf("the package is outside its sandbox:\n%s", strings.Join(problems, "\n"))
	}

	// GAP-0079: the identity is pinned.
	if !windowsEnterpriseIsElevated() || !windowsSecretIsElevated() || !windowsCoworkElevated() ||
		windowsEnterpriseRunningAsLocalSystem() || windowsClaudeSettingsCheckerIsLocalSystem() ||
		!errors.Is(enterpriseHookWindowsUserCleanupIdentity(), enterprisehooks.ErrWindowsEnterpriseNotLocalSystem) ||
		enterpriseHooksPlatformPreflight() != nil {
		t.Fatalf("the package's tests do not run as %s", testProcessIdentityNote)
	}
	if windowsEnterpriseStagingElevated() {
		t.Fatal("the lifecycle stages its scripts in the computer's ProgramData, not the caller's temp folder")
	}
}

// GAP-0079: a successful install publishes the marker, the Add/Remove
// Programs entry and the policy key, and the uninstall removes them, in the
// test sandbox and never in HKLM.
func TestStandaloneRegistrationWritesOnlyTheTestSandbox(t *testing.T) {
	savedLayout := windowsBundleLayout
	t.Cleanup(func() { windowsBundleLayout = savedLayout })
	windowsBundleLayout = func() (managed.StandaloneLayout, error) { return managed.StandaloneLayout{}, os.ErrNotExist }
	before := snapshotTestMachineRegistry()

	install := &enterprisestatus.Result{Action: "install", OK: true, Installed: true, InstalledVersion: "1.0.9-sandbox"}
	if err := updateWindowsEnterpriseRegistration(install, nil); err != nil {
		t.Fatal(err)
	}
	for path, values := range map[string]map[string]string{
		WindowsEnterpriseMarkerKey: {"Profile": managed.ProfileStandalone, "ProductVersion": "1.0.9-sandbox"},
		windowsEnterpriseARPKey:    {"DisplayVersion": "1.0.9-sandbox", "DisplayName": "Cisco DefenseClaw Enterprise"},
	} {
		key, err := registry.OpenKey(windowsEnterpriseMachineRegistry, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
		if err != nil {
			t.Fatalf("the sandbox has no %s: %v", path, err)
		}
		for name, want := range values {
			if got, _, err := key.GetStringValue(name); err != nil || got != want {
				t.Errorf("sandbox %s\\%s = %q (%v), want %q", path, name, got, err, want)
			}
		}
		_ = key.Close()
	}

	uninstall := &enterprisestatus.Result{Action: "uninstall", OK: true}
	if err := updateWindowsEnterpriseRegistration(uninstall, nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{WindowsEnterpriseMarkerKey, windowsEnterpriseARPKey} {
		if key, err := registry.OpenKey(windowsEnterpriseMachineRegistry, path, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
			_ = key.Close()
			t.Errorf("the uninstall left %s in the sandbox", path)
		}
	}
	if changes := diffTestMachineRegistry(before, snapshotTestMachineRegistry()); len(changes) != 0 {
		t.Fatalf("the registration changed HKLM:\n%s", strings.Join(changes, "\n"))
	}
}

// The registry guard sees an added, a changed and a removed value.
func TestTestMachineRegistryGuardReportsEveryChange(t *testing.T) {
	before := map[string]string{`k\kept`: "1:00", `k\changed`: "1:00", `k\removed`: "1:00"}
	after := map[string]string{`k\kept`: "1:00", `k\changed`: "1:01", `k\added`: "1:00"}
	got := strings.Join(diffTestMachineRegistry(before, after), "\n")
	want := "added k\\added = 1:00\nchanged k\\changed = 1:00 -> 1:01\nremoved k\\removed = 1:00"
	if got != want {
		t.Fatalf("diff =\n%s\nwant\n%s", got, want)
	}
	if changes := diffTestMachineRegistry(before, before); len(changes) != 0 {
		t.Fatalf("an unchanged snapshot reported %v", changes)
	}
}

// g079 review F2: the sandbox guard names a seam a test left reassigned,
// and is quiet once it is set back.
func TestTestSandboxGuardNamesALeakedSeam(t *testing.T) {
	if problems := testSandboxProblems(); len(problems) != 0 {
		t.Fatalf("the package is outside its sandbox before the test: %v", problems)
	}
	saved := windowsBundleRestoreGatewayRunning
	windowsBundleRestoreGatewayRunning = func() bool { return false }
	problems := strings.Join(testSandboxProblems(), "\n")
	windowsBundleRestoreGatewayRunning = saved
	if !strings.Contains(problems, "seam windowsBundleRestoreGatewayRunning is not the sandbox's") {
		t.Fatalf("a leaked seam was not named: %q", problems)
	}
	if problems := testSandboxProblems(); len(problems) != 0 {
		t.Fatalf("the restored seam is still reported: %v", problems)
	}
}

// g079 review F2: the folder fingerprint sees an added, a changed and a
// removed file, and leaves out a skipped folder.
func TestTestMachineFolderFingerprintSeesEveryChange(t *testing.T) {
	root := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`etc\kept.json`, "1")
	write(`etc\changed.json`, "1")
	write(`etc\removed.json`, "1")
	write(`data\gateway.log`, "1")
	skip := []string{filepath.Join(root, "data")}
	fingerprint := func() map[string]string {
		snapshot := map[string]string{}
		fingerprintTestTree(snapshot, root, skip)
		return snapshot
	}
	before := fingerprint()
	write(`etc\changed.json`, "12")
	write(`etc\added.json`, "1")
	write(`data\gateway.log`, "12")
	if err := os.Remove(filepath.Join(root, `etc\removed.json`)); err != nil {
		t.Fatal(err)
	}
	changes := strings.Join(diffTestMachineRegistry(before, fingerprint()), "\n")
	for _, want := range []string{"added file " + filepath.Join(root, `etc\added.json`),
		"changed file " + filepath.Join(root, `etc\changed.json`), "removed file " + filepath.Join(root, `etc\removed.json`)} {
		if !strings.Contains(changes, want) {
			t.Errorf("the fingerprint diff has no %q:\n%s", want, changes)
		}
	}
	if strings.Contains(changes, "gateway.log") || strings.Contains(changes, "kept.json") {
		t.Errorf("the fingerprint diff reports a skipped or unchanged file:\n%s", changes)
	}
}
