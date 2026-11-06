// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
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
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	// GAP-2572: on a managed lane host the HKLM marker key exists, so the
	// "marker present but unverified" check read it and closed every
	// per-user outage case; Secure Client and the runtime descriptor are the
	// other two machine signals the outage mode reads.
	managedHostWindowsMarkerUncertain = func() bool { return false }
	secureClientHost = func() bool { return false }
	pinTestProcessIdentity()
	normalizeTestTokenDefaultOwner()
	dir, err := os.MkdirTemp("", "defenseclaw-cli-test-")
	if err != nil {
		windowsScannerRuntimeDir = func() (string, error) { return "", err }
		managedHostDescriptorPath = func() string { return "" }
		isolateTestDeploymentReaders(os.TempDir())
		return isolateTestMachineWriters("")
	}
	isolateTestDeploymentReaders(dir)
	missingDescriptor := filepath.Join(dir, "no-runtime-descriptor")
	managedHostDescriptorPath = func() string { return missingDescriptor }
	// Absent like on a computer without a deployment.
	runtimeDir := filepath.Join(dir, "scanners")
	windowsScannerRuntimeDir = func() (string, error) { return runtimeDir, nil }
	restoreMachine := isolateTestMachineWriters(filepath.Join(dir, "lifecycle-logs"))
	return func() {
		restoreMachine()
		_ = os.RemoveAll(dir)
	}
}

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
	windowsEnterpriseIsElevated = func() bool { return true }
	windowsSecretIsElevated = func() bool { return true }
	windowsCoworkElevated = func() bool { return true }
	windowsEnterpriseRunningAsLocalSystem = func() bool { return false }
	windowsClaudeSettingsCheckerIsLocalSystem = func() bool { return false }
	enterpriseHookWindowsUserCleanupIdentity = func() error { return enterprisehooks.ErrWindowsEnterpriseNotLocalSystem }
	// The enterprise hooks commands ask the token through this seam too
	// (g079 review F3): it answers as the elevated runner.
	enterpriseHooksPlatformPreflight = func() error { return nil }
	// The lifecycle stages in the caller's own temp folder, which every
	// identity can build, never in the computer's ProgramData. A test of the
	// ProgramData staging sets useTestTokenForStaging.
	windowsEnterpriseStagingElevated = func() bool { return false }
}

// useTestTokenForStaging makes the lifecycle staging follow the test
// binary's own token, for a test of the elevated ProgramData staging itself.
func useTestTokenForStaging(t *testing.T) {
	t.Helper()
	saved := windowsEnterpriseStagingElevated
	t.Cleanup(func() { windowsEnterpriseStagingElevated = saved })
	windowsEnterpriseStagingElevated = testTokenIsElevated
}

// isolateTestMachineWriters points every machine writer of the standalone
// lifecycle at a sandbox: the registry root at a throwaway HKCU key, the
// lifecycle log at logDir in the temp folder, the event log at a writer that
// takes each event and keeps none, and the bundle marker sync, service
// start-mode restore, runtime folder repair, production bin cleanup and
// Program Files\Cisco removal at no-ops. The returned function removes the
// sandbox key.
func isolateTestMachineWriters(logDir string) func() {
	windowsBundleSyncMarker = func(*enterprisebundle.Store) error { return nil }
	windowsEnterpriseEventWriter = func(string, uint32, string, string) error { return nil }
	windowsEnterpriseLogDirectory = func() (string, error) {
		if logDir == "" {
			return "", errors.New("the tests have no temp folder for the lifecycle log")
		}
		return logDir, nil
	}
	windowsEnterpriseLogDirectoryEnsurer = func(directory string) error { return os.MkdirAll(directory, 0o700) }
	removeEmptyWindowsEnterpriseInstallParent = func() {}
	windowsEnterpriseRestoreStartModes = func(*windowsEnterpriseInstallerReport) error { return nil }
	windowsEnterpriseRepairDataDirBeforePlan = func() string { return "" }
	windowsEnterpriseRemoveReplacementCopies = func() []string { return nil }
	// The priority class is process state: a lifecycle test that lowered it
	// left every later test, and cmd.exe and the other programs they start,
	// below normal. TestWindowsLifecycleRunYieldsTheCPUToTheHooks checks the
	// real yield in a child process.
	windowsEnterpriseLifecycleYield = func() {}
	// The same for the sidecar, which raises its class to above normal
	// (TestSidecarAnswersAtTheHookPriorityClass checks it in a child).
	sidecarRaisePriority = func() {}
	// g079 review F1: service control of the DefenseClaw gateway and hook
	// guardian fails in tests.
	windowsEnterpriseHotConfigRestart = func() (bool, error) { return false, errTestSandboxNoServiceControl }
	windowsEnterpriseHotConfigRecover = func() (bool, error) { return false, errTestSandboxNoServiceControl }
	windowsEnterpriseHotConfigFailClosed = func() error { return errTestSandboxNoServiceControl }
	windowsEnterpriseHotConfigGuardianReconcile = testSandboxGuardianReconcile
	windowsSecretRestartGateway = func(func() error) (bool, error) { return false, errTestSandboxNoServiceControl }
	windowsSecretSpawnRecovery = func() (windowsSecretRecoveryControl, error) { return nil, errTestSandboxNoServiceControl }

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
	windowsEnterpriseMachineRegistry = key
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

// testMachineRegistrySandbox is this run's HKCU sandbox key.
var testMachineRegistrySandbox string

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
	return snapshot
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

// diffTestMachineRegistry lists what changed between two snapshots.
func diffTestMachineRegistry(before, after map[string]string) []string {
	var changes []string
	for name, value := range before {
		if now, ok := after[name]; !ok {
			changes = append(changes, "removed "+name+" = "+value)
		} else if now != value {
			changes = append(changes, "changed "+name+" = "+value+" -> "+now)
		}
	}
	for name, value := range after {
		if _, ok := before[name]; !ok {
			changes = append(changes, "added "+name+" = "+value)
		}
	}
	sort.Strings(changes)
	return changes
}

// guardTestMachine snapshots the computer's DefenseClaw machine registry
// before the package runs. The returned check fails the run when any test
// changed it (GAP-0079).
func guardTestMachine() func() error {
	before := snapshotTestMachineRegistry()
	return func() error {
		changes := diffTestMachineRegistry(before, snapshotTestMachineRegistry())
		if len(changes) == 0 {
			return nil
		}
		return fmt.Errorf("GAP-0079: the internal/cli tests changed the computer's own DefenseClaw machine registry "+
			"(every machine writer must reach the test sandbox HKCU\\%s):\n  %s",
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
	windowsEnterpriseRecordInspector = func(profile string) (winpath.EnterpriseDeployment, error) {
		return winpath.EnterpriseDeployment{Profile: profile, State: winpath.EnterpriseDeploymentAbsent}, nil
	}
	missing, err := managed.StandaloneWindowsLayoutForRoots(filepath.Join(dir, "no-program-files"), filepath.Join(dir, "no-program-data"))
	if err != nil {
		missing = managed.StandaloneLayout{ConfigPath: filepath.Join(dir, "no-config.yaml"),
			ManifestPath: filepath.Join(dir, "no-manifest.json"), DataDir: filepath.Join(dir, "no-data")}
	}
	windowsEnterpriseInstalledConfigPath = func() (string, error) { return missing.ConfigPath, nil }
	windowsEnterpriseInstalledConfigForStatus = func() (*config.Config, error) {
		return loadWindowsEnterpriseStandaloneConfig(missing.ConfigPath)
	}
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) { return windowsEnterpriseConfigConnectors(missing.ConfigPath) }
	windowsEnterpriseEnrolledTargets = func() (map[string]bool, error) {
		if _, err := enterprisehooks.LoadManifest(missing.ManifestPath); err != nil {
			return nil, err
		}
		return map[string]bool{}, nil
	}
	windowsEnterpriseGuardianRestores = func() (map[string]time.Time, error) {
		return readEnterpriseHookGuardianRestores(missing.DataDir)
	}
	windowsEnterpriseUnprotectedAgentsReader = func() ([]enterprisehooks.UnprotectedAgent, error) {
		return enterprisehooks.ReadWindowsUnprotectedAgents(missing.ManifestPath)
	}
	registry := connector.NewDefaultRegistry()
	windowsEnterpriseStatusV2Read = func() windowsEnterpriseStatusV2Inputs {
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
	}
	windowsEnterpriseGuardianStateForStatus = func() (enterpriseHookGuardianState, bool, error) {
		return enterpriseHookGuardianState{}, false, nil
	}
	windowsEnterpriseUserCleanupsForStatus = func() ([]enterpriseHookUserCleanup, error) { return nil, nil }
	windowsEnterpriseAgentSettingsNotices = func() []string { return nil }
	windowsEnterpriseNativeOTLPNotices = func() []string { return nil }
	windowsEnterpriseAmpMachineFolderProblems = func() []string { return nil }
	windowsEnterpriseDiscoveryHomeDirs = func() ([]string, error) { return nil, nil }
	// g079 review F1: the bundle store, the protected credentials and the
	// change spool of the computer's own layout, the uninstall footprint
	// (SCM services and machine roots), the Claude Code machine policy and
	// the gateway service's process. On a managed computer a secret test
	// that missed its spool stub wrote the real change spool as SYSTEM.
	windowsBundleLayout = func() (managed.StandaloneLayout, error) { return missing, nil }
	windowsSecretLayout = func() (managed.StandaloneLayout, error) { return missing, nil }
	spool := filepath.Join(dir, "change-spool")
	windowsChangeSpool = func(managed.StandaloneLayout) (enterprisestatus.ChangeSpool, error) {
		return enterprisestatus.ChangeSpool{Dir: filepath.Join(spool, enterprisestatus.ChangeEventsDirName), StateDir: spool}, nil
	}
	windowsEnterpriseStandaloneFootprint = func() (bool, error) { return false, nil }
	windowsEnterpriseClaudeRegistryPolicyValue = func() (string, error) { return "", nil }
	windowsBundleRestoreGatewayRunning = func() bool { return false }
	windowsStandaloneGatewayPID = func() uint32 { return 0 }
	windowsSecretGatewayLive = func() (bool, error) { return false, nil }
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

// requireAdministratorTestToken skips a test whose fixture only an
// administrator token can build (an Administrators-owned or protected
// object, a folder under C:\ProgramData), saying why. A standard user cannot
// create them, so the test cannot give the same answer as a standard user
// (GAP-0079); the elevated CI runner, an elevated administrator and
// LocalSystem run it.
func requireAdministratorTestToken(t *testing.T, why string) {
	t.Helper()
	if !testTokenIsElevated() && !testRunsAsLocalSystem() {
		t.Skip("needs an administrator token: " + why)
	}
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
