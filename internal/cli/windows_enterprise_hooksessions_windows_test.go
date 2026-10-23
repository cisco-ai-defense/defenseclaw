// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// GAP-0352: the protected session record folder is owned by Administrators;
// SYSTEM and Administrators have full control, the gateway service modify,
// and standard users only read and list this folder (their own folder below
// has its own DACL). Nobody else has access.
func TestWindowsHookSessionFolderSDDL(t *testing.T) {
	gateway, err := windows.StringToSid("S-1-5-80-1-2-3-4-5")
	if err != nil {
		t.Fatal(err)
	}
	sddl := windowsHookSessionSDDL(gateway)
	for _, want := range []string{"O:BAG:SYD:P", "(A;OICI;FA;;;SY)", "(A;OICI;FA;;;BA)", "(A;;0x1200a9;;;BU)", "(A;OICI;0x1301bf;;;S-1-5-80-1-2-3-4-5)"} {
		if !strings.Contains(sddl, want) {
			t.Fatalf("%s lacks %s", sddl, want)
		}
	}
	if strings.Count(sddl, "(A;") != 4 || strings.Contains(sddl, "(D;") {
		t.Fatalf("unexpected entries in %s", sddl)
	}
	if _, err := windows.SecurityDescriptorFromString(sddl); err != nil {
		t.Fatal(err)
	}
}

// windowsHookSessionTestHost points the lifecycle step at a record folder
// in a temporary folder, as an elevated lifecycle sees it, and accepts the
// key files the test account makes as SYSTEM's.
func windowsHookSessionTestHost(t *testing.T) (root, identity string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	identity = user.User.Sid.String()
	root = filepath.Join(t.TempDir(), windowsHookSessionFolderName)
	previousDir, previousElevated := windowsHookSessionDir, windowsEnterpriseIsElevated
	windowsHookSessionDir = func() (string, error) { return root, nil }
	windowsEnterpriseIsElevated = func() bool { return true }
	restoreOwner := enterprisepolicy.OverridePublishedSessionKeyOwnerForTest(func(path string) (bool, error) {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return info.Mode().IsRegular(), nil
	})
	// The test account writes the records in place of the gateway service,
	// which the record folder's access list names.
	restoreRevocable := enterprisepolicy.OverridePublishedSessionRevocableForTest(func(string, string) error { return nil })
	t.Cleanup(func() {
		windowsHookSessionDir, windowsEnterpriseIsElevated = previousDir, previousElevated
		restoreOwner()
		restoreRevocable()
	})
	return root, identity
}

func windowsHookSessionTestProves(root, identity string, key enterprisepolicy.SessionKey) bool {
	_, err := enterprisepolicy.CheckPublishedForeignHookSession(root, identity, key, enterprisepolicy.GuardDecision{}, func(string) error { return nil })
	return err == nil
}

// Item 7, the Windows lifecycle step (round 3 scenario 4): install, upgrade,
// repair, ensure and uninstall remove every account's key of the records
// before they change anything (KillAllPublishedSessionKeys), and status and
// verify do not; a lifecycle that is not elevated touches nothing. Only an
// install, upgrade, repair or ensure that finished without an error makes
// keys again (RotateAllPublishedSessionKeys), after it put the folder's owner
// and DACL back; one with an error, uninstall, status and verify make none.
func TestWindowsLifecycleKillsTheKeysFirstAndMakesThemLast(t *testing.T) {
	root, identity := windowsHookSessionTestHost(t)
	var kills, ensures []string
	previousKill, previousEnsure := windowsHookSessionKillKeys, windowsHookSessionRotateKeys
	windowsHookSessionKillKeys = func(path string) error {
		kills = append(kills, path)
		return previousKill(path)
	}
	windowsHookSessionRotateKeys = func(path string, trust enterprisepolicy.PublishedSessionTrust) error {
		ensures = append(ensures, path)
		return previousEnsure(path, trust)
	}
	t.Cleanup(func() { windowsHookSessionKillKeys, windowsHookSessionRotateKeys = previousKill, previousEnsure })
	for _, action := range []string{"install", "upgrade", "repair", "ensure", "uninstall", "status", "verify"} {
		kills = nil
		killWindowsHookSessionKey(action)
		want := action != "status" && action != "verify"
		if want != (len(kills) == 1 && kills[0] == root) {
			t.Fatalf("%s: kills %v", action, kills)
		}
	}
	windowsEnterpriseIsElevated = func() bool { return false }
	kills = nil
	killWindowsHookSessionKey("repair")
	if len(kills) != 0 {
		t.Fatal("a lifecycle that is not elevated must touch no key")
	}
	windowsEnterpriseIsElevated = func() bool { return true }

	opts := &windowsEnterpriseLifecycleOptions{}
	for _, action := range []string{"install", "upgrade", "repair", "ensure", "uninstall", "status", "verify"} {
		ensures = nil
		failed := &enterprisestatus.Result{Action: action}
		failed.AddError("apply_failed", "the action failed")
		applyWindowsStandaloneHookSessionRecords(failed, opts)
		if len(ensures) != 0 {
			t.Fatalf("%s that failed must make no key: %v", action, ensures)
		}
	}
	// An account folder the gateway made, without a key.
	key := enterprisepolicy.SessionKey{Connector: "copilot", Session: "s-1", Process: "windows:b:1:100"}
	if err := enterprisepolicy.WritePublishedSessionRecordsForTest(root, identity, key, enterprisepolicy.GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"status", "verify"} {
		ensures = nil
		applyWindowsStandaloneHookSessionRecords(&enterprisestatus.Result{Action: action}, opts)
		if len(ensures) != 0 {
			t.Fatalf("%s must make no key: %v", action, ensures)
		}
	}
	for _, action := range []string{"install", "upgrade", "repair", "ensure"} {
		ensures = nil
		result := &enterprisestatus.Result{Action: action}
		applyWindowsStandaloneHookSessionRecords(result, opts)
		if len(result.Warnings) != 0 {
			t.Skipf("the record folder cannot get its owner here (an elevated test): %+v", result.Warnings)
		}
		if len(ensures) != 1 || ensures[0] != root {
			t.Fatalf("%s that finished must make the keys once, last: %v", action, ensures)
		}
		if _, err := enterprisepolicy.ReadPublishedSessionKey(root, identity); err != nil {
			t.Fatalf("%s that finished must give the account a key: %v", action, err)
		}
	}
	keyDir, _ := enterprisepolicy.PublishedSessionKeyDir(root)
	if !strings.EqualFold(keyDir, filepath.Dir(root)) {
		t.Fatalf("the key must be next to the record folder: %s", keyDir)
	}
	ensures = nil
	uninstall := &enterprisestatus.Result{Action: "uninstall"}
	applyWindowsStandaloneHookSessionRecords(uninstall, opts)
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) || len(uninstall.Warnings) != 0 || len(ensures) != 0 {
		t.Fatalf("uninstall must remove the folder and make no key: %v %+v %v", err, uninstall.Warnings, ensures)
	}
	if keys, _ := filepath.Glob(filepath.Join(filepath.Dir(root), filepath.Base(root)+".*"+enterprisepolicy.PublishedSessionKeyInfix+"*")); len(keys) != 0 {
		t.Fatalf("uninstall must remove the keys: %v", keys)
	}
}

// Kill switch (round 3 scenario 4, on real folders): an account that kept a
// handle with WRITE_DAC on the record folder (from a time it owned it) can
// change the folder whatever the repair does to it, also when the repair
// runs as SYSTEM without SeRestorePrivilege and can give it no owner the
// hook refuses. It writes a trusted DACL back and puts its old records back
// after the repair. They prove nothing: the repair removed the key first
// and made a new one, which no handle on the folder reaches. The next
// exchange's allow proves the process again.
func TestWindowsHookSessionRepairWithARetainedHandleKeepsNoOldAllow(t *testing.T) {
	root, identity := windowsHookSessionTestHost(t)
	opts := &windowsEnterpriseLifecycleOptions{}
	result := &enterprisestatus.Result{Action: "install"}
	applyWindowsStandaloneHookSessionRecords(result, opts)
	if len(result.Warnings) != 0 {
		t.Skipf("the record folder cannot get its owner here (an elevated test): %+v", result.Warnings)
	}
	key := enterprisepolicy.SessionKey{Connector: "copilot", Session: "s-1", Process: "windows:b:1:100"}
	// The gateway makes the account's folder; the guardian's next pass gives
	// it a key; the next allow is published under it.
	for i := 0; i < 2; i++ {
		if err := enterprisepolicy.WritePublishedSessionRecordsForTest(root, identity, key, enterprisepolicy.GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if err := enterprisepolicy.EnsurePublishedSessionKeys(root, windowsHookSessionTrust()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !windowsHookSessionTestProves(root, identity, key) {
		t.Fatal("the published allow must prove the process")
	}
	account, _ := enterprisepolicy.PublishedSessionIdentityDir(root, identity)
	saved := filepath.Join(t.TempDir(), "saved")
	if err := os.CopyFS(saved, os.DirFS(account)); err != nil {
		t.Fatal(err)
	}
	// The repair, as SYSTEM without the restore privilege: the keys go
	// first, the folder gets its DACL back, and new keys come last.
	killWindowsHookSessionKey("repair")
	result = &enterprisestatus.Result{Action: "repair"}
	applyWindowsStandaloneHookSessionRecords(result, opts)
	if len(result.Warnings) != 0 {
		t.Fatalf("the repair must finish: %+v", result.Warnings)
	}
	// The retained handle: the account puts its old folder back and a DACL
	// the hook trusts.
	if err := os.RemoveAll(account); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(account, os.DirFS(saved)); err != nil {
		t.Fatal(err)
	}
	gateway, err := managed.WindowsServiceAccountSID(windowsHookSessionGatewayAccount)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyWindowsSDDL(root, windowsHookSessionSDDL(gateway)); err != nil {
		t.Fatal(err)
	}
	if windowsHookSessionTestProves(root, identity, key) {
		t.Fatal("records put back after a repair must prove nothing")
	}
	if err := enterprisepolicy.WritePublishedSessionRecordsForTest(root, identity, key, enterprisepolicy.GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !windowsHookSessionTestProves(root, identity, key) {
		t.Fatal("the next allow after the repair proves the process")
	}
}

// Review P1 (1.0.4 guard loop round 1, findings 4 and 6): an elevated
// install, upgrade, repair or ensure takes the key lock before it removes
// the keys and holds it to its end, so the hook guardian makes no key
// meanwhile, and a key that cannot be shown dead stops it before it changes
// anything (the error the command reports). A key that is shadowed or
// marked revoked is enough. An uninstall takes no lock and goes on.
func TestWindowsLifecycleStopsWhenAKeyCannotBeShownDead(t *testing.T) {
	windowsHookSessionTestHost(t)
	previousKill, previousLock := windowsHookSessionKillKeys, windowsHookSessionKeyLock
	t.Cleanup(func() { windowsHookSessionKillKeys, windowsHookSessionKeyLock = previousKill, previousLock })
	lockPath := enterprisepolicy.PublishedSessionKeysLockPath(t.TempDir())
	windowsHookSessionKeyLock = func() (string, error) { return lockPath, nil }
	windowsHookSessionKillKeys = func(string) error {
		return fmt.Errorf("%w: the file is in use", enterprisepolicy.ErrPublishedSessionKeyAlive)
	}
	opts := &windowsEnterpriseLifecycleOptions{}
	for _, action := range []string{"install", "upgrade", "repair", "ensure"} {
		run, err := beginWindowsHookSessionKeyChange(context.Background(), action, opts)
		if err != nil {
			t.Fatalf("%s: the key lock: %v", action, err)
		}
		err = run.kill()
		again := run.kill()
		run.release()
		if !errors.Is(err, enterprisepolicy.ErrPublishedSessionKeyAlive) || windowsEnterpriseMessageCode(err.Error(), "") != "hook_session_records_unavailable" ||
			!errors.Is(again, enterprisepolicy.ErrPublishedSessionKeyAlive) {
			t.Fatalf("%s must stop when a key cannot be shown dead: %v, then %v", action, err, again)
		}
	}
	run, err := beginWindowsHookSessionKeyChange(context.Background(), "uninstall", opts)
	if err != nil || run.kill() != nil {
		t.Fatalf("an uninstall goes on: %v", err)
	}
	run.release()
	windowsHookSessionKillKeys = func(string) error { return errors.New("the file is in use; a second key stays next to it") }
	run, err = beginWindowsHookSessionKeyChange(context.Background(), "repair", opts)
	if err == nil {
		err = run.kill()
	}
	if err != nil {
		t.Fatalf("a key that is shadowed is enough: %v", err)
	}
	if ran, err := enterprisepolicy.WithPublishedSessionKeyCreation(lockPath, func() error { return nil }); ran || err != nil {
		t.Fatalf("the guardian must make no key while the action holds the key lock: %v %v", ran, err)
	}
	run.release()
	if ran, err := enterprisepolicy.WithPublishedSessionKeyCreation(lockPath, func() error { return nil }); !ran || err != nil {
		t.Fatalf("the guardian makes keys once the action ended: %v %v", ran, err)
	}
}

// windowsHookSessionKillCounter counts the lifecycle's key removals and
// points the key lock at a temporary folder. With root "" it also points the
// record folder at an empty temporary one, so no test removes a key of the
// host it runs on.
func windowsHookSessionKillCounter(t *testing.T, root string) *int {
	t.Helper()
	previousKill, previousLock, previousDir := windowsHookSessionKillKeys, windowsHookSessionKeyLock, windowsHookSessionDir
	t.Cleanup(func() {
		windowsHookSessionKillKeys, windowsHookSessionKeyLock, windowsHookSessionDir = previousKill, previousLock, previousDir
	})
	if root == "" {
		root = filepath.Join(t.TempDir(), windowsHookSessionFolderName)
		windowsHookSessionDir = func() (string, error) { return root, nil }
	}
	lockPath := enterprisepolicy.PublishedSessionKeysLockPath(t.TempDir())
	windowsHookSessionKeyLock = func() (string, error) { return lockPath, nil }
	kills := new(int)
	windowsHookSessionKillKeys = func(path string) error {
		*kills++
		return previousKill(path)
	}
	return kills
}

// windowsHookSessionTestAllow gives the test account a key and publishes an
// allow under it, as the hook guardian and the gateway do, and returns the
// session the allow proves.
func windowsHookSessionTestAllow(t *testing.T, root, identity string) enterprisepolicy.SessionKey {
	t.Helper()
	result := &enterprisestatus.Result{Action: "install"}
	applyWindowsStandaloneHookSessionRecords(result, &windowsEnterpriseLifecycleOptions{})
	if len(result.Warnings) != 0 {
		t.Skipf("the record folder cannot get its owner here (an elevated test): %+v", result.Warnings)
	}
	key := enterprisepolicy.SessionKey{Connector: "copilot", Session: "s-1", Process: "windows:b:1:100"}
	for i := 0; i < 2; i++ {
		if err := enterprisepolicy.WritePublishedSessionRecordsForTest(root, identity, key, enterprisepolicy.GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if err := enterprisepolicy.EnsurePublishedSessionKeys(root, windowsHookSessionTrust()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !windowsHookSessionTestProves(root, identity, key) {
		t.Fatal("the published allow must prove the process")
	}
	return key
}

// runWindowsHookSessionTestAction runs one standalone lifecycle action with
// the installer stubbed (stubWindowsHookSessionTestInstaller) and returns
// its schema-2 result.
func runWindowsHookSessionTestAction(t *testing.T, action string, opts *windowsEnterpriseLifecycleOptions) (enterprisestatus.Result, error) {
	t.Helper()
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	err := runWindowsEnterpriseStandaloneAction(context.Background(), command, action, opts, `C:\stage\install-enterprise.ps1`, nil)
	var result enterprisestatus.Result
	if decodeErr := json.Unmarshal(stdout.Bytes(), &result); decodeErr != nil {
		t.Fatalf("%s: decode %q: %v", action, stdout.String(), decodeErr)
	}
	return result, err
}

// stubWindowsHookSessionTestInstaller fails every installer run and counts
// the runs, and keeps the host's own deployment out of the result.
func stubWindowsHookSessionTestInstaller(t *testing.T) *int {
	t.Helper()
	stubWindowsEnterpriseDeployments(t, nil)
	originalRunner, originalObserver := windowsEnterpriseStandaloneRunner, windowsEnterpriseStandaloneObserver
	t.Cleanup(func() {
		windowsEnterpriseStandaloneRunner, windowsEnterpriseStandaloneObserver = originalRunner, originalObserver
	})
	runs := new(int)
	windowsEnterpriseStandaloneRunner = func(context.Context, *cobra.Command, string, []string) (windowsEnterpriseStandaloneRun, error) {
		*runs++
		return windowsEnterpriseStandaloneRun{}, errors.New("the test runs no installer")
	}
	windowsEnterpriseStandaloneObserver = func(*enterprisestatus.Result, *windowsEnterpriseLifecycleOptions) string { return "" }
	return runs
}

// Review P2 (q-win-lifecycle loop round 2): a lifecycle refusal that only
// read the request changed nothing, so it comes before the session keys go:
// every account's published allow still proves its process during a
// gateway outage, as before the run. Here an upgrade or repair whose config
// moves gateway.api_port (GAP-0865) or enrols no connector (GAP-0602). The
// run that goes on removes the keys before its first change, and one whose
// key cannot be shown dead stops there, before the installer.
func TestWindowsReadOnlyLifecycleRefusalsKeepTheSessionKeys(t *testing.T) {
	root, identity := windowsHookSessionTestHost(t)
	key := windowsHookSessionTestAllow(t, root, identity)
	kills := windowsHookSessionKillCounter(t, root)
	installerRuns := stubWindowsHookSessionTestInstaller(t)
	originalPort, originalStaged, originalEnrolled := windowsEnterpriseConfigAPIPort, windowsEnterpriseStagedConnectors, windowsEnterpriseEnrolledConnectors
	t.Cleanup(func() {
		windowsEnterpriseConfigAPIPort, windowsEnterpriseStagedConnectors, windowsEnterpriseEnrolledConnectors = originalPort, originalStaged, originalEnrolled
	})
	stagedPort, staged := 18970, []string{"codex"}
	windowsEnterpriseConfigAPIPort = func(path string) (int, error) {
		if path == "" {
			return 18970, nil
		}
		return stagedPort, nil
	}
	windowsEnterpriseStagedConnectors = func(string) ([]string, error) { return staged, nil }
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) { return []string{"codex"}, nil }
	options := func() *windowsEnterpriseLifecycleOptions {
		return &windowsEnterpriseLifecycleOptions{profile: "standalone", resolvedProfile: "standalone", configPath: `C:\stage\config.yaml`, jsonOutput: true}
	}
	for _, tc := range []struct {
		name, action string
		port         int
		staged       []string
	}{
		{"upgrade that moves gateway.api_port", "upgrade", 18971, []string{"codex"}},
		{"repair that moves gateway.api_port", "repair", 18971, []string{"codex"}},
		{"upgrade that enrols no connector", "upgrade", 18970, nil},
		{"repair that enrols no connector", "repair", 18970, nil},
	} {
		stagedPort, staged = tc.port, tc.staged
		result, err := runWindowsHookSessionTestAction(t, tc.action, options())
		if commandExitCode(err) != enterprisestatus.WindowsExitInvalidArgs || len(result.Errors) != 1 || result.Errors[0].Code != "invalid_arguments" {
			t.Fatalf("%s: refusal %v, errors %+v", tc.name, err, result.Errors)
		}
		if *kills != 0 || *installerRuns != 0 {
			t.Fatalf("%s: a refusal that changed nothing removed the session keys %d time(s), installer runs %d", tc.name, *kills, *installerRuns)
		}
		if !windowsHookSessionTestProves(root, identity, key) {
			t.Fatalf("%s: the allow published before the refused run no longer proves the process", tc.name)
		}
	}
	stagedPort, staged = 18970, []string{"codex"}
	windowsHookSessionKillKeys = func(string) error {
		*kills++
		return fmt.Errorf("%w: the file is in use", enterprisepolicy.ErrPublishedSessionKeyAlive)
	}
	result, err := runWindowsHookSessionTestAction(t, "upgrade", options())
	if err == nil || *kills != 1 || *installerRuns != 0 || !windowsBundleHasCode(result.Errors, "hook_session_records_unavailable") {
		t.Fatalf("an upgrade that goes on must remove the keys before the installer: kills %d, installer runs %d, errors %+v (%v)", *kills, *installerRuns, result.Errors, err)
	}
}

// The same for a repair whose supplied config cannot replace an installed
// config.yaml that does not parse (GAP-0948): it is refused before the keys
// go and before any other change.
func TestWindowsRefusedConfigReplacementKeepsTheSessionKeys(t *testing.T) {
	const installed = "invalid: [\n"
	host, opts := newHotConfigHost(t, installed, "also invalid: [\n")
	root, identity := windowsHookSessionTestHost(t)
	key := windowsHookSessionTestAllow(t, root, identity)
	kills := windowsHookSessionKillCounter(t, root)
	installerRuns := stubWindowsHookSessionTestInstaller(t)
	opts.jsonOutput = true
	result, err := runWindowsHookSessionTestAction(t, "repair", opts)
	if err == nil || len(result.Errors) != 1 || result.Errors[0].Code != "preflight_failed" ||
		!strings.Contains(result.Errors[0].Message, "neither does the supplied config") {
		t.Fatalf("repair with an unusable supplied config: %v, errors %+v", err, result.Errors)
	}
	if *kills != 0 || *installerRuns != 0 || !windowsHookSessionTestProves(root, identity, key) {
		t.Fatalf("a refusal that changed nothing removed the session keys %d time(s), installer runs %d", *kills, *installerRuns)
	}
	if got, readErr := os.ReadFile(host.configPath); readErr != nil || string(got) != installed {
		t.Fatalf("the refused repair changed config.yaml: %q, %v", got, readErr)
	}
}

// Review P2 (q-win-lifecycle loop round 3): the installer refuses some
// requests for the recorded deployment before it changes anything (a
// deferred install over an installed deployment; an install, an upgrade, or
// a repair without both policy files or with --no-start while the deployment
// waits for its deferred configuration). The lifecycle refuses them itself,
// before the session keys go, so the allow published before the run still
// proves its process. The runs it lets go on remove the keys before the
// installer, as before: a tombstone, a completing repair, and a pending
// transaction, whose recovery changes the record first.
func TestWindowsRecordedDeploymentRefusalsKeepTheSessionKeys(t *testing.T) {
	root, identity := windowsHookSessionTestHost(t)
	kills := windowsHookSessionKillCounter(t, root)
	installerRuns := stubWindowsHookSessionTestInstaller(t)
	originalInspector, originalPending := windowsEnterpriseDeploymentInspector, windowsEnterpriseStandaloneTransactionPending
	originalPort, originalStaged, originalEnrolled := windowsEnterpriseConfigAPIPort, windowsEnterpriseStagedConnectors, windowsEnterpriseEnrolledConnectors
	originalHookRuntime := windowsEnterpriseHookRuntimeDir
	t.Cleanup(func() {
		windowsEnterpriseDeploymentInspector, windowsEnterpriseStandaloneTransactionPending = originalInspector, originalPending
		windowsEnterpriseConfigAPIPort, windowsEnterpriseStagedConnectors, windowsEnterpriseEnrolledConnectors = originalPort, originalStaged, originalEnrolled
		windowsEnterpriseHookRuntimeDir = originalHookRuntime
	})
	windowsEnterpriseHookRuntimeDir = func() (string, error) { return "", nil }
	windowsEnterpriseConfigAPIPort = func(string) (int, error) { return 18970, nil }
	windowsEnterpriseStagedConnectors = func(string) ([]string, error) { return []string{"codex"}, nil }
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) { return []string{"codex"}, nil }
	var recorded winpath.EnterpriseDeployment
	pending := false
	windowsEnterpriseDeploymentInspector = func(profile string) (winpath.EnterpriseDeployment, error) {
		if profile != managed.ProfileStandalone {
			return winpath.EnterpriseDeployment{Profile: profile, State: winpath.EnterpriseDeploymentAbsent}, nil
		}
		deployment := recorded
		deployment.Profile = profile
		return deployment, nil
	}
	windowsEnterpriseStandaloneTransactionPending = func() bool { return pending }
	installed := winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentInstalled}
	waiting := winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentInstalled, DeferredConfigPending: true}
	for _, tc := range []struct {
		name, action      string
		deployment        winpath.EnterpriseDeployment
		pending           bool
		config, manifest  string
		deferred, noStart bool
		refused           bool
	}{
		{name: "deferred install over an installed deployment", action: "install", deployment: installed, deferred: true, refused: true},
		{name: "deferred install over a deferred deployment", action: "install", deployment: waiting, deferred: true, refused: true},
		{name: "install while the deferred configuration waits", action: "install", deployment: waiting,
			config: `C:\stage\config.yaml`, manifest: `C:\stage\targets.yaml`, refused: true},
		{name: "upgrade while the deferred configuration waits", action: "upgrade", deployment: waiting, config: `C:\stage\config.yaml`, refused: true},
		{name: "repair without --manifest while the deferred configuration waits", action: "repair", deployment: waiting,
			config: `C:\stage\config.yaml`, refused: true},
		{name: "repair with --no-start while the deferred configuration waits", action: "repair", deployment: waiting,
			config: `C:\stage\config.yaml`, manifest: `C:\stage\targets.yaml`, noStart: true, refused: true},
		{name: "deferred install over a tombstone", action: "install",
			deployment: winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentTombstone}, deferred: true},
		{name: "deferred install over no deployment", action: "install",
			deployment: winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentAbsent}, deferred: true},
		{name: "repair that completes the deferred configuration", action: "repair", deployment: waiting,
			config: `C:\stage\config.yaml`, manifest: `C:\stage\targets.yaml`},
		{name: "install over a pending transaction while the deferred configuration waits", action: "install", deployment: waiting, pending: true,
			config: `C:\stage\config.yaml`, manifest: `C:\stage\targets.yaml`},
		{name: "install over an installed deployment", action: "install", deployment: installed,
			config: `C:\stage\config.yaml`, manifest: `C:\stage\targets.yaml`},
	} {
		key := windowsHookSessionTestAllow(t, root, identity)
		*kills, *installerRuns = 0, 0
		recorded, pending = tc.deployment, tc.pending
		opts := &windowsEnterpriseLifecycleOptions{profile: "standalone", resolvedProfile: "standalone", jsonOutput: true,
			configPath: tc.config, manifestPath: tc.manifest, deferredConfig: tc.deferred, noStart: tc.noStart}
		result, err := runWindowsHookSessionTestAction(t, tc.action, opts)
		if !tc.refused {
			if *kills != 1 || *installerRuns != 1 || windowsHookSessionTestProves(root, identity, key) {
				t.Fatalf("%s: a run that goes on must remove the keys before the installer: kills %d, installer runs %d, errors %+v (%v)",
					tc.name, *kills, *installerRuns, result.Errors, err)
			}
			continue
		}
		if commandExitCode(err) != enterprisestatus.WindowsExitInvalidArgs || len(result.Errors) != 1 || result.Errors[0].Code != "invalid_arguments" ||
			!strings.Contains(result.Errors[0].Message, "nothing was changed") {
			t.Fatalf("%s: refusal %v, errors %+v", tc.name, err, result.Errors)
		}
		if *kills != 0 || *installerRuns != 0 || !windowsHookSessionTestProves(root, identity, key) {
			t.Fatalf("%s: a refusal that changed nothing removed the session keys %d time(s), installer runs %d", tc.name, *kills, *installerRuns)
		}
	}
}

// windowsHookSessionInstallerDocument is an installer run whose schema-1
// JSON document has these fields.
func windowsHookSessionInstallerDocument(t *testing.T, fields map[string]any) windowsEnterpriseStandaloneRun {
	t.Helper()
	document := map[string]any{"schema_version": 1}
	for name, value := range fields {
		document[name] = value
	}
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	run := windowsEnterpriseStandaloneRun{Output: body}
	if ok, _ := document["ok"].(bool); !ok {
		run.ExitCode = 1
	}
	return run
}

// Review P2 (q-win-lifecycle loop round 3): an uninstall the installer
// refuses because a program runs from, or holds a file in, the install
// folder or holds a data file (uninstall_in_use), or because a root is
// squatted, changed nothing. The lifecycle reads those refusals first, with
// the installer's own read-only precheck (a Status that names the
// self-uninstall caller), so the keys stay and the allow published before
// the run still proves its process; a PowerShell 7 no uninstall can run on
// is refused the same way. Any other precheck answer, an installer that
// does not know the precheck included, lets the uninstall go on, and it
// removes the keys before the installer's uninstall. A forced uninstall and
// a tombstone skip the precheck.
func TestWindowsRefusedUninstallKeepsTheSessionKeys(t *testing.T) {
	root, identity := windowsHookSessionTestHost(t)
	kills := windowsHookSessionKillCounter(t, root)
	stubWindowsHookSessionTestInstaller(t)
	originalInspector, originalFootprint, originalPolicy := windowsEnterpriseDeploymentInspector, windowsEnterpriseStandaloneFootprint, windowsEnterprisePolicyDigest
	t.Cleanup(func() {
		windowsEnterpriseDeploymentInspector, windowsEnterpriseStandaloneFootprint, windowsEnterprisePolicyDigest = originalInspector, originalFootprint, originalPolicy
	})
	windowsEnterpriseStandaloneFootprint = func() (bool, error) { return true, nil }
	windowsEnterprisePolicyDigest = func(context.Context) ([]byte, error) { return nil, nil }
	state := winpath.EnterpriseDeploymentInstalled
	windowsEnterpriseDeploymentInspector = func(profile string) (winpath.EnterpriseDeployment, error) {
		if profile != managed.ProfileStandalone {
			return winpath.EnterpriseDeployment{Profile: profile, State: winpath.EnterpriseDeploymentAbsent}, nil
		}
		return winpath.EnterpriseDeployment{Profile: profile, State: state}, nil
	}
	const precheck = windowsEnterpriseUninstallPrecheckVariable + "=4242"
	installedStatus := map[string]any{"ok": true, "action": "status", "installed": true, "gateway_ready": false}
	uninstallFailed := map[string]any{"ok": false, "action": "uninstall", "installed": true, "error": "lifecycle_error: the test stops the uninstall here"}
	inUse := "uninstall_in_use: defenseclaw-acp.exe (pid 4) runs from C:\\Program Files\\Cisco\\DefenseClaw\\bin\\, so DefenseClaw cannot remove its files; nothing was changed."
	for _, tc := range []struct {
		name     string
		state    winpath.EnterpriseDeploymentState
		force    bool
		precheck func() (windowsEnterpriseStandaloneRun, error)
		refusal  string // the error code of a refused uninstall, "" for one that goes on
		runs     string
	}{
		{name: "a program runs from the install folder", refusal: "uninstall_in_use", runs: "Status " + precheck + " | Status",
			precheck: func() (windowsEnterpriseStandaloneRun, error) {
				return windowsHookSessionInstallerDocument(t, map[string]any{"ok": false, "action": "status", "error": inUse, "errors": []string{inUse}}), nil
			}},
		{name: "a squatted root", refusal: "root_squatted", runs: "Status " + precheck + " | Status",
			precheck: func() (windowsEnterpriseStandaloneRun, error) {
				message := "root_squatted: C:\\ProgramData\\Cisco\\DefenseClaw is owned by a standard user, not an administrator"
				return windowsHookSessionInstallerDocument(t, map[string]any{"ok": false, "action": "status", "error": message}), nil
			}},
		{name: "no PowerShell 7", refusal: "powershell7_required", runs: "Status " + precheck,
			precheck: func() (windowsEnterpriseStandaloneRun, error) {
				return windowsEnterpriseStandaloneRun{}, fmt.Errorf("%w: PowerShell 7 (x64 MSI) is not installed", errPowerShell7Required)
			}},
		{name: "a precheck that finds nothing", runs: "Status " + precheck + " | Uninstall",
			precheck: func() (windowsEnterpriseStandaloneRun, error) {
				return windowsHookSessionInstallerDocument(t, map[string]any{"ok": true, "action": "status", "uninstall_precheck": true}), nil
			}},
		{name: "an installer without the precheck", runs: "Status " + precheck + " | Uninstall",
			precheck: func() (windowsEnterpriseStandaloneRun, error) {
				return windowsHookSessionInstallerDocument(t, installedStatus), nil
			}},
		{name: "a precheck failure the uninstall may repair", runs: "Status " + precheck + " | Uninstall",
			precheck: func() (windowsEnterpriseStandaloneRun, error) {
				message := "deployment.json has an access list the uninstall repairs"
				return windowsHookSessionInstallerDocument(t, map[string]any{"ok": false, "action": "status", "error": message}), nil
			}},
		{name: "a precheck that cannot start", runs: "Status " + precheck + " | Uninstall",
			precheck: func() (windowsEnterpriseStandaloneRun, error) {
				return windowsEnterpriseStandaloneRun{}, errors.New("the installer exited with code 1")
			}},
		{name: "a forced uninstall", force: true, runs: "Uninstall " + windowsEnterpriseForcedUninstallVariable + "=1"},
		{name: "a tombstone", state: winpath.EnterpriseDeploymentTombstone, runs: "Uninstall"},
	} {
		key := windowsHookSessionTestAllow(t, root, identity)
		*kills = 0
		state = winpath.EnterpriseDeploymentInstalled
		if tc.state != "" {
			state = tc.state
		}
		var runs []string
		windowsEnterpriseStandaloneRunner = func(ctx context.Context, _ *cobra.Command, _ string, args []string) (windowsEnterpriseStandaloneRun, error) {
			action := windowsEnterpriseInstallerAction(args)
			label := strings.Join(append([]string{action}, windowsEnterpriseInstallerRequestEnvironment(ctx, args)...), " ")
			runs = append(runs, label)
			switch {
			case label == "Status "+precheck:
				return tc.precheck()
			case action == "Status":
				return windowsHookSessionInstallerDocument(t, installedStatus), nil
			case action == "Uninstall":
				if *kills != 1 {
					t.Fatalf("%s: the uninstall ran before the keys were removed (%d removals)", tc.name, *kills)
				}
				return windowsHookSessionInstallerDocument(t, uninstallFailed), nil
			}
			t.Fatalf("%s: unexpected installer run %q", tc.name, args)
			return windowsEnterpriseStandaloneRun{}, nil
		}
		opts := &windowsEnterpriseLifecycleOptions{profile: "standalone", resolvedProfile: "standalone", jsonOutput: true, force: tc.force}
		command := &cobra.Command{}
		var stdout bytes.Buffer
		command.SetOut(&stdout)
		command.SetErr(&bytes.Buffer{})
		err := runWindowsEnterpriseStandaloneAction(context.Background(), command, "uninstall", opts, `C:\stage\install-enterprise.ps1`,
			[]string{"-Action", "Uninstall", "-SelfUninstallCallerPID", "4242"})
		var result enterprisestatus.Result
		if decodeErr := json.Unmarshal(stdout.Bytes(), &result); decodeErr != nil {
			t.Fatalf("%s: decode %q: %v", tc.name, stdout.String(), decodeErr)
		}
		if got := strings.Join(runs, " | "); got != tc.runs {
			t.Fatalf("%s: installer runs %q, want %q", tc.name, got, tc.runs)
		}
		if tc.refusal == "" {
			if *kills != 1 || windowsHookSessionTestProves(root, identity, key) {
				t.Fatalf("%s: an uninstall that goes on must remove the keys: kills %d (%v)", tc.name, *kills, err)
			}
			continue
		}
		if err == nil || len(result.Errors) == 0 || result.Errors[0].Code != tc.refusal || result.Action != "uninstall" {
			t.Fatalf("%s: refusal %v, action %q, errors %+v", tc.name, err, result.Action, result.Errors)
		}
		if *kills != 0 || !windowsHookSessionTestProves(root, identity, key) {
			t.Fatalf("%s: a refused uninstall removed the session keys %d time(s)", tc.name, *kills)
		}
	}
}

// The uninstall precheck reaches the installer only as a Status request: an
// installer that does not know it answers a plain status, never an
// uninstall.
func TestWindowsUninstallPrecheckIsAskedOnlyOfAStatus(t *testing.T) {
	ctx := context.WithValue(context.Background(), windowsEnterpriseUninstallPrecheckKey{}, "0")
	if env := windowsEnterpriseInstallerRequestEnvironment(ctx, []string{"-Action", "Status", "-Json"}); strings.Join(env, " ") != windowsEnterpriseUninstallPrecheckVariable+"=0" {
		t.Fatalf("status environment %q", env)
	}
	for _, action := range []string{"Uninstall", "Repair", "Verify"} {
		if env := windowsEnterpriseInstallerRequestEnvironment(ctx, []string{"-Action", action}); len(env) != 0 {
			t.Fatalf("%s environment %q", action, env)
		}
	}
	if env := windowsEnterpriseInstallerRequestEnvironment(context.Background(), []string{"-Action", "Status"}); len(env) != 0 {
		t.Fatalf("a plain status asks for %q", env)
	}
}

// The same for an install that finds an untrusted scanner runtime it cannot
// remove (GAP-0490): that refusal reads only, so it comes before the keys go.
func TestWindowsUnremovableScannerRuntimeRefusalKeepsTheSessionKeys(t *testing.T) {
	root, identity := windowsHookSessionTestHost(t)
	key := windowsHookSessionTestAllow(t, root, identity)
	kills := windowsHookSessionKillCounter(t, root)
	installerRuns := stubWindowsHookSessionTestInstaller(t)
	seamDir, seamCheck := windowsScannerRuntimeDir, windowsScannerRuntimeTreeCheck
	t.Cleanup(func() { windowsScannerRuntimeDir, windowsScannerRuntimeTreeCheck = seamDir, seamCheck })
	runtime := filepath.Join(t.TempDir(), "not-the-scanner-runtime")
	if err := os.MkdirAll(runtime, 0o700); err != nil {
		t.Fatal(err)
	}
	windowsScannerRuntimeDir = func() (string, error) { return runtime, nil }
	windowsScannerRuntimeTreeCheck = func(string) error { return errors.New(`BUILTIN\Users can add files to the python folder`) }
	result, err := runWindowsHookSessionTestAction(t, "install", &windowsEnterpriseLifecycleOptions{profile: "standalone", resolvedProfile: "standalone", jsonOutput: true})
	if err == nil || !windowsBundleHasCode(result.Errors, "scanner_runtime_untrusted") {
		t.Fatalf("install over an unremovable untrusted scanner runtime: %v, errors %+v", err, result.Errors)
	}
	if *kills != 0 || *installerRuns != 0 || !windowsHookSessionTestProves(root, identity, key) {
		t.Fatalf("a refusal that changed nothing removed the session keys %d time(s), installer runs %d", *kills, *installerRuns)
	}
}
