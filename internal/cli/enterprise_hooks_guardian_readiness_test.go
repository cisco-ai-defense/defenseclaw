// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks/guardianstate"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// guardianReadinessLayout is one shipped managed_enterprise layout, re-rooted
// under a test temp directory. authDir is the value both the gateway and the
// guardian service receive in DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR.
type guardianReadinessLayout struct {
	name     string
	dataDir  string
	authDir  string
	manifest string
}

func readPackagingFile(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", ".."}, parts...)...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shipped packaging file %s: %v", path, err)
	}
	return string(data)
}

func plistStringAfter(t *testing.T, body, name, pattern string) string {
	t.Helper()
	match := regexp.MustCompile(pattern).FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("%s: shipped launchd plist no longer matches %q", name, pattern)
	}
	return strings.TrimSpace(match[1])
}

func psm1Leaf(t *testing.T, body, pattern string) string {
	t.Helper()
	match := regexp.MustCompile(pattern).FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("DefenseClawEnterprise.psm1 layout no longer matches %q", pattern)
	}
	return match[1]
}

// shippedGuardianReadinessLayouts derives the Windows and macOS layouts from
// the packaging sources that install them, so the regression test exercises
// the real directories rather than a hand-picked pair that happens to match.
func shippedGuardianReadinessLayouts(t *testing.T) []guardianReadinessLayout {
	t.Helper()
	root := t.TempDir()

	const authEnv = `<key>DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR</key>\s*<string>([^<]+)</string>`
	guardianPlist := readPackagingFile(t, "packaging", "launchd", "com.cisco.secureclient.defenseclaw.hook-guardian.plist")
	gatewayPlist := readPackagingFile(t, "packaging", "launchd", "com.cisco.secureclient.defenseclaw.plist")
	macManifest := plistStringAfter(t, guardianPlist, "hook-guardian", `<string>--manifest</string>\s*<string>([^<]+)</string>`)
	macGuardianAuth := plistStringAfter(t, guardianPlist, "hook-guardian", authEnv)
	macGatewayAuth := plistStringAfter(t, gatewayPlist, "gateway", authEnv)
	if macGuardianAuth != macGatewayAuth {
		t.Fatalf("macOS gateway and guardian LaunchDaemons disagree on %s: %q vs %q",
			managed.HookGuardianAuthorizationDirEnv, macGatewayAuth, macGuardianAuth)
	}
	// installer_lib.sh renders data_dir as "${support_dir}/runtime" and the
	// support dir is the parent of hook-guardian/targets.yaml.
	macSupport := filepath.Dir(filepath.Dir(macManifest))

	module := readPackagingFile(t, "packaging", "windows", "DefenseClawEnterprise.psm1")
	winGuardianLeaf := psm1Leaf(t, module, `\$guardianDirectory = Microsoft\.PowerShell\.Management\\Join-Path \$StateRoot '([^']+)'`)
	winAuthLeaf := psm1Leaf(t, module, `AuthorizationDirectory = \(Microsoft\.PowerShell\.Management\\Join-Path \$StateRoot '([^']+)'\)`)
	winRuntimeLeaf := psm1Leaf(t, module, "\\$runtimeDirectory = Microsoft\\.PowerShell\\.Management\\\\Join-Path `\\s*\\$StateRoot `\\s*'([^']+)'")
	winManifestLeaf := psm1Leaf(t, module, `ManifestPath = \(Microsoft\.PowerShell\.Management\\Join-Path \$guardianDirectory '([^']+)'\)`)
	for _, want := range []string{
		`"DEFENSECLAW_HOME=$RuntimeDirectory"`,
		`"DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR=$AuthorizationDirectory"`,
	} {
		if !strings.Contains(module, want) {
			t.Fatalf("Windows service environment no longer sets %s for the gateway and guardian", want)
		}
	}
	winStateRoot := filepath.Join(root, "windows", "ProgramData", "Cisco", "Cisco Secure Client", "DefenseClaw")

	return []guardianReadinessLayout{
		{
			name:     "windows",
			dataDir:  filepath.Join(winStateRoot, winRuntimeLeaf),
			authDir:  filepath.Join(winStateRoot, winAuthLeaf),
			manifest: filepath.Join(winStateRoot, winGuardianLeaf, winManifestLeaf),
		},
		{
			name:     "darwin",
			dataDir:  filepath.Join(root, "darwin", filepath.FromSlash(macSupport), "runtime"),
			authDir:  filepath.Join(root, "darwin", filepath.FromSlash(macGuardianAuth)),
			manifest: filepath.Join(root, "darwin", filepath.FromSlash(macManifest)),
		},
	}
}

type guardianReadinessSeams struct {
	ownershipCalls []string
	fileTrustCalls []string
}

// stubGuardianReadinessTrust replaces the root/Administrators trust and
// ownership primitives (temp dirs are owned by the test user) while keeping
// the writer's real directory, publication, and path-resolution logic.
func stubGuardianReadinessTrust(t *testing.T) *guardianReadinessSeams {
	t.Helper()
	seams := &guardianReadinessSeams{}
	previousCfg := cfg
	previousManifest := enterpriseHookManifest
	previousDirTrust := enterpriseHookAuthorizationDirTrustCheck
	previousFileTrust := enterpriseHookAuthorizationFileTrustCheck
	previousOwnership := enterpriseHookAuthorizationOwnershipSetter
	previousReaderTrust := guardianReadinessStateTrustCheck
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseHookManifest = previousManifest
		enterpriseHookAuthorizationDirTrustCheck = previousDirTrust
		enterpriseHookAuthorizationFileTrustCheck = previousFileTrust
		enterpriseHookAuthorizationOwnershipSetter = previousOwnership
		guardianReadinessStateTrustCheck = previousReaderTrust
	})
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationFileTrustCheck = func(path string) error {
		seams.fileTrustCalls = append(seams.fileTrustCalls, path)
		return nil
	}
	enterpriseHookAuthorizationOwnershipSetter = func(path string) error {
		seams.ownershipCalls = append(seams.ownershipCalls, path)
		return nil
	}
	guardianReadinessStateTrustCheck = func(string) error { return nil }
	return seams
}

// TestGuardianReadinessWriterAndReaderAgreeOnShippedLayouts is the #896
// regression: in the shipped Windows and macOS layouts the manifest
// directory, the gateway data_dir, and the protected authorization directory
// are three different directories. The guardian used to write .state beside
// the manifest while the gateway read <data_dir>/hook-guardian/.state, so the
// collapsed configuration state (and Secure Client GetHealth
// configuration_state) stayed waiting_for_targets forever.
func TestGuardianReadinessWriterAndReaderAgreeOnShippedLayouts(t *testing.T) {
	for _, layout := range shippedGuardianReadinessLayouts(t) {
		t.Run(layout.name, func(t *testing.T) {
			seams := stubGuardianReadinessTrust(t)
			for _, dir := range []string{layout.dataDir, layout.authDir, filepath.Dir(layout.manifest)} {
				if err := os.MkdirAll(dir, 0o750); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(layout.manifest, []byte("version: 1\ntargets: []\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			// Both services receive the same authorization directory.
			t.Setenv(managed.HookGuardianAuthorizationDirEnv, layout.authDir)
			cfg = &config.Config{DataDir: layout.dataDir, DeploymentMode: managed.DeploymentModeManagedEnterprise}
			enterpriseHookManifest = layout.manifest

			health := gateway.NewSidecarHealth()
			health.SetDaemonConfigLoaded(true)
			health.SetGuardianStateReader(newGuardianReadinessStateReader(cfg.DataDir))
			if got := health.Snapshot().Configuration.State; got != gateway.ConfigStateWaitingForTargets {
				t.Fatalf("before any guardian write: configuration state = %q, want waiting_for_targets", got)
			}

			var log bytes.Buffer
			writeGuardianStateOrLog(&log, guardianstate.StateReady)
			if strings.Contains(log.String(), "warn") {
				t.Fatalf("guardian readiness write warned: %s", log.String())
			}
			health.RefreshConfiguration()
			if got := health.Snapshot().Configuration.State; got != gateway.ConfigStateReady {
				t.Fatalf("after guardian ready: configuration state = %q, want ready", got)
			}

			wantPath := filepath.Join(layout.authDir, guardianstate.FileName)
			if _, err := os.Stat(wantPath); err != nil {
				t.Fatalf("readiness state not published in the protected authorization dir: %v", err)
			}
			for _, stale := range []string{
				filepath.Join(filepath.Dir(layout.manifest), guardianstate.FileName),
				filepath.Join(layout.dataDir, "hook-guardian", guardianstate.FileName),
				filepath.Join(layout.dataDir, guardianstate.FileName),
			} {
				if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("readiness state leaked to %s (err=%v)", stale, err)
				}
			}
			if len(seams.ownershipCalls) == 0 || seams.ownershipCalls[len(seams.ownershipCalls)-1] != wantPath {
				t.Fatalf("protected ownership not applied to %s: %v", wantPath, seams.ownershipCalls)
			}
			if len(seams.fileTrustCalls) != 1 || seams.fileTrustCalls[0] != wantPath {
				t.Fatalf("published readiness state not re-verified: %v", seams.fileTrustCalls)
			}
			if runtime.GOOS != "windows" {
				info, err := os.Stat(wantPath)
				if err != nil {
					t.Fatal(err)
				}
				if perm := info.Mode().Perm(); perm != 0o640 {
					t.Fatalf("readiness state mode = %04o, want 0640 (owner-write only)", perm)
				}
			}

			writeGuardianStateOrLog(&log, guardianstate.StateWaitingForTargets)
			health.RefreshConfiguration()
			if got := health.Snapshot().Configuration.State; got != gateway.ConfigStateWaitingForTargets {
				t.Fatalf("after guardian waiting: configuration state = %q, want waiting_for_targets", got)
			}
		})
	}
}

// TestGuardianReadinessReaderIgnoresUntrustedState pins that the gateway does
// not honor a readiness file failing the administrator-only trust contract
// (for example one a gateway-writable location could supply): it collapses to
// the waiting_for_targets safe default instead of ready.
func TestGuardianReadinessReaderIgnoresUntrustedState(t *testing.T) {
	stubGuardianReadinessTrust(t)
	authDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, authDir)
	dataDir := t.TempDir()
	if err := guardianstate.WriteState(guardianstate.PathForDataDir(dataDir), guardianstate.StateReady); err != nil {
		t.Fatal(err)
	}
	guardianReadinessStateTrustCheck = func(string) error {
		return errors.New("writable by the gateway service account")
	}

	reader := newGuardianReadinessStateReader(dataDir)
	if got := reader(); got != guardianstate.StateUnknown {
		t.Fatalf("untrusted readiness state = %q, want unknown", got)
	}
	health := gateway.NewSidecarHealth()
	health.SetDaemonConfigLoaded(true)
	health.SetGuardianStateReader(reader)
	if got := health.Snapshot().Configuration.State; got != gateway.ConfigStateWaitingForTargets {
		t.Fatalf("untrusted readiness state collapsed to %q, want waiting_for_targets", got)
	}
}

// TestGuardianReadinessWriterNeverCreatesOrTrustsForeignDirectory pins that
// the writer does not widen who can write the file: it refuses an absent or
// untrusted authorization directory instead of creating or re-permissioning
// one.
func TestGuardianReadinessWriterNeverCreatesOrTrustsForeignDirectory(t *testing.T) {
	stubGuardianReadinessTrust(t)
	dataDir := t.TempDir()

	missing := filepath.Join(t.TempDir(), "hook-guardian-state")
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, missing)
	if _, err := writeEnterpriseHookGuardianReadinessState(dataDir, guardianstate.StateReady); err == nil {
		t.Fatal("readiness write succeeded without an existing protected authorization dir")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readiness writer created the authorization dir (err=%v)", err)
	}

	untrusted := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, untrusted)
	enterpriseHookAuthorizationDirTrustCheck = func(string) error {
		return errors.New("authorization dir is writable by the gateway")
	}
	path, err := writeEnterpriseHookGuardianReadinessState(dataDir, guardianstate.StateReady)
	if err == nil {
		t.Fatal("readiness write succeeded into an untrusted authorization dir")
	}
	if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("readiness state written into an untrusted dir (err=%v)", statErr)
	}

	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
	if _, err := writeEnterpriseHookGuardianReadinessState(dataDir, "waiting_for_config"); err == nil {
		t.Fatal("readiness writer accepted a literal the sidecar cannot map")
	}
}

func TestGuardianReadinessAfterReconcileRequiresCleanRun(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  enterpriseHookReconcileRun
		err  error
		want string
	}{
		{"clean", enterpriseHookReconcileRun{}, nil, guardianstate.StateReady},
		{"pending_only", enterpriseHookReconcileRun{Pending: 2}, nil, guardianstate.StateReady},
		{"failed_target", enterpriseHookReconcileRun{Failures: 1}, nil, guardianstate.StateWaitingForTargets},
		{"state_not_published", enterpriseHookReconcileRun{StateErr: errors.New("publish exact protected enrollment set: denied")}, nil, guardianstate.StateWaitingForTargets},
		{"reconcile_error", enterpriseHookReconcileRun{}, errors.New("manifest trust check failed"), guardianstate.StateWaitingForTargets},
	} {
		if got := guardianReadinessAfterReconcile(tc.run, tc.err); got != tc.want {
			t.Errorf("%s: readiness = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// guardianWatchReadinessFixture runs the real watch loop against a faked
// per-cycle reconcile so each outcome's published readiness can be observed
// through the gateway's reader.
type guardianWatchReadinessFixture struct {
	dataDir   string
	statePath string
	reader    func() string
}

func newGuardianWatchReadinessFixture(t *testing.T) guardianWatchReadinessFixture {
	t.Helper()
	stubGuardianReadinessTrust(t)
	previousInterval := enterpriseHookWatchInterval
	previousDebounce := enterpriseHookWatchDebounce
	previousSettle := enterpriseHookWatchSettle
	previousReconcile := enterpriseHookWatchReconcileOnce
	previousRefresh := enterpriseHookGuardianReadinessRefresh
	t.Cleanup(func() {
		enterpriseHookWatchInterval = previousInterval
		enterpriseHookWatchDebounce = previousDebounce
		enterpriseHookWatchSettle = previousSettle
		enterpriseHookWatchReconcileOnce = previousReconcile
		enterpriseHookGuardianReadinessRefresh = previousRefresh
	})
	root := t.TempDir()
	dataDir := filepath.Join(root, "runtime")
	authDir := filepath.Join(root, "hook-guardian-state")
	manifestDir := filepath.Join(root, "hook-guardian")
	for _, dir := range []string{dataDir, authDir, manifestDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, authDir)
	enterpriseHookManifest = filepath.Join(manifestDir, "targets.yaml")
	if err := os.WriteFile(enterpriseHookManifest, []byte("version: 1\ntargets: []\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg = &config.Config{DataDir: dataDir}
	enterpriseHookWatchInterval = 10 * time.Millisecond
	enterpriseHookWatchDebounce = 10 * time.Millisecond
	enterpriseHookWatchSettle = 10 * time.Millisecond
	return guardianWatchReadinessFixture{
		dataDir:   dataDir,
		statePath: guardianstate.PathForDataDir(dataDir),
		reader:    newGuardianReadinessStateReader(dataDir),
	}
}

func runGuardianWatchForTest(t *testing.T, ctx context.Context) <-chan error {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	done := make(chan error, 1)
	go func() { done <- runEnterpriseHooksWatch(cmd, nil) }()
	return done
}

func waitGuardianWatchForTest(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("watch returned %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("watch loop did not stop")
	}
}

// TestGuardianWatchPublishesReadyOnlyForCleanReconciles is the #896 review
// regression. Once the guardian and gateway agree on the readiness path, the
// gateway honors whatever the guardian publishes, so the guardian must not
// publish ready after a startup reconcile that returned a nil error with a
// failed target (runEnterpriseHookReconcileOnce does exactly that), must
// retract ready when a later reconcile fails or cannot publish its state,
// must retract a ready left by a previous guardian before its own first
// reconcile, and must retract ready when it stops.
func TestGuardianWatchPublishesReadyOnlyForCleanReconciles(t *testing.T) {
	fixture := newGuardianWatchReadinessFixture(t)
	// A ready left behind by a previous guardian process (restart,
	// reinstall over a retained authorization directory).
	if _, err := writeEnterpriseHookGuardianReadinessState(fixture.dataDir, guardianstate.StateReady); err != nil {
		t.Fatal(err)
	}
	if got := fixture.reader(); got != guardianstate.StateReady {
		t.Fatalf("seeded stale ready reads as %q", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	outcomes := []struct {
		run enterpriseHookReconcileRun
		err error
	}{
		{run: enterpriseHookReconcileRun{Failures: 1}}, // startup: a target failed
		{run: enterpriseHookReconcileRun{}},            // clean
		{run: enterpriseHookReconcileRun{StateErr: errors.New("publish exact protected enrollment set: denied")}},
		{err: errors.New("enterprise hooks reconcile: manifest trust check failed")},
		{run: enterpriseHookReconcileRun{Pending: 1}}, // clean with a pending target
	}
	// observed[i] is what the gateway read when reconcile i started, i.e.
	// the readiness published for reconcile i-1 (or at startup for i == 0).
	var observed []string
	var configurationAfterStartup gateway.ConfigurationState
	calls := 0
	enterpriseHookWatchReconcileOnce = func(context.Context) (enterpriseHookReconcileRun, error) {
		observed = append(observed, fixture.reader())
		if calls == 1 {
			health := gateway.NewSidecarHealth()
			health.SetDaemonConfigLoaded(true)
			health.SetGuardianStateReader(fixture.reader)
			configurationAfterStartup = health.Snapshot().Configuration.State
		}
		if calls >= len(outcomes) {
			cancel()
			return enterpriseHookReconcileRun{}, nil
		}
		outcome := outcomes[calls]
		calls++
		return outcome.run, outcome.err
	}
	waitGuardianWatchForTest(t, runGuardianWatchForTest(t, ctx))

	want := []string{
		guardianstate.StateWaitingForTargets, // stale ready retracted before the first reconcile
		guardianstate.StateWaitingForTargets, // startup reconcile had a failed target
		guardianstate.StateReady,             // clean reconcile
		guardianstate.StateWaitingForTargets, // state publication failed
		guardianstate.StateWaitingForTargets, // reconcile error
		guardianstate.StateReady,             // clean with only pending targets
	}
	if len(observed) < len(want) {
		t.Fatalf("observed %d reconciles %v, want at least %d", len(observed), observed, len(want))
	}
	for i := range want {
		if observed[i] != want[i] {
			t.Fatalf("readiness before reconcile %d = %q, want %q (all: %v)", i, observed[i], want[i], observed)
		}
	}
	if configurationAfterStartup != gateway.ConfigStateWaitingForTargets {
		t.Fatalf("configuration state after a startup reconcile with failures = %q, want waiting_for_targets", configurationAfterStartup)
	}
	if got := fixture.reader(); got != guardianstate.StateWaitingForTargets {
		t.Fatalf("readiness after the guardian stopped = %q, want waiting_for_targets", got)
	}
}

// TestGuardianWatchRefreshesReadyBetweenReconciles pins that a healthy
// guardian keeps its ready inside guardianstate.ReadyMaxAge even when its
// --interval is longer than the gateway's age bound.
func TestGuardianWatchRefreshesReadyBetweenReconciles(t *testing.T) {
	fixture := newGuardianWatchReadinessFixture(t)
	enterpriseHookWatchInterval = time.Hour
	enterpriseHookGuardianReadinessRefresh = 10 * time.Millisecond
	var readyWrites atomic.Int32
	enterpriseHookAuthorizationOwnershipSetter = func(path string) error {
		if path == fixture.statePath {
			if body, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(body)) == guardianstate.StateReady {
				readyWrites.Add(1)
			}
		}
		return nil
	}
	enterpriseHookWatchReconcileOnce = func(context.Context) (enterpriseHookReconcileRun, error) {
		return enterpriseHookReconcileRun{}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runGuardianWatchForTest(t, ctx)
	deadline := time.Now().Add(10 * time.Second)
	for readyWrites.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	waitGuardianWatchForTest(t, done)
	if got := readyWrites.Load(); got < 3 {
		t.Fatalf("ready was published %d times with a 1h interval, want the startup ready plus refreshes", got)
	}
	if got := fixture.reader(); got != guardianstate.StateWaitingForTargets {
		t.Fatalf("readiness after the guardian stopped = %q, want waiting_for_targets", got)
	}
}

// TestGuardianReadinessReaderExpiresStaleReady pins the crash case: a
// guardian killed without retracting ready (no deferred write ran) must not
// leave the gateway reporting ready indefinitely.
func TestGuardianReadinessReaderExpiresStaleReady(t *testing.T) {
	stubGuardianReadinessTrust(t)
	authDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, authDir)
	dataDir := t.TempDir()
	path, err := writeEnterpriseHookGuardianReadinessState(dataDir, guardianstate.StateReady)
	if err != nil {
		t.Fatal(err)
	}
	reader := newGuardianReadinessStateReader(dataDir)
	if got := reader(); got != guardianstate.StateReady {
		t.Fatalf("fresh ready = %q", got)
	}
	old := time.Now().Add(-guardianstate.ReadyMaxAge - time.Minute)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	health := gateway.NewSidecarHealth()
	health.SetDaemonConfigLoaded(true)
	health.SetGuardianStateReader(reader)
	if got := health.Snapshot().Configuration.State; got != gateway.ConfigStateWaitingForTargets {
		t.Fatalf("stale ready collapsed to %q, want waiting_for_targets", got)
	}
	// The next publication by a live guardian restores ready.
	if _, err := writeEnterpriseHookGuardianReadinessState(dataDir, guardianstate.StateReady); err != nil {
		t.Fatal(err)
	}
	health.RefreshConfiguration()
	if got := health.Snapshot().Configuration.State; got != gateway.ConfigStateReady {
		t.Fatalf("re-published ready collapsed to %q, want ready", got)
	}
}

// TestGuardianWaitingWriteIsSilentWithoutAuthorizationDir pins that the
// startup/exit retraction does not warn when there is no authorization
// directory yet (nothing the gateway could read to retract), while a ready
// write still reports the missing directory.
func TestGuardianWaitingWriteIsSilentWithoutAuthorizationDir(t *testing.T) {
	stubGuardianReadinessTrust(t)
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, filepath.Join(t.TempDir(), "absent"))
	cfg = &config.Config{DataDir: t.TempDir()}
	enterpriseHookManifest = filepath.Join(t.TempDir(), "targets.yaml")
	var log bytes.Buffer
	writeGuardianStateOrLog(&log, guardianstate.StateWaitingForTargets)
	if log.Len() != 0 {
		t.Fatalf("waiting retraction without an authorization dir logged: %s", log.String())
	}
	writeGuardianStateOrLog(&log, guardianstate.StateReady)
	if !strings.Contains(log.String(), "does not exist yet") {
		t.Fatalf("ready write without an authorization dir did not warn: %q", log.String())
	}
}
