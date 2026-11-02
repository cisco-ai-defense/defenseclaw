//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedTestLayout pins a managed layout under a temp home and lets the
// unprivileged test process repair it, stamping the test user.
func managedTestLayout(t *testing.T) managed.ManagedServiceLayout {
	t.Helper()
	home := t.TempDir()
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv(managed.ConfigPathEnv, filepath.Join(home, "etc", "config.yaml"))
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, filepath.Join(home, "hook-guardian-state"))
	t.Cleanup(managed.OverrideSelfRepairForTesting(managed.UnixOwnership{
		UID: uint32(os.Getuid()), GID: uint32(os.Getgid()),
	}))
	layout, ok := managed.PinnedManagedServiceLayout()
	if !ok {
		t.Fatal("managed layout not derived")
	}
	return layout
}

func captureMarkers(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var lines []string
	previous := managed.ReportResilienceEvent
	managed.ReportResilienceEvent = func(marker string, fields map[string]string) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, managed.FormatResilienceEvent(marker, fields))
	}
	t.Cleanup(func() { managed.ReportResilienceEvent = previous })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
}

func countMarker(lines []string, marker string) int {
	count := 0
	for _, line := range lines {
		if strings.HasPrefix(line, marker+" ") {
			count++
		}
	}
	return count
}

func mkdirMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func writeMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func chflags(t *testing.T, flags, path string) {
	t.Helper()
	if output, err := exec.Command("/usr/bin/chflags", flags, path).CombinedOutput(); err != nil {
		t.Fatalf("chflags %s %s: %v: %s", flags, path, err, output)
	}
	t.Cleanup(func() { _ = exec.Command("/usr/bin/chflags", "nouchg,nouappnd", path).Run() })
}

func addACL(t *testing.T, path, entry string) {
	t.Helper()
	if output, err := exec.Command("/bin/chmod", "+a", entry, path).CombinedOutput(); err != nil {
		t.Fatalf("chmod +a: %v: %s", err, output)
	}
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// buildDriftedManagedTree lays out the managed machine objects with drift on
// each: group and other write, an untrusted write ACL and write-blocking
// flags.
func buildDriftedManagedTree(t *testing.T, layout managed.ManagedServiceLayout) {
	t.Helper()
	mkdirMode(t, filepath.Dir(layout.ConfigPath), 0o777)
	writeMode(t, layout.ConfigPath, 0o666)
	addACL(t, layout.ConfigPath, "everyone allow write")
	mkdirMode(t, layout.RuntimeDir, 0o777)
	chflags(t, "uchg", layout.RuntimeDir)
	mkdirMode(t, layout.ManifestDir, 0o775)
	writeMode(t, layout.ManifestPath, 0o664)
	chflags(t, "uappnd", layout.ManifestPath)
	mkdirMode(t, layout.AuthorizationDir, 0o777)
	writeMode(t, filepath.Join(layout.AuthorizationDir, hookGuardianAuthorizationFile), 0o666)
}

func TestGuardianPreConfigStepRepairsManagedObjects(t *testing.T) {
	layout := managedTestLayout(t)
	markers := captureMarkers(t)
	buildDriftedManagedTree(t, layout)

	repairManagedServicePathsBeforeConfigLoadPlatform(managedServiceGuardian)

	want := map[string]os.FileMode{
		filepath.Dir(layout.ConfigPath): 0o755,
		layout.ConfigPath:               0o640,
		layout.RuntimeDir:               0o750,
		layout.ManifestDir:              0o755,
		layout.ManifestPath:             0o640,
		layout.AuthorizationDir:         0o750,
		filepath.Join(layout.AuthorizationDir, hookGuardianAuthorizationFile): 0o640,
	}
	for path, mode := range want {
		if got := modeOf(t, path); got != mode {
			t.Errorf("%s mode = %04o, want %04o", path, got, mode)
		}
		result, _ := managed.AssessCanonical(path, managedKindForTest(path, layout), managed.CanonicalOptions{
			UnixOwner: &managed.UnixOwnership{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())},
			UnixMode:  mode,
		})
		if result.Outcome != managed.CanonicalOK {
			t.Errorf("%s still drifted: %v", path, result.Drift)
		}
	}
	if got := countMarker(markers(), managed.MarkerRepair); got < len(want) {
		t.Fatalf("repair markers = %d, want at least %d: %q", got, len(want), markers())
	}
}

func managedKindForTest(path string, layout managed.ManagedServiceLayout) managed.ObjectKind {
	switch path {
	case filepath.Dir(layout.ConfigPath):
		return managed.ObjectConfigDirectory
	case layout.ConfigPath:
		return managed.ObjectConfigFile
	case layout.RuntimeDir:
		return managed.ObjectRuntimeDirectory
	case layout.ManifestDir:
		return managed.ObjectAdminDirectory
	case layout.AuthorizationDir:
		return managed.ObjectAuthorizationDirectory
	}
	return managed.ObjectAdminFile
}

func TestGuardianPreConfigStepNeverFollowsStructure(t *testing.T) {
	layout := managedTestLayout(t)
	markers := captureMarkers(t)
	outside := t.TempDir()
	victim := filepath.Join(outside, "targets.yaml")
	writeMode(t, victim, 0o666)
	mkdirMode(t, filepath.Dir(layout.ConfigPath), 0o755)
	writeMode(t, layout.ConfigPath, 0o640)
	mkdirMode(t, layout.RuntimeDir, 0o750)
	if err := os.Symlink(outside, layout.ManifestDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.AuthorizationDir, []byte("not a folder"), 0o600); err != nil {
		t.Fatal(err)
	}

	repairManagedServicePathsBeforeConfigLoadPlatform(managedServiceGuardian)

	if got := modeOf(t, victim); got != 0o666 {
		t.Fatalf("symlink target was re-stamped to %04o", got)
	}
	for _, dir := range []string{layout.ManifestDir, layout.AuthorizationDir} {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("%s was not recreated as a folder: %v %v", dir, info, err)
		}
		moved, _ := filepath.Glob(dir + ".defenseclaw-moved-*")
		if len(moved) != 1 {
			t.Fatalf("%s moved-aside entries = %v", dir, moved)
		}
	}
	if countMarker(markers(), managed.MarkerBoundary) < 2 {
		t.Fatalf("markers = %q, want boundary lines", markers())
	}
}

// The guardian's startup survives drift on config.yaml and data_dir: the
// pre-config step repairs them before the first load, and a load that still
// fails is retried in process instead of exiting.
func TestGuardianStartupSurvivesConfigAndDataDirDrift(t *testing.T) {
	layout := managedTestLayout(t)
	markers := captureMarkers(t)
	buildDriftedManagedTree(t, layout)
	previous := managedServiceConfigLoader
	t.Cleanup(func() { managedServiceConfigLoader = previous })
	loads := 0
	managedServiceConfigLoader = func(path string) (*config.Config, *observabilityV8Startup, error) {
		loads++
		if modeOf(t, path)&0o022 != 0 || modeOf(t, layout.RuntimeDir)&0o022 != 0 {
			return nil, nil, fmt.Errorf("config: managed_enterprise config trust check failed: %s", path)
		}
		return &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, DataDir: layout.RuntimeDir}, nil, nil
	}
	loaded, _, err := loadGatewayConfigV8ForService(context.Background(), layout.ConfigPath, managedServiceGuardian)
	if err != nil || loaded == nil {
		t.Fatalf("guardian config load failed after repair: %v", err)
	}
	if loads != 1 {
		t.Fatalf("loads = %d, want the first load to pass after the pre-config repair", loads)
	}
	if countMarker(markers(), managed.MarkerDegraded) != 0 {
		t.Fatalf("markers = %q, want no degraded start", markers())
	}
}

func TestManagedServiceConfigLoadRetriesInsteadOfExiting(t *testing.T) {
	layout := managedTestLayout(t)
	markers := captureMarkers(t)
	previousLoader := managedServiceConfigLoader
	previousInitial, previousMax := managedConfigRetryInitialDelay, managedConfigRetryMaxDelay
	t.Cleanup(func() {
		managedServiceConfigLoader = previousLoader
		managedConfigRetryInitialDelay, managedConfigRetryMaxDelay = previousInitial, previousMax
	})
	managedConfigRetryInitialDelay, managedConfigRetryMaxDelay = time.Millisecond, 2*time.Millisecond
	loads := 0
	managedServiceConfigLoader = func(string) (*config.Config, *observabilityV8Startup, error) {
		loads++
		if loads < 4 {
			return nil, nil, errors.New("config: symlinks are not allowed in managed config path")
		}
		return &config.Config{}, nil, nil
	}
	if _, _, err := loadGatewayConfigV8ForService(context.Background(), layout.ConfigPath, managedServiceGuardian); err != nil {
		t.Fatalf("service exited instead of retrying: %v", err)
	}
	lines := markers()
	if countMarker(lines, managed.MarkerDegraded) != 1 {
		t.Fatalf("markers = %q, want one degraded line for the streak", lines)
	}
	recovered := 0
	for _, line := range lines {
		if strings.HasPrefix(line, managed.MarkerRepair+" ") && strings.Contains(line, `reason="config loaded after a degraded start"`) {
			recovered++
		}
	}
	if recovered != 1 {
		t.Fatalf("markers = %q, want one recovery line", lines)
	}

	// A command that is not a managed service still fails fast.
	loads = 0
	if _, _, err := loadGatewayConfigV8ForService(context.Background(), layout.ConfigPath, managedServiceNone); err == nil || loads != 1 {
		t.Fatalf("non-service load err = %v after %d loads, want one failing load", err, loads)
	}
}

func TestManagedServiceConfigLoadStopsOnCancel(t *testing.T) {
	layout := managedTestLayout(t)
	captureMarkers(t)
	previousLoader := managedServiceConfigLoader
	t.Cleanup(func() { managedServiceConfigLoader = previousLoader })
	managedServiceConfigLoader = func(string) (*config.Config, *observabilityV8Startup, error) {
		return nil, nil, errors.New("config: parse failure")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := loadGatewayConfigV8ForService(ctx, layout.ConfigPath, managedServiceGateway); err == nil {
		t.Fatal("cancelled retry returned no error")
	}
}

func TestDarwinGuardianLedgerRepairRestampsDrift(t *testing.T) {
	layout := managedTestLayout(t)
	markers := captureMarkers(t)
	mkdirMode(t, layout.RuntimeDir, 0o750)
	mkdirMode(t, layout.AuthorizationDir, 0o777)
	authorization := filepath.Join(layout.AuthorizationDir, hookGuardianAuthorizationFile)
	writeMode(t, authorization, 0o666)
	chflags(t, "uchg", authorization)

	previousDir, previousFile := enterpriseHookAuthorizationDirTrustCheck, enterpriseHookAuthorizationFileTrustCheck
	t.Cleanup(func() {
		enterpriseHookAuthorizationDirTrustCheck, enterpriseHookAuthorizationFileTrustCheck = previousDir, previousFile
	})
	modeCheck := func(path string) error {
		if modeOf(t, path)&0o022 != 0 {
			return errors.New("group/other writable")
		}
		return nil
	}
	enterpriseHookAuthorizationDirTrustCheck = modeCheck
	enterpriseHookAuthorizationFileTrustCheck = modeCheck

	if err := repairEnterpriseHookGuardianLedger(layout.RuntimeDir); err != nil {
		t.Fatalf("ledger repair: %v", err)
	}
	if modeOf(t, layout.AuthorizationDir) != 0o750 || modeOf(t, authorization) != 0o640 {
		t.Fatalf("modes = %04o %04o", modeOf(t, layout.AuthorizationDir), modeOf(t, authorization))
	}
	if countMarker(markers(), managed.MarkerRepair) < 2 {
		t.Fatalf("markers = %q", markers())
	}
}

func TestDarwinLedgerRepairRefusesPathsOutsideTheManagedHome(t *testing.T) {
	managedTestLayout(t)
	captureMarkers(t)
	outside := filepath.Join(t.TempDir(), "authorization.json")
	writeMode(t, outside, 0o666)
	if err := repairEnterpriseHookGuardianLedgerObjectPlatform(outside, false); err == nil {
		t.Fatal("a path outside the managed home was repaired")
	}
	if got := modeOf(t, outside); got != 0o666 {
		t.Fatalf("outside path re-stamped to %04o", got)
	}
}

func TestDarwinScopedTokenRepairedBeforeMint(t *testing.T) {
	layout := managedTestLayout(t)
	markers := captureMarkers(t)
	mkdirMode(t, layout.RuntimeDir, 0o777)
	hooks := filepath.Join(layout.RuntimeDir, "hooks")
	mkdirMode(t, hooks, 0o777)
	token, err := connector.HookAPITokenFilePath(layout.RuntimeDir, "codex")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(token, 0o644); err != nil {
		t.Fatal(err)
	}
	chflags(t, "uchg", token)

	if err := validateEnterpriseHookScopedTokenLocation(layout.RuntimeDir, "codex"); err != nil {
		t.Fatalf("token location still refused after repair: %v", err)
	}
	if modeOf(t, layout.RuntimeDir) != 0o750 || modeOf(t, hooks) != 0o700 || modeOf(t, token) != 0o600 {
		t.Fatalf("modes = %04o %04o %04o", modeOf(t, layout.RuntimeDir), modeOf(t, hooks), modeOf(t, token))
	}
	if countMarker(markers(), managed.MarkerRepair) != 3 {
		t.Fatalf("markers = %q, want three repair lines", markers())
	}
	if uid, gid := enterpriseHookTokenOwnerPlatform(nil); uid != 0 || gid != 0 {
		t.Fatalf("token owner = %d:%d, want root:wheel", uid, gid)
	}
}

func TestDarwinScopedTokenSymlinkMovedAsideNeverFollowed(t *testing.T) {
	layout := managedTestLayout(t)
	markers := captureMarkers(t)
	mkdirMode(t, layout.RuntimeDir, 0o750)
	hooks := filepath.Join(layout.RuntimeDir, "hooks")
	mkdirMode(t, hooks, 0o700)
	victim := filepath.Join(t.TempDir(), "victim")
	writeMode(t, victim, 0o666)
	token, _ := connector.HookAPITokenFilePath(layout.RuntimeDir, "codex")
	if err := os.Symlink(victim, token); err != nil {
		t.Fatal(err)
	}
	if err := validateEnterpriseHookScopedTokenLocation(layout.RuntimeDir, "codex"); err != nil {
		t.Fatalf("location refused after the symlink was moved aside: %v", err)
	}
	if modeOf(t, victim) != 0o666 {
		t.Fatal("symlink target was re-stamped")
	}
	if _, err := os.Lstat(token); !os.IsNotExist(err) {
		t.Fatalf("symlinked token still in place: %v", err)
	}
	if countMarker(markers(), managed.MarkerBoundary) < 1 {
		t.Fatalf("markers = %q", markers())
	}
}

func TestGatewayRuntimeRepairBeforeStoresOpen(t *testing.T) {
	layout := managedTestLayout(t)
	markers := captureMarkers(t)
	mkdirMode(t, layout.RuntimeDir, 0o750)
	audit := filepath.Join(layout.RuntimeDir, "audit.db")
	writeMode(t, audit, 0o664)
	chflags(t, "uchg", audit)
	wal := audit + "-wal"
	writeMode(t, wal, 0o666)
	key := filepath.Join(layout.RuntimeDir, "redaction-correlation.key")
	writeMode(t, key, 0o640)
	addACL(t, key, "everyone allow read")
	dotenv := filepath.Join(layout.RuntimeDir, ".env")
	writeMode(t, dotenv, 0o644)
	judge := filepath.Join(layout.RuntimeDir, "judge_bodies.db")
	other := filepath.Join(t.TempDir(), "judge-link")
	writeMode(t, judge, 0o600)
	if err := os.Link(judge, other); err != nil {
		t.Fatal(err)
	}

	repairGatewayRuntimePlatform(&config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		DataDir:        layout.RuntimeDir,
		AuditDB:        audit,
		JudgeBodiesDB:  judge,
	})
	for path, mode := range map[string]os.FileMode{audit: 0o600, wal: 0o600, key: 0o600, dotenv: 0o600} {
		if got := modeOf(t, path); got != mode {
			t.Errorf("%s mode = %04o, want %04o", path, got, mode)
		}
	}
	if _, err := os.Lstat(judge); !os.IsNotExist(err) {
		t.Fatalf("hard-linked judge store still in place: %v", err)
	}
	if data, err := os.ReadFile(other); err != nil || string(data) != "x" {
		t.Fatalf("the other hard link changed: %q %v", data, err)
	}
	if countMarker(markers(), managed.MarkerBoundary) < 1 {
		t.Fatalf("markers = %q", markers())
	}
}

func TestDarwinEnvConfigOnlyLosesGroupAndOtherWrite(t *testing.T) {
	managedTestLayout(t)
	markers := captureMarkers(t)
	path := filepath.Join(t.TempDir(), "env_config.json")
	writeMode(t, path, 0o666)
	repairManagedEnvConfig(path)
	if got := modeOf(t, path); got != 0o644 {
		t.Fatalf("mode = %04o, want 0644", got)
	}
	if countMarker(markers(), managed.MarkerRepair) != 1 {
		t.Fatalf("markers = %q", markers())
	}
	link := filepath.Join(t.TempDir(), "env_config.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	repairManagedEnvConfig(link)
	repairManagedEnvConfig(link)
	if countMarker(markers(), managed.MarkerBoundary) != 1 {
		t.Fatalf("markers = %q, want one boundary line for the symlink", markers())
	}
}
