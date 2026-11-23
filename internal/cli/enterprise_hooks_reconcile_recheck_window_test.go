// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// The in-process reconcile (the Windows guardian, all users' targets in
// one loop) shares one window per pass the same way. This file has no build
// tag so the native Windows run covers the path the Windows guardian runs
// (GAP-1873).
func TestEnterpriseHookReconcileRecheckWindowIsSharedByAllTargets(t *testing.T) {
	restoreEnterpriseHooksLifecycleTestState(t)
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	stubEnterpriseHookTokenSources(t)
	enableEnterpriseHookGuardianRestores(t, true)
	previousManifest, previousAPI, previousProxy := enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr
	previousVerifier, previousInstaller := enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller
	previousSession, previousCleanup := enterpriseHookReconcileSessionAvailable, enterpriseForeignHookCleanup
	previousWindow := enterpriseHookReconcileRecheckWindow
	t.Cleanup(func() {
		enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = previousManifest, previousAPI, previousProxy
		enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller = previousVerifier, previousInstaller
		enterpriseHookReconcileSessionAvailable, enterpriseForeignHookCleanup = previousSession, previousCleanup
		enterpriseHookReconcileRecheckWindow = previousWindow
	})
	enterpriseForeignHookCleanup = func(enterprisehooks.TargetCredentials, string, string) (enterprisepolicy.CleanupResult, error) {
		return enterprisepolicy.CleanupResult{}, nil
	}
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return true, nil }

	scope := t.TempDir()
	dataDir := filepath.Join(scope, "runtime")
	home := filepath.Join(scope, "home")
	for _, dir := range []string{dataDir, home} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(scope, "authorization"))
	const sid = "S-1-5-21-1-2-3-1001"
	connectors := []string{"amp", "claudecode", "codex", "cursor", "devin", "hermes"}
	windowsVersions := map[string]string{"amp": "1.0.0", "claudecode": "2.1.187", "codex": "0.200.0", "cursor": "1.7.0", "devin": "1.0.0", "hermes": "0.21.5"}
	manifest := "version: 1\ntargets:\n"
	protected := []enterpriseHookReconcileRow{}
	for _, name := range connectors {
		manifest += fmt.Sprintf("  - user_home: %q\n", home)
		if runtime.GOOS == "windows" {
			// A Windows target names its account by SID and carries the
			// agent version the enumerator found (Windows minimums apply).
			manifest += fmt.Sprintf("    agent_version: %s\n", windowsVersions[name])
		} else {
			manifest += fmt.Sprintf("    uid: %d\n    gid: %d\n", os.Getuid(), os.Getgid())
		}
		manifest += fmt.Sprintf("    sid: %s\n    connector: %s\n", sid, name)
		protected = append(protected, enterpriseHookReconcileRow{UserHome: home, SID: sid, Connector: name, OK: true})
	}
	manifestPath := filepath.Join(scope, "targets.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	_, manifestSHA256, err := enterprisehooks.LoadManifestWithSHA256(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg = &config.Config{DataDir: dataDir, DeploymentMode: "local"}
	enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = manifestPath, "127.0.0.1:18970", "127.0.0.1:4000"
	if err := writeEnterpriseHookGuardianState(dataDir, manifestPath, manifestSHA256, protected, 0, true); err != nil {
		t.Fatal(err)
	}

	// The repair bound is relative to the target's own first check, never to
	// the start of the pass: a loaded host (the full native Windows run) takes
	// an unbounded time to verify the first targets, and that time is not the
	// window under test. The window is wide enough that a window per target in
	// turn (5 x window between the first and the last first check, or five
	// windows of late repair) cannot pass for a shared one: a loaded host was
	// seen to take 1.4 s over the first five targets, the bound is 3 windows.
	const (
		window      = 1000 * time.Millisecond
		damageAfter = 200 * time.Millisecond
	)
	firstCheck := map[string]time.Time{}
	calls := []string{}
	enterpriseHookReconcileVerifier = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		now := time.Now()
		calls = append(calls, opts.ConnectorName)
		first, seen := firstCheck[opts.ConnectorName]
		if !seen {
			firstCheck[opts.ConnectorName], first = now, now
		}
		if opts.ConnectorName == "hermes" && now.Sub(first) >= damageAfter {
			return enterprisehooks.InstallResult{}, errors.New("hermes hooks block is empty")
		}
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}
	var repairedAt time.Time
	installs := []string{}
	enterpriseHookReconcileInstaller = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		repairedAt = time.Now()
		installs = append(installs, opts.ConnectorName)
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}
	enterpriseHookReconcileRecheckWindow = window
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	finished := time.Now()
	if err != nil || run.Failures != 0 || run.Repairs != 1 || strings.Join(installs, ",") != "hermes" {
		t.Fatalf("run=%+v installs=%v err=%v, want the one Hermes repair", run, installs, err)
	}
	if _, ok := guardianRestoresForTest(t, dataDir)[enterpriseHookGuardianRestoreKey(sid, "hermes")]; !ok {
		t.Fatalf("the Hermes repair inside the window was not recorded as a restore")
	}
	var firstFirst, lastFirst time.Time
	for _, at := range firstCheck {
		if firstFirst.IsZero() || at.Before(firstFirst) {
			firstFirst = at
		}
		if at.After(lastFirst) {
			lastFirst = at
		}
	}
	// Every first check comes before any recheck: the loop only verifies, the
	// shared window then rechecks all of them together.
	if len(calls) < len(connectors) {
		t.Fatalf("verified %v, want every target checked once", calls)
	}
	seenFirst := map[string]bool{}
	for i, name := range calls[:len(connectors)] {
		if seenFirst[name] {
			t.Fatalf("target %s was verified again (call %d of %v) before every target had its first check", name, i+1, calls)
		}
		seenFirst[name] = true
	}
	// The first checks are not spread over a window per target: waiting a
	// window after each target in turn puts the last first check 5 windows
	// after the first, and no load on a host does that.
	if spread := lastFirst.Sub(firstFirst); spread > 3*window {
		t.Fatalf("the first checks of the %d targets were spread over %s; want one shared %s window, not a window per target", len(connectors), spread, window)
	}
	// Shared window: hermes (the sixth target) is repaired about damageAfter
	// plus one recheck step after its own first check, and the pass ends one
	// window after the last first check. A window per target in turn after the
	// loop would repair it five windows late.
	if repaired := repairedAt.Sub(firstCheck["hermes"]); repaired > 2*window {
		t.Fatalf("the sixth target, damaged %s after its first check, was repaired %s after it; want one shared %s window", damageAfter, repaired, window)
	}
	if tail := finished.Sub(lastFirst); tail > 3*window {
		t.Fatalf("the pass ended %s after its last first check; want one shared %s window", tail, window)
	}
}
