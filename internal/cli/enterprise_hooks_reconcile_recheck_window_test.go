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

	var start time.Time
	enterpriseHookReconcileVerifier = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		if opts.ConnectorName == "hermes" && time.Since(start) >= 100*time.Millisecond {
			return enterprisehooks.InstallResult{}, errors.New("hermes hooks block is empty")
		}
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}
	var repairedAt time.Duration
	installs := []string{}
	enterpriseHookReconcileInstaller = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		repairedAt = time.Since(start)
		installs = append(installs, opts.ConnectorName)
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}
	enterpriseHookReconcileRecheckWindow = 300 * time.Millisecond
	start = time.Now()
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	took := time.Since(start)
	if err != nil || run.Failures != 0 || run.Repairs != 1 || strings.Join(installs, ",") != "hermes" {
		t.Fatalf("run=%+v installs=%v err=%v, want the one Hermes repair", run, installs, err)
	}
	if _, ok := guardianRestoresForTest(t, dataDir)[enterpriseHookGuardianRestoreKey(sid, "hermes")]; !ok {
		t.Fatalf("the Hermes repair inside the window was not recorded as a restore")
	}
	if repairedAt > 400*time.Millisecond || took > 1500*time.Millisecond {
		t.Fatalf("the sixth target, damaged 100 ms in, was repaired %s in and the pass took %s; want one shared 300 ms window", repairedAt, took)
	}
}
