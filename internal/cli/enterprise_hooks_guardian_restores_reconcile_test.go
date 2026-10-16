// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// GAP-0440: a reconcile that puts back the hooks of a target that verified
// before (a standard user emptied the Hermes hooks block) records when it
// did; the first install of a target and a pass whose targets still verify
// record nothing. The Windows guardian's reconcile is this loop; the
// platform calls it makes are stubbed here.
func TestEnterpriseHookReconcileRecordsTheTargetsItRestored(t *testing.T) {
	restoreEnterpriseHooksLifecycleTestState(t)
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	stubEnterpriseHookTokenSources(t)
	enableEnterpriseHookGuardianRestores(t, true)
	previousManifest, previousAPI, previousProxy := enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr
	previousVerifier, previousInstaller := enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller
	previousSession, previousCleanup := enterpriseHookReconcileSessionAvailable, enterpriseForeignHookCleanup
	t.Cleanup(func() {
		enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = previousManifest, previousAPI, previousProxy
		enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller = previousVerifier, previousInstaller
		enterpriseHookReconcileSessionAvailable, enterpriseForeignHookCleanup = previousSession, previousCleanup
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
	manifestPath := filepath.Join(scope, "targets.yaml")
	manifest := fmt.Sprintf("version: 1\ntargets:\n"+
		"  - user_home: %[1]q\n    uid: %[2]d\n    gid: %[3]d\n    sid: %[4]s\n    connector: hermes\n"+
		"  - user_home: %[1]q\n    uid: %[2]d\n    gid: %[3]d\n    sid: %[4]s\n    connector: codex\n",
		home, os.Getuid(), os.Getgid(), sid)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	_, manifestSHA256, err := enterprisehooks.LoadManifestWithSHA256(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg = &config.Config{DataDir: dataDir, DeploymentMode: "local"}
	enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = manifestPath, "127.0.0.1:18970", "127.0.0.1:4000"
	// The Hermes target was protected by an earlier pass; Codex is new.
	if err := writeEnterpriseHookGuardianState(dataDir, manifestPath, manifestSHA256, []enterpriseHookReconcileRow{
		{UserHome: home, SID: sid, Connector: "hermes", OK: true},
	}, 0, true); err != nil {
		t.Fatal(err)
	}

	hermesTampered := true
	enterpriseHookReconcileVerifier = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		if opts.ConnectorName == "hermes" && hermesTampered {
			return enterprisehooks.InstallResult{}, errors.New("hermes hooks block is empty")
		}
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}
	installs := []string{}
	enterpriseHookReconcileInstaller = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		installs = append(installs, opts.ConnectorName)
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}

	before := time.Now()
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	after := time.Now()
	if err != nil || run.Failures != 0 || run.Repairs != 1 || strings.Join(installs, ",") != "hermes,codex" {
		t.Fatalf("first pass: run=%+v installs=%v err=%v, want the Hermes repair and the Codex install", run, installs, err)
	}
	restores := guardianRestoresForTest(t, dataDir)
	restoredAt, ok := restores[enterpriseHookGuardianRestoreKey(sid, "hermes")]
	if len(restores) != 1 || !ok || restoredAt.Before(before) || restoredAt.After(after) {
		t.Fatalf("restores = %v, want only Hermes of %s between %s and %s", restores, sid, before, after)
	}

	// Both targets verify now: nothing is restored and the record keeps the
	// Hermes restore.
	hermesTampered = false
	installs = installs[:0]
	run, err = runEnterpriseHookReconcileOnce(context.Background())
	if err != nil || run.Failures != 0 || run.Repairs != 0 || len(installs) != 0 {
		t.Fatalf("second pass: run=%+v installs=%v err=%v, want no change", run, installs, err)
	}
	if again := guardianRestoresForTest(t, dataDir); len(again) != 1 ||
		!again[enterpriseHookGuardianRestoreKey(sid, "hermes")].Equal(restoredAt) {
		t.Fatalf("restores after a clean pass = %v, want the Hermes restore at %s", again, restoredAt)
	}
}
