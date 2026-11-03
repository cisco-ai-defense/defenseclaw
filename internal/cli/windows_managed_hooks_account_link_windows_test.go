// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestWindowsManagedHooksTeardownKeepsAccountLinkScoped(t *testing.T) {
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	oldStateTrust, oldOwnership := enterpriseHookGuardianStateFileTrustCheck, enterpriseHookAuthorizationOwnershipSetter
	oldCfg, oldLink := cfg, enterpriseHookAccountOwnedDataDirLink
	t.Cleanup(func() {
		enterpriseHookGuardianStateFileTrustCheck, enterpriseHookAuthorizationOwnershipSetter = oldStateTrust, oldOwnership
		cfg, enterpriseHookAccountOwnedDataDirLink = oldCfg, oldLink
	})
	enterpriseHookGuardianStateFileTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	// The hidden teardown command skips config loading and uses the protected
	// process profile pin instead.
	cfg = nil
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	scope := t.TempDir()
	runtimeDir := filepath.Join(scope, "runtime")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(scope, "authorization"))
	manifestPath := filepath.Join(scope, "targets.yaml")
	digest := strings.Repeat("a", 64)
	home := filepath.Join(scope, "alice")
	const sid = "S-1-5-21-1-2-3-1001"
	linked := true
	enterpriseHookAccountOwnedDataDirLink = func(gotHome, gotSID string) bool {
		return linked && gotHome == home && gotSID == sid
	}
	targets := []windowsManagedHooksTeardownTarget{
		{Connector: "claudecode", SID: sid, DataDir: filepath.Join(home, ".defenseclaw")},
		{Connector: "codex", SID: "S-1-5-21-1-2-3-1002", DataDir: filepath.Join(scope, "bob", ".defenseclaw"), Deferred: true},
	}
	protected := []enterpriseHookReconcileRow{
		{Connector: "claudecode", SID: sid, UserHome: home, OK: true},
		{Connector: "codex", SID: targets[1].SID, UserHome: filepath.Dir(targets[1].DataDir), OK: true},
	}
	if err := writeEnterpriseHookGuardianState(runtimeDir, manifestPath, digest, protected, 0, true); err != nil {
		t.Fatal(err)
	}
	failing := append([]enterpriseHookReconcileRow(nil), protected...)
	failing[0].OK = false
	failing[0].Error = enterpriseHookAccountLinkFailure
	if err := writeEnterpriseHookGuardianState(runtimeDir, manifestPath, digest, failing, 1, true); err != nil {
		t.Fatal(err)
	}
	check := func() error {
		_, err := windowsManagedHooksPendingTargetsFromGuardian(runtimeDir, manifestPath, digest, targets)
		return err
	}
	if err := check(); err != nil {
		t.Fatalf("account link blocked teardown of the machine: %v", err)
	}
	linked = false
	if err := check(); err == nil {
		t.Fatal("a link that no longer belongs to the account passed teardown")
	}
	linked = true
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileSecureClient)
	if err := check(); err == nil {
		t.Fatal("Secure Client accepted the standalone account-link case")
	}
}
