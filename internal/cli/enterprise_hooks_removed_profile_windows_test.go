// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows/registry"
)

// GAP-1657: a domain account whose profile an administrator removed keeps
// failing guardian rows until the enumerator's next pass. Status, verify and
// repair called it a signed-out account to remove with its profile, which was
// already done. A row whose home is gone and whose SID ProfileList no longer
// lists is a removed account's row; anything less is not proof.
func TestWindowsEnterpriseProfileRemovedNeedsTheHomeAndTheProfileListEntryGone(t *testing.T) {
	previous := enterpriseHookSIDProfilePath
	t.Cleanup(func() { enterpriseHookSIDProfilePath = previous })
	gone := filepath.Join(t.TempDir(), "dcad-r103-eng2")
	present := t.TempDir()
	const sid = "S-1-5-21-1111-2222-3333-1107"

	enterpriseHookSIDProfilePath = func(string) (string, error) { return "", registry.ErrNotExist }
	if !windowsEnterpriseProfileRemoved(sid, gone) {
		t.Fatal("a removed profile (home gone, no ProfileList entry) was not reported removed")
	}
	if windowsEnterpriseProfileRemoved(sid, present) {
		t.Fatal("a home that still exists was reported removed")
	}
	if windowsEnterpriseProfileRemoved("", gone) || windowsEnterpriseProfileRemoved(sid, "relative\\home") {
		t.Fatal("a row without a SID or with a relative home was reported removed")
	}
	enterpriseHookSIDProfilePath = func(string) (string, error) { return gone, nil }
	if windowsEnterpriseProfileRemoved(sid, gone) {
		t.Fatal("a SID ProfileList still lists was reported removed")
	}
	enterpriseHookSIDProfilePath = func(string) (string, error) { return "", errors.New("access is denied") }
	if windowsEnterpriseProfileRemoved(sid, gone) {
		t.Fatal("a ProfileList read failure was taken as proof the profile was removed")
	}
	if _, err := os.Lstat(gone); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fixture home %s exists", gone)
	}
}

func TestWindowsEnterpriseRemovedAccountRowCountsARemovedDomainProfile(t *testing.T) {
	previousCfg, previousPath, previousDeleted := cfg, enterpriseHookSIDProfilePath, windowsEnterpriseAccountDeleted
	t.Cleanup(func() {
		cfg, enterpriseHookSIDProfilePath, windowsEnterpriseAccountDeleted = previousCfg, previousPath, previousDeleted
	})
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}
	if !cfg.StandaloneEnterprise() {
		t.Fatal("test config is not standalone enterprise")
	}
	windowsEnterpriseAccountDeleted = func(string) bool { return false }
	enterpriseHookSIDProfilePath = func(string) (string, error) { return "", registry.ErrNotExist }
	removed := enterpriseHookReconcileRow{
		SID: "S-1-5-21-1111-2222-3333-1107", User: `DCLAB\dcad-r103-eng2`, Connector: "claudecode",
		UserHome: filepath.Join(t.TempDir(), "dcad-r103-eng2"),
		Error:    "enterprise hooks: protected target requires repair but its exact active Windows session is unavailable",
	}
	if !enterpriseHookRemovedAccountRow(removed) {
		t.Fatal("a removed domain profile's row was not counted removed")
	}
	if got := enterpriseHookSignedOutAccount(removed); got != "" {
		t.Fatalf("a removed profile's row was named a signed-out account: %q", got)
	}
	waiting := enterpriseHookReconcileRow{
		SID: "S-1-5-21-1111-2222-3333-1019", User: "dcw-std2", Connector: "hermes", UserHome: t.TempDir(),
		Error: enterpriseHookAwaitingSignInPrefix + ": its exact active Windows session is unavailable",
	}
	removedCount, awaiting := enterpriseHookExcusedFailures(enterpriseHookGuardianState{
		FailureCount: 2, Results: []enterpriseHookReconcileRow{removed, waiting},
	})
	if removedCount != 1 || awaiting != 1 {
		t.Fatalf("excused = %d removed, %d awaiting; want 1 and 1 (a removed profile next to a signed-out account)", removedCount, awaiting)
	}
	signedOut := removed
	signedOut.UserHome = t.TempDir()
	if enterpriseHookRemovedAccountRow(signedOut) {
		t.Fatal("a signed-out account whose home exists was counted removed")
	}
}
