// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-2133 (split from GAP-1800 (b), RV-1733c): the enrolled-accounts record
// dropped an account whose guardian row was marked removed. A removed
// profile (home gone, no ProfileList entry) marks the row removed for any
// account (GAP-1657). An FSLogix-style profile disk that is detached, with
// the local profile cleaned up, therefore looked like a removed profile, and
// the account left the record. Its next sign-in, with a per-user DefenseClaw
// entry planted in the managed folder, then read as a first adoption and was
// skipped. The record now drops only a deleted (local) account; a domain
// account whose profile disk is gone stays enrolled.
//
// The profile disk is simulated by a junction at the profile path that goes
// away (FSLogix mounts the container at the profile folder); the SID is a
// domain SID with no ProfileList entry and no account on this computer.
func TestGAP2133AnAccountWhoseProfileDiskIsGoneStaysEnrolled(t *testing.T) {
	gap1800TrustAll(t)
	previousOwner := enterpriseHookAuthorizationOwnershipSetter
	t.Cleanup(func() { enterpriseHookAuthorizationOwnershipSetter = previousOwner })
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	dataDir := t.TempDir()
	authorizationDir := managed.HookGuardianAuthorizationDir(dataDir)
	if err := os.MkdirAll(authorizationDir, 0o700); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	disk := filepath.Join(root, "ProfileDisk", "alice")
	home := filepath.Join(root, "Users", "alice")
	for _, dir := range []string{disk, filepath.Dir(home)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", home, disk).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v %s", err, out)
	}
	const domainSID = "S-1-5-21-1111111111-2222222222-3333333333-71105"
	if windowsEnterpriseProfileRemoved(domainSID, home) {
		t.Fatal("fixture: a mounted profile disk reads as a removed profile")
	}
	// The profile disk is detached: the folder at the profile path is gone.
	if out, err := exec.Command("cmd", "/c", "rmdir", home).CombinedOutput(); err != nil {
		t.Fatalf("rmdir junction: %v %s", err, out)
	}
	if !windowsEnterpriseProfileRemoved(domainSID, home) {
		t.Fatal("fixture: the gone rule does not fire for the detached profile disk")
	}
	if windowsEnterpriseAccountDeleted(domainSID) {
		t.Fatal("fixture: a domain account is never read as deleted")
	}

	alice := enterpriseHookReconcileRow{SID: domainSID, UserHome: home, Connector: "hermes"}
	if err := recordEnterpriseHookEnrolledAccounts(authorizationDir, "t1", nil, []enterpriseHookReconcileRow{alice}, nil); err != nil {
		t.Fatal(err)
	}
	gone := alice
	gone.Removed = true
	if err := recordEnterpriseHookEnrolledAccounts(authorizationDir, "t2", []enterpriseHookReconcileRow{alice}, nil, []enterpriseHookReconcileRow{gone}); err != nil {
		t.Fatal(err)
	}
	recorded, err := loadEnterpriseHookEnrolledAccounts(authorizationDir)
	if err != nil {
		t.Fatal(err)
	}
	if !recorded[enterpriseHookEnrolledAccountKey(domainSID)] {
		t.Fatal("GAP-2133: the account whose profile disk is gone left the enrolled-accounts record on the pass that marked its row removed")
	}
	// Without previous, the record itself must keep her too.
	if err := recordEnterpriseHookEnrolledAccounts(authorizationDir, "t3", nil, nil, []enterpriseHookReconcileRow{gone}); err != nil {
		t.Fatal(err)
	}
	recorded, err = loadEnterpriseHookEnrolledAccounts(authorizationDir)
	if err != nil {
		t.Fatal(err)
	}
	if !recorded[enterpriseHookEnrolledAccountKey(domainSID)] {
		t.Fatal("GAP-2133: the account whose profile disk is gone left the enrolled-accounts record")
	}

	// A deleted local account still leaves it.
	previous := windowsEnterpriseAccountDeleted
	t.Cleanup(func() { windowsEnterpriseAccountDeleted = previous })
	windowsEnterpriseAccountDeleted = func(sid string) bool { return sid == domainSID }
	if err := recordEnterpriseHookEnrolledAccounts(authorizationDir, "t4", nil, nil, []enterpriseHookReconcileRow{gone}); err != nil {
		t.Fatal(err)
	}
	recorded, err = loadEnterpriseHookEnrolledAccounts(authorizationDir)
	if err != nil {
		t.Fatal(err)
	}
	if recorded[enterpriseHookEnrolledAccountKey(domainSID)] {
		t.Fatal("a deleted account stayed in the enrolled-accounts record")
	}
}
