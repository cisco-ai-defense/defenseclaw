//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsAccountOwnedRootDataDirLinkExcludesChildLink(t *testing.T) {
	target := deferredPendingProofFixture(t, true)
	sid := currentWindowsTestSID(t)
	dataDir := filepath.Join(target.UserHome, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside, canary := outsideDataDirTree(t, target.UserHome)
	plantWindowsAccountJunction(t, filepath.Join(dataDir, "hooks"), outside, sid)
	if !WindowsAccountOwnedDataDirLink(target.UserHome, sid.String()) ||
		WindowsAccountOwnedRootDataDirLink(target.UserHome, sid.String()) {
		t.Fatal("a child link was classified as a root link")
	}
	requireOutsideDataDirTreeUnchanged(t, outside, canary)
}

func planValidationRootsForTarget(target ManifestTarget) (WindowsManagedRuntimePlan, error) {
	return PlanWindowsManagedRuntimeRootsForValidation(
		Manifest{Version: 1, Targets: []ManifestTarget{target}},
		`C:\ProgramData\DefenseClaw\etc\targets.yaml`,
		strings.Repeat("a", 64),
	)
}

// A signed-out account whose .defenseclaw is a junction it made itself failed
// its deferred row, and the Upgrade/Repair plan refused that profile and
// rolled back the lifecycle for every account (GAP-0193). The row now proves
// pending and the plan leaves that root pending, without following the link;
// the guardian moves it aside when the account signs in.
func TestStandaloneSignedOutAccountOwnDataDirLinkStaysPending(t *testing.T) {
	target := deferredPendingProofFixture(t, true)
	sid := currentWindowsTestSID(t)
	dataDir := filepath.Join(target.UserHome, ".defenseclaw")
	outside, canary := outsideDataDirTree(t, target.UserHome)
	plantWindowsAccountJunction(t, dataDir, outside, sid)

	if err := RequireWindowsEnterpriseDeferredTargetPending(target); err != nil {
		t.Fatalf("pending proof for the account's own junction: %v", err)
	}
	plan, err := planValidationRootsForTarget(target)
	if err != nil || len(plan.Roots) != 1 || plan.Roots[0].Baseline != windowsManagedRuntimeBaselinePending {
		t.Fatalf("repair plan = %+v, %v; want the account's root pending", plan.Roots, err)
	}
	if !WindowsAccountOwnedDataDirLink(target.UserHome, sid.String()) {
		t.Fatal("status does not name the account's own link")
	}
	if !WindowsAccountOwnedRootDataDirLink(target.UserHome, sid.String()) {
		t.Fatal("the root link was not identified")
	}
	if WindowsAccountCreatedDataDir(target.UserHome, sid.String()) {
		t.Fatal("the account's junction reads as an account-created folder the guardian would adopt")
	}
	requireOutsideDataDirTreeUnchanged(t, outside, canary)
	if info, err := windowsPathOwnerNoFollow(dataDir); err != nil || info == nil || !info.Equals(sid) {
		t.Fatalf("the junction itself changed: owner %v err %v", info, err)
	}
}

// The lifecycle retire (Upgrade, Repair, uninstall) and the classification
// before an upgrade found the account's own link at its DefenseClaw folder
// untrusted, which failed an uninstall for the computer (GAP-0193); they now
// find nothing to retire behind it and never follow it.
func TestStandaloneRetireFindsNothingBehindAnAccountOwnDataDirLink(t *testing.T) {
	target := deferredPendingProofFixture(t, true)
	sid := currentWindowsTestSID(t)
	dataDir := filepath.Join(target.UserHome, ".defenseclaw")
	outside, canary := outsideDataDirTree(t, target.UserHome)
	plantWindowsAccountJunction(t, dataDir, outside, sid)
	hookExe, _ := windowsEnterpriseHookExecutable()
	previousAncestor, previousDir, previousFile := windowsManagedPolicyAncestorTrustCheck, windowsManagedPolicyDirTrustCheck, windowsManagedPolicyFileTrustCheck
	windowsManagedPolicyAncestorTrustCheck = func(string) error { return nil }
	windowsManagedPolicyDirTrustCheck = func(string) error { return nil }
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	previousOwner, previousMutation := windowsManagedPolicyOwnerSID, windowsManagedRuntimeSelectorMutationAuthorize
	windowsManagedPolicyOwnerSID = func() (*windows.SID, error) { return sid, nil }
	windowsManagedRuntimeSelectorMutationAuthorize = func() error { return nil }
	t.Cleanup(func() {
		windowsManagedPolicyAncestorTrustCheck, windowsManagedPolicyDirTrustCheck, windowsManagedPolicyFileTrustCheck = previousAncestor, previousDir, previousFile
		windowsManagedPolicyOwnerSID, windowsManagedRuntimeSelectorMutationAuthorize = previousOwner, previousMutation
	})
	gc := WindowsManagedRuntimeGenerationGCOptions{Connector: "claudecode", TargetSID: sid.String(), DataDir: dataDir, HookExecutable: hookExe}
	if removed, err := GarbageCollectWindowsManagedRuntimeGenerations(gc); err != nil || removed != 0 {
		t.Fatalf("lifecycle retire behind the account's own link = %d, %v; want nothing to retire", removed, err)
	}
	if err := ClassifyWindowsManagedRuntimeGenerations(gc); err != nil {
		t.Fatalf("classification behind the account's own link: %v", err)
	}
	requireOutsideDataDirTreeUnchanged(t, outside, canary)
}

// A link at the DefenseClaw folder that another account or an administrator
// owns, and any link on the Secure Client profile, is still refused for that
// account.
func TestStandaloneForeignOwnedDataDirLinkStaysRefused(t *testing.T) {
	target := deferredPendingProofFixture(t, true)
	dataDir := filepath.Join(target.UserHome, ".defenseclaw")
	outside, canary := outsideDataDirTree(t, target.UserHome)
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	plantWindowsAccountJunction(t, dataDir, outside, system)
	if err := RequireWindowsEnterpriseDeferredTargetPending(target); err == nil ||
		!strings.Contains(err.Error(), "deferred target data directory is untrusted") {
		t.Fatalf("pending proof for a junction the account does not own = %v, want refused", err)
	}
	if _, err := planValidationRootsForTarget(target); err == nil ||
		!strings.Contains(err.Error(), "reject noncanonical managed runtime baseline") {
		t.Fatalf("repair plan for a junction the account does not own = %v, want refused", err)
	}
	if WindowsAccountOwnedDataDirLink(target.UserHome, currentWindowsTestSID(t).String()) {
		t.Fatal("status names a junction the account does not own as its own")
	}
	if WindowsAccountOwnedRootDataDirLink(target.UserHome, currentWindowsTestSID(t).String()) {
		t.Fatal("the root link was attributed to a different account")
	}
	if !windowsEnterpriseStandaloneProcess() || windowsEnterpriseStandaloneDeferredDataDirAccountLink(target.UserHome, dataDir, currentWindowsTestSID(t)) {
		t.Fatal("the retire would skip a junction the account does not own")
	}
	requireOutsideDataDirTreeUnchanged(t, outside, canary)
}

func TestStandaloneLifecycleValidationSkipsAdministratorOwnedDataDirLink(t *testing.T) {
	target := deferredPendingProofFixture(t, true)
	dataDir := filepath.Join(target.UserHome, ".defenseclaw")
	outside, canary := outsideDataDirTree(t, target.UserHome)
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	plantWindowsAccountJunction(t, dataDir, outside, admin)
	manifest := Manifest{Version: 1, Targets: []ManifestTarget{target}}
	plan, err := PlanWindowsManagedRuntimeRootsForValidationSkippingAccountFailures(
		manifest, `C:\ProgramData\DefenseClaw\etc\targets.yaml`, strings.Repeat("a", 64))
	if err != nil || len(plan.Roots) != 0 || len(plan.SkippedProfiles) != 1 ||
		plan.SkippedProfiles[0].SID != target.SID ||
		!strings.Contains(plan.SkippedProfiles[0].Reason, "reject noncanonical managed runtime baseline") {
		t.Fatalf("lifecycle validation plan = %+v, %v; want one account left pending", plan, err)
	}
	if pendingErr := RequireWindowsEnterpriseDeferredTargetPending(target); pendingErr == nil {
		t.Fatal("the account's foreign-owned folder became trusted")
	}
	requireOutsideDataDirTreeUnchanged(t, outside, canary)
	if owner, err := windowsPathOwnerNoFollow(dataDir); err != nil || owner == nil || !owner.Equals(admin) {
		t.Fatalf("junction owner changed: %v, %v", owner, err)
	}
}

// GAP-0585: the guardian and status name the junction an administrator (or
// SYSTEM) owns as a link the account does not own, apart from the account's
// own junction, a plain folder and a missing folder. Nothing it names is read.
func TestWindowsForeignOwnedDataDirLinkIsDistinctFromAccountOwned(t *testing.T) {
	target := deferredPendingProofFixture(t, true)
	sid := currentWindowsTestSID(t)
	dataDir := filepath.Join(target.UserHome, ".defenseclaw")
	if WindowsForeignOwnedDataDirLink(target.UserHome, sid.String()) {
		t.Fatal("a missing folder was reported as a foreign link")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if WindowsForeignOwnedDataDirLink(target.UserHome, sid.String()) {
		t.Fatal("a plain folder was reported as a foreign link")
	}
	if err := os.Remove(dataDir); err != nil {
		t.Fatal(err)
	}
	outside, canary := outsideDataDirTree(t, target.UserHome)
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	plantWindowsAccountJunction(t, dataDir, outside, admin)
	if !WindowsForeignOwnedDataDirLink(target.UserHome, sid.String()) ||
		WindowsAccountOwnedDataDirLink(target.UserHome, sid.String()) {
		t.Fatal("an Administrators-owned junction was not classified as a link the account does not own")
	}
	if WindowsForeignOwnedDataDirLink(target.UserHome, admin.String()) ||
		!WindowsAccountOwnedDataDirLink(target.UserHome, admin.String()) {
		t.Fatal("the owner of the junction was classified as foreign to it")
	}
	requireOutsideDataDirTreeUnchanged(t, outside, canary)
	if owner, err := windowsPathOwnerNoFollow(dataDir); err != nil || owner == nil || !owner.Equals(admin) {
		t.Fatalf("junction owner changed: %v, %v", owner, err)
	}
}

func TestWindowsAccountOwnDataDirLinkIsNotForeign(t *testing.T) {
	target := deferredPendingProofFixture(t, true)
	sid := currentWindowsTestSID(t)
	dataDir := filepath.Join(target.UserHome, ".defenseclaw")
	outside, canary := outsideDataDirTree(t, target.UserHome)
	plantWindowsAccountJunction(t, dataDir, outside, sid)
	if WindowsForeignOwnedDataDirLink(target.UserHome, sid.String()) ||
		!WindowsAccountOwnedDataDirLink(target.UserHome, sid.String()) {
		t.Fatal("the account's own junction (GAP-0193) was classified as foreign")
	}
	requireOutsideDataDirTreeUnchanged(t, outside, canary)
}

func TestSecureClientDeferredOwnDataDirLinkStaysRefused(t *testing.T) {
	target := deferredPendingProofFixture(t, false)
	sid := currentWindowsTestSID(t)
	dataDir := filepath.Join(target.UserHome, ".defenseclaw")
	outside, canary := outsideDataDirTree(t, target.UserHome)
	plantWindowsAccountJunction(t, dataDir, outside, sid)
	if err := RequireWindowsEnterpriseDeferredTargetPending(target); err == nil {
		t.Fatal("the Secure Client pending proof accepted a junctioned data directory")
	}
	requireOutsideDataDirTreeUnchanged(t, outside, canary)
}
