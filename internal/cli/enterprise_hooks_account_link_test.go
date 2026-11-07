// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestGAP0193AccountFolderLinkExcusesOnlyItsOwnFailedRow(t *testing.T) {
	previousCfg, previousProbe, previousRemoved := cfg, enterpriseHookAccountOwnedDataDirLink, enterpriseHookRemovedAccountRow
	t.Cleanup(func() {
		cfg, enterpriseHookAccountOwnedDataDirLink, enterpriseHookRemovedAccountRow = previousCfg, previousProbe, previousRemoved
	})
	enterpriseHookRemovedAccountRow = func(enterpriseHookReconcileRow) bool { return false }
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}
	home := filepath.Join(t.TempDir(), "alice")
	const sid = "S-1-5-21-1-2-3-1001"
	linked := true
	enterpriseHookAccountOwnedDataDirLink = func(gotHome, gotSID string) bool {
		return linked && gotHome == home && gotSID == sid
	}
	target := enterprisehooks.ManifestTarget{UserHome: home, SID: sid,
		DataDir: filepath.Join(home, ".defenseclaw"), Connector: "claudecode"}
	if !enterpriseHookTargetAccountLink(target, home, sid) {
		t.Fatal("the account's canonical folder link was not recognized")
	}
	omittedDir := target
	omittedDir.DataDir = ""
	if !enterpriseHookTargetAccountLink(omittedDir, home, sid) {
		t.Fatal("an omitted data_dir resolves to the canonical folder and must see its link")
	}
	otherDir := target
	otherDir.DataDir = filepath.Join(home, "other")
	if enterpriseHookTargetAccountLink(otherDir, home, sid) {
		t.Fatal("a different data directory was treated as the canonical link")
	}
	row := enterpriseHookReconcileRow{User: "alice", UserHome: home, SID: sid,
		Connector: "claudecode", Error: enterpriseHookAccountLinkFailure}
	healthy := enterpriseHookReconcileRow{User: "bob", UserHome: filepath.Join(t.TempDir(), "bob"),
		SID: "S-1-5-21-1-2-3-1002", Connector: "codex", OK: true}
	state := enterpriseHookGuardianState{FailureCount: 1, Results: []enterpriseHookReconcileRow{healthy, row}}
	if removed, awaiting, ownLink := enterpriseHookExcusedFailures(state); removed != 0 || awaiting != 0 || ownLink != 1 {
		t.Fatalf("own link counts = %d removed, %d awaiting, %d linked", removed, awaiting, ownLink)
	}
	enterpriseHookRemovedAccountRow = func(row enterpriseHookReconcileRow) bool {
		return row.SID == sid
	}
	if removed, awaiting, ownLink := enterpriseHookExcusedFailures(state); removed != 0 || awaiting != 0 || ownLink != 1 {
		t.Fatalf("own link before removed-account fallback = %d removed, %d awaiting, %d linked", removed, awaiting, ownLink)
	}
	enterpriseHookRemovedAccountRow = func(enterpriseHookReconcileRow) bool { return false }
	linked = false
	if removed, awaiting, ownLink := enterpriseHookExcusedFailures(state); removed != 0 || awaiting != 0 || ownLink != 0 {
		t.Fatalf("link no longer owned by account: %d, %d, %d", removed, awaiting, ownLink)
	}
	enterpriseHookRemovedAccountRow = func(row enterpriseHookReconcileRow) bool { return row.SID == sid }
	if removed, awaiting, ownLink := enterpriseHookExcusedFailures(state); removed != 1 || awaiting != 0 || ownLink != 0 {
		t.Fatalf("removed account remains excused = %d removed, %d awaiting, %d linked", removed, awaiting, ownLink)
	}
	enterpriseHookRemovedAccountRow = func(enterpriseHookReconcileRow) bool { return false }
	linked = true
	unrelated := state
	unrelated.Results = []enterpriseHookReconcileRow{healthy, row, {User: "carol", Connector: "cursor", Error: "another target failed"}}
	unrelated.FailureCount = 2
	if removed, awaiting, ownLink := enterpriseHookExcusedFailures(unrelated); removed != 0 || awaiting != 0 || ownLink != 0 {
		t.Fatalf("unrelated failure was excused: %d, %d, %d", removed, awaiting, ownLink)
	}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	if enterpriseHookTargetAccountLink(target, home, sid) || enterpriseHookAccountLinkRow(row) {
		t.Fatal("Secure Client adopted the standalone account-link rule")
	}
}

// GAP-0585: a link another principal owns at one account's folder fails only
// that account's row and is excused like the account's own link, counted in
// account_link_failures, so status, verify and the Setup adoption go on for
// the computer. The same row with the link gone, another failure beside it,
// or on Secure Client is not excused.
func TestGAP0585ForeignFolderLinkExcusesOnlyItsOwnFailedRow(t *testing.T) {
	previousCfg, previousOwned, previousForeign, previousRemoved :=
		cfg, enterpriseHookAccountOwnedDataDirLink, enterpriseHookForeignDataDirLink, enterpriseHookRemovedAccountRow
	t.Cleanup(func() {
		cfg, enterpriseHookAccountOwnedDataDirLink, enterpriseHookForeignDataDirLink, enterpriseHookRemovedAccountRow =
			previousCfg, previousOwned, previousForeign, previousRemoved
	})
	enterpriseHookRemovedAccountRow = func(enterpriseHookReconcileRow) bool { return false }
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}
	home := filepath.Join(t.TempDir(), "alice")
	const sid = "S-1-5-21-1-2-3-1001"
	foreign := true
	enterpriseHookAccountOwnedDataDirLink = func(string, string) bool { return false }
	enterpriseHookForeignDataDirLink = func(gotHome, gotSID string) bool {
		return foreign && gotHome == home && gotSID == sid
	}
	target := enterprisehooks.ManifestTarget{UserHome: home, SID: sid,
		DataDir: filepath.Join(home, ".defenseclaw"), Connector: "claudecode"}
	if !enterpriseHookTargetForeignLink(target, home, sid) || enterpriseHookTargetAccountLink(target, home, sid) {
		t.Fatal("a link the account does not own was not classified apart from the account's own link")
	}
	otherDir := target
	otherDir.DataDir = filepath.Join(home, "other")
	if enterpriseHookTargetForeignLink(otherDir, home, sid) {
		t.Fatal("a different data directory was treated as the canonical folder")
	}
	row := enterpriseHookReconcileRow{User: "alice", UserHome: home, SID: sid,
		Connector: "claudecode", Error: enterpriseHookAccountForeignLinkFailure}
	healthy := enterpriseHookReconcileRow{User: "bob", UserHome: filepath.Join(t.TempDir(), "bob"),
		SID: "S-1-5-21-1-2-3-1002", Connector: "codex", OK: true}
	state := enterpriseHookGuardianState{FailureCount: 1, Results: []enterpriseHookReconcileRow{healthy, row}}
	if removed, awaiting, linked := enterpriseHookExcusedFailures(state); removed != 0 || awaiting != 0 || linked != 1 {
		t.Fatalf("foreign link counts = %d removed, %d awaiting, %d linked", removed, awaiting, linked)
	}
	if !enterpriseHookAccountLinkRow(row) || enterpriseHookAccountLinkRowStandalone(row) {
		t.Fatal("the foreign-link row joined the teardown's account-owned link rule")
	}
	unrelated := state
	unrelated.Results = []enterpriseHookReconcileRow{healthy, row, {User: "carol", Connector: "cursor", Error: "another target failed"}}
	unrelated.FailureCount = 2
	if removed, awaiting, linked := enterpriseHookExcusedFailures(unrelated); removed != 0 || awaiting != 0 || linked != 0 {
		t.Fatalf("an unrelated failure was excused next to the foreign link: %d, %d, %d", removed, awaiting, linked)
	}
	// The same error on an account whose folder is no longer such a link is a
	// stale record, not an excuse.
	foreign = false
	if removed, awaiting, linked := enterpriseHookExcusedFailures(state); removed != 0 || awaiting != 0 || linked != 0 {
		t.Fatalf("a stale foreign-link row was excused: %d, %d, %d", removed, awaiting, linked)
	}
	// An ordinary failure of the same account is not excused by the probe.
	foreign = true
	wrong := row
	wrong.Error = "enterprise hooks: write managed Claude Code hook runtime: access is denied"
	state.Results = []enterpriseHookReconcileRow{healthy, wrong}
	if removed, awaiting, linked := enterpriseHookExcusedFailures(state); removed != 0 || awaiting != 0 || linked != 0 {
		t.Fatalf("an ordinary failure on the same account was excused: %d, %d, %d", removed, awaiting, linked)
	}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	if enterpriseHookTargetForeignLink(target, home, sid) || enterpriseHookAccountLinkRow(row) {
		t.Fatal("Secure Client adopted the standalone foreign-link rule")
	}
}

// A healthy account with a normal folder is never treated as a link account.
func TestGAP0585PlainFolderIsNotAForeignLink(t *testing.T) {
	previousCfg, previousForeign := cfg, enterpriseHookForeignDataDirLink
	t.Cleanup(func() { cfg, enterpriseHookForeignDataDirLink = previousCfg, previousForeign })
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}
	enterpriseHookForeignDataDirLink = func(string, string) bool { return false }
	home := filepath.Join(t.TempDir(), "alice")
	target := enterprisehooks.ManifestTarget{UserHome: home, SID: "S-1-5-21-1-2-3-1001",
		DataDir: filepath.Join(home, ".defenseclaw"), Connector: "claudecode"}
	if enterpriseHookTargetForeignLink(target, home, target.SID) {
		t.Fatal("a plain folder was classified as a foreign link")
	}
	row := enterpriseHookReconcileRow{UserHome: home, SID: target.SID, Error: "enterprise hooks: another failure"}
	if enterpriseHookAccountLinkRow(row) {
		t.Fatal("an ordinary failed row was excused")
	}
}

// A manifest target may omit data_dir (the Windows runtime resolves it to the
// canonical folder), so a foreign link at that folder is named the same way;
// a data_dir elsewhere is never classified (GAP-0585 review 1).
func TestGAP0585OmittedDataDirNamesTheForeignLink(t *testing.T) {
	previousCfg, previousForeign := cfg, enterpriseHookForeignDataDirLink
	t.Cleanup(func() { cfg, enterpriseHookForeignDataDirLink = previousCfg, previousForeign })
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}
	home := filepath.Join(t.TempDir(), "alice")
	const sid = "S-1-5-21-1-2-3-1001"
	enterpriseHookForeignDataDirLink = func(gotHome, gotSID string) bool {
		return gotHome == home && gotSID == sid
	}
	target := enterprisehooks.ManifestTarget{UserHome: home, SID: sid, Connector: "claudecode"}
	for _, dir := range []string{"", "   ", filepath.Join(home, ".defenseclaw")} {
		target.DataDir = dir
		if !enterpriseHookTargetForeignLink(target, home, sid) {
			t.Fatalf("data_dir %q: the foreign link was not classified", dir)
		}
	}
	target.DataDir = filepath.Join(home, "other")
	if enterpriseHookTargetForeignLink(target, home, sid) {
		t.Fatal("a data_dir outside the canonical folder was classified as the foreign link")
	}
	target.DataDir = ""
	if enterpriseHookTargetForeignLink(target, home, "S-1-5-21-1-2-3-1002") {
		t.Fatal("another account was classified as linked")
	}
}
