// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
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

// GAP-1733: an account whose canonical folder holds a per-user DefenseClaw
// install fails only its own rows with the per-user install error, which
// status, verify and the Setup adoption excuse like a foreign link and which
// does not count against coverage. The same row once the install is gone,
// with another failure beside it, or on Secure Client is not excused.
func TestGAP1733PerUserInstallFolderExcusesOnlyItsOwnFailedRow(t *testing.T) {
	previousCfg, previousOwned, previousForeign, previousPerUser, previousRemoved := cfg,
		enterpriseHookAccountOwnedDataDirLink, enterpriseHookForeignDataDirLink, enterpriseHookPerUserInstallFolder,
		enterpriseHookRemovedAccountRow
	t.Cleanup(func() {
		cfg, enterpriseHookAccountOwnedDataDirLink, enterpriseHookForeignDataDirLink, enterpriseHookPerUserInstallFolder,
			enterpriseHookRemovedAccountRow = previousCfg, previousOwned, previousForeign, previousPerUser, previousRemoved
	})
	enterpriseHookRemovedAccountRow = func(enterpriseHookReconcileRow) bool { return false }
	enterpriseHookAccountOwnedDataDirLink = func(string, string) bool { return false }
	enterpriseHookForeignDataDirLink = func(string, string) bool { return false }
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}
	home := filepath.Join(t.TempDir(), "alice")
	const sid = "S-1-5-21-1-2-3-1001"
	perUser := true
	enterpriseHookPerUserInstallFolder = func(gotHome, gotSID string) bool {
		return perUser && gotHome == home && gotSID == sid
	}
	target := enterprisehooks.ManifestTarget{UserHome: home, SID: sid, Connector: "claudecode", Deferred: true}
	// The folder rule of one pass: a skip on an account never protected,
	// tamper on an enrolled one
	// (TestGAP1733PlantedPerUserEntryOnAnEnrolledAccountIsRepairedAndNotExcused).
	perUserFolder := func(target enterprisehooks.ManifestTarget, home, sid string) bool {
		skip, tamper := newEnterpriseHookPerUserInstallPass(t.TempDir()).classify(target, home, sid, false)
		return skip || tamper
	}
	for _, dir := range []string{"", filepath.Join(home, ".defenseclaw")} {
		target.DataDir = dir
		if !perUserFolder(target, home, sid) || enterpriseHookTargetForeignLink(target, home, sid) {
			t.Fatalf("data_dir %q: the per-user install folder was not classified apart from a link", dir)
		}
	}
	otherDir := target
	otherDir.DataDir = filepath.Join(home, "other")
	if perUserFolder(otherDir, home, sid) || perUserFolder(target, home, "S-1-5-21-1-2-3-1002") {
		t.Fatal("another folder or account was classified as the per-user install")
	}
	row := enterpriseHookReconcileRow{User: "alice", UserHome: home, SID: sid,
		Connector: "claudecode", Error: enterpriseHookAccountPerUserInstallFailure}
	healthy := enterpriseHookReconcileRow{User: "bob", UserHome: filepath.Join(t.TempDir(), "bob"),
		SID: "S-1-5-21-1-2-3-1002", Connector: "codex", OK: true}
	state := enterpriseHookGuardianState{FailureCount: 1, Results: []enterpriseHookReconcileRow{healthy, row}}
	if removed, awaiting, linked := enterpriseHookExcusedFailures(state); removed != 0 || awaiting != 0 || linked != 1 {
		t.Fatalf("per-user install counts = %d removed, %d awaiting, %d linked", removed, awaiting, linked)
	}
	if !enterpriseHookAccountLinkRow(row) || enterpriseHookAccountLinkRowStandalone(row) || enterpriseHookAccountForeignLinkRow(row) {
		t.Fatal("the per-user install row joined another account-folder rule")
	}
	if note := enterpriseHookVerifyExcusedNote(enterpriseHookVerifyRun{}, row); !strings.Contains(note, "per-user DefenseClaw install") {
		t.Fatalf("verify note = %q, want the per-user install named", note)
	}
	unrelated := state
	unrelated.Results = []enterpriseHookReconcileRow{healthy, row, {User: "carol", Connector: "cursor", Error: "another target failed"}}
	unrelated.FailureCount = 2
	if removed, awaiting, linked := enterpriseHookExcusedFailures(unrelated); removed != 0 || awaiting != 0 || linked != 0 {
		t.Fatalf("an unrelated failure was excused next to the per-user install: %d, %d, %d", removed, awaiting, linked)
	}
	// Removed per-user install: the recorded error is stale, not an excuse.
	perUser = false
	if removed, awaiting, linked := enterpriseHookExcusedFailures(state); removed != 0 || awaiting != 0 || linked != 0 {
		t.Fatalf("a stale per-user install row was excused: %d, %d, %d", removed, awaiting, linked)
	}
	perUser = true
	wrong := row
	wrong.Error = "enterprise hooks: write managed Claude Code hook runtime: access is denied"
	if enterpriseHookAccountLinkRow(wrong) {
		t.Fatal("an ordinary failure on the per-user account was excused")
	}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	if perUserFolder(target, home, sid) || enterpriseHookAccountLinkRow(row) {
		t.Fatal("Secure Client adopted the standalone per-user install rule")
	}
}

// Setup's manifest adoption excuses a guardian row only by its exact error
// ($script:AccountLinkGuardianErrors). Without the per-user install error
// there the first /ensure next to a per-user install failed (GAP-1733).
func TestGAP1733SetupExcusesThePerUserInstallGuardianError(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "packaging", "windows", "DefenseClawEnterprise.psm1"))
	if err != nil {
		t.Fatalf("read the Setup module: %v", err)
	}
	module := string(body)
	start := strings.Index(module, "$script:AccountLinkGuardianErrors = @(")
	if start < 0 {
		t.Fatal("the Setup module has no AccountLinkGuardianErrors list")
	}
	end := strings.Index(module[start:], "\n)")
	if end < 0 {
		t.Fatal("the AccountLinkGuardianErrors list is not closed")
	}
	list := module[start : start+end]
	for _, failure := range []string{
		enterpriseHookAccountLinkFailure,
		enterpriseHookAccountForeignLinkFailure,
		enterpriseHookAccountPerUserInstallFailure,
	} {
		if !strings.Contains(list, "'"+strings.ReplaceAll(failure, "'", "''")+"'") {
			t.Errorf("Setup does not excuse the guardian error %q", failure)
		}
	}
}
