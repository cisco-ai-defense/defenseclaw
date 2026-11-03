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
	previousCfg, previousProbe := cfg, enterpriseHookAccountOwnedDataDirLink
	t.Cleanup(func() { cfg, enterpriseHookAccountOwnedDataDirLink = previousCfg, previousProbe })
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
	missingDir := target
	missingDir.DataDir = ""
	if enterpriseHookTargetAccountLink(missingDir, home, sid) {
		t.Fatal("a missing data directory was treated as the canonical link")
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
	linked = false
	if removed, awaiting, ownLink := enterpriseHookExcusedFailures(state); removed != 0 || awaiting != 0 || ownLink != 0 {
		t.Fatalf("link no longer owned by account: %d, %d, %d", removed, awaiting, ownLink)
	}
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
