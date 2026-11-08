// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0754: a hook entry swapped for another command is put back beside it, and
// the foreign-hook cleanup that removes the other command ran once every five
// minutes, so the config stayed changed for minutes after the restore. A pass
// that restored an element makes the cleanup due at once, once.
func TestForeignCleanupRunsInThePassThatRestoredAnElement(t *testing.T) {
	dataDir := useUserCleanupStateDir(t)
	previousCfg, previousManifest := cfg, enterpriseHookManifest
	previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
	t.Cleanup(func() {
		cfg, enterpriseHookManifest = previousCfg, previousManifest
		enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousLoad, previousCheck, previousRunner
		enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
		enterpriseHookForeignCleanupState.leftoversClean, enterpriseHookForeignCleanupState.now = false, false
		enterpriseHookForeignCleanupState.unrepaired = nil
	})
	enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
	enterpriseHookForeignCleanupState.leftoversClean, enterpriseHookForeignCleanupState.now = false, false
	cfg = &config.Config{
		DataDir:        dataDir,
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{
			Profile: managed.ProfileStandalone,
			MachinePolicy: config.EnterpriseMachinePolicyConfig{Connectors: map[string]config.EnterpriseConnectorPolicy{
				"cursor": {}, "codex": {},
			}},
		},
	}
	useStandaloneForeignHookFenceFixture(t)
	enterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
	accounts := []enterprisehooks.UnixEligibleAccount{{User: "alice", UID: 4242, GID: 4242, Home: "/home/alice", HomeInode: 7}}
	enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) { return accounts, nil }
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable, Inode: 7}
	}
	var runs atomic.Int32
	enterpriseHookWorkerRunner = func(_ context.Context, _ enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		runs.Add(1)
		var targets []enterpriseHookWorkerTargetResult
		for _, target := range request.Targets {
			targets = append(targets, enterpriseHookWorkerTargetResult{Index: target.Index, OK: true})
		}
		return enterpriseHookWorkerResponse{Targets: targets}, nil
	}
	clean := func(at time.Time) int32 {
		before := runs.Load()
		runEnterpriseHookStandaloneForeignCleanup(context.Background(), &bytes.Buffer{}, at, enterprisehooks.Manifest{},
			map[string]map[string]bool{"alice": {"codex": true}}, "")
		return runs.Load() - before
	}
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	if got := clean(now); got != 1 {
		t.Fatalf("first cleanup spawned %d workers, want one", got)
	}
	// The twin: nothing restored, so a pass a second later does no cleanup.
	if got := clean(now.Add(time.Second)); got != 0 {
		t.Fatalf("a pass within the interval spawned %d workers, want none", got)
	}
	requestEnterpriseHookForeignCleanupNow()
	if got := clean(now.Add(2 * time.Second)); got != 1 {
		t.Fatalf("the pass after a restore spawned %d workers, want one", got)
	}
	// The request is used up by that cleanup.
	if got := clean(now.Add(3 * time.Second)); got != 0 {
		t.Fatalf("the next pass spawned %d workers, want none", got)
	}
}
