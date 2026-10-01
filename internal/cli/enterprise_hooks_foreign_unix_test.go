// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestWorkerForeignCleanupRemovesTheUsersForeignHook(t *testing.T) {
	home := t.TempDir()
	hooks := filepath.Join(home, ".cursor", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooks), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hooks, []byte(`{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	reports := runEnterpriseHookWorkerForeignCleanup(enterpriseHookWorkerRequest{
		Home: home,
		ForeignCleanup: []enterpriseHookWorkerForeignCleanup{{
			Connector:  "cursor",
			HookBinary: "/opt/defenseclaw/bin/defenseclaw-hook",
			Policy:     enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: config.ForeignHooksRemove, Guard: true},
		}},
	}, time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC))
	report := reports["cursor"]
	if report.Error != "" || len(report.Removed) != 1 || report.BackupDir == "" {
		t.Fatalf("cleanup report %+v", report)
	}
	if data, _ := os.ReadFile(hooks); strings.Contains(string(data), "rewrite.sh") {
		t.Fatalf("the foreign hook is still registered: %s", data)
	}
	if _, err := os.Stat(report.BackupDir); err != nil {
		t.Fatalf("no backup of the removed hook: %v", err)
	}

	// The worker's remove mode runs the remover for its target.
	previous := enterpriseHookWorkerRemover
	t.Cleanup(func() { enterpriseHookWorkerRemover = previous })
	var removed []string
	enterpriseHookWorkerRemover = func(_ context.Context, opts enterprisehooks.InstallOptions) error {
		removed = append(removed, opts.ConnectorName+"@"+opts.UserHome)
		return nil
	}
	response := runEnterpriseHookWorkerApply(context.Background(), enterpriseHookWorkerRequest{
		Home: "/home/alice", UID: 1001, GID: 1001,
		Targets: []enterpriseHookWorkerTarget{{Index: 3, Mode: enterpriseHookWorkerModeRemove, Options: enterpriseHookWorkerOptions{ConnectorName: "codex", UserHome: "/home/alice", OwnerUID: 1001, OwnerGID: 1001}}},
	})
	if len(response.Targets) != 1 || !response.Targets[0].OK || response.Targets[0].Index != 3 || response.Targets[0].Result != nil {
		t.Fatalf("response %+v", response)
	}
	if strings.Join(removed, ",") != "codex@/home/alice" {
		t.Fatalf("removed %v", removed)
	}

	// uninstall --purge: the purge of the account's state runs after its
	// removals, and not at all when one failed (the state holds the backups
	// a retried removal restores from).
	previousPurger := enterpriseHookWorkerPurger
	t.Cleanup(func() { enterpriseHookWorkerPurger = previousPurger })
	var purged []string
	enterpriseHookWorkerPurger = func(_ context.Context, opts enterprisehooks.InstallOptions) error {
		purged = append(purged, opts.DataDir)
		return nil
	}
	purgeRequest := enterpriseHookWorkerRequest{
		Home: "/home/alice", UID: 1001, GID: 1001,
		Targets: []enterpriseHookWorkerTarget{
			{Index: 3, Mode: enterpriseHookWorkerModeRemove, Options: enterpriseHookWorkerOptions{ConnectorName: "codex", UserHome: "/home/alice", OwnerUID: 1001, OwnerGID: 1001}},
			{Index: 4, Mode: enterpriseHookWorkerModePurge, Options: enterpriseHookWorkerOptions{UserHome: "/home/alice", OwnerUID: 1001, OwnerGID: 1001, DataDir: "/home/alice/.defenseclaw"}},
		},
	}
	if response := runEnterpriseHookWorkerApply(context.Background(), purgeRequest); !response.Targets[1].OK || strings.Join(purged, ",") != "/home/alice/.defenseclaw" {
		t.Fatalf("purge response %+v, purged %v", response, purged)
	}
	// RHEL-U2-12: an account's own per-user install is kept, and the
	// worker reports that instead of a failure or a purge.
	enterpriseHookWorkerPurger = func(context.Context, enterprisehooks.InstallOptions) error {
		return &enterprisehooks.UserInstallKeptError{Found: []string{"config.yaml"}}
	}
	if response := runEnterpriseHookWorkerApply(context.Background(), purgeRequest); !response.Targets[1].OK || !strings.Contains(response.Targets[1].Kept, "own DefenseClaw install") {
		t.Fatalf("kept purge response %+v", response)
	}
	enterpriseHookWorkerPurger = func(_ context.Context, opts enterprisehooks.InstallOptions) error {
		purged = append(purged, opts.DataDir)
		return nil
	}
	enterpriseHookWorkerRemover = func(context.Context, enterprisehooks.InstallOptions) error {
		return errors.New("teardown failed")
	}
	purged = nil
	if response := runEnterpriseHookWorkerApply(context.Background(), purgeRequest); response.Targets[1].OK || len(purged) != 0 {
		t.Fatalf("purged the state of an account whose removal failed: %+v", response)
	}
}

func TestStandaloneForeignCleanupCoversMachinePolicyOnlyUsers(t *testing.T) {
	previousCfg, previousManifest := cfg, enterpriseHookManifest
	previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
	t.Cleanup(func() {
		cfg, enterpriseHookManifest = previousCfg, previousManifest
		enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousLoad, previousCheck, previousRunner
		enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
	})
	enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{
			Profile: managed.ProfileStandalone,
			MachinePolicy: config.EnterpriseMachinePolicyConfig{Connectors: map[string]config.EnterpriseConnectorPolicy{
				"cursor": {}, "codex": {},
			}},
		},
	}
	enterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
	accounts := []enterprisehooks.UnixEligibleAccount{{User: "alice", UID: 4242, GID: 4242, Home: "/home/alice", HomeInode: 7}}
	var loadedFrom string
	enterpriseHookLoadEligibleAccounts = func(path string) ([]enterprisehooks.UnixEligibleAccount, error) {
		loadedFrom = path
		return accounts, nil
	}
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable, Inode: 7}
	}
	var mu sync.Mutex
	var requests []enterpriseHookWorkerRequest
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		mu.Lock()
		defer mu.Unlock()
		if account.UID != 4242 || account.Home != "/home/alice" {
			t.Errorf("worker spawned for %+v", account)
		}
		requests = append(requests, request)
		var targets []enterpriseHookWorkerTargetResult
		for _, target := range request.Targets {
			targets = append(targets, enterpriseHookWorkerTargetResult{Index: target.Index, OK: true, Removed: target.Options.ConnectorName == "claudecode"})
		}
		return enterpriseHookWorkerResponse{
			Targets: targets,
			Cleanup: map[string]enterpriseHookWorkerCleanupReport{
				"cursor": {Removed: []string{"/home/alice/.cursor/hooks.json"}, BackupDir: "/home/alice/.defenseclaw/foreign-hooks-backup/cursor/x"},
			},
			Blocks: []enterprisepolicy.BlockSummary{{
				BlockRecord: enterprisepolicy.BlockRecord{Time: "2026-09-26T11:59:00Z", Connector: "cursor", Event: "preToolUse", Scope: "project", Path: "/home/alice/repo/.cursor/hooks.json\nforged line", Digest: "ab"},
				Count:       3, Last: "2026-09-26T11:59:30Z",
			}},
		}, nil
	}

	var log bytes.Buffer
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	// alice is enrolled per user for Codex only.
	perUser := map[string]map[string]bool{"alice": {"codex": true}}
	if removed := runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, now, perUser); removed != 2 {
		t.Fatalf("removed %d, log:\n%s", removed, log.String())
	}
	if loadedFrom != "/etc/defenseclaw/hook-guardian/"+enterprisehooks.UnixEligibleAccountsFileName {
		t.Fatalf("eligible accounts loaded from %s", loadedFrom)
	}
	if len(requests) != 1 || requests[0].Operation != enterpriseHookWorkerOpForeignCleanup {
		t.Fatalf("worker requests %+v", requests)
	}
	names := []string{}
	for _, cleanup := range requests[0].ForeignCleanup {
		names = append(names, cleanup.Connector)
		if !strings.HasSuffix(cleanup.HookBinary, "/defenseclaw-hook") || len(cleanup.OwnedCommands) == 0 {
			t.Fatalf("cleanup request %+v", cleanup)
		}
	}
	// Codex has a vendor managed-hooks lock, so only Cursor is guarded.
	if strings.Join(names, ",") != "cursor" {
		t.Fatalf("cleanup connectors %v", names)
	}
	if !strings.Contains(log.String(), "removed a cursor hook for alice") {
		t.Fatalf("log:\n%s", log.String())
	}
	// Per-user registrations of machine-policy connectors the manifest does
	// not enroll per user are leftovers of an earlier route.
	leftovers := []string{}
	for _, target := range requests[0].Targets {
		if target.Mode != enterpriseHookWorkerModeRemoveLeftover || target.Options.UserHome != "/home/alice" {
			t.Fatalf("leftover target %+v", target)
		}
		leftovers = append(leftovers, target.Options.ConnectorName)
	}
	if strings.Join(leftovers, ",") != "claudecode,copilot,cursor" ||
		!strings.Contains(log.String(), "removed DefenseClaw's per-user claudecode hooks for alice") {
		t.Fatalf("leftover removal %v, log:\n%s", leftovers, log.String())
	}
	// A repository-hook block never reaches the gateway; the guardian log
	// is where an administrator sees it, with user-written fields defanged.
	if !strings.Contains(log.String(), "blocked cursor preToolUse 3 time(s)") || !strings.Contains(log.String(), "/home/alice/repo/.cursor/hooks.json forged line") ||
		strings.Contains(log.String(), "\nforged line") {
		t.Fatalf("recorded blocks must be logged on one line each:\n%s", log.String())
	}

	// Within the interval nothing runs again; a new account does.
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, now.Add(time.Minute), perUser)
	if len(requests) != 1 {
		t.Fatal("cleanup must be throttled")
	}
	accounts = append(accounts, enterprisehooks.UnixEligibleAccount{User: "bob", UID: 4242, GID: 4242, Home: "/home/alice", HomeInode: 7})
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, now.Add(2*time.Minute), perUser)
	if len(requests) != 3 {
		t.Fatalf("a changed account list must run at once, got %d requests", len(requests))
	}
}

func TestStandaloneForeignCleanupSkipsRecreatedHomes(t *testing.T) {
	previousCfg := cfg
	previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousLoad, previousCheck, previousRunner
		enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
	})
	enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{
			Profile:       managed.ProfileStandalone,
			MachinePolicy: config.EnterpriseMachinePolicyConfig{Connectors: map[string]config.EnterpriseConnectorPolicy{"cursor": {}}},
		},
	}
	enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) {
		return []enterprisehooks.UnixEligibleAccount{{User: "alice", UID: 4242, GID: 4242, Home: "/home/alice", HomeInode: 7}}, nil
	}
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable, Inode: 8}
	}
	enterpriseHookWorkerRunner = func(context.Context, enterpriseHookWorkerAccount, enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		t.Fatal("no worker may run for a home recreated since enumeration")
		return enterpriseHookWorkerResponse{}, nil
	}
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &bytes.Buffer{}, time.Now(), nil)
}

func TestRemoveAllGroupsManifestTargetsPerAccount(t *testing.T) {
	previousCheck := enterpriseHookCheckHome
	t.Cleanup(func() { enterpriseHookCheckHome = previousCheck })
	enterpriseHookCheckHome = func(home string, _ int) enterprisehooks.HomeCheck {
		if home == "/home/pending" {
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomePending}
		}
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
	}
	uid := func(value int) *int { return &value }
	manifest := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{
		{User: "alice", UserHome: "/home/alice", UID: uid(1001), GID: uid(1001), Connector: "codex"},
		{User: "alice", UserHome: "/home/alice", UID: uid(1001), GID: uid(1001), Connector: "devin", DataDir: "/home/alice/.dc"},
		{User: "carol", UserHome: "/home/pending", UID: uid(1003), GID: uid(1003), Connector: "codex"},
		{User: "legacy", UserHome: "/home/legacy", Connector: "codex"},
	}}
	jobs, pending, failed := enterpriseHookRemoveJobs(manifest)
	if len(jobs) != 1 || len(jobs[1001].Request.Targets) != 2 {
		t.Fatalf("jobs %+v", jobs)
	}
	for _, target := range jobs[1001].Request.Targets {
		if target.Mode != enterpriseHookWorkerModeRemove || target.Options.UserHome != "/home/alice" {
			t.Fatalf("target %+v", target)
		}
	}
	if jobs[1001].Request.Targets[1].Options.DataDir != "/home/alice/.dc" || jobs[1001].Request.Targets[0].Options.DataDir != "/home/alice/.defenseclaw" {
		t.Fatalf("data dirs %+v", jobs[1001].Request.Targets)
	}
	if strings.Join(pending, ",") != "carol/codex" || len(failed) != 1 || !strings.HasPrefix(failed[0], "legacy/codex") {
		t.Fatalf("pending %v failed %v", pending, failed)
	}
}

func TestRemoveAllRemovesCopilotVSCodeFilesForEveryAvailableAccount(t *testing.T) {
	previousCheck := enterpriseHookCheckHome
	t.Cleanup(func() { enterpriseHookCheckHome = previousCheck })
	enterpriseHookCheckHome = func(home string, _ int) enterprisehooks.HomeCheck {
		if home == "/home/gone" {
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomePending}
		}
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
	}
	jobs := map[int]*enterpriseHookWorkerJob{
		501: {Account: enterpriseHookWorkerAccount{UID: 501, User: "alice", Home: "/home/alice"}, Request: enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpApply}},
	}
	accounts := []enterprisehooks.UnixEligibleAccount{
		{User: "alice", UID: 501, Home: "/home/alice"},
		{User: "bob", UID: 502, GID: 20, Home: "/home/bob"},
		{User: "carol", UID: 503, Home: "/home/gone"},
	}
	addEnterpriseHookCopilotVSCodeRemovals(jobs, accounts, &enterpriseHookWorkerCopilotVSCode{HookBinary: "/opt/dc/bin/defenseclaw-hook", HookFile: true, Plugin: true})

	if len(jobs) != 2 || jobs[502] == nil || jobs[502].Account.Home != "/home/bob" {
		t.Fatalf("jobs = %+v, want alice's and bob's (carol's home is not available)", jobs)
	}
	for uid, job := range jobs {
		got := job.Request.CopilotVSCode
		if got == nil || got.HookBinary != "/opt/dc/bin/defenseclaw-hook" || got.HookFile || got.Plugin {
			t.Fatalf("uid %d: CopilotVSCode = %+v, want a removal for the hook binary", uid, got)
		}
	}
}
