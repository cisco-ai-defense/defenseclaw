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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// useStandaloneForeignHookFenceFixture gives the standalone cfg the test set
// a guardian whose removal commits work in temporary folders
// (useForeignHookRemovalRecords).
func useStandaloneForeignHookFenceFixture(t *testing.T) {
	t.Helper()
	useForeignHookRemovalRecords(t)
}

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
	}, time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC), nil)
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
	previousPurger, previousStop := enterpriseHookWorkerPurger, enterpriseHookWorkerStopPerUser
	t.Cleanup(func() { enterpriseHookWorkerPurger, enterpriseHookWorkerStopPerUser = previousPurger, previousStop })
	enterpriseHookWorkerStopPerUser = func(enterprisehooks.InstallOptions) (bool, error) { return false, nil }
	var purged []string
	enterpriseHookWorkerPurger = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.PurgeSummary, error) {
		purged = append(purged, opts.DataDir)
		return enterprisehooks.PurgeSummary{}, nil
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
	enterpriseHookWorkerRemover = func(context.Context, enterprisehooks.InstallOptions) error {
		return errors.New("teardown failed")
	}
	purged = nil
	if response := runEnterpriseHookWorkerApply(context.Background(), purgeRequest); response.Targets[1].OK || len(purged) != 0 {
		t.Fatalf("purged the state of an account whose removal failed: %+v", response)
	}
}

func TestStandaloneForeignCleanupCoversMachinePolicyOnlyUsers(t *testing.T) {
	dataDir := useUserCleanupStateDir(t)
	previousCfg, previousManifest := cfg, enterpriseHookManifest
	previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
	t.Cleanup(func() {
		cfg, enterpriseHookManifest = previousCfg, previousManifest
		enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousLoad, previousCheck, previousRunner
		enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
		enterpriseHookForeignCleanupState.unrepaired = nil
	})
	enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
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
		if request.cleanupFence == nil {
			t.Error("the worker's cleanup must commit its removals through the guardian")
		}
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
	if removed := runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, now, enterprisehooks.Manifest{}, perUser, ""); removed != 2 {
		t.Fatalf("removed %d, log:\n%s", removed, log.String())
	}
	if loadedFrom != "/etc/defenseclaw/hook-guardian/"+enterprisehooks.UnixEligibleAccountsFileName {
		t.Fatalf("eligible accounts loaded from %s", loadedFrom)
	}
	// One worker per account: it removes and commits each removal through
	// its session; what no commit recorded is recorded once it ends.
	if len(requests) != 1 || requests[0].Operation != enterpriseHookWorkerOpForeignCleanup || len(requests[0].ForeignCleanup) != 1 {
		t.Fatalf("worker requests %+v", requests)
	}
	ledger, err := loadEnterpriseForeignHookRemovals(filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), enterprisepolicy.ForeignHookRemovalsFile))
	if err != nil || len(ledger) != 1 || ledger[0].Path != "/home/alice/.cursor/hooks.json" || ledger[0].Connector != "cursor" || ledger[0].Identity != "4242" {
		t.Fatalf("the removal must be recorded for the gateway: %+v %v", ledger, err)
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
		if target.Mode == enterpriseHookWorkerModeUnblockPersonalClaude {
			// Claude Code is not machine policy here: the blocker an
			// earlier pass may have written goes (GAP-1829).
			continue
		}
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
	if !strings.Contains(log.String(), "blocked 3 cursor hook call(s) (preToolUse 3)") || !strings.Contains(log.String(), "/home/alice/repo/.cursor/hooks.json forged line") ||
		strings.Contains(log.String(), "\nforged line") {
		t.Fatalf("recorded blocks must be logged on one line each:\n%s", log.String())
	}

	// Within the interval nothing runs again; a new account does.
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, now.Add(time.Minute), enterprisehooks.Manifest{}, perUser, "")
	if len(requests) != 1 {
		t.Fatal("cleanup must be throttled")
	}
	accounts = append(accounts, enterprisehooks.UnixEligibleAccount{User: "bob", UID: 4242, GID: 4242, Home: "/home/alice", HomeInode: 7})
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, now.Add(2*time.Minute), enterprisehooks.Manifest{}, perUser, "")
	if len(requests) != 3 {
		t.Fatalf("a changed account list must run at once, got %d requests", len(requests))
	}
}

func TestStandaloneForeignCleanupBlocksPersonalClaudeWithoutManifestRow(t *testing.T) {
	previousCfg, previousManifest := cfg, enterpriseHookManifest
	previousMachinePolicy := enterpriseHookStandaloneMachinePolicySet
	previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
	t.Cleanup(func() {
		cfg, enterpriseHookManifest = previousCfg, previousManifest
		enterpriseHookStandaloneMachinePolicySet = previousMachinePolicy
		enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousLoad, previousCheck, previousRunner
		enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
		enterpriseHookForeignCleanupState.leftoversClean = false
	})
	enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
	enterpriseHookForeignCleanupState.leftoversClean = false
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"claudecode": {}}
	enterpriseHookStandaloneMachinePolicySet = func() map[string]struct{} { return map[string]struct{}{"claudecode": {}} }
	enterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
	home := t.TempDir()
	hooks := filepath.Join(home, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(hooks, "claude-code-hook.sh")
	old := []byte("#!/bin/sh\n# defenseclaw-managed-hook v7\necho 'gateway unreachable, allowing' >&2\nexit 0\n")
	if err := os.WriteFile(path, old, 0o700); err != nil {
		t.Fatal(err)
	}
	account := enterprisehooks.UnixEligibleAccount{User: "alice", UID: 4242, GID: 4242, Home: home, HomeInode: 7}
	enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) {
		return []enterprisehooks.UnixEligibleAccount{account}, nil
	}
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable, Inode: 7}
	}
	called := false
	enterpriseHookWorkerRunner = func(ctx context.Context, _ enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		for _, target := range request.Targets {
			if target.Mode == enterpriseHookWorkerModeBlockPersonalClaude {
				called = true
			}
		}
		return runEnterpriseHookWorkerApply(ctx, request), nil
	}
	now := time.Now()
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), io.Discard, now, enterprisehooks.Manifest{}, nil, "")
	if !called {
		t.Fatal("eligible user with no Claude manifest row did not get a blocking repair")
	}
	output, err := exec.Command("/bin/sh", path).CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 || !bytes.Contains(output, []byte("this computer is managed")) {
		t.Fatalf("personal hook exit=%v output=%q", err, output)
	}
	if err := os.WriteFile(path, old, 0o700); err != nil {
		t.Fatal(err)
	}
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), io.Discard, now.Add(enterpriseHookForeignCleanupInterval), enterprisehooks.Manifest{}, nil, "")
	output, err = exec.Command("/bin/sh", path).CombinedOutput()
	if !errors.As(err, &exit) || exit.ExitCode() != 2 || !bytes.Contains(output, []byte("this computer is managed")) {
		t.Fatalf("reverted personal hook exit=%v output=%q", err, output)
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
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &bytes.Buffer{}, time.Now(), enterprisehooks.Manifest{}, nil, "")
}

// GAP-1101: rows written as enrollment.mdx documents (user, or user_home,
// with the connector) carry no uid, gid or home. remove-all failed them, so
// uninstall stopped halfway; it now resolves them as reconcile does, and a
// row it cannot resolve is failed under a name, never an empty one.
func TestRemoveAllGroupsManifestTargetsPerAccount(t *testing.T) {
	previousCheck, previousGone := enterpriseHookCheckHome, enterpriseHookRecordedHomeGone
	t.Cleanup(func() {
		enterpriseHookCheckHome, enterpriseHookRecordedHomeGone = previousCheck, previousGone
		enterprisehooks.SetStandaloneResolver(nil)
	})
	// /home/pending is a home that is not available yet (an unmounted
	// volume), not one that is gone.
	enterpriseHookRecordedHomeGone = func(home string) bool { return home != "/home/pending" && previousGone(home) }
	enterpriseHookCheckHome = func(home string, _ int) enterprisehooks.HomeCheck {
		if home == "/home/pending" {
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomePending}
		}
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
	}
	ownHome := t.TempDir()
	accounts := map[string]unixidentity.Account{"bob": {Name: "bob", UID: 41002, GID: 20, Home: "/home/bob"}}
	if os.Getuid() > 0 {
		accounts["dana"] = unixidentity.Account{Name: "dana", UID: os.Getuid(), GID: os.Getgid(), Home: ownHome}
	}
	enterprisehooks.SetStandaloneResolver(standaloneTestResolver{accounts: accounts})
	uid := func(value int) *int { return &value }
	missingHome := filepath.Join(ownHome, "gone")
	// A home is gone only from a parent that still holds other entries: an
	// empty parent can be an unmounted volume (GAP-0443).
	if err := os.Mkdir(filepath.Join(ownHome, "other"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{
		{User: "alice", UserHome: "/home/alice", UID: uid(41001), GID: uid(41001), Connector: "codex"},
		{User: "alice", UserHome: "/home/alice", UID: uid(41001), GID: uid(41001), Connector: "devin", DataDir: "/home/alice/.dc"},
		{User: "carol", UserHome: "/home/pending", UID: uid(41003), GID: uid(41003), Connector: "codex"},
		{User: "legacy", UserHome: "/home/legacy", Connector: "codex"},
		{User: "bob", Connector: "claudecode", AgentVersion: "2.1.0"},
		{UserHome: ownHome, Connector: "claudecode"},
		{UserHome: missingHome, Connector: "claudecode"},
	}}
	jobs, pending, failed := enterpriseHookRemoveJobs(resolveEnterpriseHookRemoveRows(manifest))
	if len(jobs[41001].Request.Targets) != 2 {
		t.Fatalf("jobs %+v", jobs)
	}
	for _, target := range jobs[41001].Request.Targets {
		if target.Mode != enterpriseHookWorkerModeRemove || target.Options.UserHome != "/home/alice" {
			t.Fatalf("target %+v", target)
		}
	}
	if jobs[41001].Request.Targets[1].Options.DataDir != "/home/alice/.dc" || jobs[41001].Request.Targets[0].Options.DataDir != "/home/alice/.defenseclaw" {
		t.Fatalf("data dirs %+v", jobs[41001].Request.Targets)
	}
	if bob := jobs[41002]; bob == nil || bob.Account != (enterpriseHookWorkerAccount{UID: 41002, GID: 20, User: "bob", Home: "/home/bob"}) ||
		len(bob.Request.Targets) != 1 || bob.Request.Targets[0].Options.ConnectorName != "claudecode" {
		t.Fatalf("the user-only row did not resolve to bob's account: %+v", bob)
	}
	if os.Getuid() > 0 {
		if dana := jobs[os.Getuid()]; dana == nil || dana.Account.User != "dana" || dana.Account.Home != ownHome {
			t.Fatalf("the home-only row did not resolve to the home's owner: %+v", dana)
		}
	}
	// A home-only row whose home is gone is already clean: pending with the
	// reason, never a failure that refuses the uninstall (#1287).
	if len(pending) != 2 || pending[0] != "carol/codex" ||
		!strings.HasPrefix(pending[1], missingHome+"/claudecode: its home "+missingHome+" no longer exists") || len(failed) != 1 ||
		!strings.HasPrefix(failed[0], "legacy/codex: target account \"legacy\" does not exist") {
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
	addEnterpriseHookCopilotVSCodeRemovals(jobs, accounts, &enterpriseHookWorkerCopilotVSCode{HookBinary: "/opt/dc/bin/defenseclaw-hook", HookFile: true, Plugin: true},
		map[int][]string{502: {"/home/bob/.copilot", "/home/bob/.copilot/hooks"}})

	if len(jobs) != 2 || jobs[502] == nil || jobs[502].Account.Home != "/home/bob" {
		t.Fatalf("jobs = %+v, want alice's and bob's (carol's home is not available)", jobs)
	}
	for uid, job := range jobs {
		got := job.Request.CopilotVSCode
		if got == nil || got.HookBinary != "/opt/dc/bin/defenseclaw-hook" || got.HookFile || got.Plugin {
			t.Fatalf("uid %d: CopilotVSCode = %+v, want a removal for the hook binary", uid, got)
		}
	}
	// The folders the guardian created in bob's home go with his files.
	if got := jobs[502].Request.CopilotVSCode.RemoveDirs; len(got) != 2 || len(jobs[501].Request.CopilotVSCode.RemoveDirs) != 0 {
		t.Fatalf("RemoveDirs bob %v alice %v", got, jobs[501].Request.CopilotVSCode.RemoveDirs)
	}
}

// A deleted Copilot VS Code Local hook file is the guardian's to rewrite on
// its next pass (WIN-R1-25, #1055), not after the cleanup interval; one it
// could not rewrite waits for the interval.
func TestStandaloneForeignCleanupRewritesADeletedCopilotLocalHookFileAtOnce(t *testing.T) {
	previousCfg := cfg
	previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousLoad, previousCheck, previousRunner
		enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
		enterpriseHookForeignCleanupState.unrepaired = nil
	})
	enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{
			Profile:       managed.ProfileStandalone,
			MachinePolicy: config.EnterpriseMachinePolicyConfig{Connectors: map[string]config.EnterpriseConnectorPolicy{"copilot": {}}},
		},
	}
	useStandaloneForeignHookFenceFixture(t)
	home := t.TempDir()
	enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) {
		return []enterprisehooks.UnixEligibleAccount{{User: "alice", UID: 4242, GID: 4242, Home: home}}, nil
	}
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
	}
	runs := 0
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		runs++
		request.Home = account.Home // as the worker spawn does
		return enterpriseHookWorkerResponse{CopilotVSCode: runEnterpriseHookWorkerCopilotVSCode(request)}, nil
	}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &bytes.Buffer{}, now, enterprisehooks.Manifest{}, nil, "")
	hookFile := enterprisepolicy.CopilotVSCodeLocalHookFilePath(home)
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &bytes.Buffer{}, now.Add(time.Minute), enterprisehooks.Manifest{}, nil, "")
	if _, err := os.Stat(hookFile); err != nil || runs != 1 {
		t.Fatalf("first pass must place the file and the next stay idle: runs=%d err=%v", runs, err)
	}
	if err := os.Remove(hookFile); err != nil {
		t.Fatal(err)
	}
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &bytes.Buffer{}, now.Add(2*time.Minute), enterprisehooks.Manifest{}, nil, "")
	if _, err := os.Stat(hookFile); err != nil || runs != 2 {
		t.Fatalf("a deleted hook file must be rewritten on the next pass: runs=%d err=%v", runs, err)
	}
	// One the worker cannot rewrite waits for the interval, not every pass.
	enterpriseHookWorkerRunner = func(context.Context, enterpriseHookWorkerAccount, enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		runs++
		return enterpriseHookWorkerResponse{}, nil
	}
	if err := os.Remove(hookFile); err != nil {
		t.Fatal(err)
	}
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &bytes.Buffer{}, now.Add(3*time.Minute), enterprisehooks.Manifest{}, nil, "")
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &bytes.Buffer{}, now.Add(4*time.Minute), enterprisehooks.Manifest{}, nil, "")
	if runs != 3 {
		t.Fatalf("an unrepaired hook file must not re-run the cleanup every pass: runs=%d", runs)
	}
}

func TestStandaloneCopilotKeptIndependentHookDoesNotClaimCoverage(t *testing.T) {
	previousCfg, previousManifest := cfg, enterpriseHookManifest
	previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
	previousRecordLoad, previousRecordWrite := enterpriseHookLoadCopilotVSCodeAccounts, enterpriseHookWriteCopilotVSCodeAccounts
	t.Cleanup(func() {
		cfg, enterpriseHookManifest = previousCfg, previousManifest
		enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousLoad, previousCheck, previousRunner
		enterpriseHookLoadCopilotVSCodeAccounts, enterpriseHookWriteCopilotVSCodeAccounts = previousRecordLoad, previousRecordWrite
		enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
		enterpriseHookForeignCleanupState.leftoversClean = false
	})
	enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
	enterpriseHookForeignCleanupState.leftoversClean = false
	cfg = &config.Config{DataDir: useUserCleanupStateDir(t), DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"copilot": {}}
	useStandaloneForeignHookFenceFixture(t)
	enterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
	home := t.TempDir()
	account := enterprisehooks.UnixEligibleAccount{User: "alice", UID: 4242, GID: 4242, Home: home}
	enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) {
		return []enterprisehooks.UnixEligibleAccount{account}, nil
	}
	enterpriseHookLoadCopilotVSCodeAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) { return nil, nil }
	var recorded []enterprisehooks.UnixEligibleAccount
	enterpriseHookWriteCopilotVSCodeAccounts = func(_ string, accounts []enterprisehooks.UnixEligibleAccount) error {
		recorded = accounts
		return nil
	}
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
	}
	enterpriseHookWorkerRunner = func(_ context.Context, worker enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		if request.CopilotVSCode == nil || !request.CopilotVSCode.HookFile {
			t.Fatalf("guardian omitted the required Local hook for %s", worker.User)
		}
		response := enterpriseHookWorkerResponse{CopilotVSCode: &enterpriseHookWorkerCopilotVSCodeReport{
			Kept: []string{enterprisepolicy.CopilotVSCodeLocalHookFilePath(worker.Home)},
		}}
		for _, target := range request.Targets {
			response.Targets = append(response.Targets, enterpriseHookWorkerTargetResult{Index: target.Index, OK: true})
		}
		return response, nil
	}
	var log bytes.Buffer
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, time.Now(), enterprisehooks.Manifest{}, nil, "")
	if enterpriseHookForeignCleanupState.leftoversClean || len(recorded) != 0 {
		t.Fatalf("guardian claimed Local hook coverage after preserving an independent handler: clean=%t recorded=%v log=%s",
			enterpriseHookForeignCleanupState.leftoversClean, recorded, log.String())
	}
}

func TestStandaloneForeignCleanupRemovesVSCodeHooksOfAccountsNoLongerEligible(t *testing.T) {
	previousCfg, previousManifest := cfg, enterpriseHookManifest
	previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
	previousLoadVSCode, previousWriteVSCode := enterpriseHookLoadCopilotVSCodeAccounts, enterpriseHookWriteCopilotVSCodeAccounts
	t.Cleanup(func() {
		cfg, enterpriseHookManifest = previousCfg, previousManifest
		enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousLoad, previousCheck, previousRunner
		enterpriseHookLoadCopilotVSCodeAccounts, enterpriseHookWriteCopilotVSCodeAccounts = previousLoadVSCode, previousWriteVSCode
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
	useStandaloneForeignHookFenceFixture(t)
	enterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
	// The record lives in the guardian's authorization directory: the
	// guardian service cannot write the manifest folder (ReadOnlyPaths=
	// /etc/defenseclaw), so a record next to the manifest was never written.
	stateRoot := t.TempDir()
	cfg.DataDir = filepath.Join(stateRoot, "var", "lib", "defenseclaw")
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	guardianRoot := filepath.Join(stateRoot, "var", "lib", "defenseclaw-hook-guardian")
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianRoot)
	recordPath := filepath.Join(guardianRoot, enterprisehooks.UnixCopilotVSCodeAccountsFileName)
	alice := enterprisehooks.UnixEligibleAccount{User: "alice", UID: 4242, GID: 4242, Home: "/home/alice", HomeInode: 7}
	// dave got the VS Code Local files while eligible, then was excluded.
	dave := enterprisehooks.UnixEligibleAccount{User: "dave", UID: 4343, GID: 4343, Home: "/home/dave", HomeInode: 7,
		CreatedDirs: []string{"/home/dave/.copilot", "/home/dave/.copilot/hooks"}}
	enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) {
		return []enterprisehooks.UnixEligibleAccount{alice}, nil
	}
	enterpriseHookLoadCopilotVSCodeAccounts = func(path string) ([]enterprisehooks.UnixEligibleAccount, error) {
		switch path {
		case recordPath:
			return []enterprisehooks.UnixEligibleAccount{alice, dave}, nil
		case "/etc/defenseclaw/hook-guardian/" + enterprisehooks.UnixCopilotVSCodeAccountsFileName:
			return nil, nil // an earlier build's place, merged when present
		}
		t.Errorf("VS Code accounts record read from %s", path)
		return nil, nil
	}
	var written []enterprisehooks.UnixEligibleAccount
	enterpriseHookWriteCopilotVSCodeAccounts = func(path string, accounts []enterprisehooks.UnixEligibleAccount) error {
		if path != recordPath {
			t.Errorf("VS Code accounts record written to %s, want %s", path, recordPath)
		}
		written = accounts
		return nil
	}
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable, Inode: 7}
	}
	var mu sync.Mutex
	requests := map[string]enterpriseHookWorkerRequest{}
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		mu.Lock()
		defer mu.Unlock()
		requests[account.User] = request
		response := enterpriseHookWorkerResponse{}
		for _, target := range request.Targets {
			response.Targets = append(response.Targets, enterpriseHookWorkerTargetResult{Index: target.Index, OK: true})
		}
		if request.CopilotVSCode != nil {
			response.CopilotVSCode = &enterpriseHookWorkerCopilotVSCodeReport{Removed: []string{account.Home + "/.copilot/hooks/defenseclaw-vscode.json"}}
		}
		return response, nil
	}
	var log bytes.Buffer
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC), enterprisehooks.Manifest{}, nil, "")
	if got := requests["dave"].CopilotVSCode; got == nil || len(got.RemoveDirs) != 2 {
		t.Fatalf("dave's removal %+v, want the folders the guardian created in his home", got)
	}

	got, ok := requests["dave"]
	if !ok || got.CopilotVSCode == nil || got.CopilotVSCode.HookFile || got.CopilotVSCode.Plugin ||
		!strings.HasSuffix(got.CopilotVSCode.HookBinary, "/defenseclaw-hook") || len(got.ForeignCleanup) != 0 || len(got.Targets) != 0 {
		t.Fatalf("dave's request %+v, want only the VS Code Local removal; log:\n%s", got, log.String())
	}
	if !strings.Contains(log.String(), "removed DefenseClaw's VS Code Local hooks for dave") {
		t.Fatalf("log:\n%s", log.String())
	}
	// Copilot is no longer governed: both the excluded and still eligible
	// account lose its Local hooks, leaving no accounts to record.
	if got := requests["alice"].CopilotVSCode; got == nil || got.HookFile || got.Plugin {
		t.Fatalf("alice's removal %+v", got)
	}
	if len(written) != 0 {
		t.Fatalf("record written %+v after removal", written)
	}
	// A governed pass records the folders each write created (only below
	// that home) and keeps the ones recorded before.
	governedNext := nextCopilotVSCodeAccounts([]enterprisehooks.UnixEligibleAccount{dave}, []enterprisehooks.UnixEligibleAccount{alice, {User: "dave", UID: 4343, GID: 4343, Home: "/home/dave", HomeInode: 7}}, true, map[int]bool{},
		map[int][]string{4242: {"/home/alice/.copilot", "/etc/elsewhere"}})
	if len(governedNext) != 2 || !slices.Equal(governedNext[0].CreatedDirs, []string{"/home/alice/.copilot"}) || len(governedNext[1].CreatedDirs) != 2 {
		t.Fatalf("governed record %+v", governedNext)
	}
	if sameCopilotVSCodeAccounts([]enterprisehooks.UnixEligibleAccount{alice}, governedNext[:1]) {
		t.Fatal("a record that gained created folders must be rewritten")
	}

	// While the Local harness is governed every eligible account is recorded.
	next := nextCopilotVSCodeAccounts(nil, []enterprisehooks.UnixEligibleAccount{alice, dave}, true, map[int]bool{}, nil)
	if len(next) != 2 {
		t.Fatalf("governed record %+v", next)
	}
	if len(nextCopilotVSCodeAccounts(next, nil, false, map[int]bool{4242: true, 4343: true}, nil)) != 0 {
		t.Fatal("removed accounts must leave the record")
	}
}

func TestStandaloneCopilotVSCodeWritesOnlyToEnrolledAccounts(t *testing.T) {
	for _, tc := range []struct {
		name        string
		unenrolled  string
		disabledRow bool
		want        map[string]bool
	}{
		{name: "inspect without machine policy rows", unenrolled: config.EnterpriseUnenrolledInspect,
			want: map[string]bool{"alice": true, "bob": false, "carol": true}},
		{name: "deny requires a Copilot row", unenrolled: config.EnterpriseUnenrolledDeny,
			want: map[string]bool{"alice": true, "bob": false, "carol": false}},
		{name: "deny ignores a disabled Copilot row", unenrolled: config.EnterpriseUnenrolledDeny, disabledRow: true,
			want: map[string]bool{"alice": true, "bob": false, "carol": false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previousCfg, previousManifest := cfg, enterpriseHookManifest
			previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
			previousLoadVSCode, previousWriteVSCode := enterpriseHookLoadCopilotVSCodeAccounts, enterpriseHookWriteCopilotVSCodeAccounts
			t.Cleanup(func() {
				cfg, enterpriseHookManifest = previousCfg, previousManifest
				enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousLoad, previousCheck, previousRunner
				enterpriseHookLoadCopilotVSCodeAccounts, enterpriseHookWriteCopilotVSCodeAccounts = previousLoadVSCode, previousWriteVSCode
				enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
				enterpriseHookForeignCleanupState.leftoversClean = false
				enterpriseHookForeignCleanupState.unrepaired = nil
			})
			enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
			enterpriseHookForeignCleanupState.leftoversClean = false
			enterpriseHookForeignCleanupState.unrepaired = nil
			cfg = &config.Config{DataDir: useUserCleanupStateDir(t), DeploymentMode: managed.DeploymentModeManagedEnterprise}
			cfg.Enterprise.Profile = managed.ProfileStandalone
			cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"copilot": {}}
			cfg.Enterprise.Enrollment.UnenrolledUsers = tc.unenrolled
			cfg.Enterprise.Enrollment.ExcludeUsers = []string{"4202"}
			useStandaloneForeignHookFenceFixture(t)
			enterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
			accounts := []enterprisehooks.UnixEligibleAccount{
				{User: "alice", UID: 4201, GID: 4201, Home: "/home/alice", HomeInode: 7},
				// The eligible record is stale after an administrator excludes bob.
				{User: "bob", UID: 4202, GID: 4202, Home: "/home/bob", HomeInode: 7},
				{User: "carol", UID: 4203, GID: 4203, Home: "/home/carol", HomeInode: 7},
			}
			enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) { return accounts, nil }
			enterpriseHookLoadCopilotVSCodeAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) { return accounts, nil }
			var written []enterprisehooks.UnixEligibleAccount
			enterpriseHookWriteCopilotVSCodeAccounts = func(_ string, next []enterprisehooks.UnixEligibleAccount) error {
				written = next
				return nil
			}
			enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
				return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable, Inode: 7}
			}
			var mu sync.Mutex
			requests := map[string]*enterpriseHookWorkerCopilotVSCode{}
			enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
				mu.Lock()
				requests[account.User] = request.CopilotVSCode
				mu.Unlock()
				report := &enterpriseHookWorkerCopilotVSCodeReport{}
				if request.CopilotVSCode != nil && !request.CopilotVSCode.HookFile {
					report.Removed = []string{account.Home + "/.copilot/hooks/defenseclaw-vscode.json"}
				}
				return enterpriseHookWorkerResponse{CopilotVSCode: report}, nil
			}
			aliceUID := 4201
			manifest := enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{{User: "alice", UID: &aliceUID, Connector: "copilot"}}}
			if tc.disabledRow {
				carolUID, disabled := 4203, false
				manifest.Targets = append(manifest.Targets, enterprisehooks.ManifestTarget{
					User: "carol", UID: &carolUID, Connector: "copilot", Enabled: &disabled,
				})
			}
			runEnterpriseHookStandaloneForeignCleanup(context.Background(), io.Discard, time.Now(), manifest, nil, "")
			for user, want := range tc.want {
				request := requests[user]
				if request == nil || request.HookFile != want || request.Plugin && !want {
					t.Errorf("%s VS Code request %+v, want hook file=%t", user, request, want)
				}
			}
			wantCount := 0
			for _, scoped := range tc.want {
				if scoped {
					wantCount++
				}
			}
			for _, account := range written {
				if !tc.want[account.User] {
					t.Errorf("VS Code accounts record retained out-of-scope %s", account.User)
				}
			}
			if len(written) != wantCount {
				t.Errorf("VS Code accounts record %+v does not match scope %+v", written, tc.want)
			}
		})
	}
}

func TestStandaloneForeignCleanupRemovesVSCodeHooksWhenCopilotIsRemoved(t *testing.T) {
	previousCfg, previousManifest := cfg, enterpriseHookManifest
	previousLoad, previousVSCodeLoad := enterpriseHookLoadEligibleAccounts, enterpriseHookLoadCopilotVSCodeAccounts
	previousCheck, previousRunner := enterpriseHookCheckHome, enterpriseHookWorkerRunner
	t.Cleanup(func() {
		cfg, enterpriseHookManifest = previousCfg, previousManifest
		enterpriseHookLoadEligibleAccounts, enterpriseHookLoadCopilotVSCodeAccounts = previousLoad, previousVSCodeLoad
		enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousCheck, previousRunner
		enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
		enterpriseHookForeignCleanupState.leftoversClean = false
		enterpriseHookForeignCleanupState.unrepaired = nil
	})
	enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
	root := t.TempDir()
	cfg = &config.Config{DataDir: root, DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone,
			MachinePolicy: config.EnterpriseMachinePolicyConfig{Connectors: map[string]config.EnterpriseConnectorPolicy{"cursor": {}}}}}
	enterpriseHookManifest = filepath.Join(root, "manifest", "targets.yaml")
	authDir := filepath.Join(root, "auth")
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, authDir)
	if err := os.MkdirAll(authDir, 0o700); err != nil {
		t.Fatal(err)
	}
	recordPath := enterpriseHookCopilotVSCodeAccountsPath(enterpriseHookManifest)
	if err := os.WriteFile(recordPath, []byte("record"), 0o600); err != nil {
		t.Fatal(err)
	}
	removal, err := enterpriseHookCopilotVSCodeRemoval()
	if err != nil {
		t.Fatal(err)
	}
	eligible := enterprisehooks.UnixEligibleAccount{User: "alice", UID: 4242, GID: 4242, Home: filepath.Join(root, "alice")}
	excluded := enterprisehooks.UnixEligibleAccount{User: "bob", UID: 4343, GID: 4343, Home: filepath.Join(root, "bob")}
	prior := enterprisehooks.UnixEligibleAccount{User: "charlie", UID: 4444, GID: 4444, Home: filepath.Join(root, "charlie")}
	for _, account := range []enterprisehooks.UnixEligibleAccount{eligible, excluded, prior} {
		if err := os.MkdirAll(account.Home, 0o700); err != nil {
			t.Fatal(err)
		}
		result, err := enterprisepolicy.EnsureCopilotVSCodeUser(enterprisepolicy.CopilotVSCodeUserRequest{
			Home: account.Home, GOOS: runtime.GOOS, HookBinary: removal.HookBinary, HookFile: true, Plugin: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		switch account.User {
		case "alice":
			eligible.CreatedDirs = result.CreatedDirs
		case "bob":
			excluded.CreatedDirs = result.CreatedDirs
		}
	}
	enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) {
		return []enterprisehooks.UnixEligibleAccount{eligible, prior}, nil
	}
	enterpriseHookLoadCopilotVSCodeAccounts = func(path string) ([]enterprisehooks.UnixEligibleAccount, error) {
		if path == recordPath {
			return []enterprisehooks.UnixEligibleAccount{eligible, excluded}, nil
		}
		return nil, nil
	}
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
	}
	var mu sync.Mutex
	requested := map[string]bool{}
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		mu.Lock()
		requested[account.User] = request.CopilotVSCode != nil
		mu.Unlock()
		response := enterpriseHookWorkerResponse{}
		for _, target := range request.Targets {
			response.Targets = append(response.Targets, enterpriseHookWorkerTargetResult{Index: target.Index, OK: true})
		}
		if request.CopilotVSCode != nil {
			request.Home = account.Home
			response.CopilotVSCode = runEnterpriseHookWorkerCopilotVSCode(request)
		}
		return response, nil
	}
	var log bytes.Buffer
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, time.Now(), enterprisehooks.Manifest{}, nil, "")
	for _, account := range []enterprisehooks.UnixEligibleAccount{eligible, excluded, prior} {
		if !requested[account.User] {
			t.Errorf("%s did not get a VS Code Local removal request: %s", account.User, log.String())
		}
		for _, path := range []string{enterprisepolicy.CopilotVSCodeLocalHookFilePath(account.Home), enterprisepolicy.CopilotPluginDir(account.Home)} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s remains after removal: %v", path, err)
			}
		}
		if account.User != prior.User {
			for _, dir := range account.CreatedDirs {
				if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("guardian-created directory %s remains: %v", dir, err)
				}
			}
		}
	}
	if _, err := os.Lstat(recordPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("VS Code Local accounts record remains: %v", err)
	}
}
