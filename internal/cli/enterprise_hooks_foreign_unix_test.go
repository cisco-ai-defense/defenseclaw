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
	"slices"
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
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &bytes.Buffer{}, now, nil)
	hookFile := enterprisepolicy.CopilotVSCodeLocalHookFilePath(home)
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &bytes.Buffer{}, now.Add(time.Minute), nil)
	if _, err := os.Stat(hookFile); err != nil || runs != 1 {
		t.Fatalf("first pass must place the file and the next stay idle: runs=%d err=%v", runs, err)
	}
	if err := os.Remove(hookFile); err != nil {
		t.Fatal(err)
	}
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &bytes.Buffer{}, now.Add(2*time.Minute), nil)
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
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &bytes.Buffer{}, now.Add(3*time.Minute), nil)
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &bytes.Buffer{}, now.Add(4*time.Minute), nil)
	if runs != 3 {
		t.Fatalf("an unrepaired hook file must not re-run the cleanup every pass: runs=%d", runs)
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
	enterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
	// The record lives in the guardian's authorization directory: the
	// guardian service cannot write the manifest folder (ReadOnlyPaths=
	// /etc/defenseclaw), so a record next to the manifest was never written.
	cfg.DataDir = "/var/lib/defenseclaw"
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, "/var/lib/defenseclaw-hook-guardian")
	recordPath := "/var/lib/defenseclaw-hook-guardian/" + enterprisehooks.UnixCopilotVSCodeAccountsFileName
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
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC), nil)
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
	// dave leaves the record once removed; alice stays recorded.
	if len(written) != 1 || written[0].User != "alice" {
		t.Fatalf("record written %+v, want alice only", written)
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
