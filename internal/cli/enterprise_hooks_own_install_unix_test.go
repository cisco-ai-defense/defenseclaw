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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// rel-1-0-6 GAP-0178: the enrollment's Claude Code blocker keeps the
// account's own hook script, bytes and mode, and the uninstall's unblock
// puts it back instead of leaving a missing script.
func TestBlockingThePersonalClaudeHookKeepsTheOwnScriptForTheUninstall(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	path := filepath.Join(dataDir, "hooks", "claude-code-hook.sh")
	own := []byte("#!/bin/sh\n# defenseclaw-managed-hook v7\necho own >&2\nexit 0\n")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, own, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := blockPersonalClaudeHook(enterprisehooks.InstallOptions{ConnectorName: "claudecode", UserHome: home}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != enterprisehooks.PersonalClaudeHookBlocker {
		t.Fatalf("the blocker is not in place: %q", got)
	}
	removed, restored, err := enterprisehooks.UnblockPersonalClaudeHook(dataDir)
	if err != nil || !removed || !restored {
		t.Fatalf("unblock = %t, %t, %v; want the own script back", removed, restored, err)
	}
	info, err := os.Stat(path)
	got, _ := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, own) || info.Mode().Perm() != 0o750 {
		t.Fatalf("the own script is not back byte for byte: %q %v", got, err)
	}
}

// Every remove-all job ends with the own install put-back, after its purge;
// an account a pending cleanup keeps gets none.
func TestRemoveAllEndsEveryJobWithTheOwnInstallPutBack(t *testing.T) {
	jobs := map[int]*enterpriseHookWorkerJob{
		1001: newEnterpriseHookRemoveJob(enterpriseHookWorkerAccount{UID: 1001, GID: 1001, User: "sample-a", Home: "/home/sample-a"}),
		1002: newEnterpriseHookRemoveJob(enterpriseHookWorkerAccount{UID: 1002, GID: 1002, User: "sample-b", Home: "/home/sample-b"}),
	}
	jobs[1001].Request.Targets = append(jobs[1001].Request.Targets, enterpriseHookWorkerTarget{Index: 4, Mode: enterpriseHookWorkerModePurge})
	addEnterpriseHookOwnInstallRestores(jobs, map[int]string{1002: enterpriseHookPurgeSkipPending})
	targets := jobs[1001].Request.Targets
	last := targets[len(targets)-1]
	if last.Mode != enterpriseHookWorkerModeRestoreOwnInstall || last.Index <= 4 || last.Options.DataDir != "/home/sample-a/.defenseclaw" {
		t.Fatalf("the job does not end with the put-back: %+v", targets)
	}
	for _, target := range jobs[1002].Request.Targets {
		if target.Mode == enterpriseHookWorkerModeRestoreOwnInstall {
			t.Fatalf("an account a pending cleanup keeps got the put-back: %+v", target)
		}
	}
}

// ownInstallHermesHome is an account with its own per-user install whose
// Hermes registration the enrollment reused: the config is kept in the own
// install snapshot and its backup record names it.
func ownInstallHermesHome(t *testing.T) (home, dataDir string) {
	t.Helper()
	home = t.TempDir()
	dataDir = filepath.Join(home, ".defenseclaw")
	config := filepath.Join(home, ".hermes", "config.yaml")
	record, err := json.Marshal(map[string]any{"version": 1, "connector": "hermes", "logical_name": "config.yaml", "path": config, "existed": true, "pristine_sha256": "0"})
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		filepath.Join(dataDir, "config.yaml"):                                     "gateway: {}\n",
		filepath.Join(dataDir, "connector_backups", "hermes", "config.yaml.json"): string(record),
		config: "hooks:\n  pre_tool_call: own\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := enterprisehooks.PreserveOwnInstall(home, dataDir); err != nil {
		t.Fatal(err)
	}
	return home, dataDir
}

// rel-1-0-6 GAP-0178: an uninstall job that puts the own install back leaves
// the Hermes registration the enrollment reused from that install in place
// (its config is as the install had it); a job without the put-back tears
// it down as before.
func TestUninstallLeavesARegistrationReusedFromTheOwnInstall(t *testing.T) {
	home, dataDir := ownInstallHermesHome(t)
	previous := enterpriseHookWorkerRemover
	t.Cleanup(func() { enterpriseHookWorkerRemover = previous })
	calls := 0
	enterpriseHookWorkerRemover = func(context.Context, enterprisehooks.InstallOptions) error { calls++; return nil }
	remove := enterpriseHookWorkerTarget{Index: 0, Mode: enterpriseHookWorkerModeRemove, Options: enterpriseHookWorkerOptions{
		ConnectorName: "hermes", UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), DataDir: dataDir}}
	uninstall := enterpriseHookWorkerRequest{Standalone: true, Home: home, UID: os.Getuid(), GID: os.Getgid(), Targets: []enterpriseHookWorkerTarget{remove}}
	result := runEnterpriseHookWorkerApply(context.Background(), uninstall).Targets[0]
	if calls != 1 || result.OwnInstall {
		t.Fatalf("a removal without the put-back must tear down: calls=%d %+v", calls, result)
	}
	calls = 0
	uninstall.Targets = append(uninstall.Targets, enterpriseHookWorkerTarget{Index: 1, Mode: enterpriseHookWorkerModeRestoreOwnInstall,
		Options: enterpriseHookWorkerOptions{UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), DataDir: dataDir}})
	results := runEnterpriseHookWorkerApply(context.Background(), uninstall).Targets
	if calls != 0 || !results[0].OK || !results[0].OwnInstall || !results[1].OK || !results[1].Removed {
		t.Fatalf("the reused registration was torn down or the put-back did not run: calls=%d %+v", calls, results)
	}
}

// The purge keeps the per-user gateway of an account whose folder holds
// its own install running; any other account's gateway is stopped first.
func TestPurgeKeepsTheGatewayOfAnOwnInstallRunning(t *testing.T) {
	home, dataDir := ownInstallHermesHome(t)
	previousStop, previousPurger := enterpriseHookWorkerStopPerUser, enterpriseHookWorkerPurger
	t.Cleanup(func() { enterpriseHookWorkerStopPerUser, enterpriseHookWorkerPurger = previousStop, previousPurger })
	stops := 0
	enterpriseHookWorkerStopPerUser = func(enterprisehooks.InstallOptions) (bool, error) { stops++; return true, nil }
	enterpriseHookWorkerPurger = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.PurgeSummary, error) {
		return enterprisehooks.PurgeSummary{Kept: true}, nil
	}
	purge := func(dir string) enterpriseHookWorkerRequest {
		return enterpriseHookWorkerRequest{Home: home, UID: os.Getuid(), GID: os.Getgid(), Targets: []enterpriseHookWorkerTarget{{Index: 0, Mode: enterpriseHookWorkerModePurge,
			Options: enterpriseHookWorkerOptions{UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), DataDir: dir}}}}
	}
	if result := runEnterpriseHookWorkerApply(context.Background(), purge(dataDir)).Targets[0]; stops != 0 || !result.OK || result.Purged.Gateway {
		t.Fatalf("the own install's gateway was stopped: stops=%d %+v", stops, result)
	}
	other := filepath.Join(t.TempDir(), ".defenseclaw")
	if err := os.MkdirAll(filepath.Join(other, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if result := runEnterpriseHookWorkerApply(context.Background(), purge(other)).Targets[0]; stops != 1 || !result.OK {
		t.Fatalf("a folder without an own install must stop the gateway first: stops=%d %+v", stops, result)
	}
}
