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
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// rel-1-0-4 RB1-1: every uninstall, purge or not, removes the Claude Code
// blocker the enrollment wrote for each eligible account, after the
// account's removals and before its purge, whether or not a manifest row
// names the account.
func TestRemoveAllUnblocksPersonalClaudeForEveryAccount(t *testing.T) {
	previousCheck := enterpriseHookCheckHome
	t.Cleanup(func() { enterpriseHookCheckHome = previousCheck })
	enterpriseHookCheckHome = func(home string, _ int) enterprisehooks.HomeCheck {
		if home == "/home/gone" {
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomePending}
		}
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
	}
	alice := newEnterpriseHookRemoveJob(enterpriseHookWorkerAccount{UID: 501, GID: 20, User: "alice", Home: "/home/alice"})
	alice.Request.Targets = append(alice.Request.Targets, enterpriseHookWorkerTarget{Index: 4, Mode: enterpriseHookWorkerModeRemove,
		Options: enterpriseHookWorkerOptions{ConnectorName: "claudecode", UserHome: "/home/alice", OwnerUID: 501, OwnerGID: 20}})
	jobs := map[int]*enterpriseHookWorkerJob{501: alice}
	addEnterpriseHookPersonalClaudeUnblocks(jobs, []enterprisehooks.UnixEligibleAccount{
		{User: "alice", UID: 501, GID: 20, Home: "/home/alice"},
		{User: "bob", UID: 502, GID: 20, Home: "/home/bob"},
		{User: "carol", UID: 503, GID: 20, Home: "/home/gone"},
	})
	if len(jobs) != 2 || jobs[503] != nil {
		t.Fatalf("jobs = %+v, want alice's and bob's (carol's home is not available)", jobs)
	}
	seen := map[int]bool{}
	for uid, job := range jobs {
		last := job.Request.Targets[len(job.Request.Targets)-1]
		if last.Mode != enterpriseHookWorkerModeUnblockPersonalClaude || last.Options.UserHome != job.Account.Home ||
			last.Options.OwnerUID != uid || last.Options.DataDir != filepath.Join(job.Account.Home, ".defenseclaw") || last.Index <= 4 || seen[last.Index] {
			t.Fatalf("uid %d: last target %+v", uid, last)
		}
		seen[last.Index] = true
	}
	if len(jobs[502].Request.Targets) != 1 || jobs[502].Account.User != "bob" {
		t.Fatalf("bob's job %+v", jobs[502])
	}
	report := enterpriseHooksRemoveAllReport{}
	addEnterpriseHookRemoveRuns(&report, []enterpriseHookWorkerOutcome{{Job: *jobs[502], Response: enterpriseHookWorkerResponse{
		Targets: []enterpriseHookWorkerTargetResult{{Index: jobs[502].Request.Targets[0].Index, OK: true}},
	}}})
	if report.Removed != 0 || len(report.Failed) != 0 {
		t.Fatalf("an account without a blocker is reported %+v", report)
	}
}

// The worker removes the exact blocker that enrollment mode writes, before
// a purge that keeps the account's own install, and nothing else.
func TestWorkerUnblockPersonalClaudeRemovesTheEnrollmentBlocker(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	script := filepath.Join(dataDir, "hooks", "claude-code-hook.sh")
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	personal := "#!/bin/bash\n# defenseclaw-managed-hook v3\nexec defenseclaw-hook claude-code\n"
	if err := os.WriteFile(script, []byte(personal), 0o700); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	options := enterpriseHookWorkerOptions{ConnectorName: "claudecode", UserHome: home, OwnerUID: uid, OwnerGID: gid}
	if response := runEnterpriseHookWorkerApply(context.Background(), enterpriseHookWorkerRequest{Home: home, UID: uid, GID: gid,
		Targets: []enterpriseHookWorkerTarget{{Index: 0, Mode: enterpriseHookWorkerModeBlockPersonalClaude, Options: options}}}); !response.Targets[0].OK {
		t.Fatalf("block response %+v", response)
	}
	if got, _ := os.ReadFile(script); string(got) != enterprisehooks.PersonalClaudeHookBlocker {
		t.Fatalf("enrollment wrote %q, want the blocker", got)
	}

	previousPurger, previousStop := enterpriseHookWorkerPurger, enterpriseHookWorkerStopPerUser
	t.Cleanup(func() { enterpriseHookWorkerPurger, enterpriseHookWorkerStopPerUser = previousPurger, previousStop })
	enterpriseHookWorkerStopPerUser = func(enterprisehooks.InstallOptions) (bool, error) { return false, nil }
	blockerAtPurge := true
	enterpriseHookWorkerPurger = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.PurgeSummary, error) {
		_, err := os.Lstat(script)
		blockerAtPurge = !errors.Is(err, os.ErrNotExist)
		return enterprisehooks.PurgeSummary{Kept: true}, nil
	}
	request := enterpriseHookWorkerRequest{Home: home, UID: uid, GID: gid, Targets: []enterpriseHookWorkerTarget{
		{Index: 1, Mode: enterpriseHookWorkerModeUnblockPersonalClaude, Options: enterpriseHookWorkerOptions{ConnectorName: "claudecode", UserHome: home, OwnerUID: uid, OwnerGID: gid, DataDir: dataDir}},
		{Index: 2, Mode: enterpriseHookWorkerModePurge, Options: enterpriseHookWorkerOptions{UserHome: home, OwnerUID: uid, OwnerGID: gid, DataDir: dataDir}},
	}}
	response := runEnterpriseHookWorkerApply(context.Background(), request)
	if len(response.Targets) != 2 || !response.Targets[0].OK || !response.Targets[0].Removed || response.Targets[0].Result != nil || !response.Targets[1].OK {
		t.Fatalf("unblock response %+v", response)
	}
	if blockerAtPurge {
		t.Fatal("the blocker was still in place when the purge ran")
	}

	// The account's own script is not the blocker: it stays.
	if err := os.WriteFile(script, []byte(personal), 0o700); err != nil {
		t.Fatal(err)
	}
	response = runEnterpriseHookWorkerApply(context.Background(), request)
	if !response.Targets[0].OK || response.Targets[0].Removed {
		t.Fatalf("personal script response %+v", response)
	}
	if got, _ := os.ReadFile(script); string(got) != personal {
		t.Fatalf("the account's own script changed: %q", got)
	}
}
