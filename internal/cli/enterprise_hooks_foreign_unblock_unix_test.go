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
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// foreignCleanupRealWorkerPass is a standalone guardian whose machine policy
// removes Cursor's foreign hooks and covers Claude Code only when
// claudeManaged, with this process's account as the one eligible account
// and the real worker process (enterpriseHookWorkerMain) as its worker, so
// the worker's own request checks run on every job the pass builds.
func foreignCleanupRealWorkerPass(t *testing.T, claudeManaged bool) string {
	t.Helper()
	useEnterpriseHookWorkerHelper(t, "real")
	previousManifest, previousMachinePolicy := enterpriseHookManifest, enterpriseHookStandaloneMachinePolicySet
	previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
	t.Cleanup(func() {
		enterpriseHookManifest, enterpriseHookStandaloneMachinePolicySet = previousManifest, previousMachinePolicy
		enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousLoad, previousCheck, previousRunner
		enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
		enterpriseHookForeignCleanupState.leftoversClean = false
		enterpriseHookForeignCleanupState.unrepaired = nil
	})
	enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
	enterpriseHookForeignCleanupState.leftoversClean = false
	policy := map[string]config.EnterpriseConnectorPolicy{"cursor": {}}
	published := map[string]struct{}{"cursor": {}}
	if claudeManaged {
		published[enterprisepolicy.ConnectorClaudeCode] = struct{}{}
	}
	useForeignHookGuardian(t, policy)
	enterpriseHookStandaloneMachinePolicySet = func() map[string]struct{} { return published }
	enterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
	account := selfWorkerAccount(t)
	enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) {
		return []enterprisehooks.UnixEligibleAccount{{User: account.User, UID: account.UID, GID: account.GID, Home: account.Home}}, nil
	}
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
	}
	enterpriseHookWorkerRunner = runEnterpriseHookWorker
	return account.Home
}

// GAP-1829 and R3-1: while the device stays managed and the machine policy
// no longer covers Claude Code, the guardian's foreign cleanup removes the
// blocker an earlier pass wrote over an account's own hook script, and
// nothing else. The real worker takes that target next to the job's other
// work: the account's unapproved Cursor hook goes in the same job.
func TestStandaloneForeignCleanupUnblocksPersonalClaudeWhenThePolicyDropsIt(t *testing.T) {
	home := foreignCleanupRealWorkerPass(t, false)
	cursorHook := foreignHookTestCursorHook(t, home)
	hooks := filepath.Join(home, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(hooks, "claude-code-hook.sh")
	if err := os.WriteFile(path, []byte(enterprisehooks.PersonalClaudeHookBlocker), 0o700); err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, time.Now(), enterprisehooks.Manifest{}, map[string]map[string]bool{}, "")
	if strings.Contains(log.String(), "does not take mode") {
		t.Fatalf("the worker refused the foreign cleanup job:\n%s", log.String())
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the Claude Code blocker stayed after the policy dropped Claude Code: %v\n%s", err, log.String())
	}
	if !strings.Contains(log.String(), "removed the Claude Code blocker") {
		t.Fatalf("the removal is not logged:\n%s", log.String())
	}
	if foreignHookTestHookPresent(cursorHook) {
		t.Fatalf("the unapproved Cursor hook stayed: the job's foreign cleanup did not run\n%s", log.String())
	}
	// The account's own script is not the blocker: it stays.
	own := []byte("#!/bin/bash\n# defenseclaw-managed-hook v3\nexec defenseclaw-hook claude-code\n")
	if err := os.WriteFile(path, own, 0o700); err != nil {
		t.Fatal(err)
	}
	enterpriseHookForeignCleanupState.fingerprint = ""
	log.Reset()
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, time.Now(), enterprisehooks.Manifest{}, map[string]map[string]bool{}, "")
	if got, err := os.ReadFile(path); err != nil || string(got) != string(own) {
		t.Fatalf("the account's own script changed: %q %v\n%s", got, err, log.String())
	}
}

// R3-1 class guard: the real worker takes every target mode the foreign
// cleanup gives a job, whether the machine policy covers Claude Code
// (block) or not (unblock), next to the leftover removals and a foreign
// hook cleanup.
func TestForeignCleanupWorkerTakesEveryModeTheGuardianSends(t *testing.T) {
	for _, claudeManaged := range []bool{false, true} {
		name := "claude not covered"
		if claudeManaged {
			name = "claude covered"
		}
		t.Run(name, func(t *testing.T) {
			home := foreignCleanupRealWorkerPass(t, claudeManaged)
			cursorHook := foreignHookTestCursorHook(t, home)
			sent := map[string]bool{}
			enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
				for _, target := range request.Targets {
					sent[target.Mode] = true
				}
				return runEnterpriseHookWorker(ctx, account, request)
			}
			var log strings.Builder
			runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, time.Now(), enterprisehooks.Manifest{}, map[string]map[string]bool{}, "")
			if strings.Contains(log.String(), "cleanup for ") {
				t.Fatalf("the worker refused the job:\n%s", log.String())
			}
			for mode := range sent {
				if !enterpriseHookWorkerForeignCleanupModes[mode] {
					t.Fatalf("the guardian sent mode %q the worker does not take", mode)
				}
			}
			want := enterpriseHookWorkerModeUnblockPersonalClaude
			if claudeManaged {
				want = enterpriseHookWorkerModeBlockPersonalClaude
			}
			if !sent[want] || !sent[enterpriseHookWorkerModeRemoveLeftover] {
				t.Fatalf("modes sent %v, want %s and %s", sent, want, enterpriseHookWorkerModeRemoveLeftover)
			}
			if foreignHookTestHookPresent(cursorHook) {
				t.Fatalf("the unapproved Cursor hook stayed\n%s", log.String())
			}
		})
	}
}

// GAP-1889: a runtime descriptor the guardian cannot read (mid-upgrade)
// does not say the machine policy dropped Claude Code: the pass leaves the
// blocker in place (the managed hook may still decide) and writes none over
// the account's own script, while the job's other work still runs.
func TestStandaloneForeignCleanupKeepsTheClaudeBlockerWhenThePolicyIsUnknown(t *testing.T) {
	home := foreignCleanupRealWorkerPass(t, false)
	enterpriseHookStandaloneMachinePolicySet = func() map[string]struct{} { return nil }
	cursorHook := foreignHookTestCursorHook(t, home)
	hooks := filepath.Join(home, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(hooks, "claude-code-hook.sh")
	for _, body := range []string{enterprisehooks.PersonalClaudeHookBlocker, "#!/bin/bash\n# defenseclaw-managed-hook v3\nexec defenseclaw-hook claude-code\n"} {
		if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
		enterpriseHookForeignCleanupState.fingerprint = ""
		var log strings.Builder
		runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, time.Now(), enterprisehooks.Manifest{}, map[string]map[string]bool{}, "")
		if got, err := os.ReadFile(path); err != nil || string(got) != body {
			t.Fatalf("an unknown machine policy changed the Claude Code hook script: %q %v\n%s", got, err, log.String())
		}
		if strings.Contains(log.String(), "removed the Claude Code blocker") {
			t.Fatalf("an unknown machine policy logged a blocker removal:\n%s", log.String())
		}
	}
	if foreignHookTestHookPresent(cursorHook) {
		t.Fatal("the unapproved Cursor hook stayed: the job's foreign cleanup did not run")
	}
}
