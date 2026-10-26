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
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1829: while the device stays managed and the machine policy no longer
// covers Claude Code, the guardian's foreign cleanup removes the blocker an
// earlier pass wrote over an account's own hook script, and nothing else.
func TestStandaloneForeignCleanupUnblocksPersonalClaudeWhenThePolicyDropsIt(t *testing.T) {
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
	enterpriseHookStandaloneMachinePolicySet = func() map[string]struct{} { return map[string]struct{}{} }
	enterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
	home := t.TempDir()
	hooks := filepath.Join(home, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(hooks, "claude-code-hook.sh")
	if err := os.WriteFile(path, []byte(enterprisehooks.PersonalClaudeHookBlocker), 0o700); err != nil {
		t.Fatal(err)
	}
	account := enterprisehooks.UnixEligibleAccount{User: "alice", UID: 4242, GID: 4242, Home: home, HomeInode: 7}
	enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) {
		return []enterprisehooks.UnixEligibleAccount{account}, nil
	}
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable, Inode: 7}
	}
	enterpriseHookWorkerRunner = func(ctx context.Context, _ enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		for _, target := range request.Targets {
			if target.Mode == enterpriseHookWorkerModeBlockPersonalClaude {
				t.Errorf("the personal hook was blocked while the policy does not cover Claude Code: %+v", target)
			}
		}
		return runEnterpriseHookWorkerApply(ctx, request), nil
	}
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), io.Discard, time.Now(), enterprisehooks.Manifest{}, nil, "")
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the Claude Code blocker stayed after the policy dropped Claude Code: %v", err)
	}
	// The account's own script is not the blocker: it stays.
	own := []byte("#!/bin/bash\n# defenseclaw-managed-hook v3\nexec defenseclaw-hook claude-code\n")
	if err := os.WriteFile(path, own, 0o700); err != nil {
		t.Fatal(err)
	}
	enterpriseHookForeignCleanupState.fingerprint = ""
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), io.Discard, time.Now(), enterprisehooks.Manifest{}, nil, "")
	if got, err := os.ReadFile(path); err != nil || string(got) != string(own) {
		t.Fatalf("the account's own script changed: %q %v", got, err)
	}
}
