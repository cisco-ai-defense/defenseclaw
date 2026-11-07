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
	"io"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0777: the guardian wrote the Copilot Local hook file into the home of
// an enrolled account that was deleted, minutes before the enumerator
// revoked it, and verify reported that file as an account outside
// enrollment. A confirmed-gone account (the evidence its targets retire on)
// gets no write; an account that still answers keeps its file.
func TestStandaloneCopilotLocalHookIsNotWrittenForAConfirmedGoneAccount(t *testing.T) {
	for _, tc := range []struct {
		name string
		gone map[string]bool
		want map[string]bool
	}{
		{name: "every account answers", gone: nil, want: map[string]bool{"alice": true, "bob": true, "carol": true}},
		{name: "bob was deleted", gone: map[string]bool{"bob": true}, want: map[string]bool{"alice": true, "bob": false, "carol": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previousCfg, previousManifest := cfg, enterpriseHookManifest
			previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
			previousLoadVSCode, previousWriteVSCode := enterpriseHookLoadCopilotVSCodeAccounts, enterpriseHookWriteCopilotVSCodeAccounts
			previousUIDGone, previousNameGone := enterpriseHookRecordedAccountGone, enterpriseHookGuardianFreshAccountGone
			reset := func() {
				enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
				enterpriseHookForeignCleanupState.leftoversClean = false
				enterpriseHookForeignCleanupState.unrepaired = nil
				enterpriseHookForeignGone.Lock()
				enterpriseHookForeignGone.checked = nil
				enterpriseHookForeignGone.Unlock()
			}
			t.Cleanup(func() {
				cfg, enterpriseHookManifest = previousCfg, previousManifest
				enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousLoad, previousCheck, previousRunner
				enterpriseHookLoadCopilotVSCodeAccounts, enterpriseHookWriteCopilotVSCodeAccounts = previousLoadVSCode, previousWriteVSCode
				enterpriseHookRecordedAccountGone, enterpriseHookGuardianFreshAccountGone = previousUIDGone, previousNameGone
				reset()
			})
			reset()
			cfg = &config.Config{DataDir: useUserCleanupStateDir(t), DeploymentMode: managed.DeploymentModeManagedEnterprise}
			cfg.Enterprise.Profile = managed.ProfileStandalone
			cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"copilot": {}}
			cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledInspect
			useStandaloneForeignHookFenceFixture(t)
			enterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
			enterpriseHookRecordedAccountGone = func(_ context.Context, name string, _ int) bool { return tc.gone[name] }
			enterpriseHookGuardianFreshAccountGone = func(_ context.Context, name string) bool { return tc.gone[name] }
			accounts := []enterprisehooks.UnixEligibleAccount{
				{User: "alice", UID: 4201, GID: 4201, Home: "/home/alice", HomeInode: 7},
				{User: "bob", UID: 4202, GID: 4202, Home: "/home/bob", HomeInode: 7},
				{User: "carol", UID: 4203, GID: 4203, Home: "/home/carol", HomeInode: 7},
			}
			enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) { return accounts, nil }
			enterpriseHookLoadCopilotVSCodeAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) { return nil, nil }
			enterpriseHookWriteCopilotVSCodeAccounts = func(string, []enterprisehooks.UnixEligibleAccount) error { return nil }
			enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
				return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable, Inode: 7}
			}
			var mu sync.Mutex
			requests := map[string]*enterpriseHookWorkerCopilotVSCode{}
			enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
				mu.Lock()
				requests[account.User] = request.CopilotVSCode
				mu.Unlock()
				return enterpriseHookWorkerResponse{CopilotVSCode: &enterpriseHookWorkerCopilotVSCodeReport{}}, nil
			}
			runEnterpriseHookStandaloneForeignCleanup(context.Background(), io.Discard, time.Now(), enterprisehooks.Manifest{}, nil, "")
			for user, want := range tc.want {
				request := requests[user]
				written := request != nil && (request.HookFile || request.Plugin)
				if written != want {
					t.Errorf("%s VS Code request %+v, want a Local hook write=%t", user, request, want)
				}
			}
		})
	}
}
