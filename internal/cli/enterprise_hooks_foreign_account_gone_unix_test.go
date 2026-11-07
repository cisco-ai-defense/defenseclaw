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
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// foreignGoneFixture runs the standalone foreign-hook cleanup over three
// eligible accounts whose removal answer the test sets between passes.
type foreignGoneFixture struct {
	mu       sync.Mutex
	gone     map[string]bool
	requests map[string]*enterpriseHookWorkerCopilotVSCode
}

func newForeignGoneFixture(t *testing.T) *foreignGoneFixture {
	t.Helper()
	f := &foreignGoneFixture{gone: map[string]bool{}}
	previousCfg, previousManifest := cfg, enterpriseHookManifest
	previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
	previousLoadVSCode, previousWriteVSCode := enterpriseHookLoadCopilotVSCodeAccounts, enterpriseHookWriteCopilotVSCodeAccounts
	previousUIDGone, previousNameGone := enterpriseHookRecordedAccountGone, enterpriseHookGuardianFreshAccountGone
	t.Cleanup(func() {
		cfg, enterpriseHookManifest = previousCfg, previousManifest
		enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousLoad, previousCheck, previousRunner
		enterpriseHookLoadCopilotVSCodeAccounts, enterpriseHookWriteCopilotVSCodeAccounts = previousLoadVSCode, previousWriteVSCode
		enterpriseHookRecordedAccountGone, enterpriseHookGuardianFreshAccountGone = previousUIDGone, previousNameGone
		resetForeignCleanupState()
	})
	resetForeignCleanupState()
	cfg = &config.Config{DataDir: useUserCleanupStateDir(t), DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"copilot": {}}
	cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledInspect
	useStandaloneForeignHookFenceFixture(t)
	enterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
	enterpriseHookRecordedAccountGone = func(_ context.Context, name string, _ int) bool { return f.isGone(name) }
	enterpriseHookGuardianFreshAccountGone = func(_ context.Context, name string) bool { return f.isGone(name) }
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
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		f.mu.Lock()
		f.requests[account.User] = request.CopilotVSCode
		f.mu.Unlock()
		return enterpriseHookWorkerResponse{CopilotVSCode: &enterpriseHookWorkerCopilotVSCodeReport{}}, nil
	}
	return f
}

func resetForeignCleanupState() {
	enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
	enterpriseHookForeignCleanupState.leftoversClean = false
	enterpriseHookForeignCleanupState.unrepaired = nil
}

func (f *foreignGoneFixture) isGone(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gone[name]
}

func (f *foreignGoneFixture) setGone(name string, gone bool) {
	f.mu.Lock()
	f.gone[name] = gone
	f.mu.Unlock()
}

// pass runs one cleanup pass, as a later reconcile would (its throttle
// reset), and reports which accounts were asked to write the Local hook.
func (f *foreignGoneFixture) pass() map[string]bool {
	f.mu.Lock()
	f.requests = map[string]*enterpriseHookWorkerCopilotVSCode{}
	f.mu.Unlock()
	resetForeignCleanupState()
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), io.Discard, time.Now(), enterprisehooks.Manifest{}, nil, "")
	f.mu.Lock()
	defer f.mu.Unlock()
	written := map[string]bool{}
	for _, user := range []string{"alice", "bob", "carol"} {
		request := f.requests[user]
		written[user] = request != nil && (request.HookFile || request.Plugin)
	}
	return written
}

// GAP-0777: the guardian wrote the Copilot Local hook file into the home of
// an enrolled account that was deleted, minutes before the enumerator
// revoked it, and verify reported that file as an account outside
// enrollment. A confirmed-gone account (the evidence its targets retire on)
// gets no write; an account that still answers keeps its file.
func TestStandaloneCopilotLocalHookIsNotWrittenForAConfirmedGoneAccount(t *testing.T) {
	for _, tc := range []struct {
		name string
		gone []string
		want map[string]bool
	}{
		{name: "every account answers", want: map[string]bool{"alice": true, "bob": true, "carol": true}},
		{name: "bob was deleted", gone: []string{"bob"}, want: map[string]bool{"alice": true, "bob": false, "carol": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newForeignGoneFixture(t)
			for _, name := range tc.gone {
				f.setGone(name, true)
			}
			if got := f.pass(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Local hook writes %v, want %v", got, tc.want)
			}
		})
	}
}

// The removal answer decides each write on its own pass: an account deleted
// after a pass that saw it live gets no write on the next one, and an account
// recreated after a pass that saw it gone is written again at once, not
// after an answer kept from before expires.
func TestStandaloneCopilotLocalHookAnswerIsReadFreshOnEveryPass(t *testing.T) {
	f := newForeignGoneFixture(t)
	live := map[string]bool{"alice": true, "bob": true, "carol": true}
	deleted := map[string]bool{"alice": true, "bob": false, "carol": true}
	if got := f.pass(); !reflect.DeepEqual(got, live) {
		t.Fatalf("live account: writes %v, want %v", got, live)
	}
	f.setGone("bob", true)
	if got := f.pass(); !reflect.DeepEqual(got, deleted) {
		t.Fatalf("account deleted after a live answer: writes %v, want %v", got, deleted)
	}
	f.setGone("bob", false)
	if got := f.pass(); !reflect.DeepEqual(got, live) {
		t.Fatalf("account recreated after a gone answer: writes %v, want %v", got, live)
	}
}
