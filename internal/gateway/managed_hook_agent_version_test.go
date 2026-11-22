// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// gap0114Ledger is a guardian authorization as the guardian writes it: each
// protected row carries the install result with the agent version it probed
// in the account and the hook contract it rendered.
const gap0114Ledger = `{"version":1,"ok":true,"protected_targets":[
 {"user":"dcm-std1","uid":1001,"connector":"claudecode","ok":true,
  "result":{"connector":"claudecode","user_home":"/home/dcm-std1","data_dir":"/home/dcm-std1/.defenseclaw",
   "agent_version":"2.1.323 (Claude Code)","hook_contract_id":"claudecode-hooks-v2"}},
 {"user":"dcm-std1","uid":1001,"connector":"codex","ok":true,
  "result":{"connector":"codex","agent_version":"0.168.0","hook_contract_id":"codex-hooks-v4"}},
 {"user":"dcm-std2","uid":1002,"connector":"claudecode","ok":true,
  "result":{"connector":"claudecode","agent_version":"2.1.180","hook_contract_id":"claudecode-hooks-v1"}},
 {"user":"dcw-std1","sid":"s-1-5-21-1-2-3-1104","connector":"claudecode","ok":true,
  "result":{"connector":"claudecode","agent_version":"2.1.323","hook_contract_id":"claudecode-hooks-v2"}},
 {"user":"dcm-split","uid":1003,"connector":"claudecode","ok":true,
  "result":{"connector":"claudecode","agent_version":"2.1.323","hook_contract_id":"claudecode-hooks-v2"}},
 {"user":"dcm-split","uid":1003,"connector":"claudecode","ok":true,
  "result":{"connector":"claudecode","agent_version":"2.1.180","hook_contract_id":"claudecode-hooks-v1"}},
 {"user":"dcm-failed","uid":1004,"connector":"claudecode","ok":false,
  "result":{"connector":"claudecode","agent_version":"2.1.323","hook_contract_id":"claudecode-hooks-v2"}},
 {"user":"dcm-noprobe","uid":1005,"connector":"claudecode","ok":true,"result":{"connector":"claudecode"}}
]}`

func useGAP0114Ledger(t *testing.T, raw string, err error) {
	t.Helper()
	var ledger managedHookLedger
	if raw != "" {
		if decodeErr := json.Unmarshal([]byte(raw), &ledger); decodeErr != nil {
			t.Fatal(decodeErr)
		}
	}
	previous := loadCallerAgentLedger
	loadCallerAgentLedger = func(string) (managedHookLedger, error) { return ledger, err }
	t.Cleanup(func() { loadCallerAgentLedger = previous })
}

// TestGAP0114ManagedHookProfileUsesTheCallersRecordedAgentVersion: a
// standalone gateway serves every enrolled account from the machine data
// dir, where no agent version is ever cached, so every managed hook row
// said hook_compatibility_status=unversioned and used claudecode-hooks-v1
// for Claude Code 2.1.323 (v2 starts at 2.1.219), on managed Linux, macOS
// and Windows. The guardian already records each protected target's probed
// version and rendered contract; the request's profile now comes from the
// verified caller's row.
func TestGAP0114ManagedHookProfileUsesTheCallersRecordedAgentVersion(t *testing.T) {
	useGAP0114Ledger(t, gap0114Ledger, nil)
	api := &APIServer{scannerCfg: &config.Config{DataDir: t.TempDir()}}
	unversioned := api.hookProfileForConnector("claudecode")
	if unversioned.CompatibilityStatus != connector.HookCompatibilityUnversioned {
		t.Fatalf("machine profile status %q, want unversioned (no version in the machine data dir)", unversioned.CompatibilityStatus)
	}
	peer := func(uid int) context.Context {
		return withManagedHookPeer(context.Background(), managedHookPeer{UID: uid})
	}
	credential := func(identity string) context.Context {
		return context.WithValue(context.Background(), verifiedUserScopedIdentityContextKey{}, identity)
	}
	cases := []struct {
		name, connector, contract, status string
		ctx                               context.Context
	}{
		{"hook-socket peer, Claude Code 2.1.323", "claudecode", "claudecode-hooks-v2", connector.HookCompatibilityKnown, peer(1001)},
		{"per-user credential uid", "claudecode", "claudecode-hooks-v2", connector.HookCompatibilityKnown, credential("1001")},
		{"per-user credential SID, case folded", "claudecode", "claudecode-hooks-v2", connector.HookCompatibilityKnown, credential("S-1-5-21-1-2-3-1104")},
		{"same account, codex", "codex", "codex-hooks-v4", connector.HookCompatibilityKnown, peer(1001)},
		{"another account on an older agent", "claudecode", "claudecode-hooks-v1", connector.HookCompatibilityKnown, peer(1002)},
	}
	for _, tc := range cases {
		profile := api.hookProfileForRequest(tc.ctx, tc.connector)
		if profile.ContractID != tc.contract || profile.CompatibilityStatus != tc.status || profile.AgentVersion == "" {
			t.Errorf("%s: contract %q status %q version %q, want %q %q and the recorded version",
				tc.name, profile.ContractID, profile.CompatibilityStatus, profile.AgentVersion, tc.contract, tc.status)
		}
	}
}

// TestGAP0114ProfileStaysUnversionedWithoutOneRecordedVersion: everything
// that does not name one recorded version for the verified caller resolves
// as before.
func TestGAP0114ProfileStaysUnversionedWithoutOneRecordedVersion(t *testing.T) {
	api := &APIServer{scannerCfg: &config.Config{DataDir: t.TempDir()}}
	want := api.hookProfileForConnector("claudecode")
	peer := func(uid int) context.Context {
		return withManagedHookPeer(context.Background(), managedHookPeer{UID: uid})
	}
	cases := []struct {
		name string
		ctx  context.Context
		err  error
	}{
		{"no verified caller (per-user gateway)", context.Background(), nil},
		{"caller with no protected target", peer(4242), nil},
		{"caller's targets record different versions", peer(1003), nil},
		{"caller's target is not protected", peer(1004), nil},
		{"caller's target records no version", peer(1005), nil},
		{"root has no ledger row", peer(0), nil},
		{"ledger unreadable", peer(1001), errors.New("hook guardian authorization is not root-owned")},
	}
	for _, tc := range cases {
		useGAP0114Ledger(t, gap0114Ledger, tc.err)
		got := api.hookProfileForRequest(tc.ctx, "claudecode")
		if got.ContractID != want.ContractID || got.CompatibilityStatus != want.CompatibilityStatus || got.AgentVersion != want.AgentVersion {
			t.Errorf("%s: contract %q status %q version %q, want the machine profile %q %q %q",
				tc.name, got.ContractID, got.CompatibilityStatus, got.AgentVersion,
				want.ContractID, want.CompatibilityStatus, want.AgentVersion)
		}
	}
}
