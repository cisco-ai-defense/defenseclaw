// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// substrate-1 GAP-0208 (lane E2V, gateway d1d359076e): every connector-hook
// row of a Claude Code actor carried hook_compatibility_status=unknown,
// "pinned hook contract claudecode-hooks-v2 does not match resolved contract
// claudecode-hooks-v1". The kit's envelope pins v2; the registration then
// carried no agent version (the create route recorded none before GAP-0201,
// and an actor made outside DefenseClaw got one only with GAP-0347), so the
// sandbox profile resolved the unversioned default, v1. A registration from
// an attested template carries the template's agent version, and the row is
// known on v2. The first case keeps the E2 registration's shape: with no
// agent version the gateway cannot verify the actor's claimed contract, and
// the row stays unknown (never a known status the gateway did not prove).
func TestGAP0208ClaudeActorHookContractIsKnown(t *testing.T) {
	version := kit.AgentVersion("claudecode", "")
	contract := connector.ResolveSandboxHookContract("claudecode", version).Contract.ContractID
	if contract != "claudecode-hooks-v2" {
		t.Fatalf("the kit's Claude Code %s resolves %q, want claudecode-hooks-v2 (the kit's envelope pin)", version, contract)
	}
	for _, tc := range []struct {
		name, harness, hookContract, status string
	}{
		{"e2-registration-without-agent-version", "", "", connector.HookCompatibilityUnknown},
		{"attested-template", version, contract, connector.HookCompatibilityKnown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installCorrelationHMACForTest(t)
			installDefaultProfileConnector(t, "claudecode")
			_, chains := newTestChainLeaderServiceWith(t, "")
			regs, err := registry.OpenFileStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := regs.Put(context.Background(), registry.Registration{Atespace: "eng-web", Name: "alice-1", UID: subUID1,
				Attributed: true, Profile: "eng", Connector: "claudecode", HarnessVersion: tc.harness, HookContract: tc.hookContract}); err != nil {
				t.Fatal(err)
			}
			r := chartReplica{newSubstrateFixture(t, func(c *SubstrateConfig) { c.Chains, c.Registrations = chains, regs })}
			r.f.regs = regs
			r.f.api.store, r.f.api.logger = testStoreAndV8Logger(t)
			r.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "list-1", "ls"))
			events, err := r.f.api.store.ListEvents(100)
			if err != nil {
				t.Fatal(err)
			}
			rows := 0
			for _, ev := range events {
				if ev.Action != "connector-hook" {
					continue
				}
				rows++
				extra, _ := ev.Structured["extra"].(map[string]any)
				status, _ := extra["hook_compatibility_status"].(string)
				id, _ := extra["hook_contract_id"].(string)
				reason, _ := extra["hook_compatibility_reason"].(string)
				if status != tc.status || id != "claudecode-hooks-v2" {
					t.Fatalf("connector-hook row: status %q contract %q reason %q, want %q on claudecode-hooks-v2", status, id, reason, tc.status)
				}
				if tc.status == connector.HookCompatibilityUnknown && !strings.Contains(reason, "claudecode-hooks-v2") {
					t.Fatalf("an unverified row does not say why: reason %q", reason)
				}
			}
			if rows == 0 {
				t.Fatal("no connector-hook audit row")
			}
		})
	}
}
