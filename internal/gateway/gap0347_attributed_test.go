// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// substrate-1 GAP-0347 (the Kind E2E on PR #1456 push 22): an actor made
// outside DefenseClaw (kubectl ate create actor in a managed atespace) has an
// attributed registration. From an unattested template it names no connector:
// the gateway resolves no hook profile, so its tool step is reported as
// unrecorded (GAP-0339), with that reason, not the lifecycle's. From an
// attested template the controller records the attested connector, agent
// version and hook contract, and its harmless step is allowed, as a launched
// actor's is.
func TestGAP0347AttributedActorStep(t *testing.T) {
	version := kit.AgentVersion("claudecode", "")
	contract := connector.ResolveSandboxHookContract("claudecode", version).Contract.ContractID
	for _, tc := range []struct {
		name                        string
		conn, harness, hookContract string
		unrecorded                  bool
	}{
		{"unattested-template", "", "", "", true},
		{"attested-template", "claudecode", version, contract, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installCorrelationHMACForTest(t)
			installDefaultProfileConnector(t, "claudecode")
			_, chains := newTestChainLeaderServiceWith(t, "")
			mine, err := registry.OpenFileStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := mine.Put(context.Background(), registry.Registration{Atespace: "eng-web", Name: "alice-1", UID: subUID1,
				Attributed: true, Profile: "eng", Connector: tc.conn, HarnessVersion: tc.harness, HookContract: tc.hookContract}); err != nil {
				t.Fatal(err)
			}
			r := chartReplica{newSubstrateFixture(t, func(c *SubstrateConfig) { c.Chains, c.Registrations = chains, mine })}
			r.f.regs = mine
			r.f.api.store, r.f.api.logger = testStoreAndV8Logger(t)
			got := r.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "list-1", "ls"))
			v, err := chains.CheckEgress(context.Background(), chainstate.EgressRequest{
				Actor: chainstate.Actor{Atespace: "eng-web", UID: subUID1}, Host: "github.com", Method: "POST",
			})
			if err != nil {
				t.Fatal(err)
			}
			// The binding names no connector, so the hook's correlation is
			// unavailable and the finding has no rule id on the answer: the
			// leader's mark (what the callout reads) is the proof.
			marked := slices.Contains(got.RuleIDs, substrateChainUnrecordedRule) || v.Unrecorded != ""
			if marked != tc.unrecorded || got.Action == guardrailActionBlock || got.WouldBlock {
				t.Fatalf("hook %q %v would_block=%v, callout %+v: want unrecorded=%v and not blocked", got.Action, got.RuleIDs, got.WouldBlock, v, tc.unrecorded)
			}
			if tc.unrecorded && !strings.Contains(v.Unrecorded, "no attested connector is recorded") {
				t.Fatalf("callout %+v: want the reason (no connector) kept for the egress check", v)
			}
			if !tc.unrecorded && (got.Action != "allow" || v.Unrecorded != "") {
				t.Fatalf("hook %q, callout %+v: want allow and no unrecorded mark", got.Action, v)
			}
		})
	}
}
