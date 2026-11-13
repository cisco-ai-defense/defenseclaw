//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// GAP-0201 residual (R6): when the active ruleset's fingerprint cannot be
// computed, an actor's tool step was dropped with no
// SUBSTRATE-CHAIN-UNRECORDED report. It is reported like every other
// reason a step cannot reach the actor window.
func TestSubstrateChainStepIsReportedWhenTheRulesetFingerprintFails(t *testing.T) {
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	_, chains := newTestChainLeaderService(t)
	r := chartReplica{newSubstrateFixture(t, func(c *SubstrateConfig) { c.Chains = chains })}
	r.f.api.store, r.f.api.logger = testStoreAndV8Logger(t)
	if err := r.f.regs.Put(context.Background(), withHarness(t, r.f, "alice-1", kit.AgentVersion("claudecode", ""), "claudecode-hooks-v2")); err != nil {
		t.Fatal(err)
	}
	got := r.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "list-1", "ls -la"))
	if slices.Contains(got.RuleIDs, substrateChainUnrecordedRule) {
		t.Fatalf("attested registration: %+v, want the step recorded", got)
	}
	orig := toolChainRulesetFingerprint
	toolChainRulesetFingerprint = func(context.Context, string, connector.HookProfile) (string, error) {
		return "", errors.New("lifecycle not encodable")
	}
	t.Cleanup(func() { toolChainRulesetFingerprint = orig })
	got = r.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "list-2", "ls -la"))
	if !slices.Contains(got.RuleIDs, substrateChainUnrecordedRule) {
		t.Fatalf("failed fingerprint: %+v, want an alert naming %s", got, substrateChainUnrecordedRule)
	}
}
