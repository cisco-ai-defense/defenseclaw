// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// substrate-1 GAP-0267: a PreToolUse decision forgotten on its replica (its
// answer unconfirmed, its audit row not written) is forgotten on every
// replica: the PostToolUse on another one still writes the alert.
func TestGAP0267ForgottenPreToolUseIsForgottenOnEveryReplica(t *testing.T) {
	a, b, shared, alerts := gap0267Replicas(t)
	ctx := withSubstrateActor(t.Context(), *f14Actor(t, "gap0267-forget", "3b6c2d1e-8f4a-4b9c-a1d2-5e6f7a8b9c0d"))
	key, _, ok := a.preToolDecisionKeyFor(ctx, agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse",
		SessionID: "session-1", ToolInvocationID: "tool-1"})
	if !ok {
		t.Fatal("no key")
	}
	a.recordPreToolDecision(ctx, key)
	a.forgetPreToolDecision(ctx, key)
	decided, forgotten := key.sharedHashes()
	if known, _ := shared.Seen(ctx, key.sharedScope(), []historyHash{decided, forgotten}); len(known) != 2 {
		t.Fatalf("the shared record holds %d of the decided and forgotten marks, want both", len(known))
	}
	if b.preToolDecided(ctx, key) {
		t.Fatal("replica B still finds a PreToolUse decision replica A forgot")
	}
	gap0267Finish(t, ctx, b, "claudecode", "PostToolUse", "session-1", "tool-1")
	if alerts(b) != 1 {
		t.Fatalf("replica B alerts=%d, want 1", alerts(b))
	}
}
