// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
)

// substrate-1 GAP-0270: each replica of a Substrate gateway numbered an
// actor session's turns from the hooks that landed on it, so the step_idx of
// one session's hook events differed by replica. An actor's hook events now
// carry no step index; a host call keeps its per-session numbering.
func TestGAP0270ActorHookEventsCarryNoReplicaStepIndex(t *testing.T) {
	a, b := &APIServer{}, &APIServer{}
	ctx := withSubstrateActor(t.Context(), *f14Actor(t, "gap0270", "3b6c2d1e-8f4a-4b9c-a1d2-5e6f7a8b9c0d"))
	stamp := func(api *APIServer, ctx context.Context, event string) int {
		var env HookAuditEnvelope
		api.stampHookEnvelopeIdentity(ctx, "claudecode", &env, agentHookRequest{ConnectorName: "claudecode",
			HookEventName: event, SessionID: "session-1"}, agentHookResponse{Action: "allow"})
		return env.StepIdx
	}
	// One session: two prompts on replica A, the third on replica B.
	for i, call := range []struct {
		api   *APIServer
		event string
	}{{a, "UserPromptSubmit"}, {a, "PreToolUse"}, {a, "UserPromptSubmit"}, {b, "UserPromptSubmit"}, {b, "PreToolUse"}} {
		if got := stamp(call.api, ctx, call.event); got != 0 {
			t.Errorf("actor hook call %d (%s) has step_idx %d, want none: a replica cannot number the session's turns", i, call.event, got)
		}
	}
	host := &APIServer{}
	for i, want := range []int{1, 1, 2} {
		event := []string{"UserPromptSubmit", "PreToolUse", "UserPromptSubmit"}[i]
		if got := stamp(host, t.Context(), event); got != want {
			t.Errorf("host hook call %d (%s) step_idx %d, want %d", i, event, got, want)
		}
	}
}
