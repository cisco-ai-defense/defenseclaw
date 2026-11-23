// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// substrate-1 GAP-0456: every Claude Code actor run on the cert cluster
// raised HIGH subsystem.degraded health records (subsystem
// hook-pre-tool-missing) while its PreToolUse hook worked. The record is the
// health projection of the missing-PreToolUse alert: each one was a
// PostToolUse that landed on the other gateway replica than its PreToolUse
// (GAP-0267), 160 ms after it for the fastest tool. Here the replicas share
// a real leader over its RPC, and the PostToolUse follows its PreToolUse at
// once: no health record. A tool result with no PreToolUse anywhere, and the
// laptop gateway (one process), keep the alert where it is due.
type gap0456Replica struct {
	api     *APIServer
	emitter *captureJudgeRuntimeV8Emitter
}

func gap0456NewReplica(t *testing.T) gap0456Replica {
	t.Helper()
	store, logger := testStoreAndLogger(t)
	emitter := &captureJudgeRuntimeV8Emitter{}
	logger.SetRuntimeV8Emitter(emitter)
	return gap0456Replica{api: &APIServer{store: store, logger: logger}, emitter: emitter}
}

func (r gap0456Replica) hook(t *testing.T, ctx context.Context, connector, event, tool string) {
	t.Helper()
	req := agentHookRequest{ConnectorName: connector, ConnectorInstanceID: "caller-instance",
		HookEventName: event, SessionID: "session-1", ToolInvocationID: tool, ToolName: "Bash"}
	resp := agentHookResponse{Action: "allow", RawAction: "allow", Mode: "action"}
	if !r.api.finalizeAgentHook(ctx, connector, req, resp, nil, []byte(`{}`), time.Millisecond, false, nil).AuditPersisted {
		t.Fatal("hook decision audit was not persisted")
	}
}

func (r gap0456Replica) degraded() int {
	return countCanonicalEvent(r.emitter.snapshot(), observability.TelemetryEventSubsystemDegraded)
}

func TestGAP0456NoDegradedHealthWhenPreToolUseLandedOnAnotherReplica(t *testing.T) {
	useSubstrateChains(newTestChainLeader(t))
	t.Cleanup(func() { useSubstrateChains(nil) })
	actor := withSubstrateActor(t.Context(), *f14Actor(t, "gap0456", "3b6c2d1e-8f4a-4b9c-a1d2-5e6f7a8b9c0d"))
	for _, connector := range []string{"claudecode", "codex"} {
		t.Run(connector, func(t *testing.T) {
			a, b := gap0456NewReplica(t), gap0456NewReplica(t)
			a.hook(t, actor, connector, "PreToolUse", "toolu_"+connector+"_1")
			b.hook(t, actor, connector, "PostToolUseFailure", "toolu_"+connector+"_1")
			b.hook(t, actor, connector, "PostToolUse", "toolu_"+connector+"_1")
			if n := a.degraded() + b.degraded(); n != 0 {
				t.Fatalf("%d subsystem.degraded health records for a PostToolUse whose PreToolUse ran on the other replica, want 0", n)
			}
			// A tool result that no replica saw a PreToolUse for is still
			// reported: the check works, it is not switched off.
			b.hook(t, actor, connector, "PostToolUse", "toolu_"+connector+"_2")
			if n := b.degraded(); n != 1 {
				t.Fatalf("%d subsystem.degraded health records for a tool result with no PreToolUse anywhere, want 1", n)
			}
		})
	}
}

func TestGAP0456LaptopGatewayRaisesNoDegradedHealthForAPairedToolCall(t *testing.T) {
	for _, connector := range []string{"claudecode", "codex"} {
		t.Run(connector, func(t *testing.T) {
			r := gap0456NewReplica(t)
			ctx := t.Context()
			for i, event := range []string{"PreToolUse", "PostToolUseFailure", "PostToolUse"} {
				r.hook(t, ctx, connector, event, "toolu_laptop_1")
				if n := r.degraded(); n != 0 {
					t.Fatalf("after %s (%d): %d subsystem.degraded health records, want 0", event, i, n)
				}
			}
			r.hook(t, ctx, connector, "PostToolUse", "toolu_laptop_2")
			if n := r.degraded(); n != 1 {
				t.Fatalf("%d subsystem.degraded health records for a tool result without its PreToolUse, want 1", n)
			}
		})
	}
}
