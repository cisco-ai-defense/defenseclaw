// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// substrate-1 GAP-0676: GAP-0444 stopped a replica minting the turn of an
// actor's hook calls, because the other replicas of a Substrate gateway never
// see that turn. The model rail (proxy and stream adapters) still minted one
// at a model start, so one actor turn had a turn_id on its model events that
// no other replica knew. An actor's model call keeps the turn ID the agent
// sends; a host session keeps its minted turns.
func TestGAP0676ActorModelCallsCarryNoReplicaMintedTurn(t *testing.T) {
	installCorrelationHMACForTest(t)
	rail := func(ctx context.Context, store *audit.Store, session string) llmRailCorrelationResult {
		t.Helper()
		result, err := correlateLLMRailOccurrence(ctx, llmRailCorrelationInput{
			store: store, spec: connector.DefaultCorrelationSpec("openclaw"),
			rail: audit.CorrelationRailStream, surface: connector.CorrelationSurfaceStream,
			lifecycle: connector.CorrelationLifecycleModelStart,
			meta: llmEventMeta{SessionID: session, AgentID: "agent-" + session, MessageID: "msg-" + session,
				SourceEventID: "msg-" + session, PromptID: "prompt-" + session},
			rawPayload: []byte(`{"messageId":"msg-` + session + `","sessionKey":"` + session + `"}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	store := newLLMRailCorrelationStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close() //nolint:errcheck

	actorCtx := withSubstrateActor(t.Context(), *f14Actor(t, "gap0676", "3b6c2d1e-8f4a-4b9c-a1d2-5e6f7a8b9c0d"))
	if got := rail(actorCtx, store, "actor-1"); got.meta.TurnID != "" || audit.EnvelopeFromContext(got.ctx).TurnID != "" {
		t.Fatalf("an actor model call has turn_id %q (envelope %q) minted by one replica; the other replicas cannot know it",
			got.meta.TurnID, audit.EnvelopeFromContext(got.ctx).TurnID)
	}
	// The same actor session's next model call finds no cursor turn either.
	if got := rail(actorCtx, store, "actor-1"); got.meta.TurnID != "" {
		t.Fatalf("an actor's second model call has turn_id %q", got.meta.TurnID)
	}
	if got := rail(t.Context(), store, "host-1"); got.meta.TurnID == "" {
		t.Fatal("a host session lost its minted model turn")
	}
}
