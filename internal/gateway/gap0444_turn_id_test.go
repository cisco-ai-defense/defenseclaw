// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

// substrate-1 GAP-0444: each replica of a Substrate gateway minted the turn
// of an actor session at the UserPromptSubmit that landed on it and kept it
// in its own cursor, so one turn's hook events had different turn_id values
// on different replicas (Claude Code sends no turn ID). An actor's hook
// calls now carry no minted turn; a host session keeps its minted turns.
func TestGAP0444ActorHookCallsCarryNoReplicaMintedTurn(t *testing.T) {
	installCorrelationHMACForTest(t)
	profile := (&APIServer{}).hookProfileForConnector("claudecode")
	events := readClaudeCodeAgentToolFixture(t)
	actorCtx := withSubstrateActor(t.Context(), *f14Actor(t, "gap0444", "3b6c2d1e-8f4a-4b9c-a1d2-5e6f7a8b9c0d"))
	replica := func() *APIServer {
		server, store := newHookCorrelationServer(t, filepath.Join(t.TempDir(), "audit.db"))
		t.Cleanup(func() { _ = store.Close() })
		return server
	}
	correlate := func(server *APIServer, ctx context.Context, i int) agentHookRequest {
		t.Helper()
		raw, err := json.Marshal(events[i])
		if err != nil {
			t.Fatal(err)
		}
		req := normalizeAgentHookRequestWithProfile("claudecode", events[i], profile)
		_, req, err = server.correlateHookOccurrence(ctx, profile, req, raw)
		if err != nil || req.SuppressCorrelationEmit {
			t.Fatalf("fixture line %d (%v): err %v, suppressed %t", i+1, events[i]["hook_event_name"], err, req.SuppressCorrelationEmit)
		}
		return req
	}

	// One actor session spread over two replicas with no affinity.
	a, b := replica(), replica()
	for i := range events {
		server := a
		if i%3 == 2 {
			server = b
		}
		if got := correlate(server, actorCtx, i).TurnID; got != "" {
			t.Fatalf("actor hook call %d (%v) has turn_id %q minted by one replica; the other replicas cannot know it", i+1, events[i]["hook_event_name"], got)
		}
	}

	host := replica()
	minted := 0
	for i := range events {
		if correlate(host, t.Context(), i).TurnID != "" {
			minted++
		}
	}
	if minted == 0 {
		t.Fatal("a host session lost its minted turns")
	}
}
