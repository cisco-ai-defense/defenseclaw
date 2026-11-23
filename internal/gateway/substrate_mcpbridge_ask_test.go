// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// TestMCPBridgeAskHeldApprovedOrTimedOut (B3.3 S4a ask path): a tools/call
// whose verdict is ask is held, never forwarded, until the owner decides.
// An approval forwards the judged message; a denial and the ask limit both
// answer the agent with mcp_call_denied and the laptop never sees the call.
func TestMCPBridgeAskHeldApprovedOrTimedOut(t *testing.T) {
	// Test-only rule fixture: the tool "publish" asks, everything else gets
	// the real verdict.
	real := substrateMCPJudge
	substrateMCPJudge = func(a *APIServer, ctx context.Context, reg registry.Registration, req substrateCalloutRequest) SubstrateCalloutVerdict {
		if strings.HasPrefix(req.MCP.Tool, "publish") {
			return SubstrateCalloutVerdict{V: "1", Verdict: "ask", Source: "tool_rules", Reason: "matched: TIXH-ASK:fixture ask", Severity: "HIGH"}
		}
		return real(a, ctx, reg, req)
	}
	poll := substrateMCPAskPoll
	substrateMCPAskPoll = 10 * time.Millisecond
	t.Cleanup(func() { substrateMCPJudge, substrateMCPAskPoll = real, poll })

	b := newTixgBridge(t, false)
	store := asks.NewMemory()
	var limit atomic.Int64
	limit.Store(int64(time.Minute))
	st := b.fixture.api.substrateState()
	st.cfg.Asks = asksDirect{store}
	st.cfg.UnattendedAsk = func(string) SubstrateUnattendedAsk {
		return SubstrateUnattendedAsk{Timeout: time.Duration(limit.Load())}
	}
	laptop, agent, resp := b.open(t)
	if laptop == nil {
		t.Fatalf("bridge refused: %+v", resp)
	}
	send := func(s string) {
		t.Helper()
		if err := agent.WriteMessage(websocket.BinaryMessage, []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	call := func(id int, tool string) string {
		return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":{"id":"a"}}}`, id, tool)
	}
	seen := map[string]bool{}
	pending := func() asks.Ask {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			list, err := store.List(t.Context(), asks.ListRequest{All: true, Atespace: "eng-web", Actor: "alice-1"})
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range list {
				if a.State == asks.StatePending && !seen[a.ID] {
					if !strings.HasPrefix(a.Tool, "mcp__notes__publish") {
						t.Fatalf("ask tool %q, want mcp__notes__publish", a.Tool)
					}
					seen[a.ID] = true
					return a
				}
			}
			if time.Now().After(deadline) {
				t.Fatal("no pending ask was opened for the held call")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	// next asserts the laptop's next message is tools/call id with tool: a
	// held call sent before it was not forwarded.
	next := func(id float64, tool string) {
		t.Helper()
		m := tixgRead(t, laptop)
		if p, _ := m["params"].(map[string]any); m["id"] != id || p["name"] != tool {
			t.Fatalf("laptop got %v, want tools/call %v %s", m, id, tool)
		}
	}
	decide := func(id, decision string) {
		t.Helper()
		if _, err := store.Resolve(t.Context(), asks.ResolveRequest{ID: id, Decision: decision, CallerID: ownerOf(alice).ID()}); err != nil {
			t.Fatal(err)
		}
	}
	denied := func(id float64, tool, why string) {
		t.Helper()
		m := tixgRead(t, agent)
		e, _ := m["error"].(map[string]any)
		if m["id"] != id || e == nil || !strings.HasPrefix(e["message"].(string), "mcp_call_denied: The guard denied tool notes."+tool+": "+why) {
			t.Fatalf("answer %v, want mcp_call_denied (%s)", m, why)
		}
	}

	// Held: a later allowed call overtakes it; approved: it is forwarded.
	send(call(1, "publish"))
	a := pending()
	send(call(2, "read_note"))
	next(2, "read_note")
	decide(a.ID, "approve")
	next(1, "publish")

	// Held past the ask limit: denied, never forwarded.
	limit.Store(int64(150 * time.Millisecond))
	// Each case asks for its own tool: an approval is kept per tool
	// (GAP-0840, not this test's subject).
	send(call(3, "publish_b"))
	pending()
	denied(3, "publish_b", "the approval was not given in time")
	send(call(4, "read_note"))
	next(4, "read_note")

	// Held, then denied by the owner: denied, never forwarded.
	limit.Store(int64(time.Minute))
	send(call(5, "publish_c"))
	a = pending()
	decide(a.ID, "deny")
	denied(5, "publish_c", "the approval was denied")
	send(call(6, "read_note"))
	next(6, "read_note")

	b.mu.Lock()
	defer b.mu.Unlock()
	var approved, deniedRows int
	for _, row := range b.audits {
		switch row["event"] {
		case "substrate.mcp.approved":
			approved++
		case "substrate.mcp.denied":
			deniedRows++
		}
	}
	if approved != 1 || deniedRows != 2 {
		t.Fatalf("audit rows: %d approved, %d denied (want 1, 2)", approved, deniedRows)
	}
}
