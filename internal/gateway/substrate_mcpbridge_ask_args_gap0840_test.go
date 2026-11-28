// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// TestMCPBridgeAskBindsTheCallGAP0840: a held call's ask names that call.
// Two held calls of one tool with other arguments get two asks, each with
// its own argument preview, and approving one forwards only that call. Two
// identical held calls join one ask, and its once approval lets exactly one
// of them through: the other asks again. Secret-named and credential-shaped
// values never reach the summary.
func TestMCPBridgeAskBindsTheCallGAP0840(t *testing.T) {
	real := substrateMCPJudge
	substrateMCPJudge = func(a *APIServer, ctx context.Context, reg registry.Registration, req substrateCalloutRequest) SubstrateCalloutVerdict {
		if req.MCP.Tool == "publish" {
			return SubstrateCalloutVerdict{V: "1", Verdict: "ask", Source: "tool_rules", Reason: "matched: T0840-ASK:fixture ask", Severity: "HIGH"}
		}
		return real(a, ctx, reg, req)
	}
	poll := substrateMCPAskPoll
	substrateMCPAskPoll = 10 * time.Millisecond
	t.Cleanup(func() { substrateMCPJudge, substrateMCPAskPoll = real, poll })

	b := newTixgBridge(t, false)
	store := asks.NewMemory()
	st := b.fixture.api.substrateState()
	st.cfg.Asks = asksDirect{store}
	st.cfg.UnattendedAsk = func(string) SubstrateUnattendedAsk { return SubstrateUnattendedAsk{Timeout: time.Minute} }
	laptop, agent, resp := b.open(t)
	if laptop == nil {
		t.Fatalf("bridge refused: %+v", resp)
	}
	send := func(id int, tool, args string) {
		t.Helper()
		msg := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, id, tool, args)
		if err := agent.WriteMessage(websocket.BinaryMessage, []byte(msg)); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	// fresh waits until n new pending asks exist and returns them.
	fresh := func(n int) []asks.Ask {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		var out []asks.Ask
		for {
			list, err := store.List(t.Context(), asks.ListRequest{All: true, Atespace: "eng-web", Actor: "alice-1"})
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range list {
				if a.State == asks.StatePending && !seen[a.ID] {
					seen[a.ID] = true
					out = append(out, a)
				}
			}
			if len(out) >= n {
				return out
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d new pending asks, want %d (asks: %+v)", len(out), n, list)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	next := func(tool string) float64 {
		t.Helper()
		m := tixgRead(t, laptop)
		p, _ := m["params"].(map[string]any)
		if p["name"] != tool {
			t.Fatalf("laptop got %v, want tools/call %s", m, tool)
		}
		id, _ := m["id"].(float64)
		return id
	}
	approve := func(id string) {
		t.Helper()
		if _, err := store.Resolve(t.Context(), asks.ResolveRequest{ID: id, Decision: "approve", CallerID: ownerOf(alice).ID()}); err != nil {
			t.Fatal(err)
		}
	}
	summaryOf := func(want string, got []asks.Ask) asks.Ask {
		t.Helper()
		for _, a := range got {
			if strings.Contains(a.Summary, want) {
				return a
			}
		}
		t.Fatalf("no ask summary shows %s: %+v", want, got)
		return asks.Ask{}
	}

	// Other arguments: two asks; one approval forwards its own call only.
	send(1, "publish", `{"title":"one"}`)
	send(2, "publish", `{"title":"two"}`)
	two := fresh(2)
	one, second := summaryOf(`title="one"`, two), summaryOf(`title="two"`, two)
	if one.ID == second.ID || one.Rule == second.Rule || !strings.HasPrefix(one.Rule, "mcp_call:") {
		t.Fatalf("asks not bound to their call: %+v / %+v", one, second)
	}
	approve(one.ID)
	if got := next("publish"); got != 1 {
		t.Fatalf("approval of call 1 forwarded call %v", got)
	}
	send(3, "read_note", `{"id":"a"}`)
	if got := next("read_note"); got != 3 {
		t.Fatalf("laptop got call %v before read_note 3: call 2 went through on call 1's approval", got)
	}
	approve(second.ID)
	if got := next("publish"); got != 2 {
		t.Fatalf("approval of call 2 forwarded call %v", got)
	}

	// Identical arguments: one ask, one call per once approval.
	send(4, "publish", `{"title":"same"}`)
	send(5, "publish", `{"title":"same"}`)
	joined := fresh(1)
	time.Sleep(100 * time.Millisecond)
	if extra := fresh(0); len(joined) != 1 || len(extra) != 0 {
		t.Fatalf("identical calls opened %d asks", len(joined)+len(extra))
	}
	approve(joined[0].ID)
	first := next("publish")
	again := fresh(1)
	send(6, "read_note", `{"id":"b"}`)
	if got := next("read_note"); got != 6 {
		t.Fatalf("laptop got call %v before read_note 6: one once approval released both identical calls", got)
	}
	approve(again[0].ID)
	if got := next("publish"); got == first || (got != 4 && got != 5) {
		t.Fatalf("second identical call: laptop got %v after %v", got, first)
	}

	// Secret values stay out of the summary.
	cred := "gh" + "p_" + strings.Repeat("Q", 36)
	send(7, "publish", `{"api_token":"opaque-value-7f3","note":"`+cred+`","title":"seven"}`)
	hidden := fresh(1)[0]
	if strings.Contains(hidden.Summary, "opaque-value-7f3") || strings.Contains(hidden.Summary, cred) ||
		!strings.Contains(hidden.Summary, `title="seven"`) || !strings.Contains(hidden.Summary, "<hidden len=") {
		t.Fatalf("summary %q", hidden.Summary)
	}
	if _, err := store.Resolve(t.Context(), asks.ResolveRequest{ID: hidden.ID, Decision: "deny", CallerID: ownerOf(alice).ID()}); err != nil {
		t.Fatal(err)
	}
	m := tixgRead(t, agent)
	if m["id"] != float64(7) || m["error"] == nil {
		t.Fatalf("denied call 7: agent got %v", m)
	}
}

// TestSubstrateCalloutAskRefusesToolAsksGAP0842: the callout ask route
// raises host asks only. A tool ask there carried no arguments, so two
// different calls of one tool joined one pending ask and one approval
// answered both; tool asks come only from the MCP bridge, which binds each
// to its call (GAP-0840).
func TestSubstrateCalloutAskRefusesToolAsksGAP0842(t *testing.T) {
	store := asks.NewMemory()
	fake := ateapifake.New()
	fake.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "bob-1"}})
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Asks, c.Policies = asksDirect{store}, fake
	})
	for _, body := range []string{
		`{"actor":{"atespace":"eng-web","name":"bob-1"},"tool":"mcp__notes__publish","summary":"call A"}`,
		`{"actor":{"atespace":"eng-web","name":"bob-1"},"host":"  ","summary":"call B"}`,
	} {
		rec := f.do(t, f.admin, http.MethodPost, substrateCalloutAskPath, subCallout, body, "X-DefenseClaw-Client", "substrate-extproc")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: HTTP %d %s, want 400", body, rec.Code, rec.Body)
		}
	}
	list, err := store.List(t.Context(), asks.ListRequest{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("the route opened asks: %+v", list)
	}
}
