// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

// GAP-1112: the /llm passthrough ended every usage record with nil, so an
// upstream stream that broke off after the provider began answering was
// recorded as a completed call of known (input-only) cost, and the unknown-cost
// budget deny (GAP-0812) never fired for actor calls. The stream outcome now
// reaches the record: the upstream body failing is upstream_error, the agent
// going away (context done or a failed write) is cancelled, and a call with no
// final output usage is charged as unknown.

const cutStreamStart = `event: message_start
data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-haiku-4-5-20251001","content":[],"usage":{"input_tokens":1000,"output_tokens":1}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}

`

const cutStreamEnd = `event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":50}}

event: message_stop
data: {"type":"message_stop"}

`

// resetAfter streams the SSE head, then resets the connection (no final
// usage, no end of stream); with tail set it sends the whole stream.
func resetAfter(tail string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(cutStreamStart))
		w.(http.Flusher).Flush()
		if tail != "" {
			_, _ = w.Write([]byte(tail))
			return
		}
		time.Sleep(20 * time.Millisecond)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = conn.Close()
	}
}

func usd1112(v float64) *float64 { return &v }

// installPricedUsageEngine is installUsageEngine with Haiku prices and the
// routing admin runtime as the budget sink, as the gateway wires it.
func installPricedUsageEngine(t *testing.T) chan modelusage.Record {
	t.Helper()
	ch := make(chan modelusage.Record, 16)
	e := modelusage.NewEngine(usageCaptureSink{ch: ch})
	e.Apply(config.TokenomicsConfig{Enabled: true}, config.PricingConfig{Version: "t1", Models: []config.PriceEntryConfig{
		{Provider: "anthropic", Model: "claude-haiku-4-5*", PriceRatesConfig: config.PriceRatesConfig{InputPerMTok: usd1112(1), OutputPerMTok: usd1112(5)}},
		{Provider: "openai", Model: "gpt-5*", PriceRatesConfig: config.PriceRatesConfig{InputPerMTok: usd1112(1), OutputPerMTok: usd1112(5)}},
	}})
	e.SetSpendSink(routingAdminRuntime)
	prev := processModelUsage.Load()
	processModelUsage.Store(e)
	t.Cleanup(func() {
		e.SetSpendSink(nil)
		e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
		processModelUsage.Store(prev)
	})
	return ch
}

func actorDenyBudgets() []config.RoutingBudget {
	return []config.RoutingBudget{
		{ID: "agent", Scope: "actor", Subject: "*", Period: "day", LimitUSD: 10, OnExceed: "deny"},
		{ID: "nightly", Scope: "batch", Subject: "*", Period: "day", LimitUSD: 20, OnExceed: "deny"},
	}
}

// cutStreamCall runs one actor call through the passthrough stream against
// the upstream and returns its usage record and the verdict of the next call
// of the same actor under managed actor and batch deny budgets.
func cutStreamCall(t *testing.T, budgets []config.RoutingBudget, upstream http.HandlerFunc) (modelusage.Record, routingadmin.Verdict) {
	t.Helper()
	now := time.Now()
	isolatedRoutingAdminRuntimeAt(t, now)
	policy := routingadmin.Compile(nil, budgets, true)
	cfg := &config.Config{}
	cfg.Routing.Admin = &config.RoutingAdminConfig{Budgets: budgets}
	if routingAdminRuntime.For(cfg) == nil {
		t.Fatal("evaluator")
	}
	ledger := routingAdminRuntime.Ledger()
	ledger.ApplyRemote(policy.BudgetIDs(), nil, now)
	ch := installPricedUsageEngine(t)

	actor := &engine.Actor{Key: "substrate:eng-web/a1", Atespace: "eng-web", BatchID: "run-7"}
	call := routingadmin.Request{Connector: "claudecode", Actor: actor}
	first := policy.Evaluate(call, ledger, now)
	if first.Deny != nil || len(first.ChargeKeys) != len(budgets) {
		t.Fatalf("first call must be allowed and charge actor and batch: %+v deny %+v", first, first.Deny)
	}

	up := httptest.NewServer(upstream)
	defer up.Close()
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{"model":"claude-haiku-4-5-20251001","stream":true}`))
	hreq, err := http.NewRequestWithContext(req.Context(), http.MethodPost, up.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(hreq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	rec := httptest.NewRecorder()
	w, finish := beginUsage(req.Context(), rec, modelusage.CallFacts{
		Listener: engine.ListenerGuardrail, Connector: "claudecode", APIFamily: modelusage.FamilyMessages,
		CallRole: modelusage.RoleAgent, Streaming: true,
		RequestedProvider: "anthropic", RequestedModel: "claude-haiku-4-5-20251001",
		SelectedProvider: "anthropic", SelectedModel: "claude-haiku-4-5-20251001",
		ChargeKeys: first.ChargeKeys,
	})
	func() {
		defer finish(nil) // as handlePassthrough does
		(&passthroughStream{
			p: newPassthroughProxy(t), w: w, r: req, resp: resp, mode: "observe", label: "t", provider: "anthropic",
			path: "/v1/messages", model: "claude-haiku-4-5-20251001", telemetry: ChatRequest{Model: "claude-haiku-4-5-20251001"},
		}).run()
	}()
	got := nextUsage(t, ch)
	return got, policy.Evaluate(call, ledger, now)
}

// A stream the upstream resets after message_start and one text delta is a
// failed call of unknown cost: the next call of the actor is refused.
func TestPassthroughStreamCutIsUnknownCostAndDeniesNext(t *testing.T) {
	all := actorDenyBudgets()
	for _, tc := range []struct {
		name    string
		budgets []config.RoutingBudget
		deny    string
	}{
		{"actor and batch", all, "budget_cost_unknown:agent"},
		{"actor", all[:1], "budget_cost_unknown:agent"},
		{"batch", all[1:], "budget_cost_unknown:nightly"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, next := cutStreamCall(t, tc.budgets, resetAfter(""))
			if rec.Outcome != "failed" || rec.ErrorType != "upstream_error" {
				t.Fatalf("a cut stream is a failed call: outcome %q error %q", rec.Outcome, rec.ErrorType)
			}
			if next.Deny == nil || next.Deny.Code != tc.deny {
				t.Fatalf("next call of the actor after an unknown-cost call: %+v", next)
			}
		})
	}
}

// Control: a stream that ends with its final usage is charged known and the
// next call is allowed.
func TestPassthroughCompleteStreamStaysKnown(t *testing.T) {
	rec, next := cutStreamCall(t, actorDenyBudgets(), resetAfter(cutStreamEnd))
	if rec.Outcome != "completed" || rec.ErrorType != "" {
		t.Fatalf("a whole stream is completed: outcome %q error %q", rec.Outcome, rec.ErrorType)
	}
	if next.Deny != nil {
		t.Fatalf("next call after a known-cost call: %+v", next)
	}
}

// The agent going away mid-stream is cancelled (the upstream did not fail),
// and a call cut before its final usage is unknown all the same.
func TestPassthroughClientGoneIsCancelledUnknown(t *testing.T) {
	now := time.Now()
	isolatedRoutingAdminRuntimeAt(t, now)
	ch := installPricedUsageEngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(cutStreamStart))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer up.Close()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil).WithContext(ctx)
	hreq, _ := http.NewRequestWithContext(ctx, http.MethodPost, up.URL, nil)
	resp, err := http.DefaultClient.Do(hreq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	w, finish := beginUsage(ctx, httptest.NewRecorder(), modelusage.CallFacts{
		Listener: engine.ListenerGuardrail, Connector: "claudecode", APIFamily: modelusage.FamilyMessages,
		CallRole: modelusage.RoleAgent, Streaming: true, SelectedProvider: "anthropic", SelectedModel: "claude-haiku-4-5-20251001",
	})
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	func() {
		defer finish(nil)
		(&passthroughStream{
			p: newPassthroughProxy(t), w: w, r: req, resp: resp, mode: "observe", label: "t", provider: "anthropic",
			path: "/v1/messages", model: "claude-haiku-4-5-20251001", telemetry: ChatRequest{Model: "claude-haiku-4-5-20251001"},
		}).run()
	}()
	rec := nextUsage(t, ch)
	if rec.Outcome != "cancelled" {
		t.Fatalf("the agent went away: outcome %q error %q", rec.Outcome, rec.ErrorType)
	}
}

// The same handler, whole: a streamed reset and a non-streamed reset are
// recorded as failed with an upstream error, never as completed.
func TestHandlePassthroughCutBodyRecordsUpstreamError(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stream bool
		up     http.HandlerFunc
	}{
		{"streamed", true, resetAfter("")},
		{"non-streamed", false, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", "500")
			_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","usage":{"input_tokens":1000,`))
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			if tc, ok := conn.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			_ = conn.Close()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch := installPricedUsageEngine(t)
			up := httptest.NewServer(tc.up)
			defer up.Close()
			proxy := newPassthroughProxy(t)
			u, _ := url.Parse(up.URL)
			registerForwardingProviderDomain(t, u.Hostname(), "anthropic")
			body := mustJSON(t, map[string]any{"model": "claude-haiku-4-5-20251001", "stream": tc.stream, "max_tokens": 10,
				"messages": []map[string]string{{"role": "user", "content": "hi"}}})
			postPassthrough(t, proxy, up.URL, "/v1/messages", nil, body)
			rec := nextUsage(t, ch)
			if rec.Outcome != "failed" || rec.ErrorType != "upstream_error" {
				t.Fatalf("%s reset: outcome %q error %q status %d", tc.name, rec.Outcome, rec.ErrorType, rec.Status)
			}
		})
	}
}
