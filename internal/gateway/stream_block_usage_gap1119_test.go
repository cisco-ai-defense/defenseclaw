// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

// substrate-1:GAP-1119: a guardrail block in the middle of a stream ended
// the stream with the gateway's own block tail, and the usage record read
// that tail as the provider's answer. On the /llm passthrough the Anthropic
// tail carries message_delta usage output_tokens 1, so the call was charged
// as known input + 1 output token although the provider billed the output
// it generated up to the cut; on the translated chat path the record had no
// usage at all and charged nothing. A stream the gateway ends is now a
// cancelled call (error type blocked) whose usage is only what the provider
// sent, so a block before the final usage is of unknown cost.

const gap1119Model = "claude-haiku-4-5-20251001"

// gap1119Budgets starts the routing admin runtime with managed actor and
// batch deny budgets and returns the first call of the actor (allowed).
func gap1119Budgets(t *testing.T) (*routingadmin.Policy, *routingadmin.Ledger, routingadmin.Request, routingadmin.Verdict) {
	t.Helper()
	now := time.Now()
	isolatedRoutingAdminRuntimeAt(t, now)
	budgets := actorDenyBudgets()
	policy := routingadmin.Compile(nil, budgets, true)
	cfg := &config.Config{}
	cfg.Routing.Admin = &config.RoutingAdminConfig{Budgets: budgets}
	if routingAdminRuntime.For(cfg) == nil {
		t.Fatal("evaluator")
	}
	ledger := routingAdminRuntime.Ledger()
	ledger.ApplyRemote(policy.BudgetIDs(), nil, now)
	call := routingadmin.Request{Connector: "claudecode", Actor: &engine.Actor{Key: "substrate:eng-web/a1", Atespace: "eng-web", BatchID: "run-7"}}
	first := policy.Evaluate(call, ledger, now)
	if first.Deny != nil || len(first.ChargeKeys) != len(budgets) {
		t.Fatalf("first call must be allowed and charge actor and batch: %+v", first)
	}
	return policy, ledger, call, first
}

func gap1119Facts(family modelusage.APIFamily, provider, model string, keys []string) modelusage.CallFacts {
	return modelusage.CallFacts{
		Listener: engine.ListenerGuardrail, Connector: "claudecode", APIFamily: family,
		CallRole: modelusage.RoleAgent, Streaming: true,
		RequestedProvider: provider, RequestedModel: model, SelectedProvider: provider, SelectedModel: model,
		ChargeKeys: keys,
	}
}

// A refused tool call after reply text went out ends the Anthropic stream
// with the block tail; the provider's message_delta never reached the agent.
func TestPassthroughBlockMidStreamIsUnknownCost(t *testing.T) {
	covAllowPrivate(t)
	policy, ledger, call, first := gap1119Budgets(t)
	ch := installPricedUsageEngine(t)
	text, _ := json.Marshal(gap1206Text)
	name, _ := json.Marshal(covBlockedTool)
	up := gap1206Upstream(t, "text/event-stream",
		gap1206SSE(`{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"`+gap1119Model+`","content":[],"usage":{"input_tokens":1000,"output_tokens":1}}}`,
			`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":`+string(text)+`}}`,
			`{"type":"content_block_stop","index":0}`),
		gap1206SSE(`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"tu_1","name":`+string(name)+`,"input":{}}}`,
			`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"note\":\"x\"}"}}`,
			`{"type":"content_block_stop","index":1}`,
			`{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":400}}`,
			`{"type":"message_stop"}`))
	proxy := covProxy(t, up, "anthropic", &covInspector{})
	gap1206SendFirst(t, proxy)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{"model":"`+gap1119Model+`","stream":true}`))
	hreq, err := http.NewRequestWithContext(req.Context(), http.MethodPost, up.srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(hreq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := httptest.NewRecorder()
	w, finish := beginUsage(req.Context(), out, gap1119Facts(modelusage.FamilyMessages, "anthropic", gap1119Model, first.ChargeKeys))
	func() {
		defer finish(nil) // as handlePassthrough does
		(&passthroughStream{
			p: proxy, w: w, r: req, resp: resp, mode: "action", label: "t", provider: "anthropic",
			path: "/v1/messages", model: gap1119Model, telemetry: ChatRequest{Model: gap1119Model},
		}).run()
	}()
	rec := nextUsage(t, ch)
	body := out.Body.String()
	if strings.Contains(body, covBlockedTool) || !strings.Contains(body, "message_stop") {
		t.Fatalf("precondition: the refused call ends the stream with the block tail:\n%.600s", body)
	}
	if rec.Outcome != "cancelled" || rec.ErrorType != "blocked" {
		t.Fatalf("a stream the gateway ended is a cancelled, blocked call: outcome %q error %q usage %+v", rec.Outcome, rec.ErrorType, rec.Usage)
	}
	if next := policy.Evaluate(call, ledger, time.Now()); next.Deny == nil || next.Deny.Code != "budget_cost_unknown:agent" {
		t.Fatalf("next call of the actor after a block before the final usage: %+v", next)
	}
}

// gap1119ChatProvider streams text with the block marker, then either waits
// for the cut (cut) or ends with the provider's usage, ignoring the cut.
type gap1119ChatProvider struct {
	mockProvider
	cut bool
}

func (p *gap1119ChatProvider) ChatCompletionStream(ctx context.Context, _ *ChatRequest, cb func(StreamChunk)) (*ChatUsage, error) {
	for _, part := range []string{"working on it. ", strings.Repeat(covMarker+" reading the files. ", 80)} {
		cb(StreamChunk{ID: "c1", Object: "chat.completion.chunk", Model: "gpt-5-mini",
			Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Role: "assistant", Content: part}}}})
	}
	if p.cut {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return nil, nil
		}
	}
	return &ChatUsage{PromptTokens: 1000, CompletionTokens: 400, TotalTokens: 1400}, nil
}

// The translated chat path: a mid-stream block cuts the provider call before
// its usage, so the call is of unknown cost; a block after the provider
// returned its usage keeps the known cost.
func TestTranslatedChatBlockMidStreamIsUnknownCost(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cut     bool
		unknown bool
	}{{"cut before usage", true, true}, {"usage returned", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			policy, ledger, call, first := gap1119Budgets(t)
			ch := installPricedUsageEngine(t)
			prov := &gap1119ChatProvider{cut: tc.cut}
			proxy := newTestProxy(t, prov, &covInspector{}, "action")
			gap1206SendFirst(t, proxy)
			chatReq := ChatRequest{Model: "gpt-5-mini", Stream: true, Messages: []ChatMessage{{Role: "user", Content: "hi"}}}
			httpReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			out := httptest.NewRecorder()
			w, finish := beginUsage(httpReq.Context(), out, gap1119Facts(modelusage.FamilyChat, "openai", "gpt-5-mini", first.ChargeKeys))
			func() {
				defer finish(nil)
				traceResult := proxyV8DefaultResult(true)
				agentCtx, requestTrace := proxy.startProxyV8RequestTrace(httpReq.Context(), &chatReq, "", "")
				proxy.handleStreamingRequest(w, httpReq, &chatReq, "openai", "action", "", prov, agentCtx, "", nil, requestTrace, &traceResult)
				requestTrace.Finish(traceResult)
			}()
			rec := nextUsage(t, ch)
			if !strings.Contains(out.Body.String(), "chatcmpl-blocked") {
				t.Fatalf("precondition: the stream is blocked:\n%.600s", out.Body.String())
			}
			if rec.Outcome != "cancelled" || rec.ErrorType != "blocked" {
				t.Fatalf("a stream the gateway ended is a cancelled, blocked call: outcome %q error %q", rec.Outcome, rec.ErrorType)
			}
			next := policy.Evaluate(call, ledger, time.Now())
			switch {
			case tc.unknown && (next.Deny == nil || next.Deny.Code != "budget_cost_unknown:agent"):
				t.Fatalf("next call after a block before the provider's usage: %+v", next)
			case !tc.unknown && next.Deny != nil:
				t.Fatalf("next call after a block with the provider's usage (known cost): %+v", next.Deny)
			case !tc.unknown && (rec.Cost.ComputedUSD == nil || *rec.Cost.ComputedUSD <= 0):
				t.Fatalf("the provider's usage keeps its computed cost: %+v", rec.Cost)
			}
		})
	}
}

type gap1119NopRW struct{ h http.Header }

func (n gap1119NopRW) Header() http.Header         { return n.h }
func (n gap1119NopRW) WriteHeader(int)             {}
func (n gap1119NopRW) Write(b []byte) (int, error) { return len(b), nil }

// Allocation pin of the /llm stream path: the usage writer's Write takes no
// allocation of its own, before and after the gateway ends the stream.
func TestUsageWriterWriteAllocs(t *testing.T) {
	uw := &usageResponseWriter{ResponseWriter: gap1119NopRW{h: http.Header{}}, call: modelusage.Noop.Begin(context.Background(), modelusage.CallFacts{}), streaming: true}
	b := []byte(cutStreamStart)
	if a := testing.AllocsPerRun(1000, func() { _, _ = uw.Write(b) }); a != 0 {
		t.Fatalf("allocs per streamed write: %v", a)
	}
	usageStreamBlocked(uw)
	if a := testing.AllocsPerRun(1000, func() { _, _ = uw.Write(b) }); a != 0 {
		t.Fatalf("allocs per write after the block: %v", a)
	}
}
