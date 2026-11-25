// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"io"
	"net"
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

// actorUsageCall runs one actor call under managed actor and batch deny
// budgets: run answers through the usage writer; it returns the usage record
// and the verdict of the actor's next call.
func actorUsageCall(t *testing.T, f modelusage.CallFacts, ctx context.Context, run func(w http.ResponseWriter)) (modelusage.Record, routingadmin.Verdict) {
	t.Helper()
	budgets := actorDenyBudgets()
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
	if first.Deny != nil {
		t.Fatalf("first call denied: %+v", first.Deny)
	}
	f.Listener, f.Connector, f.CallRole, f.ChargeKeys = engine.ListenerGuardrail, "claudecode", modelusage.RoleAgent, first.ChargeKeys
	w, finish := beginUsage(ctx, httptest.NewRecorder(), f)
	func() {
		defer finish(nil) // as the handlers do
		run(w)
	}()
	return nextUsage(t, ch), policy.Evaluate(call, ledger, now)
}

// cancelOnWrite cancels the agent's context right after a write that
// carries marker has reached the agent: the exact point the agent leaves.
type cancelOnWrite struct {
	http.ResponseWriter
	marker string
	cancel context.CancelFunc
}

func (c *cancelOnWrite) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	if strings.Contains(string(b), c.marker) {
		c.cancel()
	}
	return n, err
}

func (c *cancelOnWrite) Flush() {}

func (c *cancelOnWrite) Unwrap() http.ResponseWriter { return c.ResponseWriter }

const openAIStreamHead = "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-5-mini\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n\n"
const openAIStreamEnd = "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-5-mini\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"

// GAP-1121: an agent that leaves after the final event reached it, before the
// gateway reads the upstream's end of stream, got its whole answer: the call
// is not cut, and the actor's next call is not denied. An agent that leaves
// before the final event stays cancelled and of unknown cost. The cancel
// happens in the write of the marker event, so the order is fixed.
func TestPassthroughAgentLeavesAroundTheFinalEvent(t *testing.T) {
	for _, tc := range []struct {
		name, path, provider, model, body, marker string
		fam                                       modelusage.APIFamily
		whole                                     bool
	}{
		{"openai chat after [DONE]", "/v1/chat/completions", "openai", "gpt-5-mini", openAIStreamHead + openAIStreamEnd, "[DONE]", modelusage.FamilyChat, true},
		{"anthropic after message_stop", "/v1/messages", "anthropic", "claude-haiku-4-5-20251001", cutStreamStart + cutStreamEnd, "message_stop", modelusage.FamilyMessages, true},
		{"openai chat before the final event", "/v1/chat/completions", "openai", "gpt-5-mini", openAIStreamHead, "\"hi\"", modelusage.FamilyChat, false},
		{"anthropic before message_stop", "/v1/messages", "anthropic", "claude-haiku-4-5-20251001", cutStreamStart, "hello", modelusage.FamilyMessages, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte(tc.body))
				w.(http.Flusher).Flush()
				<-r.Context().Done() // the upstream does not end the stream
			}))
			defer up.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req := httptest.NewRequest(http.MethodPost, tc.path, nil).WithContext(ctx)
			hreq, _ := http.NewRequestWithContext(ctx, http.MethodPost, up.URL, nil)
			resp, err := http.DefaultClient.Do(hreq)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			f := modelusage.CallFacts{APIFamily: tc.fam, Streaming: true, SelectedProvider: tc.provider, SelectedModel: tc.model}
			rec, next := actorUsageCall(t, f, ctx, func(w http.ResponseWriter) {
				(&passthroughStream{
					p: newPassthroughProxy(t), w: &cancelOnWrite{ResponseWriter: w, marker: tc.marker, cancel: cancel}, r: req, resp: resp,
					mode: "observe", label: "t", provider: tc.provider, path: tc.path, model: tc.model, telemetry: ChatRequest{Model: tc.model},
				}).run()
			})
			if tc.whole {
				if rec.Outcome != "completed" || next.Deny != nil {
					t.Fatalf("the agent had the whole stream: outcome %q error %q next %+v", rec.Outcome, rec.ErrorType, next.Deny)
				}
				return
			}
			if rec.Outcome != "cancelled" || next.Deny == nil || !strings.HasPrefix(next.Deny.Code, "budget_cost_unknown:") {
				t.Fatalf("the agent left first: outcome %q error %q next %+v", rec.Outcome, rec.ErrorType, next.Deny)
			}
		})
	}
}

// GAP-1122 (a): the fail-open path that forwards a stream it cannot decode
// (an unknown Content-Encoding in observe mode) ends the call with the
// upstream's read error: a cut there is of unknown cost.
func TestPassthroughCopyRestCutIsUnknownCost(t *testing.T) {
	rec, next := cutStreamCall(t, actorDenyBudgets(), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "x-unknown-coding")
		_, _ = w.Write([]byte(cutStreamStart))
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
	})
	if rec.Outcome != "failed" || rec.ErrorType != "upstream_error" {
		t.Fatalf("a cut undecodable stream is a failed call: outcome %q error %q", rec.Outcome, rec.ErrorType)
	}
	if next.Deny == nil || next.Deny.Code != "budget_cost_unknown:agent" {
		t.Fatalf("next call after an unknown-cost call: %+v", next.Deny)
	}
}

type cutChatProvider struct {
	err   error
	usage *ChatUsage
}

func (cutChatProvider) ChatCompletion(context.Context, *ChatRequest) (*ChatResponse, error) {
	return nil, errors.New("unused")
}

func (p cutChatProvider) ChatCompletionStream(_ context.Context, _ *ChatRequest, cb func(StreamChunk)) (*ChatUsage, error) {
	cb(StreamChunk{ID: "c1", Model: "gpt-5-mini", Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Role: "assistant", Content: "hello"}}}})
	return p.usage, p.err
}

func chatFacts() modelusage.CallFacts {
	return modelusage.CallFacts{APIFamily: modelusage.FamilyChat, Streaming: true, SelectedProvider: "openai", SelectedModel: "gpt-5-mini"}
}

// GAP-1112 / GAP-1122 (c): the translated chat stream (handleStreamingRequest)
// ends its usage record with the provider's stream error; (b) the usage the
// provider adapter returns reaches the record.
func TestTranslatedChatStreamUsageOutcome(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prov    cutChatProvider
		outcome string
		denied  bool
	}{
		{"reset", cutChatProvider{err: errors.New("stream read: connection reset by peer")}, "failed", true},
		{"canceled", cutChatProvider{err: context.Canceled}, "cancelled", true},
		{"complete", cutChatProvider{usage: &ChatUsage{PromptTokens: 1000, CompletionTokens: 50, TotalTokens: 1050}}, "completed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy := newTestProxy(t, tc.prov, newMockInspector(), "observe")
			rec, next := actorUsageCall(t, chatFacts(), context.Background(), func(w http.ResponseWriter) {
				chatReq := ChatRequest{Model: "gpt-5-mini", Stream: true, Messages: []ChatMessage{{Role: "user", Content: "hi"}}}
				httpReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
				traceResult := proxyV8DefaultResult(true)
				agentCtx, requestTrace := proxy.startProxyV8RequestTrace(httpReq.Context(), &chatReq, "", "")
				proxy.handleStreamingRequest(w, httpReq, &chatReq, "openai", "observe", "", tc.prov,
					agentCtx, "", nil, requestTrace, &traceResult)
				requestTrace.Finish(traceResult)
			})
			if rec.Outcome != tc.outcome {
				t.Fatalf("outcome %q error %q, want %q", rec.Outcome, rec.ErrorType, tc.outcome)
			}
			if got := next.Deny != nil && strings.HasPrefix(next.Deny.Code, "budget_cost_unknown:"); got != tc.denied {
				t.Fatalf("next call denied for unknown cost = %v, want %v (%+v)", got, tc.denied, next.Deny)
			}
			if tc.prov.usage != nil && (rec.Usage.Input != 1000 || rec.Usage.Output != 50) {
				t.Fatalf("the adapter's usage did not reach the record: %+v", rec.Usage)
			}
		})
	}
}

// noAnswerChatProvider fails before the provider answers: no chunk.
type noAnswerChatProvider struct{ err error }

func (noAnswerChatProvider) ChatCompletion(context.Context, *ChatRequest) (*ChatResponse, error) {
	return nil, errors.New("unused")
}

func (p noAnswerChatProvider) ChatCompletionStream(context.Context, *ChatRequest, func(StreamChunk)) (*ChatUsage, error) {
	return nil, p.err
}

// rel-1-0-10:GAP-2233: on the translated chat stream the gateway sends the
// agent its own 200 and SSE headers before it calls the provider (GAP-0628).
// That header is not the provider answering: a call that fails before the
// provider answered (a refused connect, a 429 the adapter returns as an
// error) is a failed call the provider billed nothing for, never of unknown
// cost, and the actor's next call is allowed. A stream the provider began
// and then broke off stays of unknown cost (TestTranslatedChatStreamUsageOutcome).
func TestTranslatedChatStreamNoAnswerIsNotUnknownCost(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"refused", errors.New("dial tcp 127.0.0.1:9: connect: connection refused")},
		{"429", errors.New("upstream returned status 429: rate limited")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prov := noAnswerChatProvider{err: tc.err}
			proxy := newTestProxy(t, prov, newMockInspector(), "observe")
			rec, next := actorUsageCall(t, chatFacts(), context.Background(), func(w http.ResponseWriter) {
				chatReq := ChatRequest{Model: "gpt-5-mini", Stream: true, Messages: []ChatMessage{{Role: "user", Content: "hi"}}}
				httpReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
				traceResult := proxyV8DefaultResult(true)
				agentCtx, requestTrace := proxy.startProxyV8RequestTrace(httpReq.Context(), &chatReq, "", "")
				proxy.handleStreamingRequest(w, httpReq, &chatReq, "openai", "observe", "", prov,
					agentCtx, "", nil, requestTrace, &traceResult)
				requestTrace.Finish(traceResult)
			})
			if rec.Outcome != "failed" || rec.ErrorType != "upstream_error" {
				t.Errorf("outcome %q error %q, want failed upstream_error", rec.Outcome, rec.ErrorType)
			}
			if next.Deny != nil {
				t.Errorf("next call after a call the provider never answered: %+v", next.Deny)
			}
			if rec.Status == http.StatusOK {
				t.Errorf("the gateway's own 200 reached the record as the provider's status")
			}
		})
	}
}

// The raw (OpenAI-compatible body kept) chat stream ends its usage record
// with the upstream read error too.
func TestRawChatStreamReadErrorIsUnknownCost(t *testing.T) {
	proxy := newTestProxy(t, cutChatProvider{}, newMockInspector(), "observe")
	rec, next := actorUsageCall(t, chatFacts(), context.Background(), func(w http.ResponseWriter) {
		chatReq := ChatRequest{Model: "gpt-5-mini", Stream: true, RawBody: []byte(`{"model":"gpt-5-mini","stream":true}`),
			Messages: []ChatMessage{{Role: "user", Content: "hi"}}}
		httpReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		traceResult := proxyV8DefaultResult(true)
		agentCtx, requestTrace := proxy.startProxyV8RequestTrace(httpReq.Context(), &chatReq, "", "")
		llmCtx, modelTrace := requestTrace.StartModel(agentCtx, proxy.proxyV8ModelInput(agentCtx, &chatReq, "openai", time.Now().UTC()))
		resp := &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Request: httpReq,
			Body: io.NopCloser(io.MultiReader(strings.NewReader(openAIStreamHead), &errAfterReader1112{err: errors.New("connection reset by peer")})),
		}
		proxy.rawForwardChatCompletionStream(w, httpReq, resp, &chatReq, "observe", "", llmCtx, "", "openai",
			modelTrace, &traceResult, time.Now().Add(-time.Millisecond))
		modelTrace.Finish(traceResult)
		requestTrace.Finish(traceResult)
	})
	if rec.Outcome != "failed" || rec.ErrorType != "upstream_error" {
		t.Fatalf("a cut raw chat stream: outcome %q error %q", rec.Outcome, rec.ErrorType)
	}
	if next.Deny == nil || !strings.HasPrefix(next.Deny.Code, "budget_cost_unknown:") {
		t.Fatalf("next call after an unknown-cost call: %+v", next.Deny)
	}
}

type errAfterReader1112 struct{ err error }

func (f *errAfterReader1112) Read([]byte) (int, error) { return 0, f.err }
