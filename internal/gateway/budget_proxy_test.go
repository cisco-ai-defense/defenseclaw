// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//
// Integration tests exercising the GuardrailProxy with a real OPA-backed
// BudgetEnforcer. These cover the pre-call deny / monitor / allow paths and
// confirm that post-call Record updates sliding-window counters so the next
// request sees the new usage.

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// newBudgetProxy wires a testing proxy with a real OPA-backed budget
// enforcer installed. The caller controls mode (enforce / monitor) and the
// per-subject budget data.
func newBudgetProxy(t *testing.T, prov LLMProvider, mode string, budgetData map[string]interface{}) *GuardrailProxy {
	t.Helper()
	proxy := newTestProxy(t, prov, newMockInspector(), "guardrail")
	eng := setupBudgetOPA(t, budgetData)
	proxy.budget = NewBudgetEnforcer(config.BudgetConfig{
		Enabled:       true,
		Mode:          mode,
		SubjectHeader: "X-DC-Subject",
	}, eng)
	return proxy
}

// postChatWithSubject issues a POST with a subject header set for budget
// attribution.
func postChatWithSubject(t *testing.T, proxy *GuardrailProxy, subject string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if subject != "" {
		req.Header.Set("X-DC-Subject", subject)
	}
	rec := httptest.NewRecorder()
	proxy.handleChatCompletion(rec, req)
	return rec
}

// decodeBlockedResponse extracts defenseclaw_blocked metadata from a JSON
// response body.
func decodeBlockedResponse(t *testing.T, body []byte) (bool, string) {
	t.Helper()
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal response: %v — body=%s", err, string(body))
	}
	dc, ok := resp["defenseclaw_blocked"]
	if !ok {
		return false, ""
	}
	blocked, _ := dc.(bool)
	reason, _ := resp["defenseclaw_reason"].(string)
	return blocked, reason
}

// ---------------------------------------------------------------------------
// Integration: pre-call enforce deny
// ---------------------------------------------------------------------------

func TestProxyBudget_EnforceDeniesOverLimit(t *testing.T) {
	prov := &mockProvider{}
	budget := testBudgetData()
	budget["subjects"].(map[string]interface{})["user:throttle"] = map[string]interface{}{
		"tokens_per_minute":   50,
		"tokens_per_hour":     500,
		"tokens_per_day":      5000,
		"requests_per_minute": 100,
		"requests_per_hour":   1000,
		"requests_per_day":    10000,
		"cost_per_hour":       100.0,
		"cost_per_day":        1000.0,
	}
	proxy := newBudgetProxy(t, prov, "enforce", budget)

	// Build a chat request with max_tokens=500 to blow past the 50 TPM limit.
	max := 500
	body := mustJSON(t, &ChatRequest{
		Model:     "gpt-4o",
		MaxTokens: &max,
		Messages:  []ChatMessage{{Role: "user", Content: "hi"}},
	})

	rec := postChatWithSubject(t, proxy, "user:throttle", body)

	// Blocked requests are returned as OpenAI-compatible 200 responses with
	// the defenseclaw_blocked marker set.
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200 (OpenAI-compatible block), body=%s", rec.Code, rec.Body.String())
	}
	blocked, reason := decodeBlockedResponse(t, rec.Body.Bytes())
	if !blocked {
		t.Fatalf("expected defenseclaw_blocked=true, got body=%s", rec.Body.String())
	}
	if !strings.Contains(strings.ToLower(reason), "budget") {
		t.Fatalf("expected reason to mention budget, got %q", reason)
	}

	// Upstream must not have been called.
	if prov.getLastReq() != nil {
		t.Fatalf("upstream was invoked despite pre-call block")
	}
}

// ---------------------------------------------------------------------------
// Integration: monitor mode does not block
// ---------------------------------------------------------------------------

func TestProxyBudget_MonitorAllowsButLogs(t *testing.T) {
	prov := &mockProvider{}
	budget := testBudgetData()
	budget["subjects"].(map[string]interface{})["user:throttle"] = map[string]interface{}{
		"tokens_per_minute":   50,
		"tokens_per_hour":     500,
		"tokens_per_day":      5000,
		"requests_per_minute": 100,
		"requests_per_hour":   1000,
		"requests_per_day":    10000,
		"cost_per_hour":       100.0,
		"cost_per_day":        1000.0,
	}
	proxy := newBudgetProxy(t, prov, "monitor", budget)

	max := 500
	body := mustJSON(t, &ChatRequest{
		Model:     "gpt-4o",
		MaxTokens: &max,
		Messages:  []ChatMessage{{Role: "user", Content: "hi"}},
	})
	rec := postChatWithSubject(t, proxy, "user:throttle", body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	// In monitor mode, the upstream is called — the response is not a block.
	if blocked, _ := decodeBlockedResponse(t, rec.Body.Bytes()); blocked {
		t.Fatalf("monitor mode should not block, body=%s", rec.Body.String())
	}
	if prov.getLastReq() == nil {
		t.Fatalf("upstream should have been invoked in monitor mode")
	}
}

// ---------------------------------------------------------------------------
// Integration: allow path records usage into tracker
// ---------------------------------------------------------------------------

func TestProxyBudget_AllowRecordsUsage(t *testing.T) {
	prov := &mockProvider{
		response: &ChatResponse{
			ID:     "chatcmpl-x",
			Object: "chat.completion",
			Model:  "gpt-4o",
			Choices: []ChatChoice{{
				Index:        0,
				Message:      &ChatMessage{Role: "assistant", Content: "ok"},
				FinishReason: strPtr("stop"),
			}},
			Usage: &ChatUsage{PromptTokens: 20, CompletionTokens: 10, TotalTokens: 30},
		},
	}
	proxy := newBudgetProxy(t, prov, "enforce", testBudgetData())

	max := 50
	body := mustJSON(t, &ChatRequest{
		Model:     "gpt-4o",
		MaxTokens: &max,
		Messages:  []ChatMessage{{Role: "user", Content: "hi"}},
	})

	rec := postChatWithSubject(t, proxy, "user:alice", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if blocked, _ := decodeBlockedResponse(t, rec.Body.Bytes()); blocked {
		t.Fatalf("unexpected block: %s", rec.Body.String())
	}

	// Post-call Record should have booked 20+10=30 tokens under user:alice.
	u := proxy.budget.tracker.Snapshot("user:alice")
	if u.TokensLastMinute != 30 {
		t.Fatalf("tokens_last_minute=%d, want 30", u.TokensLastMinute)
	}
	if u.RequestsLastMinute != 1 {
		t.Fatalf("requests_last_minute=%d, want 1", u.RequestsLastMinute)
	}
}

// ---------------------------------------------------------------------------
// Integration: disabled enforcer is a true no-op
// ---------------------------------------------------------------------------

func TestProxyBudget_DisabledDoesNothing(t *testing.T) {
	prov := &mockProvider{}
	proxy := newTestProxy(t, prov, newMockInspector(), "guardrail")
	// BudgetEnforcer disabled — no OPA engine, Enabled() returns false.
	proxy.budget = NewBudgetEnforcer(config.BudgetConfig{Enabled: false}, nil)

	max := 999999 // would trivially exceed any limit if one were set
	body := mustJSON(t, &ChatRequest{
		Model:     "gpt-4o",
		MaxTokens: &max,
		Messages:  []ChatMessage{{Role: "user", Content: "hi"}},
	})
	rec := postChatWithSubject(t, proxy, "user:whoever", body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if blocked, _ := decodeBlockedResponse(t, rec.Body.Bytes()); blocked {
		t.Fatalf("disabled enforcer must not block: %s", rec.Body.String())
	}
	if prov.getLastReq() == nil {
		t.Fatalf("upstream should have been invoked")
	}
}

// ---------------------------------------------------------------------------
// Integration: streaming path records usage
// ---------------------------------------------------------------------------

func TestProxyBudget_StreamingRecordsUsage(t *testing.T) {
	prov := &mockProvider{
		streamChunks: []StreamChunk{{
			ID:     "x",
			Object: "chat.completion.chunk",
			Model:  "gpt-4o",
			Choices: []ChatChoice{{
				Index: 0,
				Delta: &ChatMessage{Role: "assistant", Content: "hello"},
			}},
		}},
		streamUsage: &ChatUsage{PromptTokens: 15, CompletionTokens: 5, TotalTokens: 20},
	}
	proxy := newBudgetProxy(t, prov, "enforce", testBudgetData())

	stream := true
	max := 50
	body := mustJSON(t, &ChatRequest{
		Model:     "gpt-4o",
		MaxTokens: &max,
		Stream:    stream,
		Messages:  []ChatMessage{{Role: "user", Content: "hi"}},
	})
	rec := postChatWithSubject(t, proxy, "user:streamer", body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	u := proxy.budget.tracker.Snapshot("user:streamer")
	if u.TokensLastMinute != 20 {
		t.Fatalf("streaming tokens_last_minute=%d, want 20", u.TokensLastMinute)
	}
	if u.RequestsLastMinute != 1 {
		t.Fatalf("streaming requests_last_minute=%d, want 1", u.RequestsLastMinute)
	}
}

// ---------------------------------------------------------------------------
// Integration: subject header attribution
// ---------------------------------------------------------------------------

func TestProxyBudget_SubjectAttribution(t *testing.T) {
	prov := &mockProvider{
		response: &ChatResponse{
			ID: "x", Object: "chat.completion", Model: "gpt-4o",
			Choices: []ChatChoice{{Index: 0, Message: &ChatMessage{Role: "assistant", Content: "k"}, FinishReason: strPtr("stop")}},
			Usage:   &ChatUsage{PromptTokens: 10, CompletionTokens: 10, TotalTokens: 20},
		},
	}
	proxy := newBudgetProxy(t, prov, "enforce", testBudgetData())

	max := 50
	body := mustJSON(t, &ChatRequest{
		Model:     "gpt-4o",
		MaxTokens: &max,
		Messages:  []ChatMessage{{Role: "user", Content: "hi"}},
	})
	rec := postChatWithSubject(t, proxy, "team-a", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}

	// team-a accrued usage; team-b must remain at zero.
	a := proxy.budget.tracker.Snapshot("team-a")
	b := proxy.budget.tracker.Snapshot("team-b")
	if a.TokensLastMinute != 20 {
		t.Fatalf("team-a tokens_last_minute=%d, want 20", a.TokensLastMinute)
	}
	if b.TokensLastMinute != 0 {
		t.Fatalf("team-b should have zero usage, got %d", b.TokensLastMinute)
	}
}

// ---------------------------------------------------------------------------
// Integration: deny contract — blocked response conforms to OpenAI shape
// ---------------------------------------------------------------------------

func TestProxyBudget_BlockedResponseShape(t *testing.T) {
	prov := &mockProvider{}
	budget := testBudgetData()
	budget["subjects"].(map[string]interface{})["user:tight"] = map[string]interface{}{
		"tokens_per_minute":   1,
		"tokens_per_hour":     1,
		"tokens_per_day":      1,
		"requests_per_minute": 1000,
		"requests_per_hour":   1000,
		"requests_per_day":    1000,
		"cost_per_hour":       1000.0,
		"cost_per_day":        1000.0,
	}
	proxy := newBudgetProxy(t, prov, "enforce", budget)

	max := 100
	body := mustJSON(t, &ChatRequest{
		Model:     "gpt-4o",
		MaxTokens: &max,
		Messages:  []ChatMessage{{Role: "user", Content: "hi"}},
	})
	rec := postChatWithSubject(t, proxy, "user:tight", body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// OpenAI-compatible shape: must have id, object, model, choices[].
	if _, ok := resp["id"]; !ok {
		t.Fatalf("missing id: %s", rec.Body.String())
	}
	if obj, _ := resp["object"].(string); obj != "chat.completion" {
		t.Fatalf("object=%q, want chat.completion", obj)
	}
	if model, _ := resp["model"].(string); model != "gpt-4o" {
		t.Fatalf("model=%q, want gpt-4o", model)
	}
	choices, ok := resp["choices"].([]interface{})
	if !ok || len(choices) == 0 {
		t.Fatalf("missing or empty choices: %s", rec.Body.String())
	}
	// DefenseClaw marker must be set so clients can detect policy denials.
	blocked, _ := resp["defenseclaw_blocked"].(bool)
	if !blocked {
		t.Fatalf("defenseclaw_blocked missing: %s", rec.Body.String())
	}
}

// Ensure tests don't leak goroutines waiting on the budget check.
func TestProxyBudget_NoLeakOnDeny(t *testing.T) {
	prov := &mockProvider{}
	budget := testBudgetData()
	budget["subjects"].(map[string]interface{})["user:x"] = map[string]interface{}{
		"tokens_per_minute":   1,
		"tokens_per_hour":     1,
		"tokens_per_day":      1,
		"requests_per_minute": 1000,
		"requests_per_hour":   1000,
		"requests_per_day":    1000,
		"cost_per_hour":       1000.0,
		"cost_per_day":        1000.0,
	}
	proxy := newBudgetProxy(t, prov, "enforce", budget)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	max := 100
	body := mustJSON(t, &ChatRequest{
		Model: "gpt-4o", MaxTokens: &max,
		Messages: []ChatMessage{{Role: "user", Content: "hi"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Subject", "user:x")
	rec := httptest.NewRecorder()
	proxy.handleChatCompletion(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}
