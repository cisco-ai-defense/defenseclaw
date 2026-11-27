// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// rel-1-0-10:GAP-2254 and GAP-2255: on the translated chat stream, a call
// in which the provider accepted a request (HTTP 2xx: a stream opened, a
// Replicate prediction was created) and that then broke before its usage
// is of unknown cost, so the actor's next call is denied. An error status
// that came inside the stream (Gemini error.code, an OpenAI-family
// status_code, a Bedrock retryable exception) or from a later request of
// the same call (an agent-supplied fallback, the Replicate stream URL) does
// not make it a failed http_NNN call that cost nothing. A call whose every
// request was refused with an error status stays a failed http_NNN call and
// the next call is allowed (rel-1-0-10:GAP-2238).
func TestTranslatedChatStreamAcceptedRequestIsUnknownCost(t *testing.T) {
	sse200 := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
	}
	status := func(w http.ResponseWriter, code int, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
	const rateLimited = `{"error":{"message":"rate limited","type":"rate_limit_error"}}`
	for _, tc := range []struct {
		name, model string
		root        bool // base URL without /v1
		fallbacks   []string
		h           func(w http.ResponseWriter, r *http.Request, hit int32, url string)
		denied      bool
		status      int    // the provider's status on the record
		errType     string // the record's error type when the call is not denied
	}{
		// GAP-2254: the status is inside a stream the provider opened with 200.
		{"oa-200-sse-error-status500", "openai/gpt-5-mini", false, nil, func(w http.ResponseWriter, r *http.Request, _ int32, _ string) {
			sse200(w)
			_, _ = w.Write([]byte("data: {\"error\":{\"message\":\"server error mid stream\",\"type\":\"server_error\"},\"status_code\":500}\n\n"))
		}, true, http.StatusOK, ""},
		{"gemini-200-then-error-code500", "gemini/gemini-2.5-flash", true, nil, func(w http.ResponseWriter, r *http.Request, _ int32, _ string) {
			sse200(w)
			_, _ = w.Write([]byte("data: {\"error\":{\"code\":500,\"message\":\"Internal error encountered.\",\"status\":\"INTERNAL\"}}\n\n"))
		}, true, http.StatusOK, ""},
		// Unchanged: the reverse order, and calls no provider accepted.
		{"fallback-200-reset-then-429", "openai/gpt-5-mini", false, []string{"openai/gpt-5-nano"}, func(w http.ResponseWriter, r *http.Request, hit int32, _ string) {
			if hit == 1 {
				sse200(w)
				time.Sleep(50 * time.Millisecond)
				resetConn1112(w)
				return
			}
			status(w, http.StatusTooManyRequests, rateLimited)
		}, true, http.StatusOK, ""},
		{"fallback-429-then-429", "openai/gpt-5-mini", false, []string{"openai/gpt-5-nano"}, func(w http.ResponseWriter, r *http.Request, _ int32, _ string) {
			status(w, http.StatusTooManyRequests, rateLimited)
		}, false, http.StatusTooManyRequests, "http_429"},
		{"oa-503", "openai/gpt-5-mini", false, nil, func(w http.ResponseWriter, r *http.Request, _ int32, _ string) {
			status(w, http.StatusServiceUnavailable, `{"error":{"message":"unavailable","type":"server_error"}}`)
		}, false, http.StatusServiceUnavailable, "http_503"},
		{"replicate-create-429", "replicate/meta/meta-llama-3-8b-instruct", true, nil, func(w http.ResponseWriter, r *http.Request, _ int32, _ string) {
			status(w, http.StatusTooManyRequests, `{"detail":"rate limited"}`)
		}, false, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			var upURL string
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tc.h(w, r, hits.Add(1), upURL)
			}))
			defer up.Close()
			upURL = up.URL
			base := up.URL + "/v1"
			if tc.root {
				base = up.URL
			}
			prov, err := NewProviderWithBase(tc.model, "fixture-key", base)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			proxy := newTestProxy(t, prov, newMockInspector(), "observe")
			rec, next := actorUsageCall(t, chatFacts(), ctx, func(w http.ResponseWriter) {
				chatReq := ChatRequest{Model: "gpt-5-mini", Stream: true, Fallbacks: tc.fallbacks, Messages: []ChatMessage{{Role: "user", Content: "hi"}}}
				httpReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil).WithContext(ctx)
				traceResult := proxyV8DefaultResult(true)
				agentCtx, requestTrace := proxy.startProxyV8RequestTrace(httpReq.Context(), &chatReq, "", "")
				proxy.handleStreamingRequest(w, httpReq, &chatReq, "openai", "observe", "", prov,
					agentCtx, "", nil, requestTrace, &traceResult)
				requestTrace.Finish(traceResult)
			})
			if rec.Outcome != "failed" {
				t.Errorf("outcome %q error %q, want failed", rec.Outcome, rec.ErrorType)
			}
			if got := next.Deny != nil && strings.HasPrefix(next.Deny.Code, "budget_cost_unknown:"); got != tc.denied {
				t.Errorf("next call denied for unknown cost = %v, want %v (record status %d error %q, %d provider requests)", got, tc.denied, rec.Status, rec.ErrorType, hits.Load())
			}
			if rec.Status != tc.status {
				t.Errorf("record status %d, want %d", rec.Status, tc.status)
			}
			if tc.errType != "" && rec.ErrorType != tc.errType {
				t.Errorf("error type %q, want %q", rec.ErrorType, tc.errType)
			}
		})
	}
}

// rel-1-0-10:GAP-2254: a Bedrock retryable stream exception (here
// serviceUnavailableException, mapped to 503) is an error Bifrost did not make
// itself and carries a status, like an HTTP status refusal. It is the
// provider's 503 only when no stream opened; after Bifrost marked the call
// accepted it answered 200.
func TestBifrostStreamAnswerAcceptedCall(t *testing.T) {
	code := http.StatusServiceUnavailable
	typ := "serviceUnavailableException"
	exc := &schemas.BifrostError{StatusCode: &code, Type: &typ, Error: &schemas.ErrorField{Message: "bedrock stream serviceUnavailableException: try again"}}
	for _, tc := range []struct {
		name     string
		accepted bool
		want     int
	}{
		{"refused-with-status", false, http.StatusServiceUnavailable},
		{"stream-opened", true, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bCtx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			bCtx.SetValue(schemas.BifrostContextKeyProviderResponseHeaders, map[string]string{})
			if tc.accepted {
				bCtx.SetValue(schemas.BifrostContextKeyProviderAccepted, true)
			}
			if got, ok := bifrostStreamAnswer(bCtx, exc); !ok || got != tc.want {
				t.Errorf("bifrostStreamAnswer = %d, %v; want %d, true", got, ok, tc.want)
			}
		})
	}
}
