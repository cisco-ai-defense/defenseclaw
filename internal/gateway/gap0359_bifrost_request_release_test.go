// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestGAP0359TimedOutModelCallKeepsItsRequestUntilTheWorkerIsDone: a model
// call that ends on its deadline (the 0.4 s hook judge timeout) returned to
// the caller while the Bifrost provider worker still held the pooled request;
// handleRequest reset that request and put it back in the pool, so the
// worker's next read of it (GetRequestFields) raced the reset and a later call
// could be handed the same object (rel-1-0-10:GAP-0359: DATA RACE in
// TestHookLaneJudgeProviderFailuresFollowTheHookFailMode on a loaded box).
// The model answers only after the caller's deadline, so every call here takes
// that path; under -race the reset is reported as a data race on the first
// call. A call that answers in time (the benign twin) keeps its answer.
func TestGAP0359TimedOutModelCallKeepsItsRequestUntilTheWorkerIsDone(t *testing.T) {
	closeBifrostTenantsAfter(t)
	var entered, open atomic.Int32
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered.Add(1)
		open.Add(1)
		defer open.Add(-1)
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		select { // answer after the caller's deadline, whatever the transport does
		case <-release:
		case <-time.After(300 * time.Millisecond):
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":"gap0359-late","object":"chat.completion","created":1,"model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"late"},"finish_reason":"stop"}]}`)
	}))
	defer server.Close()
	provider, err := NewProviderForLLMConfig(&config.LLMConfig{
		Provider: "openai", Model: "openai/test-model", APIKey: "test-placeholder-gap0359", BaseURL: server.URL,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		_, callErr := provider.ChatCompletion(ctx, &ChatRequest{
			Model: "openai/test-model", Messages: []ChatMessage{{Role: "user", Content: fmt.Sprintf("summarize file %d", i)}},
		})
		cancel()
		if !errors.Is(callErr, context.DeadlineExceeded) {
			t.Fatalf("call %d: error %v, want the deadline", i, callErr)
		}
	}
	close(release)
	// Let every worker finish with its request inside the test: a call can end
	// before its request reaches the server (the deadline cut the dial), so the
	// wait is for the calls the server took to end.
	for end := time.Now().Add(10 * time.Second); open.Load() > 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("%d model calls still open 10 s after their deadline", open.Load())
		}
	}
	t.Logf("%d of 8 calls reached the model server before their deadline", entered.Load())

	answer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":"gap0359-twin","object":"chat.completion","created":1,"model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"in time"},"finish_reason":"stop"}]}`)
	}))
	defer answer.Close()
	twin, err := NewProviderForLLMConfig(&config.LLMConfig{
		Provider: "openai", Model: "openai/test-model", APIKey: "test-placeholder-gap0359-twin", BaseURL: answer.URL,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := twin.ChatCompletion(t.Context(), &ChatRequest{
		Model: "openai/test-model", Messages: []ChatMessage{{Role: "user", Content: "list the files"}},
	})
	if err != nil || resp == nil || len(resp.Choices) == 0 || resp.Choices[0].Message == nil || resp.Choices[0].Message.Content != "in time" {
		t.Fatalf("a call that answers in time: %+v, %v", resp, err)
	}
}
