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
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// The real provider must retain the caller's cancellation cause after the
// transport closes, so judge records can name a stopped request correctly.
func TestGAP0564RealProviderCancellationReason(t *testing.T) {
	entered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	defer server.CloseClientConnections()
	provider, err := NewProviderForLLMConfig(&config.LLMConfig{
		Provider: "openai", Model: "openai/test-model", APIKey: "test-placeholder", BaseURL: server.URL,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, callErr := provider.ChatCompletion(ctx, &ChatRequest{
			Model: "openai/test-model", Messages: []ChatMessage{{Role: "user", Content: "summarize these files"}},
		})
		done <- callErr
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("model transport did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("model cancellation cause = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("model transport did not stop after cancellation")
	}
}

// A completed model request still supplies the benign judge answer.
func TestGAP0564RealProviderBenignAnswer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":"gap0564-answer","object":"chat.completion","created":1,"model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}]}`, allFalseInjectionJSON)
	}))
	defer server.Close()
	provider, err := NewProviderForLLMConfig(&config.LLMConfig{
		Provider: "openai", Model: "openai/test-model", APIKey: "test-placeholder", BaseURL: server.URL,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	judge := &LLMJudge{
		cfg:   &config.JudgeConfig{Enabled: true, Injection: true},
		model: "test-model", provider: provider, rp: &guardrail.RulePack{},
	}
	verdict := judge.runInjectionJudge(t.Context(), "please list the files in this folder")
	if verdict == nil || verdict.Action != "allow" {
		t.Fatalf("benign judge answer = %+v, want allow", verdict)
	}
}
