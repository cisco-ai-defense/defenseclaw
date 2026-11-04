// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

type gap0564HTTPProvider struct {
	mockLLMProvider
	client *http.Client
	url    string
}

func (p *gap0564HTTPProvider) ChatCompletion(ctx context.Context, _ *ChatRequest) (*ChatResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &ChatResponse{Choices: []ChatChoice{{Message: &ChatMessage{Content: string(content)}}}}, nil
}

// A bounded hook releases its model request and every queued judge when its
// answer window closes. The completion record names the cancellation.
func TestGAP0564BoundedHookCancelsHTTPAndQueue(t *testing.T) {
	var started atomic.Int32
	entered := make(chan struct{}, 1)
	disconnected := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		started.Add(1)
		select {
		case entered <- struct{}{}:
		default:
		}
		<-r.Context().Done()
		select {
		case disconnected <- struct{}{}:
		default:
		}
	}))
	defer server.Close()
	defer server.CloseClientConnections()

	auditStore, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditStore.Close()
	if err := auditStore.Init(); err != nil {
		t.Fatal(err)
	}
	logger := audit.NewLogger(auditStore)
	runtime := &captureJudgeRuntimeV8Emitter{}
	logger.SetRuntimeV8Emitter(runtime)
	responses := NewJudgeStore(nil, logger, 16)
	SetJudgeResponseStore(responses)
	defer SetJudgeResponseStore(nil)
	defer responses.Shutdown(context.Background())

	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.DetectionStrategy = "judge_first"
	cfg.Guardrail.Judge = config.JudgeConfig{
		Enabled: true, Injection: true, HookConnectors: []string{"codex"}, HookTimeout: 4,
	}
	provider := &gap0564HTTPProvider{client: server.Client(), url: server.URL}
	scheduler := &judgeScheduler{limit: 1}
	judge := &LLMJudge{
		cfg: &cfg.Guardrail.Judge, model: "test-model", provider: provider,
		rp: &guardrail.RulePack{}, calls: scheduler,
	}
	api := &APIServer{scannerCfg: cfg}
	api.SetHookJudge(judge)

	const calls = 6
	results := make(chan *ScanVerdict, calls)
	start := time.Now().Add(-2 * time.Second)
	run := func() {
		results <- api.runHookJudge(boundedHookContext(start), "prompt", "prompt", "codex",
			"please list the files in this folder", "", nil)
	}
	go run()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the model request did not start")
	}
	for i := 1; i < calls; i++ {
		go run()
	}
	for i := 0; i < calls; i++ {
		select {
		case verdict := <-results:
			if verdict != nil {
				t.Fatalf("late judge changed the rule verdict: %+v", verdict)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("a hook answer waited past its window")
		}
	}
	select {
	case <-disconnected:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("model server did not see the client disconnect")
	}
	deadline := time.Now().Add(time.Second)
	for len(api.hookJudgeSem) != 0 || scheduler.queued(judgeCallContent) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("judge work remained: hook slots=%d queued=%d", len(api.hookJudgeSem), scheduler.queued(judgeCallContent))
		}
		time.Sleep(time.Millisecond)
	}
	if got := started.Load(); got != 1 {
		t.Fatalf("model requests started=%d, want only the first call", got)
	}
	if err := responses.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, record := range runtime.snapshot() {
		if judgeCanonicalAttributes(t, record)["defenseclaw.judge.error_summary"] == "cancelled" {
			return
		}
	}
	t.Fatal("judge completion did not record the cancellation reason")
}

// A model answer received while the hook is waiting still decides a benign
// call and is recorded before the request context ends.
func TestGAP0564BenignAnswerBeforeCancellation(t *testing.T) {
	auditStore, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditStore.Close()
	if err := auditStore.Init(); err != nil {
		t.Fatal(err)
	}
	logger := audit.NewLogger(auditStore)
	runtime := &captureJudgeRuntimeV8Emitter{}
	logger.SetRuntimeV8Emitter(runtime)
	responses := NewJudgeStore(nil, logger, 8)
	SetJudgeResponseStore(responses)
	defer SetJudgeResponseStore(nil)
	defer responses.Shutdown(context.Background())

	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.DetectionStrategy = "judge_first"
	cfg.Guardrail.Judge = config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"codex"}}
	provider := &mockLLMProvider{response: &ChatResponse{
		Choices: []ChatChoice{{Message: &ChatMessage{Content: allFalseInjectionJSON}}},
	}}
	api := &APIServer{scannerCfg: cfg}
	api.SetHookJudge(&LLMJudge{cfg: &cfg.Guardrail.Judge, model: "test-model", provider: provider, rp: &guardrail.RulePack{}})
	verdict := api.runHookJudge(boundedHookContext(time.Now()), "prompt", "prompt", "codex",
		"please list the files in this folder", "", nil)
	if verdict == nil || verdict.Action != "allow" {
		t.Fatalf("benign judge answer changed the call: %+v", verdict)
	}
	if err := responses.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	records := runtime.snapshot()
	if len(records) != 1 || string(records[0].Outcome()) != "allowed" {
		t.Fatalf("benign judge completion was not recorded: count=%d", len(records))
	}
}

func TestGAP0564ProxyPostCallContextFollowsCaller(t *testing.T) {
	proxy := &GuardrailProxy{}
	caller, cancel := context.WithCancel(context.Background())
	post, done := proxy.postCallContext(caller)
	defer done()
	cancel()
	select {
	case <-post.Done():
		if post.Err() != context.Canceled {
			t.Fatalf("proxy context ended with %v, want caller cancellation", post.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("proxy judge kept running after its caller ended")
	}

	proxy.SetSecureClientIntegration(true)
	secureCaller, secureCancel := context.WithCancel(context.Background())
	securePost, secureDone := proxy.postCallContext(secureCaller)
	defer secureDone()
	secureCancel()
	select {
	case <-securePost.Done():
		t.Fatal("Secure Client completion context changed with caller cancellation")
	case <-time.After(20 * time.Millisecond):
	}
}
