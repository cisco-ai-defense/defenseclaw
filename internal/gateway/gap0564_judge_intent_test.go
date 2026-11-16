// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

type gap0564IntentProvider struct {
	mockLLMProvider
	started chan struct{}
	calls   atomic.Int32
}

func (p *gap0564IntentProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	if p.calls.Add(1) == 1 {
		close(p.started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return p.mockLLMProvider.ChatCompletion(ctx, req)
}

// A canceled queued call keeps its place in the session history. A later
// call still carries the user task supplied through UserPromptSubmit.
func TestGAP0564QueuedCancellationPreservesClaudeCodeJudgeIntent(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.DetectionStrategy = "regex_only"
	cfg.Guardrail.DetectionStrategyToolCall = "judge_first"
	cfg.Guardrail.Judge = config.JudgeConfig{Enabled: true, ToolInjection: true, HookConnectors: []string{"claudecode"}}
	provider := &gap0564IntentProvider{
		mockLLMProvider: mockLLMProvider{response: injectionHitProvider().response},
		started:         make(chan struct{}),
	}
	judge := &LLMJudge{
		cfg: &cfg.Guardrail.Judge, model: "test-model", provider: provider,
		rp: &guardrail.RulePack{}, calls: &judgeScheduler{limit: 1},
	}
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	api.SetHookJudge(judge)
	postClaudeCodeHook(t, api, `{"session_id":"cc-intent-queued","hook_event_name":"UserPromptSubmit","cwd":"/tmp",`+
		`"prompt":"list the quarterly report fixtures"}`)

	base := ContextWithSessionID(t.Context(), "cc-intent-queued")
	firstCtx, cancelFirst := context.WithCancel(base)
	defer cancelFirst()
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		judge.RunToolJudge(firstCtx, "Bash", `{"command":"list first-marker fixtures"}`)
	}()
	select {
	case <-provider.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first judge call did not start")
	}

	queuedCtx, cancelQueued := context.WithCancel(base)
	queuedDone := make(chan struct{})
	go func() {
		defer close(queuedDone)
		judge.RunToolJudge(queuedCtx, "Bash", `{"command":"list queued-marker fixtures"}`)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for judge.calls.queued(judgeCallTool) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("second judge call did not queue")
		}
		time.Sleep(time.Millisecond)
	}
	cancelQueued()
	select {
	case <-queuedDone:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled queued call did not finish")
	}
	cancelFirst()
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled running call did not finish")
	}

	judge.RunToolJudge(base, "Bash", `{"command":"list retry-marker fixtures"}`)
	if got := provider.calls.Load(); got != 2 {
		t.Fatalf("provider calls=%d, want the running call and the retry", got)
	}
	sample := lastToolJudgeSample(t, &provider.mockLLMProvider)
	markers := []string{"list the quarterly report fixtures", "first-marker", "queued-marker", "retry-marker"}
	previous := -1
	for _, marker := range markers {
		position := strings.Index(sample, marker)
		if position <= previous {
			t.Fatalf("judge sample lost or reordered %q: %q", marker, sample)
		}
		previous = position
	}
}
