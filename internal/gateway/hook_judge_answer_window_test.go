// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// slowLLMProvider answers like injectionHitProvider after delay, and says
// on finished each time a call ended (answered or cancelled).
type slowLLMProvider struct {
	mockLLMProvider
	delay    time.Duration
	finished chan error
}

func (p *slowLLMProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	select {
	case <-time.After(p.delay):
	case <-ctx.Done():
		p.finished <- ctx.Err()
		return nil, ctx.Err()
	}
	resp, err := p.mockLLMProvider.ChatCompletion(ctx, req)
	p.finished <- nil
	return resp, err
}

func newAnswerWindowJudgeServer(mode string, delay time.Duration) (*APIServer, *slowLLMProvider) {
	p := &slowLLMProvider{
		mockLLMProvider: mockLLMProvider{response: injectionHitProvider().response},
		delay:           delay,
		finished:        make(chan error, 8),
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = mode
	cfg.Guardrail.Judge = config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"codex"}}
	cfg.Guardrail.DetectionStrategy = "judge_first"
	a := &APIServer{scannerCfg: cfg}
	a.SetHookJudge(&LLMJudge{cfg: &cfg.Guardrail.Judge, model: "test-model", provider: p, rp: &guardrail.RulePack{}})
	return a, p
}

// boundedHookContext is the context of a hook call that asked for progress
// reports (a bounded managed hook) and reached the gateway at start.
func boundedHookContext(start time.Time) context.Context {
	return context.WithValue(context.Background(), hookProgressContextKey{},
		&hookProgressWriter{ResponseWriter: httptest.NewRecorder(), start: start})
}

// GAP-2625: a bounded hook does not hold an observe answer for a slow judge.
// GAP-0564: the detached request ends within the hook answer window.
func TestHookJudgeDoesNotHoldAnObserveAnswer(t *testing.T) {
	a, p := newAnswerWindowJudgeServer("observe", 2*time.Second)
	t0 := time.Now()
	got := a.runHookJudge(boundedHookContext(t0), "prompt", "prompt", "codex", "please list the files in this folder", "", nil)
	if elapsed := time.Since(t0); got != nil || elapsed > 500*time.Millisecond {
		t.Fatalf("observe answer waited %s for the judge (verdict %v), want an immediate answer without it", elapsed, got)
	}
	select {
	case err := <-p.finished:
		if err != nil {
			t.Fatalf("observe judge failed inside its answer window: %v", err)
		}
	case <-time.After(hookJudgeAnswerWindow):
		t.Fatal("observe judge did not finish inside the hook answer window")
	}
	deadline := t0.Add(hookJudgeAnswerWindow)
	for len(a.hookJudgeSem) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("observe judge kept a model slot after the hook answer window")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestGAP0564ObserveJudgeEndsAtAnswerWindow(t *testing.T) {
	a, p := newAnswerWindowJudgeServer("observe", 5*time.Second)
	t0 := time.Now()
	got := a.runHookJudge(boundedHookContext(t0), "prompt", "prompt", "codex", "please list the files in this folder", "", nil)
	if got != nil || time.Since(t0) > 500*time.Millisecond {
		t.Fatalf("observe answer waited for the judge: %v", got)
	}
	select {
	case err := <-p.finished:
		if err != context.DeadlineExceeded {
			t.Fatalf("observe judge ended with %v, want its answer-window deadline", err)
		}
	case <-time.After(hookJudgeAnswerWindow + time.Second):
		t.Fatal("observe judge outlived its answer window")
	}
}

// GAP-2625: in action mode the answer waits for the judge only inside the
// hook answer window, then keeps the rule verdict and cancels the model call.
func TestHookJudgeHoldsAnActionAnswerOnlyInsideTheWindow(t *testing.T) {
	a, p := newAnswerWindowJudgeServer("action", 2*time.Second)
	t0 := time.Now()
	// The call reached the gateway 3 s ago: 400 ms of the window are left.
	got := a.runHookJudge(boundedHookContext(t0.Add(-3*time.Second)), "prompt", "prompt", "codex", "please list the files in this folder", "", nil)
	if elapsed := time.Since(t0); got != nil || elapsed > time.Second {
		t.Fatalf("action answer waited %s for a late judge (verdict %v), want the rule verdict at the window end", elapsed, got)
	}
	select {
	case err := <-p.finished:
		if err != context.Canceled {
			t.Fatalf("late judge finished with %v, want cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the late judge never finished")
	}

	// A judge that answers inside the window still decides the call.
	fast, _ := newAnswerWindowJudgeServer("action", 0)
	if got := fast.runHookJudge(boundedHookContext(time.Now()), "prompt", "prompt", "codex", "please list the files in this folder", "", nil); got == nil || len(got.Findings) == 0 {
		t.Fatalf("a judge inside the window gave no verdict: %v", got)
	}
}
