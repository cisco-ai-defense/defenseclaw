// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

const prepassArgs = `{"command":"go test ./internal/... -run TestSomething -count=1 -v"}`

// countingDecisionServer wraps fakeDecisionModel and counts its requests.
func countingDecisionServer(t *testing.T, choice string, pAllow float64) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	inner := fakeDecisionModel(t, choice, pAllow, nil)
	t.Cleanup(inner.Close)
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		inner.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func prepassServer(t *testing.T, delay time.Duration, choice string, pAllow float64) (*APIServer, *atomic.Int64) {
	t.Helper()
	srv, hits := countingDecisionServer(t, choice, pAllow)
	p := &slowLLMProvider{mockLLMProvider: mockLLMProvider{response: injectionHitProvider().response}, delay: delay, finished: make(chan error, 8)}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Judge = config.JudgeConfig{Enabled: true, Injection: true, ToolInjection: true, HookConnectors: []string{"codex"}}
	cfg.Guardrail.DetectionStrategy = "judge_first"
	a := &APIServer{scannerCfg: cfg}
	a.SetHookJudge(&LLMJudge{cfg: &cfg.Guardrail.Judge, model: "test-model", provider: p, rp: &guardrail.RulePack{},
		decision: testDecisionModel(t, srv.URL, "")})
	return a, hits
}

// TestDecisionPrepassUnderJudgeLoad (review round 3, P3-1): System One
// answers before the judge's own gates, so with every judge slot busy or the
// hook judge budget spent a confident block still stands as the HIGH floor,
// and the model is asked once.
func TestDecisionPrepassUnderJudgeLoad(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(a *APIServer) context.Context
	}{
		{"all judge slots busy", func(a *APIServer) context.Context {
			a.hookJudgeSemOnce.Do(func() { a.hookJudgeSem = make(chan struct{}) })
			return context.Background()
		}},
		{"hook judge budget under the judge minimum", func(*APIServer) context.Context {
			// 800 ms left: too little for the judge (1 s minimum), a quarter
			// of it (200 ms) for the decision model.
			return withHookJudgeBudget(context.Background(), time.Now().Add(800*time.Millisecond))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, hits := prepassServer(t, 0, "block", 0.02)
			v := a.runHookJudge(tc.setup(a), "tool_call", "tool_call", "codex", prepassArgs, "Bash", nil)
			if v == nil || v.Severity != "HIGH" || !hasFinding(v.Findings, decisionModelFindingID) {
				t.Fatalf("verdict = %+v, want the HIGH decision-model floor", v)
			}
			if hits.Load() != 1 {
				t.Fatalf("decision model asked %d times, want 1", hits.Load())
			}
		})
	}
	// A fully spent hook judge budget leaves no time for either: the rule
	// verdict, and the decision model is not asked (review round 4, P4-1).
	spentSrv, spentHits := prepassServer(t, 0, "block", 0.02)
	if v := spentSrv.runHookJudge(withHookJudgeBudget(context.Background(), time.Now()), "tool_call", "tool_call", "codex", prepassArgs, "Bash", nil); v != nil || spentHits.Load() != 0 {
		t.Fatalf("spent budget: verdict %+v, %d requests; want the rule verdict and no request", v, spentHits.Load())
	}
	// An escalation keeps the rule verdict when the judge cannot run.
	a, _ := prepassServer(t, 0, "allow", 0.55)
	a.hookJudgeSemOnce.Do(func() { a.hookJudgeSem = make(chan struct{}) })
	if v := a.runHookJudge(context.Background(), "tool_call", "tool_call", "codex", prepassArgs, "Bash", nil); v != nil {
		t.Fatalf("escalated call with no judge slot = %+v, want the rule verdict (nil)", v)
	}
}

// TestDecisionPrepassAsksOnceAndRecordsOnce: on the normal path the judge
// uses the prepass answer and sample: one model request, one session entry.
func TestDecisionPrepassAsksOnceAndRecordsOnce(t *testing.T) {
	a, hits := prepassServer(t, 0, "allow", 0.55)
	ctx := ContextWithSessionID(context.Background(), "prepass-session")
	a.runHookJudge(ctx, "tool_call", "tool_call", "codex", prepassArgs, "Bash", nil)
	if hits.Load() != 1 {
		t.Fatalf("decision model asked %d times, want 1", hits.Load())
	}
	j := a.hookJudge.Load()
	j.toolContextMu.Lock()
	n := 0
	for _, e := range j.toolContext {
		n += len(e.events)
	}
	j.toolContextMu.Unlock()
	if n != 1 {
		t.Fatalf("session context holds %d entries for one call, want 1", n)
	}
}

// TestDecisionFloorNeverWeakensClosedRefusal (review round 3, P3-2): an
// escalated CRITICAL call under hook_fail_mode closed whose judge gives no
// verdict is refused, also when a System One floor exists
// (escalate_rule_flagged false lets a rule-flagged call get one). Matrix and
// fixtures from the reviewer's TestS1Rev3EscalatedCriticalClosedWithFloor.
func TestDecisionFloorNeverWeakensClosedRefusal(t *testing.T) {
	command := pythonWrapped("cat ~/.ssh/id_rsa")
	critical := func() mockLLMProvider {
		return mockLLMProvider{response: &ChatResponse{Choices: []ChatChoice{{Message: &ChatMessage{Content: escalationJudgeCritical}}}}}
	}
	failures := map[string]func() (LLMProvider, func(context.Context) context.Context){
		"provider error": func() (LLMProvider, func(context.Context) context.Context) {
			return &mockLLMProvider{err: errors.New("judge provider down")}, nil
		},
		"timeout": func() (LLMProvider, func(context.Context) context.Context) {
			return &escalationSlowJudge{mockLLMProvider: critical(), delay: 5 * time.Second}, nil
		},
		"late window": func() (LLMProvider, func(context.Context) context.Context) {
			return &escalationSlowJudge{mockLLMProvider: critical(), delay: 1500 * time.Millisecond},
				func(ctx context.Context) context.Context {
					return context.WithValue(ctx, shellToolGateKey{}, time.Now().Add(400*time.Millisecond))
				}
		},
	}
	modes := []struct {
		name, pack string
		edit       func(*config.Config)
	}{
		{"explicit closed", "default", func(c *config.Config) { c.Guardrail.HookFailMode = "closed" }},
		{"strict tier", "strict", nil},
	}
	for _, s1 := range []string{"noS1", "S1block", "S1block-noRF"} {
		for failure, setup := range failures {
			for _, mode := range modes {
				t.Run(s1+"/"+failure+"/"+mode.name, func(t *testing.T) {
					provider, withCtx := setup()
					a := escalationHookServerWith(t, provider, mode.pack, func(c *config.Config) {
						c.Guardrail.Judge.HookTimeout = 0.3
						if failure == "late window" {
							c.Guardrail.Judge.HookTimeout = 3
						}
						if mode.edit != nil {
							mode.edit(c)
						}
					})
					if s1 != "noS1" {
						srv, _ := countingDecisionServer(t, "block", 0.02)
						dc := &config.Config{DecisionModel: config.DecisionModelConfig{Enabled: true, Model: "fake", BaseURL: srv.URL, Timeout: 1}}
						if s1 == "S1block-noRF" {
							off := false
							dc.DecisionModel.EscalateRuleFlagged = &off
						}
						dm := newDecisionModel(dc, "")
						cfg := a.scannerCfg
						a.SetHookJudge(&LLMJudge{cfg: &cfg.Guardrail.Judge, model: "test-model", provider: provider, rp: &guardrail.RulePack{}, decision: dm})
					}
					ctx := t.Context()
					if withCtx != nil {
						ctx = withCtx(ctx)
					}
					resp := escalationPreToolUseCtx(t, ctx, a, command)
					if resp.RawAction != guardrailActionBlock {
						t.Fatalf("raw_action=%q findings=%v, want block (closed mode, the judge gave no verdict)", resp.RawAction, resp.Findings)
					}
				})
			}
		}
	}
}
