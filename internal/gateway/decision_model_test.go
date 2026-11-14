// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// fakeDecisionModel answers the System One protocol with the given
// disposition and P(allow).
func fakeDecisionModel(t *testing.T, choice string, pAllow float64, seen *atomic.Value) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if seen != nil {
			seen.Store(string(body) + "\nauth=" + r.Header.Get("Authorization"))
		}
		rest := (1 - pAllow) / 2
		probs := map[string]float64{"allow": pAllow, "confirm": rest, "block": rest}
		if choice == "block" {
			probs = map[string]float64{"allow": pAllow, "confirm": 0, "block": 1 - pAllow}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model": "fake",
			"answers": map[string]any{
				"disposition": map[string]any{"type": "choice", "choice": choice, "probabilities": probs, "confidence": 0.9},
				// The risk score follows the disposition risk (0..2).
				"risk": map[string]any{"type": "score", "score": 2 * (1 - pAllow)},
			},
		})
	}))
}

func testDecisionModel(t *testing.T, url string, mode string) *decisionModel {
	t.Helper()
	cfg := &config.Config{DecisionModel: config.DecisionModelConfig{
		Enabled: true, Model: "fake", BaseURL: url, Timeout: 1, OnConfidentBlock: mode,
	}}
	dm := newDecisionModel(cfg, "")
	if dm == nil {
		t.Fatal("newDecisionModel returned nil for an active block")
	}
	return dm
}

func TestNewDecisionModelOffByDefault(t *testing.T) {
	if newDecisionModel(&config.Config{}, "") != nil {
		t.Fatal("a zero config must not build a decision model")
	}
	cfg := &config.Config{DecisionModel: config.DecisionModelConfig{Enabled: true, Model: "m", BaseURL: "http://10.0.0.1/x"}}
	if newDecisionModel(cfg, "") != nil {
		t.Fatal("plain http to a remote host must leave the decision model off")
	}
}

func TestDecisionModelRoutes(t *testing.T) {
	cases := []struct {
		choice string
		pAllow float64
		want   decisionRoute
	}{
		{"allow", 0.95, decisionAllow},      // risk 0.05 <= 0.30
		{"allow", 0.60, decisionEscalate},   // risk 0.40: unclear
		{"confirm", 0.10, decisionEscalate}, // high risk but not a block answer
		{"block", 0.05, decisionBlock},      // risk 0.95 >= 0.75
		{"block", 0.40, decisionEscalate},   // risk 0.60: unclear
	}
	for _, tc := range cases {
		srv := fakeDecisionModel(t, tc.choice, tc.pAllow, nil)
		dm := testDecisionModel(t, srv.URL, "")
		got := dm.decide(context.Background(), decisionModelState{CurrentToolCall: decisionModelToolCall{Tool: "Bash", Arguments: "{}"}})
		srv.Close()
		if got.route != tc.want || got.failure != "" {
			t.Errorf("%s p_allow=%.2f: route=%v failure=%q, want %v", tc.choice, tc.pAllow, got.route, got.failure, tc.want)
		}
	}
}

func TestDecisionModelRequestContract(t *testing.T) {
	var seen atomic.Value
	srv := fakeDecisionModel(t, "allow", 0.99, &seen)
	defer srv.Close()
	t.Setenv(config.DefenseClawDecisionModelKeyEnv, "dm-secret")
	dm := testDecisionModel(t, srv.URL, "")
	dm.decide(context.Background(), decisionModelState{
		SessionUserIntent: "fix the tests",
		CurrentToolCall:   decisionModelToolCall{Tool: "Bash", Arguments: `{"command":"go test ./..."}`},
	})
	got, _ := seen.Load().(string)
	for _, want := range []string{`"model":"fake"`, `"current_tool_call"`, `"session_user_intent":"fix the tests"`, `"disposition"`, `"risk"`, "auth=Bearer dm-secret"} {
		if !strings.Contains(got, want) {
			t.Errorf("request lacks %s: %s", want, got)
		}
	}
	// The context-sufficiency question was never read and is not asked.
	if strings.Contains(got, "context_sufficient") {
		t.Errorf("request still asks context_sufficient: %s", got)
	}
}

func TestDecisionModelOutOfContractEscalates(t *testing.T) {
	bodies := []string{
		`not json`,
		`{"answers":{}}`,
		`{"answers":{"disposition":{"type":"noul","noul":0.1}}}`,
		`{"answers":{"disposition":{"type":"choice","choice":"maybe","probabilities":{"allow":1}}}}`,
		`{"answers":{"disposition":{"type":"choice","choice":"allow","probabilities":{"allow":0.5}}}}`,
		`{"answers":{"disposition":{"type":"choice","choice":"allow","probabilities":{"allow":1.5,"block":-0.5}}}}`,
	}
	for _, body := range bodies {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
		dm := testDecisionModel(t, srv.URL, "")
		got := dm.decide(context.Background(), decisionModelState{})
		srv.Close()
		if got.route != decisionEscalate || got.failure == "" {
			t.Errorf("%s: route=%v failure=%q, want escalate with a failure", body, got.route, got.failure)
		}
	}
}

func TestDecisionModelUnavailableEscalates(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	defer slow.Close()
	dm := testDecisionModel(t, slow.URL, "")
	dm.timeout = 100 * time.Millisecond
	dm.client.Timeout = dm.timeout
	got := dm.decide(context.Background(), decisionModelState{})
	if got.route != decisionEscalate || got.failure == "" || strings.Contains(got.failureCause, slow.URL) {
		t.Fatalf("timeout: %+v", got)
	}

	down := testDecisionModel(t, "http://127.0.0.1:1/v1/systemone", "")
	if got := down.decide(context.Background(), decisionModelState{}); got.route != decisionEscalate || got.failure == "" {
		t.Fatalf("connection refused: %+v", got)
	}

	redirect := httptest.NewServer(http.RedirectHandler("https://elsewhere.example/", http.StatusFound))
	defer redirect.Close()
	if got := testDecisionModel(t, redirect.URL, "").decide(context.Background(), decisionModelState{}); got.route != decisionEscalate {
		t.Fatalf("redirect must not be followed: %+v", got)
	}
}

func TestStrongerDecisionVerdict(t *testing.T) {
	floor := &ScanVerdict{Action: "block", Severity: "HIGH", Findings: []string{decisionModelFindingID}, Scanner: decisionModelScanner}
	if got := strongerDecisionVerdict(errorVerdict("llm-judge-tool"), floor); got.Severity != "HIGH" || got.Action != "block" ||
		got.Scanner != decisionModelScanner || !got.decisionFloorOnly || floor.decisionFloorOnly {
		// A copy of the floor, marked as standing in for a judge that gave
		// nothing (a closed-mode refusal still applies).
		t.Fatalf("a failed judge must leave the decision model floor, marked floor-only: %+v", got)
	}
	critical := &ScanVerdict{Action: "block", Severity: "CRITICAL", Findings: []string{"JUDGE-TOOL-INJ-EXFIL"}, Scanner: "llm-judge-tool"}
	if got := strongerDecisionVerdict(critical, floor); got != critical {
		t.Fatal("a stronger judge verdict must win")
	}
	clean := allowVerdict("llm-judge-tool")
	got := strongerDecisionVerdict(clean, floor)
	if got.Severity != "HIGH" || got.Action != "block" || !strings.Contains(strings.Join(got.Findings, ","), decisionModelFindingID) {
		t.Fatalf("judge allow under a confident block = %+v", got)
	}
}

func TestRunToolDecisionAllowSkipsJudge(t *testing.T) {
	srv := fakeDecisionModel(t, "allow", 0.97, nil)
	defer srv.Close()
	j := &LLMJudge{cfg: &config.JudgeConfig{ToolInjection: true}, decision: testDecisionModel(t, srv.URL, "")}
	// provider is nil: reaching the LLM judge would panic, so a passing
	// test proves the confident allow skipped it.
	v := j.runToolJudgeSample(context.Background(), "Bash", `{"command":"ls"}`, "sample")
	if v == nil || v.Action != "allow" || v.Scanner != decisionModelScanner {
		t.Fatalf("verdict = %+v", v)
	}
}

// TestRunToolDecisionRetiredDecideStillRunsTheJudge: on_confident_block
// decide is retired (owner 2026-11-13): it still loads, and a confident
// block still goes to the judge, with the HIGH floor kept when the judge
// gives no verdict.
func TestRunToolDecisionRetiredDecideStillRunsTheJudge(t *testing.T) {
	srv := fakeDecisionModel(t, "block", 0.02, nil)
	defer srv.Close()
	judge := &countingJudgeProvider{}
	j := &LLMJudge{cfg: &config.JudgeConfig{ToolInjection: true}, decision: testDecisionModel(t, srv.URL, config.DecisionModelDecide), provider: judge}
	v := j.runToolJudgeSample(context.Background(), "Bash", `{"command":"x"}`, "sample")
	if judge.calls.Load() == 0 {
		t.Fatal("a confident block skipped the LLM judge")
	}
	if v == nil || v.Severity != "HIGH" || v.Action != "block" {
		t.Fatalf("verdict = %+v, want the HIGH decision-model floor", v)
	}
}

// TestDecisionModelSaferRouting: a confident block needs the disposition
// AND the risk score (R4), and never lands on a call the rules flagged
// (RF); both are configurable and on by default.
func TestDecisionModelSaferRouting(t *testing.T) {
	answer := func(score any) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			ans := map[string]any{"disposition": map[string]any{"type": "choice", "choice": "block", "probabilities": map[string]float64{"allow": 0.02, "confirm": 0.03, "block": 0.95}}}
			if score != nil {
				ans["risk"] = map[string]any{"type": "score", "score": score}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"answers": ans})
		}))
	}
	flagged := withDecisionRuleFloor(context.Background(), true)
	cases := []struct {
		name  string
		score any
		ctx   context.Context
		cfg   func(*config.DecisionModelConfig)
		want  decisionRoute
	}{
		{"block and score 1.6", 1.6, context.Background(), nil, decisionBlock},
		{"score at the gate", 1.5, context.Background(), nil, decisionBlock},
		{"score below the gate", 1.4, context.Background(), nil, decisionEscalate},
		{"no score answer", nil, context.Background(), nil, decisionEscalate},
		{"score out of range", 3.0, context.Background(), nil, decisionEscalate},
		{"rules flagged the call", 1.9, flagged, nil, decisionEscalate},
		{"rule-flag escalation off", 1.9, flagged, func(c *config.DecisionModelConfig) { off := false; c.EscalateRuleFlagged = &off }, decisionBlock},
		{"lower gate configured", 1.2, context.Background(), func(c *config.DecisionModelConfig) { c.BlockRiskScore = 1.0 }, decisionBlock},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := answer(tc.score)
			defer srv.Close()
			cfg := &config.Config{DecisionModel: config.DecisionModelConfig{Enabled: true, Model: "fake", BaseURL: srv.URL, Timeout: 1}}
			if tc.cfg != nil {
				tc.cfg(&cfg.DecisionModel)
			}
			if got := newDecisionModel(cfg, "").decide(tc.ctx, decisionModelState{}); got.route != tc.want {
				t.Fatalf("route = %v, want %v (risk score %v)", got.route, tc.want, got.riskScore)
			}
		})
	}
}

func TestRunToolDecisionRuleFloorKeepsTheJudge(t *testing.T) {
	srv := fakeDecisionModel(t, "allow", 0.99, nil)
	defer srv.Close()
	judge := &countingJudgeProvider{}
	j := &LLMJudge{cfg: &config.JudgeConfig{ToolInjection: true}, decision: testDecisionModel(t, srv.URL, ""), provider: judge}
	ctx := withDecisionRuleFloor(context.Background(), rulesFlagged(&ToolInspectVerdict{Action: "alert", Severity: "HIGH", Findings: []string{"CMD-X"}}))
	// The confident allow must not skip the judge when the rules flagged the
	// call. The provider counts the call instead of being nil: reaching a nil
	// provider was a hardware fault recovered in the test, which on Windows
	// AMX hosts corrupts the heap below the goroutine stack
	// (golang/go#81238, rel-1-0-6:GAP-0550).
	j.runToolJudgeSample(ctx, "Bash", `{"command":"x"}`, "sample")
	if judge.calls.Load() == 0 {
		t.Fatal("a rule-flagged call skipped the LLM judge")
	}
}

// countingJudgeProvider records that the judge asked its model and fails the
// request, so a test can tell the judge ran without a real model.
type countingJudgeProvider struct{ calls atomic.Int32 }

func (p *countingJudgeProvider) ChatCompletion(context.Context, *ChatRequest) (*ChatResponse, error) {
	p.calls.Add(1)
	return nil, errors.New("counting judge provider: no model")
}

func (p *countingJudgeProvider) ChatCompletionStream(context.Context, *ChatRequest, func(StreamChunk)) (*ChatUsage, error) {
	p.calls.Add(1)
	return nil, errors.New("counting judge provider: no model")
}

func TestRulesFlagged(t *testing.T) {
	for _, v := range []*ToolInspectVerdict{nil, {Action: "allow", Severity: "NONE"}, {Action: "allow"}} {
		if rulesFlagged(v) {
			t.Fatalf("clean verdict flagged: %+v", v)
		}
	}
	if !rulesFlagged(&ToolInspectVerdict{Action: "alert", Severity: "MEDIUM"}) {
		t.Fatal("a MEDIUM rule verdict must be a floor")
	}
}

func TestDecisionModelBudgetLeavesTheJudgeItsTime(t *testing.T) {
	dm := testDecisionModel(t, "http://127.0.0.1:1/v1/systemone", "")
	dm.timeout = 3 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if got := dm.budget(ctx); got > 500*time.Millisecond+10*time.Millisecond {
		t.Fatalf("budget %s exceeds a quarter of the 2s judge deadline", got)
	}
	short, cancelShort := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelShort()
	if got := dm.decide(short, decisionModelState{}); !got.skipped || got.route != decisionEscalate {
		t.Fatalf("a call with no budget must be skipped and escalated: %+v", got)
	}
}

func TestDecisionModelBreakerPausesAfterRepeatedFailures(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	dm := testDecisionModel(t, srv.URL, "")
	var lines []string
	for range 6 {
		res := dm.decide(context.Background(), decisionModelState{})
		if res.route != decisionEscalate || res.failure == "" {
			t.Fatalf("a failing model must escalate: %+v", res)
		}
		if res.logLine != "" {
			lines = append(lines, res.logLine)
		}
	}
	if calls.Load() != decisionBreakerFailures {
		t.Fatalf("model called %d times, want %d before the breaker opens", calls.Load(), decisionBreakerFailures)
	}
	if len(lines) != 2 {
		t.Fatalf("log lines = %q, want the first failure and the trip", lines)
	}
}
