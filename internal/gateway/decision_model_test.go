// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
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
	for _, want := range []string{`"model":"fake"`, `"current_tool_call"`, `"session_user_intent":"fix the tests"`, `"disposition"`, `"risk"`, `"context_sufficient"`, "auth=Bearer dm-secret"} {
		if !strings.Contains(got, want) {
			t.Errorf("request lacks %s: %s", want, got)
		}
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
	if got := strongerDecisionVerdict(errorVerdict("llm-judge-tool"), floor); got != floor {
		t.Fatal("a failed judge must leave the decision model floor")
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

func TestRunToolDecisionDecideBlockSkipsJudge(t *testing.T) {
	srv := fakeDecisionModel(t, "block", 0.02, nil)
	defer srv.Close()
	j := &LLMJudge{cfg: &config.JudgeConfig{ToolInjection: true}, decision: testDecisionModel(t, srv.URL, config.DecisionModelDecide)}
	v := j.runToolJudgeSample(context.Background(), "Bash", `{"command":"x"}`, "sample")
	if v == nil || v.Severity != "HIGH" || v.Scanner != decisionModelScanner {
		t.Fatalf("verdict = %+v", v)
	}
}

func TestRunToolDecisionRuleFloorKeepsTheJudge(t *testing.T) {
	srv := fakeDecisionModel(t, "allow", 0.99, nil)
	defer srv.Close()
	j := &LLMJudge{cfg: &config.JudgeConfig{ToolInjection: true}, decision: testDecisionModel(t, srv.URL, "")}
	ctx := withDecisionRuleFloor(context.Background(), rulesFlagged(&ToolInspectVerdict{Action: "alert", Severity: "HIGH", Findings: []string{"CMD-X"}}))
	// provider is nil, so reaching the judge panics: the confident allow
	// must not skip the judge when the rules flagged the call.
	defer func() {
		if recover() == nil {
			t.Fatal("a rule-flagged call skipped the LLM judge")
		}
	}()
	j.runToolJudgeSample(ctx, "Bash", `{"command":"x"}`, "sample")
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
