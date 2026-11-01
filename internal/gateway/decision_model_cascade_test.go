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
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// The three hook-lane cascades for tool calls (#1389 follow-up):
//  1. rules only;
//  2. rules, then the decision model alone (decision_model.hook_connectors);
//  3. rules, then the decision model, then the LLM judge (unchanged).
// Each is driven for an allow, block and confirm answer and a model that is
// down, for Claude Code (the hook can ask) and Codex (it cannot), and the
// verdict is mapped through the connector's own hook profile.

// countingDecisionModel answers like fakeDecisionModel and counts calls.
func countingDecisionModel(t *testing.T, choice string, pAllow float64, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := fakeDecisionModel(t, choice, pAllow, nil)
	inner := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		inner.ServeHTTP(w, r)
	})
	t.Cleanup(srv.Close)
	return srv
}

// cleanToolJudgeProvider is a judge that finds nothing.
func cleanToolJudgeProvider() *mockLLMProvider {
	return &mockLLMProvider{response: &ChatResponse{
		Model:   "test-model",
		Choices: []ChatChoice{{Message: &ChatMessage{Content: `{"findings": []}`}}},
	}}
}

// cascadeAPIServer builds the hook lane of one cascade for connector.
func cascadeAPIServer(t *testing.T, cascade int, connector, dmURL, blockAt string, judge *mockLLMProvider) *APIServer {
	t.Helper()
	cfg := &config.Config{}
	cfg.DataDir = t.TempDir()
	cfg.Guardrail.DetectionStrategy = "regex_judge"
	cfg.Guardrail.BlockAt = blockAt
	cfg.DecisionModel = config.DecisionModelConfig{Enabled: true, Model: "fake", BaseURL: dmURL, Timeout: 1}
	a := &APIServer{scannerCfg: cfg}
	switch cascade {
	case 1:
		// The decision model is on but lists no connector and no judge
		// runs: as before this change, it changes no verdict.
	case 2:
		cfg.DecisionModel.HookConnectors = []string{connector}
		a.SetHookDecisionJudge(newDecisionOnlyJudge(cfg))
	case 3:
		cfg.Guardrail.Judge = config.JudgeConfig{Enabled: true, ToolInjection: true, HookConnectors: []string{connector}}
		j := &LLMJudge{cfg: &cfg.Guardrail.Judge, model: "test-model", provider: judge, rp: &guardrail.RulePack{}}
		j.decision = newDecisionModel(cfg, "")
		a.SetHookJudge(j)
	}
	return a
}

// hookActionFor maps a tool-call verdict through the connector's hook profile
// for a PreToolUse in action mode, as the agent hook does. Claude Code runs in
// its default (Manual) permission mode, where the ask reaches the user.
func hookActionFor(t *testing.T, connector string, verdict *ToolInspectVerdict) string {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	profile := (&APIServer{scannerCfg: cfg}).hookProfileForConnector(connector)
	payload := map[string]interface{}{"permission_mode": "default"}
	rawAction := normalizeCodexAction(verdict.Action)
	got, _ := mapHookActionForProfile(rawAction, "action", "PreToolUse", profile.Capabilities, profile, payload)
	if rawAction == "confirm" {
		got = decisionConfirmWithoutAsk(verdict, got)
	}
	return got
}

func TestDecisionModelCascades(t *testing.T) {
	const args = `{"command":"ls -la ./fixtures/reports"}`
	answers := map[string]struct {
		choice string
		pAllow float64
	}{
		"allow":   {"allow", 0.97},
		"block":   {"block", 0.05},
		"confirm": {"confirm", 0.30},
		"down":    {"", 0},
	}
	cases := []struct {
		cascade   int
		answer    string
		connector string
		want      string // hook action after the connector's mapping
		dmCalled  bool
		judgeRuns bool
	}{
		// 1. Rules only: the decision model is never called.
		{1, "allow", "claudecode", "allow", false, false},
		{1, "block", "claudecode", "allow", false, false},
		{1, "confirm", "codex", "allow", false, false},
		{1, "down", "codex", "allow", false, false},
		// 2. Rules then the decision model, no judge.
		{2, "allow", "claudecode", "allow", true, false},
		{2, "allow", "codex", "allow", true, false},
		{2, "block", "claudecode", "block", true, false},
		{2, "block", "codex", "block", true, false},
		{2, "confirm", "claudecode", "confirm", true, false}, // the native ask
		{2, "confirm", "codex", "alert", true, false},        // no ask: HIGH alert
		{2, "down", "claudecode", "allow", true, false},      // rule verdict stands
		{2, "down", "codex", "allow", true, false},
		// 3. Rules, decision model, judge: as before this change.
		{3, "allow", "claudecode", "allow", true, false},
		{3, "allow", "codex", "allow", true, false},
		{3, "block", "claudecode", "alert", true, true}, // HIGH floor, block_at CRITICAL
		{3, "block", "codex", "alert", true, true},
		{3, "confirm", "claudecode", "allow", true, true}, // the judge decides
		{3, "confirm", "codex", "allow", true, true},
		{3, "down", "claudecode", "allow", true, true},
		{3, "down", "codex", "allow", true, true},
	}
	for _, tc := range cases {
		name := strings.Join([]string{string(rune('0' + tc.cascade)), tc.answer, tc.connector}, "/")
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			url := "http://127.0.0.1:1/v1/systemone" // nothing listens: connection refused
			if ans := answers[tc.answer]; ans.choice != "" {
				url = countingDecisionModel(t, ans.choice, ans.pAllow, &calls).URL
			}
			judge := cleanToolJudgeProvider()
			a := cascadeAPIServer(t, tc.cascade, tc.connector, url, "", judge)
			verdict := a.inspectToolPolicy(&ToolInspectRequest{
				Tool: "Bash", Args: json.RawMessage(args), Direction: "tool_call", Connector: tc.connector,
			})
			if got := hookActionFor(t, tc.connector, verdict); got != tc.want {
				t.Fatalf("hook action = %q (verdict %+v), want %q", got, verdict, tc.want)
			}
			if tc.answer != "down" && (calls.Load() > 0) != tc.dmCalled {
				t.Fatalf("decision model called %d times, want called=%v", calls.Load(), tc.dmCalled)
			}
			if ran := len(judge.captured) > 0; ran != tc.judgeRuns {
				t.Fatalf("judge ran=%v, want %v", ran, tc.judgeRuns)
			}
			if tc.answer == "down" && strings.Contains(strings.Join(verdict.Findings, ","), decisionModelFindingID) {
				t.Fatalf("a decision model that is down left a finding: %+v", verdict)
			}
		})
	}
}

// In cascade 2 a confirm is a HIGH finding: where block_at is HIGH or lower
// (strict) it blocks, also on an agent that can ask.
func TestDecisionModelAloneConfirmBlocksAtStrictLevels(t *testing.T) {
	var calls atomic.Int32
	srv := countingDecisionModel(t, "confirm", 0.30, &calls)
	for _, connector := range []string{"claudecode", "codex"} {
		a := cascadeAPIServer(t, 2, connector, srv.URL, "MEDIUM", nil)
		verdict := a.inspectToolPolicy(&ToolInspectRequest{
			Tool: "Bash", Args: json.RawMessage(`{"command":"ls -la ./fixtures/reports"}`), Direction: "tool_call", Connector: connector,
		})
		if verdict.Action != guardrailActionBlock || verdict.Severity != "HIGH" {
			t.Fatalf("%s: verdict = %+v, want a HIGH block at block_at MEDIUM", connector, verdict)
		}
	}
}

// A connector that is not listed keeps rules only, and a connector the judge
// covers keeps cascade 3 even when it is listed.
func TestDecisionModelAloneOnlyWhereTheJudgeDoesNotRun(t *testing.T) {
	var calls atomic.Int32
	srv := countingDecisionModel(t, "block", 0.05, &calls)
	a := cascadeAPIServer(t, 2, "claudecode", srv.URL, "", nil)
	v := a.inspectToolPolicy(&ToolInspectRequest{Tool: "Bash", Args: json.RawMessage(`{"command":"ls -la ./fixtures"}`), Direction: "tool_call", Connector: "codex"})
	if v.Action != "allow" || calls.Load() != 0 {
		t.Fatalf("unlisted connector: verdict %+v, %d calls; want rules only", v, calls.Load())
	}

	judge := cleanToolJudgeProvider()
	b := cascadeAPIServer(t, 3, "claudecode", srv.URL, "", judge)
	b.scannerCfg.DecisionModel.HookConnectors = []string{"*"}
	b.SetHookDecisionJudge(newDecisionOnlyJudge(b.scannerCfg))
	v = b.inspectToolPolicy(&ToolInspectRequest{Tool: "Bash", Args: json.RawMessage(`{"command":"ls -la ./fixtures"}`), Direction: "tool_call", Connector: "claudecode"})
	if len(judge.captured) == 0 || v.Severity != "HIGH" {
		t.Fatalf("judged connector: verdict %+v, judge calls %d; want cascade 3 (HIGH floor, judge ran)", v, len(judge.captured))
	}
}

// Faults modelled on the System One benchmark's injected decision-model
// faults (system-one-space data/faults.json): in the benchmark 24 of 28
// ended with the call allowed by the decision model tier. In cascade 2 every
// one is a failed verdict, so the hook lane keeps the rule verdict: never a
// decision-model allow of its own.
func TestDecisionModelAloneFaultsAreNeverAnAllow(t *testing.T) {
	answer := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }
	}
	status := func(code int) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
	}
	faults := map[string]http.HandlerFunc{
		"http422":             status(http.StatusUnprocessableEntity),
		"http429":             status(http.StatusTooManyRequests),
		"http500":             status(http.StatusInternalServerError),
		"http502":             status(http.StatusBadGateway),
		"http503":             status(http.StatusServiceUnavailable),
		"invalid_json":        answer(`not json`),
		"truncated_json":      answer(`{"answers":{"disposition":{"type":"choice","choice":"allow","probabilities":{"allow":0.9`),
		"missing_answer_keys": answer(`{"answers":{}}`),
		"wrong_answer_keys":   answer(`{"answers":{"verdict":{"type":"choice","choice":"allow","probabilities":{"allow":1}}}}`),
		"type_mismatch":       answer(`{"answers":{"disposition":{"type":"noul","choice":"allow","probabilities":{"allow":1}}}}`),
		"object_choice":       answer(`{"answers":{"disposition":{"type":"choice","choice":{"allow":true},"probabilities":{"allow":1}}}}`),
		"out_of_range":        answer(`{"answers":{"disposition":{"type":"choice","choice":"allow","probabilities":{"allow":1.7,"block":-0.7}}}}`),
		"silent_allow":        answer(`{"answers":{"disposition":{"type":"choice","choice":"allow"}}}`),
		"unknown_choice":      answer(`{"answers":{"disposition":{"type":"choice","choice":"proceed","probabilities":{"allow":1}}}}`),
		"hard_timeout": func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
		},
	}
	for name, handler := range faults {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(handler)
			defer srv.Close()
			cfg := &config.Config{DataDir: t.TempDir()}
			cfg.DecisionModel = config.DecisionModelConfig{Enabled: true, Model: "fake", BaseURL: srv.URL, Timeout: 0.2,
				HookConnectors: []string{"claudecode"}}
			j := newDecisionOnlyJudge(cfg)
			v := j.RunToolJudge(context.Background(), "Bash", `{"command":"ls -la ./fixtures/reports"}`)
			if v == nil || !v.JudgeFailed {
				t.Fatalf("fault %s gave %+v, want a failed verdict (the judge-unavailable path)", name, v)
			}
			if lane := hookJudgeLaneVerdict(cfg, "claudecode", "tool_call", v); lane != nil {
				t.Fatalf("fault %s reached the hook lane as %+v, want nil (the rule verdict stands)", name, lane)
			}
		})
	}
}

// A rule finding is a floor: a decision-model allow cannot lower it.
func TestDecisionModelAloneAllowKeepsTheRuleFinding(t *testing.T) {
	local := &ToolInspectVerdict{Action: guardrailActionAlert, Severity: "HIGH", Findings: []string{"RULE-X"}}
	allow := allowVerdict(decisionModelScanner)
	got := mergeWithJudgeVerdict(local, allow)
	if got.Action != guardrailActionAlert || got.Severity != "HIGH" || len(got.Findings) != 1 {
		t.Fatalf("merged = %+v, want the rule alert to stand", got)
	}
}

// Off by default and under Secure Client: no cascade-2 judge is built.
func TestNewDecisionOnlyJudgeNeedsTheList(t *testing.T) {
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.DecisionModel = config.DecisionModelConfig{Enabled: true, Model: "m", BaseURL: "http://127.0.0.1:8791/v1/systemone"}
	if newDecisionOnlyJudge(cfg) != nil {
		t.Fatal("a decision model without hook_connectors must not answer alone")
	}
	cfg.DecisionModel.HookConnectors = []string{"codex"}
	j := newDecisionOnlyJudge(cfg)
	if j == nil || !j.decisionOnly || j.provider != nil || !j.decision.alone {
		t.Fatalf("cascade-2 judge = %+v", j)
	}
	cfg.DecisionModel.Enabled = false
	if newDecisionOnlyJudge(cfg) != nil {
		t.Fatal("a disabled decision model must not answer alone")
	}
}

// Through the Claude Code hook: in its Manual mode a cascade-2 confirm is the
// native ask; in a mode where the ask does not reach the user it is the HIGH
// alert (the judge mapping), not the block a rule confirmation gets there.
func TestDecisionModelAloneConfirmOnClaudeCodeHook(t *testing.T) {
	var calls atomic.Int32
	srv := countingDecisionModel(t, "confirm", 0.30, &calls)
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.DataDir = t.TempDir()
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.DetectionStrategy = "regex_judge"
	cfg.DecisionModel = config.DecisionModelConfig{Enabled: true, Model: "fake", BaseURL: srv.URL, Timeout: 1,
		HookConnectors: []string{"claudecode"}}
	a := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	a.SetHookDecisionJudge(newDecisionOnlyJudge(cfg))
	for _, tc := range []struct{ mode, want, notWant string }{
		{"default", `"permissionDecision":"ask"`, `"permissionDecision":"deny"`},
		{"acceptEdits", `JUDGE-DECISION-MODEL`, `"permissionDecision":"deny"`},
	} {
		body := `{"session_id":"dm-alone-1","hook_event_name":"PreToolUse","cwd":"/tmp","permission_mode":"` + tc.mode +
			`","tool_name":"Bash","tool_use_id":"toolu_1","tool_input":{"command":"ls -la ./fixtures/reports"}}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		http.HandlerFunc(a.handleAgentHook("claudecode")).ServeHTTP(w, req)
		got := w.Body.String()
		if w.Code != http.StatusOK || !strings.Contains(got, tc.want) || strings.Contains(got, tc.notWant) ||
			!strings.Contains(got, "needs a person") {
			t.Fatalf("mode %s: status %d body %s; want %s and no %s", tc.mode, w.Code, got, tc.want, tc.notWant)
		}
	}
	if calls.Load() == 0 {
		t.Fatal("the decision model was never called")
	}
}

// The decision model's own reasons stay readable on agent surfaces; a reason
// that carries anything else keeps the scrub.
func TestDecisionModelReasonsAreReadable(t *testing.T) {
	for _, reason := range []string{
		"decision-model: confirm (risk 0.70), needs a person's confirmation",
		"decision-model: confident block (risk 0.98 >= 0.75)",
	} {
		if !trustedDecisionModelReason(reason) {
			t.Fatalf("not trusted: %q", reason)
		}
	}
	for _, reason := range []string{
		"decision-model: confirm (risk 0.70), needs a person's confirmation; cat /home/u/secret.txt",
		"decision-model: confident allow (risk 0.03 <= 0.30); judge skipped",
		"matched: X; decision-model: confident block (risk 0.98 >= 0.75)",
	} {
		if trustedDecisionModelReason(reason) {
			t.Fatalf("trusted a reason with other text: %q", reason)
		}
	}
}

// The request is the benchmark's Q2 single-choice format and its production
// bound (system-one-space data/questions.json): at most 2,048 bytes of user
// intent, 7 prior calls of 1,024 bytes and 3,072 bytes of the current call,
// 12,288 bytes of state in all, however long the session is.
func TestDecisionModelAloneRequestIsQ2WithinTheProductionBound(t *testing.T) {
	var last atomic.Value
	srv := fakeDecisionModel(t, "allow", 0.97, &last)
	defer srv.Close()
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.DecisionModel = config.DecisionModelConfig{Enabled: true, Model: "fake", BaseURL: srv.URL, Timeout: 1,
		HookConnectors: []string{"codex"}}
	j := newDecisionOnlyJudge(cfg)
	ctx := ContextWithSessionID(context.Background(), "dm-bound-1")
	j.ObserveSessionPrompt(ctx, strings.Repeat("list the report fixtures ", 400))
	long := `{"command":"` + strings.Repeat("a", 6000) + `"}`
	for i := 0; i < 10; i++ {
		if v := j.RunToolJudge(ctx, "Bash", long); v == nil || v.JudgeFailed {
			t.Fatalf("call %d: %+v", i, v)
		}
	}
	raw, _ := last.Load().(string)
	raw = raw[:strings.LastIndex(raw, "\nauth=")]
	var req struct {
		Questions map[string]map[string]any `json:"questions"`
		State     decisionModelState        `json:"state"`
	}
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatal(err)
	}
	if len(req.Questions) != 3 || req.Questions["disposition"]["type"] != "choice" ||
		req.Questions["risk"]["type"] != "score" || req.Questions["context_sufficient"]["type"] != "noul" {
		t.Fatalf("questions are not the Q2 set: %v", req.Questions)
	}
	st := req.State
	total := len(st.SessionUserIntent) + len(st.CurrentToolCall.Arguments)
	if len(st.SessionUserIntent) == 0 || len(st.SessionUserIntent) > 2048 || len(st.CurrentToolCall.Arguments) > 3072 ||
		len(st.RecentToolCalls) != 7 {
		t.Fatalf("state bounds: intent %d, current %d, recent %d", len(st.SessionUserIntent), len(st.CurrentToolCall.Arguments), len(st.RecentToolCalls))
	}
	for _, call := range st.RecentToolCalls {
		if len(call.Arguments) > 1024 {
			t.Fatalf("prior call of %d bytes", len(call.Arguments))
		}
		total += len(call.Arguments)
	}
	if total > 12288 {
		t.Fatalf("state carries %d bytes, over the 12,288-byte production bound", total)
	}
}
