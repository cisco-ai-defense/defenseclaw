// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

const fallbackTestPrompt = "please list the files in this folder and say which are large"

func judgeFallbacksFor(connector string) int {
	details := judgeHealth.details()
	byConnector, _ := details["judge_fallbacks_by_connector"].(map[string]interface{})
	n, _ := byConnector[connector].(int)
	return n
}

// #1395: every way the rules decide a hook check the judge was asked to
// review is reported once, with its reason, on the call (its audit row and
// record) and in the per-connector count. The verdict stays the rules'.
func TestHookJudgeFallbackReasons(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   string
		delay  time.Duration
		setup  func(a *APIServer, p *slowLLMProvider) context.Context
		reason string
	}{
		{name: "timeout", mode: "action", delay: 2 * time.Second, reason: judgeFallbackTimeout,
			setup: func(a *APIServer, _ *slowLLMProvider) context.Context {
				a.scannerCfg.Guardrail.Judge.HookTimeout = 0.1
				return context.Background()
			}},
		{name: "error", mode: "action", reason: judgeFallbackError,
			setup: func(_ *APIServer, p *slowLLMProvider) context.Context {
				p.err = errors.New("provider refused the request")
				return context.Background()
			}},
		{name: "late", mode: "action", delay: 2 * time.Second, reason: judgeFallbackLate,
			setup: func(*APIServer, *slowLLMProvider) context.Context {
				// The hook reached the gateway 3 s ago: 400 ms of the window left.
				return boundedHookContext(time.Now().Add(-3 * time.Second))
			}},
		{name: "busy", mode: "action", reason: judgeFallbackBusy,
			setup: func(a *APIServer, _ *slowLLMProvider) context.Context {
				a.hookJudgeSemOnce.Do(func() { a.hookJudgeSem = make(chan struct{}) })
				return context.Background()
			}},
		{name: "budget", mode: "action", reason: judgeFallbackBudget,
			setup: func(*APIServer, *slowLLMProvider) context.Context {
				return withHookJudgeBudget(context.Background(), time.Now())
			}},
		{name: "answered", mode: "action", reason: "",
			setup: func(*APIServer, *slowLLMProvider) context.Context { return context.Background() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			judgeHealth.reset()
			t.Cleanup(judgeHealth.reset)
			a, p := newAnswerWindowJudgeServer(tc.mode, tc.delay)
			ctx := withHookJudgeFallbackNote(tc.setup(a, p))
			v := a.runHookJudge(ctx, "prompt", "prompt", "codex", fallbackTestPrompt, "", nil)
			if got := hookJudgeFallbackReason(ctx); got != tc.reason {
				t.Fatalf("fallback reason = %q, want %q", got, tc.reason)
			}
			want := 0
			if tc.reason != "" {
				want = 1
				if v != nil {
					t.Fatalf("a %s fallback returned a judge verdict %+v; the rules must decide", tc.reason, v)
				}
			} else if v == nil {
				t.Fatal("the judge answered in time but gave no verdict")
			}
			if tc.name == "late" {
				// The late judge still finishes; its answer is not a second fallback.
				select {
				case <-p.finished:
				case <-time.After(5 * time.Second):
					t.Fatal("the late judge never finished")
				}
			}
			if got := judgeFallbacksFor("codex"); got != want {
				t.Fatalf("codex fallbacks = %d, want %d (details %v)", got, want, judgeHealth.details())
			}
		})
	}
}

func TestJudgeHealthReportsFallbacksWithoutJudgeCalls(t *testing.T) {
	judgeHealth.reset()
	t.Cleanup(judgeHealth.reset)
	judgeHealth.recordFallback("claudecode", judgeFallbackBusy, time.Now())
	judgeHealth.recordFallback("claudecode", judgeFallbackTimeout, time.Now())
	judgeHealth.recordFallback("codex", judgeFallbackLate, time.Now())
	details := judgeHealth.details()
	if details["judge_fallbacks"] != 3 {
		t.Fatalf("judge_fallbacks = %v, want 3", details["judge_fallbacks"])
	}
	if _, ok := details["judge_state"]; ok {
		t.Fatalf("judge_state without any judge call: %v", details)
	}
	if got := details["judge_last_fallback"]; got != "late (codex)" {
		t.Fatalf("judge_last_fallback = %v, want late (codex)", got)
	}
	judgeHealth.record(false, "", time.Now())
	if judgeHealth.details()["judge_state"] != "ok" || judgeHealth.details()["judge_fallbacks"] != 3 {
		t.Fatalf("details after a good call = %v, want ok with the fallbacks kept", judgeHealth.details())
	}
	judgeHealth.applyJudge(&LLMJudge{}, "")
	if judgeHealth.details() != nil {
		t.Fatalf("a new judge kept the old fallbacks: %v", judgeHealth.details())
	}
}

func TestHookDecisionRecordCarriesTheJudgeFallback(t *testing.T) {
	for reason, present := range map[string]bool{
		judgeFallbackTimeout: true, judgeFallbackError: true, judgeFallbackLate: true,
		judgeFallbackBusy: true, judgeFallbackBudget: true, "": false, "made-up": false,
	} {
		env := HookAuditEnvelope{Extra: map[string]string{hookJudgeFallbackExtraKey: reason}}
		got, ok := hookDecisionV8JudgeFallback(env).Get()
		if ok != present || (present && got != reason) {
			t.Fatalf("reason %q: record field = %q present=%v, want present=%v", reason, got, ok, present)
		}
	}
}

// End to end through the Copilot hook handler: a judge that fails leaves the
// rules' verdict (allow for a benign call) and counts one copilot fallback.
func TestHookJudgeFallbackCountedThroughTheHookHandler(t *testing.T) {
	judgeHealth.reset()
	t.Cleanup(judgeHealth.reset)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "copilot"
	cfg.Guardrail.DetectionStrategy = "judge_first"
	cfg.Guardrail.Judge = config.JudgeConfig{Enabled: true, Injection: true, ToolInjection: true,
		HookConnectors: []string{"copilot"}, HookTimeout: 2}
	provider := &mockLLMProvider{err: errors.New("judge model unreachable")}
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	api.SetHookJudge(&LLMJudge{cfg: &cfg.Guardrail.Judge, model: "test-model", provider: provider, rp: &guardrail.RulePack{}})
	cwd, _ := json.Marshal(t.TempDir())
	body := `{"sessionId":"f1395-hook","cwd":` + string(cwd) +
		`,"toolName":"bash","toolArgs":"{\"command\":\"git log --oneline -n 20 -- ./internal\"}"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
	if h := hookpaths.ResolveConnector("copilot", "", "preToolUse", []byte(body)); h != "" {
		req.Header.Set(hookpaths.Header, h)
	}
	w := httptest.NewRecorder()
	api.handleAgentHook("copilot").ServeHTTP(w, req)
	var answer struct {
		Action string `json:"action"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &answer)
	if answer.Action != "allow" {
		t.Fatalf("benign call with a failed judge = %s, want the rules' allow", w.Body.String())
	}
	if len(provider.captured) == 0 {
		t.Fatalf("fixture: the hook judge was never asked: %s", w.Body.String())
	}
	if got := judgeFallbacksFor("copilot"); got != 1 {
		t.Fatalf("copilot fallbacks = %d, want 1 (details %v)", got, judgeHealth.details())
	}
}

func TestShellHookBoundsOnlyClaudeCodeAndCodexToolGates(t *testing.T) {
	plain := httptest.NewRequest(http.MethodPost, "/", nil)
	progress := httptest.NewRequest(http.MethodPost, "/", nil)
	progress.Header.Set(hookexec.HookProgressHeader, "1")
	for _, tc := range []struct {
		connector, event string
		r                *http.Request
		want             bool
	}{
		{"claudecode", "PreToolUse", plain, true},
		{"codex", "PermissionRequest", plain, true},
		{"claudecode", "UserPromptSubmit", plain, false},
		{"claudecode", "PostToolUse", plain, false},
		{"copilot", "preToolUse", plain, false},
		{"claudecode", "PreToolUse", progress, false}, // the progress-bounded native hook already is
	} {
		if got := shellHookBoundsToolGate(tc.connector, tc.event, tc.r); got != tc.want {
			t.Errorf("%s %s progress=%v: %v, want %v", tc.connector, tc.event, tc.r == progress, got, tc.want)
		}
	}
}

// #1395, live on dc-rhel: the Claude Code shell hook gives PreToolUse 4 s in
// all and does not ask for progress reports. A tool judge queued on a slow
// model held the answer to its 8 s hook_timeout, the hook gave up at 4 s and
// failed the benign call closed. The answer now keeps the rule verdict at the
// answer window and reports a late judge.
func TestShellToolGateJudgeAnswersInsideTheHookBudget(t *testing.T) {
	judgeHealth.reset()
	t.Cleanup(judgeHealth.reset)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.DetectionStrategy = "judge_first"
	cfg.Guardrail.Judge = config.JudgeConfig{Enabled: true, Injection: true, ToolInjection: true,
		HookConnectors: []string{"claudecode"}}
	slow := &slowLLMProvider{mockLLMProvider: mockLLMProvider{response: &ChatResponse{Model: "test-model",
		Choices: []ChatChoice{{Message: &ChatMessage{Content: "{}"}}}}}, delay: 6 * time.Second, finished: make(chan error, 8)}
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	api.SetHookJudge(&LLMJudge{cfg: &cfg.Guardrail.Judge, model: "test-model", provider: slow, rp: &guardrail.RulePack{}})
	cwd, _ := json.Marshal(t.TempDir())
	body := `{"session_id":"f1395-shell-gate","hook_event_name":"PreToolUse","cwd":` + string(cwd) +
		`,"tool_name":"Bash","tool_use_id":"t1","tool_input":{"command":"git log --oneline -n 20 -- ./internal"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookexec.HookAnswerWithinHeader, "2600") // the helper's wait after the shell's own start
	if h := hookpaths.ResolveConnector("claudecode", "", "PreToolUse", []byte(body)); h != "" {
		req.Header.Set(hookpaths.Header, h)
	}
	w := httptest.NewRecorder()
	start := time.Now()
	api.handleAgentHook("claudecode").ServeHTTP(w, req)
	elapsed := time.Since(start)
	if elapsed > 2600*time.Millisecond {
		t.Fatalf("PreToolUse answered after %s with a 6 s judge; the hook waits 2.6 s", elapsed)
	}
	if strings.Contains(w.Body.String(), `"deny"`) || strings.Contains(w.Body.String(), `"block"`) {
		t.Fatalf("benign call denied: %s", w.Body.String())
	}
	if got := judgeFallbacksFor("claudecode"); got != 1 {
		t.Fatalf("claudecode fallbacks = %d, want 1 late (details %v)", got, judgeHealth.details())
	}
	if last, _ := judgeHealth.details()["judge_last_fallback"].(string); last != "late (claudecode)" {
		t.Fatalf("last fallback = %q, want late (claudecode)", last)
	}
}

func TestShellToolGateWindowFollowsTheHookWait(t *testing.T) {
	start := time.Now()
	base := context.WithValue(context.Background(), hookRequestStartKey{}, start)
	for _, tc := range []struct {
		header string
		want   time.Duration
	}{
		{"", shellToolGateDefaultWindow},
		{"junk", shellToolGateDefaultWindow},
		{"2600", 2300 * time.Millisecond},
		{"200", 0},
		{"30000", hookJudgeAnswerWindow}, // a hook cannot stretch the window
	} {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		if tc.header != "" {
			r.Header.Set(hookexec.HookAnswerWithinHeader, tc.header)
		}
		end, bounded := hookJudgeAnswerEnd(withShellToolGateBound(base, r))
		if !bounded || end.Sub(start) != tc.want {
			t.Errorf("header %q: window %s bounded=%v, want %s", tc.header, end.Sub(start), bounded, tc.want)
		}
	}
}
