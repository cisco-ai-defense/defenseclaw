// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// GAP-1835 regression test, end to end through the Copilot hook handler: the
// calls of one preToolUse toolCalls envelope share one hook judge budget. It
// uses only names that exist both at the fix parent fa1a23f334 and at the fix
// 079b1245de, so the same file fails at the parent (6 serial judge calls,
// about 12 s) and passes with the fix. Copilot CLI itself sends one
// preToolUse per call (TST-33530, TST-41426), so this shape is scripted only
// (SCRIPTED-ONLY.md, GAP-1835).

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

const sv1835CleanJudgeJSON = `{
  "Instruction Manipulation": {"reasoning": "none", "label": false},
  "Context Manipulation": {"reasoning": "none", "label": false},
  "Obfuscation": {"reasoning": "none", "label": false},
  "Semantic Manipulation": {"reasoning": "none", "label": false},
  "Token Exploitation": {"reasoning": "none", "label": false}
}`

// sv1835SlowJudge is a 2 s judge stub (the gap's "measure with a 2 s judge
// stub"): every call waits 2 s or until its context ends.
type sv1835SlowJudge struct {
	mockLLMProvider
	delay time.Duration
	calls atomic.Int32
}

func (s *sv1835SlowJudge) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	s.calls.Add(1)
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return s.mockLLMProvider.ChatCompletion(ctx, req)
}

// TestSV105GAP1835EnvelopeJudgeLatencyIsOneBudget: a Copilot preToolUse
// toolCalls envelope of 6 benign calls, with the hook judge on for copilot,
// judge_first, hook_timeout 4 s and a 2 s judge stub, answers within one
// hook judge budget (not 6 x 2 s serial judge time) and still allows.
func TestSV105GAP1835EnvelopeJudgeLatencyIsOneBudget(t *testing.T) {
	const hookTimeout = 4.0
	for _, mode := range []string{"observe", "action"} {
		t.Run(mode, func(t *testing.T) {
			project := t.TempDir()
			cfg := &config.Config{}
			cfg.Guardrail.Mode = mode
			cfg.Guardrail.Connector = "copilot"
			cfg.Guardrail.DetectionStrategy = "judge_first"
			cfg.Guardrail.Judge = config.JudgeConfig{Enabled: true, Injection: true, ToolInjection: true,
				HookConnectors: []string{"copilot"}, HookTimeout: hookTimeout}
			stub := &sv1835SlowJudge{delay: 2 * time.Second, mockLLMProvider: mockLLMProvider{response: &ChatResponse{
				Model: "test-model", Choices: []ChatChoice{{Message: &ChatMessage{Content: sv1835CleanJudgeJSON}}},
				Usage: &ChatUsage{PromptTokens: 30, CompletionTokens: 18}}}}
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			api.SetHookJudge(&LLMJudge{cfg: &cfg.Guardrail.Judge, model: "test-model", provider: stub, rp: &guardrail.RulePack{}})

			cmds := []string{
				"ls -la ./src/components/forms",
				"cat ./docs/getting-started/install.md",
				"git log --oneline -n 20 -- ./internal",
				"grep -rn TODO ./src/components/forms",
				"wc -l ./docs/getting-started/install.md",
				"git status --short --branch -- ./src",
			}
			var calls []string
			for i, c := range cmds {
				q, _ := json.Marshal(c)
				calls = append(calls, `{"id":"c`+string(rune('1'+i))+`","name":"bash","args":{"command":`+string(q)+`}}`)
			}
			cwd, _ := json.Marshal(project)
			body := `{"sessionId":"sv105-1835-` + mode + `","cwd":` + string(cwd) + `,"toolCalls":[` + strings.Join(calls, ",") + `]}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
			if h := hookpaths.ResolveConnector("copilot", "", "preToolUse", []byte(body)); h != "" {
				req.Header.Set(hookpaths.Header, h)
			}
			w := httptest.NewRecorder()
			start := time.Now()
			api.handleAgentHook("copilot").ServeHTTP(w, req)
			elapsed := time.Since(start)
			n := stub.calls.Load()
			var answer struct {
				Action string `json:"action"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &answer)
			t.Logf("mode=%s calls=%d judge_calls=%d elapsed=%s action=%s", mode, len(cmds), n, elapsed.Round(10*time.Millisecond), answer.Action)
			if n == 0 {
				t.Fatalf("fixture: the hook judge was never asked: %s", w.Body.String())
			}
			budget := time.Duration(hookTimeout * float64(time.Second))
			if elapsed > budget+1500*time.Millisecond {
				t.Errorf("GAP-1835: a %d-call envelope took %s with %d serial judge calls; want one %s hook judge budget for the envelope",
					len(cmds), elapsed.Round(10*time.Millisecond), n, budget)
			}
			if int(n) >= len(cmds) {
				t.Errorf("GAP-1835: every one of the %d calls was judged in turn (%d judge calls)", len(cmds), n)
			}
			if answer.Action != "allow" {
				t.Errorf("benign envelope not allowed (no over-tightening expected): %s", w.Body.String())
			}
		})
	}
}
