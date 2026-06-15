// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// hookInjectionHitJSON is a recorded injection-judge response with one
// strong category hit — the wire contract from injectionSystemPrompt.
const hookInjectionHitJSON = `{
  "Instruction Manipulation": {"reasoning": "Sample explicitly asks to ignore prior instructions.", "label": true},
  "Context Manipulation": {"reasoning": "none", "label": false},
  "Obfuscation": {"reasoning": "none", "label": false},
  "Semantic Manipulation": {"reasoning": "none", "label": false},
  "Token Exploitation": {"reasoning": "none", "label": false}
}`

// newHookJudgeAPIServer builds an APIServer with the hook-lane judge
// wired the same way the sidecar does at boot (SetHookJudge), backed
// by the shared mockLLMProvider so tests can observe whether the
// judge's LLM was actually called.
func newHookJudgeAPIServer(t *testing.T, jcfg config.JudgeConfig, strategy string, mock *mockLLMProvider) *APIServer {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Judge = jcfg
	cfg.Guardrail.DetectionStrategy = strategy
	a := &APIServer{scannerCfg: cfg}
	a.SetHookJudge(&LLMJudge{
		cfg:      &cfg.Guardrail.Judge,
		model:    "test-model",
		provider: mock,
		rp:       &guardrail.RulePack{},
	})
	return a
}

func injectionHitProvider() *mockLLMProvider {
	return &mockLLMProvider{
		response: &ChatResponse{
			Model: "test-model",
			Choices: []ChatChoice{
				{Message: &ChatMessage{Content: hookInjectionHitJSON}},
			},
			Usage: &ChatUsage{PromptTokens: 30, CompletionTokens: 18},
		},
	}
}

func judgeTaggedFinding(findings []string) bool {
	for _, f := range findings {
		if strings.HasPrefix(f, "llm-judge:") {
			return true
		}
	}
	return false
}

// A connector listed in guardrail.judge.hook_connectors must have its
// hook content forwarded to the judge, and a judge hit must escalate
// the verdict with llm-judge:-tagged findings.
func TestHookJudge_GatedConnectorRunsJudge(t *testing.T) {
	mock := injectionHitProvider()
	a := newHookJudgeAPIServer(t,
		config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"hermes"}},
		"judge_first", mock)

	verdict := a.inspectMessageContent(t.Context(), &ToolInspectRequest{
		Tool: "message", Content: "hello there, lovely weather today",
		Direction: "prompt", Connector: "hermes",
	})

	if len(mock.captured) == 0 {
		t.Fatal("judge provider was never called for a gated connector")
	}
	if verdict.Action == "allow" {
		t.Fatalf("action=%q, want escalation from a judge injection hit (verdict=%+v)", verdict.Action, verdict)
	}
	if !judgeTaggedFinding(verdict.Findings) {
		t.Fatalf("no llm-judge: tagged finding in %v", verdict.Findings)
	}
}

// A connector NOT in hook_connectors must keep today's behavior:
// regex + AID only, judge LLM never contacted.
func TestHookJudge_UngatedConnectorSkipsJudge(t *testing.T) {
	mock := injectionHitProvider()
	a := newHookJudgeAPIServer(t,
		config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"hermes"}},
		"judge_first", mock)

	verdict := a.inspectMessageContent(t.Context(), &ToolInspectRequest{
		Tool: "message", Content: "hello there, lovely weather today",
		Direction: "prompt", Connector: "opencode",
	})

	if len(mock.captured) != 0 {
		t.Fatalf("judge provider called %d time(s) for an ungated connector", len(mock.captured))
	}
	if verdict.Action != "allow" {
		t.Fatalf("action=%q, want allow on benign content without judge (verdict=%+v)", verdict.Action, verdict)
	}
}

// detection_strategy=regex_only keeps the judge off even for gated
// connectors.
func TestHookJudge_RegexOnlyStrategySkipsJudge(t *testing.T) {
	mock := injectionHitProvider()
	a := newHookJudgeAPIServer(t,
		config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"hermes"}},
		"regex_only", mock)

	a.inspectMessageContent(t.Context(), &ToolInspectRequest{
		Tool: "message", Content: "hello there, lovely weather today",
		Direction: "prompt", Connector: "hermes",
	})

	if len(mock.captured) != 0 {
		t.Fatalf("judge provider called %d time(s) under regex_only", len(mock.captured))
	}
}

// Under the default regex_judge strategy a HIGH+ regex/AID verdict is
// already decisive — the judge round-trip must be skipped.
func TestHookJudge_RegexJudgeSkipsWhenLocalLanesDecisive(t *testing.T) {
	mock := injectionHitProvider()
	// Empty strategy resolves to the regex_judge default.
	a := newHookJudgeAPIServer(t,
		config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"hermes"}},
		"", mock)

	v := a.hookJudgeInspect(t.Context(), &ToolInspectRequest{
		Tool: "message", Direction: "prompt", Connector: "hermes",
	}, "some content", &ToolInspectVerdict{Action: "block", Severity: "HIGH"})

	if v != nil {
		t.Fatalf("verdict=%+v, want nil when regex already HIGH", v)
	}
	if len(mock.captured) != 0 {
		t.Fatalf("judge provider called %d time(s) despite decisive regex verdict", len(mock.captured))
	}
}

// Callers with a sub-second deadline (the legacy /inspect handler runs
// under 200ms) must never pay a judge round-trip — blowing that budget
// would 504 the whole verdict.
func TestHookJudge_ShortDeadlineSkipsJudge(t *testing.T) {
	mock := injectionHitProvider()
	a := newHookJudgeAPIServer(t,
		config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"hermes"}},
		"judge_first", mock)

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	v := a.hookJudgeInspect(ctx, &ToolInspectRequest{
		Tool: "message", Direction: "prompt", Connector: "hermes",
	}, "some content", &ToolInspectVerdict{Action: "allow", Severity: "NONE"})

	if v != nil {
		t.Fatalf("verdict=%+v, want nil under a 200ms deadline", v)
	}
	if len(mock.captured) != 0 {
		t.Fatalf("judge provider called %d time(s) under a 200ms deadline", len(mock.captured))
	}
}

// Judge unavailability fails open to the regex/AID verdict: a provider
// error must leave the hook verdict exactly as the local lanes decided.
func TestHookJudge_ProviderErrorFailsOpen(t *testing.T) {
	mock := &mockLLMProvider{err: errors.New("provider down")}
	a := newHookJudgeAPIServer(t,
		config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"hermes"}},
		"judge_first", mock)

	verdict := a.inspectMessageContent(t.Context(), &ToolInspectRequest{
		Tool: "message", Content: "hello there, lovely weather today",
		Direction: "prompt", Connector: "hermes",
	})

	if len(mock.captured) == 0 {
		t.Fatal("judge provider was never attempted")
	}
	if verdict.Action != "allow" {
		t.Fatalf("action=%q, want allow (fail-open) when the judge errors (verdict=%+v)", verdict.Action, verdict)
	}
	if judgeTaggedFinding(verdict.Findings) {
		t.Fatalf("failed judge leaked findings into %v", verdict.Findings)
	}
}

// Hook tool_result content maps to the judge's "completion" direction;
// with only the injection judge enabled (a prompt-direction judge) no
// sub-judge applies, so the provider must not be called.
func TestHookJudge_ToolResultMapsToCompletionDirection(t *testing.T) {
	mock := injectionHitProvider()
	a := newHookJudgeAPIServer(t,
		config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"hermes"}},
		"judge_first", mock)

	a.inspectMessageContent(t.Context(), &ToolInspectRequest{
		Tool: "fetch_url", Content: "tool output: hello there",
		Direction: "tool_result", Connector: "hermes",
	})

	if len(mock.captured) != 0 {
		t.Fatalf("injection judge called %d time(s) on completion-direction content", len(mock.captured))
	}
}

// HookConnectorEnabled gating matrix: case-insensitive names, the "*"
// wildcard, judge.enabled as a hard precondition, and empty-list-off.
func TestJudgeHookConnectorEnabled(t *testing.T) {
	cases := []struct {
		name      string
		cfg       config.JudgeConfig
		connector string
		want      bool
	}{
		{"case-insensitive match", config.JudgeConfig{Enabled: true, HookConnectors: []string{"Hermes"}}, "hermes", true},
		{"unlisted connector", config.JudgeConfig{Enabled: true, HookConnectors: []string{"hermes"}}, "opencode", false},
		{"wildcard", config.JudgeConfig{Enabled: true, HookConnectors: []string{"*"}}, "opencode", true},
		{"judge disabled wins", config.JudgeConfig{Enabled: false, HookConnectors: []string{"*"}}, "hermes", false},
		{"empty list off", config.JudgeConfig{Enabled: true}, "hermes", false},
		{"empty connector name", config.JudgeConfig{Enabled: true, HookConnectors: []string{"*"}}, "", false},
	}
	for _, tc := range cases {
		if got := tc.cfg.HookConnectorEnabled(tc.connector); got != tc.want {
			t.Errorf("%s: HookConnectorEnabled(%q)=%v, want %v", tc.name, tc.connector, got, tc.want)
		}
	}
}
