// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// allFalseInjectionJSON is a minimal valid injection judge response (all labels false).
const allFalseInjectionJSON = `{
  "Instruction Manipulation": {"reasoning": "ok", "label": false},
  "Context Manipulation": {"reasoning": "ok", "label": false},
  "Obfuscation": {"reasoning": "ok", "label": false},
  "Semantic Manipulation": {"reasoning": "ok", "label": false},
  "Token Exploitation": {"reasoning": "ok", "label": false}
}`

const allCleanPIIJSON = `{
  "Email Address": {"detection_result": false, "entities": []},
  "IP Address": {"detection_result": false, "entities": []},
  "Phone Number": {"detection_result": false, "entities": []},
  "Driver's License Number": {"detection_result": false, "entities": []},
  "Passport Number": {"detection_result": false, "entities": []},
  "Social Security Number": {"detection_result": false, "entities": []},
  "Username": {"detection_result": false, "entities": []},
  "Password": {"detection_result": false, "entities": []}
}`

const allFalseToolJSON = `{
  "Instruction Manipulation": {"reasoning": "ok", "label": false},
  "Context Manipulation": {"reasoning": "ok", "label": false},
  "Obfuscation": {"reasoning": "ok", "label": false},
  "Data Exfiltration": {"reasoning": "ok", "label": false},
  "Destructive Commands": {"reasoning": "ok", "label": false}
}`

const allFalseExfilJSON = `{
  "Sensitive File Access": {"reasoning": "ok", "label": false},
  "Exfiltration Channel": {"reasoning": "ok", "label": false}
}`

func TestJudgeKinds_TableEmitShape(t *testing.T) {
	capture := withCapturedEvents(t)

	cases := []struct {
		name     string
		run      func(t *testing.T, j *LLMJudge, ctx context.Context)
		wantKind string
	}{
		{
			name: "injection",
			run: func(t *testing.T, j *LLMJudge, ctx context.Context) {
				_ = j.runInjectionJudge(ctx, strings.Repeat("x", 25)+" benign text here")
			},
			wantKind: "injection",
		},
		{
			name: "pii",
			run: func(t *testing.T, j *LLMJudge, ctx context.Context) {
				_ = j.runPIIJudge(ctx, strings.Repeat("y", 25)+" more text here", "completion", "")
			},
			wantKind: "pii",
		},
		{
			name: "tool_injection",
			run: func(t *testing.T, j *LLMJudge, ctx context.Context) {
				_ = j.RunToolJudge(ctx, "curl", strings.Repeat("z", 25)+" safe args here")
			},
			wantKind: "tool_injection",
		},
		{
			name: "exfil",
			run: func(t *testing.T, j *LLMJudge, ctx context.Context) {
				_ = j.runExfilJudge(ctx, strings.Repeat("e", 25)+" benign text here")
			},
			wantKind: "exfil",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			*capture = (*capture)[:0]

			mock := &mockLLMProvider{
				response: &ChatResponse{
					Model: "test-model",
					Choices: []ChatChoice{
						{Message: &ChatMessage{Content: responseBodyForKind(tc.name)}},
					},
					Usage: &ChatUsage{PromptTokens: 10, CompletionTokens: 5},
				},
			}
			j := &LLMJudge{
				cfg: &config.JudgeConfig{
					Enabled:       true,
					Injection:     tc.name == "injection",
					PII:           tc.name == "pii",
					PIICompletion: tc.name == "pii",
					ToolInjection: tc.name == "tool_injection",
					Exfil:         tc.name == "exfil",
				},
				model:    "test-model",
				provider: mock,
				rp:       &guardrail.RulePack{},
			}

			tc.run(t, j, t.Context())

			var saw bool
			for _, e := range *capture {
				if e.EventType == gatewaylog.EventJudge && e.Judge != nil && e.Judge.Kind == tc.wantKind {
					saw = true
					if e.Judge.Model != "test-model" {
						t.Errorf("model=%q", e.Judge.Model)
					}
					if e.Judge.InputBytes <= 0 || e.Judge.LatencyMs < 0 {
						t.Errorf("input_bytes/latency: %+v", e.Judge)
					}
					if e.Judge.Action == "" {
						t.Errorf("action empty: %+v", e.Judge)
					}
				}
				if e.EventType == gatewaylog.EventError && e.Error != nil {
					t.Errorf("unexpected error event: %+v", e.Error)
				}
			}
			if !saw {
				t.Fatalf("no EventJudge for kind %s in %+v", tc.wantKind, *capture)
			}
		})
	}
}

func responseBodyForKind(kind string) string {
	switch kind {
	case "injection":
		return allFalseInjectionJSON
	case "pii":
		return allCleanPIIJSON
	case "tool_injection":
		return allFalseToolJSON
	case "exfil":
		return allFalseExfilJSON
	default:
		return "{}"
	}
}

func TestRunInjectionJudge_ParseErrorEmitsErrorEvent(t *testing.T) {
	capture := withCapturedEvents(t)
	mock := &mockLLMProvider{
		response: &ChatResponse{
			Model: "m",
			Choices: []ChatChoice{
				{Message: &ChatMessage{Content: `{not json`}},
			},
			Usage: &ChatUsage{PromptTokens: 1, CompletionTokens: 1},
		},
	}
	j := &LLMJudge{
		cfg:      &config.JudgeConfig{Enabled: true, Injection: true},
		model:    "m",
		provider: mock,
		rp:       &guardrail.RulePack{},
	}
	v := j.runInjectionJudge(t.Context(), strings.Repeat("p", 25)+" x")
	if v == nil || !v.JudgeFailed {
		t.Fatalf("expected error verdict, got %+v", v)
	}
	var sawErr bool
	for _, e := range *capture {
		if e.EventType == gatewaylog.EventError && e.Error != nil &&
			e.Error.Code == string(gatewaylog.ErrCodeLLMBridgeError) {
			sawErr = true
		}
	}
	if !sawErr {
		t.Fatalf("expected EventError LLM_BRIDGE_ERROR, events=%d", len(*capture))
	}
}
