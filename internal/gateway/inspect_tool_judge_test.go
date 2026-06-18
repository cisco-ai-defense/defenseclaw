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
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// J3-3b / J3-3c / J3-3d coverage: the LLM judge is wired into the
// tool-call args lane (inspectToolPolicy) and the tool-output lane
// (handleInspectToolResponse), OPT-IN and OFF BY DEFAULT. Each lane is
// proved both default-off (shipped regex_only ⇒ no judge round-trip)
// and opt-in-on (per-direction strategy set ⇒ judge runs + escalates).

// benignToolArgs is a tool-call args payload that no built-in regex /
// CodeGuard pattern flags, so any escalation in these tests comes solely
// from the judge lane — not from the local scanners.
const benignToolArgs = `{"path":"README.md","query":"weather today"}`

// piiCompletionHitJSON is a recorded PII-judge response with one email
// hit — the wire contract piiToVerdict parses. The PII judge is the
// only sub-judge that fires on the "completion" direction, which is
// what tool output maps to.
const piiCompletionHitJSON = `{
  "Email Address": {"detection_result": true, "entities": ["test@example.com"]}
}`

func piiCompletionHitProvider() *mockLLMProvider {
	return &mockLLMProvider{
		response: &ChatResponse{
			Model: "test-model",
			Choices: []ChatChoice{
				{Message: &ChatMessage{Content: piiCompletionHitJSON}},
			},
			Usage: &ChatUsage{PromptTokens: 24, CompletionTokens: 12},
		},
	}
}

// ---------------------------------------------------------------------------
// J3-3b — tool-call args lane (inspectToolPolicy)
// ---------------------------------------------------------------------------

// Default off: with the shipped regex_only strategy the tool-call lane
// never contacts the judge, even for a gated connector.
func TestToolCallJudge_DefaultOffRegexOnly(t *testing.T) {
	mock := injectionHitProvider()
	a := newHookJudgeAPIServer(t,
		config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"hermes"}},
		"regex_only", mock)

	verdict := a.inspectToolPolicy(&ToolInspectRequest{
		Tool: "fetch_url", Args: json.RawMessage(benignToolArgs),
		Direction: "tool_call", Connector: "hermes",
	})

	if len(mock.captured) != 0 {
		t.Fatalf("judge provider called %d time(s) under regex_only tool-call lane", len(mock.captured))
	}
	if verdict.Action != "allow" {
		t.Fatalf("action=%q, want allow on benign args without judge (verdict=%+v)", verdict.Action, verdict)
	}
}

// Opt-in on (global strategy): with a judge strategy and a gated
// connector the tool-call lane judges the args and a judge hit escalates
// the verdict with an llm-judge:-tagged finding.
func TestToolCallJudge_OptInRunsJudge(t *testing.T) {
	mock := injectionHitProvider()
	a := newHookJudgeAPIServer(t,
		config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"hermes"}},
		"judge_first", mock)

	verdict := a.inspectToolPolicy(&ToolInspectRequest{
		Tool: "fetch_url", Args: json.RawMessage(benignToolArgs),
		Direction: "tool_call", Connector: "hermes",
	})

	if len(mock.captured) == 0 {
		t.Fatal("judge provider never called for an opted-in tool-call lane")
	}
	if verdict.Action == "allow" {
		t.Fatalf("action=%q, want escalation from a judge injection hit (verdict=%+v)", verdict.Action, verdict)
	}
	if !judgeTaggedFinding(verdict.Findings) {
		t.Fatalf("no llm-judge: tagged finding in %v", verdict.Findings)
	}
}

func TestToolCallJudge_ProviderErrorFailsOpen(t *testing.T) {
	mock := &mockLLMProvider{err: errors.New("provider down")}
	a := newHookJudgeAPIServer(t,
		config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"hermes"}},
		"judge_first", mock)

	verdict := a.inspectToolPolicy(&ToolInspectRequest{
		Tool: "fetch_url", Args: json.RawMessage(benignToolArgs),
		Direction: "tool_call", Connector: "hermes",
	})

	if len(mock.captured) == 0 {
		t.Fatal("judge provider was never attempted")
	}
	if verdict.Action != "allow" {
		t.Fatalf("action=%q, want allow (fail-open) when the tool-call judge errors (verdict=%+v)", verdict.Action, verdict)
	}
	if judgeTaggedFinding(verdict.Findings) {
		t.Fatalf("failed judge leaked findings into %v", verdict.Findings)
	}
}

// The per-direction field is honored independently of the global
// strategy: detection_strategy_tool_call=judge_first turns the lane on
// even when the global strategy is regex_only — proving the formerly
// dead detection_strategy_tool_call config now drives the lane.
func TestToolCallJudge_PerDirectionStrategyDrivesLane(t *testing.T) {
	mock := injectionHitProvider()
	a := newHookJudgeAPIServer(t,
		config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"hermes"}},
		"regex_only", mock)
	a.scannerCfg.Guardrail.DetectionStrategyToolCall = "judge_first"

	verdict := a.inspectToolPolicy(&ToolInspectRequest{
		Tool: "fetch_url", Args: json.RawMessage(benignToolArgs),
		Direction: "tool_call", Connector: "hermes",
	})

	if len(mock.captured) == 0 {
		t.Fatal("detection_strategy_tool_call=judge_first did not run the judge")
	}
	if verdict.Action == "allow" {
		t.Fatalf("action=%q, want escalation under per-direction tool_call strategy", verdict.Action)
	}
}

// An ungated connector keeps the lane off regardless of strategy.
func TestToolCallJudge_UngatedConnectorSkipsJudge(t *testing.T) {
	mock := injectionHitProvider()
	a := newHookJudgeAPIServer(t,
		config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"hermes"}},
		"judge_first", mock)

	a.inspectToolPolicy(&ToolInspectRequest{
		Tool: "fetch_url", Args: json.RawMessage(benignToolArgs),
		Direction: "tool_call", Connector: "opencode",
	})

	if len(mock.captured) != 0 {
		t.Fatalf("judge provider called %d time(s) for an ungated tool-call connector", len(mock.captured))
	}
}

// The generic /inspect/tool endpoint runs inspectToolPolicy under a
// 200ms deadline (inspectToolPolicyCtx); the judge deadline guard must
// short-circuit there even when opted in, so the verdict still returns
// fast rather than 504-ing on a judge round-trip (J3-3c boundary: the
// fix gives the NATIVE lanes their own timeout, it does not widen the
// generic endpoint's 200ms cap).
func TestToolCallJudge_GenericEndpoint200msShortCircuits(t *testing.T) {
	mock := injectionHitProvider()
	a := newHookJudgeAPIServer(t,
		config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"hermes"}},
		"judge_first", mock)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	a.inspectToolPolicyCtx(ctx, &ToolInspectRequest{
		Tool: "fetch_url", Args: json.RawMessage(benignToolArgs),
		Direction: "tool_call", Connector: "hermes",
	})

	if len(mock.captured) != 0 {
		t.Fatalf("judge provider called %d time(s) under the 200ms generic-endpoint deadline", len(mock.captured))
	}
}

// ---------------------------------------------------------------------------
// J3-3c / J3-3d — tool-output lane (handleInspectToolResponse)
// ---------------------------------------------------------------------------

// newToolOutputJudgeServer builds a full APIServer (with audit logger,
// so the HTTP handler's audit calls are safe) with the hook judge wired
// and the process connector set so connectorName() resolves to a gated
// connector — ToolResponseInspectRequest carries no connector field.
func newToolOutputJudgeServer(t *testing.T, jcfg config.JudgeConfig, strategy string, mock *mockLLMProvider) *APIServer {
	t.Helper()
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Judge = jcfg
	cfg.Guardrail.DetectionStrategy = strategy
	cfg.Guardrail.Connector = "hermes"
	a := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	a.SetHookJudge(&LLMJudge{
		cfg:      &cfg.Guardrail.Judge,
		model:    "test-model",
		provider: mock,
		rp:       &guardrail.RulePack{},
	})
	return a
}

// Default off: the shipped regex_only completion strategy keeps the
// tool-output lane regex-only — no judge round-trip.
func TestToolOutputJudge_DefaultOffRegexOnly(t *testing.T) {
	mock := piiCompletionHitProvider()
	a := newToolOutputJudgeServer(t,
		config.JudgeConfig{Enabled: true, PII: true, PIICompletion: true, HookConnectors: []string{"hermes"}},
		"regex_only", mock)

	_, verdict := postInspectToolResponse(t, a,
		`{"tool":"fetch_url","output":"the meeting is at noon, see you there"}`)

	if len(mock.captured) != 0 {
		t.Fatalf("judge provider called %d time(s) under regex_only tool-output lane", len(mock.captured))
	}
	if verdict.Action != "allow" {
		t.Fatalf("action=%q, want allow on benign output without judge (verdict=%+v)", verdict.Action, verdict)
	}
}

// Opt-in on: with completion opted into a judge strategy the tool-output
// lane forwards the output to the judge (completion direction → PII
// judge), and a judge hit escalates with an llm-judge:-tagged finding.
func TestToolOutputJudge_OptInRunsJudge(t *testing.T) {
	mock := piiCompletionHitProvider()
	a := newToolOutputJudgeServer(t,
		config.JudgeConfig{Enabled: true, PII: true, PIICompletion: true, HookConnectors: []string{"hermes"}},
		"judge_first", mock)

	// The claimed PII entity must appear in the output or the judge's
	// hallucination guard drops it; the llm-judge:-tagged finding below
	// is what proves the judge (not the regex lane) contributed.
	_, verdict := postInspectToolResponse(t, a,
		`{"tool":"fetch_url","output":"please reach me at test@example.com about the meeting"}`)

	if len(mock.captured) == 0 {
		t.Fatal("judge provider never called for an opted-in tool-output lane")
	}
	// Mode defaults to observe, so a block is surfaced as would_block
	// with action downgraded to allow; assert the latent escalation and
	// the judge finding rather than the post-mode action.
	if verdict.RawAction == "allow" && !verdict.WouldBlock {
		t.Fatalf("raw_action=%q would_block=%v, want a latent escalation from the PII judge (verdict=%+v)",
			verdict.RawAction, verdict.WouldBlock, verdict)
	}
	if !judgeTaggedFinding(verdict.Findings) {
		t.Fatalf("no llm-judge: tagged finding in %v", verdict.Findings)
	}
}

// Per-direction completion strategy drives the tool-output lane
// independently of the global strategy.
func TestToolOutputJudge_PerDirectionStrategyDrivesLane(t *testing.T) {
	mock := piiCompletionHitProvider()
	a := newToolOutputJudgeServer(t,
		config.JudgeConfig{Enabled: true, PII: true, PIICompletion: true, HookConnectors: []string{"hermes"}},
		"regex_only", mock)
	a.scannerCfg.Guardrail.DetectionStrategyCompletion = "judge_first"

	postInspectToolResponse(t, a,
		`{"tool":"fetch_url","output":"the meeting is at noon, see you there"}`)

	if len(mock.captured) == 0 {
		t.Fatal("detection_strategy_completion=judge_first did not run the tool-output judge")
	}
}
