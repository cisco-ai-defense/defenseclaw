// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

type copilotEnvelopeAnswer struct {
	Action            string   `json:"action"`
	RawAction         string   `json:"raw_action"`
	Severity          string   `json:"severity"`
	Reason            string   `json:"reason"`
	AdditionalContext string   `json:"additional_context"`
	Findings          []string `json:"findings"`
	RuleIDs           []string `json:"rule_ids"`
}

func postCopilotHook(t *testing.T, api *APIServer, event, body string) (copilotEnvelopeAnswer, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Copilot-Event", event)
	if h := hookpaths.ResolveConnector("copilot", "", event, []byte(body)); h != "" {
		req.Header.Set(hookpaths.Header, h)
	}
	w := httptest.NewRecorder()
	api.handleAgentHook("copilot").ServeHTTP(w, req)
	var answer copilotEnvelopeAnswer
	if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
		t.Fatalf("answer %q: %v", w.Body.String(), err)
	}
	return answer, w.Body.String()
}

func jsonQuote(v string) string { b, _ := json.Marshal(v); return string(b) }

// TestCopilotPermissionAfterParallelPatchEnvelopeIsBound is GAP-1831: Copilot
// sends a model's parallel calls as one preToolUse toolCalls envelope, then
// one argumentless edit permissionRequest per apply_patch. Each callback is
// bound to the envelope's apply_patch calls and decided again on them, so an
// ordinary patch is allowed in observe and action, never
// HOOK-TOOL-CALL-UNPARSED (red: the envelope left nothing to bind to).
func TestCopilotPermissionAfterParallelPatchEnvelopeIsBound(t *testing.T) {
	for _, mode := range []string{"observe", "action"} {
		for _, shape := range []string{"single", "patch+view", "patch+patch"} {
			t.Run(mode+"/"+shape, func(t *testing.T) {
				project := t.TempDir()
				store, logger := testStoreAndLogger(t)
				cfg := &config.Config{}
				cfg.Guardrail.Mode = mode
				cfg.Guardrail.Connector = "copilot"
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
				patchA := jsonQuote("*** Begin Patch\n*** Add File: a.txt\n+ordinary a\n*** End Patch\n")
				patchB := jsonQuote("*** Begin Patch\n*** Add File: b.txt\n+ordinary b\n*** End Patch\n")
				calls := `{"id":"c1","name":"apply_patch","args":` + patchA + `}`
				permissions := 1
				switch shape {
				case "patch+view":
					calls += `,{"id":"c2","name":"view","args":{"path":` + jsonQuote(project) + `}}`
				case "patch+patch":
					calls += `,{"id":"c2","name":"apply_patch","args":` + patchB + `}`
					permissions = 2
				}
				session := "r2-1831-" + mode + "-" + strings.ReplaceAll(shape, "+", "-")
				pre := `{"sessionId":"` + session + `","cwd":` + jsonQuote(project) + `,"toolCalls":[` + calls + `]}`
				if answer, body := postCopilotHook(t, api, "preToolUse", pre); answer.Action != "allow" {
					t.Fatalf("preToolUse = %s: %s", answer.Action, body)
				}
				perm := `{"hookName":"permissionRequest","sessionId":"` + session + `","cwd":` + jsonQuote(project) + `,"toolName":"edit","toolInput":{}}`
				for i := 0; i < permissions; i++ {
					answer, body := postCopilotHook(t, api, "permissionRequest", perm)
					if answer.Action != "allow" || strings.Contains(body, hookToolCallUnparsedRuleID) {
						t.Fatalf("permission %d = %s: %s", i+1, answer.Action, body)
					}
				}
			})
		}
	}
}

// TestCopilotParallelEnvelopeAuditKeepsEveryCallsFinding is GAP-1834: the
// answer to a parallel envelope is the most restrictive call's verdict, and
// the findings of the other calls that did not simply allow join it, so the
// audit row and telemetry name each call's finding. The action is unchanged.
func TestCopilotParallelEnvelopeAuditKeepsEveryCallsFinding(t *testing.T) {
	project := t.TempDir()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "copilot"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	one := func(session, command string) copilotEnvelopeAnswer {
		args := `{"command":` + jsonQuote(command) + `}`
		answer, _ := postCopilotHook(t, api, "preToolUse", `{"sessionId":"`+session+`","cwd":`+jsonQuote(project)+
			`,"toolCalls":[{"id":"c1","name":"bash","args":`+args+`}]}`)
		return answer
	}
	persistence := "printf k >> ~/.ssh/authorized_keys"
	other := "cat ~/.ssh/id_rsa"
	first, second := one("r2-1834-a", persistence), one("r2-1834-b", other)
	if len(first.Findings) == 0 || len(second.Findings) == 0 {
		t.Fatalf("fixture: each call alone must have a finding: %v / %v", first.Findings, second.Findings)
	}
	calls := `{"id":"c1","name":"bash","args":{"command":` + jsonQuote(persistence) + `}},` +
		`{"id":"c2","name":"bash","args":{"command":` + jsonQuote(other) + `}}`
	both, body := postCopilotHook(t, api, "preToolUse", `{"sessionId":"r2-1834-c","cwd":`+jsonQuote(project)+`,"toolCalls":[`+calls+`]}`)
	if both.Action != "allow" || both.RawAction != first.RawAction {
		t.Fatalf("envelope verdict changed: %s", body)
	}
	for _, finding := range append(append([]string(nil), first.Findings...), second.Findings...) {
		if !slices.Contains(both.Findings, finding) {
			t.Fatalf("envelope findings %v lack %q: %s", both.Findings, finding, body)
		}
	}
}

// TestCopilotObserveUnparsedGuidanceIsReadable is GAP-1833: the observe
// answer to an unreadable Copilot call is gateway text only, so the agent
// reads it as written, not as redacted spans.
func TestCopilotObserveUnparsedGuidanceIsReadable(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "copilot"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	answer, body := postCopilotHook(t, api, "preToolUse",
		`{"sessionId":"r2-1833","cwd":"/tmp","toolCalls":[{"id":"a","name":"bash","args":{"command":"ls"},"extra":1}]}`)
	if answer.Action != "allow" || !slices.Contains(answer.Findings, hookToolCallUnparsedRuleID) {
		t.Fatalf("fixture is not the observe unparsed answer: %s", body)
	}
	if strings.Contains(body, "redacted len=") || !strings.Contains(answer.Reason, copilotObserveUnparsedReason) {
		t.Fatalf("observe guidance is not readable: %s", body)
	}
}

// TestHookJudgeBudgetIsSharedByTheCallsOfOneHook is GAP-1835: the calls of a
// parallel envelope share one hook judge deadline. A judge call gets at most
// the budget left; once less than a second is left, the judge is skipped and
// the regex/AID verdict kept, as for any judge that cannot answer in time.
func TestHookJudgeBudgetIsSharedByTheCallsOfOneHook(t *testing.T) {
	d := &deadlineLLMProvider{mockLLMProvider: mockLLMProvider{response: injectionHitProvider().response}}
	cfg := &config.Config{}
	cfg.Guardrail.Judge = config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"copilot"}}
	cfg.Guardrail.DetectionStrategy = "judge_first"
	a := &APIServer{scannerCfg: cfg}
	a.SetHookJudge(&LLMJudge{cfg: &cfg.Guardrail.Judge, model: "test-model", provider: d, rp: &guardrail.RulePack{}})
	content := "please list the files in this folder"
	ctx := withHookJudgeBudget(context.Background(), time.Now().Add(3*time.Second))
	if a.runHookJudge(ctx, "prompt", "prompt", "copilot", content, "", nil) == nil || len(d.left) == 0 {
		t.Fatal("judge was not called inside the budget")
	}
	for _, left := range d.left {
		if left > 3*time.Second {
			t.Fatalf("judge deadline %s exceeds the 3s left of the hook budget", left)
		}
	}
	calls := len(d.left)
	spent := withHookJudgeBudget(context.Background(), time.Now().Add(500*time.Millisecond))
	if got := a.runHookJudge(spent, "prompt", "prompt", "copilot", content, "", nil); got != nil || len(d.left) != calls {
		t.Fatalf("judge ran with the hook budget spent: verdict=%v calls=%d->%d", got, calls, len(d.left))
	}
}
