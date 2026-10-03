// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

func acpWordingTestConfig() *config.Config {
	return &config.Config{ACP: config.ACPConfig{
		Enabled: true, Mode: "action", DefaultProfile: "default",
		Clients: map[string]config.ACPBinding{"zed": {Enabled: true, Profile: "default"}},
		Agents:  map[string]config.ACPBinding{"kiro": {Enabled: true, Profile: "default"}},
		Profiles: map[string]config.ACPProfile{"default": {
			Mode: "action", AllowedClients: []string{"zed"}, AllowedAgents: []string{"kiro"},
		}},
	}}
}

func evaluateACPFrame(t *testing.T, api *APIServer, direction acp.Direction, surface acp.Surface, method, frame string) acp.Verdict {
	t.Helper()
	body, err := json.Marshal(acp.Evaluation{
		Profile: "default", Mode: acp.ModeAction, AgentID: "kiro", ClientID: "zed",
		Direction: direction, Surface: surface, Method: method, Payload: json.RawMessage(frame),
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	api.handleACPEvaluate(response, httptest.NewRequest(http.MethodPost, "/api/v1/acp/evaluate", bytes.NewReader(body)))
	var verdict acp.Verdict
	if err := json.Unmarshal(response.Body.Bytes(), &verdict); err != nil || verdict.Action != "block" {
		t.Fatalf("status=%d verdict=%+v err=%v, want block", response.Code, verdict, err)
	}
	return verdict
}

// An ACP block reaches the editor in the hook connectors' wording, not as the
// raw "matched: ID:title" text (GAP-1793), and is recorded as an
// apply_guardrail span under an "invoke_agent kiro" span that names the ACP
// session and the user, so Galileo, which has no guardrail span shape, sees
// it too (GAP-1836, GAP-1946).
func TestACPEvaluateBlockUsesAgentWordingAndEmitsGuardrailSpan(t *testing.T) {
	resetConnectorRuleCategories(t)
	api, capture := bindHookModelV8Runtime(t, []string{"traces"})
	api.scannerCfg = acpWordingTestConfig()
	frame := `{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"sess-acp-1",` +
		`"prompt":[{"type":"text","text":"Run echo ` + codexHighEntropyAWSKey() + ` > key.txt"}]}}`
	verdict := evaluateACPFrame(t, api, acp.ClientToAgent, acp.SurfacePrompt, "session/prompt", frame)
	if !strings.HasPrefix(verdict.Reason, "DefenseClaw policy blocked this action (") ||
		!strings.Contains(verdict.Reason, "rule SEC-AWS-KEY: AWS access key") ||
		!strings.HasSuffix(verdict.Reason, agentBlockNoRetry) || strings.Contains(verdict.Reason, "matched:") {
		t.Fatalf("ACP block reason = %q, want the hook connectors' wording", verdict.Reason)
	}

	var guard, agent *tracepb.Span
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline) && (guard == nil || agent == nil); time.Sleep(10 * time.Millisecond) {
		traces, _ := capture.snapshot()
		for _, span := range hookModelV8CapturedSpans(traces) {
			attributes := inspectTraceV8ProtoAttributes(span.Attributes)
			switch {
			case strings.HasPrefix(span.Name, "apply_guardrail") && attributes["defenseclaw.guardrail.decision"] == "block" &&
				attributes["defenseclaw.guardrail.target_type"] == "prompt":
				guard = span
			case span.Name == "invoke_agent kiro":
				agent = span
			}
		}
	}
	if guard == nil || agent == nil {
		t.Fatalf("ACP block spans: apply_guardrail=%v invoke_agent=%v, want both", guard != nil, agent != nil)
	}
	if !bytes.Equal(guard.ParentSpanId, agent.SpanId) || !bytes.Equal(guard.TraceId, agent.TraceId) {
		t.Fatalf("apply_guardrail parent=%s, want the invoke_agent span %s",
			hex.EncodeToString(guard.ParentSpanId), hex.EncodeToString(agent.SpanId))
	}
	attributes := inspectTraceV8ProtoAttributes(agent.Attributes)
	if attributes["defenseclaw.outcome"] != "blocked" || attributes["gen_ai.conversation.id"] != "sess-acp-1" {
		t.Fatalf("invoke_agent outcome=%q conversation=%q, want blocked and the ACP session",
			attributes["defenseclaw.outcome"], attributes["gen_ai.conversation.id"])
	}
	// GAP-2332: the agent span Galileo ingests names the rule of the block.
	if attributes["defenseclaw.guardrail.action"] != "block" || attributes["defenseclaw.guardrail.rule_id"] != "SEC-AWS-KEY" ||
		attributes["defenseclaw.guardrail.severity"] == "" {
		t.Fatalf("invoke_agent guardrail=%q/%q/%q, want block, SEC-AWS-KEY and a severity",
			attributes["defenseclaw.guardrail.action"], attributes["defenseclaw.guardrail.rule_id"],
			attributes["defenseclaw.guardrail.severity"])
	}
	if user := useridentity.Current(); user.ID != "" && attributes["user.id"] != user.ID {
		t.Fatalf("invoke_agent user.id=%q, want the gateway's user %q", attributes["user.id"], user.ID)
	}
}

// A block of the agent's own output (a session/update the agent sends after
// its tool has run) says the output was withheld and the step may have run,
// not that the action was blocked (GAP-1956).
func TestACPEvaluateOutputBlockSaysOutputWasWithheld(t *testing.T) {
	resetConnectorRuleCategories(t)
	api := &APIServer{scannerCfg: acpWordingTestConfig()}
	frame := `{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{` +
		`"sessionUpdate":"tool_call","toolCallId":"t1","title":"echo ` + codexHighEntropyAWSKey() + ` > key.txt"}}}`
	verdict := evaluateACPFrame(t, api, acp.AgentToClient, acp.SurfaceOutput, "session/update", frame)
	if !strings.HasPrefix(verdict.Reason, "DefenseClaw policy withheld agent output (") ||
		!strings.Contains(verdict.Reason, "rule SEC-AWS-KEY: AWS access key") ||
		!strings.HasSuffix(verdict.Reason, "The agent may already have run the step; check its effects.") ||
		strings.Contains(verdict.Reason, "blocked this action") {
		t.Fatalf("ACP output block reason = %q, want the withheld-output wording", verdict.Reason)
	}

	for in, want := range map[string]string{
		"DefenseClaw blocked this action under your organization's policy (rule X-1: t (a)). " + agentBlockNoRetry +
			" Contact your administrator if you need it allowed.": "DefenseClaw withheld agent output under your organization's policy " +
			"(rule X-1: t (a)). The agent may already have run the step; check its effects.",
		"DefenseClaw could not check this step.": "DefenseClaw could not check this step.",
	} {
		if got := acpWithheldOutputReason(in); got != want {
			t.Fatalf("acpWithheldOutputReason(%q) = %q, want %q", in, got, want)
		}
	}
}

// The verdict row names a rule-pack rule by its own ID, as the hook rows and
// the span do, not as "UNKNOWN-<id>" (GAP-1946).
func TestACPEvaluateVerdictRowKeepsRulePackRuleID(t *testing.T) {
	resetConnectorRuleCategories(t)
	ruleCategoriesMu.Lock()
	allRuleCategories = []ruleCategory{{
		Name: "secrets",
		Rules: []PatternRule{{
			ID: "CERT-S3-PROMPT-MARKER", Pattern: regexp.MustCompile(`\bdccert-prompt-marker\b`),
			Title: "Certification marker prompt", Severity: "CRITICAL", Confidence: 0.95,
		}},
	}}
	allRuleGeneration = nil
	ruleCategoriesMu.Unlock()
	api, capture := newGuardrailEventV8TestAPI(t)
	api.scannerCfg = acpWordingTestConfig()
	frame := `{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"sess-acp-2",` +
		`"prompt":[{"type":"text","text":"Reply with exactly dccert-prompt-marker"}]}}`
	evaluateACPFrame(t, api, acp.ClientToAgent, acp.SurfacePrompt, "session/prompt", frame)

	events := readStoredGuardrailEventsV8(t, capture.store.DatabasePath())
	if len(events) != 1 {
		t.Fatalf("stored verdict rows = %d, want 1", len(events))
	}
	rendered := fmt.Sprint(events[0].Body["defenseclaw.guardrail.rule_ids"])
	if rendered != "[CERT-S3-PROMPT-MARKER]" {
		t.Fatalf("ACP verdict rule_ids = %s, want [CERT-S3-PROMPT-MARKER]", rendered)
	}
	if events[0].Correlation.SessionID != "sess-acp-2" || events[0].Correlation.TraceID == "" {
		t.Fatalf("ACP verdict session_id=%q trace_id=%q, want the ACP session and the decision's trace",
			events[0].Correlation.SessionID, events[0].Correlation.TraceID)
	}
}
