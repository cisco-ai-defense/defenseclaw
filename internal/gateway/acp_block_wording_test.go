// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/config"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// An ACP block reaches the editor in the hook connectors' wording, not as the
// raw "matched: ID:title" text (GAP-1793), and is recorded as an
// apply_guardrail span like a hook decision (GAP-1836).
func TestACPEvaluateBlockUsesAgentWordingAndEmitsGuardrailSpan(t *testing.T) {
	resetConnectorRuleCategories(t)
	api, capture := bindHookModelV8Runtime(t, []string{"traces"})
	api.scannerCfg = &config.Config{ACP: config.ACPConfig{
		Enabled: true, Mode: "action", DefaultProfile: "default",
		Clients: map[string]config.ACPBinding{"zed": {Enabled: true, Profile: "default"}},
		Agents:  map[string]config.ACPBinding{"kiro": {Enabled: true, Profile: "default"}},
		Profiles: map[string]config.ACPProfile{"default": {
			Mode: "action", AllowedClients: []string{"zed"}, AllowedAgents: []string{"kiro"},
		}},
	}}
	frame := `{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"s",` +
		`"prompt":[{"type":"text","text":"Run echo ` + codexHighEntropyAWSKey() + ` > key.txt"}]}}`
	body, err := json.Marshal(acp.Evaluation{
		Profile: "default", Mode: acp.ModeAction, AgentID: "kiro", ClientID: "zed",
		Direction: acp.ClientToAgent, Surface: acp.SurfacePrompt, Method: "session/prompt",
		Payload: json.RawMessage(frame),
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
	if !strings.HasPrefix(verdict.Reason, "DefenseClaw policy blocked this action (") ||
		!strings.Contains(verdict.Reason, "rule SEC-AWS-KEY: AWS access key") ||
		!strings.HasSuffix(verdict.Reason, agentBlockNoRetry) || strings.Contains(verdict.Reason, "matched:") {
		t.Fatalf("ACP block reason = %q, want the hook connectors' wording", verdict.Reason)
	}

	var spans []*tracepb.Span
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		traces, _ := capture.snapshot()
		if spans = hookModelV8CapturedSpans(traces); len(spans) > 0 {
			break
		}
	}
	for _, span := range spans {
		attributes := inspectTraceV8ProtoAttributes(span.Attributes)
		if strings.HasPrefix(span.Name, "apply_guardrail") && attributes["defenseclaw.guardrail.decision"] == "block" &&
			attributes["defenseclaw.guardrail.target_type"] == "prompt" {
			return
		}
	}
	t.Fatalf("ACP block produced no apply_guardrail block span: %d spans", len(spans))
}
