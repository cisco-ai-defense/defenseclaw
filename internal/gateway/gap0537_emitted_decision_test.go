package gateway

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// The emitted decision uses the instance already verified for its paired
// connector audit row. A call with no verified instance stays
// an allowed decision without an invented identity.
func TestGAP0537DecisionRecordCarriesAuditInstance(t *testing.T) {
	for _, tc := range []struct {
		name, instance string
	}{
		{name: "verified", instance: "ais-verified"},
		{name: "benign without instance"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api, capture := bindHookModelV8Runtime(t, []string{"logs"})
			ctx := audit.ContextWithEnvelope(context.Background(), audit.CorrelationEnvelope{
				AgentID: "agent-root", AgentInstanceID: tc.instance, SessionID: "session-one",
			})
			req := agentHookRequest{ConnectorName: "hermes", HookEventName: "pre_tool_call", AgentID: "agent-root", SessionID: "session-one"}
			resp := agentHookResponse{Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action"}
			if result := api.emitHookDecisionObservabilityV8(ctx, req, resp, HookAuditEnvelope{ElapsedMs: 1}, false); result != hookDecisionLogPersisted {
				t.Fatalf("decision result=%v, want persisted", result)
			}
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				logs := hookModelV8CapturedLogs(capture.logSnapshot())
				if len(logs) != 0 {
					var wire struct {
						Body map[string]any `json:"body"`
					}
					if err := json.Unmarshal([]byte(logs[0].GetBody().GetStringValue()), &wire); err != nil {
						t.Fatalf("decision body: %v", err)
					}
					if got := wire.Body["defenseclaw.guardrail.effective_action"]; got != "allow" {
						t.Fatalf("decision action=%v, want allow", got)
					}
					got, present := wire.Body["defenseclaw.agent.instance_id"]
					if tc.instance == "" && present || tc.instance != "" && got != tc.instance {
						t.Fatalf("decision instance=%v present=%t, want %q", got, present, tc.instance)
					}
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatal("exported decision log missing")
		})
	}
}

func TestReviewHermesEmittedDecisionRecordMatchesAudit(t *testing.T) {
	peer := reviewHermesPeer(t)
	api, capture := bindHookModelV8Runtime(t, []string{"logs"})
	first := agentHookRequest{ConnectorName: "hermes", HookEventName: "pre_llm_call", SessionID: "session-one", AgentID: "agent-root"}
	firstCtx := enrichAgentHookContext(peer, first)
	transform := agentHookRequest{ConnectorName: "hermes", HookEventName: "transform_terminal_output", Payload: map[string]interface{}{}, AgentIdentityID: AgentIdentityFromContext(firstCtx).IdentityID}
	api.hermesTasks.fill(&transform)
	ctx := enrichAgentHookContext(peer, transform)
	auditEnvelope := audit.EnvelopeFromContext(ctx)
	if auditEnvelope.AgentID == "" || auditEnvelope.AgentInstanceID == "" {
		t.Fatalf("connector audit correlation missing: agent=%q instance=%q", auditEnvelope.AgentID, auditEnvelope.AgentInstanceID)
	}
	response := agentHookResponse{Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action"}
	result := api.emitHookDecisionObservabilityV8(ctx, transform, response, HookAuditEnvelope{ElapsedMs: 1}, false)
	if result != hookDecisionLogPersisted {
		t.Fatalf("hook decision result=%v, want persisted", result)
	}
	deadline := time.Now().Add(3 * time.Second)
	var logsCount int
	for time.Now().Before(deadline) {
		logs := hookModelV8CapturedLogs(capture.logSnapshot())
		logsCount = len(logs)
		if logsCount > 0 {
			var wire struct {
				Body map[string]any `json:"body"`
			}
			if err := json.Unmarshal([]byte(logs[0].GetBody().GetStringValue()), &wire); err != nil {
				t.Fatalf("hook decision body: %v", err)
			}
			for key, want := range map[string]string{
				"gen_ai.agent.id":               auditEnvelope.AgentID,
				"gen_ai.conversation.id":        auditEnvelope.SessionID,
				"defenseclaw.agent.instance_id": auditEnvelope.AgentInstanceID,
			} {
				if got := wire.Body[key]; got != want {
					t.Errorf("decision %s=%q, connector audit=%q", key, got, want)
				}
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("exported hook decision logs=%d, want one", logsCount)
}
