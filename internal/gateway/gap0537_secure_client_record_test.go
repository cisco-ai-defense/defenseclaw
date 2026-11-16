package gateway

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestGAP0537SecureClientHookDecisionRecordUnchanged(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs"})
	api.scannerCfg = &config.Config{DeploymentMode: "managed_enterprise"}
	if !api.scannerCfg.SecureClientIntegration() {
		t.Fatal("review fixture is not Secure Client")
	}
	gap0537Registry(t)
	previous := ManagedEnterpriseActive()
	SetManagedEnterpriseActive(true)
	t.Cleanup(func() { SetManagedEnterpriseActive(previous) })
	req := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse", SessionID: "sc-review-session", AgentID: "agent-reported"}
	ctx := enrichAgentHookContext(context.Background(), req)
	if id := audit.EnvelopeFromContext(ctx).AgentInstanceID; id == "" {
		t.Fatal("Secure Client instance absent from existing audit correlation")
	}
	resp := agentHookResponse{Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action"}
	if got := api.emitHookDecisionObservabilityV8(ctx, req, resp, HookAuditEnvelope{ElapsedMs: 1}, false); got != hookDecisionLogPersisted {
		t.Fatalf("decision result=%v", got)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		logs := hookModelV8CapturedLogs(capture.logSnapshot())
		if len(logs) != 0 {
			var wire struct {
				Body map[string]any `json:"body"`
			}
			if err := json.Unmarshal([]byte(logs[0].GetBody().GetStringValue()), &wire); err != nil {
				t.Fatal(err)
			}
			if _, present := wire.Body["defenseclaw.agent.instance_id"]; present {
				t.Fatal("Secure Client hook decision record gained instance field")
			}
			if got := wire.Body["defenseclaw.guardrail.effective_action"]; got != "allow" {
				t.Fatalf("Secure Client action=%v, want allow", got)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Secure Client decision log missing")
}
