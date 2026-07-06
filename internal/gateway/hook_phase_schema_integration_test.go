// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// TestHookPhaseTelemetryRealFixturesThroughSchemaAndAudit is the regression
// gate for WIN-AUD-043. It deliberately starts each connector with its real
// live-E2E PreToolUse fixture: before the fix, enrichHookPhase assigned the
// sentinel "unknown" to agent_previous_phase, and the strict runtime schema
// gate dropped the lifecycle and tool_invocation events.
func TestHookPhaseTelemetryRealFixturesThroughSchemaAndAudit(t *testing.T) {
	for _, connectorName := range []string{"codex", "claudecode"} {
		connectorName := connectorName
		t.Run(connectorName, func(t *testing.T) {
			fixturePath := filepath.Join("..", "..", "scripts", "live-connector-e2e", "golden", connectorName, "pre_tool_allow.json")
			body, err := os.ReadFile(fixturePath)
			if err != nil {
				t.Fatalf("read live connector fixture: %v", err)
			}
			var fixture map[string]interface{}
			if err := json.Unmarshal(body, &fixture); err != nil {
				t.Fatalf("decode live connector fixture: %v", err)
			}

			store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
			if err != nil {
				t.Fatalf("audit.NewStore: %v", err)
			}
			t.Cleanup(func() { _ = store.Close() })
			if err := store.Init(); err != nil {
				t.Fatalf("store.Init: %v", err)
			}

			validator, err := gatewaylog.NewDefaultValidator()
			if err != nil {
				t.Fatalf("gatewaylog.NewDefaultValidator: %v", err)
			}
			gatewayJSONL := filepath.Join(t.TempDir(), "gateway.jsonl")
			writer, err := gatewaylog.New(gatewaylog.Config{JSONLPath: gatewayJSONL, Validator: validator})
			if err != nil {
				t.Fatalf("gatewaylog.New: %v", err)
			}
			t.Cleanup(func() { _ = writer.Close() })
			var gatewayEvents []gatewaylog.Event
			writer.WithFanout(func(event gatewaylog.Event) {
				gatewayEvents = append(gatewayEvents, event)
			})
			SetEventWriter(writer)
			t.Cleanup(func() { SetEventWriter(nil) })

			logger := audit.NewLogger(store)
			logger.SetStructuredEmitter(newAuditBridge(writer))
			t.Cleanup(func() { logger.Close() })
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connectorName
			api := &APIServer{scannerCfg: cfg, store: store, logger: logger}

			requestID := "request-win-aud-043-" + connectorName
			ctx := audit.ContextWithEnvelope(context.Background(), audit.CorrelationEnvelope{
				RunID:     "run-win-aud-043",
				RequestID: requestID,
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connectorName+"/hook", bytes.NewReader(body)).WithContext(ctx)
			req.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			api.handleAgentHook(connectorName).ServeHTTP(response, req)

			if response.Code != http.StatusOK {
				t.Fatalf("hook status=%d body=%s", response.Code, response.Body.String())
			}
			var hookResponse map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &hookResponse); err != nil {
				t.Fatalf("decode hook response: %v", err)
			}
			if got := hookResponse["action"]; got != "allow" {
				t.Fatalf("hook action=%v want allow; telemetry fix must not change enforcement", got)
			}
			if got := writer.SchemaViolationsCount(); got != 0 {
				t.Fatalf("schema violations=%d want 0; events=%+v", got, gatewayEvents)
			}
			persistedJSONL, err := os.ReadFile(gatewayJSONL)
			if err != nil {
				t.Fatalf("read persisted gateway JSONL: %v", err)
			}
			persistedTypes := map[gatewaylog.EventType]bool{}
			for _, line := range bytes.Split(persistedJSONL, []byte{'\n'}) {
				if len(bytes.TrimSpace(line)) == 0 {
					continue
				}
				if err := validator.ValidateBytes(line); err != nil {
					t.Fatalf("persisted gateway event failed runtime schema: %v\n%s", err, line)
				}
				var event gatewaylog.Event
				if err := json.Unmarshal(line, &event); err != nil {
					t.Fatalf("decode persisted gateway event: %v", err)
				}
				if event.AgentLifecycleEvent == "tool_start" || event.EventType == gatewaylog.EventHookDecision {
					persistedTypes[event.EventType] = true
				}
			}
			for _, eventType := range []gatewaylog.EventType{gatewaylog.EventLifecycle, gatewaylog.EventToolInvocation, gatewaylog.EventHookDecision} {
				if !persistedTypes[eventType] {
					t.Errorf("%s did not persist to gateway JSONL", eventType)
				}
			}

			var lifecycle, toolInvocation, hookDecision *gatewaylog.Event
			for i := range gatewayEvents {
				event := &gatewayEvents[i]
				switch {
				case event.EventType == gatewaylog.EventLifecycle && event.AgentLifecycleEvent == "tool_start":
					lifecycle = event
				case event.EventType == gatewaylog.EventToolInvocation && event.Tool != nil && event.Tool.Phase == "call":
					toolInvocation = event
				case event.EventType == gatewaylog.EventHookDecision:
					hookDecision = event
				}
			}
			for name, event := range map[string]*gatewaylog.Event{
				"lifecycle": lifecycle, "tool_invocation": toolInvocation, "hook_decision": hookDecision,
			} {
				if event == nil {
					t.Fatalf("missing %s event after runtime schema gate; events=%+v", name, gatewayEvents)
				}
				if event.Timestamp.IsZero() || event.Connector != connectorName || event.SessionID != fixture["session_id"] || event.RequestID != requestID {
					t.Errorf("%s correlation mismatch: %+v", name, event)
				}
				if event.AgentPhase != "tool" || event.AgentPreviousPhase != "" || event.AgentSequence != 1 {
					t.Errorf("%s phase=(%q,%q,%d), want (tool, omitted, 1)", name, event.AgentPhase, event.AgentPreviousPhase, event.AgentSequence)
				}
				if event.AgentLifecycleID == "" || event.AgentExecutionID == "" || event.AgentOperationID == "" {
					t.Errorf("%s missing agent correlation IDs: %+v", name, event)
				}
			}
			if hookDecision.HookDecision == nil || hookDecision.HookDecision.Action != "allow" || hookDecision.HookDecision.Enforced {
				t.Errorf("hook decision attribution changed: %+v", hookDecision.HookDecision)
			}

			auditEvents, err := store.ListEvents(20)
			if err != nil {
				t.Fatalf("store.ListEvents: %v", err)
			}
			var auditRow *audit.Event
			for i := range auditEvents {
				if auditEvents[i].Action == string(audit.ActionConnectorHook) {
					auditRow = &auditEvents[i]
					break
				}
			}
			if auditRow == nil {
				t.Fatalf("no connector-hook audit row persisted: %+v", auditEvents)
			}
			if auditRow.Timestamp.IsZero() || auditRow.RequestID != requestID || auditRow.SessionID != fixture["session_id"] || auditRow.Connector != connectorName {
				t.Errorf("audit correlation mismatch: %+v", auditRow)
			}
			if auditRow.Structured["action"] != "allow" || auditRow.Structured["event"] != "PreToolUse" {
				t.Errorf("audit decision attribution mismatch: %#v", auditRow.Structured)
			}
			if auditRow.Structured["agent_phase"] != "tool" {
				t.Errorf("audit phase=%#v want tool: %#v", auditRow.Structured["agent_phase"], auditRow.Structured)
			}
			if _, exists := auditRow.Structured["agent_previous_phase"]; exists {
				t.Errorf("first-event audit row must omit previous phase: %#v", auditRow.Structured)
			}
		})
	}
}
