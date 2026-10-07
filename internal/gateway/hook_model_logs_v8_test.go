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

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/proto"
)

func TestHookModelLogsV8RouteRichUnredactedRequestAndResponseWithoutGatewayJSONL(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs"})
	meta := richHookModelV8Meta()
	const prompt = "contact private.person@example.com"
	const response = "response for private.person@example.com"
	for _, producer := range []struct {
		key   gatewaylog.EventType
		event string
	}{
		{gatewaylog.EventLLMPrompt, observability.TelemetryEventModelRequest},
		{gatewaylog.EventLLMResponse, observability.TelemetryEventModelResponse},
	} {
		if _, err := router.NewClassifiedLogMetadata(
			observability.ProducerGatewayEvent, observability.ProducerKey(producer.key),
			observability.ClassificationContext{
				Bucket: observability.BucketModelIO, EventName: observability.EventName(producer.event), RawSeverity: "INFO",
			},
			observability.SourceConnector, "codex", observability.ProducerKey(producer.key),
		); err != nil {
			t.Fatalf("model log metadata %s: %v", producer.event, err)
		}
	}
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return "model-log-test", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	envelope := observability.FamilyEnvelopeInput{
		Source: observability.SourceConnector, Connector: "codex", Action: "model.request", Phase: "model",
		Provenance: observability.FamilyProvenanceInput{
			Producer: "gateway.hook.model", BinaryVersion: "test", ConfigGeneration: 1,
			ConfigDigest: "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	if _, err := buildHookModelRequestLogRecord(t.Context(), builder, envelope, llmEventMeta{}, prompt); err != nil {
		t.Fatalf("build model request: %v", err)
	}
	envelope.Action = "model.response"
	if _, err := buildHookModelResponseLogRecord(t.Context(), builder, envelope, llmEventMeta{}, response, []string{"stop"}); err != nil {
		t.Fatalf("build model response: %v", err)
	}
	api.emitLLMPromptEventV8(t.Context(), meta, prompt, nil)
	api.emitLLMResponseEventV8(t.Context(), meta, response, "", []string{"stop"})

	var eventNames = map[string]bool{}
	var wire []byte
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		requests := capture.logSnapshot()
		eventNames = map[string]bool{}
		wire = wire[:0]
		for _, request := range requests {
			encoded, err := proto.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			wire = append(wire, encoded...)
			for _, resource := range request.GetResourceLogs() {
				for _, scope := range resource.GetScopeLogs() {
					for _, record := range scope.GetLogRecords() {
						eventNames[logStringAttribute(record.GetAttributes(), "defenseclaw.event.name")] = true
					}
				}
			}
		}
		if eventNames[observability.TelemetryEventModelRequest] &&
			eventNames[observability.TelemetryEventModelResponse] {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !eventNames[observability.TelemetryEventModelRequest] ||
		!eventNames[observability.TelemetryEventModelResponse] {
		t.Fatalf("canonical model log events=%v", eventNames)
	}
	if !bytes.Contains(wire, []byte(prompt)) || !bytes.Contains(wire, []byte(response)) {
		t.Fatal("default redaction_profile none did not preserve model log content")
	}
}

// GAP-0070: a sandboxed session's model and agent lifecycle logs carry the
// sandbox binding and the agent identity, so they join its hook decisions;
// so do its tool_start and tool_end lifecycle logs (GAP-0202).
func TestHookModelAndLifecycleLogsV8CarrySandboxAndAgentIdentity(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs"})
	ctx := audit.ContextWithEnvelope(t.Context(), audit.CorrelationEnvelope{
		SandboxID: "0f5b3c2e-9d4a-4f61-8a7e-2c1b0d9e6f33", SandboxName: "dc-codex-app-0a1b",
	})
	meta := richHookModelV8Meta()
	meta.AgentIdentityID = "agt-0123456789abcdef"
	api.emitLLMPromptEventV8(ctx, meta, "sandboxed prompt", nil)
	if got := api.emitHookLifecycleEvent(ctx, meta); got != hookLifecycleV8Persisted {
		t.Fatalf("lifecycle emission = %d, want persisted", got)
	}
	toolStart := meta
	toolStart.LifecycleEvent, toolStart.LifecycleState, toolStart.ToolName, toolStart.ToolID =
		observability.TelemetryEventToolStart, "running", "Bash", "call-1"
	if got := api.emitHookLifecycleEvent(ctx, toolStart); got != hookLifecycleV8Persisted {
		t.Fatalf("tool_start emission = %d, want persisted", got)
	}
	eventuallyTrue(t, func() bool { return len(hookModelV8CapturedLogs(capture.logSnapshot())) >= 3 })
	seen := map[string]bool{}
	for _, record := range hookModelV8CapturedLogs(capture.logSnapshot()) {
		var wire struct {
			Body map[string]any `json:"body"`
		}
		name := logStringAttribute(record.GetAttributes(), "defenseclaw.event.name")
		if err := json.Unmarshal([]byte(record.GetBody().GetStringValue()), &wire); err != nil {
			t.Fatalf("%s body: %v", name, err)
		}
		if wire.Body["defenseclaw.sandbox.id"] != "0f5b3c2e-9d4a-4f61-8a7e-2c1b0d9e6f33" ||
			wire.Body["defenseclaw.sandbox.name"] != "dc-codex-app-0a1b" ||
			wire.Body["defenseclaw.agent.identity.id"] != "agt-0123456789abcdef" {
			t.Errorf("%s body = %v, want the sandbox id, name and agent identity", name, wire.Body)
		}
		seen[name] = true
	}
	if !seen[observability.TelemetryEventModelRequest] || !seen[observability.TelemetryEventTurnEnd] ||
		!seen[observability.TelemetryEventToolStart] {
		t.Fatalf("captured log events = %v, want model.request, turn_end and tool_start", seen)
	}
}

// GAP-0158: the runtime the gateway runs reads the signed lifecycle history,
// so a hook after a restart restores its session's lineage instead of
// skipping the restore.
func TestHookLifecycleHistoryReadsThroughTheGatewayRuntime(t *testing.T) {
	api, _ := bindHookModelV8Runtime(t, []string{"logs"})
	meta := richHookModelV8Meta()
	if got := api.emitHookLifecycleEvent(t.Context(), meta); got != hookLifecycleV8Persisted {
		t.Fatalf("lifecycle emission = %d, want persisted", got)
	}
	history, ok := api.observabilityV8RuntimeEmitter().(hookLifecycleHistoryRuntime)
	if !ok {
		t.Fatalf("gateway runtime %T reads no lifecycle history", api.observabilityV8RuntimeEmitter())
	}
	projection, found, err := history.LatestLifecycleProjection(t.Context(), audit.LifecycleProjectionQuery{
		Connector: meta.Source, SessionID: meta.SessionID, AgentID: meta.AgentID,
	})
	if err != nil || !found || projection.ParentAgentID != meta.ParentAgentID || projection.Depth != meta.AgentDepth {
		t.Fatalf("lifecycle history = %+v found=%t err=%v, want the parent link", projection, found, err)
	}
}

func TestCodexNotifyEmitsCanonicalV8ModelLogsWithSourceFacts(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs"})
	const body = `{
		"type":"agent-turn-complete",
		"thread-id":"thread-123",
		"turn-id":"turn-abc",
		"model":"gpt-5",
		"input-messages":["first prompt","contact notify.person@example.com"],
		"last-assistant-message":"notify response for notify.person@example.com",
		"finish-reason":"stop"
	}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/codex/notify", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.handleCodexNotify(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("notify status=%d body=%q", response.Code, response.Body.String())
	}

	deadline := time.Now().Add(3 * time.Second)
	var wire []byte
	var names map[string]bool
	for time.Now().Before(deadline) {
		wire, names = capturedModelLogWire(t, capture)
		if names[observability.TelemetryEventModelRequest] && names[observability.TelemetryEventModelResponse] {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !names[observability.TelemetryEventModelRequest] || !names[observability.TelemetryEventModelResponse] {
		t.Fatalf("notify canonical model log events=%v", names)
	}
	for _, fact := range []string{
		"thread-123", "turn-abc", "gpt-5", "contact notify.person@example.com",
		"notify response for notify.person@example.com",
	} {
		if !bytes.Contains(wire, []byte(fact)) {
			t.Fatalf("notify canonical logs missing source fact %q", fact)
		}
	}
}

// GAP-0203: the notify webhook is no hook, so its model logs join the agent
// identity and instance the session was seen under on the hook path.
func TestCodexNotifyModelLogsJoinTheHookSessionIdentity(t *testing.T) {
	const identityID = "agt-0123456789abcdef"
	sharedRegMu.Lock()
	previous := sharedReg
	sharedReg = NewAgentRegistry("", "")
	registry := sharedReg
	sharedRegMu.Unlock()
	t.Cleanup(func() {
		sharedRegMu.Lock()
		sharedReg = previous
		sharedRegMu.Unlock()
	})
	hook, _ := registry.ResolveForAgentIdentity(t.Context(), identityID, "thread-join", "")
	if hook.AgentInstanceID == "" {
		t.Fatal("the hook path minted no agent instance")
	}
	api, capture := bindHookModelV8Runtime(t, []string{"logs"})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/codex/notify", strings.NewReader(
		`{"type":"agent-turn-complete","thread-id":"thread-join","turn-id":"turn-join","model":"gpt-5","input-messages":["hello"],"last-assistant-message":"hi"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.handleCodexNotify(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("notify status=%d", response.Code)
	}
	eventuallyTrue(t, func() bool {
		_, names := capturedModelLogWire(t, capture)
		return names[observability.TelemetryEventModelRequest] && names[observability.TelemetryEventModelResponse]
	})
	wire, _ := capturedModelLogWire(t, capture)
	for _, want := range []string{identityID, hook.AgentInstanceID} {
		if !bytes.Contains(wire, []byte(want)) {
			t.Fatalf("notify model logs do not carry %q", want)
		}
	}
}

func TestClaudeMessageDisplayPreservesReportedV8ResponseIdentity(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs"})
	api.emitClaudeCodeHookLLMEvent(t.Context(), claudeCodeHookRequest{
		HookEventName: "MessageDisplay", SessionID: "claude-session", TurnID: "claude-turn",
		MessageID: "msg-provider-123", Model: "claude-sonnet-4", Delta: "reported response",
		DisplayFinal: true,
	}, nil, []byte(`{"message_id":"msg-provider-123"}`))

	var bodyAttributes map[string]interface{}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, record := range hookModelV8CapturedLogs(capture.logSnapshot()) {
			if logStringAttribute(record.Attributes, "defenseclaw.event.name") == observability.TelemetryEventModelResponse {
				var wire struct {
					Body map[string]interface{} `json:"body"`
				}
				if err := json.Unmarshal([]byte(record.Body.GetStringValue()), &wire); err != nil {
					t.Fatal(err)
				}
				bodyAttributes = wire.Body
				break
			}
		}
		if len(bodyAttributes) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := bodyAttributes["gen_ai.response.id"]; got != "msg-provider-123" {
		t.Fatalf("reported Claude response ID=%q", got)
	}
	if got := bodyAttributes["gen_ai.response.model"]; got != "claude-sonnet-4" {
		t.Fatalf("reported Claude response model=%q", got)
	}
	if got := bodyAttributes["defenseclaw.model.response.id"]; got != "msg-provider-123" {
		t.Fatalf("internal Claude response ID=%q", got)
	}
}

func capturedModelLogWire(t *testing.T, capture *hookModelV8OTLPCapture) ([]byte, map[string]bool) {
	t.Helper()
	var wire []byte
	names := make(map[string]bool)
	for _, request := range capture.logSnapshot() {
		encoded, err := proto.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		wire = append(wire, encoded...)
		for _, resource := range request.GetResourceLogs() {
			for _, scope := range resource.GetScopeLogs() {
				for _, record := range scope.GetLogRecords() {
					names[logStringAttribute(record.GetAttributes(), "defenseclaw.event.name")] = true
				}
			}
		}
	}
	return wire, names
}

func logStringAttribute(attributes []*commonpb.KeyValue, key string) string {
	for _, attribute := range attributes {
		if attribute.GetKey() == key {
			return attribute.GetValue().GetStringValue()
		}
	}
	return ""
}
