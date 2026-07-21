// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	if _, err := buildHookModelRequestLogRecord(builder, envelope, llmEventMeta{}, prompt); err != nil {
		t.Fatalf("build model request: %v", err)
	}
	envelope.Action = "model.response"
	if _, err := buildHookModelResponseLogRecord(builder, envelope, llmEventMeta{}, response, []string{"stop"}); err != nil {
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
