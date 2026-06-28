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

package telemetry

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

type stubSpanExporter struct{ err error }

func (s stubSpanExporter) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error { return s.err }
func (s stubSpanExporter) Shutdown(context.Context) error                             { return nil }

type canaryRejectingSpanExporter struct {
	calls [][]sdktrace.ReadOnlySpan
}

func (e *canaryRejectingSpanExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	e.calls = append(e.calls, append([]sdktrace.ReadOnlySpan(nil), spans...))
	if len(spans) > 0 && isCanarySpan(spans[0]) {
		return errors.New("OTLP partial success: canary rejected (2 spans rejected)")
	}
	return nil
}

func (*canaryRejectingSpanExporter) Shutdown(context.Context) error { return nil }

func disabledCfg() *config.Config {
	return &config.Config{
		OTel: config.OTelConfig{
			Enabled: false,
		},
		Claw: config.ClawConfig{
			Mode:    config.ClawOpenClaw,
			HomeDir: "/tmp/test-claw",
		},
		Gateway: config.GatewayConfig{
			Host: "127.0.0.1",
			Port: 18789,
		},
		Environment: "test",
	}
}

func TestDestinationSpanExporterRecordsAcknowledgementFailureAndPartialSuccess(t *testing.T) {
	tests := []struct {
		name                                    string
		err                                     error
		wantDelivered, wantRejected, wantFailed uint64
	}{
		{name: "acknowledged", wantDelivered: 3},
		{name: "transport failure", err: errors.New("401 unauthorized"), wantFailed: 3},
		{name: "partial success", err: errors.New("OTLP partial success: invalid schema (2 spans rejected)"), wantDelivered: 1, wantRejected: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &Provider{}
			exporter := &destinationSpanExporter{
				next: stubSpanExporter{err: tt.err}, provider: provider, destination: "galileo",
			}
			spans := make([]sdktrace.ReadOnlySpan, 3)
			_ = exporter.ExportSpans(context.Background(), spans)
			got := provider.DestinationDeliveryStats("galileo")
			if got.Attempted != 3 || got.Delivered != tt.wantDelivered ||
				got.Rejected != tt.wantRejected || got.Failed != tt.wantFailed {
				t.Fatalf("delivery=%+v", got)
			}
			if tt.err == nil && (got.LastSuccessAt.IsZero() || got.LastError != "") {
				t.Fatalf("successful delivery metadata=%+v", got)
			}
			if tt.err != nil && got.LastError == "" {
				t.Fatalf("failed delivery missing last error: %+v", got)
			}
		})
	}
}

func TestDestinationSpanExporterCanaryAcknowledgementUsesExactTrace(t *testing.T) {
	span := func(traceID trace.TraceID, spanByte byte, canary bool) sdktrace.ReadOnlySpan {
		attrs := []attribute.KeyValue(nil)
		if canary {
			attrs = append(attrs, attribute.Bool(telemetryCanaryAttribute, true))
		}
		var spanID trace.SpanID
		spanID[0] = spanByte
		return tracetest.SpanStub{
			SpanContext: trace.NewSpanContext(trace.SpanContextConfig{
				TraceID: traceID, SpanID: spanID,
			}),
			Attributes: attrs,
		}.Snapshot()
	}
	var normalTraceID, canaryTraceID trace.TraceID
	normalTraceID[0] = 1
	canaryTraceID[0] = 2
	downstream := &canaryRejectingSpanExporter{}
	provider := &Provider{}
	exporter := &destinationSpanExporter{
		next: downstream, provider: provider, destination: "galileo",
	}

	err := exporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{
		span(normalTraceID, 1, false),
		span(canaryTraceID, 2, true),
		span(canaryTraceID, 3, true),
	})
	if err == nil {
		t.Fatal("expected canary partial-success error")
	}
	if len(downstream.calls) != 2 || len(downstream.calls[0]) != 1 || len(downstream.calls[1]) != 2 {
		t.Fatalf("export calls=%v want normal batch then isolated canary trace", downstream.calls)
	}
	if provider.DestinationAcknowledgedCanaryTrace("galileo", canaryTraceID.String()) {
		t.Fatal("rejected canary was corrupted by concurrent successful delivery")
	}
	stats := provider.DestinationDeliveryStats("galileo")
	if stats.Delivered != 1 || stats.Rejected != 2 || stats.ExportBatches != 2 {
		t.Fatalf("delivery=%+v want one normal delivery and two rejected canary spans", stats)
	}
}

func TestNewProvider_Disabled(t *testing.T) {
	p, err := NewProvider(context.Background(), disabledCfg(), "test")
	if err != nil {
		t.Fatalf("NewProvider disabled: %v", err)
	}
	if p.Enabled() {
		t.Error("expected disabled provider")
	}
	if p.LogsEnabled() {
		t.Error("expected logs disabled")
	}
	if p.TracesEnabled() {
		t.Error("expected traces disabled")
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("shutdown disabled: %v", err)
	}
}

func TestNewProvider_NilSafe(t *testing.T) {
	var p *Provider

	if p.Enabled() {
		t.Error("nil provider should not be enabled")
	}
	if p.LogsEnabled() {
		t.Error("nil provider logs should not be enabled")
	}
	if p.TracesEnabled() {
		t.Error("nil provider traces should not be enabled")
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("nil shutdown: %v", err)
	}
}

func TestDisabledProvider_EmitLifecycleEvent_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	p.EmitLifecycleEvent("block", "test-skill", "skill", "test reason", "HIGH", nil)
}

func TestDisabledProvider_EmitScanResult_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	result := &scanner.ScanResult{
		Scanner:   "test-scanner",
		Target:    "/tmp/test",
		Timestamp: time.Now(),
		Duration:  100 * time.Millisecond,
	}
	p.EmitScanResult(result, "scan-123", "skill", "clean", "codex")
}

func TestDisabledProvider_EmitRuntimeAlert_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	p.EmitRuntimeAlert(AlertDangerousCommand, "HIGH", SourceLocalPattern,
		"test alert", nil, nil, "", "")
}

func TestDisabledProvider_StartToolSpan_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	ctx, span := p.StartToolSpan(context.Background(), "shell", "running",
		json.RawMessage(`{"cmd":"ls"}`), false, "", "builtin", "",
		ToolSpanContext{})
	if span != nil {
		t.Error("span should be nil when disabled")
	}
	if ctx == nil {
		t.Error("context should not be nil")
	}
}

func TestStartToolSpan_RawArgsOnlyWhenRedactionDisabled(t *testing.T) {
	redaction.SetDisableAll(false)
	t.Cleanup(func() { redaction.SetDisableAll(false) })

	p, exp := newTracingProvider(t)
	_, span := p.StartToolSpan(context.Background(), "shell", "running",
		json.RawMessage(`{"secret":"abc123"}`), false, "", "builtin", "",
		ToolSpanContext{})
	p.EndToolSpan(span, 0, 0, time.Now(), "shell", "builtin")
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if _, ok := attrByKey(spans[0].Attributes, "defenseclaw.tool.args"); ok {
		t.Fatal("raw tool args were exported while redaction was enabled")
	}

	redaction.SetDisableAll(true)
	p, exp = newTracingProvider(t)
	_, span = p.StartToolSpan(context.Background(), "shell", "running",
		json.RawMessage(`{"secret":"abc123"}`), false, "", "builtin", "",
		ToolSpanContext{})
	p.EndToolSpan(span, 0, 0, time.Now(), "shell", "builtin")
	spans = exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d raw-mode spans, want 1", len(spans))
	}
	if got, ok := attrByKey(spans[0].Attributes, "defenseclaw.tool.args"); !ok || got.AsString() != `{"secret":"abc123"}` {
		t.Fatalf("raw tool args attr = %q ok=%v, want exact JSON", got.AsString(), ok)
	}
}

func TestStartToolSpan_EmitsSessionToolPolicyCorrelation(t *testing.T) {
	p, exp := newTracingProvider(t)
	attachTraceTestResourceContext(t, p)
	_, span := p.StartToolSpan(context.Background(), "shell", "running",
		json.RawMessage(`{"cmd":"rg -n observed_agent_session ."}`), false, "", "builtin", "",
		ToolSpanContext{
			ToolID:         "tool-123",
			SessionID:      "session-123",
			RunID:          "run-123",
			DestinationApp: "builtin",
			PolicyID:       "policy-allow-shell",
			AgentName:      "codex",
			AgentID:        "openai_codex",
		})
	p.EndToolSpan(span, 0, 0, time.Now(), "shell", "builtin")

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}

	for key, want := range map[string]string{
		"gen_ai.tool.call.id":         "tool-123",
		"gen_ai.conversation.id":      "session-123",
		"defenseclaw.run.id":          "run-123",
		"defenseclaw.destination.app": "builtin",
		"defenseclaw.policy.id":       "policy-allow-shell",
		"gen_ai.agent.name":           "codex",
		"gen_ai.agent.id":             "openai_codex",
		"gen_ai.operation.name":       "execute_tool",
		"gen_ai.tool.name":            "shell",
	} {
		got, ok := attrByKey(spans[0].Attributes, key)
		if !ok || got.AsString() != want {
			t.Fatalf("%s = %q ok=%v, want %q", key, got.AsString(), ok, want)
		}
	}
	assertMirroredResourceJoinKeys(t, spans[0].Attributes)
}

func TestStartAgentSpan_MirrorsResourceJoinKeysOntoSpan(t *testing.T) {
	p, exp := newTracingProvider(t)
	attachTraceTestResourceContext(t, p)

	_, span := p.StartAgentSpan(context.Background(), "session-123", "codex", "codex", "openai_codex", "openai", "codex")
	p.EndAgentSpan(span, "")

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}

	assertMirroredResourceJoinKeys(t, spans[0].Attributes)
	if got, ok := attrByKey(spans[0].Attributes, "gen_ai.agent.type"); !ok || got.AsString() != "codex" {
		t.Fatalf("gen_ai.agent.type=%q ok=%v want codex", got.AsString(), ok)
	}
}

func TestStartLLMSpan_MirrorsResourceJoinKeysOntoSpan(t *testing.T) {
	redaction.SetDisableAll(false)
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	p, exp := newTracingProvider(t)
	attachTraceTestResourceContext(t, p)

	_, span := p.StartLLMSpan(context.Background(), "openai", "gpt-5.5", "openai", 2048, 0.1)
	p.SetGenAIInput(span, "private prompt content")
	p.SetGenAIOutput(span, "private response content")
	p.EndLLMSpan(context.Background(), span, "gpt-5.5", 100, 50, []string{"stop"}, 0, "", "", "openai", time.Now(), "codex", "codex", "openai_codex", "")

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}

	assertMirroredResourceJoinKeys(t, spans[0].Attributes)
	for _, key := range []string{"gen_ai.input.messages", "gen_ai.output.messages"} {
		got, ok := attrByKey(spans[0].Attributes, key)
		if !ok {
			t.Fatalf("%s missing", key)
		}
		var messages []map[string]string
		if err := json.Unmarshal([]byte(got.AsString()), &messages); err != nil || len(messages) != 1 {
			t.Fatalf("%s=%q invalid GenAI messages: %v", key, got.AsString(), err)
		}
		if !strings.Contains(messages[0]["content"], "<redacted") {
			t.Fatalf("%s content=%q, want redacted value", key, messages[0]["content"])
		}
		if strings.Contains(messages[0]["content"], "private") {
			t.Fatalf("%s leaked raw content: %q", key, got.AsString())
		}
	}
}

func TestEndLLMSpan_OmitsUnknownTokenCounts(t *testing.T) {
	p, exp := newTracingProvider(t)
	_, span := p.StartLLMSpan(context.Background(), "openai", "gpt-5.5", "openai", 0, 0)
	p.EndLLMSpan(context.Background(), span, "gpt-5.5", 0, 0, []string{"stop"}, 0, "", "", "openai", time.Now(), "codex", "codex", "agent", "session")

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	for _, key := range []string{"gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens"} {
		if _, ok := attrByKey(spans[0].Attributes, key); ok {
			t.Fatalf("%s should be absent when usage is unknown", key)
		}
	}
}

func TestStartApprovalSpan_RawCommandOnlyWhenRedactionDisabled(t *testing.T) {
	redaction.SetDisableAll(false)
	t.Cleanup(func() { redaction.SetDisableAll(false) })

	p, exp := newTracingProvider(t)
	_, span := p.StartApprovalSpan(context.Background(), "approval-1", "/usr/bin/curl",
		[]string{"-H", "Authorization: Bearer secret"}, "/tmp/work",
		ToolSpanContext{})
	p.EndApprovalSpan(span, "approved", "ok", false, false)
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	for _, key := range []string{"defenseclaw.approval.command", "defenseclaw.approval.argv", "defenseclaw.approval.cwd"} {
		if _, ok := attrByKey(spans[0].Attributes, key); ok {
			t.Fatalf("%s exported while redaction was enabled", key)
		}
	}

	redaction.SetDisableAll(true)
	p, exp = newTracingProvider(t)
	_, span = p.StartApprovalSpan(context.Background(), "approval-1", "/usr/bin/curl",
		[]string{"-H", "Authorization: Bearer secret"}, "/tmp/work",
		ToolSpanContext{})
	p.EndApprovalSpan(span, "approved", "ok", false, false)
	spans = exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d raw-mode spans, want 1", len(spans))
	}
	if got, ok := attrByKey(spans[0].Attributes, "defenseclaw.approval.command"); !ok || got.AsString() != "/usr/bin/curl" {
		t.Fatalf("raw command attr = %q ok=%v, want /usr/bin/curl", got.AsString(), ok)
	}
	if got, ok := attrByKey(spans[0].Attributes, "defenseclaw.approval.argv"); !ok {
		t.Fatal("raw argv attr missing in raw mode")
	} else if argv := got.AsStringSlice(); len(argv) != 2 || argv[1] != "Authorization: Bearer secret" {
		t.Fatalf("raw argv attr = %#v, want original argv", argv)
	}
	if got, ok := attrByKey(spans[0].Attributes, "defenseclaw.approval.cwd"); !ok || got.AsString() != "/tmp/work" {
		t.Fatalf("raw cwd attr = %q ok=%v, want /tmp/work", got.AsString(), ok)
	}
}

func TestStartAgentSpan_EmitsRunID(t *testing.T) {
	gatewaylog.SetProcessRunID("run-agent-123")
	t.Cleanup(func() { gatewaylog.SetProcessRunID("") })

	p, exp := newTracingProvider(t)
	_, span := p.StartAgentSpan(context.Background(), "session-123", "codex", "codex", "openai_codex", "openai", "codex")
	p.EndAgentSpan(span, "")

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	got, ok := attrByKey(spans[0].Attributes, "defenseclaw.run.id")
	if !ok || got.AsString() != "run-agent-123" {
		t.Fatalf("defenseclaw.run.id=%q ok=%v want run-agent-123", got.AsString(), ok)
	}
}

func TestStartLLMSpan_EmitsRunID(t *testing.T) {
	gatewaylog.SetProcessRunID("run-llm-123")
	t.Cleanup(func() { gatewaylog.SetProcessRunID("") })

	p, exp := newTracingProvider(t)
	_, span := p.StartLLMSpan(context.Background(), "openai", "gpt-5.5", "openai", 1024, 0.2)
	p.EndLLMSpan(context.Background(), span, "gpt-5.5", 12, 34, []string{"stop"}, 0, "", "", "openai", time.Now(), "codex", "codex", "openai_codex", "")

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	got, ok := attrByKey(spans[0].Attributes, "defenseclaw.run.id")
	if !ok || got.AsString() != "run-llm-123" {
		t.Fatalf("defenseclaw.run.id=%q ok=%v want run-llm-123", got.AsString(), ok)
	}
}

func TestDisabledProvider_Metrics_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	ctx := context.Background()
	p.RecordScan(ctx, "test", "skill", "clean", 100, map[string]int{"HIGH": 1}, "codex")
	p.RecordToolCall(ctx, "shell", "builtin", false)
	p.RecordToolDuration(ctx, "shell", "builtin", 50)
	p.RecordToolError(ctx, "shell", 1)
	p.RecordApproval(ctx, "approved", true, false)
	p.RecordLLMTokens(ctx, "chat", "openai", "gpt-4", "", "", "", 100, 200)
	p.RecordLLMDuration(ctx, "chat", "openai", "gpt-4", "", "", 0.5)
	p.RecordAlert(ctx, "dangerous-command", "HIGH", "local-pattern", "codex")
	p.RecordGuardrailEvaluation(ctx, "ai-defense", "block")
	p.RecordGuardrailLatency(ctx, "ai-defense", 100)
}

func TestExpandHeaders(t *testing.T) {
	t.Setenv("TEST_TOKEN", "abc123")

	headers := map[string]string{
		"X-SF-TOKEN": "${TEST_TOKEN}",
		"X-Static":   "static-value",
	}

	expanded := expandHeaders(headers)
	if expanded["X-SF-TOKEN"] != "abc123" {
		t.Errorf("expected abc123, got %s", expanded["X-SF-TOKEN"])
	}
	if expanded["X-Static"] != "static-value" {
		t.Errorf("expected static-value, got %s", expanded["X-Static"])
	}
}

func TestExpandHeaders_MissingEnv(t *testing.T) {
	headers := map[string]string{
		"X-TOKEN": "${NONEXISTENT_VAR_12345}",
	}
	expanded := expandHeaders(headers)
	if expanded["X-TOKEN"] != "" {
		t.Errorf("expected empty for missing env, got %q", expanded["X-TOKEN"])
	}
}

// TestExpandHeaders_NoAutoInjection enforces that expandHeaders is
// vendor-neutral and only expands explicitly configured destination headers.
func TestExpandHeaders_NoAutoInjection(t *testing.T) {
	t.Setenv("SPLUNK_ACCESS_TOKEN", "should-be-ignored")
	expanded := expandHeaders(map[string]string{})
	if _, ok := expanded["X-SF-Token"]; ok {
		t.Fatalf("expandHeaders must not auto-inject Splunk token, got %v", expanded)
	}
	if len(expanded) != 0 {
		t.Fatalf("expandHeaders should return empty map for empty input, got %v", expanded)
	}
}

func TestNewProvider_MultipleTraceDestinationsFanOut(t *testing.T) {
	type requestInfo struct {
		path    string
		header  string
		content string
	}
	localC := make(chan requestInfo, 4)
	galileoC := make(chan requestInfo, 4)
	newReceiver := func(ch chan<- requestInfo) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ch <- requestInfo{
				path:    r.URL.Path,
				header:  r.Header.Get("Galileo-API-Key"),
				content: r.Header.Get("Content-Type"),
			}
			w.WriteHeader(http.StatusOK)
		}))
	}
	local := newReceiver(localC)
	defer local.Close()
	galileo := newReceiver(galileoC)
	defer galileo.Close()

	t.Setenv("TEST_GALILEO_KEY", "test-key")
	cfg := disabledCfg()
	cfg.OTel = config.OTelConfig{
		Enabled: true,
		Traces: config.OTelTracePolicyConfig{
			Sampler:    "always_on",
			SamplerArg: "1.0",
		},
		Batch: config.OTelBatchConfig{
			MaxExportBatchSize: 1,
			ScheduledDelayMs:   10,
			MaxQueueSize:       8,
		},
		Destinations: []config.OTelDestinationConfig{
			{
				Name:     "local-observability",
				Enabled:  true,
				Protocol: "http",
				Endpoint: local.URL,
				Traces: config.OTelTracesConfig{
					Enabled: true,
					URLPath: "/v1/traces",
				},
			},
			{
				Name: "galileo",
				// Filtering is driven by SpanFilter, not a vendor/preset string.
				Preset:   "misspelled-on-purpose",
				Enabled:  true,
				Protocol: "http",
				Endpoint: galileo.URL,
				Headers: map[string]string{
					"Galileo-API-Key": "${TEST_GALILEO_KEY}",
					"project":         "defenseclaw-tests",
					"logstream":       "default",
				},
				Traces: config.OTelTracesConfig{
					Enabled: true,
					URLPath: "/otel/traces",
				},
				SpanFilter: config.OTelSpanFilterConfig{
					Operations: []config.OTelSpanFilterOperationConfig{{
						Name: "chat",
						RequireAttributes: []string{
							"gen_ai.operation.name", "gen_ai.provider.name", "gen_ai.request.model",
							"gen_ai.input.messages", "gen_ai.output.messages",
						},
					}},
				},
			},
		},
	}

	p, err := NewProvider(context.Background(), cfg, "test")
	if err != nil {
		t.Fatalf("NewProvider err=%v", err)
	}
	_, span := p.StartLLMSpan(
		context.Background(), "openai", "gpt-4o-mini", "openai", 16, 0,
	)
	p.SetGenAIInput(span, "fan-out test input")
	p.SetGenAIOutput(span, "fan-out test output")
	p.EndLLMSpan(
		context.Background(), span, "gpt-4o-mini", 4, 4, []string{"stop"},
		0, "none", "", "openai", time.Now(), "codex", "codex", "agent-test", "session-test",
	)
	_, operationalSpan := p.Tracer().Start(context.Background(), "defenseclaw.test.operational")
	operationalSpan.End()
	_, upstreamErrorSpan := p.StartLLMSpan(
		context.Background(), "openai", "gpt-4o-mini", "openai", 16, 0,
	)
	p.SetGenAIInput(upstreamErrorSpan, "request without a response")
	p.SetGenAIOutput(upstreamErrorSpan, "")
	p.EndLLMSpan(
		context.Background(), upstreamErrorSpan, "gpt-4o-mini", 4, 0, []string{"error"},
		0, "none", "", "openai", time.Now(), "codex", "codex", "agent-test", "session-test",
	)
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown err=%v", err)
	}

	assertRequest := func(name string, ch <-chan requestInfo, path, key string) {
		t.Helper()
		select {
		case got := <-ch:
			if got.path != path {
				t.Errorf("%s path=%q want %q", name, got.path, path)
			}
			if got.header != key {
				t.Errorf("%s Galileo-API-Key=%q want %q", name, got.header, key)
			}
			if got.content != "application/x-protobuf" {
				t.Errorf("%s Content-Type=%q want application/x-protobuf", name, got.content)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("timed out waiting for %s OTLP request", name)
		}
	}
	assertRequest("local", localC, "/v1/traces", "")
	assertRequest("galileo", galileoC, "/otel/traces", "test-key")
	assertRequest("local operational", localC, "/v1/traces", "")
	assertRequest("local upstream-error GenAI", localC, "/v1/traces", "")
	select {
	case got := <-galileoC:
		t.Errorf("Galileo received non-GenAI operational span request: %+v", got)
	case <-time.After(100 * time.Millisecond):
	}
	stats := p.DestinationRoutingStats("galileo")
	if stats.Accepted != 1 || stats.Dropped != 2 {
		t.Fatalf("DestinationRoutingStats=%+v want accepted=1 dropped=2", stats)
	}
	delivery := p.DestinationDeliveryStats("galileo")
	if delivery.Attempted != 1 || delivery.Delivered != 1 ||
		delivery.Rejected != 0 || delivery.Failed != 0 {
		t.Fatalf("DestinationDeliveryStats=%+v want attempted=delivered=1", delivery)
	}
}

func TestResolveValue(t *testing.T) {
	tests := []struct {
		name   string
		signal string
		global string
		want   string
	}{
		{"signal set", "signal-endpoint", "global-endpoint", "signal-endpoint"},
		{"signal empty", "", "global-endpoint", "global-endpoint"},
		{"both empty", "", "", ""},
		{"signal set global empty", "signal-endpoint", "", "signal-endpoint"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveValue(tt.signal, tt.global)
			if got != tt.want {
				t.Errorf("resolveValue(%q, %q) = %q, want %q", tt.signal, tt.global, got, tt.want)
			}
		})
	}
}

func TestResolveProtocolNormalizesStandardOTELValues(t *testing.T) {
	if got := resolveProtocol("http/protobuf", ""); got != "http" {
		t.Fatalf("http/protobuf resolved to %q", got)
	}
	if got := resolveProtocol("grpc/protobuf", ""); got != "grpc" {
		t.Fatalf("grpc/protobuf resolved to %q", got)
	}
}

func TestValidateCredentialTransport(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		insecure bool
		headers  map[string]string
		wantErr  bool
	}{
		{name: "remote plaintext auth", endpoint: "http://collector.example.test/v1/traces", headers: map[string]string{"Authorization": "Bearer secret"}, wantErr: true},
		{name: "remote insecure grpc token", endpoint: "collector.example.test:4317", insecure: true, headers: map[string]string{"X-SF-Token": "secret"}, wantErr: true},
		{name: "remote TLS auth", endpoint: "https://collector.example.test/v1/traces", headers: map[string]string{"api-key": "secret"}},
		{name: "loopback plaintext auth", endpoint: "http://127.0.0.1:4318/v1/traces", headers: map[string]string{"Galileo-API-Key": "secret"}},
		{name: "metadata only plaintext", endpoint: "http://collector.example.test/v1/traces", headers: map[string]string{"project": "demo"}},
		{name: "userinfo rejected", endpoint: "https://user:pass@collector.example.test/v1/traces", headers: map[string]string{"Authorization": "secret"}, wantErr: true},
		{name: "userinfo rejected without headers", endpoint: "https://user:pass@collector.example.test/v1/traces", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCredentialTransport(tt.endpoint, tt.insecure, tt.headers)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateCredentialTransport() error=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestSpanMatchesFilterRequiresEveryNonEmptyAttribute(t *testing.T) {
	filter := config.OTelSpanFilterConfig{
		RequireOperation: "chat",
		RequireAttributes: []string{
			"gen_ai.operation.name", "gen_ai.provider.name", "gen_ai.request.model",
			"gen_ai.input.messages", "gen_ai.output.messages",
		},
	}
	values := map[string]string{
		"gen_ai.operation.name":  "chat",
		"gen_ai.provider.name":   "openai",
		"gen_ai.request.model":   "gpt-5.5",
		"gen_ai.input.messages":  `[{"role":"user","content":"hi"}]`,
		"gen_ai.output.messages": `[{"role":"assistant","content":"hello"}]`,
	}
	span := func(overrides map[string]string, omitted string) sdktrace.ReadOnlySpan {
		attrs := make([]attribute.KeyValue, 0, len(values))
		for key, value := range values {
			if key == omitted {
				continue
			}
			if override, ok := overrides[key]; ok {
				value = override
			}
			attrs = append(attrs, attribute.String(key, value))
		}
		return tracetest.SpanStub{Attributes: attrs}.Snapshot()
	}
	if !spanMatchesFilter(span(nil, ""), filter) {
		t.Fatal("complete GenAI span did not match filter")
	}
	for _, missing := range filter.RequireAttributes {
		if spanMatchesFilter(span(nil, missing), filter) {
			t.Errorf("span missing %q matched filter", missing)
		}
	}
	if spanMatchesFilter(span(map[string]string{"gen_ai.output.messages": "   "}, ""), filter) {
		t.Error("span with empty output matched filter")
	}
	if spanMatchesFilter(span(map[string]string{"gen_ai.operation.name": "embeddings"}, ""), filter) {
		t.Error("span with wrong operation matched filter")
	}
}

func TestSpanMatchesFilterOperationBranches(t *testing.T) {
	filter := config.OTelSpanFilterConfig{Operations: []config.OTelSpanFilterOperationConfig{
		{Name: "chat", RequireAttributes: []string{"gen_ai.operation.name", "gen_ai.request.model"}},
		{Name: "invoke_agent", RequireAttributes: []string{"gen_ai.operation.name", "gen_ai.agent.name"}},
		{Name: "execute_tool", RequireAttributes: []string{"gen_ai.operation.name", "gen_ai.tool.name"}},
	}}
	span := func(operation, key, value string) sdktrace.ReadOnlySpan {
		return tracetest.SpanStub{Attributes: []attribute.KeyValue{
			attribute.String("gen_ai.operation.name", operation),
			attribute.String(key, value),
		}}.Snapshot()
	}
	for _, tc := range []struct {
		operation string
		key       string
	}{
		{operation: "chat", key: "gen_ai.request.model"},
		{operation: "invoke_agent", key: "gen_ai.agent.name"},
		{operation: "execute_tool", key: "gen_ai.tool.name"},
	} {
		if !spanMatchesFilter(span(tc.operation, tc.key, "present"), filter) {
			t.Errorf("complete %q branch did not match", tc.operation)
		}
		if spanMatchesFilter(span(tc.operation, tc.key, " "), filter) {
			t.Errorf("empty %q branch attribute matched", tc.operation)
		}
	}
	if spanMatchesFilter(span("embeddings", "gen_ai.request.model", "model"), filter) {
		t.Error("unknown operation matched")
	}
}

func TestNewProviderRejectsCredentialBearingRemotePlaintextDestination(t *testing.T) {
	cfg := disabledCfg()
	cfg.OTel = config.OTelConfig{
		Enabled: true,
		Traces:  config.OTelTracePolicyConfig{Sampler: "always_on", SamplerArg: "1.0"},
		Batch: config.OTelBatchConfig{
			MaxExportBatchSize: 1,
			ScheduledDelayMs:   10,
			MaxQueueSize:       8,
		},
		Destinations: []config.OTelDestinationConfig{{
			Name: "unsafe", Enabled: true, Protocol: "http",
			Endpoint: "http://collector.example.test/v1/traces",
			Headers:  map[string]string{"Authorization": "Bearer secret"},
			Traces:   config.OTelTracesConfig{Enabled: true},
		}},
	}
	_, err := NewProvider(context.Background(), cfg, "test")
	if err == nil || !strings.Contains(err.Error(), "must use TLS") {
		t.Fatalf("NewProvider error=%v, want credential transport rejection", err)
	}
}

func TestTemporalitySelector(t *testing.T) {
	kinds := []sdkmetric.InstrumentKind{
		sdkmetric.InstrumentKindCounter,
		sdkmetric.InstrumentKindUpDownCounter,
		sdkmetric.InstrumentKindHistogram,
		sdkmetric.InstrumentKindGauge,
		sdkmetric.InstrumentKindObservableCounter,
		sdkmetric.InstrumentKindObservableUpDownCounter,
		sdkmetric.InstrumentKindObservableGauge,
	}

	t.Run("delta", func(t *testing.T) {
		sel := temporalitySelector("delta")
		for _, k := range kinds {
			if got := sel(k); got != metricdata.DeltaTemporality {
				t.Errorf("temporalitySelector(\"delta\")(%v) = %v, want Delta", k, got)
			}
		}
	})

	t.Run("empty defaults to delta", func(t *testing.T) {
		sel := temporalitySelector("")
		for _, k := range kinds {
			if got := sel(k); got != metricdata.DeltaTemporality {
				t.Errorf("temporalitySelector(\"\")(%v) = %v, want Delta", k, got)
			}
		}
	})

	t.Run("cumulative", func(t *testing.T) {
		sel := temporalitySelector("cumulative")
		// Should return the SDK default (cumulative for all kinds).
		for _, k := range kinds {
			if got := sel(k); got != metricdata.CumulativeTemporality {
				t.Errorf("temporalitySelector(\"cumulative\")(%v) = %v, want Cumulative", k, got)
			}
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		sel := temporalitySelector("Cumulative")
		if got := sel(sdkmetric.InstrumentKindHistogram); got != metricdata.CumulativeTemporality {
			t.Errorf("temporalitySelector(\"Cumulative\") should be case-insensitive, got %v", got)
		}
	})
}

func TestBuildSampler(t *testing.T) {
	tests := []struct {
		name string
		arg  string
	}{
		{"always_on", ""},
		{"always_off", ""},
		{"parentbased_traceidratio", "0.5"},
		{"parentbased_traceidratio", "invalid"},
		{"unknown", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := buildSampler(tt.name, tt.arg)
			if s == nil {
				t.Error("sampler should not be nil")
			}
		})
	}
}

func TestActionMapping(t *testing.T) {
	tests := []struct {
		action        string
		wantLifecycle string
		wantActor     string
	}{
		{"install-detected", "install", "watcher"},
		{"install-rejected", "block", "watcher"},
		{"install-allowed", "allow", "watcher"},
		{"install-clean", "install", "watcher"},
		{"install-warning", "install", "watcher"},
		{"install-scan-error", "scan-error", "watcher"},
		{"block", "block", "user"},
		{"watcher-block", "block", "watcher"},
		{"allow", "allow", "user"},
		{"quarantine", "quarantine", "defenseclaw"},
		{"restore", "restore", "user"},
		{"deploy", "install", "user"},
		{"stop", "uninstall", "user"},
		{"disable", "disable", "defenseclaw"},
		{"enable", "enable", "user"},
		{"api-skill-disable", "disable", "user"},
		{"api-skill-enable", "enable", "user"},
		{"watch-start", "watch-start", "watcher"},
		{"watch-stop", "watch-stop", "watcher"},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			m, ok := actionMap[tt.action]
			if !ok {
				t.Fatalf("action %q not in actionMap", tt.action)
			}
			if m.LifecycleAction != tt.wantLifecycle {
				t.Errorf("lifecycle: got %s, want %s", m.LifecycleAction, tt.wantLifecycle)
			}
			if m.Actor != tt.wantActor {
				t.Errorf("actor: got %s, want %s", m.Actor, tt.wantActor)
			}
		})
	}
}

func TestNonLifecycleActionsExcluded(t *testing.T) {
	nonLifecycle := []string{
		"sidecar-start", "sidecar-stop", "sidecar-connected",
		"gateway-tool-call", "gateway-tool-result",
		"gateway-approval-requested",
		"api-config-patch",
	}
	for _, action := range nonLifecycle {
		if _, ok := actionMap[action]; ok {
			t.Errorf("operational action %q should not be in lifecycle actionMap", action)
		}
	}
}

func TestSeverityMapping(t *testing.T) {
	tests := []struct {
		input    string
		wantText string
		wantNum  int
	}{
		{"CRITICAL", "ERROR", 17},
		{"ERROR", "ERROR", 17},
		{"HIGH", "WARN", 13},
		{"WARN", "WARN", 13},
		{"INFO", "INFO", 9},
		{"LOW", "INFO", 9},
		{"MEDIUM", "INFO", 9},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			text, num := severityToOTel(tt.input)
			if text != tt.wantText {
				t.Errorf("text: got %s, want %s", text, tt.wantText)
			}
			if num != tt.wantNum {
				t.Errorf("num: got %d, want %d", num, tt.wantNum)
			}
		})
	}
}

func TestTruncateStr(t *testing.T) {
	tests := []struct {
		input string
		max   int
		want  string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is too long", 10, "this is to…"},
		{"", 5, ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := truncateStr(tt.input, tt.max); got != tt.want {
				t.Errorf("truncateStr(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.want)
			}
		})
	}
}

func TestBaseCommand(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"curl http://example.com", "curl"},
		{"/usr/bin/bash -c echo hello", "bash"},
		{"", ""},
		{"  git status  ", "git"},
		{"npm", "npm"},
		{"/usr/local/bin/python3 script.py", "python3"},
		{"./relative/path/to/binary --flag", "binary"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := baseCommand(tt.input); got != tt.want {
				t.Errorf("baseCommand(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildScanBody_ExcludesSensitiveFields(t *testing.T) {
	result := &scanner.ScanResult{
		Scanner:   "codeguard",
		Target:    "/path/to/project",
		Timestamp: time.Now(),
		Duration:  200 * time.Millisecond,
		Findings: []scanner.Finding{
			{
				ID:          "f1",
				Severity:    scanner.SeverityHigh,
				Title:       "Hardcoded secret",
				Description: "Found AWS key AKIA... in source",
				Location:    "/path/to/project/src/config.go:42",
				Remediation: "Use environment variables instead",
				Scanner:     "codeguard",
				Tags:        []string{"secrets", "aws"},
			},
		},
	}

	body := buildScanBody(result, "scan-001", "code")

	if len(body.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(body.Findings))
	}
	f := body.Findings[0]

	if f.ID != "f1" {
		t.Errorf("ID: got %q, want %q", f.ID, "f1")
	}
	if f.Severity != "HIGH" {
		t.Errorf("Severity: got %q, want %q", f.Severity, "HIGH")
	}
	if f.Title != "Hardcoded secret" {
		t.Errorf("Title: got %q, want %q", f.Title, "Hardcoded secret")
	}
	if f.Scanner != "codeguard" {
		t.Errorf("Scanner: got %q, want %q", f.Scanner, "codeguard")
	}
	if len(f.Tags) != 2 || f.Tags[0] != "secrets" {
		t.Errorf("Tags: got %v, want [secrets aws]", f.Tags)
	}

	bodyJSON, _ := json.Marshal(body)
	bodyStr := string(bodyJSON)
	for _, sensitive := range []string{"AKIA", "config.go:42", "environment variables"} {
		if containsStr(bodyStr, sensitive) {
			t.Errorf("scan body should not contain sensitive content %q", sensitive)
		}
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestDeviceFingerprint_MissingFile(t *testing.T) {
	fp := deviceFingerprint("/nonexistent/path/to/key")
	if fp != "" {
		t.Errorf("expected empty fingerprint for missing file, got %q", fp)
	}
}

func TestDeviceFingerprint_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/bad.key"
	if err := os.WriteFile(path, []byte("not a PEM file"), 0600); err != nil {
		t.Fatal(err)
	}
	fp := deviceFingerprint(path)
	if fp != "" {
		t.Errorf("expected empty fingerprint for invalid PEM, got %q", fp)
	}
}

func TestDeviceFingerprint_WrongSeedSize(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/wrong.key"
	pemData := "-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----\n"
	if err := os.WriteFile(path, []byte(pemData), 0600); err != nil {
		t.Fatal(err)
	}
	fp := deviceFingerprint(path)
	if fp != "" {
		t.Errorf("expected empty fingerprint for wrong seed size, got %q", fp)
	}
}

func TestDeviceFingerprint_ValidKey(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/device.key"

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: seed})
	if err := os.WriteFile(path, pemBlock, 0600); err != nil {
		t.Fatal(err)
	}

	fp := deviceFingerprint(path)
	if fp == "" {
		t.Fatal("expected non-empty fingerprint for valid key")
	}
	if len(fp) != 64 {
		t.Errorf("expected 64-char hex fingerprint, got %d chars: %s", len(fp), fp)
	}

	fp2 := deviceFingerprint(path)
	if fp != fp2 {
		t.Errorf("fingerprint not deterministic: %s != %s", fp, fp2)
	}
}

func TestScanSeverityToOTel(t *testing.T) {
	tests := []struct {
		input    string
		wantText string
		wantNum  int
	}{
		{"CRITICAL", "ERROR", 17},
		{"HIGH", "WARN", 13},
		{"MEDIUM", "INFO", 9},
		{"LOW", "INFO", 9},
		{"", "INFO", 9},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			text, num := scanSeverityToOTel(tt.input)
			if text != tt.wantText {
				t.Errorf("text: got %q, want %q", text, tt.wantText)
			}
			if num != tt.wantNum {
				t.Errorf("num: got %d, want %d", num, tt.wantNum)
			}
		})
	}
}

func TestFindingSeverityToOTel(t *testing.T) {
	tests := []struct {
		input    string
		wantText string
		wantNum  int
	}{
		{"CRITICAL", "CRITICAL", 21},
		{"HIGH", "HIGH", 17},
		{"MEDIUM", "MEDIUM", 13},
		{"LOW", "LOW", 9},
		{"INFO", "INFO", 9},
		{"", "INFO", 9},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			text, num := findingSeverityToOTel(tt.input)
			if text != tt.wantText {
				t.Errorf("text: got %q, want %q", text, tt.wantText)
			}
			if num != tt.wantNum {
				t.Errorf("num: got %d, want %d", num, tt.wantNum)
			}
		})
	}
}

func TestAlertSeverityToOTel(t *testing.T) {
	tests := []struct {
		input    string
		wantText string
		wantNum  int
	}{
		{"CRITICAL", "CRITICAL", 21},
		{"HIGH", "HIGH", 17},
		{"MEDIUM", "MEDIUM", 13},
		{"LOW", "LOW", 9},
		{"unknown", "LOW", 9},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			text, num := alertSeverityToOTel(tt.input)
			if text != tt.wantText {
				t.Errorf("text: got %q, want %q", text, tt.wantText)
			}
			if num != tt.wantNum {
				t.Errorf("num: got %d, want %d", num, tt.wantNum)
			}
		})
	}
}

func TestResolveServiceName(t *testing.T) {
	tests := []struct {
		name   string
		envVal string
		attrs  map[string]string
		want   string
	}{
		{
			"env var takes priority",
			"from-env",
			map[string]string{"service.name": "from-config"},
			"from-env",
		},
		{
			"config attr used when no env",
			"",
			map[string]string{"service.name": "from-config"},
			"from-config",
		},
		{
			"default when both empty",
			"",
			map[string]string{},
			"defenseclaw",
		},
		{
			"default when nil attrs",
			"",
			nil,
			"defenseclaw",
		},
		{
			"env var empty string falls through",
			"",
			map[string]string{"service.name": ""},
			"defenseclaw",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OTEL_SERVICE_NAME", tt.envVal)
			got := resolveServiceName(tt.attrs)
			if got != tt.want {
				t.Errorf("resolveServiceName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildResource(t *testing.T) {
	cfg := disabledCfg()
	cfg.OTel.Resource.Attributes = map[string]string{
		"custom.attr": "custom-value",
	}
	res := buildResource(cfg, "1.0.0-test")
	if res == nil {
		t.Fatal("resource should not be nil")
	}
}

func TestBuildResource_ServiceNameFromEnv(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "my-app-from-env")
	cfg := disabledCfg()
	cfg.OTel.Resource.Attributes = map[string]string{
		"service.name": "from-config",
	}

	res := buildResource(cfg, "1.0.0")
	iter := res.Iter()
	var found string
	count := 0
	for iter.Next() {
		kv := iter.Attribute()
		if string(kv.Key) == "service.name" {
			found = kv.Value.AsString()
			count++
		}
	}
	if found != "my-app-from-env" {
		t.Errorf("service.name = %q, want %q", found, "my-app-from-env")
	}
	if count != 1 {
		t.Errorf("service.name appeared %d times, want exactly 1 (no duplicates)", count)
	}
}

func TestBuildResource_ServiceNameDedup(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "")
	cfg := disabledCfg()
	cfg.OTel.Resource.Attributes = map[string]string{
		"service.name": "custom-name",
		"custom.attr":  "value",
	}

	res := buildResource(cfg, "1.0.0")
	iter := res.Iter()
	serviceNameCount := 0
	customAttrFound := false
	var serviceNameVal string
	for iter.Next() {
		kv := iter.Attribute()
		switch string(kv.Key) {
		case "service.name":
			serviceNameCount++
			serviceNameVal = kv.Value.AsString()
		case "custom.attr":
			customAttrFound = true
		}
	}
	if serviceNameCount != 1 {
		t.Errorf("service.name appeared %d times, want 1", serviceNameCount)
	}
	if serviceNameVal != "custom-name" {
		t.Errorf("service.name = %q, want %q", serviceNameVal, "custom-name")
	}
	if !customAttrFound {
		t.Error("custom.attr should still be present in resource")
	}
}

func TestBuildResource_DefaultServiceName(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "")
	cfg := disabledCfg()
	cfg.OTel.Resource.Attributes = map[string]string{}

	res := buildResource(cfg, "1.0.0")
	iter := res.Iter()
	for iter.Next() {
		kv := iter.Attribute()
		if string(kv.Key) == "service.name" {
			if kv.Value.AsString() != "defenseclaw" {
				t.Errorf("service.name = %q, want %q", kv.Value.AsString(), "defenseclaw")
			}
			return
		}
	}
	t.Error("service.name attribute not found")
}

func TestBuildResource_AgentWatchContextAttributes(t *testing.T) {
	cfg := disabledCfg()
	cfg.TenantID = "tenant-a"
	cfg.WorkspaceID = "workspace-1"
	cfg.DeploymentMode = "unmanaged_byod"
	cfg.DiscoverySource = "registry"

	res := buildResource(cfg, "1.0.0")
	got := map[string]string{}
	iter := res.Iter()
	for iter.Next() {
		kv := iter.Attribute()
		got[string(kv.Key)] = kv.Value.AsString()
	}

	for key, want := range map[string]string{
		"tenant.id":              "tenant-a",
		"workspace.id":           "workspace-1",
		"deployment.environment": "test",
		"deployment.mode":        "unmanaged_byod",
		"discovery.source":       "registry",
	} {
		if got[key] != want {
			t.Errorf("%s=%q, want %q", key, got[key], want)
		}
	}
}

// resourceAttrs flattens a built resource into a key->value map for assertions.
func resourceAttrs(t *testing.T, cfg *config.Config) map[string]string {
	t.Helper()
	res := buildResource(cfg, "1.0.0")
	got := map[string]string{}
	iter := res.Iter()
	for iter.Next() {
		kv := iter.Attribute()
		got[string(kv.Key)] = kv.Value.AsString()
	}
	return got
}

// TestBuildResource_SingleConnectorMode pins the unchanged single-connector
// behavior: claw.mode names the active connector and home_dir is its resolved
// path. This is the regression guard for the Option-A multi-connector branch.
func TestBuildResource_SingleConnectorMode(t *testing.T) {
	cfg := disabledCfg()

	got := resourceAttrs(t, cfg)

	wantMode := cfg.ActiveConnector()
	if wantMode == "multi" {
		t.Fatalf("test fixture resolves to the multi sentinel; want a single connector")
	}
	if got["defenseclaw.claw.mode"] != wantMode {
		t.Errorf("claw.mode=%q, want %q", got["defenseclaw.claw.mode"], wantMode)
	}
	if want := cfg.ConnectorHomeDir(wantMode); got["defenseclaw.claw.home_dir"] != want {
		t.Errorf("claw.home_dir=%q, want %q", got["defenseclaw.claw.home_dir"], want)
	}
}

// TestBuildResource_MultiConnectorMode verifies that when more than one
// connector is active the process-level descriptor reports the "multi"
// sentinel with an empty home_dir. The true per-event connector is carried by
// the `connector` metric label / `defenseclaw.connector.source` span attribute,
// which are emitted independently of the resource.
func TestBuildResource_MultiConnectorMode(t *testing.T) {
	cfg := disabledCfg()
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex":  {},
		"cursor": {},
	}

	got := resourceAttrs(t, cfg)

	if got["defenseclaw.claw.mode"] != "multi" {
		t.Errorf("claw.mode=%q, want %q", got["defenseclaw.claw.mode"], "multi")
	}
	if got["defenseclaw.claw.home_dir"] != "" {
		t.Errorf("claw.home_dir=%q, want empty in multi mode", got["defenseclaw.claw.home_dir"])
	}
}

// ---------------------------------------------------------------------------
// OTel metric verification tests — ensure guardrail metrics are actually
// recorded with the correct instruments and attribute values.
// ---------------------------------------------------------------------------

func TestRecordGuardrailEvaluation_EmitsMetric(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordGuardrailEvaluation(ctx, "guardrail-proxy", "block")
	p.RecordGuardrailEvaluation(ctx, "guardrail-proxy", "allow")
	p.RecordGuardrailEvaluation(ctx, "guardrail-proxy", "block")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	found := findCounter(rm, "defenseclaw.guardrail.evaluations")
	if found == nil {
		t.Fatal("metric defenseclaw.guardrail.evaluations not found")
		return
	}

	sum, ok := found.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("expected Sum[int64], got %T", found.Data)
	}

	blockCount := counterValueByAttr(sum, "guardrail.action_taken", "block")
	allowCount := counterValueByAttr(sum, "guardrail.action_taken", "allow")

	if blockCount != 2 {
		t.Errorf("block count = %d, want 2", blockCount)
	}
	if allowCount != 1 {
		t.Errorf("allow count = %d, want 1", allowCount)
	}
}

func TestRecordGuardrailLatency_EmitsMetric(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordGuardrailLatency(ctx, "guardrail-proxy", 15.5)
	p.RecordGuardrailLatency(ctx, "guardrail-proxy", 22.0)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	found := findHistogram(rm, "defenseclaw.guardrail.latency")
	if found == nil {
		t.Fatal("metric defenseclaw.guardrail.latency not found")
		return
	}

	hist, ok := found.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("expected Histogram[float64], got %T", found.Data)
	}

	if len(hist.DataPoints) == 0 {
		t.Fatal("expected at least one histogram data point")
	}

	dp := hist.DataPoints[0]
	if dp.Count != 2 {
		t.Errorf("histogram count = %d, want 2", dp.Count)
	}
	if dp.Sum != 37.5 {
		t.Errorf("histogram sum = %f, want 37.5", dp.Sum)
	}

	hasScanner := hasAttribute(dp.Attributes, "guardrail.scanner", "guardrail-proxy")
	if !hasScanner {
		t.Error("histogram missing attribute guardrail.scanner=guardrail-proxy")
	}
}

func TestRecordLLMTokens_EmitsMetric(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordLLMTokens(ctx, "chat", "openai", "gpt-4", "test-agent", "agent-id-1", "sess-123", 150, 75)
	p.RecordLLMTokens(ctx, "chat", "openai", "gpt-4", "test-agent", "agent-id-1", "sess-123", 200, 0) // no completion tokens

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	found := findHistogram(rm, "gen_ai.client.token.usage")
	if found == nil {
		t.Fatal("metric gen_ai.client.token.usage not found")
		return
	}

	hist, ok := found.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("expected Histogram[float64], got %T", found.Data)
	}

	var inputSum, outputSum float64
	for _, dp := range hist.DataPoints {
		for _, attr := range dp.Attributes.ToSlice() {
			if string(attr.Key) == "gen_ai.token.type" {
				if attr.Value.AsString() == "input" {
					inputSum += dp.Sum
				} else if attr.Value.AsString() == "output" {
					outputSum += dp.Sum
				}
			}
		}
	}

	if inputSum != 350 {
		t.Errorf("input token sum = %v, want 350", inputSum)
	}
	if outputSum != 75 {
		t.Errorf("output token sum = %v, want 75", outputSum)
	}

	// Verify gen_ai.agent.name attribute is present on data points.
	for _, dp := range hist.DataPoints {
		hasAgentName := hasAttribute(dp.Attributes, "gen_ai.agent.name", "test-agent")
		if !hasAgentName {
			t.Error("histogram data point missing attribute gen_ai.agent.name=test-agent")
		}
		// v7 cardinality-safe identity: gen_ai.agent.id is bounded
		// per deployment (one per configured agent) and gives o11y a
		// stable join key that survives renames. Pin its presence so
		// a regression in EndLLMSpan threading doesn't silently drop it.
		hasAgentID := hasAttribute(dp.Attributes, "gen_ai.agent.id", "agent-id-1")
		if !hasAgentID {
			t.Error("histogram data point missing attribute gen_ai.agent.id=agent-id-1")
		}
		hasSessionID := hasAttribute(dp.Attributes, "gen_ai.conversation.id", "sess-123")
		if !hasSessionID {
			t.Error("histogram data point missing attribute gen_ai.conversation.id=sess-123")
		}
	}
}

func TestRecordGuardrailEvaluation_DisabledProvider_NoOp(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	p.RecordGuardrailEvaluation(context.Background(), "test", "block")
}

func TestDisabledProvider_RecordPolicyEvaluation_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	ctx := context.Background()
	p.RecordPolicyEvaluation(ctx, "admission", "blocked")
	p.RecordPolicyLatency(ctx, "firewall", 42.0)
	p.RecordPolicyReload(ctx, "success")
}

func TestDisabledProvider_EmitPolicyDecision_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	p.EmitPolicyDecision("admission", "blocked", "evil-skill", "skill", "on block list", nil)
}

func TestEmitPolicyDecision_EnabledProvider_AllVerdicts(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	p.EmitPolicyDecision("admission", "blocked", "evil-skill", "skill", "on block list", nil)
	p.EmitPolicyDecision("firewall", "deny", "evil.com", "network", "denied by rule", map[string]string{
		"rule_name": "block-external",
	})
	p.EmitPolicyDecision("reload", "success", "/etc/policies", "", "OPA reload", nil)
	p.EmitPolicyDecision("admission", "failed", "broken", "skill", "engine error", map[string]string{
		"error": "timeout",
		"empty": "",
	})
	p.EmitPolicyDecision("sandbox", "allow", "good-skill", "skill", "clean", nil)
}

func TestDisabledProvider_PolicySpan_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	ctx, span := p.StartPolicySpan(context.Background(), "firewall", "network", "example.com")
	if span != nil {
		t.Error("span should be nil when disabled")
	}
	if ctx == nil {
		t.Error("context should not be nil")
	}
	p.EndPolicySpan(nil, "firewall", "allow", "default allow", time.Now().Add(-10*time.Millisecond))
}

func TestRecordPolicyEvaluation_EmitsMetric(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordPolicyEvaluation(ctx, "admission", "blocked")
	p.RecordPolicyEvaluation(ctx, "admission", "clean")
	p.RecordPolicyEvaluation(ctx, "firewall", "deny")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	found := findCounter(rm, "defenseclaw.policy.evaluations")
	if found == nil {
		t.Fatal("metric defenseclaw.policy.evaluations not found")
		return
	}

	sum, ok := found.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("expected Sum[int64], got %T", found.Data)
	}

	blockedCount := counterValueByAttr(sum, "policy.verdict", "blocked")
	if blockedCount != 1 {
		t.Errorf("blocked count = %d, want 1", blockedCount)
	}

	cleanCount := counterValueByAttr(sum, "policy.verdict", "clean")
	if cleanCount != 1 {
		t.Errorf("clean count = %d, want 1", cleanCount)
	}

	denyCount := counterValueByAttr(sum, "policy.verdict", "deny")
	if denyCount != 1 {
		t.Errorf("deny count = %d, want 1", denyCount)
	}
}

func TestRecordPolicyLatency_EmitsMetric(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordPolicyLatency(ctx, "admission", 5.0)
	p.RecordPolicyLatency(ctx, "admission", 12.5)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	found := findHistogram(rm, "defenseclaw.policy.latency")
	if found == nil {
		t.Fatal("metric defenseclaw.policy.latency not found")
		return
	}

	hist, ok := found.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("expected Histogram[float64], got %T", found.Data)
	}

	if len(hist.DataPoints) == 0 {
		t.Fatal("expected at least one histogram data point")
	}

	dp := hist.DataPoints[0]
	if dp.Count != 2 {
		t.Errorf("histogram count = %d, want 2", dp.Count)
	}
	if dp.Sum != 17.5 {
		t.Errorf("histogram sum = %f, want 17.5", dp.Sum)
	}
}

func TestRecordPolicyReload_EmitsMetric(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordPolicyReload(ctx, "success")
	p.RecordPolicyReload(ctx, "failed")
	p.RecordPolicyReload(ctx, "success")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	found := findCounter(rm, "defenseclaw.policy.reloads")
	if found == nil {
		t.Fatal("metric defenseclaw.policy.reloads not found")
		return
	}

	sum, ok := found.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("expected Sum[int64], got %T", found.Data)
	}

	successCount := counterValueByAttr(sum, "policy.status", "success")
	failedCount := counterValueByAttr(sum, "policy.status", "failed")

	if successCount != 2 {
		t.Errorf("success count = %d, want 2", successCount)
	}
	if failedCount != 1 {
		t.Errorf("failed count = %d, want 1", failedCount)
	}
}

func TestStartEndPolicySpan_RecordsAttributes(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	exporter := tracetest.NewInMemoryExporter()
	p, err := NewProviderForTraceTest(reader, exporter)
	if err != nil {
		t.Fatalf("NewProviderForTraceTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	start := time.Now()
	ctx, span := p.StartPolicySpan(ctx, "firewall", "network", "evil.example.com")
	if span == nil {
		t.Fatal("span should not be nil with trace-enabled provider")
	}
	if ctx == nil {
		t.Fatal("context should not be nil")
	}

	time.Sleep(time.Millisecond)
	p.EndPolicySpan(span, "firewall", "deny", "blocked by firewall rule", start)

	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least one recorded span")
	}

	s := spans[len(spans)-1]
	if s.Name != "policy/firewall" {
		t.Errorf("span name = %q, want %q", s.Name, "policy/firewall")
	}

	attrMap := make(map[string]string)
	for _, a := range s.Attributes {
		attrMap[string(a.Key)] = a.Value.AsString()
	}
	if attrMap["defenseclaw.policy.domain"] != "firewall" {
		t.Errorf("domain attr = %q, want %q", attrMap["defenseclaw.policy.domain"], "firewall")
	}
	if attrMap["defenseclaw.policy.target_type"] != "network" {
		t.Errorf("target_type attr = %q, want %q", attrMap["defenseclaw.policy.target_type"], "network")
	}
	if attrMap["defenseclaw.policy.target_name"] != "evil.example.com" {
		t.Errorf("target_name attr = %q, want %q", attrMap["defenseclaw.policy.target_name"], "evil.example.com")
	}
	if attrMap["defenseclaw.policy.verdict"] != "deny" {
		t.Errorf("verdict attr = %q, want %q", attrMap["defenseclaw.policy.verdict"], "deny")
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	evalMetric := findCounter(rm, "defenseclaw.policy.evaluations")
	if evalMetric == nil {
		t.Fatal("EndPolicySpan should also record policy.evaluations metric")
		return
	}
}

func TestEmitGenAICanaryDetachesFilteredHTTPParent(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	exporter := tracetest.NewInMemoryExporter()
	p, err := NewProviderForTraceTest(reader, exporter)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	parentCtx, parent := p.Tracer().Start(context.Background(), "POST /api/v1/telemetry/canary")
	traceID, err := p.EmitGenAICanary(parentCtx)
	if err != nil {
		t.Fatal(err)
	}
	spans := exporter.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("spans=%d want root agent + child chat", len(spans))
	}
	var agent, chat tracetest.SpanStub
	for _, span := range spans {
		switch span.Name {
		case "invoke_agent defenseclaw":
			agent = span
		case "chat gpt-4o-mini":
			chat = span
		}
	}
	if agent.Name == "" || chat.Name == "" {
		t.Fatalf("unexpected spans: %+v", spans)
	}
	if !isCanarySpan(agent.Snapshot()) || !isCanarySpan(chat.Snapshot()) {
		t.Fatal("runtime canary spans are missing the isolation marker")
	}
	if agent.Parent.IsValid() {
		t.Fatalf("agent retained filtered HTTP parent %s", agent.Parent.SpanID())
	}
	if chat.Parent.SpanID() != agent.SpanContext.SpanID() {
		t.Fatalf("chat parent=%s want agent=%s", chat.Parent.SpanID(), agent.SpanContext.SpanID())
	}
	if chat.SpanContext.TraceID().String() != traceID {
		t.Fatalf("chat trace=%s returned=%s", chat.SpanContext.TraceID(), traceID)
	}
	parent.End()
}

func TestStartEndPolicySpan_BlockedSetsErrorStatus(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	exporter := tracetest.NewInMemoryExporter()
	p, err := NewProviderForTraceTest(reader, exporter)
	if err != nil {
		t.Fatalf("NewProviderForTraceTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	start := time.Now()
	_, span := p.StartPolicySpan(context.Background(), "admission", "skill", "evil-skill")
	p.EndPolicySpan(span, "admission", "blocked", "on block list", start)

	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected recorded span")
	}
	s := spans[len(spans)-1]
	if s.Status.Code.String() != "Error" {
		t.Errorf("span status = %q, want Error for blocked verdict", s.Status.Code.String())
	}
}

func TestStartEndPolicySpan_AllowSetsOkStatus(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	exporter := tracetest.NewInMemoryExporter()
	p, err := NewProviderForTraceTest(reader, exporter)
	if err != nil {
		t.Fatalf("NewProviderForTraceTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	start := time.Now()
	_, span := p.StartPolicySpan(context.Background(), "admission", "skill", "safe-skill")
	p.EndPolicySpan(span, "admission", "allow", "clean scan", start)

	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected recorded span")
	}
	s := spans[len(spans)-1]
	if s.Status.Code.String() != "Ok" {
		t.Errorf("span status = %q, want Ok for allow verdict", s.Status.Code.String())
	}
}

func TestEndPolicySpan_NilSpan_StillRecordsMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	p.EndPolicySpan(nil, "sandbox", "restrict", "denied endpoints", time.Now().Add(-5*time.Millisecond))

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	evalMetric := findCounter(rm, "defenseclaw.policy.evaluations")
	if evalMetric == nil {
		t.Fatal("EndPolicySpan(nil) should still record policy.evaluations metric")
		return
	}
}

func TestNilProvider_PolicyMethods_NoPanic(t *testing.T) {
	var p *Provider
	ctx := context.Background()

	p.RecordPolicyEvaluation(ctx, "admission", "blocked")
	p.RecordPolicyLatency(ctx, "firewall", 10.0)
	p.RecordPolicyReload(ctx, "success")
	p.EmitPolicyDecision("admission", "blocked", "target", "skill", "reason", nil)

	ctx2, span := p.StartPolicySpan(ctx, "firewall", "network", "example.com")
	if span != nil {
		t.Error("nil provider should return nil span")
	}
	if ctx2 == nil {
		t.Error("nil provider should still return non-nil context")
	}
	p.EndPolicySpan(nil, "firewall", "deny", "reason", time.Now())
}

func TestPolicyVerdictSeverity(t *testing.T) {
	tests := []struct {
		verdict  string
		wantText string
		wantNum  int
	}{
		{"blocked", "WARN", 13},
		{"rejected", "WARN", 13},
		{"deny", "WARN", 13},
		{"block", "WARN", 13},
		{"failed", "ERROR", 17},
		{"allow", "INFO", 9},
		{"clean", "INFO", 9},
		{"success", "INFO", 9},
	}
	for _, tt := range tests {
		t.Run(tt.verdict, func(t *testing.T) {
			text, num := policyVerdictSeverity(tt.verdict)
			if text != tt.wantText {
				t.Errorf("text: got %q, want %q", text, tt.wantText)
			}
			if num != tt.wantNum {
				t.Errorf("num: got %d, want %d", num, tt.wantNum)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Metric collection helpers
// ---------------------------------------------------------------------------

func findCounter(rm metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	for _, sm := range rm.ScopeMetrics {
		for i := range sm.Metrics {
			if sm.Metrics[i].Name == name {
				return &sm.Metrics[i]
			}
		}
	}
	return nil
}

func findHistogram(rm metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	return findCounter(rm, name) // same lookup, different data type
}

func counterValueByAttr(sum metricdata.Sum[int64], key, val string) int64 {
	for _, dp := range sum.DataPoints {
		if hasAttribute(dp.Attributes, key, val) {
			return dp.Value
		}
	}
	return 0
}

func hasAttribute(attrs attribute.Set, key, val string) bool {
	v, ok := attrs.Value(attribute.Key(key))
	return ok && v.AsString() == val
}
