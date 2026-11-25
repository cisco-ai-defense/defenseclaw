// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

// GAP-2065: on a managed RHEL host the gateway counted
// telemetry.records.dropped with reason unsupported_identity on claudecode
// ingest while an AD user's sandboxes ran Claude Code. Those are the records
// of Claude Code's own exporter that no inbound binding imports (the
// tool_result, tool_decision and api_error events, and every metric but
// token usage and operation duration): counted and dropped by design, at
// INFO (GAP-1165). The prompt in the same batch is imported, and DefenseClaw's
// own hook decision and sandbox lifecycle records never pass through this
// path, so a drop of this class loses none of them.
func TestGAP2065ClaudeCodeUnimportedNativeRecordsAreCountedAsUnsupportedIdentity(t *testing.T) {
	fixture := newCodexNativeOTLPFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC()

	logs := claudeUserPromptLog(now, claudeUserPromptAttributes(claudeCodeRedactedPrompt))
	records := logs.ResourceLogs[0].ScopeLogs[0].LogRecords
	for _, name := range []string{"tool_result", "tool_decision", "api_error"} {
		copied := &logspb.LogRecord{
			TimeUnixNano: records[0].TimeUnixNano,
			Body:         &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "claude_code." + name}},
			Attributes: withNativeAttribute(claudeUserPromptAttributes(claudeCodeRedactedPrompt), "event.name",
				otlpClassifierStringAttribute("event.name", name)),
		}
		logs.ResourceLogs[0].ScopeLogs[0].LogRecords = append(logs.ResourceLogs[0].ScopeLogs[0].LogRecords, copied)
	}
	accounting, err := api.importDecodedOTLPRequestV8(context.Background(), logs, otelSignalLogs, "claudecode", now)
	if err != nil || !accounting.valid() {
		t.Fatalf("logs accounting=%+v err=%v", accounting, err)
	}
	if accounting.imported != 1 || accounting.unsupportedIdentity != 3 {
		t.Fatalf("logs: imported=%d unsupported_identity=%d, want the prompt imported and the 3 other events counted as unsupported_identity (%+v)",
			accounting.imported, accounting.unsupportedIdentity, accounting)
	}

	var metrics []*metricspb.Metric
	for _, name := range []string{"claude_code.session.count", "claude_code.lines_of_code.count", "claude_code.active_time.total", "claude_code.commit.count"} {
		metrics = append(metrics, &metricspb.Metric{Name: name, Unit: "count", Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{
			AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA, IsMonotonic: true,
			DataPoints: []*metricspb.NumberDataPoint{{
				StartTimeUnixNano: uint64(now.Add(-time.Minute).UnixNano()), TimeUnixNano: uint64(now.UnixNano()),
				Value:      &metricspb.NumberDataPoint_AsDouble{AsDouble: 1},
				Attributes: []*commonpb.KeyValue{otlpClassifierStringAttribute("session.id", nativeUsageSession)},
			}},
		}}})
	}
	counters := &collectormetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource:     &resourcepb.Resource{Attributes: []*commonpb.KeyValue{otlpClassifierStringAttribute("service.name", "claude-code")}},
		ScopeMetrics: []*metricspb.ScopeMetrics{{Scope: &commonpb.InstrumentationScope{Name: "com.anthropic.claude_code"}, Metrics: metrics}},
	}}}
	accounting, err = api.importDecodedOTLPRequestV8(context.Background(), counters, otelSignalMetrics, "claudecode", now)
	if err != nil || !accounting.valid() {
		t.Fatalf("metrics accounting=%+v err=%v", accounting, err)
	}
	if accounting.unsupportedIdentity != int64(len(metrics)) {
		t.Fatalf("metrics: unsupported_identity=%d, want every one of the %d unimported Claude Code metrics (%+v)",
			accounting.unsupportedIdentity, len(metrics), accounting)
	}
	// The per-batch drop event of this class is INFO, not a WARN stream.
	if !otlpDropIsExpectedUnmapped(observability.EventName(observability.TelemetryEventTelemetryRecordsDropped), string(otlpInboundUnsupportedIdentity)) {
		t.Fatal("an unsupported_identity drop is not reported as the expected INFO drop")
	}
}
