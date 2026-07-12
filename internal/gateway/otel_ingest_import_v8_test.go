// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"go.opentelemetry.io/otel/trace"
	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

func TestPrimaryDispositionPreservesConstructedDerivativeOnDeliveryDegradation(t *testing.T) {
	t.Parallel()

	degraded := otlpInboundTargetResult{collected: true, deliveryDegraded: true}
	tests := []struct {
		name string
		leaf otlpInboundLeafResult
		want otlpInboundPrimaryDisposition
	}{
		{
			name: "derive only",
			leaf: otlpInboundLeafResult{
				derivatives:      []otlpInboundTargetResult{degraded},
				hasDerivedTarget: true,
			},
			want: otlpInboundDerivedOnly,
		},
		{
			name: "import and derive",
			leaf: otlpInboundLeafResult{
				primary:          &otlpInboundTargetResult{collected: true, recorded: true},
				derivatives:      []otlpInboundTargetResult{degraded},
				hasImportTarget:  true,
				hasDerivedTarget: true,
			},
			want: otlpInboundImportedAndDerived,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := primaryDispositionForInboundLeaf(test.leaf); got != test.want {
				t.Fatalf("primary disposition = %q, want %q", got, test.want)
			}
		})
	}
}

func TestOTLPInboundUnsupportedLeafCompletesPrimaryAccounting(t *testing.T) {
	previousInstance := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("otlp-inbound-accounting-test")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstance) })
	fixture := newOTLPV8MetricFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	message := &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{}}}},
	}}}
	accounting, err := api.importDecodedOTLPRequestV8(context.Background(), message, otelSignalLogs, "codex", time.Now().UTC())
	if err != nil || !accounting.valid() || accounting.unsupportedIdentity != 1 {
		t.Fatalf("unsupported accounting = %+v err=%v", accounting, err)
	}
}

func TestOTLPInboundGeneratedConnectorLogImportsThroughSQLite(t *testing.T) {
	previousInstance := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("otlp-inbound-log-test")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstance) })

	fixture := newOTLPV8MetricFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	classifier := mustOTLPInboundClassifierV8(t)
	match, ok := classifier.catalog.Match("otlp.codex.user_prompt.v1.log.model.request")
	if !ok {
		t.Fatal("generated Codex user-prompt match missing")
	}
	leaf, source := inboundFixtureLeafForMatch(t, match)
	leaf.logRecord.TimeUnixNano = uint64(time.Now().Add(-time.Second).UnixNano())
	message := &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource:  &resourcepb.Resource{Attributes: inboundFixtureResourceAttributes(&leaf)},
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{leaf.logRecord}}},
	}}}
	accounting, err := api.importDecodedOTLPRequestV8(context.Background(), message, otelSignalLogs, source, time.Now().UTC())
	if err != nil || !accounting.valid() || accounting.imported != 1 {
		t.Fatalf("connector-log accounting = %+v err=%v", accounting, err)
	}
	database, err := sql.Open("sqlite", fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var eventName, bucket string
	if err = database.QueryRow(`SELECT event_name, bucket FROM audit_events WHERE event_name = 'model.request'`).Scan(&eventName, &bucket); err != nil {
		t.Fatal(err)
	}
	if eventName != "model.request" || bucket != "model.io" {
		t.Fatalf("imported connector log = %q/%q", bucket, eventName)
	}
}

func TestOTLPInboundConnectorPromptPreservesDeclaredLifecycleCorrelation(t *testing.T) {
	previousInstance := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("otlp-inbound-log-lifecycle-test")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstance) })

	fixture := newOTLPV8MetricFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	classifier := mustOTLPInboundClassifierV8(t)
	match, ok := classifier.catalog.Match("otlp.codex.user_prompt.v1.log.model.request")
	if !ok {
		t.Fatal("generated Codex user-prompt match missing")
	}
	leaf, source := inboundFixtureLeafForMatch(t, match)
	now := time.Now().UTC()
	leaf.logRecord.TimeUnixNano = uint64(now.UnixNano())
	leaf.logRecord.Body = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "follow-up prompt"}}
	leaf.logRecord.Attributes = append(leaf.logRecord.Attributes,
		otlpClassifierStringAttribute("gen_ai.conversation.id", "conversation-1"),
		otlpClassifierStringAttribute("gen_ai.agent.id", "agent-child"),
		otlpClassifierStringAttribute("gen_ai.agent.name", "reviewer"),
		otlpClassifierStringAttribute("defenseclaw.agent.root.id", "agent-root"),
		otlpClassifierStringAttribute("defenseclaw.agent.parent.id", "agent-parent"),
		otlpClassifierStringAttribute("defenseclaw.agent.lineage.provenance", "reported"),
		otlpClassifierStringAttribute("defenseclaw.agent.lifecycle.id", "lifecycle-child"),
		otlpClassifierStringAttribute("defenseclaw.agent.execution.id", "execution-child"),
		otlpClassifierStringAttribute("defenseclaw.request.id", "request-2"),
		otlpClassifierStringAttribute("defenseclaw.turn.id", "turn-2"),
		otlpClassifierStringAttribute("defenseclaw.operation.id", "operation-2"),
		otlpClassifierIntAttribute("defenseclaw.agent.depth", 2),
	)
	message := &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource:  &resourcepb.Resource{Attributes: inboundFixtureResourceAttributes(&leaf)},
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{leaf.logRecord}}},
	}}}
	accounting, err := api.importDecodedOTLPRequestV8(
		context.Background(), message, otelSignalLogs, source, now,
	)
	if err != nil || accounting.imported != 1 || !accounting.valid() {
		t.Fatalf("connector prompt accounting=%+v err=%v", accounting, err)
	}

	record := inboundStoredProjectedRecord(t, fixture.path, source, "model.request")
	body, ok := record["body"].(map[string]any)
	if !ok {
		t.Fatalf("body=%#v", record["body"])
	}
	want := map[string]any{
		"gen_ai.conversation.id":               "conversation-1",
		"gen_ai.agent.id":                      "agent-child",
		"gen_ai.agent.name":                    "reviewer",
		"defenseclaw.agent.root.id":            "agent-root",
		"defenseclaw.agent.parent.id":          "agent-parent",
		"defenseclaw.agent.lineage.provenance": "reported",
		"defenseclaw.agent.lifecycle.id":       "lifecycle-child",
		"defenseclaw.agent.execution.id":       "execution-child",
		"defenseclaw.request.id":               "request-2",
		"defenseclaw.turn.id":                  "turn-2",
		"defenseclaw.operation.id":             "operation-2",
		"defenseclaw.agent.depth":              float64(2),
	}
	for key, expected := range want {
		if got := body[key]; got != expected {
			t.Errorf("%s=%#v want=%#v; body=%#v", key, got, expected, body)
		}
	}
}

func TestOTLPInboundConnectorLogMatrix(t *testing.T) {
	previousInstance := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("otlp-inbound-connector-log-matrix")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstance) })

	fixture := newOTLPV8MetricFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	classifier := mustOTLPInboundClassifierV8(t)
	tests := []struct {
		matchID       string
		content       string
		eventName     string
		outcome       string
		requestID     string
		reportedKey   string
		stateKey      string
		oppositeKey   string
		oppositeState string
	}{
		{"otlp.codex.user_prompt.v1.log.model.request", "codex prompt", "model.request", "attempted", "request-1", "defenseclaw.telemetry.input.reported", "defenseclaw.content.input.state", "defenseclaw.telemetry.output.reported", "defenseclaw.content.output.state"},
		{"otlp.claudecode.user_prompt.v1.log.model.request", "claude prompt", "model.request", "attempted", "", "defenseclaw.telemetry.input.reported", "defenseclaw.content.input.state", "defenseclaw.telemetry.output.reported", "defenseclaw.content.output.state"},
		{"otlp.codex.response_completed.v1.log.model.response", "codex response", "model.response", "completed", "", "defenseclaw.telemetry.output.reported", "defenseclaw.content.output.state", "defenseclaw.telemetry.input.reported", "defenseclaw.content.input.state"},
	}
	now := time.Now().UTC()
	for index, test := range tests {
		match, ok := classifier.catalog.Match(test.matchID)
		if !ok {
			t.Fatalf("generated connector match %q missing", test.matchID)
		}
		leaf, source := inboundFixtureLeafForMatch(t, match)
		if test.matchID == "otlp.codex.response_completed.v1.log.model.response" {
			// The exact Codex class requires the parsed completion record's
			// decimal-string token fields. A generic `present` fixture value is
			// intentionally rejected by the Codex-only strict coercion path.
			setInboundFixtureAttribute(leaf.logRecord, "input_token_count", "17")
			setInboundFixtureAttribute(leaf.logRecord, "output_token_count", "23")
		}
		leaf.logRecord.TimeUnixNano = uint64(now.Add(time.Duration(index) * time.Nanosecond).UnixNano())
		leaf.logRecord.Body = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: test.content}}
		leaf.logRecord.Attributes = append(leaf.logRecord.Attributes,
			otlpClassifierStringAttribute("session_id", "session-1"),
			otlpClassifierStringAttribute("turn_id", "turn-1"),
		)
		if test.requestID != "" {
			leaf.logRecord.Attributes = append(leaf.logRecord.Attributes,
				otlpClassifierStringAttribute("request.id", test.requestID),
			)
		}
		message := &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
			Resource:  &resourcepb.Resource{Attributes: inboundFixtureResourceAttributes(&leaf)},
			ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{leaf.logRecord}}},
		}}}
		accounting, err := api.importDecodedOTLPRequestV8(
			context.Background(), message, otelSignalLogs, source, now,
		)
		acceptedPrimary := accounting.imported + accounting.importedAndDerived
		if err != nil || acceptedPrimary != 1 || !accounting.valid() {
			t.Fatalf("%s accounting=%+v err=%v", test.matchID, accounting, err)
		}
		if test.matchID == "otlp.codex.response_completed.v1.log.model.response" &&
			accounting.derivativeNoObservation != 1 {
			t.Fatalf("%s missing no-hook derivative accounting: %+v", test.matchID, accounting)
		}

		record := inboundStoredProjectedRecord(t, fixture.path, source, test.eventName)
		if record["outcome"] != test.outcome {
			t.Fatalf("%s outcome=%#v", test.matchID, record["outcome"])
		}
		correlation, ok := record["correlation"].(map[string]any)
		if !ok || correlation["session_id"] != "session-1" || correlation["turn_id"] != "turn-1" {
			t.Fatalf("%s correlation=%#v", test.matchID, record["correlation"])
		}
		requestID, requestPresent := correlation["request_id"]
		if test.requestID == "" && requestPresent {
			t.Fatalf("%s turn leaked into request_id=%#v; correlation=%#v", test.matchID, requestID, correlation)
		}
		if test.requestID != "" && requestID != test.requestID {
			t.Fatalf("%s request_id=%#v want %q; correlation=%#v", test.matchID, requestID, test.requestID, correlation)
		}
		body, ok := record["body"].(map[string]any)
		if !ok || body[test.reportedKey] != true || body[test.stateKey] != "preserved" ||
			body[test.oppositeKey] != false || body[test.oppositeState] != "not_reported" {
			t.Fatalf("%s content flags=%#v", test.matchID, record["body"])
		}
	}

	codexPrompt, ok := classifier.catalog.Match("otlp.codex.user_prompt.v1.log.model.request")
	if !ok {
		t.Fatal("generated Codex prompt match missing")
	}
	wrongSource, _ := inboundFixtureLeafForMatch(t, codexPrompt)
	classification, err := classifier.classify(wrongSource, "claudecode")
	if err != nil || classification.identityState != otlpInboundIdentityUnsupported {
		t.Fatalf("wrong source state=%d err=%v", classification.identityState, err)
	}
	wrongEvent, source := inboundFixtureLeafForMatch(t, codexPrompt)
	wrongEvent.leafAttributes.values["event.name"] = &commonpb.AnyValue{
		Value: &commonpb.AnyValue_StringValue{StringValue: "codex.user_prompt.extra"},
	}
	classification, err = classifier.classify(wrongEvent, source)
	if err != nil || classification.identityState != otlpInboundIdentityUnsupported {
		t.Fatalf("wrong event state=%d err=%v", classification.identityState, err)
	}

	conflict, source := inboundFixtureLeafForMatch(t, codexPrompt)
	conflict.logRecord.Body = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "prompt"}}
	conflict.logRecord.Attributes = append(conflict.logRecord.Attributes,
		otlpClassifierStringAttribute("session_id", "session-a"),
		otlpClassifierStringAttribute("gen_ai.conversation.id", "session-b"),
	)
	message := &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource:  &resourcepb.Resource{Attributes: inboundFixtureResourceAttributes(&conflict)},
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{conflict.logRecord}}},
	}}}
	accounting, err := api.importDecodedOTLPRequestV8(
		context.Background(), message, otelSignalLogs, source, now,
	)
	if err != nil || accounting.invalidMappedField != 1 || !accounting.valid() {
		t.Fatalf("alias conflict accounting=%+v err=%v", accounting, err)
	}
}

func inboundStoredProjectedRecord(t *testing.T, path, connector, eventName string) map[string]any {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var encoded string
	if err := database.QueryRow(`
		SELECT projected_record_json FROM audit_events
		WHERE connector = ? AND event_name = ? ORDER BY rowid DESC LIMIT 1`,
		connector, eventName,
	).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(encoded), &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestOTLPInboundSourceTimestampFutureBoundary(t *testing.T) {
	previousInstance := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("otlp-inbound-time-test")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstance) })

	fixture := newOTLPV8MetricFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	classifier := mustOTLPInboundClassifierV8(t)
	match, ok := classifier.catalog.Match("otlp.codex.user_prompt.v1.log.model.request")
	if !ok {
		t.Fatal("generated Codex user-prompt match missing")
	}
	receipt := time.Now().UTC().Truncate(time.Nanosecond)
	importAt := func(sourceTime time.Time) otlpInboundBatchAccounting {
		leaf, source := inboundFixtureLeafForMatch(t, match)
		leaf.logRecord.TimeUnixNano = uint64(sourceTime.UnixNano())
		message := &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
			Resource:  &resourcepb.Resource{Attributes: inboundFixtureResourceAttributes(&leaf)},
			ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{leaf.logRecord}}},
		}}}
		accounting, err := api.importDecodedOTLPRequestV8(context.Background(), message, otelSignalLogs, source, receipt)
		if err != nil {
			t.Fatalf("import at %s: %v", sourceTime, err)
		}
		return accounting
	}
	if accounting := importAt(receipt.Add(5 * time.Minute)); accounting.imported != 1 {
		t.Fatalf("+5m boundary accounting = %+v", accounting)
	}
	if accounting := importAt(receipt.Add(5*time.Minute + time.Nanosecond)); accounting.invalidRecord != 1 {
		t.Fatalf("+5m+1ns boundary accounting = %+v", accounting)
	}
}

func TestOTLPInboundPR403TopologyAndMissingData(t *testing.T) {
	previousInstance := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("otlp-inbound-trace-test")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstance) })

	fixture := newOTLPTraceFixture(t, "always_on", true, nil)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	classifier := mustOTLPInboundClassifierV8(t)
	match, ok := classifier.catalog.Match("otlp.genai.span.operation.v1.span.model.chat")
	if !ok {
		t.Fatal("generated GenAI chat span match missing")
	}
	leaf, source := inboundFixtureLeafForMatch(t, match)
	now := time.Now().UTC()
	leaf.span.StartTimeUnixNano = uint64(now.Add(-time.Second).UnixNano())
	leaf.span.EndTimeUnixNano = uint64(now.UnixNano())
	leaf.span.Kind = tracepb.Span_SPAN_KIND_CLIENT
	leaf.span.ParentSpanId = []byte{2, 0, 0, 0, 0, 0, 0, 2}
	message := &collectortracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource:   &resourcepb.Resource{Attributes: inboundFixtureResourceAttributes(&leaf)},
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{leaf.span}}},
	}}}
	accounting, err := api.importDecodedOTLPRequestV8(context.Background(), message, otelSignalTraces, source, now)
	if err != nil || accounting.imported != 1 {
		t.Fatalf("trace accounting = %+v err=%v", accounting, err)
	}
	spans := fixture.pipelines.capture(t, 1).snapshot()
	if len(spans) != 1 || spans[0].Record().EventName() != "span.model.chat" {
		t.Fatalf("imported traces = %#v", spans)
	}
	if parent, present := spans[0].ParentSpanID(); !present || parent.String() != "0200000000000002" {
		t.Fatalf("parent topology = %q present=%t", parent, present)
	}
	body, present := spans[0].Record().Body()
	if !present {
		t.Fatal("generic GenAI span body absent")
	}
	object, err := body.Object()
	if err != nil {
		t.Fatal(err)
	}
	attributes := object["attributes"].(map[string]any)
	for _, absent := range []string{
		"defenseclaw.agent.root.id", "defenseclaw.agent.parent.id",
		"defenseclaw.agent.execution.id", "defenseclaw.turn.id", "gen_ai.tool.call.id",
	} {
		if value, exists := attributes[absent]; exists {
			t.Fatalf("generic GenAI span fabricated %s=%#v", absent, value)
		}
	}
}

func TestOTLPInboundIdentityTimeAndProvenance(t *testing.T) {
	previousInstance := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("otlp-inbound-identity-test")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstance) })

	fixture := newOTLPTraceFixture(t, "always_on", true, nil)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	classifier := mustOTLPInboundClassifierV8(t)
	wire := classifier.catalog.WireContract()
	match, ok := classifier.catalog.Match("otlp.genai.span.operation.v1.span.model.chat")
	if !ok {
		t.Fatal("generated GenAI chat span match missing")
	}
	leaf, source := inboundFixtureLeafForMatch(t, match)
	receipt := time.Now().UTC()
	end := receipt.Add(-time.Second)
	leaf.span.StartTimeUnixNano = uint64(end.Add(-time.Second).UnixNano())
	leaf.span.EndTimeUnixNano = uint64(end.UnixNano())
	leaf.span.Kind = tracepb.Span_SPAN_KIND_CLIENT
	leaf.span.Attributes = append(leaf.span.Attributes,
		otlpClassifierStringAttribute(wire.RecordIDKey, "sender-record-id"),
	)
	message := &collectortracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource:   &resourcepb.Resource{Attributes: inboundFixtureResourceAttributes(&leaf)},
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{leaf.span}}},
	}}}
	accounting, err := api.importDecodedOTLPRequestV8(
		context.Background(), message, otelSignalTraces, source, receipt,
	)
	if err != nil || accounting.imported != 1 || !accounting.valid() {
		t.Fatalf("identity accounting=%+v err=%v", accounting, err)
	}
	spans := fixture.pipelines.capture(t, 1).snapshot()
	if len(spans) != 1 {
		t.Fatalf("identity captured spans=%d", len(spans))
	}
	record := spans[0].Record()
	if record.RecordID() == "" || record.RecordID() == "sender-record-id" || record.Source() != observability.SourceOTelReceiver ||
		!record.Timestamp().Equal(end) {
		t.Fatalf("local identity id=%q source=%q timestamp=%s", record.RecordID(), record.Source(), record.Timestamp())
	}
	if record.Correlation().SidecarInstanceID != "otlp-trace-test" ||
		record.Correlation().TraceID != "01000000000000000000000000000001" ||
		record.Correlation().SpanID != "0100000000000001" {
		t.Fatalf("local correlation=%#v", record.Correlation())
	}
	provenance := record.Provenance()
	if provenance.Producer != "defenseclaw" || provenance.BinaryVersion != "8.0.0" ||
		provenance.ConfigGeneration != 1 || provenance.ConfigDigest == "" || provenance.Import == nil {
		t.Fatalf("local provenance=%#v", provenance)
	}
	if provenance.Import.AuthenticatedSource != "fixture-source" || provenance.Import.UpstreamRecordID != "" ||
		provenance.Import.UpstreamInstanceID != "" || provenance.Import.LastHopInstanceID != "" ||
		provenance.Import.LastHopDestination != "" || provenance.Import.IngressHopCount != 0 {
		t.Fatalf("external absence provenance=%#v", provenance.Import)
	}

	nativeMatch, ok := classifier.catalog.Match("otlp.native.span.v8.span.config.reload")
	if !ok {
		t.Fatal("native config-reload match missing")
	}
	native, nativeSource := inboundFixtureLeafForMatch(t, nativeMatch)
	native.resource.attributes.values[wire.SemanticInstanceKey] = &commonpb.AnyValue{
		Value: &commonpb.AnyValue_StringValue{StringValue: "semantic-upstream"},
	}
	native.leafAttributes.values[wire.ForwardInstanceKey] = &commonpb.AnyValue{
		Value: &commonpb.AnyValue_StringValue{StringValue: "immediate-forwarder"},
	}
	native.leafAttributes.values[wire.ForwardDestinationKey] = &commonpb.AnyValue{
		Value: &commonpb.AnyValue_StringValue{StringValue: "collector-a"},
	}
	native.leafAttributes.values[wire.ForwardHopCountKey] = &commonpb.AnyValue{
		Value: &commonpb.AnyValue_IntValue{IntValue: 2},
	}
	nativeProvenance, err := inboundImportProvenanceV8(
		native, nativeMatch, nativeMatch.Targets()[0], wire, nativeSource,
	)
	if err != nil {
		t.Fatal(err)
	}
	if nativeProvenance.UpstreamInstanceID != "semantic-upstream" ||
		nativeProvenance.LastHopInstanceID != "immediate-forwarder" ||
		nativeProvenance.LastHopDestination != "collector-a" || nativeProvenance.IngressHopCount != 2 ||
		nativeProvenance.UpstreamRecordID != "" {
		t.Fatalf("native semantic/forward provenance=%#v", nativeProvenance)
	}
}

func TestOTLPInboundGenAISpanFamilyMatrix(t *testing.T) {
	previousInstance := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("otlp-inbound-genai-matrix-test")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstance) })

	fixture := newOTLPTraceFixture(t, "always_on", true, nil)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	classifier := mustOTLPInboundClassifierV8(t)
	tests := []struct {
		matchID string
		bucket  observability.Bucket
		family  observability.EventName
		name    string
		wire    tracepb.Span_SpanKind
		kind    trace.SpanKind
	}{
		{"otlp.genai.span.operation.v1.span.agent.invoke", observability.BucketAgentLifecycle, "span.agent.invoke", "invoke_agent present", tracepb.Span_SPAN_KIND_CLIENT, trace.SpanKindClient},
		{"otlp.genai.span.operation.v1.span.model.chat", observability.BucketModelIO, "span.model.chat", "chat present", tracepb.Span_SPAN_KIND_CLIENT, trace.SpanKindClient},
		{"otlp.genai.span.operation.v1.span.model.embeddings", observability.BucketModelIO, "span.model.embeddings", "embeddings present", tracepb.Span_SPAN_KIND_CLIENT, trace.SpanKindClient},
		{"otlp.genai.span.operation.v1.span.tool.execute", observability.BucketToolActivity, "span.tool.execute", "execute_tool present", tracepb.Span_SPAN_KIND_CLIENT, trace.SpanKindClient},
		{"otlp.genai.span.operation.v1.span.retrieval.search", observability.BucketToolActivity, "span.retrieval.search", "retrieve present", tracepb.Span_SPAN_KIND_CLIENT, trace.SpanKindClient},
		{"otlp.genai.span.operation.v1.span.workflow.run", observability.BucketAgentLifecycle, "span.workflow.run", "workflow present", tracepb.Span_SPAN_KIND_INTERNAL, trace.SpanKindInternal},
	}
	now := time.Now().UTC()
	for index, test := range tests {
		match, ok := classifier.catalog.Match(test.matchID)
		if !ok {
			t.Fatalf("generated GenAI match %q missing", test.matchID)
		}
		leaf, source := inboundFixtureLeafForMatch(t, match)
		leaf.span.TraceId[1] = byte(index + 1)
		leaf.span.SpanId[1] = byte(index + 1)
		leaf.span.StartTimeUnixNano = uint64(now.Add(-time.Second).UnixNano())
		leaf.span.EndTimeUnixNano = uint64(now.UnixNano())
		leaf.span.Kind = test.wire
		message := &collectortracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
			Resource:   &resourcepb.Resource{Attributes: inboundFixtureResourceAttributes(&leaf)},
			ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{leaf.span}}},
		}}}
		accounting, err := api.importDecodedOTLPRequestV8(
			context.Background(), message, otelSignalTraces, source, now,
		)
		if err != nil || accounting.imported != 1 || !accounting.valid() {
			t.Fatalf("%s accounting=%+v err=%v", test.matchID, accounting, err)
		}
		spans := fixture.pipelines.capture(t, 1).snapshot()
		if len(spans) != index+1 {
			t.Fatalf("%s captured spans=%d want=%d", test.matchID, len(spans), index+1)
		}
		got := spans[index]
		if got.Record().Bucket() != test.bucket || got.Record().EventName() != test.family ||
			got.Name() != test.name || got.Kind() != test.kind {
			t.Fatalf("%s identity=%s/%s name=%q kind=%s", test.matchID,
				got.Record().Bucket(), got.Record().EventName(), got.Name(), got.Kind())
		}
	}

	chat, ok := classifier.catalog.Match("otlp.genai.span.operation.v1.span.model.chat")
	if !ok {
		t.Fatal("generated GenAI chat span match missing")
	}
	missingOperation, source := inboundFixtureLeafForMatch(t, chat)
	delete(missingOperation.leafAttributes.values, "gen_ai.operation.name")
	missingOperation.span.Name = "chat present"
	classification, err := classifier.classify(missingOperation, source)
	if err != nil || classification.identityState != otlpInboundIdentityUnsupported {
		t.Fatalf("heuristic span name classified as state=%d err=%v", classification.identityState, err)
	}
}

func TestOTLPInboundTraceMappingRejectsMissingPinnedPrivateFactsBeforeConstruction(t *testing.T) {
	api := &APIServer{}
	classifier := mustOTLPInboundClassifierV8(t)
	match, ok := classifier.catalog.Match("otlp.genai.span.operation.v1.span.model.chat")
	if !ok {
		t.Fatal("generated GenAI chat span match missing")
	}
	leaf, source := inboundFixtureLeafForMatch(t, match)
	now := time.Now().UTC()
	leaf.span.StartTimeUnixNano = uint64(now.Add(-time.Second).UnixNano())
	leaf.span.EndTimeUnixNano = uint64(now.UnixNano())
	leaf.span.Kind = tracepb.Span_SPAN_KIND_CLIENT
	targets := match.Targets()
	if len(targets) == 0 {
		t.Fatal("generated GenAI chat target missing")
	}
	var occurrenceIDs int
	if _, _, err := api.mapInboundTraceV8(
		leaf, match, targets[0], classifier.catalog.WireContract(), source, now,
		observabilityruntime.EmitContext{},
	); err == nil {
		occurrenceIDs++
	}
	if occurrenceIDs != 0 {
		t.Fatalf("missing private facts reached occurrence construction: %d", occurrenceIDs)
	}
}

func TestOTLPInboundTraceCustomResourceNativeAndExternalBoundaries(t *testing.T) {
	classifier := mustOTLPInboundClassifierV8(t)
	wire := classifier.catalog.WireContract()

	native, ok := classifier.catalog.Match("otlp.native.span.v8.span.config.reload")
	if !ok {
		t.Fatal("native config-reload span match missing")
	}
	nativeLeaf, _ := inboundFixtureLeafForMatch(t, native)
	setInboundFixtureResourceAttribute(&nativeLeaf, "operator.profile", "soc")
	custom, preserved, err := mapInboundTraceCustomResourceV8(
		nativeLeaf, native, native.Targets()[0], wire,
	)
	if err != nil {
		t.Fatal(err)
	}
	sealed, present := custom.Get()
	if !present || sealed.Values()["operator.profile"] != "soc" {
		t.Fatalf("native custom = %#v present=%v", sealed.Values(), present)
	}
	if _, present := preserved["operator.profile"]; !present {
		t.Fatal("native custom key counted as dropped")
	}

	collision := nativeLeaf
	setInboundFixtureResourceAttribute(&collision, "service-name", "forged")
	if _, _, err := mapInboundTraceCustomResourceV8(
		collision, native, native.Targets()[0], wire,
	); err == nil {
		t.Fatal("native normalized fixed/custom collision must reject")
	}
	malformed := nativeLeaf
	attributes := inboundFixtureResourceAttributes(&malformed)
	attributes = append(attributes, &commonpb.KeyValue{
		Key: "operator.level", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: 7}},
	})
	setInboundFixtureResourceAttributes(&malformed, attributes)
	if _, _, err := mapInboundTraceCustomResourceV8(
		malformed, native, native.Targets()[0], wire,
	); err == nil {
		t.Fatal("native malformed custom type must reject")
	}
	wrongSchema := nativeLeaf
	wrongSchema.resource.schemaURL = "https://example.test/wrong"
	if _, _, err := mapInboundTraceCustomResourceV8(
		wrongSchema, native, native.Targets()[0], wire,
	); err == nil {
		t.Fatal("native resource schema URL mismatch must reject")
	}

	external, ok := classifier.catalog.Match("otlp.genai.span.operation.v1.span.model.chat")
	if !ok {
		t.Fatal("external GenAI chat span match missing")
	}
	externalLeaf, _ := inboundFixtureLeafForMatch(t, external)
	setInboundFixtureResourceAttribute(&externalLeaf, "operator.profile", "external")
	externalAttributes := inboundFixtureResourceAttributes(&externalLeaf)
	externalAttributes = append(externalAttributes,
		&commonpb.KeyValue{Key: "operator.level", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: 7}}},
		otlpClassifierStringAttribute("service-name", "forged"),
	)
	setInboundFixtureResourceAttributes(&externalLeaf, externalAttributes)
	externalCustom, externalPreserved, err := mapInboundTraceCustomResourceV8(
		externalLeaf, external, external.Targets()[0], wire,
	)
	if err != nil {
		t.Fatal(err)
	}
	externalSealed, present := externalCustom.Get()
	if !present || externalSealed.Values()["operator.profile"] != "external" ||
		len(externalSealed.Values()) != 1 {
		t.Fatalf("external custom = %#v present=%v", externalSealed.Values(), present)
	}
	if _, present := externalPreserved["operator.level"]; present {
		t.Fatal("external malformed custom type was preserved")
	}
	if _, present := externalPreserved["service-name"]; present {
		t.Fatal("external reserved/custom collision was preserved")
	}
}

func TestOTLPInboundUnknownFieldsDropAndCount(t *testing.T) {
	previousInstance := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("otlp-inbound-unknown-fields-test")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstance) })

	fixture := newOTLPTraceFixture(t, "always_on", true, nil)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	classifier := mustOTLPInboundClassifierV8(t)
	match, ok := classifier.catalog.Match("otlp.genai.span.operation.v1.span.model.chat")
	if !ok {
		t.Fatal("generated GenAI chat span match missing")
	}
	leaf, source := inboundFixtureLeafForMatch(t, match)
	now := time.Now().UTC()
	leaf.span.StartTimeUnixNano = uint64(now.Add(-time.Second).UnixNano())
	leaf.span.EndTimeUnixNano = uint64(now.UnixNano())
	leaf.span.Kind = tracepb.Span_SPAN_KIND_CLIENT
	leaf.span.DroppedAttributesCount = 4
	leaf.span.Attributes = append(leaf.span.Attributes,
		otlpClassifierStringAttribute("sender.unknown.span", "drop-me"),
	)
	resourceAttributes := append(inboundFixtureResourceAttributes(&leaf), &commonpb.KeyValue{
		Key:   "sender.unknown.resource",
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: 7}},
	})
	message := &collectortracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: &resourcepb.Resource{
			Attributes: resourceAttributes, DroppedAttributesCount: 5,
		},
		ScopeSpans: []*tracepb.ScopeSpans{{
			Scope: &commonpb.InstrumentationScope{
				Attributes:             []*commonpb.KeyValue{otlpClassifierStringAttribute("sender.unknown.scope", "drop-me")},
				DroppedAttributesCount: 6,
			},
			Spans: []*tracepb.Span{leaf.span},
		}},
	}}}
	accounting, err := api.importDecodedOTLPRequestV8(
		context.Background(), message, otelSignalTraces, source, now,
	)
	if err != nil || accounting.imported != 1 || accounting.unknownFieldsDropped != 3 || !accounting.valid() {
		t.Fatalf("unknown-field accounting=%+v err=%v", accounting, err)
	}
	spans := fixture.pipelines.capture(t, 1).snapshot()
	if len(spans) != 1 {
		t.Fatalf("unknown-field captured spans=%d", len(spans))
	}
	body, present := spans[0].Record().Body()
	if !present {
		t.Fatal("unknown-field record body absent")
	}
	object, err := body.Object()
	if err != nil {
		t.Fatal(err)
	}
	resource := object["resource"].(map[string]any)
	scope := object["scope"].(map[string]any)
	if object["dropped_attributes_count"] != json.Number("5") ||
		resource["dropped_attributes_count"] != json.Number("6") ||
		scope["dropped_attributes_count"] != json.Number("7") {
		t.Fatalf("canonical dropped counts span=%#v resource=%#v scope=%#v",
			object["dropped_attributes_count"], resource["dropped_attributes_count"], scope["dropped_attributes_count"])
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"sender.unknown.span", "sender.unknown.resource", "sender.unknown.scope", "drop-me"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("unknown input %q survived canonical body: %s", forbidden, encoded)
		}
	}

	duplicate, source := inboundFixtureLeafForMatch(t, match)
	duplicate.span.StartTimeUnixNano = uint64(now.Add(-time.Second).UnixNano())
	duplicate.span.EndTimeUnixNano = uint64(now.UnixNano())
	duplicate.span.Kind = tracepb.Span_SPAN_KIND_CLIENT
	duplicate.span.Attributes = append(duplicate.span.Attributes,
		otlpClassifierStringAttribute("gen_ai.operation.name", "embeddings"),
	)
	duplicateMessage := &collectortracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource:   &resourcepb.Resource{Attributes: inboundFixtureResourceAttributes(&duplicate)},
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{duplicate.span}}},
	}}}
	accounting, err = api.importDecodedOTLPRequestV8(
		context.Background(), duplicateMessage, otelSignalTraces, source, now,
	)
	if err != nil || accounting.unsupportedIdentity != 1 || !accounting.valid() {
		t.Fatalf("duplicate registered key accounting=%+v err=%v", accounting, err)
	}
	if got := len(fixture.pipelines.capture(t, 1).snapshot()); got != 1 {
		t.Fatalf("duplicate registered key emitted %d extra spans", got-1)
	}
}

func TestOTLPInboundClaudeTokenMetricDerivesCanonicalObservation(t *testing.T) {
	previousInstance := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("otlp-inbound-metric-test")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstance) })

	fixture := newOTLPV8MetricFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC()
	point := &metricspb.NumberDataPoint{
		TimeUnixNano: uint64(now.UnixNano()),
		Attributes: []*commonpb.KeyValue{
			otlpClassifierStringAttribute("type", "cacheRead"),
			otlpClassifierStringAttribute("model", "claude-opus"),
		},
		Value: &metricspb.NumberDataPoint_AsInt{AsInt: 41},
	}
	message := &collectormetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			otlpClassifierStringAttribute("service.name", "claude-code"),
			otlpClassifierStringAttribute("service.instance.id", "claude-instance"),
		}},
		ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
			Name: "claude_code.token.usage", Unit: "{token}",
			Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{point}}},
		}}}},
	}}}
	accounting, err := api.importDecodedOTLPRequestV8(context.Background(), message, otelSignalMetrics, "claudecode", now)
	if err != nil || accounting.derivedOnly != 1 || accounting.derivativeRecorded != 1 {
		t.Fatalf("Claude metric accounting = %+v err=%v", accounting, err)
	}
	metrics := fixture.pipelines.sinks(t, 1).local.snapshot()
	if len(metrics) != 1 || metrics[0].Descriptor().Name != "gen_ai.client.token.usage" {
		t.Fatalf("derived metrics = %#v", metrics)
	}
	attributes := metrics[0].Attributes()
	if attributes["gen_ai.token.type"] != "cacheRead" || attributes["gen_ai.request.model"] != "claude-opus" {
		t.Fatalf("derived metric labels = %#v", attributes)
	}
}

func TestOTLPInboundHistogramMeanIsExplicitDerivation(t *testing.T) {
	previousInstance := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("otlp-inbound-histogram-mean-test")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstance) })

	fixture := newOTLPV8MetricFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC()
	sum := 8000.0
	point := &metricspb.HistogramDataPoint{
		TimeUnixNano: uint64(now.UnixNano()), Count: 4, Sum: &sum,
		ExplicitBounds: []float64{1000, 2000, 3000}, BucketCounts: []uint64{1, 1, 1, 1},
	}
	message := &collectormetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			otlpClassifierStringAttribute("service.name", "codex"),
		}},
		ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
			Name: "gen_ai.client.operation.duration", Unit: "ms",
			Data: &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{
				AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
				DataPoints:             []*metricspb.HistogramDataPoint{point},
			}},
		}}}},
	}}}
	accounting, err := api.importDecodedOTLPRequestV8(
		context.Background(), message, otelSignalMetrics, "codex", now,
	)
	if err != nil || accounting.derivedOnly != 1 || accounting.derivativeRecorded != 1 || !accounting.valid() {
		t.Fatalf("histogram accounting=%+v err=%v", accounting, err)
	}
	metrics := fixture.pipelines.sinks(t, 1).local.snapshot()
	if len(metrics) != 1 || metrics[0].Descriptor().Name != "gen_ai.client.operation.duration" {
		t.Fatalf("histogram derived metrics=%#v", metrics)
	}
	value, ok := metrics[0].Value().Double()
	if !ok || value != 2 {
		t.Fatalf("histogram mean value=%v double=%t, want 2s", value, ok)
	}
	provenance := metrics[0].CanonicalRecord().Provenance()
	if provenance.Import == nil || provenance.Import.Derivation != observability.ImportDerivationArithmeticMean {
		t.Fatalf("histogram provenance=%#v", provenance.Import)
	}
	count, present := provenance.Import.SourceAggregateCount.Get()
	if !present || count != 4 {
		t.Fatalf("histogram aggregate count=%d present=%t", count, present)
	}
}

func TestOTLPInboundPR412DerivedMetricMatrix(t *testing.T) {
	previousInstance := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("otlp-inbound-pr412-matrix-test")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstance) })

	fixture := newOTLPV8MetricFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC()
	units := []struct {
		unit  string
		value float64
	}{
		{"", 2}, {"s", 2}, {"second", 2}, {"seconds", 2},
		{"ms", 2000}, {"millisecond", 2000}, {"milliseconds", 2000},
		{"us", 2_000_000}, {"microsecond", 2_000_000}, {"microseconds", 2_000_000},
		{"ns", 2_000_000_000}, {"nanosecond", 2_000_000_000}, {"nanoseconds", 2_000_000_000},
	}
	durationMetrics := make([]*metricspb.Metric, 0, len(units))
	for _, unit := range units {
		durationMetrics = append(durationMetrics, &metricspb.Metric{
			Name: "gen_ai.client.operation.duration", Unit: unit.unit,
			Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{
				TimeUnixNano: uint64(now.UnixNano()),
				Attributes: []*commonpb.KeyValue{
					otlpClassifierStringAttribute("gen_ai.operation.name", "chat"),
					otlpClassifierStringAttribute("gen_ai.provider.name", "openai"),
					otlpClassifierStringAttribute("gen_ai.request.model", "gpt-5"),
				},
				Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: unit.value},
			}}}},
		})
	}
	durationMessage := &collectormetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			otlpClassifierStringAttribute("service.name", "codex"),
		}},
		ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: durationMetrics}},
	}}}
	accounting, err := api.importDecodedOTLPRequestV8(
		context.Background(), durationMessage, otelSignalMetrics, "codex", now,
	)
	if err != nil || accounting.derivedOnly != int64(len(units)) ||
		accounting.derivativeRecorded != int64(len(units)) || !accounting.valid() {
		t.Fatalf("duration matrix accounting=%+v err=%v", accounting, err)
	}

	tokenTypes := []string{"input", "output", "cacheRead", "cacheCreation"}
	tokenPoints := make([]*metricspb.NumberDataPoint, 0, len(tokenTypes))
	for index, tokenType := range tokenTypes {
		tokenPoints = append(tokenPoints, &metricspb.NumberDataPoint{
			TimeUnixNano: uint64(now.UnixNano()),
			Attributes: []*commonpb.KeyValue{
				otlpClassifierStringAttribute("type", tokenType),
				otlpClassifierStringAttribute("model", "claude-opus"),
			},
			Value: &metricspb.NumberDataPoint_AsInt{AsInt: int64(index + 1)},
		})
	}
	tokenMessage := &collectormetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			otlpClassifierStringAttribute("service.name", "claude-code"),
			otlpClassifierStringAttribute("service.instance.id", "claude-instance"),
		}},
		ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
			Name: "claude_code.token.usage", Unit: "{token}",
			Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: tokenPoints}},
		}}}},
	}}}
	accounting, err = api.importDecodedOTLPRequestV8(
		context.Background(), tokenMessage, otelSignalMetrics, "claudecode", now,
	)
	if err != nil || accounting.derivedOnly != int64(len(tokenTypes)) ||
		accounting.derivativeRecorded != int64(len(tokenTypes)) || !accounting.valid() {
		t.Fatalf("token matrix accounting=%+v err=%v", accounting, err)
	}

	metrics := fixture.pipelines.sinks(t, 1).local.snapshot()
	if len(metrics) != len(units)+len(tokenTypes) {
		t.Fatalf("PR412 metric count=%d want=%d", len(metrics), len(units)+len(tokenTypes))
	}
	for index := range units {
		metric := metrics[index]
		value, ok := metric.Value().Double()
		if metric.Descriptor().Name != "gen_ai.client.operation.duration" || !ok || value != 2 {
			t.Fatalf("duration[%d] descriptor=%s value=%v double=%t", index, metric.Descriptor().Name, value, ok)
		}
		attributes := metric.Attributes()
		if attributes["gen_ai.operation.name"] != "chat" || attributes["gen_ai.provider.name"] != "openai" ||
			attributes["gen_ai.request.model"] != "gpt-5" {
			t.Fatalf("duration[%d] labels=%#v", index, attributes)
		}
	}
	for index, tokenType := range tokenTypes {
		metric := metrics[len(units)+index]
		if metric.Descriptor().Name != "gen_ai.client.token.usage" ||
			metric.Attributes()["gen_ai.token.type"] != tokenType {
			t.Fatalf("token[%d] descriptor=%s labels=%#v", index, metric.Descriptor().Name, metric.Attributes())
		}
	}

	durationRequest := func(name, unit string) *collectormetricspb.ExportMetricsServiceRequest {
		point := &metricspb.NumberDataPoint{
			TimeUnixNano: uint64(now.UnixNano()),
			Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: 2},
		}
		metric := &metricspb.Metric{
			Name: name, Unit: unit,
			Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{
				DataPoints: []*metricspb.NumberDataPoint{point},
			}},
		}
		return &collectormetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
			ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{metric}}},
		}}}
	}
	for _, invalidUnit := range []string{"MS", " ms", "fortnight"} {
		accounting, err = api.importDecodedOTLPRequestV8(
			context.Background(), durationRequest("gen_ai.client.operation.duration", invalidUnit),
			otelSignalMetrics, "codex", now,
		)
		if err != nil || accounting.invalidRecord != 1 || accounting.derivativeInvalidRecord != 1 || !accounting.valid() {
			t.Fatalf("invalid unit %q accounting=%+v err=%v", invalidUnit, accounting, err)
		}
	}
	accounting, err = api.importDecodedOTLPRequestV8(
		context.Background(), durationRequest("prefix.gen_ai.client.operation.duration", "s"),
		otelSignalMetrics, "codex", now,
	)
	if err != nil || accounting.unsupportedIdentity != 1 || !accounting.valid() {
		t.Fatalf("substring instrument accounting=%+v err=%v", accounting, err)
	}
	if got := len(fixture.pipelines.sinks(t, 1).local.snapshot()); got != len(metrics) {
		t.Fatalf("invalid variants emitted %d additional metrics", got-len(metrics))
	}
}

func TestOTLPInboundDuplicateAndCumulativeSemantics(t *testing.T) {
	previousInstance := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("otlp-inbound-cumulative-test")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstance) })

	fixture := newOTLPV8MetricFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC()
	send := func(value int64, start uint64, serviceInstance, model string) otlpInboundBatchAccounting {
		t.Helper()
		point := &metricspb.NumberDataPoint{
			StartTimeUnixNano: start, TimeUnixNano: uint64(now.UnixNano()),
			Attributes: []*commonpb.KeyValue{
				otlpClassifierStringAttribute("type", "input"),
				otlpClassifierStringAttribute("model", model),
				otlpClassifierStringAttribute("conversation.id", "conversation-a"),
			},
			Value: &metricspb.NumberDataPoint_AsInt{AsInt: value},
		}
		message := &collectormetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
				otlpClassifierStringAttribute("service.name", "claude-code"),
				otlpClassifierStringAttribute("service.instance.id", serviceInstance),
			}},
			ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
				Name: "claude_code.token.usage", Unit: "tokens",
				Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{
					AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
					IsMonotonic:            true, DataPoints: []*metricspb.NumberDataPoint{point},
				}},
			}}}},
		}}}
		accounting, err := api.importDecodedOTLPRequestV8(
			context.Background(), message, otelSignalMetrics, "claudecode", now,
		)
		if err != nil || !accounting.valid() {
			t.Fatalf("cumulative value=%d accounting=%+v err=%v", value, accounting, err)
		}
		return accounting
	}

	startOne := uint64(now.Add(-time.Minute).UnixNano())
	if accounting := send(10, startOne, "instance-a", " Claude-4-Sonnet "); accounting.derivedOnly != 1 {
		t.Fatalf("first cumulative accounting=%+v", accounting)
	}
	if accounting := send(10, startOne, "instance-a", " Claude-4-Sonnet "); accounting.derivativeRecorded != 1 {
		t.Fatalf("repeat cumulative accounting=%+v", accounting)
	}
	if accounting := send(9, startOne, "instance-a", " Claude-4-Sonnet "); accounting.derivativeRecorded != 1 {
		t.Fatalf("older cumulative accounting=%+v", accounting)
	}
	send(15, startOne, "instance-a", " Claude-4-Sonnet ")
	startTwo := uint64(now.Add(-30 * time.Second).UnixNano())
	send(20, startTwo, "instance-a", " Claude-4-Sonnet ")
	// Service instance participates in the generated framed identity, so a
	// second process starts with its full cumulative value rather than
	// subtracting instance-a's state.
	send(7, startTwo, "instance-b", " Claude-4-Sonnet ")

	metrics := fixture.pipelines.sinks(t, 1).local.snapshot()
	values := make([]int64, 0, len(metrics))
	for _, metric := range metrics {
		if metric.Descriptor().Name != "gen_ai.client.token.usage" {
			continue
		}
		double, ok := metric.Value().Double()
		value := int64(double)
		if !ok || float64(value) != double {
			t.Fatalf("cumulative metric value arm=%#v", metric.Value())
		}
		values = append(values, value)
		attributes := metric.Attributes()
		if attributes["gen_ai.request.model"] != "claude-4" || attributes["gen_ai.token.type"] != "input" ||
			attributes["gen_ai.conversation.id"] != "conversation-a" {
			t.Fatalf("generated cumulative labels=%#v", attributes)
		}
	}
	if want := []int64{10, 5, 20, 7}; !reflect.DeepEqual(values, want) {
		t.Fatalf("cumulative deltas=%v want=%v", values, want)
	}

	traceFixture := newOTLPTraceFixture(t, "always_on", true, nil)
	traceAPI := &APIServer{}
	traceAPI.bindOTLPObservabilityRuntime(traceFixture.runtime)
	classifier := mustOTLPInboundClassifierV8(t)
	match, ok := classifier.catalog.Match("otlp.genai.span.operation.v1.span.model.chat")
	if !ok {
		t.Fatal("generated GenAI chat span match missing")
	}
	leaf, source := inboundFixtureLeafForMatch(t, match)
	leaf.span.StartTimeUnixNano = uint64(now.Add(-time.Second).UnixNano())
	leaf.span.EndTimeUnixNano = uint64(now.UnixNano())
	leaf.span.Kind = tracepb.Span_SPAN_KIND_CLIENT
	message := &collectortracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource:   &resourcepb.Resource{Attributes: inboundFixtureResourceAttributes(&leaf)},
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{leaf.span}}},
	}}}
	for attempt := 0; attempt < 2; attempt++ {
		accounting, err := traceAPI.importDecodedOTLPRequestV8(
			context.Background(), message, otelSignalTraces, source, now,
		)
		if err != nil || accounting.imported != 1 || !accounting.valid() {
			t.Fatalf("ordinary repeat %d accounting=%+v err=%v", attempt, accounting, err)
		}
	}
	spans := traceFixture.pipelines.capture(t, 1).snapshot()
	if len(spans) != 2 {
		t.Fatalf("ordinary repeated spans=%d", len(spans))
	}
	if spans[0].Record().RecordID() == spans[1].Record().RecordID() {
		t.Fatalf("ordinary repeated IDs=%q/%q", spans[0].Record().RecordID(), spans[1].Record().RecordID())
	}
}

func TestSelectedInboundTimePrecedenceAndUint64Bounds(t *testing.T) {
	t.Parallel()

	receipt := time.Unix(1_700_000_000, 123).UTC()
	timeNanos := uint64(receipt.Add(-2 * time.Second).UnixNano())
	observedNanos := uint64(receipt.Add(-time.Second).UnixNano())
	record := &logspb.LogRecord{TimeUnixNano: timeNanos, ObservedTimeUnixNano: observedNanos}
	selected, err := selectedInboundLogTime(record, receipt)
	if err != nil || selected.UnixNano() != int64(timeNanos) {
		t.Fatalf("log time precedence = %s err=%v", selected, err)
	}
	record.TimeUnixNano = 0
	selected, err = selectedInboundLogTime(record, receipt)
	if err != nil || selected.UnixNano() != int64(observedNanos) {
		t.Fatalf("observed time fallback = %s err=%v", selected, err)
	}
	record.ObservedTimeUnixNano = 0
	selected, err = selectedInboundLogTime(record, receipt)
	if err != nil || !selected.Equal(receipt) {
		t.Fatalf("receipt fallback = %s err=%v", selected, err)
	}

	point := &metricspb.NumberDataPoint{TimeUnixNano: timeNanos}
	leaf := otlpDecodedLeaf{signal: otelSignalMetrics, metricShape: otlpTypedMetricGauge, numberPoint: point}
	selected, err = selectedInboundMetricTime(leaf, receipt)
	if err != nil || selected.UnixNano() != int64(timeNanos) {
		t.Fatalf("metric point time = %s err=%v", selected, err)
	}
	point.TimeUnixNano = 0
	selected, err = selectedInboundMetricTime(leaf, receipt)
	if err != nil || !selected.Equal(receipt) {
		t.Fatalf("metric receipt fallback = %s err=%v", selected, err)
	}

	if selected, err = inboundTimeFromUnixNano(math.MaxInt64); err != nil || selected.UnixNano() != math.MaxInt64 {
		t.Fatalf("MaxInt64 boundary = %s err=%v", selected, err)
	}
	if _, err = inboundTimeFromUnixNano(uint64(math.MaxInt64) + 1); err == nil {
		t.Fatal("MaxInt64+1 timestamp must be rejected before uint64-to-int64 conversion")
	}
	record.TimeUnixNano = uint64(math.MaxInt64) + 1
	record.ObservedTimeUnixNano = observedNanos
	if _, err = selectedInboundLogTime(record, receipt); err == nil {
		t.Fatal("invalid nonzero source time must not fall through to observed time")
	}
}

func TestInboundStructuredMessagePartsPreserveRegisteredAndDynamicMembers(t *testing.T) {
	t.Parallel()

	value, err := inboundJSONAnyValue([]byte(`{
		"type":"server_tool_call",
		"id":"call-1",
		"name":"web_search",
		"server_tool_call":{"type":"search","query":"defenseclaw"},
		"vendor_extension":true
	}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	part, err := inboundGenAIMessagePart(value)
	if err != nil {
		t.Fatal(err)
	}
	server, ok := part.(observability.TelemetryStructuredArmGenAIMessagePartServerToolCall)
	if !ok || server.Value.Name != "web_search" || server.Value.ServerToolCall.Type != "search" ||
		len(server.Value.ServerToolCall.Entries) != 1 || len(server.Value.Entries) != 1 ||
		server.Value.Entries[0].Name != "vendor_extension" {
		t.Fatalf("server tool call part type = %T", part)
	}

	textValue := &commonpb.AnyValue{Value: &commonpb.AnyValue_KvlistValue{KvlistValue: &commonpb.KeyValueList{Values: []*commonpb.KeyValue{
		{Key: "type", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "text"}}},
		{Key: "content", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "hello"}}},
		{Key: "vendor_extension", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: 7}}},
	}}}}
	if _, err = inboundGenAIMessagePart(textValue); err != nil {
		t.Fatalf("registered text dynamic member rejected: %v", err)
	}

	for _, test := range []struct {
		name         string
		json         string
		wantFinish   string
		wantReported bool
	}{
		{
			name: "omitted",
			json: `{"role":"assistant","parts":[{"type":"text","content":"hello"}]}`,
		},
		{
			name:       "reported",
			json:       `{"role":"assistant","finish_reason":"tool_calls","parts":[{"type":"text","content":"hello"}]}`,
			wantFinish: "tool_calls", wantReported: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := inboundJSONAnyValue([]byte(test.json), 0)
			if err != nil {
				t.Fatal(err)
			}
			message, err := inboundGenAIOutputMessage(value)
			if err != nil {
				t.Fatal(err)
			}
			finish, reported := message.FinishReason.Get()
			if finish != test.wantFinish || reported != test.wantReported {
				t.Fatalf("finish reason=%q reported=%t", finish, reported)
			}
		})
	}
}

func TestOTLPInboundFieldClassAndDynamicMemberConformance(t *testing.T) {
	previousInstance := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("otlp-inbound-field-class-test")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstance) })

	fixture := newOTLPV8MetricFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	classifier := mustOTLPInboundClassifierV8(t)
	match, ok := classifier.catalog.Match("otlp.codex.user_prompt.v1.log.model.request")
	if !ok {
		t.Fatal("generated Codex prompt match missing")
	}
	leaf, source := inboundFixtureLeafForMatch(t, match)
	now := time.Now().UTC()
	redactionShapedText := "[REDACTED:email:sender-controlled]"
	leaf.logRecord.TimeUnixNano = uint64(now.UnixNano())
	leaf.logRecord.Body = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: redactionShapedText}}
	leaf.logRecord.Attributes = append(leaf.logRecord.Attributes,
		otlpClassifierStringAttribute("field_classes", `{"/gen_ai.input.messages":"metadata"}`),
		otlpClassifierStringAttribute("sensitivity", "public"),
	)
	message := &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource:  &resourcepb.Resource{Attributes: inboundFixtureResourceAttributes(&leaf)},
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{leaf.logRecord}}},
	}}}
	accounting, err := api.importDecodedOTLPRequestV8(
		context.Background(), message, otelSignalLogs, source, now,
	)
	if err != nil || accounting.imported != 1 || accounting.unknownFieldsDropped != 2 || !accounting.valid() {
		t.Fatalf("field-class accounting=%+v err=%v", accounting, err)
	}
	record := inboundStoredProjectedRecord(t, fixture.path, source, "model.request")
	classes, ok := record["field_classes"].(map[string]any)
	if !ok {
		t.Fatalf("field classes=%#v", record["field_classes"])
	}
	contentClass := false
	for pointer, class := range classes {
		if strings.HasPrefix(pointer, "/gen_ai.input.messages/") && class == "content" {
			contentClass = true
		}
		if strings.Contains(pointer, "field_classes") || strings.Contains(pointer, "sensitivity") {
			t.Fatalf("sender field-class claim survived as %q=%#v", pointer, class)
		}
	}
	if !contentClass {
		t.Fatalf("generated input-message content class absent: %#v", classes)
	}
	encoded, err := json.Marshal(record["body"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), redactionShapedText) {
		t.Fatalf("redaction-shaped sender string was treated as trusted transformation: %s", encoded)
	}

	dynamic, err := inboundJSONAnyValue([]byte(`{
		"type":"server_tool_call",
		"name":"web_search",
		"server_tool_call":{"type":"search","query":"defenseclaw"},
		"sender_dynamic_key":{"nested":true}
	}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	part, err := inboundGenAIMessagePart(dynamic)
	if err != nil {
		t.Fatal(err)
	}
	server, ok := part.(observability.TelemetryStructuredArmGenAIMessagePartServerToolCall)
	if !ok || len(server.Value.Entries) != 1 || server.Value.Entries[0].Name != "sender_dynamic_key" {
		t.Fatalf("dynamic member was not retained as a classified value: %#v", part)
	}
}

func TestOTLPInboundHopAndOriginMatrix(t *testing.T) {
	t.Parallel()
	wire := mustOTLPInboundClassifierV8(t).catalog.WireContract()
	leafWith := func(attributes ...*commonpb.KeyValue) otlpDecodedLeaf {
		return otlpDecodedLeaf{
			signal:         otelSignalLogs,
			logRecord:      &logspb.LogRecord{Attributes: attributes},
			leafAttributes: newOTLPTypedAttributeIndex(attributes),
		}
	}
	instance := otlpClassifierStringAttribute(wire.ForwardInstanceKey, "instance-a")
	destination := otlpClassifierStringAttribute(wire.ForwardDestinationKey, "collector-a")
	hop := otlpClassifierIntAttribute(wire.ForwardHopCountKey, 2)

	if metadata, err := inboundForwardMetadataV8(leafWith(), wire, false); err != nil || metadata != (inboundForwardMetadata{}) {
		t.Fatalf("absent external tuple = %+v err=%v", metadata, err)
	}
	if _, err := inboundForwardMetadataV8(leafWith(), wire, true); err == nil {
		t.Fatal("native tuple must be present")
	}
	metadata, err := inboundForwardMetadataV8(leafWith(instance, destination, hop), wire, false)
	if err != nil || metadata.hop != 2 || metadata.instanceID != "instance-a" || metadata.destination != "collector-a" {
		t.Fatalf("complete tuple = %+v err=%v", metadata, err)
	}
	for name, leaf := range map[string]otlpDecodedLeaf{
		"instance only":       leafWith(instance),
		"destination only":    leafWith(destination),
		"hop only":            leafWith(hop),
		"pair without hop":    leafWith(instance, destination),
		"instance and hop":    leafWith(instance, hop),
		"destination and hop": leafWith(destination, hop),
	} {
		leaf := leaf
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := inboundForwardMetadataV8(leaf, wire, false); err == nil {
				t.Fatal("partial forwarding tuple must be rejected")
			}
		})
	}
	if _, err := inboundForwardMetadataV8(leafWith(instance, destination, otlpClassifierIntAttribute(wire.ForwardHopCountKey, -1)), wire, false); err == nil {
		t.Fatal("negative hop must be rejected")
	}
	if _, err := inboundForwardMetadataV8(leafWith(instance, destination, otlpClassifierIntAttribute(wire.ForwardHopCountKey, int64(wire.MaxForwardHops)+1)), wire, false); err == nil {
		t.Fatal("hop above maximum must be rejected")
	}
}

func TestInboundOriginPolicyRequiresExactLocalForwardPair(t *testing.T) {
	previousInstance := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("local-forward-instance")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstance) })

	classifier := mustOTLPInboundClassifierV8(t)
	wire := classifier.catalog.WireContract()
	match, ok := classifier.catalog.Match("otlp.codex.user_prompt.v1.log.model.request")
	if !ok {
		t.Fatal("generated Codex user-prompt match missing")
	}
	leaf := func(instance, destination string, hop int64) otlpDecodedLeaf {
		attributes := []*commonpb.KeyValue{
			otlpClassifierStringAttribute(wire.ForwardInstanceKey, instance),
			otlpClassifierStringAttribute(wire.ForwardDestinationKey, destination),
			otlpClassifierIntAttribute(wire.ForwardHopCountKey, hop),
		}
		return otlpDecodedLeaf{
			signal: otelSignalLogs, logRecord: &logspb.LogRecord{Attributes: attributes},
			leafAttributes: newOTLPTypedAttributeIndex(attributes),
		}
	}
	policyField := func(policy any, name string) reflect.Value {
		field := reflect.ValueOf(policy).FieldByName(name)
		if !field.IsValid() {
			t.Fatalf("sealed policy field %q missing", name)
		}
		return field
	}
	local, err := inboundOptionalExportPolicyV8(leaf("local-forward-instance", "collector-a", 1), match, wire)
	if err != nil || policyField(local, "originDestination").String() != "collector-a" || policyField(local, "suppressAll").Bool() {
		t.Fatalf("local origin policy = %#v err=%v", local, err)
	}
	foreign, err := inboundOptionalExportPolicyV8(leaf("other-instance", "collector-a", 1), match, wire)
	if err != nil || policyField(foreign, "originDestination").String() != "" || policyField(foreign, "suppressAll").Bool() {
		t.Fatalf("foreign same-text policy = %#v err=%v", foreign, err)
	}
	terminal, err := inboundOptionalExportPolicyV8(leaf("other-instance", "collector-a", int64(wire.MaxForwardHops)), match, wire)
	if err != nil || policyField(terminal, "originDestination").String() != "" || !policyField(terminal, "suppressAll").Bool() {
		t.Fatalf("terminal policy = %#v err=%v", terminal, err)
	}
}
