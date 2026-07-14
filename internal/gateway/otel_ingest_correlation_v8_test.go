// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

func codexCorrelationTurnRequest(now time.Time, inputTokens int64) *collectortracepb.ExportTraceServiceRequest {
	return &collectortracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			otlpClassifierStringAttribute("service.name", "Codex Desktop"),
		}},
		ScopeSpans: []*tracepb.ScopeSpans{{
			Scope: &commonpb.InstrumentationScope{Name: "Codex Desktop"},
			Spans: []*tracepb.Span{{
				TraceId: []byte{0xca, 0x34, 0xa9, 0x9d, 0xb9, 0x82, 0x50, 0x2e, 0x22, 0xc0, 0xd7, 0xd2, 0x8d, 0x29, 0x52, 0xec},
				SpanId:  []byte{0x10, 0x34, 0xa9, 0x9d, 0xb9, 0x82, 0x50, 0x2e},
				Name:    "session_task.turn", Kind: tracepb.Span_SPAN_KIND_INTERNAL,
				StartTimeUnixNano: uint64(now.Add(-time.Second).UnixNano()),
				EndTimeUnixNano:   uint64(now.UnixNano()),
				Attributes: []*commonpb.KeyValue{
					otlpClassifierStringAttribute("thread.id", "thread-native-1"),
					otlpClassifierStringAttribute("turn.id", "turn-native-1"),
					otlpClassifierStringAttribute("model", "gpt-5.4"),
					otlpClassifierIntAttribute("input_token_count", inputTokens),
					otlpClassifierIntAttribute("output_token_count", 3),
					// This deliberately nonexistent semantic-convention key must
					// never enter the typed model-request ledger.
					otlpClassifierStringAttribute("gen_ai.request.id", "not-a-model-request"),
				},
			}},
		}},
	}}}
}

func codexCorrelationResponseRequest(now time.Time, responseID string) *collectorlogspb.ExportLogsServiceRequest {
	attributes := []*commonpb.KeyValue{
		otlpClassifierStringAttribute("event.name", "codex.sse_event"),
		otlpClassifierStringAttribute("event.kind", "response.completed"),
		otlpClassifierStringAttribute("conversation.id", "conversation-native-1"),
		otlpClassifierStringAttribute("model", "gpt-5.4"),
		otlpClassifierStringAttribute("input_token_count", "10"),
		otlpClassifierStringAttribute("output_token_count", "3"),
	}
	if responseID != "" {
		attributes = append(attributes, otlpClassifierStringAttribute("gen_ai.response.id", responseID))
	}
	return &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			otlpClassifierStringAttribute("service.name", "codex_cli_rs"),
		}},
		ScopeLogs: []*logspb.ScopeLogs{{
			Scope: &commonpb.InstrumentationScope{Name: "codex_cli_rs"},
			LogRecords: []*logspb.LogRecord{{
				TimeUnixNano: uint64(now.UnixNano()),
				Body: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{
					StringValue: "response.completed",
				}},
				Attributes: attributes,
			}},
		}},
	}}}
}

func codexCorrelationToolRequest(now time.Time, toolCallID string) *collectortracepb.ExportTraceServiceRequest {
	return &collectortracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			otlpClassifierStringAttribute("service.name", "codex_cli_rs"),
		}},
		ScopeSpans: []*tracepb.ScopeSpans{{
			Scope: &commonpb.InstrumentationScope{Name: "codex_cli_rs"},
			Spans: []*tracepb.Span{{
				TraceId:           []byte{0xda, 0x44, 0xb9, 0xad, 0xc9, 0x92, 0x60, 0x3e, 0x32, 0xd0, 0xe7, 0xe2, 0x9d, 0x39, 0x62, 0xfc},
				SpanId:            []byte{0x20, 0x44, 0xb9, 0xad, 0xc9, 0x92, 0x60, 0x3e},
				Name:              "execute_tool shell",
				Kind:              tracepb.Span_SPAN_KIND_INTERNAL,
				StartTimeUnixNano: uint64(now.Add(-time.Second).UnixNano()),
				EndTimeUnixNano:   uint64(now.UnixNano()),
				Attributes: []*commonpb.KeyValue{
					otlpClassifierStringAttribute("gen_ai.operation.name", "execute_tool"),
					otlpClassifierStringAttribute("gen_ai.tool.name", "shell"),
					otlpClassifierStringAttribute("gen_ai.tool.call.id", toolCallID),
					otlpClassifierStringAttribute("gen_ai.conversation.id", "conversation-native-tool-1"),
				},
			}},
		}},
	}}}
}

func openCorrelationDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func correlateCodexToolStartWithoutNativeID(
	t *testing.T,
	ctx context.Context,
	api *APIServer,
	sessionID string,
	marker string,
) agentHookRequest {
	t.Helper()
	profile := api.hookProfileForConnector("codex")
	req := normalizeAgentHookRequestWithProfile("codex", map[string]interface{}{
		"hook_event_name": "PreToolUse",
		"session_id":      sessionID,
		"tool_name":       "shell",
	}, profile)
	_, correlated, err := api.correlateHookOccurrence(
		ctx, profile, req, []byte("codex-tool-start-without-native-id:"+marker),
	)
	if err != nil {
		t.Fatal(err)
	}
	if correlated.ToolInvocationID == "" || correlated.SemanticEventID == "" ||
		correlated.LogicalEventID == "" {
		t.Fatalf("hook start did not mint durable operation identity: %+v", correlated)
	}
	return correlated
}

func TestNativeOTLPCorrelationSpanReplayConflictAndSourceIsolation(t *testing.T) {
	installCorrelationHMACForTest()
	fixture := newCodexNativeOTLPFixture(t)
	api := &APIServer{store: fixture.store}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC().Truncate(time.Nanosecond)
	request := codexCorrelationTurnRequest(now, 10)

	first, err := api.importDecodedOTLPRequestV8(t.Context(), request, otelSignalTraces, "codex", now)
	if err != nil || !first.valid() || first.importedAndDerived != 1 {
		t.Fatalf("first native span accounting=%+v err=%v", first, err)
	}
	replay, err := api.importDecodedOTLPRequestV8(t.Context(), request, otelSignalTraces, "codex", now.Add(time.Second))
	if err != nil || !replay.valid() || replay.exactReplaySuppressed != 1 {
		t.Fatalf("exact native span replay accounting=%+v err=%v", replay, err)
	}

	conflicting := proto.Clone(request).(*collectortracepb.ExportTraceServiceRequest)
	conflicting.ResourceSpans[0].ScopeSpans[0].Spans[0].Attributes = append(
		conflicting.ResourceSpans[0].ScopeSpans[0].Spans[0].Attributes,
		otlpClassifierStringAttribute("provider.extra", "changed-payload"),
	)
	conflict, err := api.importDecodedOTLPRequestV8(t.Context(), conflicting, otelSignalTraces, "codex", now.Add(2*time.Second))
	if err != nil || !conflict.valid() || conflict.importedAndDerived != 1 {
		t.Fatalf("conflicting native span accounting=%+v err=%v", conflict, err)
	}

	wrongSource, err := api.importDecodedOTLPRequestV8(t.Context(), request, otelSignalTraces, "claudecode", now.Add(3*time.Second))
	if err != nil || !wrongSource.valid() || wrongSource.unsupportedIdentity != 1 {
		t.Fatalf("wrong authenticated source accounting=%+v err=%v", wrongSource, err)
	}

	database := openCorrelationDB(t, fixture.path)
	var events, receipts, deliveries, conflicts, forbidden, claudeInstances int
	queries := []struct {
		query string
		args  []any
		out   *int
	}{
		{`SELECT COUNT(*) FROM correlation_events WHERE connector='codex' AND source_rail='native_otlp'`, nil, &events},
		{`SELECT COUNT(*) FROM correlation_receipts`, nil, &receipts},
		{`SELECT COALESCE(SUM(delivery_count),0) FROM correlation_receipts`, nil, &deliveries},
		{`SELECT COUNT(*) FROM correlation_relationships WHERE status='conflicted'`, nil, &conflicts},
		{`SELECT COUNT(*) FROM correlation_identifiers WHERE source_field='gen_ai.request.id' OR identifier_kind='model_request'`, nil, &forbidden},
		{`SELECT COUNT(*) FROM correlation_connector_instances WHERE connector='claudecode'`, nil, &claudeInstances},
	}
	for _, query := range queries {
		if err := database.QueryRow(query.query, query.args...).Scan(query.out); err != nil {
			t.Fatal(err)
		}
	}
	if events != 2 || receipts != 2 || deliveries != 3 || conflicts != 1 || forbidden != 0 || claudeInstances != 0 {
		t.Fatalf("ledger events=%d receipts=%d deliveries=%d conflicts=%d forbidden=%d claude_instances=%d",
			events, receipts, deliveries, conflicts, forbidden, claudeInstances)
	}
	var custody string
	if err := database.QueryRow(`SELECT export_custody FROM correlation_connector_instances WHERE connector='codex'`).Scan(&custody); err != nil {
		t.Fatal(err)
	}
	if custody != string(audit.ConnectorCustodyDefenseClaw) {
		t.Fatalf("successful native span custody=%q", custody)
	}
	spans := fixture.pipelines.traces.capture(t, 1).snapshot()
	if len(spans) != 2 {
		t.Fatalf("provider spans=%d want first+conflict only", len(spans))
	}
	for _, span := range spans {
		correlation := span.Record().Correlation()
		for name, value := range map[string]string{
			"semantic":           correlation.SemanticEventID,
			"logical":            correlation.LogicalEventID,
			"connector instance": correlation.ConnectorInstanceID,
		} {
			parsed, parseErr := uuid.Parse(value)
			if parseErr != nil || parsed.Version() != 7 {
				t.Errorf("%s=%q is not UUIDv7", name, value)
			}
		}
	}
}

func TestNativeOTLPLeafCanaryRequiresEveryCollectedTarget(t *testing.T) {
	durable := otlpInboundTargetResult{collected: true, recorded: true}
	noObservation := otlpInboundTargetResult{collected: true, acceptedNoObservation: true}
	failed := otlpInboundTargetResult{collected: true, persistenceFailed: true}
	disabled := otlpInboundTargetResult{}

	for name, fixture := range map[string]struct {
		result otlpInboundLeafResult
		want   bool
	}{
		"all-durable": {
			result: otlpInboundLeafResult{primary: &durable, derivatives: []otlpInboundTargetResult{durable, noObservation}, hasImportTarget: true, hasDerivedTarget: true},
			want:   true,
		},
		"one-derivative-failed": {
			result: otlpInboundLeafResult{primary: &durable, derivatives: []otlpInboundTargetResult{durable, failed}, hasImportTarget: true, hasDerivedTarget: true},
		},
		"one-derivative-disabled": {
			result: otlpInboundLeafResult{primary: &durable, derivatives: []otlpInboundTargetResult{durable, disabled}, hasImportTarget: true, hasDerivedTarget: true},
		},
		"missing-required-derivative": {
			result: otlpInboundLeafResult{primary: &durable, hasImportTarget: true, hasDerivedTarget: true},
		},
		"only-derived-durable": {
			result: otlpInboundLeafResult{derivatives: []otlpInboundTargetResult{durable}, hasDerivedTarget: true},
			want:   true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := nativeOTLPLeafCanarySucceeded(fixture.result); got != fixture.want {
				t.Fatalf("canary=%v want %v for %+v", got, fixture.want, fixture.result)
			}
		})
	}
}

func TestNativeOTLPIdenticalLogsRemainDistinctAndSourceProvenCodexCallIDJoinsHook(t *testing.T) {
	installCorrelationHMACForTest()
	fixture := newCodexNativeOTLPFixture(t)
	api := &APIServer{store: fixture.store}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC().Truncate(time.Nanosecond)

	identical := codexCorrelationResponseRequest(now, "")
	for index := 0; index < 2; index++ {
		accounting, err := api.importDecodedOTLPRequestV8(t.Context(), identical, otelSignalLogs, "codex", now.Add(time.Duration(index)*time.Second))
		if err != nil || !accounting.valid() || accounting.importedAndDerived != 1 || accounting.exactReplaySuppressed != 0 {
			t.Fatalf("identical log %d accounting=%+v err=%v", index, accounting, err)
		}
	}
	database := openCorrelationDB(t, fixture.path)
	var events, receipts, logicalGroups int
	if err := database.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT logical_group_id)
		FROM correlation_events WHERE source_rail='native_otlp'`).Scan(&events, &logicalGroups); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_receipts`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if events != 2 || logicalGroups != 2 || receipts != 0 {
		t.Fatalf("identical no-source logs events=%d groups=%d receipts=%d", events, logicalGroups, receipts)
	}

	profile := api.hookProfileForConnector("codex")
	hookPayload := map[string]interface{}{
		"hook_event_name": "PostToolUse", "session_id": "conversation-native-tool-1",
		"tool_name": "shell", "tool_use_id": "codex-call-source-backed-1",
	}
	hook := normalizeAgentHookRequestWithProfile("codex", hookPayload, profile)
	_, hook, err := api.correlateHookOccurrence(t.Context(), profile, hook,
		[]byte(`{"hook_event_name":"PostToolUse","session_id":"conversation-native-tool-1","tool_name":"shell","tool_use_id":"codex-call-source-backed-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	joined, err := api.importDecodedOTLPRequestV8(t.Context(),
		loadCodexToolResultSourceFixture(t), otelSignalLogs, "codex", now.Add(time.Minute))
	if err != nil || !joined.valid() || joined.imported != 1 {
		t.Fatalf("hook/native exact tool-call join=%+v err=%v", joined, err)
	}
	var joinedEvents, joinedGroups, sameAs, exactClaims int
	if err := database.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT logical_group_id)
		FROM correlation_events WHERE logical_group_id=?`, hook.LogicalEventID).Scan(&joinedEvents, &joinedGroups); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_relationships
		WHERE relationship_type='same_as' AND status='active'`).Scan(&sameAs); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_identity_claims
		WHERE identifier_kind='tool_invocation' AND event_name='tool_end'`).Scan(&exactClaims); err != nil {
		t.Fatal(err)
	}
	if joinedEvents != 2 || joinedGroups != 1 || sameAs == 0 || exactClaims != 2 {
		t.Fatalf("hook/native join events=%d groups=%d same_as=%d exact_claims=%d",
			joinedEvents, joinedGroups, sameAs, exactClaims)
	}
}

func TestNativeOTLPNoSharedToolIDLinksUniquePendingWithoutCollapse(t *testing.T) {
	installCorrelationHMACForTest()
	fixture := newCodexNativeOTLPFixture(t)
	api := &APIServer{store: fixture.store}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC().Truncate(time.Nanosecond)

	hook := correlateCodexToolStartWithoutNativeID(
		t, t.Context(), api, "conversation-native-tool-1", "unique",
	)
	if hook.ToolInvocationID == "provider-tool-call-unshared" {
		t.Fatal("test hook unexpectedly shared the provider tool-call identity")
	}
	accounting, err := api.importDecodedOTLPRequestV8(
		t.Context(), codexCorrelationToolRequest(now, "provider-tool-call-unshared"),
		otelSignalTraces, "codex", now,
	)
	if err != nil || !accounting.valid() || accounting.importedAndDerived != 1 {
		t.Fatalf("native tool accounting=%+v err=%v", accounting, err)
	}

	database := openCorrelationDB(t, fixture.path)
	var nativeSemantic, nativeLogical string
	if err := database.QueryRow(`SELECT semantic_event_id, logical_group_id
		FROM correlation_events WHERE source_rail='native_otlp'`).Scan(
		&nativeSemantic, &nativeLogical,
	); err != nil {
		t.Fatal(err)
	}
	if nativeLogical == hook.LogicalEventID {
		t.Fatalf("derived pending match collapsed logical groups: native=%q hook=%q",
			nativeLogical, hook.LogicalEventID)
	}
	var causedBy, sameAs int
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_relationships
		WHERE from_kind='semantic_event' AND from_id=?
		  AND to_kind='semantic_event' AND to_id=?
		  AND relationship_type='caused_by' AND method='derived'
		  AND rule_id='unique-compatible-native-pending' AND status='active'`,
		nativeSemantic, hook.SemanticEventID).Scan(&causedBy); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_relationships
		WHERE relationship_type='same_as'`).Scan(&sameAs); err != nil {
		t.Fatal(err)
	}
	var pendingStatus, terminalSemantic string
	if err := database.QueryRow(`SELECT status, terminal_semantic_event_id
		FROM correlation_pending_operations WHERE operation_id=?`,
		hook.ToolInvocationID).Scan(&pendingStatus, &terminalSemantic); err != nil {
		t.Fatal(err)
	}
	if causedBy != 1 || sameAs != 0 || pendingStatus != string(audit.CorrelationOperationCompleted) ||
		terminalSemantic != nativeSemantic {
		t.Fatalf("derived join caused_by=%d same_as=%d pending=%q terminal=%q native=%q",
			causedBy, sameAs, pendingStatus, terminalSemantic, nativeSemantic)
	}
}

func TestNativeOTLPNoSharedToolIDAmbiguityRemainsUnresolved(t *testing.T) {
	installCorrelationHMACForTest()
	fixture := newCodexNativeOTLPFixture(t)
	api := &APIServer{store: fixture.store}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC().Truncate(time.Nanosecond)

	first := correlateCodexToolStartWithoutNativeID(
		t, t.Context(), api, "conversation-native-tool-1", "ambiguous-first",
	)
	second := correlateCodexToolStartWithoutNativeID(
		t, t.Context(), api, "conversation-native-tool-1", "ambiguous-second",
	)
	if first.ToolInvocationID == second.ToolInvocationID {
		t.Fatalf("independent pending operations reused identity %q", first.ToolInvocationID)
	}
	accounting, err := api.importDecodedOTLPRequestV8(
		t.Context(), codexCorrelationToolRequest(now, "provider-tool-call-ambiguous"),
		otelSignalTraces, "codex", now,
	)
	if err != nil || !accounting.valid() || accounting.importedAndDerived != 1 {
		t.Fatalf("native tool accounting=%+v err=%v", accounting, err)
	}

	database := openCorrelationDB(t, fixture.path)
	var events, groups, semanticEdges, activePending int
	if err := database.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT logical_group_id)
		FROM correlation_events`).Scan(&events, &groups); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_relationships
		WHERE from_kind='semantic_event' AND to_kind='semantic_event'
		  AND relationship_type IN ('same_as','caused_by')`).Scan(&semanticEdges); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_pending_operations
		WHERE status='active' AND session_id='conversation-native-tool-1'`).Scan(&activePending); err != nil {
		t.Fatal(err)
	}
	if events != 3 || groups != 3 || semanticEdges != 0 || activePending != 2 {
		t.Fatalf("ambiguous join events=%d groups=%d semantic_edges=%d active_pending=%d",
			events, groups, semanticEdges, activePending)
	}
}

func TestNativeOTLPSharedTraceAddsTopologyWithoutBusinessIdentity(t *testing.T) {
	installCorrelationHMACForTest()
	fixture := newCodexNativeOTLPFixture(t)
	api := &APIServer{store: fixture.store}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC().Truncate(time.Nanosecond)

	const traceIDHex = "da44b9adc992603e32d0e7e29d3962fc"
	traceID, err := trace.TraceIDFromHex(traceIDHex)
	if err != nil {
		t.Fatal(err)
	}
	hookSpanID, err := trace.SpanIDFromHex("3044b9adc992603e")
	if err != nil {
		t.Fatal(err)
	}
	hookCtx := trace.ContextWithRemoteSpanContext(t.Context(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: hookSpanID, TraceFlags: trace.FlagsSampled, Remote: true,
	}))
	hook := correlateCodexToolStartWithoutNativeID(
		t, hookCtx, api, "conversation-native-tool-1", "shared-w3c",
	)
	accounting, err := api.importDecodedOTLPRequestV8(
		t.Context(), codexCorrelationToolRequest(now, "provider-tool-call-traced"),
		otelSignalTraces, "codex", now,
	)
	if err != nil || !accounting.valid() || accounting.importedAndDerived != 1 {
		t.Fatalf("native tool accounting=%+v err=%v", accounting, err)
	}

	database := openCorrelationDB(t, fixture.path)
	var nativeSemantic, nativeLogical string
	if err := database.QueryRow(`SELECT semantic_event_id, logical_group_id
		FROM correlation_events WHERE source_rail='native_otlp'`).Scan(
		&nativeSemantic, &nativeLogical,
	); err != nil {
		t.Fatal(err)
	}
	var traceMembers, sameAs, derivedCause, traceBusinessIdentity int
	if err := database.QueryRow(`SELECT COUNT(DISTINCT from_id)
		FROM correlation_relationships
		WHERE from_kind='semantic_event' AND to_kind='trace' AND to_id=?
		  AND relationship_type='belongs_to' AND method='trace_exact' AND status='active'`,
		traceIDHex).Scan(&traceMembers); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_relationships
		WHERE relationship_type='same_as'`).Scan(&sameAs); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_relationships
		WHERE from_kind='semantic_event' AND from_id=?
		  AND to_kind='semantic_event' AND to_id=?
		  AND relationship_type='caused_by' AND method='derived'`,
		nativeSemantic, hook.SemanticEventID).Scan(&derivedCause); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_relationships
		WHERE from_kind='semantic_event' AND to_kind='semantic_event'
		  AND method='trace_exact'`).Scan(&traceBusinessIdentity); err != nil {
		t.Fatal(err)
	}
	if nativeLogical == hook.LogicalEventID || traceMembers != 2 || sameAs != 0 ||
		derivedCause != 1 || traceBusinessIdentity != 0 {
		t.Fatalf("W3C topology native_group=%q hook_group=%q trace_members=%d same_as=%d derived=%d trace_business=%d",
			nativeLogical, hook.LogicalEventID, traceMembers, sameAs, derivedCause, traceBusinessIdentity)
	}
}

func TestNativeOTLPNonAuthoritativeSourceEventDoesNotMergeRails(t *testing.T) {
	installCorrelationHMACForTest()
	fixture := newCodexNativeOTLPFixture(t)
	api := &APIServer{store: fixture.store}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC().Truncate(time.Nanosecond)

	profile := api.hookProfileForConnector("codex")
	profile.Correlation.Lifecycle = append(profile.Correlation.Lifecycle,
		connector.CorrelationLifecycleBinding{
			Lifecycle: connector.CorrelationLifecycleModelEnd,
			Events:    []string{"AfterModel"},
		})
	hookPayload := map[string]interface{}{
		"hook_event_name": "AfterModel",
		"session_id":      "conversation-native-1",
		"item_id":         "provider-item-shared",
		"response_id":     "hook-response-distinct",
	}
	hook := normalizeAgentHookRequestWithProfile("codex", hookPayload, profile)
	_, hook, err := api.correlateHookOccurrence(t.Context(), profile, hook,
		[]byte(`{"hook_event_name":"AfterModel","item_id":"provider-item-shared","response_id":"hook-response-distinct","session_id":"conversation-native-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if hook.CorrelationReceipt == nil {
		t.Fatal("hook source occurrence did not create an exact delivery receipt")
	}
	persistCanonicalCorrelationObservation(t, fixture.store, hook.SemanticEventID, "model.end")
	if err := api.finalizeHookCorrelationReceipt(t.Context(), hook.CorrelationReceipt); err != nil {
		t.Fatal(err)
	}

	native := codexCorrelationResponseRequest(now, "native-response-distinct")
	record := native.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	record.Attributes = append(record.Attributes,
		otlpClassifierStringAttribute("item.id", "provider-item-shared"),
	)
	accounting, err := api.importDecodedOTLPRequestV8(
		t.Context(), native, otelSignalLogs, "codex", now,
	)
	if err != nil || !accounting.valid() || accounting.importedAndDerived != 1 ||
		accounting.exactReplaySuppressed != 0 {
		t.Fatalf("cross-rail shared-source accounting=%+v err=%v", accounting, err)
	}

	database := openCorrelationDB(t, fixture.path)
	var events, groups, receipts, receiptConflicts, sameAs, sourceIdentifiers int
	if err := database.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT logical_group_id)
		FROM correlation_events`).Scan(&events, &groups); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*),
		SUM(CASE WHEN conflicts_with_semantic_event_id IS NOT NULL THEN 1 ELSE 0 END)
		FROM correlation_receipts`).Scan(&receipts, &receiptConflicts); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_relationships
		WHERE relationship_type='same_as' AND status='active'`).Scan(&sameAs); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_identifiers
		WHERE identifier_kind='source_event'`).Scan(&sourceIdentifiers); err != nil {
		t.Fatal(err)
	}
	if events != 2 || groups != 2 || receipts != 2 || receiptConflicts != 0 || sameAs != 0 || sourceIdentifiers != 2 {
		t.Fatalf("cross-rail shared source events=%d groups=%d receipts=%d receipt_conflicts=%d same_as=%d source_identifiers=%d",
			events, groups, receipts, receiptConflicts, sameAs, sourceIdentifiers)
	}
}

func TestNativeOTLPMetricGetsOccurrenceContextWithoutIdentityLabels(t *testing.T) {
	installCorrelationHMACForTest()
	fixture := newCodexNativeOTLPFixture(t)
	api := &APIServer{store: fixture.store}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC().Truncate(time.Nanosecond)
	request := codexNativeTokenHistogramRequest(now, codexNativeTokenPoint{tokenType: "input", value: 17})
	accounting, err := api.importDecodedOTLPRequestV8(t.Context(), request, otelSignalMetrics, "codex", now)
	if err != nil || !accounting.valid() || accounting.derivedOnly != 1 || accounting.derivativeRecorded != 1 {
		t.Fatalf("native metric correlation accounting=%+v err=%v", accounting, err)
	}
	metrics := fixture.pipelines.metrics.sinks(t, 1).local.snapshot()
	found := false
	for _, metric := range metrics {
		if metric.Descriptor().Name != observability.TelemetryInstrumentGenAIClientTokenUsage {
			continue
		}
		found = true
		correlation := metric.CanonicalRecord().Correlation()
		if correlation.SemanticEventID == "" || correlation.LogicalEventID == "" || correlation.ConnectorInstanceID == "" {
			t.Fatalf("metric occurrence correlation=%+v", correlation)
		}
		for _, forbidden := range []string{
			"defenseclaw.semantic_event.id", "defenseclaw.logical_event.id",
			"defenseclaw.connector.instance.id", "defenseclaw.turn.id",
			"defenseclaw.request.id", "gen_ai.tool.call.id",
		} {
			if _, present := metric.Attributes()[forbidden]; present {
				t.Errorf("metric exported high-cardinality label %q", forbidden)
			}
		}
	}
	if !found {
		t.Fatal("correlated native token metric not recorded")
	}
}

func TestNativeOTLPDropOnlyDoesNotPromoteCustodyOrPoisonReplay(t *testing.T) {
	installCorrelationHMACForTest()
	fixture := newCodexNativeOTLPFixtureWithCollection(t, false)
	api := &APIServer{store: fixture.store}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC().Truncate(time.Nanosecond)
	request := codexCorrelationTurnRequest(now, 10)
	for index := 0; index < 2; index++ {
		accounting, err := api.importDecodedOTLPRequestV8(t.Context(), request, otelSignalTraces,
			"codex", now.Add(time.Duration(index)*time.Second))
		if err != nil || !accounting.valid() || accounting.collectionDisabled != 1 || accounting.exactReplaySuppressed != 0 {
			t.Fatalf("drop-only attempt %d accounting=%+v err=%v", index, accounting, err)
		}
	}
	database := openCorrelationDB(t, fixture.path)
	var custody string
	var deliveries int
	if err := database.QueryRow(`SELECT export_custody FROM correlation_connector_instances WHERE connector='codex'`).Scan(&custody); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT delivery_count FROM correlation_receipts`).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if custody != string(audit.ConnectorCustodyExternal) || deliveries != 2 {
		t.Fatalf("drop-only custody=%q deliveries=%d", custody, deliveries)
	}
}

func TestNativeOTLPReceiptFailureRetriesUntilExactCanarySucceeds(t *testing.T) {
	installCorrelationHMACForTest()
	fixture := newCodexNativeOTLPFixture(t)
	api := &APIServer{store: fixture.store}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC().Truncate(time.Nanosecond)
	message := codexCorrelationTurnRequest(now, 10)
	classifier := mustOTLPInboundClassifierV8(t)
	var leaf otlpDecodedLeaf
	if _, err := walkDecodedOTLPLeaves(message, otelSignalTraces, func(current otlpDecodedLeaf) error {
		leaf = current
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	classification, err := classifier.classify(leaf, "codex")
	if err != nil {
		t.Fatal(err)
	}

	first, err := api.correlateNativeOTLPLeafV8(t.Context(), leaf, classification.match, "codex", now)
	if err != nil || first.suppressEmission || first.receipt == nil {
		t.Fatalf("failed first attempt result=%+v err=%v", first, err)
	}
	// Simulate canonical persistence failure by deliberately not finalizing the
	// first receipt. Even if some older leaf had already promoted custody, this
	// exact receipt remains pending.
	repo, err := fixture.store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ResolveConnectorInstance(t.Context(), "codex", first.profileVersion,
		audit.ConnectorCustodyDefenseClaw); err != nil {
		t.Fatal(err)
	}

	second, err := api.correlateNativeOTLPLeafV8(t.Context(), leaf, classification.match, "codex", now.Add(time.Second))
	if err != nil || second.suppressEmission || second.semantic != first.semantic {
		t.Fatalf("pending receipt retry result=%+v first=%+v err=%v", second, first, err)
	}
	// Correlation relationship logs are already present, but they are not the
	// native leaf's canonical persistence canary and cannot authorize replay
	// suppression by themselves.
	if err := api.finalizeNativeOTLPCustodyV8(t.Context(), second); !errors.Is(err, audit.ErrCorrelationNotFound) {
		t.Fatalf("relationship-only finalization err=%v want correlation not found", err)
	}
	persistCanonicalCorrelationObservation(t, fixture.store, string(second.semantic), "model.end")
	if err := api.finalizeNativeOTLPCustodyV8(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	third, err := api.correlateNativeOTLPLeafV8(t.Context(), leaf, classification.match, "codex", now.Add(2*time.Second))
	if err != nil || !third.suppressEmission || third.semantic != first.semantic {
		t.Fatalf("accepted receipt replay result=%+v first=%+v err=%v", third, first, err)
	}
	database := openCorrelationDB(t, fixture.path)
	var deliveries int
	var accepted sql.NullInt64
	if err := database.QueryRow(`SELECT delivery_count, accepted_time_unix_nano FROM correlation_receipts`).Scan(
		&deliveries, &accepted); err != nil {
		t.Fatal(err)
	}
	if deliveries != 3 || !accepted.Valid {
		t.Fatalf("receipt deliveries=%d accepted=%v", deliveries, accepted)
	}
}

func TestNativeOTLPConflictingAliasesFailBeforeOccurrencePersistence(t *testing.T) {
	installCorrelationHMACForTest()
	fixture := newCodexNativeOTLPFixture(t)
	api := &APIServer{store: fixture.store}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC().Truncate(time.Nanosecond)
	request := codexCorrelationResponseRequest(now, "response-conflicting-aliases")
	record := request.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	record.Attributes = append(record.Attributes,
		otlpClassifierStringAttribute("gen_ai.conversation.id", "different-conversation"))
	accounting, err := api.importDecodedOTLPRequestV8(t.Context(), request, otelSignalLogs, "codex", now)
	if err != nil || !accounting.valid() || accounting.invalidMappedField != 1 {
		t.Fatalf("conflicting aliases accounting=%+v err=%v", accounting, err)
	}
	database := openCorrelationDB(t, fixture.path)
	var events, receipts int
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_receipts`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if events != 0 || receipts != 0 {
		t.Fatalf("conflicting aliases persisted events=%d receipts=%d", events, receipts)
	}
}

func TestNativeOTLPTypedIdentityConsistencyKeepsKindsIndependent(t *testing.T) {
	values := []connector.CorrelationValue{
		{Target: connector.CorrelationTargetTurn, Namespace: "claudecode", IDKind: "turn", Value: "defenseclaw-turn"},
		{Target: connector.CorrelationTargetTurn, Namespace: "claudecode", IDKind: "prompt", Value: "claude-prompt"},
	}
	if err := validateNativeOTLPValueConsistency(values); err != nil {
		t.Fatalf("distinct typed IDs were treated as contradictory aliases: %v", err)
	}
	ctx := contextWithNativeOTLPCorrelation(t.Context(), "claudecode", audit.ConnectorInstance{},
		audit.SemanticEventID("semantic"), audit.LogicalEventID("logical"), values, "")
	if got := audit.EnvelopeFromContext(ctx).TurnID; got != "claude-prompt" {
		t.Fatalf("context turn=%q want provider-preferred prompt", got)
	}
	stored, ok := nativeOTLPCorrelationValuesFromContext(ctx, "claudecode")
	if !ok || len(stored) != len(values) || stored[1].Value != "claude-prompt" {
		t.Fatalf("native transaction values were not carried to canonical projection: %+v", stored)
	}
	if _, ok := nativeOTLPCorrelationValuesFromContext(ctx, "codex"); ok {
		t.Fatal("authenticated connector mismatch reused native correlation values")
	}

	conflicting := append(append([]connector.CorrelationValue(nil), values...), connector.CorrelationValue{
		Target: connector.CorrelationTargetTurn, Namespace: "claudecode", IDKind: "prompt", Value: "different-prompt",
	})
	if err := validateNativeOTLPValueConsistency(conflicting); err == nil {
		t.Fatal("conflicting aliases of one typed prompt identity were accepted")
	}
}

func TestNativeOTLPReportedLogicalCannotInventGroup(t *testing.T) {
	installCorrelationHMACForTest()
	server, store := newHookCorrelationServer(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close() //nolint:errcheck
	classifier := mustOTLPInboundClassifierV8(t)
	match, ok := classifier.catalog.Match("otlp.codex.response_completed.v1.log.model.response")
	if !ok {
		t.Fatal("Codex response match missing")
	}
	message := codexCorrelationResponseRequest(time.Now().UTC(), "response-logical-1")
	var leaf otlpDecodedLeaf
	if _, err := walkDecodedOTLPLeaves(message, otelSignalLogs, func(current otlpDecodedLeaf) error {
		leaf = current
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	semantic, _ := audit.NewSemanticEventID()
	logical, _ := audit.NewSemanticEventID()
	leaf.logRecord.Attributes = append(leaf.logRecord.Attributes,
		otlpClassifierStringAttribute("defenseclaw.semantic_event.id", string(semantic)),
		otlpClassifierStringAttribute("defenseclaw.logical_event.id", string(logical)),
	)
	leaf.leafAttributes = newOTLPTypedAttributeIndex(leaf.logRecord.Attributes)
	if _, err := server.correlateNativeOTLPLeafV8(context.Background(), leaf, match, "codex", time.Now().UTC()); err == nil {
		t.Fatal("brand-new native semantic event invented a logical group")
	}
	leaf.logRecord.Attributes = replaceInboundFixtureAttribute(leaf.logRecord.Attributes,
		"defenseclaw.logical_event.id", otlpClassifierStringAttribute("defenseclaw.logical_event.id", string(semantic)))
	leaf.leafAttributes = newOTLPTypedAttributeIndex(leaf.logRecord.Attributes)
	correlated, err := server.correlateNativeOTLPLeafV8(context.Background(), leaf, match, "codex", time.Now().UTC())
	if err != nil {
		t.Fatalf("self-grouped new semantic occurrence: %v", err)
	}
	envelope := audit.EnvelopeFromContext(correlated.ctx)
	if envelope.SemanticEventID != string(semantic) || envelope.LogicalEventID != string(semantic) {
		t.Fatalf("self-grouped envelope=%+v", envelope)
	}
}

func TestNativeOTLPMirrorCompatibilityRequiresAuthoritativeField(t *testing.T) {
	spec := connector.DefaultCorrelationSpec("codex")
	spec.MirrorIdentityTargets = []connector.CorrelationTarget{connector.CorrelationTargetTool}
	spec.NativeTelemetry.AuthoritativeFields = []connector.CorrelationTarget{
		connector.CorrelationTargetSession,
		connector.CorrelationTargetTurn,
	}
	if got := nativeOTLPMirrorCompatibility(spec, otelSignalLogs,
		string(connector.CorrelationLifecycleToolStart)); got != nil {
		t.Fatalf("non-authoritative tool ID received cross-rail same-as authority: %+v", got)
	}
}

func TestNativeNonAuthoritativeValuesArePreservedButNotMatched(t *testing.T) {
	spec := connector.DefaultCorrelationSpec("codex")
	values := spec.NativeOTLPValues(map[string]interface{}{
		"item.id":                "item-evidence-1",
		"gen_ai.response.id":     "response-authority-1",
		"gen_ai.conversation.id": "session-membership-1",
	})
	if len(values) < 3 {
		t.Fatalf("reviewed native evidence was not preserved: %+v", values)
	}
	matched := correlationMatchValuesForRail(spec, audit.CorrelationRailNativeOTLP, values)
	for _, value := range matched {
		if value.Target == connector.CorrelationTargetSourceEvent {
			t.Fatalf("non-authoritative Codex item ID entered matcher: %+v", value)
		}
	}
	if containsCorrelationTarget(matched, connector.CorrelationTargetModelResponse) {
		t.Fatalf("unproven response occurrence ID entered cross-rail matcher: %+v", matched)
	}
	if !containsCorrelationTarget(matched, connector.CorrelationTargetSession) {
		t.Fatalf("typed session membership was excluded from non-collapsing matching: %+v", matched)
	}
}

func containsCorrelationTarget(values []connector.CorrelationValue, target connector.CorrelationTarget) bool {
	for _, value := range values {
		if value.Target == target {
			return true
		}
	}
	return false
}
