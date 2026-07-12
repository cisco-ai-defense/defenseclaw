// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

func eventRouterToolV8BootstrapRaw(dataDir, endpoint string, traces, metrics bool) []byte {
	return []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nobservability:\n  metric_policy:\n    export_interval_seconds: 1\n  buckets:\n    tool.activity:\n      collect: {logs: true, traces: %t, metrics: %t}\n    guardrail.evaluation:\n      collect: {logs: true, traces: false, metrics: %t}\n    security.finding:\n      collect: {logs: true, traces: false, metrics: %t}\n  destinations:\n    - name: tool-otlp\n      kind: otlp\n      endpoint: %q\n      protocol: http/protobuf\n      tls: {insecure: true}\n      network_safety: {allow_private_networks: true}\n      batch: {max_export_batch_size: 16, scheduled_delay_ms: 10}\n      send: {signals: [traces, metrics], buckets: ['*']}\n",
		dataDir, traces, metrics, metrics, metrics, endpoint,
	))
}

func bindEventRouterToolV8Runtime(
	t *testing.T,
	traces, metrics bool,
) (*EventRouter, *hookModelV8OTLPCapture, string) {
	t.Helper()
	capture := &hookModelV8OTLPCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	t.Cleanup(server.Close)
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	router := NewEventRouter(nil, fixture.store, fixture.logger, false)
	router.SetDefaultPolicyID("policy-tool-1")
	fixture.sidecar.setEventRouter(router)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath,
		eventRouterToolV8BootstrapRaw(fixture.dataDir, server.URL, traces, metrics),
	)
	if err != nil || !bound {
		t.Fatalf("bootstrap EventRouter tool runtime bound=%t error=%v", bound, err)
	}
	return router, capture, fixture.store.DatabasePath()
}

func routeEventRouterToolCall(t *testing.T, router *EventRouter, payload ToolCallPayload) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	router.handleToolCall(EventFrame{Type: "event", Event: "tool_call", Payload: raw})
}

func routeEventRouterToolResult(t *testing.T, router *EventRouter, payload ToolResultPayload) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	router.handleToolResult(EventFrame{Type: "event", Event: "tool_result", Payload: raw})
}

func TestEventRouterToolV8PairsConcurrentSameNameCallsOnlyByCallID(t *testing.T) {
	router, capture, databasePath := bindEventRouterToolV8Runtime(t, true, true)
	routeEventRouterToolCall(t, router, ToolCallPayload{
		Tool: "shell", ID: "call-one", SessionID: "session-one", RunID: "run-one",
		AgentName: "reported-agent", Args: json.RawMessage(`{"marker":"private-call-one"}`),
	})
	routeEventRouterToolCall(t, router, ToolCallPayload{
		Tool: "shell", ID: "call-two", SessionID: "session-one", RunID: "run-one",
		AgentName: "reported-agent", Args: json.RawMessage(`{"marker":"private-call-two"}`),
	})
	zero := 0
	routeEventRouterToolResult(t, router, ToolResultPayload{
		Tool: "shell", ID: "call-two", SessionID: "session-one", RunID: "run-one",
		AgentName: "reported-agent", Output: `{"result":"private-result-two"}`, ExitCode: &zero,
	})
	routeEventRouterToolResult(t, router, ToolResultPayload{
		Tool: "shell", ID: "call-one", SessionID: "session-one", RunID: "run-one",
		AgentName: "reported-agent", Output: `{"result":"private-result-one"}`, ExitCode: &zero,
	})

	spans := waitForEventRouterToolSpans(t, capture, 2)
	byID := make(map[string]*tracepb.Span)
	for _, span := range spans {
		byID[gatewayProtoAttribute(span.Attributes, "gen_ai.tool.call.id")] = span
	}
	for _, test := range []struct {
		id, input, output string
	}{
		{"call-one", "private-call-one", "private-result-one"},
		{"call-two", "private-call-two", "private-result-two"},
	} {
		span := byID[test.id]
		if span == nil {
			t.Fatalf("missing generated tool span for %s; ids=%v", test.id, eventRouterToolSpanIDs(spans))
		}
		attributes := hookModelV8ProtoAttributes(span)
		if !strings.Contains(attributes["gen_ai.tool.call.arguments"], test.input) ||
			!strings.Contains(attributes["gen_ai.tool.call.result"], test.output) {
			t.Errorf("tool %s cross-paired attributes=%v", test.id, attributes)
		}
		if attributes["gen_ai.conversation.id"] != "session-one" ||
			attributes["defenseclaw.run.id"] != "run-one" ||
			attributes["gen_ai.agent.name"] != "reported-agent" ||
			attributes["gen_ai.agent.id"] != "" {
			t.Errorf("tool %s reported/missing topology=%v", test.id, attributes)
		}
	}
	_, metricRequests := capture.snapshot()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) &&
		eventRouterToolMetricMaximum(metricRequests, observability.TelemetryInstrumentDefenseClawToolCalls) < 2 {
		time.Sleep(10 * time.Millisecond)
		_, metricRequests = capture.snapshot()
	}
	points := hookModelV8MetricPoints(metricRequests, observability.TelemetryInstrumentDefenseClawToolCalls)
	maximum := eventRouterToolMetricMaximum(metricRequests, observability.TelemetryInstrumentDefenseClawToolCalls)
	if maximum != 2 {
		t.Errorf("tool call metric maximum=%v points=%+v want=2", maximum, points)
	}
	assertEventRouterToolLocalLogs(t, databasePath,
		[]string{"private-call-one", "private-call-two", "private-result-one", "private-result-two"})
}

func eventRouterToolMetricMaximum(
	requests []*collectormetricspb.ExportMetricsServiceRequest,
	name string,
) float64 {
	maximum := float64(0)
	for _, point := range hookModelV8MetricPoints(requests, name) {
		if point.value > maximum {
			maximum = point.value
		}
	}
	return maximum
}

func TestEventRouterToolV8GeneratedLogsBuildAndPersist(t *testing.T) {
	router, _, databasePath := bindEventRouterToolV8Runtime(t, false, false)
	now := time.Now().UTC()
	observation := router.newEventRouterToolObservation(
		"shell", "log-only", "session-log", "run-log", "reported-agent",
		`{"input":"private-log-input"}`, `{"output":"private-log-output"}`, nil, now, now,
	)
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return now }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return "log-occurrence", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	directInput := generatedToolV8Input(observation)
	directInput.Envelope.Provenance.BinaryVersion = "8.0.0-test"
	directInput.Envelope.Provenance.ConfigGeneration = 1
	directInput.Envelope.Provenance.ConfigDigest = strings.Repeat("a", 64)
	if _, err := buildEventRouterToolLog(builder, eventRouterToolLogRequested, directInput); err != nil {
		t.Fatalf("direct requested builder: %v", err)
	}
	if err := router.emitEventRouterToolLogV8(t.Context(), eventRouterToolLogRequested, observation); err != nil {
		t.Fatalf("requested log: %v", err)
	}
	if err := router.emitEventRouterToolLogV8(t.Context(), eventRouterToolLogCompleted, observation); err != nil {
		t.Fatalf("completed log: %v", err)
	}
	assertEventRouterToolLocalLogs(t, databasePath, []string{"private-log-input", "private-log-output"})
}

func TestEventRouterToolV8MissingCallIDIsTruthfulResultOnly(t *testing.T) {
	router, capture, _ := bindEventRouterToolV8Runtime(t, true, false)
	routeEventRouterToolCall(t, router, ToolCallPayload{
		Tool: "read_file", Args: json.RawMessage(`{"path":"private-input"}`),
	})
	routeEventRouterToolResult(t, router, ToolResultPayload{
		Tool: "read_file", Output: "private-result",
	})
	spans := waitForEventRouterToolSpans(t, capture, 1)
	attributes := hookModelV8ProtoAttributes(spans[0])
	if attributes["gen_ai.tool.call.id"] != "" ||
		attributes["gen_ai.tool.call.arguments"] != "" ||
		!strings.Contains(attributes["gen_ai.tool.call.result"], "private-result") {
		t.Fatalf("missing-ID result-only attributes=%v", attributes)
	}
	if spans[0].StartTimeUnixNano != spans[0].EndTimeUnixNano {
		t.Fatalf("result-only span invented duration start=%d end=%d",
			spans[0].StartTimeUnixNano, spans[0].EndTimeUnixNano)
	}
}

func TestEventRouterToolV8BlockedCallIsTerminalWithoutPendingState(t *testing.T) {
	router, capture, databasePath := bindEventRouterToolV8Runtime(t, true, true)
	if err := router.policy.BlockToolForConnector("shell", "", "test policy"); err != nil {
		t.Fatal(err)
	}
	routeEventRouterToolCall(t, router, ToolCallPayload{
		Tool: "shell", ID: "call-blocked", Args: json.RawMessage(`{"command":"private-blocked"}`),
	})
	spans := waitForEventRouterToolSpans(t, capture, 1)
	attributes := hookModelV8ProtoAttributes(spans[0])
	if gatewayProtoAttribute(spans[0].Attributes, "defenseclaw.outcome") != "blocked" ||
		attributes["defenseclaw.tool.status"] != "blocked" ||
		spans[0].Status.GetCode() == tracepb.Status_STATUS_CODE_ERROR {
		t.Fatalf("policy-blocked tool span attributes=%v status=%v", attributes, spans[0].Status)
	}
	router.toolObservationMu.Lock()
	pending := len(router.toolObservations)
	router.toolObservationMu.Unlock()
	if pending != 0 {
		t.Fatalf("blocked call retained %d pending observations", pending)
	}
	points := waitForEventRouterMetricPoints(
		t, capture, observability.TelemetryInstrumentDefenseClawInspectEvaluations, 1,
	)
	if len(points) != 1 || points[0].attributes["defenseclaw.metric.action"] != "block" ||
		points[0].attributes["defenseclaw.connector.source"] != "openclaw" ||
		points[0].attributes["defenseclaw.security.severity"] != "HIGH" ||
		points[0].attributes["defenseclaw.metric.tool"] != "shell" {
		t.Fatalf("generated inspect metric=%+v", points)
	}
	assertEventRouterToolLocalLogs(t, databasePath, []string{"private-blocked"})
}

func TestEventRouterToolV8DangerousFindingFeedsGeneratedAlertAndDashboardMetrics(t *testing.T) {
	router, capture, _ := bindEventRouterToolV8Runtime(t, false, true)
	routeEventRouterToolCall(t, router, ToolCallPayload{
		Tool: "shell", ID: "call-dangerous", SessionID: "session-dangerous", RunID: "run-dangerous",
		Args: json.RawMessage(`{"command":"rm -rf /"}`),
	})
	inspect := waitForEventRouterMetricPoints(
		t, capture, observability.TelemetryInstrumentDefenseClawInspectEvaluations, 1,
	)
	alerts := waitForEventRouterMetricPoints(
		t, capture, observability.TelemetryInstrumentDefenseClawAlertCount, 1,
	)
	if len(inspect) != 1 || inspect[0].attributes["defenseclaw.metric.action"] != "alert" ||
		inspect[0].attributes["defenseclaw.security.severity"] != "CRITICAL" {
		t.Fatalf("dangerous inspect metric=%+v", inspect)
	}
	if len(alerts) != 1 || alerts[0].attributes["defenseclaw.metric.alert.type"] != "tool-call-flagged" ||
		alerts[0].attributes["defenseclaw.metric.alert.source"] != "tool-inspect" ||
		alerts[0].attributes["defenseclaw.metric.alert.severity"] != "CRITICAL" ||
		alerts[0].attributes["defenseclaw.connector.source"] != "openclaw" {
		t.Fatalf("dangerous alert metric=%+v", alerts)
	}
}

func waitForEventRouterMetricPoints(
	t *testing.T,
	capture *hookModelV8OTLPCapture,
	name string,
	want int,
) []hookModelV8MetricPoint {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, requests := capture.snapshot()
		points := hookModelV8MetricPoints(requests, name)
		if len(points) >= want {
			return points
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, requests := capture.snapshot()
	return hookModelV8MetricPoints(requests, name)
}

func TestEventRouterToolV8ConflictingResultDoesNotMergeCallContent(t *testing.T) {
	router := NewEventRouter(nil, nil, nil, false)
	now := time.Now().UTC()
	call := router.newEventRouterToolObservation(
		"shell", "call-conflict", "session-one", "run-one", "", `{"secret":"call-content"}`, "", nil, now, now,
	)
	if !router.rememberEventRouterToolCallV8(call) {
		t.Fatal("valid call was not retained")
	}
	completed := router.completeEventRouterToolCallV8(ToolResultPayload{
		Tool: "read_file", ID: "call-conflict", SessionID: "session-one", RunID: "run-one",
		Output: "result-content",
	}, now.Add(time.Second))
	if completed.tool != "read_file" || completed.arguments != "" || completed.result != "result-content" ||
		!completed.startedAt.Equal(completed.finishedAt) {
		t.Fatalf("conflicting result merged retained call facts: %+v", completed)
	}
}

func TestEventRouterToolV8ExpiredCallCannotPairWithLateResult(t *testing.T) {
	router := NewEventRouter(nil, nil, nil, false)
	now := time.Now().UTC()
	router.toolObservationNow = func() time.Time { return now }
	call := router.newEventRouterToolObservation(
		"shell", "call-expired", "session-one", "run-one", "", `{"secret":"old"}`, "", nil, now, now,
	)
	if !router.rememberEventRouterToolCallV8(call) {
		t.Fatal("valid call was not retained")
	}
	now = now.Add(eventRouterToolTTL + time.Second)
	completed := router.completeEventRouterToolCallV8(ToolResultPayload{
		Tool: "shell", ID: "call-expired", Output: "late-result",
	}, now)
	if completed.arguments != "" || completed.startedAt != completed.finishedAt {
		t.Fatalf("expired call paired with late result: %+v", completed)
	}
}

func TestEventRouterToolV8TraceCollectionCanBeDisabledWithoutLosingMetrics(t *testing.T) {
	router, capture, _ := bindEventRouterToolV8Runtime(t, false, true)
	routeEventRouterToolCall(t, router, ToolCallPayload{
		Tool: "shell", ID: "metric-only", Args: json.RawMessage(`{"command":"true"}`),
	})
	routeEventRouterToolResult(t, router, ToolResultPayload{Tool: "shell", ID: "metric-only", Output: "ok"})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		traceRequests, metricRequests := capture.snapshot()
		if len(hookModelV8CapturedSpans(traceRequests)) != 0 {
			t.Fatal("trace-disabled EventRouter tool exported a span")
		}
		if hookModelV8MetricPointCount(metricRequests, observability.TelemetryInstrumentDefenseClawToolCalls) == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("trace-disabled EventRouter tool did not export its independently enabled metric")
}

func waitForEventRouterToolSpans(
	t *testing.T,
	capture *hookModelV8OTLPCapture,
	want int,
) []*tracepb.Span {
	t.Helper()
	var tools []*tracepb.Span
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		tools = tools[:0]
		for _, span := range hookModelV8CapturedSpansFromCapture(capture) {
			if gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family") ==
				observability.TelemetryFamilyToolExecute {
				tools = append(tools, span)
			}
		}
		if len(tools) == want {
			return tools
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("captured generated tool spans=%d want=%d", len(tools), want)
	return nil
}

func eventRouterToolSpanIDs(spans []*tracepb.Span) []string {
	ids := make([]string, 0, len(spans))
	for _, span := range spans {
		ids = append(ids, gatewayProtoAttribute(span.Attributes, "gen_ai.tool.call.id"))
	}
	return ids
}

func assertEventRouterToolLocalLogs(t *testing.T, databasePath string, markers []string) {
	t.Helper()
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.QueryContext(t.Context(), `
		SELECT projected_record_json, COALESCE(destination_app,''), COALESCE(tool_name,''), COALESCE(tool_id,'')
		FROM audit_events
		WHERE event_name IN ('tool.invocation.requested', 'tool.invocation.completed', 'tool.invocation.blocked')
		ORDER BY timestamp ASC`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var joined strings.Builder
	for rows.Next() {
		var projected, destinationApp, toolName, toolID string
		if err := rows.Scan(&projected, &destinationApp, &toolName, &toolID); err != nil {
			t.Fatal(err)
		}
		if destinationApp != eventRouterToolProvider || toolName == "" || toolID == "" {
			t.Errorf("generated local tool projection lost dashboard dimensions destination=%q tool=%q id=%q",
				destinationApp, toolName, toolID)
		}
		joined.WriteString(projected)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, marker := range markers {
		if !strings.Contains(joined.String(), marker) {
			t.Errorf("default-unredacted local tool logs omit %q: %s", marker, joined.String())
		}
	}
}
