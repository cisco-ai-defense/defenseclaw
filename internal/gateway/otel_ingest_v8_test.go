// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

var otlpV8MetricFamilies = []observability.EventName{
	observability.EventName(observability.TelemetryInstrumentDefenseClawOTelIngestBytes),
	observability.EventName(observability.TelemetryInstrumentDefenseClawOTelIngestLastSeenTs),
	observability.EventName(observability.TelemetryInstrumentDefenseClawOTelIngestMalformed),
	observability.EventName(observability.TelemetryInstrumentDefenseClawOTelIngestRecords),
	observability.EventName(observability.TelemetryInstrumentDefenseClawOTelIngestRequests),
	observability.EventName(observability.TelemetryInstrumentDefenseClawAgentTokenUsage),
	observability.EventName(observability.TelemetryInstrumentGenAIClientOperationDuration),
	observability.EventName(observability.TelemetryInstrumentGenAIClientTokenUsage),
}

type otlpV8MetricCaptureSink struct {
	mu       sync.Mutex
	records  []telemetry.V8ProjectedMetric
	shutdown atomic.Int32
}

func (sink *otlpV8MetricCaptureSink) RecordMetric(_ context.Context, metric telemetry.V8ProjectedMetric) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.records = append(sink.records, metric)
	return nil
}

func (*otlpV8MetricCaptureSink) ForceFlush(context.Context) error { return nil }
func (sink *otlpV8MetricCaptureSink) Shutdown(context.Context) error {
	sink.shutdown.Add(1)
	return nil
}

func (sink *otlpV8MetricCaptureSink) snapshot() []telemetry.V8ProjectedMetric {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return append([]telemetry.V8ProjectedMetric(nil), sink.records...)
}

type otlpV8MetricGenerationSinks struct {
	canonical *otlpV8MetricCaptureSink
	local     *otlpV8MetricCaptureSink
}

type otlpV8MetricPipelines struct {
	mu          sync.Mutex
	generations map[uint64]otlpV8MetricGenerationSinks
}

func (pipelines *otlpV8MetricPipelines) build(
	_ context.Context,
	plan *config.ObservabilityV8Plan,
	generation uint64,
	_ telemetry.V8MetricReaderSpec,
) (telemetry.V8GenerationPipelines, error) {
	collected := false
	for _, bucket := range plan.Snapshot().Buckets {
		collected = collected || bucket.Collect.Metrics
	}
	if !collected {
		return telemetry.V8GenerationPipelines{}, nil
	}
	sinks := otlpV8MetricGenerationSinks{
		canonical: &otlpV8MetricCaptureSink{}, local: &otlpV8MetricCaptureSink{},
	}
	pipelines.mu.Lock()
	pipelines.generations[generation] = sinks
	pipelines.mu.Unlock()
	return telemetry.V8GenerationPipelines{MetricPipelines: []telemetry.V8GenerationMetricPipeline{
		{
			Destination: "canonical", Projection: telemetry.V8MetricProjectionCanonical,
			SelectedFamilies: append([]observability.EventName(nil), otlpV8MetricFamilies...), Sink: sinks.canonical,
		},
		{
			Destination: "local", Projection: telemetry.V8MetricProjectionLocal,
			SelectedFamilies: append([]observability.EventName(nil), otlpV8MetricFamilies...), Sink: sinks.local,
		},
	}}, nil
}

func (pipelines *otlpV8MetricPipelines) sinks(t *testing.T, generation uint64) otlpV8MetricGenerationSinks {
	t.Helper()
	pipelines.mu.Lock()
	defer pipelines.mu.Unlock()
	sinks, ok := pipelines.generations[generation]
	if !ok {
		t.Fatalf("metric sinks for generation %d missing", generation)
	}
	return sinks
}

type otlpV8MetricFixture struct {
	runtime   *observabilityruntime.Runtime
	store     *audit.Store
	path      string
	judgePath string
	pipelines *otlpV8MetricPipelines
}

func compileOTLPV8MetricPlan(t *testing.T, path, judgePath string, collectLogs, collectMetrics bool) *config.ObservabilityV8Plan {
	t.Helper()
	retentionDays := 0
	collectTraces := false
	source := &config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path: path, JudgeBodiesPath: judgePath, RetentionDays: &retentionDays,
		},
		Defaults: config.ObservabilityV8BucketPolicySource{Collect: config.ObservabilityV8CollectSource{
			Logs: &collectLogs, Traces: &collectTraces, Metrics: &collectMetrics,
		}},
	}
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func newOTLPV8MetricFixture(t *testing.T) otlpV8MetricFixture {
	t.Helper()
	previousInstanceID := gatewaylog.SidecarInstanceID()
	if previousInstanceID == "" {
		gatewaylog.SetSidecarInstanceID("otlp-ingest-v8-test")
		t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstanceID) })
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.db")
	judgePath := filepath.Join(directory, "judge-bodies.db")
	store, err := audit.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	engine, err := observabilityredaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	var ids atomic.Uint64
	failureBuilder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("otlp-v8-failure-%d", ids.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	reaper, err := audit.NewRetentionReaper(store, nil, 0, audit.RetentionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	retention, err := observabilityruntime.NewRetentionController(
		reaper, observabilityruntime.RetentionControllerOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	pipelines := &otlpV8MetricPipelines{generations: make(map[uint64]otlpV8MetricGenerationSinks)}
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "otlp-ingest-v8-test",
		DefenseClawInstanceID: "otlp-ingest-v8-test", GenerationPipelines: pipelines.build,
	})
	plan := compileOTLPV8MetricPlan(t, path, judgePath, true, true)
	runtime, err := observabilityruntime.New(
		t.Context(), runtimegraph.ConfigFromPlan(plan, false), observabilityruntime.Options{
			Store: store, Engine: engine, RecordBuilder: failureBuilder,
			Reporter: &discardSidecarGraphReporter{}, RetentionController: retention,
			TelemetryProviderFactory: providerFactory,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close runtime: %v", err)
		}
	})
	return otlpV8MetricFixture{
		runtime: runtime, store: store, path: path, judgePath: judgePath, pipelines: pipelines,
	}
}

type storedOTLPV8Event struct {
	action    string
	eventName string
	bucket    string
	source    string
	connector string
	severity  string
	payload   string
	mandatory int
}

func readStoredOTLPV8Events(t *testing.T, path string) []storedOTLPV8Event {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT action, COALESCE(event_name,''), COALESCE(bucket,''),
		COALESCE(source,''), COALESCE(connector,''), COALESCE(severity,''),
		COALESCE(payload_json,''), COALESCE(mandatory,0)
		FROM audit_events WHERE bucket = 'telemetry.ingest' ORDER BY timestamp, id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []storedOTLPV8Event
	for rows.Next() {
		var event storedOTLPV8Event
		if err := rows.Scan(
			&event.action, &event.eventName, &event.bucket, &event.source,
			&event.connector, &event.severity, &event.payload, &event.mandatory,
		); err != nil {
			t.Fatal(err)
		}
		result = append(result, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func disableOTLPV8Collection(t *testing.T, fixture sidecarRuntimeFixture) {
	t.Helper()
	disabled := false
	retentionDays := 0
	source := &config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path:            fixture.path,
			JudgeBodiesPath: filepath.Join(filepath.Dir(fixture.path), "judge-bodies.db"),
			RetentionDays:   &retentionDays,
		},
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketTelemetryIngest: {
				Collect: config.ObservabilityV8CollectSource{Logs: &disabled},
			},
		},
	}
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	result, reloadErr := fixture.runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(plan, false))
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("disable telemetry.ingest collection: result=%+v err=%v", result, reloadErr)
	}
}

func TestOTLPIngestV8AcceptedBatchUsesCanonicalRouterWithoutRawBody(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	body := `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"secret prompt must not persist"}}]}]}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(otelSourceHeader, "codex")
	response := httptest.NewRecorder()

	api.handleOTLPLogs(response, request)

	if response.Code != http.StatusOK || response.Body.String() != "{}" {
		t.Fatalf("response=%d %q", response.Code, response.Body.String())
	}
	events := readStoredOTLPV8Events(t, fixture.path)
	if len(events) != 2 {
		t.Fatalf("events=%d want normalized+drop: %#v", len(events), events)
	}
	var event, dropped storedOTLPV8Event
	for _, candidate := range events {
		switch candidate.eventName {
		case "telemetry.batch.normalized":
			event = candidate
		case "telemetry.records.dropped":
			dropped = candidate
		}
	}
	if event.action != "otel.ingest.logs" || event.eventName != "telemetry.batch.normalized" ||
		event.bucket != "telemetry.ingest" || event.source != "otel_receiver" ||
		event.connector != "codex" || event.severity != "INFO" || event.mandatory != 0 {
		t.Fatalf("canonical event=%#v", event)
	}
	if dropped.eventName == "" || dropped.severity != "MEDIUM" ||
		!strings.Contains(dropped.payload, `"defenseclaw.telemetry.rejection_reason_class":"unsupported_identity"`) {
		t.Fatalf("canonical drop event=%#v", dropped)
	}
	if strings.Contains(event.payload, "secret prompt") || strings.Contains(event.payload, "_splunk_hec_events") {
		t.Fatalf("canonical ingest metadata retained opaque body: %s", event.payload)
	}
	for _, want := range []string{
		`"defenseclaw.telemetry.record_count":1`,
		`"defenseclaw.telemetry.signal":"logs"`,
		`"defenseclaw.telemetry.payload_format":"json"`,
	} {
		if !strings.Contains(event.payload, want) {
			t.Errorf("payload missing %s: %s", want, event.payload)
		}
	}
}

func TestOTLPIngestV8RegistersEveryInboundSignalAsTelemetryIngestMetadata(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	for _, test := range []struct {
		path string
		body string
	}{
		{path: "/v1/logs", body: `{"resourceLogs":[]}`},
		{path: "/v1/traces", body: `{"resourceSpans":[]}`},
		{path: "/v1/metrics", body: `{"resourceMetrics":[]}`},
	} {
		request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		switch test.path {
		case "/v1/logs":
			api.handleOTLPLogs(response, request)
		case "/v1/traces":
			api.handleOTLPTraces(response, request)
		case "/v1/metrics":
			api.handleOTLPMetrics(response, request)
		}
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%q", test.path, response.Code, response.Body.String())
		}
	}
	events := readStoredOTLPV8Events(t, fixture.path)
	if len(events) != 3 {
		t.Fatalf("events=%d want three: %#v", len(events), events)
	}
	wantActions := map[string]bool{
		"otel.ingest.logs": false, "otel.ingest.traces": false, "otel.ingest.metrics": false,
	}
	for _, event := range events {
		if event.eventName != "telemetry.batch.normalized" || event.bucket != "telemetry.ingest" {
			t.Fatalf("unexpected signal metadata: %#v", event)
		}
		if _, ok := wantActions[event.action]; !ok {
			t.Fatalf("unregistered action: %#v", event)
		}
		wantActions[event.action] = true
	}
	for action, seen := range wantActions {
		if !seen {
			t.Errorf("missing canonical metadata for %s", action)
		}
	}
}

func TestOTLPIngestV8CollectionDropConstructsNoAcceptedRecord(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	disableOTLPV8Collection(t, fixture)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	request := httptest.NewRequest(http.MethodPost, "/v1/metrics", strings.NewReader(`{"resourceMetrics":[]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	api.handleOTLPMetrics(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if events := readStoredOTLPV8Events(t, fixture.path); len(events) != 0 {
		t.Fatalf("collection-disabled accepted batch constructed records: %#v", events)
	}
}

func TestOTLPIngestV8CodexSSENoHookDoesNotFabricateDashboardMetrics(t *testing.T) {
	fixture := newOTLPV8MetricFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	body := `{"resourceLogs":[{"resource":{"attributes":[
		{"key":"service.name","value":{"stringValue":"codex"}}
	]},"scopeLogs":[{"logRecords":[{"attributes":[
		{"key":"event.name","value":{"stringValue":"codex.sse_event"}},
		{"key":"event.kind","value":{"stringValue":"response.completed"}},
		{"key":"gen_ai.conversation.id","value":{"stringValue":"session-1"}},
		{"key":"gen_ai.operation.name","value":{"stringValue":"chat"}},
		{"key":"gen_ai.provider.name","value":{"stringValue":"openai"}},
		{"key":"gen_ai.request.model","value":{"stringValue":"gpt-5"}},
		{"key":"input_token_count","value":{"stringValue":"17"}},
		{"key":"output_token_count","value":{"stringValue":"23"}}
	]}]}]}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(otelSourceHeader, "codex")
	response := httptest.NewRecorder()

	api.handleOTLPLogs(response, request)

	if response.Code != http.StatusOK || response.Body.String() != "{}" {
		t.Fatalf("response=%d %q", response.Code, response.Body.String())
	}
	if events := readStoredOTLPV8Events(t, fixture.path); len(events) != 1 {
		t.Fatalf("local canonical events=%d want 1: %#v", len(events), events)
	}
	sinks := fixture.pipelines.sinks(t, 1)
	canonical := sinks.canonical.snapshot()
	local := sinks.local.snapshot()
	if len(canonical) != 4 || len(local) != 4 {
		t.Fatalf("metric deliveries canonical=%d local=%d want 4 ingest metrics each", len(canonical), len(local))
	}
	wantNames := map[string]int{
		"defenseclaw.otel.ingest.requests":     1,
		"defenseclaw.otel.ingest.records":      1,
		"defenseclaw.otel.ingest.bytes":        1,
		"defenseclaw.otel.ingest.last_seen_ts": 1,
	}
	gotNames := make(map[string]int)
	for _, metric := range canonical {
		gotNames[metric.Descriptor().Name]++
		if metric.Generation() != 1 || metric.ConfigDigest() == "" || metric.Destination() != "canonical" {
			t.Fatalf("canonical metric lost generation ownership: generation=%d digest=%q destination=%q",
				metric.Generation(), metric.ConfigDigest(), metric.Destination())
		}
	}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("canonical metric names=%v want %v", gotNames, wantNames)
	}
	// The token-bearing SSE record can produce root-scoped agent accounting only
	// after an exact hook lifecycle join. Standard token usage belongs to the
	// native codex.turn.token_usage histogram, and duration belongs to the exact
	// session_task.turn span. This log-only fixture has neither authority.
	for _, metric := range local {
		if metric.Descriptor().Name != "defenseclaw.otel.ingest.requests" {
			continue
		}
		attributes := metric.Attributes()
		if attributes["connector"] != "codex" || attributes["source"] != "codex" ||
			attributes["signal"] != "logs" || attributes["result"] != "ok" ||
			metric.Profile() != observability.RuntimeLocalObservabilityProfile {
			t.Fatalf("local PR412 request projection=%v profile=%q", attributes, metric.Profile())
		}
	}
}

func TestOTLPIngestV8DoesNotDualWriteLegacyProvider(t *testing.T) {
	fixture := newOTLPV8MetricFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(
		`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{}]}]}]}`,
	))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(otelSourceHeader, "codex")
	response := httptest.NewRecorder()

	api.handleOTLPLogs(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	sinks := fixture.pipelines.sinks(t, 1)
	if len(sinks.local.snapshot()) != 4 || len(sinks.canonical.snapshot()) != 4 {
		t.Fatalf("canonical destinations local=%d canonical=%d want four ingest metrics each",
			len(sinks.local.snapshot()), len(sinks.canonical.snapshot()))
	}
}

func TestOTLPIngestV8MetricCollectionDisabledBuildsNothing(t *testing.T) {
	fixture := newOTLPV8MetricFixture(t)
	disabled := compileOTLPV8MetricPlan(t, fixture.path, fixture.judgePath, false, false)
	result, reloadErr := fixture.runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(disabled, false))
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("disable reload=%s err=%v", result.Status(), reloadErr)
	}
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	request := httptest.NewRequest(http.MethodPost, "/v1/metrics", strings.NewReader(`{"resourceMetrics":[]}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(otelSourceHeader, "claudecode")
	response := httptest.NewRecorder()

	api.handleOTLPMetrics(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if events := readStoredOTLPV8Events(t, fixture.path); len(events) != 0 {
		t.Fatalf("disabled log collection persisted: %#v", events)
	}
	first := fixture.pipelines.sinks(t, 1)
	if len(first.canonical.snapshot()) != 0 || len(first.local.snapshot()) != 0 {
		t.Fatal("disabled generation received metrics")
	}
	fixture.pipelines.mu.Lock()
	_, builtDisabledMetricPipelines := fixture.pipelines.generations[2]
	fixture.pipelines.mu.Unlock()
	if builtDisabledMetricPipelines {
		t.Fatal("metric-disabled reload constructed destination metric pipelines")
	}
}

func TestOTLPIngestV8ReloadPinsDerivedMetricsToPublishedGeneration(t *testing.T) {
	fixture := newOTLPV8MetricFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	emit := func() {
		request := httptest.NewRequest(http.MethodPost, "/v1/traces", strings.NewReader(`{"resourceSpans":[]}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(otelSourceHeader, "codex")
		response := httptest.NewRecorder()
		api.handleOTLPTraces(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
		}
	}
	emit()
	first := fixture.pipelines.sinks(t, 1)
	if len(first.canonical.snapshot()) != 3 || len(first.local.snapshot()) != 3 {
		t.Fatalf("generation one deliveries canonical=%d local=%d want requests+bytes+last_seen",
			len(first.canonical.snapshot()), len(first.local.snapshot()))
	}
	enabled := compileOTLPV8MetricPlan(t, fixture.path, fixture.judgePath, true, true)
	result, reloadErr := fixture.runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(enabled, false))
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload=%s err=%v", result.Status(), reloadErr)
	}
	emit()
	second := fixture.pipelines.sinks(t, 2)
	if len(first.canonical.snapshot()) != 3 || len(first.local.snapshot()) != 3 ||
		len(second.canonical.snapshot()) != 3 || len(second.local.snapshot()) != 3 {
		t.Fatalf("cross-generation delivery first=%d/%d second=%d/%d",
			len(first.canonical.snapshot()), len(first.local.snapshot()),
			len(second.canonical.snapshot()), len(second.local.snapshot()))
	}
	for _, metric := range second.canonical.snapshot() {
		if metric.Generation() != 2 {
			t.Fatalf("new metric retained stale generation %d", metric.Generation())
		}
	}
}

func TestOTLPIngestV8MalformedBatchPersistsMandatoryFloorWhenCollectionDisabled(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	disableOTLPV8Collection(t, fixture)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	request := httptest.NewRequest(http.MethodPost, "/v1/traces", strings.NewReader(`{"resourceSpans":[],"opaque":"raw"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	api.handleOTLPTraces(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	events := readStoredOTLPV8Events(t, fixture.path)
	if len(events) != 1 {
		t.Fatalf("events=%d want mandatory floor: %#v", len(events), events)
	}
	if events[0].eventName != "telemetry.batch.rejected" || events[0].action != "otel.ingest.malformed" ||
		events[0].severity != "MEDIUM" || events[0].mandatory != 1 {
		t.Fatalf("malformed floor=%#v", events[0])
	}
	if strings.Contains(events[0].payload, "opaque") || strings.Contains(events[0].payload, "raw") {
		t.Fatalf("mandatory floor retained malformed body: %s", events[0].payload)
	}
	if strings.Contains(events[0].payload, "resource_count") || strings.Contains(events[0].payload, "normalized_bytes") {
		t.Fatalf("mandatory floor fabricated unavailable normalization facts: %s", events[0].payload)
	}
}

func TestOTLPIngestV8MalformedFloorAndDashboardMetricsRemainIndependent(t *testing.T) {
	fixture := newOTLPV8MetricFixture(t)
	plan := compileOTLPV8MetricPlan(t, fixture.path, fixture.judgePath, false, true)
	result, reloadErr := fixture.runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(plan, false))
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload=%s err=%v", result.Status(), reloadErr)
	}
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	request := httptest.NewRequest(http.MethodPost, "/v1/metrics", strings.NewReader(
		`{"resourceMetrics":[],"opaque":"must-not-persist"}`,
	))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(otelSourceHeader, "claudecode")
	response := httptest.NewRecorder()

	api.handleOTLPMetrics(response, request)

	if response.Code != http.StatusOK || response.Body.String() != "{}" {
		t.Fatalf("response=%d %q", response.Code, response.Body.String())
	}
	events := readStoredOTLPV8Events(t, fixture.path)
	if len(events) != 1 || events[0].eventName != "telemetry.batch.rejected" || events[0].mandatory != 1 ||
		strings.Contains(events[0].payload, "opaque") || strings.Contains(events[0].payload, "must-not-persist") {
		t.Fatalf("mandatory floor=%#v", events)
	}
	sinks := fixture.pipelines.sinks(t, 2)
	for name, metrics := range map[string][]telemetry.V8ProjectedMetric{
		"canonical": sinks.canonical.snapshot(), "local": sinks.local.snapshot(),
	} {
		if len(metrics) != 4 {
			t.Fatalf("%s malformed metrics=%d want requests+malformed+bytes+last_seen", name, len(metrics))
		}
		counts := make(map[string]int)
		for _, metric := range metrics {
			counts[metric.Descriptor().Name]++
		}
		if counts["defenseclaw.otel.ingest.requests"] != 1 ||
			counts["defenseclaw.otel.ingest.malformed"] != 1 ||
			counts["defenseclaw.otel.ingest.bytes"] != 1 ||
			counts["defenseclaw.otel.ingest.last_seen_ts"] != 1 {
			t.Fatalf("%s malformed metric families=%v", name, counts)
		}
	}
}

func TestOTLPIngestV8MalformedOrdinaryRecordUsesGeneratedOptionalFacts(t *testing.T) {
	fixture := newOTLPV8MetricFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	request := httptest.NewRequest(http.MethodPost, "/v1/traces", strings.NewReader(
		`{"resourceSpans":[],"unregistered":"raw-value"}`,
	))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(otelSourceHeader, "codex")
	response := httptest.NewRecorder()

	api.handleOTLPTraces(response, request)

	if response.Code != http.StatusOK || response.Body.String() != "{}" {
		t.Fatalf("response=%d %q", response.Code, response.Body.String())
	}
	events := readStoredOTLPV8Events(t, fixture.path)
	if len(events) != 1 || events[0].eventName != "telemetry.batch.rejected" || events[0].mandatory != 1 {
		t.Fatalf("rejected event=%#v", events)
	}
	for _, want := range []string{
		`"defenseclaw.telemetry.signal":"traces"`,
		`"defenseclaw.telemetry.payload_format":"json"`,
		`"defenseclaw.telemetry.rejection_reason_class":"invalid_json"`,
	} {
		if !strings.Contains(events[0].payload, want) {
			t.Errorf("payload missing %s: %s", want, events[0].payload)
		}
	}
	for _, forbidden := range []string{"unregistered", "raw-value", "resource_count", "normalized_bytes"} {
		if strings.Contains(events[0].payload, forbidden) {
			t.Fatalf("rejected record retained/fabricated %q: %s", forbidden, events[0].payload)
		}
	}
}

func TestOTLPIngestV8OversizeReturns413AndPersistsContentFreeFloor(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(
		`{"resourceLogs":[],"secret":"oversize-content"}`,
	))
	request.Body = http.MaxBytesReader(httptest.NewRecorder(), request.Body, 8)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(otelSourceHeader, "codex")
	response := httptest.NewRecorder()

	api.handleOTLPLogs(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	events := readStoredOTLPV8Events(t, fixture.path)
	if len(events) != 1 || events[0].eventName != "telemetry.batch.rejected" || events[0].mandatory != 1 ||
		!strings.Contains(events[0].payload, `"defenseclaw.telemetry.rejection_reason_class":"body_too_large"`) ||
		strings.Contains(events[0].payload, "oversize-content") {
		t.Fatalf("oversize floor=%#v", events)
	}
}

func TestOTLPIngestV8WholeBatchSuccessNeverClaimsPartialSuccess(t *testing.T) {
	fixture := newOTLPV8MetricFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	body := `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{},{}]}]}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(otelSourceHeader, "codex")
	response := httptest.NewRecorder()

	api.handleOTLPLogs(response, request)

	if response.Code != http.StatusOK || response.Body.String() != "{}" || strings.Contains(response.Body.String(), "partialSuccess") {
		t.Fatalf("response=%d %q", response.Code, response.Body.String())
	}
	events := readStoredOTLPV8Events(t, fixture.path)
	seenNormalized, seenDrop := false, false
	for _, event := range events {
		seenNormalized = seenNormalized || event.eventName == "telemetry.batch.normalized" &&
			strings.Contains(event.payload, `"defenseclaw.telemetry.record_count":2`)
		seenDrop = seenDrop || event.eventName == "telemetry.records.dropped" &&
			strings.Contains(event.payload, `"defenseclaw.telemetry.record_count":2`) &&
			strings.Contains(event.payload, `"defenseclaw.telemetry.rejection_reason_class":"unsupported_identity"`)
	}
	if len(events) != 2 || !seenNormalized || !seenDrop {
		t.Fatalf("whole-batch event=%#v", events)
	}
	local := fixture.pipelines.sinks(t, 1).local.snapshot()
	var recordMetric telemetry.V8ProjectedMetric
	for _, metric := range local {
		if metric.Descriptor().Name == "defenseclaw.otel.ingest.records" {
			recordMetric = metric
		}
	}
	if value, ok := recordMetric.Value().Int64(); !ok || value != 2 {
		t.Fatalf("record metric value=%d ok=%t", value, ok)
	}
}

func TestOTLPIngestV8AuthenticationFailurePersistsMandatoryTelemetryIngest(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	disableOTLPV8Collection(t, fixture)
	api := &APIServer{scannerCfg: &config.Config{}}
	api.scannerCfg.Gateway.Token = "configured-token"
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	handler := api.tokenAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unauthenticated request reached OTLP handler")
	}))
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(`{"resourceLogs":[]}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	events := readStoredOTLPV8Events(t, fixture.path)
	if len(events) != 1 || events[0].eventName != "telemetry.authentication.failed" ||
		events[0].mandatory != 1 || events[0].connector != "unknown" {
		t.Fatalf("authentication floor=%#v", events)
	}
}

func TestNormalizeOTLPIngestBodyRejectsNestedUnknownProtobufFields(t *testing.T) {
	record := &logspb.LogRecord{Body: &commonpb.AnyValue{
		Value: &commonpb.AnyValue_StringValue{StringValue: "safe"},
	}}
	record.ProtoReflect().SetUnknown(protowire.AppendVarint(
		protowire.AppendTag(nil, 999, protowire.VarintType), 1,
	))
	payload := &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{record}}},
	}}}
	body, err := proto.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := normalizeOTLPIngestBody(body, otelSignalLogs, "application/x-protobuf"); err == nil {
		t.Fatal("nested unknown protobuf field was silently preserved or dropped")
	}
}

func TestNormalizeOTLPIngestBodyRejectsUnknownJSONFields(t *testing.T) {
	body := []byte(`{"resourceLogs":[],"_splunk_hec_events":[{"event":"raw prompt"}]}`)
	if _, _, err := normalizeOTLPIngestBody(body, otelSignalLogs, "application/json"); err == nil {
		t.Fatal("unknown transport-specific field was silently accepted")
	}
}

func TestNormalizeOTLPIngestBodyRejectsDuplicateJSONMembersAtEveryDepth(t *testing.T) {
	tests := []string{
		`{"resourceLogs":[],"resourceLogs":[]}`,
		`{"resourceLogs":[{"scopeLogs":[],"scopeLogs":[]}]}`,
		`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"first","stringValue":"second"}}]}]}]}`,
	}
	for _, body := range tests {
		if _, _, err := normalizeOTLPIngestBody([]byte(body), otelSignalLogs, "application/json"); err == nil {
			t.Fatalf("duplicate JSON member was silently normalized: %s", body)
		}
	}

	// Repeated OTLP attribute keys are distinct list entries, not duplicate
	// lexical JSON members. Decode preserves them so the generated binding can
	// reject only targets for which the duplicate is ambiguous.
	valid := []byte(`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"attributes":[` +
		`{"key":"event.name","value":{"stringValue":"first"}},` +
		`{"key":"event.name","value":{"stringValue":"second"}}]}]}]}]}`)
	decoded, err := decodeOTLPIngestBody(valid, otelSignalLogs, "application/json")
	if err != nil {
		t.Fatalf("attribute-list duplicates must reach generated mapping: %v", err)
	}
	request, ok := decoded.message.(*collectorlogspb.ExportLogsServiceRequest)
	if !ok || len(request.GetResourceLogs()) != 1 ||
		len(request.GetResourceLogs()[0].GetScopeLogs()[0].GetLogRecords()[0].GetAttributes()) != 2 {
		t.Fatalf("typed OTLP model did not retain repeated attribute entries: %#v", decoded.message)
	}
}

func TestDecodedOTLPIngestStatsCountsLeafRecordsAndMetricDataPoints(t *testing.T) {
	tests := []struct {
		name      string
		signal    otelIngestSignal
		body      string
		resources int64
		records   int64
	}{
		{
			name: "logs", signal: otelSignalLogs, resources: 1, records: 2,
			body: `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{},{}]}]}]}`,
		},
		{
			name: "traces", signal: otelSignalTraces, resources: 1, records: 2,
			body: `{"resourceSpans":[{"scopeSpans":[{"spans":[{},{}]}]}]}`,
		},
		{
			name: "metric data points", signal: otelSignalMetrics, resources: 1, records: 4,
			body: `{"resourceMetrics":[{"scopeMetrics":[{"metrics":[` +
				`{"name":"gauge","gauge":{"dataPoints":[{"asInt":"1"},{"asDouble":2.5}]}},` +
				`{"name":"sum","sum":{"aggregationTemporality":1,"isMonotonic":true,"dataPoints":[{"asInt":"3"}]}},` +
				`{"name":"histogram","histogram":{"aggregationTemporality":1,"dataPoints":[{"count":"2","sum":4.0}]}}` +
				`]}]}]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoded, err := decodeOTLPIngestBody([]byte(test.body), test.signal, "application/json")
			if err != nil {
				t.Fatal(err)
			}
			stats, err := decodedOTLPIngestStats(decoded.message, test.signal)
			if err != nil {
				t.Fatal(err)
			}
			if stats.Resources != test.resources || stats.Records != test.records {
				t.Fatalf("stats=%+v want resources=%d records=%d", stats, test.resources, test.records)
			}
		})
	}

	decoded, err := decodeOTLPIngestBody([]byte(tests[0].body), otelSignalLogs, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodedOTLPIngestStats(decoded.message, otelSignalTraces); err == nil {
		t.Fatal("signal/message type mismatch was silently accepted")
	}
}

func TestOTLPIngestV8SelfExportMarkersStopRecursiveEmission(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	classifier := mustOTLPInboundClassifierV8(t)
	match, ok := classifier.catalog.Match("otlp.native.log.v8.log.telemetry.batch.accepted")
	if !ok {
		t.Fatal("native telemetry.batch.accepted match missing")
	}
	leaf, source := inboundFixtureLeafForMatch(t, match)
	setInboundFixtureAttribute(
		leaf.logRecord, classifier.catalog.WireContract().ForwardInstanceKey, gatewaylog.SidecarInstanceID(),
	)
	leaf.leafAttributes = newOTLPTypedAttributeIndex(leaf.logRecord.Attributes)
	leaf.logRecord.Body = inboundProjectedLogBody(t, leaf)
	body, err := proto.Marshal(&collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource:  &resourcepb.Resource{Attributes: inboundFixtureResourceAttributes(&leaf)},
		SchemaUrl: leaf.resource.schemaURL,
		ScopeLogs: []*logspb.ScopeLogs{{
			Scope:     &commonpb.InstrumentationScope{Name: leaf.scope.name, Version: leaf.scope.version},
			SchemaUrl: leaf.scope.schemaURL, LogRecords: []*logspb.LogRecord{leaf.logRecord},
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/x-protobuf")
	request.Header.Set(otelSourceHeader, source)
	response := httptest.NewRecorder()

	api.handleOTLPLogs(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if events := readStoredOTLPV8Events(t, fixture.path); len(events) != 0 {
		t.Fatalf("self export recursively emitted telemetry: %#v", events)
	}
}

func TestOTLPInboundSelfOtherAndMixedBatch(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	classifier := mustOTLPInboundClassifierV8(t)
	match, ok := classifier.catalog.Match("otlp.native.log.v8.log.telemetry.batch.accepted")
	if !ok {
		t.Fatal("native telemetry.batch.accepted match missing")
	}
	leaf, source := inboundFixtureLeafForMatch(t, match)
	setInboundFixtureAttribute(
		leaf.logRecord, classifier.catalog.WireContract().ForwardInstanceKey, gatewaylog.SidecarInstanceID(),
	)
	leaf.leafAttributes = newOTLPTypedAttributeIndex(leaf.logRecord.Attributes)
	leaf.logRecord.Body = inboundProjectedLogBody(t, leaf)
	message := &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource:  &resourcepb.Resource{Attributes: inboundFixtureResourceAttributes(&leaf)},
		SchemaUrl: leaf.resource.schemaURL,
		ScopeLogs: []*logspb.ScopeLogs{{
			Scope:      &commonpb.InstrumentationScope{Name: leaf.scope.name, Version: leaf.scope.version},
			SchemaUrl:  leaf.scope.schemaURL,
			LogRecords: []*logspb.LogRecord{leaf.logRecord},
		}},
	}, {
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{
			Body: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "external record must keep the batch alive"}},
		}}}},
	}}}
	body, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/x-protobuf")
	request.Header.Set(otelSourceHeader, source)
	response := httptest.NewRecorder()

	api.handleOTLPLogs(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	events := readStoredOTLPV8Events(t, fixture.path)
	seenNormalized, seenDrop := false, false
	for _, event := range events {
		seenNormalized = seenNormalized || event.eventName == "telemetry.batch.normalized" &&
			strings.Contains(event.payload, `"defenseclaw.telemetry.record_count":2`)
		seenDrop = seenDrop || event.eventName == "telemetry.records.dropped" &&
			strings.Contains(event.payload, `"defenseclaw.telemetry.record_count":1`) &&
			strings.Contains(event.payload, `"defenseclaw.telemetry.rejection_reason_class":"unsupported_identity"`)
	}
	if len(events) != 2 || !seenNormalized || !seenDrop {
		t.Fatalf("mixed batch was dropped or misclassified: %#v", events)
	}
}

func TestDefenseClawSelfExportRequiresEveryTraceOrMetricItem(t *testing.T) {
	traceOwned := `{"resourceSpans":[{"resource":{"attributes":[
		{"key":"defenseclaw.instance.id","value":{"stringValue":"sidecar-1"}}
	]},"scopeSpans":[{"spans":[{"attributes":[
		{"key":"defenseclaw.bucket","value":{"stringValue":"agent.lifecycle"}},
		{"key":"defenseclaw.span.family","value":{"stringValue":"span.agent.invoke"}},
		{"key":"defenseclaw.config.generation","value":{"intValue":"1"}}
	]}]}]}]}`
	traceMixed := strings.Replace(traceOwned, `]}]}]}]}`, `]},{"name":"external"}]}]}]}`, 1)
	metricOwned := `{"resourceMetrics":[{"resource":{"attributes":[
		{"key":"defenseclaw.instance.id","value":{"stringValue":"sidecar-1"}}
	]},"scopeMetrics":[{"metrics":[{"name":"defenseclaw.otel.ingest.requests"}]}]}]}`
	metricMixed := strings.Replace(metricOwned, `}]}]}]}`, `},{"name":"external.metric"}]}]}]}`, 1)
	for _, test := range []struct {
		name   string
		signal otelIngestSignal
		body   string
		want   bool
	}{
		{name: "all trace items owned", signal: otelSignalTraces, body: traceOwned, want: true},
		{name: "mixed trace items", signal: otelSignalTraces, body: traceMixed, want: false},
		{name: "all metric items owned", signal: otelSignalMetrics, body: metricOwned, want: true},
		{name: "mixed metric items", signal: otelSignalMetrics, body: metricMixed, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := isDefenseClawSelfExport([]byte(test.body), test.signal); got != test.want {
				t.Fatalf("isDefenseClawSelfExport()=%t want %t body=%s", got, test.want, test.body)
			}
		})
	}
}

func TestDefenseClawSelfExportRejectsSpoofedOrIncompleteOwnershipMarkers(t *testing.T) {
	logWithoutOwnedResource := `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"attributes":[
		{"key":"defenseclaw.record.id","value":{"stringValue":"record-1"}},
		{"key":"defenseclaw.bucket","value":{"stringValue":"telemetry.ingest"}},
		{"key":"defenseclaw.signal","value":{"stringValue":"logs"}},
		{"key":"defenseclaw.event.name","value":{"stringValue":"telemetry.batch.accepted"}}
	]}]}]}]}`
	traceWithUnknownFamily := `{"resourceSpans":[{"resource":{"attributes":[
		{"key":"defenseclaw.instance.id","value":{"stringValue":"sidecar-1"}}
	]},"scopeSpans":[{"spans":[{"attributes":[
		{"key":"defenseclaw.bucket","value":{"stringValue":"agent.lifecycle"}},
		{"key":"defenseclaw.span.family","value":{"stringValue":"span.attacker.fabricated"}},
		{"key":"defenseclaw.config.generation","value":{"intValue":"1"}}
	]}]}]}]}`
	if isDefenseClawSelfExport([]byte(logWithoutOwnedResource), otelSignalLogs) {
		t.Fatal("external log markers without an owned resource suppressed the batch")
	}
	if isDefenseClawSelfExport([]byte(traceWithUnknownFamily), otelSignalTraces) {
		t.Fatal("unregistered trace family suppressed the batch")
	}
}

func TestOTLPIngestUnboundFailsClosedWithoutLegacyWrite(t *testing.T) {
	store, logger := newOTLPIngestTestStore(t)
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger)
	if api.hasOTLPObservabilityRuntime() {
		t.Fatal("NewAPIServer must not invent an observability runtime")
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(`{"resourceLogs":[]}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(otelSourceHeader, "codex")
	response := httptest.NewRecorder()

	api.handleOTLPLogs(response, request)
	logger.Close()

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	rows, err := store.ListEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("unbound receiver used legacy persistence: %#v", rows)
	}
}
