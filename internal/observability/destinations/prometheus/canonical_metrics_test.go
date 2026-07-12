// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package prometheus

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	prom "github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type generatedMetricReporter struct{}

func (generatedMetricReporter) PlatformHealth(*runtimegraph.Graph, runtimegraph.Report) error {
	return nil
}
func (generatedMetricReporter) ComplianceActivity(*runtimegraph.Graph, runtimegraph.Report) error {
	return nil
}

type failingGeneratedMetricSink struct{ records atomic.Int64 }

func (sink *failingGeneratedMetricSink) RecordMetric(context.Context, telemetry.V8ProjectedMetric) error {
	sink.records.Add(1)
	return errors.New("injected sibling failure")
}
func (*failingGeneratedMetricSink) ForceFlush(context.Context) error { return nil }
func (*failingGeneratedMetricSink) Shutdown(context.Context) error   { return nil }

type capturedMetricListeners struct {
	mu        sync.Mutex
	listeners []net.Listener
	failAt    int
	calls     int
}

func (capture *capturedMetricListeners) listen(
	_ context.Context,
	network string,
	_ string,
) (net.Listener, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	capture.calls++
	if capture.failAt > 0 && capture.calls == capture.failAt {
		return nil, fmt.Errorf("injected listener failure")
	}
	listener, err := net.Listen(network, "127.0.0.1:0")
	if err == nil {
		capture.listeners = append(capture.listeners, listener)
	}
	return listener, err
}

func (capture *capturedMetricListeners) count() int {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return len(capture.listeners)
}

func (capture *capturedMetricListeners) listener(t *testing.T, index int) net.Listener {
	t.Helper()
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if index < 0 || index >= len(capture.listeners) {
		t.Fatalf("listener index=%d count=%d", index, len(capture.listeners))
	}
	return capture.listeners[index]
}

type generatedMetricHarness struct {
	component *telemetry.V8ProviderComponent
	provider  *telemetry.Provider
	plan      *config.ObservabilityV8Plan
	listen    *capturedMetricListeners
	ids       atomic.Uint64
}

func newGeneratedMetricHarness(
	t *testing.T,
	plan *config.ObservabilityV8Plan,
	listen *capturedMetricListeners,
) *generatedMetricHarness {
	return newGeneratedMetricHarnessGeneration(t, plan, listen, 1)
}

func newGeneratedMetricHarnessGeneration(
	t *testing.T,
	plan *config.ObservabilityV8Plan,
	listen *capturedMetricListeners,
	generation uint64,
) *generatedMetricHarness {
	t.Helper()
	if listen == nil {
		listen = &capturedMetricListeners{}
	}
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "native-prometheus-test",
		GenerationPipelines: func(
			ctx context.Context,
			candidate *config.ObservabilityV8Plan,
			generation uint64,
			spec telemetry.V8MetricReaderSpec,
		) (telemetry.V8GenerationPipelines, error) {
			return PreparePlanPipelines(
				ctx, candidate, generation, spec, Options{Listen: listen.listen},
			)
		},
	})
	componentValue, err := providerFactory.Prepare(
		context.Background(),
		runtimegraph.BuildInput{
			Config: runtimegraph.ConfigFromPlan(plan, false), Generation: generation,
		},
		&runtimegraph.Acquisitions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	component, ok := componentValue.(*telemetry.V8ProviderComponent)
	if !ok {
		t.Fatalf("provider component type=%T", componentValue)
	}
	component.Activate()
	provider, ok := component.Provider()
	if !ok {
		t.Fatal("active graph has no v8 provider")
	}
	harness := &generatedMetricHarness{
		component: component, provider: provider, plan: plan, listen: listen,
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = harness.component.StopIntake(ctx)
		if err := harness.provider.Shutdown(ctx); err != nil {
			t.Errorf("close generated metric harness: %v", err)
		}
		_ = harness.component.Close(ctx)
	})
	return harness
}

func (harness *generatedMetricHarness) envelope() observability.FamilyEnvelopeInput {
	digest, generation, ok := harness.provider.V8PlanBinding()
	if !ok {
		panic("provider is not plan-bound")
	}
	return observability.FamilyEnvelopeInput{
		Source: "gateway",
		Provenance: observability.FamilyProvenanceInput{
			Producer: "defenseclaw", BinaryVersion: "8.0.0",
			ConfigGeneration: int64(generation), ConfigDigest: digest,
		},
	}
}

func (harness *generatedMetricHarness) builder(t *testing.T) *observability.FamilyBuilder {
	t.Helper()
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Unix(100, 0).UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("prom-metric-%d", harness.ids.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return builder
}

type generatedMetricBuild struct {
	record observability.Record
	err    error
}

func generatedMetricBuilt(record observability.Record, err error) generatedMetricBuild {
	return generatedMetricBuild{record: record, err: err}
}

func (harness *generatedMetricHarness) record(t *testing.T, built generatedMetricBuild) {
	t.Helper()
	if built.err != nil {
		t.Fatal(built.err)
	}
	result, recordErr := harness.provider.RecordGeneratedMetric(t.Context(), built.record)
	if recordErr != nil || result != (telemetry.V8MetricRecordResult{Matched: 1, Delivered: 1}) {
		t.Fatalf("record %s result=%+v err=%v", built.record.EventName(), result, recordErr)
	}
}

func scrapeCapturedMetric(t *testing.T, listener net.Listener, path string) string {
	t.Helper()
	response, err := testHTTPClient().Get("http://" + listener.Addr().String() + path)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("scrape status=%d body=%q", response.StatusCode, string(body))
	}
	return string(body)
}

func TestGeneratedRecordScrapeCoversEveryCatalogShapeAliasesBoundsAndCumulativeSemantics(t *testing.T) {
	defaultGatherer := prom.DefaultGatherer
	defaultMeterProvider := otel.GetMeterProvider()
	plan, _ := compilePrometheus(t, allMetricsSource("metrics"), true)
	harness := newGeneratedMetricHarness(t, plan, nil)
	if harness.listen.count() != 1 {
		t.Fatalf("listeners=%d", harness.listen.count())
	}
	builder, envelope := harness.builder(t), harness.envelope()

	// counter/int64: two records prove the pull view is cumulative even though
	// the generated application contract is delta.
	harness.record(t, generatedMetricBuilt(builder.BuildMetricDefenseClawActivityTotal(
		observability.MetricDefenseClawActivityTotalInput{
			Envelope: envelope, Value: 2,
			DefenseClawMetricAction:     observability.Present("reload"),
			DefenseClawMetricActor:      observability.Present("operator"),
			DefenseClawMetricTargetType: observability.Present("config"),
		},
	)))
	harness.record(t, generatedMetricBuilt(builder.BuildMetricDefenseClawActivityTotal(
		observability.MetricDefenseClawActivityTotalInput{
			Envelope: envelope, Value: 3,
			DefenseClawMetricAction:     observability.Present("reload"),
			DefenseClawMetricActor:      observability.Present("operator"),
			DefenseClawMetricTargetType: observability.Present("config"),
		},
	)))
	// histogram/int64 with an authored explicit boundary table.
	harness.record(t, generatedMetricBuilt(builder.BuildMetricDefenseClawJudgePersistBatchSize(
		observability.MetricDefenseClawJudgePersistBatchSizeInput{Envelope: envelope, Value: 7},
	)))
	// histogram/double with PR #412's connector aliases and boundaries.
	harness.record(t, generatedMetricBuilt(builder.BuildMetricDefenseClawConnectorHookLatency(
		observability.MetricDefenseClawConnectorHookLatencyInput{
			Envelope: envelope, Value: 7.5,
			DefenseClawConnectorSource: observability.Present("codex"),
			DefenseClawMetricEventType: observability.Present("prompt"),
			DefenseClawMetricReason:    observability.Present("allow"),
			DefenseClawMetricResult:    observability.Present("ok"),
		},
	)))
	// gauge/int64.
	harness.record(t, generatedMetricBuilt(builder.BuildMetricDefenseClawAgentDiscoveryInstalled(
		observability.MetricDefenseClawAgentDiscoveryInstalledInput{
			Envelope: envelope, Value: 4,
			DefenseClawConnectorSource: observability.Present("codex"),
		},
	)))
	// gauge/double: unmapped canonical identity labels must survive alongside
	// the connector/type aliases used by the Agent360 dashboards.
	harness.record(t, generatedMetricBuilt(builder.BuildMetricDefenseClawAgentLastSeen(
		observability.MetricDefenseClawAgentLastSeenInput{
			Envelope: envelope, Value: 123.5,
			DefenseClawConnectorSource:  observability.Present("codex"),
			DefenseClawAgentLifecycleID: observability.Present("lifecycle-1"),
			GenAIAgentID:                observability.Present("agent-1"),
			DefenseClawAgentType:        observability.Present("root"),
		},
	)))
	// updowncounter/int64: the cumulative pull value retains signed updates.
	harness.record(t, generatedMetricBuilt(builder.BuildMetricDefenseClawAuditSinkCircuitState(
		observability.MetricDefenseClawAuditSinkCircuitStateInput{
			Envelope: envelope, Value: 3,
			DefenseClawMetricSinkKind: observability.Present("otlp"),
			DefenseClawMetricSinkName: observability.Present("primary"),
		},
	)))
	harness.record(t, generatedMetricBuilt(builder.BuildMetricDefenseClawAuditSinkCircuitState(
		observability.MetricDefenseClawAuditSinkCircuitStateInput{
			Envelope: envelope, Value: -1,
			DefenseClawMetricSinkKind: observability.Present("otlp"),
			DefenseClawMetricSinkName: observability.Present("primary"),
		},
	)))

	body := scrapeCapturedMetric(t, harness.listen.listener(t, 0), "/metrics")
	for _, want := range []string{
		`# HELP defenseclaw_connector_hook_latency_milliseconds Connector hook handler latency.`,
		`defenseclaw_activity_total{action="reload",actor="operator",target_type="config"} 5`,
		`defenseclaw_judge_persist_batch_size_bucket{le="8"} 1`,
		`defenseclaw_connector_hook_latency_milliseconds_bucket{connector="codex",event_type="prompt",reason="allow",result="ok",le="10"} 1`,
		`defenseclaw_connector_hook_latency_milliseconds_sum{connector="codex",event_type="prompt",reason="allow",result="ok"} 7.5`,
		`defenseclaw_connector_hook_latency_milliseconds_count{connector="codex",event_type="prompt",reason="allow",result="ok"} 1`,
		`defenseclaw_agent_discovery_installed_ratio{connector="codex"} 4`,
		`defenseclaw_agent_last_seen_seconds{connector="codex",defenseclaw_agent_lifecycle_id="lifecycle-1",gen_ai_agent_id="agent-1",gen_ai_agent_type="root"} 123.5`,
		`defenseclaw_audit_sink_circuit_state{sink_kind="otlp",sink_name="primary"} 2`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q\n%s", want, body)
		}
	}
	for _, forbidden := range []string{
		"defenseclaw_metric_action=", "defenseclaw_connector_source=", "otel_scope_", "target_info", "go_gc_", "process_cpu_",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("generated private scrape contains %q", forbidden)
		}
	}
	if prom.DefaultGatherer != defaultGatherer {
		t.Fatal("generated destination replaced the process-global Prometheus gatherer")
	}
	if otel.GetMeterProvider() != defaultMeterProvider {
		t.Fatal("generated destination replaced the process-global OTel meter provider")
	}

	covered := map[string]struct{}{
		"counter/int64": {}, "histogram/int64": {}, "histogram/double": {},
		"gauge/int64": {}, "gauge/double": {}, "updowncounter/int64": {},
	}
	catalogShapes := map[string]struct{}{}
	descriptors, err := telemetry.V8MetricDescriptorCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, descriptor := range descriptors {
		catalogShapes[descriptor.InstrumentType+"/"+descriptor.ValueType] = struct{}{}
	}
	if !reflect.DeepEqual(covered, catalogShapes) {
		t.Fatalf("shape coverage=%v catalog=%v", covered, catalogShapes)
	}
}

func TestGeneratedPrometheusMaterializesAndScrapesEveryGeneratedContract(t *testing.T) {
	plan, destination := compilePrometheus(t, allMetricsSource("metrics"), true)
	provider, err := telemetry.NewProviderV8Inactive(t.Context(), plan, 1, telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "all-contracts-resource",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	resource, ok := provider.V8ResourceContext()
	if !ok {
		t.Fatal("provider resource unavailable")
	}
	captured := &capturedMetricListeners{}
	factory, err := NewFactory(destination, Options{Listen: captured.listen})
	if err != nil {
		t.Fatal(err)
	}
	sink, err := factory.NewCanonicalMetricSink(t.Context(), 1, deltaSpec(), resource)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := sink.Shutdown(ctx); err != nil {
			t.Errorf("shutdown all-contract sink: %v", err)
		}
	})
	descriptors, err := telemetry.V8MetricDescriptorCatalog()
	if err != nil || len(descriptors) == 0 {
		t.Fatalf("descriptors=%d err=%v", len(descriptors), err)
	}
	for _, descriptor := range descriptors {
		instrument, instrumentErr := sink.instrument(descriptor)
		if instrumentErr != nil {
			t.Fatalf("materialize %s: %v", descriptor.Name, instrumentErr)
		}
		switch descriptor.InstrumentType + "/" + descriptor.ValueType {
		case "counter/int64":
			instrument.intCounter.Add(t.Context(), 1)
		case "counter/double":
			instrument.fltCounter.Add(t.Context(), 1)
		case "updowncounter/int64":
			instrument.intUpDown.Add(t.Context(), 1)
		case "updowncounter/double":
			instrument.fltUpDown.Add(t.Context(), 1)
		case "histogram/int64":
			instrument.intHist.Record(t.Context(), 1)
		case "histogram/double":
			instrument.fltHist.Record(t.Context(), 1)
		case "gauge/int64":
			instrument.intGauge.Record(t.Context(), 1)
		case "gauge/double":
			instrument.fltGauge.Record(t.Context(), 1)
		default:
			t.Fatalf("unsupported generated shape %s/%s", descriptor.InstrumentType, descriptor.ValueType)
		}
	}
	body := scrapeCapturedMetric(t, captured.listener(t, 0), "/metrics")
	if got := strings.Count(body, "# TYPE "); got != len(descriptors) || len(sink.instruments) != len(descriptors) {
		t.Fatalf("scraped families=%d instruments=%d generated descriptors=%d", got, len(sink.instruments), len(descriptors))
	}
	// Canaries cover the suffix strategies used by the compatibility
	// dashboards. Exact aliases are exercised through generated records above.
	for _, name := range []string{
		"defenseclaw_otel_ingest_bytes_total", "defenseclaw_agent_last_seen_seconds",
		"defenseclaw_agent_discovery_installed_ratio", "defenseclaw_connector_hook_latency_milliseconds",
		"gen_ai_client_operation_duration_seconds",
	} {
		if !strings.Contains(body, "# TYPE "+name+" ") {
			t.Errorf("scrape omitted normalized family %q", name)
		}
	}
}

func TestGeneratedPrometheusReloadIsolationAndShutdownRetry(t *testing.T) {
	captured := &capturedMetricListeners{}
	firstSource := allMetricsSource("metrics")
	firstSource.Path = "/metrics-v1"
	firstPlan, _ := compilePrometheus(t, firstSource, true)
	first := newGeneratedMetricHarnessGeneration(t, firstPlan, captured, 1)
	firstBuilder, firstEnvelope := first.builder(t), first.envelope()
	first.record(t, generatedMetricBuilt(firstBuilder.BuildMetricDefenseClawActivityTotal(
		observability.MetricDefenseClawActivityTotalInput{Envelope: firstEnvelope, Value: 1},
	)))
	firstAddress := captured.listener(t, 0).Addr().String()
	firstBody := scrapeCapturedMetric(t, captured.listener(t, 0), "/metrics-v1")
	if !strings.Contains(firstBody, "defenseclaw_activity_total 1") {
		t.Fatalf("generation one scrape:\n%s", firstBody)
	}

	// A caller timeout stops only that wait; provider/sink shutdown continues
	// on generation-owned internal deadlines and a later call observes the same
	// terminal result.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := first.provider.Shutdown(canceled); err == nil {
		t.Fatal("canceled shutdown wait unexpectedly succeeded")
	}
	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	if err := first.provider.Shutdown(shutdownContext); err != nil {
		t.Fatalf("shutdown retry: %v", err)
	}
	if _, err := testHTTPClient().Get("http://" + firstAddress + "/metrics-v1"); err == nil {
		t.Fatal("retired generation still accepted scrapes")
	}
	retiredRecord := generatedMetricBuilt(firstBuilder.BuildMetricDefenseClawActivityTotal(
		observability.MetricDefenseClawActivityTotalInput{Envelope: firstEnvelope, Value: 1},
	))
	if retiredRecord.err != nil {
		t.Fatal(retiredRecord.err)
	}
	if result, err := first.provider.RecordGeneratedMetric(t.Context(), retiredRecord.record); err == nil ||
		result != (telemetry.V8MetricRecordResult{}) {
		t.Fatalf("retired generation result=%+v err=%v", result, err)
	}

	secondSource := prometheusSource("metrics")
	secondSource.Path = "/metrics-v2"
	secondSource.Send = &config.ObservabilityV8SendSource{
		Signals: []observability.Signal{observability.SignalMetrics},
		Buckets: []observability.Bucket{observability.BucketModelIO},
	}
	secondPlan, _ := compilePrometheus(t, secondSource, true)
	second := newGeneratedMetricHarnessGeneration(t, secondPlan, captured, 2)
	secondBuilder, secondEnvelope := second.builder(t), second.envelope()
	second.record(t, generatedMetricBuilt(secondBuilder.BuildMetricDefenseClawStreamBytesSent(
		observability.MetricDefenseClawStreamBytesSentInput{
			Envelope: secondEnvelope, Value: 12,
			HTTPRoute:          observability.Present("/v1/chat"),
			DefenseClawOutcome: observability.Present("completed"),
		},
	)))
	if captured.count() != 2 {
		t.Fatalf("generation listeners=%d", captured.count())
	}
	secondBody := scrapeCapturedMetric(t, captured.listener(t, 1), "/metrics-v2")
	if !strings.Contains(secondBody, `defenseclaw_stream_bytes_sent_bucket{http_route="/v1/chat",outcome="completed",le="+Inf"} 1`) ||
		strings.Contains(secondBody, "defenseclaw_activity_total") {
		t.Fatalf("generation two scrape leaked selection/state:\n%s", secondBody)
	}
}

func TestGeneratedPrometheusMultipleDestinationsRouteIndependently(t *testing.T) {
	agent := prometheusSource("agent-metrics")
	agent.Path = "/agent"
	agent.Send = &config.ObservabilityV8SendSource{
		Signals: []observability.Signal{observability.SignalMetrics},
		Buckets: []observability.Bucket{observability.BucketAgentLifecycle},
	}
	compliance := prometheusSource("compliance-metrics")
	compliance.Path = "/compliance"
	compliance.Send = &config.ObservabilityV8SendSource{
		Signals: []observability.Signal{observability.SignalMetrics},
		Buckets: []observability.Bucket{observability.BucketComplianceActivity},
	}
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path: t.TempDir() + "/audit.db", JudgeBodiesPath: t.TempDir() + "/judge.db",
		},
		Destinations: []config.ObservabilityV8DestinationSource{agent, compliance},
	})
	if err != nil {
		t.Fatal(err)
	}
	captured := &capturedMetricListeners{}
	harness := newGeneratedMetricHarness(t, plan, captured)
	if captured.count() != 2 {
		t.Fatalf("listeners=%d", captured.count())
	}
	builder, envelope := harness.builder(t), harness.envelope()
	harness.record(t, generatedMetricBuilt(builder.BuildMetricDefenseClawConnectorHookLatency(
		observability.MetricDefenseClawConnectorHookLatencyInput{
			Envelope: envelope, Value: 2,
			DefenseClawConnectorSource: observability.Present("codex"),
		},
	)))
	harness.record(t, generatedMetricBuilt(builder.BuildMetricDefenseClawActivityTotal(
		observability.MetricDefenseClawActivityTotalInput{Envelope: envelope, Value: 1},
	)))
	agentBody := scrapeCapturedMetric(t, captured.listener(t, 0), "/agent")
	complianceBody := scrapeCapturedMetric(t, captured.listener(t, 1), "/compliance")
	if !strings.Contains(agentBody, "defenseclaw_connector_hook_latency_milliseconds_count") ||
		strings.Contains(agentBody, "defenseclaw_activity_total") {
		t.Fatalf("agent destination route leakage:\n%s", agentBody)
	}
	if !strings.Contains(complianceBody, "defenseclaw_activity_total") ||
		strings.Contains(complianceBody, "defenseclaw_connector_hook_latency") {
		t.Fatalf("compliance destination route leakage:\n%s", complianceBody)
	}
}

func TestGeneratedPrometheusCardinalityLimitUsesOneOverflowSeries(t *testing.T) {
	plan, _ := compilePrometheus(t, allMetricsSource("metrics"), true)
	harness := newGeneratedMetricHarness(t, plan, nil)
	builder, envelope := harness.builder(t), harness.envelope()
	for index := 0; index < 2_050; index++ {
		harness.record(t, generatedMetricBuilt(builder.BuildMetricDefenseClawAgentDiscoveryInstalled(
			observability.MetricDefenseClawAgentDiscoveryInstalledInput{
				Envelope: envelope, Value: 1,
				DefenseClawConnectorSource: observability.Present("connector-" + strconv.Itoa(index)),
			},
		)))
	}
	body := scrapeCapturedMetric(t, harness.listen.listener(t, 0), "/metrics")
	series := 0
	overflow := 0
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "defenseclaw_agent_discovery_installed_ratio{") {
			continue
		}
		series++
		if strings.Contains(line, `otel_metric_overflow="true"`) {
			overflow++
		}
	}
	if series != 2_048 || overflow != 1 {
		t.Fatalf("cardinality series=%d overflow=%d", series, overflow)
	}
}

func TestGeneratedPrometheusRejectsWrongGenerationAndUnselectedFamily(t *testing.T) {
	source := prometheusSource("metrics")
	source.Send = &config.ObservabilityV8SendSource{
		Signals: []observability.Signal{observability.SignalMetrics},
		Buckets: []observability.Bucket{observability.BucketAgentLifecycle},
	}
	plan, _ := compilePrometheus(t, source, true)
	harness := newGeneratedMetricHarness(t, plan, nil)
	builder, envelope := harness.builder(t), harness.envelope()

	unselected, err := builder.BuildMetricDefenseClawActivityTotal(
		observability.MetricDefenseClawActivityTotalInput{Envelope: envelope, Value: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result, recordErr := harness.provider.RecordGeneratedMetric(t.Context(), unselected); recordErr != nil ||
		result != (telemetry.V8MetricRecordResult{}) {
		t.Fatalf("unselected result=%+v err=%v", result, recordErr)
	}

	wrongEnvelope := envelope
	wrongEnvelope.Provenance.ConfigGeneration++
	wrong, err := builder.BuildMetricDefenseClawAgentDiscoveryInstalled(
		observability.MetricDefenseClawAgentDiscoveryInstalledInput{
			Envelope: wrongEnvelope, Value: 1,
			DefenseClawConnectorSource: observability.Present("codex"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result, recordErr := harness.provider.RecordGeneratedMetric(t.Context(), wrong); recordErr == nil ||
		result != (telemetry.V8MetricRecordResult{}) {
		t.Fatalf("wrong generation result=%+v err=%v", result, recordErr)
	}
	body := scrapeCapturedMetric(t, harness.listen.listener(t, 0), "/metrics")
	if strings.Contains(body, "defenseclaw_activity_total") || strings.Contains(body, "defenseclaw_agent_discovery_installed_ratio") {
		t.Fatalf("rejected generated records reached scrape:\n%s", body)
	}
}

func TestGeneratedPrometheusCollectionGatePrecedesDestinationConstruction(t *testing.T) {
	descriptors, descriptorErr := telemetry.V8MetricDescriptorCatalog()
	if descriptorErr != nil || len(descriptors) == 0 {
		t.Fatalf("generated metric descriptors=%d err=%v", len(descriptors), descriptorErr)
	}
	var calls atomic.Int64
	listen := func(context.Context, string, string) (net.Listener, error) {
		calls.Add(1)
		return net.Listen("tcp", "127.0.0.1:0")
	}
	plan, _ := compilePrometheus(t, allMetricsSource("metrics"), false)
	prepared, err := PreparePlanPipelines(t.Context(), plan, 1, deltaSpec(), Options{Listen: listen})
	if err != nil || len(prepared.MetricPipelines) != 0 || len(prepared.MetricReaders) != 0 || calls.Load() != 0 {
		t.Fatalf("disabled pipelines=%d readers=%d listener calls=%d err=%v",
			len(prepared.MetricPipelines), len(prepared.MetricReaders), calls.Load(), err)
	}

	plan, _ = compilePrometheus(t, allMetricsSource("metrics"), true)
	prepared, err = PreparePlanPipelines(t.Context(), plan, 1, deltaSpec(), Options{Listen: listen})
	if err != nil || len(prepared.MetricPipelines) != 1 || len(prepared.MetricReaders) != 1 || len(prepared.HealthSources) != 1 || calls.Load() != 1 {
		t.Fatalf("declaration pipelines=%d readers=%d listener calls=%d err=%v",
			len(prepared.MetricPipelines), len(prepared.MetricReaders), calls.Load(), err)
	}
	t.Cleanup(func() { _ = prepared.MetricReaders[0].Shutdown(context.Background()) })
	if prepared.MetricPipelines[0].Projection != telemetry.V8MetricProjectionLocal ||
		len(prepared.MetricPipelines[0].SelectedFamilies) != len(descriptors) ||
		!sort.SliceIsSorted(prepared.MetricPipelines[0].SelectedFamilies, func(left, right int) bool {
			return prepared.MetricPipelines[0].SelectedFamilies[left] < prepared.MetricPipelines[0].SelectedFamilies[right]
		}) {
		t.Fatalf("generated pipeline projection=%q families=%d",
			prepared.MetricPipelines[0].Projection, len(prepared.MetricPipelines[0].SelectedFamilies))
	}
}

func TestGeneratedPrometheusSiblingInitializationFailureRollsBackBoundListener(t *testing.T) {
	first, second := prometheusSource("first"), prometheusSource("second")
	second.Path = "/second"
	source := &config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path: t.TempDir() + "/audit.db", JudgeBodiesPath: t.TempDir() + "/judge.db",
		},
		Destinations: []config.ObservabilityV8DestinationSource{first, second},
	}
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	captured := &capturedMetricListeners{failAt: 2}
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "rollback-test",
		GenerationPipelines: func(
			ctx context.Context,
			candidate *config.ObservabilityV8Plan,
			generation uint64,
			spec telemetry.V8MetricReaderSpec,
		) (telemetry.V8GenerationPipelines, error) {
			return PreparePlanPipelines(
				ctx, candidate, generation, spec, Options{Listen: captured.listen},
			)
		},
	})
	manager, createErr := runtimegraph.New(
		t.Context(), runtimegraph.ConfigFromPlan(plan, false),
		[]runtimegraph.ComponentFactory{providerFactory}, runtimegraph.DefaultOptions(generatedMetricReporter{}),
	)
	if manager != nil {
		_ = manager.Close(context.Background())
	}
	if createErr == nil || captured.count() != 1 {
		t.Fatalf("manager=%v listeners=%d err=%v", manager != nil, captured.count(), createErr)
	}
	address := captured.listener(t, 0).Addr().String()
	listener, listenErr := net.Listen("tcp", address)
	if listenErr != nil {
		t.Fatalf("rollback leaked bound listener: %v", listenErr)
	}
	_ = listener.Close()
}

func TestGeneratedPrometheusRecordSurvivesSiblingDestinationFailure(t *testing.T) {
	plan, _ := compilePrometheus(t, allMetricsSource("metrics"), true)
	captured := &capturedMetricListeners{}
	failing := &failingGeneratedMetricSink{}
	family := observability.EventName("defenseclaw.connector.hook.latency")
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "sibling-record-test",
		GenerationPipelines: func(
			ctx context.Context,
			candidate *config.ObservabilityV8Plan,
			generation uint64,
			spec telemetry.V8MetricReaderSpec,
		) (telemetry.V8GenerationPipelines, error) {
			pipelines, err := PreparePlanPipelines(
				ctx, candidate, generation, spec, Options{Listen: captured.listen},
			)
			if err != nil {
				return telemetry.V8GenerationPipelines{}, err
			}
			pipelines.MetricPipelines = append(pipelines.MetricPipelines, telemetry.V8GenerationMetricPipeline{
				Destination: "failing-sibling", Projection: telemetry.V8MetricProjectionCanonical,
				SelectedFamilies: []observability.EventName{family}, Sink: failing,
			})
			return pipelines, nil
		},
	})
	componentValue, err := providerFactory.Prepare(
		t.Context(),
		runtimegraph.BuildInput{Config: runtimegraph.ConfigFromPlan(plan, false), Generation: 1},
		&runtimegraph.Acquisitions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	component := componentValue.(*telemetry.V8ProviderComponent)
	component.Activate()
	provider, ok := component.Provider()
	if !ok {
		t.Fatal("provider unavailable")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = component.StopIntake(ctx)
		_ = provider.Shutdown(ctx)
		_ = component.Close(ctx)
	})
	digest, generation, ok := provider.V8PlanBinding()
	if !ok {
		t.Fatal("provider binding unavailable")
	}
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Unix(100, 0).UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return "sibling-record", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.BuildMetricDefenseClawConnectorHookLatency(
		observability.MetricDefenseClawConnectorHookLatencyInput{
			Envelope: observability.FamilyEnvelopeInput{
				Source: "gateway", Provenance: observability.FamilyProvenanceInput{
					Producer: "defenseclaw", BinaryVersion: "8.0.0",
					ConfigGeneration: int64(generation), ConfigDigest: digest,
				},
			},
			Value: 4, DefenseClawConnectorSource: observability.Present("codex"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	result, recordErr := provider.RecordGeneratedMetric(t.Context(), record)
	if recordErr == nil || result != (telemetry.V8MetricRecordResult{Matched: 2, Delivered: 1, Failed: 1}) ||
		failing.records.Load() != 1 {
		t.Fatalf("isolated record result=%+v sibling=%d err=%v", result, failing.records.Load(), recordErr)
	}
	body := scrapeCapturedMetric(t, captured.listener(t, 0), "/metrics")
	if !strings.Contains(body, `defenseclaw_connector_hook_latency_milliseconds_count{connector="codex"} 1`) {
		t.Fatalf("healthy Prometheus destination lost sibling-failed record:\n%s", body)
	}
}
