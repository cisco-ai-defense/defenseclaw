// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations"
	galileodestination "github.com/defenseclaw/defenseclaw/internal/observability/destinations/galileo"
	otlpdestination "github.com/defenseclaw/defenseclaw/internal/observability/destinations/otlp"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	collectormetricpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

const (
	e2e4TraceID       = "2030405060708090a0b0c0d0e0f00112"
	e2e4NativeTraceID = "30405060708090a0b0c0d0e0f0011223"
	e2e4RawEmail      = "operator@example.test"
)

type e2e4MetricCapture struct {
	mu       sync.Mutex
	requests []*collectormetricpb.ExportMetricsServiceRequest
}

type e2e4OTLPFailureCapture struct {
	mu       sync.Mutex
	failures []otlpdestination.CanonicalFailure
}

func (capture *e2e4OTLPFailureCapture) ObserveOTLPCanonicalFailure(
	failure otlpdestination.CanonicalFailure,
) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	capture.failures = append(capture.failures, failure)
}

func (capture *e2e4OTLPFailureCapture) snapshot() []otlpdestination.CanonicalFailure {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]otlpdestination.CanonicalFailure(nil), capture.failures...)
}

func (capture *e2e4MetricCapture) handle(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/v1/metrics" {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	body, _ := io.ReadAll(request.Body)
	decoded := &collectormetricpb.ExportMetricsServiceRequest{}
	if err := proto.Unmarshal(body, decoded); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	capture.mu.Lock()
	capture.requests = append(capture.requests, proto.Clone(decoded).(*collectormetricpb.ExportMetricsServiceRequest))
	capture.mu.Unlock()
	writer.Header().Set("Content-Type", "application/x-protobuf")
	writer.WriteHeader(http.StatusOK)
}

func (capture *e2e4MetricCapture) snapshot() []*collectormetricpb.ExportMetricsServiceRequest {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]*collectormetricpb.ExportMetricsServiceRequest(nil), capture.requests...)
}

type e2e4FunnelCounters struct {
	Observed, Accepted, Dropped, Failed, Closed uint64
}

func (counters e2e4FunnelCounters) reconciled() bool {
	return counters.Observed == counters.Accepted+counters.Dropped+counters.Failed+counters.Closed
}

type e2e4FunnelConsumer struct {
	mu       sync.Mutex
	delegate telemetry.V8CanonicalSpanConsumer
	counters e2e4FunnelCounters
}

func (consumer *e2e4FunnelConsumer) bind(delegate telemetry.V8CanonicalSpanConsumer) error {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	if delegate == nil || consumer.delegate != nil {
		return fmt.Errorf("invalid Galileo funnel binding")
	}
	consumer.delegate = delegate
	return nil
}

func (consumer *e2e4FunnelConsumer) TryEnqueue(span telemetry.V8CanonicalEndedSpan) telemetry.V8CanonicalSpanEnqueueResult {
	consumer.mu.Lock()
	delegate := consumer.delegate
	consumer.counters.Observed++
	consumer.mu.Unlock()
	result := telemetry.V8CanonicalSpanEnqueueFailed
	if delegate != nil {
		result = delegate.TryEnqueue(span)
	}
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	switch result {
	case telemetry.V8CanonicalSpanEnqueueAccepted:
		consumer.counters.Accepted++
	case telemetry.V8CanonicalSpanEnqueueDropped:
		consumer.counters.Dropped++
	case telemetry.V8CanonicalSpanEnqueueClosed:
		consumer.counters.Closed++
	default:
		consumer.counters.Failed++
	}
	return result
}

func (consumer *e2e4FunnelConsumer) ForceFlush(ctx context.Context) error {
	consumer.mu.Lock()
	delegate := consumer.delegate
	consumer.mu.Unlock()
	if delegate == nil {
		return fmt.Errorf("Galileo funnel is not bound")
	}
	return delegate.ForceFlush(ctx)
}

func (consumer *e2e4FunnelConsumer) Shutdown(ctx context.Context) error {
	consumer.mu.Lock()
	delegate := consumer.delegate
	consumer.mu.Unlock()
	if delegate == nil {
		return nil
	}
	return delegate.Shutdown(ctx)
}

func (consumer *e2e4FunnelConsumer) reset() {
	consumer.mu.Lock()
	consumer.counters = e2e4FunnelCounters{}
	consumer.mu.Unlock()
}

func (consumer *e2e4FunnelConsumer) snapshot() e2e4FunnelCounters {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	return consumer.counters
}

func (capture *galileoTraceCapture) reset() {
	capture.mu.Lock()
	capture.requests = nil
	capture.mu.Unlock()
}

func (capture *galileoCanonicalFailureCapture) reset() {
	capture.mu.Lock()
	capture.failures = nil
	capture.mu.Unlock()
}

func TestE2E4ConfiguredSignalsKeepGalileoBoundedAndGenericOTLPLossless(t *testing.T) {
	directory := t.TempDir()
	storePath, judgePath := filepath.Join(directory, "audit.db"), filepath.Join(directory, "judge.db")
	store, err := audit.NewStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	galileoCapture, genericCapture, metricCapture := &galileoTraceCapture{}, &galileoTraceCapture{}, &e2e4MetricCapture{}
	galileoServer := httptest.NewServer(http.HandlerFunc(galileoCapture.handle))
	genericServer := httptest.NewServer(http.HandlerFunc(genericCapture.handle))
	metricServer := httptest.NewServer(http.HandlerFunc(metricCapture.handle))
	defer galileoServer.Close()
	defer genericServer.Close()
	defer metricServer.Close()

	source := observabilitySource(storePath, judgePath, []config.ObservabilityV8DestinationSource{
		e2e4Destination("galileo", galileoServer.URL, "galileo", []observability.Signal{observability.SignalTraces}, []observability.Bucket{"*"}, "sensitive"),
		e2e4Destination("generic", genericServer.URL, "", []observability.Signal{observability.SignalTraces}, []observability.Bucket{"*"}, "none"),
		e2e4Destination("metrics", metricServer.URL, "", []observability.Signal{observability.SignalMetrics}, []observability.Bucket{observability.BucketModelIO}, ""),
	})
	e2e4ConfigureCollection(source)
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	e2e4AssertCompiledCollection(t, plan)

	engine, err := redaction.NewEngine([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	health, failures, otlpFailures, funnel := &integrationDeliveryHealth{}, &galileoCanonicalFailureCapture{}, &e2e4OTLPFailureCapture{}, &e2e4FunnelConsumer{}
	factory, err := destinations.NewFactory(destinations.Options{
		ConsoleStream: destinations.ConsoleStderr, Stdout: io.Discard, Stderr: io.Discard,
		Secrets:  &integrationSecrets{values: map[string]string{}, calls: map[string]int{}},
		CALoader: &integrationCALoader{}, Resolver: net.DefaultResolver, Dialer: &net.Dialer{},
		Warnings: &integrationWarnings{}, RedactionEngine: engine, DeliveryObserver: health,
		GalileoObserver: failures, OTLPCanonicalObserver: otlpFailures,
	})
	if err != nil {
		t.Fatal(err)
	}
	basePipelines := factory.OTLPGenerationPipelineFactory()
	pipelineFactory := func(
		ctx context.Context, candidate *config.ObservabilityV8Plan, generation uint64,
		spec telemetry.V8MetricReaderSpec,
	) (telemetry.V8GenerationPipelines, error) {
		pipelines, prepareErr := basePipelines(ctx, candidate, generation, spec)
		if prepareErr != nil {
			return pipelines, prepareErr
		}
		for index := range pipelines.SpanPipelines {
			if pipelines.SpanPipelines[index].Destination != "galileo" {
				continue
			}
			if bindErr := funnel.bind(pipelines.SpanPipelines[index].Canonical); bindErr != nil {
				return telemetry.V8GenerationPipelines{}, bindErr
			}
			pipelines.SpanPipelines[index].Canonical = funnel
		}
		return pipelines, nil
	}
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "integration-test", Environment: "test", ServiceInstanceID: "e2e4-service",
		DefenseClawInstanceID: "e2e4-instance", GenerationPipelines: pipelineFactory,
	})
	reaper, err := audit.NewRetentionReaper(store, nil, 0, audit.RetentionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	retention, err := observabilityruntime.NewRetentionController(reaper, observabilityruntime.RetentionControllerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := observabilityruntime.New(context.Background(), runtimegraph.ConfigFromPlan(plan, false), observabilityruntime.Options{
		Store: store, Engine: engine, RecordBuilder: mustRecordBuilder(t, "e2e4-runtime-failure"),
		Reporter: &discardReporter{}, RetentionController: retention,
		DestinationAdapterFactory: factory, DestinationObserver: health,
		TelemetryProviderFactory: providerFactory,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeAttempted := false
	t.Cleanup(func() {
		if closeAttempted {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = runtime.Close(ctx)
	})

	e2e4AssertDisabledContentLogsAreLazy(t, runtime, store)
	canary, err := runtime.EmitTraceCanary(t.Context(), "galileo")
	if err != nil || !canary.Acknowledged || canary.Destination != "galileo" || canary.Generation != 1 {
		t.Fatalf("Galileo canary=%+v error=%v", canary, err)
	}
	assertGalileoHealthyDelivery(t, health, "galileo")
	galileoCapture.reset()
	genericCapture.reset()
	failures.reset()
	funnel.reset()

	input := "Contact " + e2e4RawEmail + "; then look up the weather in Raleigh."
	emitGalileoRichGraphConfigured(t, runtime, e2e4TraceID, 2, input, galileoRichOutput)
	e2e4EmitUnsupportedNativeSpans(t, runtime)
	e2e4RecordIndependentMetric(t, runtime)
	preCanaryFailures, preCanaryFunnel := failures.snapshot(), funnel.snapshot()
	for _, destination := range []string{"generic", "galileo"} {
		canary, canaryErr := runtime.EmitTraceCanary(t.Context(), destination)
		if canaryErr != nil || !canary.Acknowledged || canary.Destination != destination || canary.Generation != 1 {
			healthSnapshot, healthSnapshotErr := runtime.DestinationHealthSnapshot(t.Context())
			capture := genericCapture
			if destination == "galileo" {
				capture = galileoCapture
			}
			t.Fatalf(
				"post-delivery %s canary=%+v error=%v captured_trace=%v captured_families=%v otlp_failures=%+v health=%+v health_error=%v",
				destination, canary, canaryErr, e2e4CaptureContainsTrace(capture.snapshot(), canary.TraceID),
				e2e4CapturedFamilyIDs(capture.snapshot()), otlpFailures.snapshot(), healthSnapshot, healthSnapshotErr,
			)
		}
	}
	preCloseHealth, healthErr := runtime.DestinationHealthSnapshot(t.Context())
	if healthErr != nil {
		t.Fatalf("pre-close destination health: %v", healthErr)
	}
	closeAttempted = true
	closeContext, cancelClose := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelClose()
	if err := runtime.Close(closeContext); err != nil {
		t.Fatalf("close E2E-4 runtime: %v; pre-close health=%+v", err, preCloseHealth)
	}

	e2e4AssertGalileoProjection(t, galileoCapture.snapshot(), preCanaryFailures, preCanaryFunnel)
	e2e4AssertGenericProjection(t, genericCapture.snapshot())
	e2e4AssertMetricProjection(t, metricCapture.snapshot())
}

func e2e4Destination(
	name, endpoint, preset string,
	signals []observability.Signal,
	buckets []observability.Bucket,
	profile string,
) config.ObservabilityV8DestinationSource {
	// Exercise the compiler-owned transport defaults. In particular, the
	// Galileo preset's one-second delay keeps the exact two-span diagnostic
	// canary in one accepted request, as required by the release contract.
	batch := config.ObservabilityV8BatchSource{}
	if name == "generic" {
		// Keep the two-span canary atomic while preventing one invalid rich
		// projection from poisoning an unrelated queued pair.
		batch.MaxExportBatchSize = 2
	}
	return config.ObservabilityV8DestinationSource{
		Name: name, Kind: config.ObservabilityV8DestinationOTLP, Preset: preset,
		Protocol: "http/protobuf", Endpoint: endpoint,
		Send:          &config.ObservabilityV8SendSource{Signals: signals, Buckets: buckets, RedactionProfile: profile},
		Batch:         batch,
		TLS:           config.ObservabilityV8TLSSource{Insecure: true},
		NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
	}
}

func e2e4ConfigureCollection(source *config.ObservabilityV8Source) {
	yes, no := true, false
	source.Defaults.Collect.Traces = &no
	source.Defaults.Collect.Metrics = &no
	source.Buckets = map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
		observability.BucketAgentLifecycle:      {Collect: config.ObservabilityV8CollectSource{Traces: &yes}},
		observability.BucketModelIO:             {Collect: config.ObservabilityV8CollectSource{Logs: &no, Traces: &yes, Metrics: &yes}},
		observability.BucketToolActivity:        {Collect: config.ObservabilityV8CollectSource{Logs: &no, Traces: &yes}},
		observability.BucketGuardrailEvaluation: {Collect: config.ObservabilityV8CollectSource{Traces: &yes}},
		observability.BucketEnforcementAction:   {Collect: config.ObservabilityV8CollectSource{Traces: &yes}},
		observability.BucketAssetScan:           {Collect: config.ObservabilityV8CollectSource{Traces: &yes}},
		observability.BucketPlatformHealth:      {Collect: config.ObservabilityV8CollectSource{Traces: &yes}},
	}
}

func e2e4AssertCompiledCollection(t *testing.T, plan *config.ObservabilityV8Plan) {
	t.Helper()
	policies := make(map[observability.Bucket]config.ObservabilityV8EffectiveCollect)
	for _, bucket := range plan.Snapshot().Buckets {
		policies[bucket.Bucket] = bucket.Collect
	}
	if policies[observability.BucketModelIO].Logs || policies[observability.BucketToolActivity].Logs ||
		!policies[observability.BucketModelIO].Traces || !policies[observability.BucketToolActivity].Traces ||
		!policies[observability.BucketAgentLifecycle].Traces || !policies[observability.BucketGuardrailEvaluation].Traces ||
		!policies[observability.BucketModelIO].Metrics || policies[observability.BucketToolActivity].Metrics {
		t.Fatalf("compiled E2E-4 collection policy=%+v", policies)
	}
}

func e2e4AssertDisabledContentLogsAreLazy(
	t *testing.T,
	runtime *observabilityruntime.Runtime,
	store *audit.Store,
) {
	t.Helper()
	before, err := store.ListEvents(64)
	if err != nil {
		t.Fatal(err)
	}
	var constructions atomic.Int64
	tests := []struct {
		key     observability.ProducerKey
		context observability.ClassificationContext
	}{
		{key: "llm_prompt", context: observability.ClassificationContext{RawSeverity: "INFO"}},
		{key: "tool_invocation", context: observability.ClassificationContext{
			Bucket: observability.BucketToolActivity, EventName: "tool.invocation.requested", RawSeverity: "INFO",
		}},
	}
	for _, test := range tests {
		metadata, metadataErr := router.NewClassifiedLogMetadata(
			observability.ProducerGatewayEvent, test.key, test.context,
			observability.SourceGateway, "codex", test.key,
		)
		if metadataErr != nil {
			t.Fatal(metadataErr)
		}
		_, emitErr := runtime.Emit(t.Context(), metadata, func(
			observabilityruntime.EmitContext, router.Admission,
		) (observability.Record, error) {
			constructions.Add(1)
			return observability.Record{}, fmt.Errorf("disabled content log builder executed")
		})
		if emitErr != nil {
			t.Fatalf("disabled %q log error=%v", test.key, emitErr)
		}
	}
	after, err := store.ListEvents(64)
	if err != nil || len(after) != len(before) || constructions.Load() != 0 {
		t.Fatalf("disabled log construction=%d events=%d/%d error=%v", constructions.Load(), len(before), len(after), err)
	}
}

type e2e4NativeSpanSpec struct {
	family, targetID, spanID, name, kind string
	outcome                              observability.Outcome
	values                               map[string]any
}

var e2e4NativeSpanSpecs = []e2e4NativeSpanSpec{
	{
		family:   observability.TelemetryFamilyGuardrailApply,
		targetID: "otlp.native.span.v8.span.guardrail.apply.span.guardrail.apply",
		spanID:   "405060708090a001", name: "apply_guardrail inspect prompt", kind: "INTERNAL",
		outcome: observability.OutcomeAllowed,
		values: map[string]any{
			"defenseclaw.guardrail.name": "inspect", "defenseclaw.guardrail.target_type": "prompt",
			"defenseclaw.guardrail.raw_action": "allow", "defenseclaw.guardrail.effective_action": "allow",
			"defenseclaw.policy.id": "policy-e2e4",
		},
	},
	{
		family:   observability.TelemetryFamilyEnforcementApply,
		targetID: "otlp.native.span.v8.span.enforcement.apply.span.enforcement.apply",
		spanID:   "405060708090a002", name: "enforcement allow", kind: "INTERNAL",
		outcome: observability.OutcomeApplied,
		values: map[string]any{
			"defenseclaw.enforcement.effective_action": "allow", "defenseclaw.policy.id": "policy-e2e4",
		},
	},
	{
		family:   observability.TelemetryFamilyAssetScan,
		targetID: "otlp.native.span.v8.span.asset.scan.span.asset.scan",
		spanID:   "405060708090a003", name: "asset.scan", kind: "INTERNAL",
		outcome: observability.OutcomeCompleted,
		values: map[string]any{
			"defenseclaw.scan.id": "scan-e2e4", "defenseclaw.scan.scanner": "codeguard",
			"defenseclaw.scan.target_ref": "fixture.go", "defenseclaw.scan.target_type": "file",
			"defenseclaw.scan.finding_count": int64(0), "defenseclaw.scan.verdict": "clean",
		},
	},
	{
		family:   observability.TelemetryFamilyDestinationExport,
		targetID: "otlp.native.span.v8.span.destination.export.span.destination.export",
		spanID:   "405060708090a004", name: "telemetry.export generic", kind: "CLIENT",
		outcome: observability.OutcomeCompleted,
		values: map[string]any{
			"defenseclaw.destination.id": "generic", "defenseclaw.destination.signal": "traces",
			"defenseclaw.destination.delivery_outcome": "delivered",
			"defenseclaw.destination.delivered_items":  int64(1),
			"defenseclaw.destination.rejected_items":   int64(0),
		},
	},
}

func e2e4EmitUnsupportedNativeSpans(t *testing.T, runtime *observabilityruntime.Runtime) {
	t.Helper()
	catalog, err := observability.LoadInboundCatalog()
	if err != nil {
		t.Fatal(err)
	}
	sequence := 0
	builder, err := observability.NewInboundImportBuilder(
		observability.ClockFunc(time.Now),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			sequence++
			return fmt.Sprintf("e2e4-native-%d", sequence), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := runtime.BeginInboundImportBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Close()
	receipt := time.Now().UTC()
	for index, spec := range e2e4NativeSpanSpecs {
		target, ok := catalog.Target(spec.targetID)
		if !ok || target.Family() != spec.family {
			t.Fatalf("native target unavailable family=%q target=%q", spec.family, spec.targetID)
		}
		result, importErr := batch.ImportTrace(t.Context(), target, "codex", func(snapshot observabilityruntime.EmitContext) (observability.Record, error) {
			provenance, present := snapshot.InboundLocalProvenance()
			if !present {
				return observability.Record{}, errGalileoRichFixture
			}
			start := receipt.Add(time.Duration(-500+index*50) * time.Millisecond)
			return builder.BuildTrace(target, observability.InboundImportedTraceInput{
				ReceiptTime: receipt,
				Correlation: observability.Correlation{TraceID: e2e4NativeTraceID, SpanID: spec.spanID},
				Provenance:  provenance,
				Import: observability.InboundImportProvenanceInput{
					AuthenticatedSource: "codex", UpstreamInstanceID: "e2e4-upstream",
					UpstreamRecordID: "e2e4-" + spec.family, UpstreamServiceName: "e2e4-fixture",
					UpstreamRedactionProfile: "none", IngressHopCount: 1,
					LastHopInstanceID: "e2e4-forwarder", LastHopDestination: "generic",
				},
				Outcome: observability.Present(spec.outcome), Kind: spec.kind,
				NativeSpanName:    observability.Present(spec.name),
				StartTimeUnixNano: uint64(start.UnixNano()), EndTimeUnixNano: uint64(start.Add(20 * time.Millisecond).UnixNano()),
				TraceState: observability.Present("dc=e2e4"), Flags: 1,
				Status: observability.NewTraceStatusOK(),
				Resource: observability.InboundTraceResourceInput{
					Fields: galileoRichResourceFields(t, target),
				},
				Fields: galileoRichMapCapabilities(t, target.Fields(), spec.values, "", ""),
			})
		})
		if importErr != nil || result.Matched != 2 || result.Delivered != 1 || result.Dropped != 1 ||
			result.Failed != 0 || result.Suppressed != 0 {
			t.Fatalf("native family %q delivery=%+v error=%v", spec.family, result, importErr)
		}
	}
}

func e2e4RecordIndependentMetric(t *testing.T, runtime *observabilityruntime.Runtime) {
	t.Helper()
	result, err := runtime.RecordGeneratedMetric(
		t.Context(), observability.EventName(observability.TelemetryInstrumentGenAIClientOperationDuration),
		func(snapshot observabilityruntime.EmitContext) (observability.Record, error) {
			builder, builderErr := observability.NewFamilyBuilder(
				observability.ClockFunc(time.Now),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return "e2e4-metric", nil }),
			)
			if builderErr != nil {
				return observability.Record{}, builderErr
			}
			return builder.BuildMetricGenAIClientOperationDuration(observability.MetricGenAIClientOperationDurationInput{
				Envelope: observability.FamilyEnvelopeInput{
					Source: observability.SourceGateway,
					Provenance: observability.FamilyProvenanceInput{
						Producer: "defenseclaw", BinaryVersion: "integration-test",
						ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
					},
				},
				Value: 0.125, GenAIOperationName: observability.Present("chat"),
				GenAIProviderName: observability.Present("openai"),
				GenAIRequestModel: observability.Present("gpt-4o-mini"),
			})
		},
	)
	if err != nil || result.Matched != 1 || result.Delivered != 1 || result.Failed != 0 || result.Suppressed != 0 {
		t.Fatalf("independent metric result=%+v error=%v", result, err)
	}
}

func e2e4AssertGalileoProjection(
	t *testing.T,
	requests []*collectortracepb.ExportTraceServiceRequest,
	failures []galileodestination.CanonicalFailure,
	funnel e2e4FunnelCounters,
) {
	t.Helper()
	spans := e2e4TraceSpans(t, requests, true)
	want := []string{
		observability.TelemetryFamilyAgentInvoke, observability.TelemetryFamilyGuardrailJudge,
		observability.TelemetryFamilyModelChat, observability.TelemetryFamilyRetrievalSearch,
		observability.TelemetryFamilyToolExecute, observability.TelemetryFamilyWorkflowRun,
	}
	got := make([]string, 0, len(spans))
	var eventCount int
	for family, span := range spans {
		got = append(got, family)
		for _, event := range span.Events {
			eventCount++
			if event.Name != "model.retry" || strings.Contains(fmt.Sprint(galileoProtoAttributes(event.Attributes)), e2e4RawEmail) {
				t.Fatalf("unsafe Galileo event=%+v", event)
			}
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") || eventCount != 1 {
		t.Fatalf("Galileo families/events=%v/%d want=%v/1", got, eventCount, want)
	}
	model := fmt.Sprint(galileoProtoAttributes(spans[observability.TelemetryFamilyModelChat].Attributes))
	if strings.Contains(model, e2e4RawEmail) || !strings.Contains(model, "weather in Raleigh") ||
		!strings.Contains(model, "redacted") {
		t.Fatalf("Galileo sensitive projection was not partially redacted: %s", model)
	}
	if len(failures) != len(e2e4NativeSpanSpecs) {
		t.Fatalf("Galileo unsupported failures=%+v", failures)
	}
	for _, failure := range failures {
		if failure.Destination != "galileo" || failure.Generation != 1 ||
			failure.Code != galileodestination.CanonicalFailureUnsupportedShape {
			t.Fatalf("Galileo misclassification failure=%+v", failure)
		}
	}
	if funnel.Observed != 10 || funnel.Accepted != 6 || funnel.Dropped != 4 ||
		funnel.Failed != 0 || funnel.Closed != 0 || !funnel.reconciled() {
		t.Fatalf("Galileo E2E-4 funnel=%+v", funnel)
	}
}

func e2e4AssertGenericProjection(t *testing.T, requests []*collectortracepb.ExportTraceServiceRequest) {
	t.Helper()
	spans := e2e4TraceSpans(t, requests, false)
	if len(spans) != 10 {
		t.Fatalf("generic OTLP families=%d want=10: %v", len(spans), spans)
	}
	model := fmt.Sprint(galileoProtoAttributes(spans[observability.TelemetryFamilyModelChat].Attributes))
	if !strings.Contains(model, e2e4RawEmail) {
		t.Fatalf("generic OTLP did not retain unredacted native model content: %s", model)
	}
	wantNative := map[string]string{
		observability.TelemetryFamilyGuardrailApply:    "defenseclaw.guardrail.name",
		observability.TelemetryFamilyEnforcementApply:  "defenseclaw.enforcement.effective_action",
		observability.TelemetryFamilyAssetScan:         "defenseclaw.scan.scanner",
		observability.TelemetryFamilyDestinationExport: "defenseclaw.destination.id",
	}
	for family, key := range wantNative {
		span := spans[family]
		if span == nil {
			t.Fatalf("generic OTLP lost native family %q", family)
		}
		attributes := galileoProtoAttributes(span.Attributes)
		if attributes[key] == nil || attributes["openinference.span.kind"] != nil {
			t.Fatalf("native family %q was changed or Galileo-misclassified: %v", family, attributes)
		}
	}
}

func e2e4TraceSpans(
	t *testing.T,
	requests []*collectortracepb.ExportTraceServiceRequest,
	wantGalileo bool,
) map[string]*tracepb.Span {
	t.Helper()
	result := make(map[string]*tracepb.Span)
	for _, request := range requests {
		for _, resourceSpans := range request.ResourceSpans {
			for _, scopeSpans := range resourceSpans.ScopeSpans {
				scope := galileoProtoAttributes(scopeSpans.Scope.Attributes)
				_, hasGalileo := scope["defenseclaw.galileo.compatibility_profile"]
				if hasGalileo != wantGalileo {
					t.Fatalf("destination-private Galileo scope marker=%v want=%v scope=%v", hasGalileo, wantGalileo, scope)
				}
				for _, span := range scopeSpans.Spans {
					traceID := fmt.Sprintf("%x", span.TraceId)
					if traceID != e2e4TraceID && (wantGalileo || traceID != e2e4NativeTraceID) {
						continue
					}
					family, _ := galileoProtoAttributes(span.Attributes)["defenseclaw.span.family"].(string)
					if family == "" || result[family] != nil {
						t.Fatalf("missing or duplicate projected family %q", family)
					}
					result[family] = span
				}
			}
		}
	}
	return result
}

func e2e4CaptureContainsTrace(
	requests []*collectortracepb.ExportTraceServiceRequest,
	traceID string,
) bool {
	if traceID == "" {
		return false
	}
	for _, request := range requests {
		for _, resourceSpans := range request.ResourceSpans {
			for _, scopeSpans := range resourceSpans.ScopeSpans {
				for _, span := range scopeSpans.Spans {
					if fmt.Sprintf("%x", span.TraceId) == traceID {
						return true
					}
				}
			}
		}
	}
	return false
}

func e2e4CapturedFamilyIDs(requests []*collectortracepb.ExportTraceServiceRequest) []string {
	set := make(map[string]struct{})
	for _, request := range requests {
		for _, resourceSpans := range request.ResourceSpans {
			for _, scopeSpans := range resourceSpans.ScopeSpans {
				for _, span := range scopeSpans.Spans {
					family, _ := galileoProtoAttributes(span.Attributes)["defenseclaw.span.family"].(string)
					if family != "" {
						set[family] = struct{}{}
					}
				}
			}
		}
	}
	families := make([]string, 0, len(set))
	for family := range set {
		families = append(families, family)
	}
	sort.Strings(families)
	return families
}

func e2e4AssertMetricProjection(t *testing.T, requests []*collectormetricpb.ExportMetricsServiceRequest) {
	t.Helper()
	var found int
	for _, request := range requests {
		for _, resourceMetrics := range request.ResourceMetrics {
			for _, scopeMetrics := range resourceMetrics.ScopeMetrics {
				for _, metric := range scopeMetrics.Metrics {
					if metric.Name == observability.TelemetryInstrumentGenAIClientOperationDuration {
						found++
					}
				}
			}
		}
	}
	if found != 1 {
		t.Fatalf("independent metric exports=%d requests=%d", found, len(requests))
	}
}

var _ telemetry.V8CanonicalSpanConsumer = (*e2e4FunnelConsumer)(nil)
