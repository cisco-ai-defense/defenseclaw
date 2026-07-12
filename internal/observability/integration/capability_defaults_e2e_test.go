// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/otlp"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/prometheus"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	collectorlogpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetricpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

const e2e5RawContent = "Capability defaults preserve operator@example.test in raw projections."

type e2e5OTLPCapture struct {
	mu      sync.Mutex
	logs    []*collectorlogpb.ExportLogsServiceRequest
	metrics []*collectormetricpb.ExportMetricsServiceRequest
	traces  []*collectortracepb.ExportTraceServiceRequest
}

func (capture *e2e5OTLPCapture) handle(writer http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	capture.mu.Lock()
	defer capture.mu.Unlock()
	switch request.URL.Path {
	case "/v1/logs":
		decoded := &collectorlogpb.ExportLogsServiceRequest{}
		if err := proto.Unmarshal(body, decoded); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		capture.logs = append(capture.logs, proto.Clone(decoded).(*collectorlogpb.ExportLogsServiceRequest))
	case "/v1/traces":
		decoded := &collectortracepb.ExportTraceServiceRequest{}
		if err := proto.Unmarshal(body, decoded); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		capture.traces = append(capture.traces, proto.Clone(decoded).(*collectortracepb.ExportTraceServiceRequest))
	case "/v1/metrics":
		decoded := &collectormetricpb.ExportMetricsServiceRequest{}
		if err := proto.Unmarshal(body, decoded); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		capture.metrics = append(capture.metrics, proto.Clone(decoded).(*collectormetricpb.ExportMetricsServiceRequest))
	default:
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	writer.Header().Set("Content-Type", "application/x-protobuf")
	writer.WriteHeader(http.StatusOK)
}

func (capture *e2e5OTLPCapture) snapshot() (logs [][]byte, traces [][]byte, metrics [][]byte) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	for _, request := range capture.logs {
		encoded, _ := proto.Marshal(request)
		logs = append(logs, encoded)
	}
	for _, request := range capture.traces {
		encoded, _ := proto.Marshal(request)
		traces = append(traces, encoded)
	}
	for _, request := range capture.metrics {
		encoded, _ := proto.Marshal(request)
		metrics = append(metrics, encoded)
	}
	return logs, traces, metrics
}

type e2e5PrometheusListener struct {
	mu       sync.Mutex
	listener net.Listener
}

func (capture *e2e5PrometheusListener) listen(ctx context.Context, network, _ string) (net.Listener, error) {
	listener, err := (&net.ListenConfig{}).Listen(ctx, network, "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	capture.mu.Lock()
	capture.listener = listener
	capture.mu.Unlock()
	return listener, nil
}

func (capture *e2e5PrometheusListener) address(t *testing.T) string {
	t.Helper()
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if capture.listener == nil {
		t.Fatal("Prometheus capability-default listener was not prepared")
	}
	return capture.listener.Addr().String()
}

func TestE2E5CapabilityDefaultsExportAllSupportedSignalsUnredacted(t *testing.T) {
	directory := t.TempDir()
	storePath := filepath.Join(directory, "audit.db")
	judgePath := filepath.Join(directory, "judge.db")
	rawJSONLPath := filepath.Join(directory, "raw.jsonl")
	strictJSONLPath := filepath.Join(directory, "strict.jsonl")

	capture := &e2e5OTLPCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handle))
	defer server.Close()

	source := observabilitySource(storePath, judgePath, []config.ObservabilityV8DestinationSource{
		{Name: "raw-jsonl", Kind: config.ObservabilityV8DestinationJSONL, Path: rawJSONLPath},
		{Name: "prometheus", Kind: config.ObservabilityV8DestinationPrometheus, Listen: "127.0.0.1:9464", Path: "/metrics"},
		{
			Name: "otlp-all", Kind: config.ObservabilityV8DestinationOTLP,
			Endpoint: server.URL, Protocol: "http/protobuf",
			TLS:           config.ObservabilityV8TLSSource{Insecure: true},
			NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
		},
		{
			Name: "strict-jsonl", Kind: config.ObservabilityV8DestinationJSONL, Path: strictJSONLPath,
			Send: &config.ObservabilityV8SendSource{
				Signals: []observability.Signal{observability.SignalLogs},
				Buckets: []observability.Bucket{"*"}, RedactionProfile: "strict",
			},
		},
	})
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	e2e5AssertCapabilityPlan(t, plan)

	store, err := audit.NewStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	engine, err := redaction.NewEngine([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	health := &integrationDeliveryHealth{}
	factory, err := destinations.NewFactory(destinations.Options{
		ConsoleStream: destinations.ConsoleStderr, Stdout: io.Discard, Stderr: io.Discard,
		Secrets:  &integrationSecrets{values: map[string]string{}, calls: map[string]int{}},
		CALoader: &integrationCALoader{}, Resolver: net.DefaultResolver, Dialer: &net.Dialer{},
		Warnings: &integrationWarnings{}, RedactionEngine: engine, DeliveryObserver: health,
		OTLPCanonicalObserver: otlp.CanonicalObserverFunc(func(otlp.CanonicalFailure) {}),
	})
	if err != nil {
		t.Fatal(err)
	}
	listener := &e2e5PrometheusListener{}
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "integration-test", Environment: "test", ServiceInstanceID: "e2e5-service",
		DefenseClawInstanceID: "e2e5-instance",
		GenerationPipelines:   factory.GenerationPipelineFactory(prometheus.Options{Listen: listener.listen}),
	})
	reaper, err := audit.NewRetentionReaper(store, nil, 0, audit.RetentionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	retention, err := observabilityruntime.NewRetentionController(reaper, observabilityruntime.RetentionControllerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := observabilityruntime.New(t.Context(), runtimegraph.ConfigFromPlan(plan, false), observabilityruntime.Options{
		Store: store, Engine: engine, RecordBuilder: mustRecordBuilder(t, "e2e5-runtime-failure"),
		Reporter: &discardReporter{}, RetentionController: retention,
		DestinationAdapterFactory: factory, DestinationObserver: health,
		TelemetryProviderFactory: providerFactory,
	})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = runtime.Close(context.Background())
		}
	})

	e2e5EmitContentLog(t, runtime)
	emitGalileoRichGraphConfigured(t, runtime, "405060708090a0b0c0d0e0f001122334", 1, e2e5RawContent, "raw output")
	e2e5RecordMetric(t, runtime)
	prometheusBody := e2e5ScrapePrometheus(t, listener.address(t))
	if err := runtime.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	closed = true

	rawJSONL, err := os.ReadFile(rawJSONLPath)
	if err != nil {
		t.Fatal(err)
	}
	strictJSONL, err := os.ReadFile(strictJSONLPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rawJSONL, []byte(e2e5RawContent)) || !bytes.Contains(rawJSONL, []byte(`"redaction_profile":"none"`)) {
		t.Fatalf("capability-default JSONL lost raw projection: %s", rawJSONL)
	}
	if bytes.Contains(strictJSONL, []byte(e2e5RawContent)) || !bytes.Contains(strictJSONL, []byte(`"redaction_profile":"strict"`)) {
		t.Fatalf("explicit strict JSONL projection=%s", strictJSONL)
	}
	logs, traces, metrics := capture.snapshot()
	if !e2e5Contains(logs, e2e5RawContent) || !e2e5Contains(logs, "redaction_profile") || !e2e5Contains(logs, "none") {
		t.Fatal("capability-default OTLP logs did not retain the raw none projection")
	}
	if !e2e5Contains(traces, e2e5RawContent) {
		t.Fatal("capability-default OTLP traces did not retain content")
	}
	if !e2e5Contains(metrics, "gen_ai.client.operation.duration") {
		t.Fatal("capability-default OTLP metrics did not contain the generated metric")
	}
	if !bytes.Contains(prometheusBody, []byte("gen_ai_client_operation_duration_seconds")) {
		t.Fatalf("capability-default Prometheus metric missing:\n%s", prometheusBody)
	}
}

func e2e5AssertCapabilityPlan(t *testing.T, plan *config.ObservabilityV8Plan) {
	t.Helper()
	wantSignals := map[string][]observability.Signal{
		"raw-jsonl":  {observability.SignalLogs},
		"prometheus": {observability.SignalMetrics},
		"otlp-all":   {observability.SignalLogs, observability.SignalTraces, observability.SignalMetrics},
	}
	for name, signals := range wantSignals {
		destination, ok := plan.RuntimeDestination(name)
		if !ok || destination.PolicyForm != config.ObservabilityV8PolicyCapabilityDefault ||
			fmt.Sprint(destination.SelectedSignals) != fmt.Sprint(signals) || len(destination.Routes) != 1 ||
			len(destination.Routes[0].Selector.Buckets) != len(observability.Buckets()) {
			t.Fatalf("capability-default destination %s=%+v", name, destination)
		}
		if name != "prometheus" && destination.Routes[0].RedactionProfileByBucket[observability.BucketModelIO] != "none" {
			t.Fatalf("capability-default destination %s is not explicitly unredacted", name)
		}
	}
	raw, _ := plan.RuntimeDestination("raw-jsonl")
	otlp, _ := plan.RuntimeDestination("otlp-all")
	if raw.Transport.Batch == nil || raw.Transport.Batch.MaxQueueSize != 2048 || raw.Transport.Batch.MaxQueueBytes != 67_108_864 ||
		otlp.Transport.Batch == nil || otlp.Transport.Batch.MaxExportBatchSize != 512 ||
		otlp.Transport.Batch.MaxExportBatchBytes != 8_388_608 || otlp.Transport.Batch.ScheduledDelayMS != 5000 {
		t.Fatalf("implicit queue/batch defaults raw=%+v otlp=%+v", raw.Transport.Batch, otlp.Transport.Batch)
	}
	strict, ok := plan.RuntimeDestination("strict-jsonl")
	if !ok || strict.PolicyForm != config.ObservabilityV8PolicyConciseSend || len(strict.Routes) != 1 ||
		strict.Routes[0].RedactionProfileByBucket[observability.BucketModelIO] != "strict" {
		t.Fatalf("explicit strict destination=%+v", strict)
	}
}

func e2e5EmitContentLog(t *testing.T, runtime *observabilityruntime.Runtime) {
	t.Helper()
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent, "llm_prompt",
		observability.ClassificationContext{RawSeverity: "INFO"},
		observability.SourceGateway, "codex", "llm_prompt",
	)
	if err != nil {
		t.Fatal(err)
	}
	builder := mustRecordBuilder(t, "e2e5-model-log")
	outcome, err := runtime.Emit(t.Context(), metadata, func(snapshot observabilityruntime.EmitContext, admission router.Admission) (observability.Record, error) {
		return builder.BuildClassifiedLog(observability.ClassifiedLogInput{
			ProducerKind: observability.ProducerGatewayEvent, ProducerKey: "llm_prompt",
			ClassificationContext: observability.ClassificationContext{RawSeverity: "INFO"},
			Source:                observability.SourceGateway, Connector: "codex", Action: "llm_prompt",
			Correlation: observability.Correlation{RunID: "e2e5-run", RequestID: "e2e5-request"},
			Provenance: observability.Provenance{
				Producer: "e2e5", BinaryVersion: "integration-test",
				RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
				ConfigGeneration:      int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
			},
			Body:         map[string]any{"content": e2e5RawContent},
			FieldClasses: map[string]observability.FieldClass{"/content": observability.FieldClassContent},
		})
	})
	if err != nil || admissionNotOrdinary(outcome.Admission()) || !outcome.LocalPersisted() || len(outcome.OptionalWork()) != 3 {
		t.Fatalf("capability-default log outcome=%+v error=%v", outcome, err)
	}
}

func admissionNotOrdinary(admission router.Admission) bool {
	return admission != router.AdmissionOrdinary
}

func e2e5RecordMetric(t *testing.T, runtime *observabilityruntime.Runtime) {
	t.Helper()
	result, err := runtime.RecordGeneratedMetric(
		t.Context(), observability.EventName(observability.TelemetryInstrumentGenAIClientOperationDuration),
		func(snapshot observabilityruntime.EmitContext) (observability.Record, error) {
			builder, builderErr := observability.NewFamilyBuilder(
				observability.ClockFunc(time.Now),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return "e2e5-metric", nil }),
			)
			if builderErr != nil {
				return observability.Record{}, builderErr
			}
			return builder.BuildMetricGenAIClientOperationDuration(observability.MetricGenAIClientOperationDurationInput{
				Envelope: observability.FamilyEnvelopeInput{
					Source: observability.SourceGateway,
					Provenance: observability.FamilyProvenanceInput{
						Producer: "e2e5", BinaryVersion: "integration-test",
						ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
					},
				},
				Value: 0.125, GenAIOperationName: observability.Present("chat"),
				GenAIProviderName: observability.Present("openai"), GenAIRequestModel: observability.Present("gpt-4o-mini"),
			})
		},
	)
	if err != nil || result.Matched != 2 || result.Delivered != 2 || result.Failed != 0 || result.Suppressed != 0 {
		t.Fatalf("capability-default metric result=%+v error=%v", result, err)
	}
}

func e2e5ScrapePrometheus(t *testing.T, address string) []byte {
	t.Helper()
	response, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + address + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("Prometheus scrape status=%d error=%v body=%s", response.StatusCode, err, body)
	}
	return body
}

func e2e5Contains(requests [][]byte, value string) bool {
	for _, request := range requests {
		if bytes.Contains(request, []byte(value)) {
			return true
		}
	}
	return false
}
