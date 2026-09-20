// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type benchmarkGraphReporter struct{}

func (benchmarkGraphReporter) PlatformHealth(*runtimegraph.Graph, runtimegraph.Report) error {
	return nil
}

func (benchmarkGraphReporter) ComplianceActivity(*runtimegraph.Graph, runtimegraph.Report) error {
	return nil
}

type benchmarkAdapterFactory struct {
	mu       sync.Mutex
	adapters map[string]*benchmarkAdapter
}

func (factory *benchmarkAdapterFactory) PrepareDestination(
	_ context.Context,
	destination config.ObservabilityV8EffectiveDestination,
	_ telemetry.V8ResourceContext,
) (delivery.Adapter, DestinationAdapterCleanup, error) {
	adapter := &benchmarkAdapter{delivered: make(chan int, 1)}
	factory.mu.Lock()
	factory.adapters[destination.Name] = adapter
	factory.mu.Unlock()
	return adapter, func(context.Context) error { return nil }, nil
}

func (factory *benchmarkAdapterFactory) adapter(name string) *benchmarkAdapter {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return factory.adapters[name]
}

type benchmarkAdapter struct {
	delivered chan int
}

func (*benchmarkAdapter) EncodedSize(sizes []int) (int, bool) {
	return delivery.DelimitedEncodedSize(sizes, 0, 1, 0)
}

func (adapter *benchmarkAdapter) Deliver(ctx context.Context, batch delivery.Batch) delivery.DeliveryResult {
	select {
	case adapter.delivered <- batch.Len():
		return delivery.DeliveryResult{Outcome: delivery.OutcomeDelivered}
	case <-ctx.Done():
		return delivery.DeliveryResult{Outcome: delivery.OutcomeTransient}
	}
}

type benchmarkMetricSink struct {
	records atomic.Int64
}

func (sink *benchmarkMetricSink) RecordMetric(context.Context, telemetry.V8ProjectedMetric) error {
	sink.records.Add(1)
	return nil
}

func (*benchmarkMetricSink) ForceFlush(context.Context) error { return nil }
func (*benchmarkMetricSink) Shutdown(context.Context) error   { return nil }

func BenchmarkDisabledSignalCollection(b *testing.B) {
	no := false
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "benchmark", ServiceInstanceID: "benchmark-disabled-signals",
		DefenseClawInstanceID: "benchmark-disabled-signals",
	})
	runtime, _ := newBenchmarkRuntime(b, func(source *config.ObservabilityV8Source) {
		source.Defaults.Collect.Traces = &no
		source.Defaults.Collect.Metrics = &no
	}, Options{TelemetryProviderFactory: providerFactory})
	traceInput := observability.SpanAgentInvokeInput{
		DefenseClawAgentType: "root", Kind: "INTERNAL",
		StartTimeUnixNano: uint64(time.Now().UTC().UnixNano()),
	}
	var metricBuilds atomic.Int64
	metricBuilder := func(EmitContext) (observability.Record, error) {
		metricBuilds.Add(1)
		return observability.Record{}, nil
	}

	b.Run("trace", func(b *testing.B) {
		if _, span, err := runtime.StartAgentTrace(b.Context(), traceInput); err != nil || span != nil {
			b.Fatalf("disabled trace warm-up span=%v err=%v", span, err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		unexpected := 0
		for range b.N {
			_, span, err := runtime.StartAgentTrace(b.Context(), traceInput)
			if err != nil {
				b.Fatal(err)
			}
			if span != nil {
				unexpected++
				span.Abort()
			}
		}
		b.StopTimer()
		if unexpected != 0 {
			b.Fatalf("disabled trace created %d handles", unexpected)
		}
	})

	b.Run("metric", func(b *testing.B) {
		if result, err := runtime.RecordGeneratedMetric(b.Context(), generatedMetricFamily, metricBuilder); err != nil || result != (telemetry.V8MetricRecordResult{}) {
			b.Fatalf("disabled metric warm-up=%+v err=%v", result, err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			if _, err := runtime.RecordGeneratedMetric(b.Context(), generatedMetricFamily, metricBuilder); err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()
		if metricBuilds.Load() != 0 {
			b.Fatalf("disabled metric constructed %d records", metricBuilds.Load())
		}
	})
}

func BenchmarkDisabledLogCollection(b *testing.B) {
	no := false
	runtime, _ := newBenchmarkRuntime(b, func(source *config.ObservabilityV8Source) {
		source.Defaults.Collect.Logs = &no
	}, Options{})
	metadata := benchmarkDiagnosticMetadata(b)
	var builds atomic.Int64
	builder := func(EmitContext, router.Admission) (observability.Record, error) {
		builds.Add(1)
		return observability.Record{}, nil
	}
	if outcome, err := runtime.Emit(b.Context(), metadata, builder); err != nil || outcome.Admission() != router.AdmissionDrop {
		b.Fatalf("disabled log warm-up admission=%s err=%v", outcome.Admission(), err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := runtime.Emit(b.Context(), metadata, builder); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if builds.Load() != 0 {
		b.Fatalf("disabled log constructed %d records", builds.Load())
	}
}

func BenchmarkLogPipeline(b *testing.B) {
	b.Run("local_only", func(b *testing.B) {
		runtime, _ := newBenchmarkRuntime(b, nil, Options{})
		metadata := benchmarkDiagnosticMetadata(b)
		builder := benchmarkLogBuilder(b)
		if outcome, err := runtime.EmitLocalOnly(b.Context(), metadata, builder); err != nil || !outcome.LocalPersisted() || len(outcome.OptionalWork()) != 0 {
			b.Fatalf("local-only warm-up persisted=%t work=%d err=%v", outcome.LocalPersisted(), len(outcome.OptionalWork()), err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		persisted := 0
		for range b.N {
			outcome, err := runtime.EmitLocalOnly(b.Context(), metadata, builder)
			if err != nil {
				b.Fatal(err)
			}
			if outcome.LocalPersisted() {
				persisted++
			}
		}
		b.StopTimer()
		if persisted != b.N {
			b.Fatalf("local-only persisted=%d want=%d", persisted, b.N)
		}
	})

	b.Run("local_plus_three_memory_sinks", func(b *testing.B) {
		factory := &benchmarkAdapterFactory{adapters: make(map[string]*benchmarkAdapter)}
		runtime, _ := newBenchmarkRuntime(b, func(source *config.ObservabilityV8Source) {
			for index := 1; index <= 3; index++ {
				name := fmt.Sprintf("memory-%d", index)
				source.Destinations = append(source.Destinations, config.ObservabilityV8DestinationSource{
					Name: name, Kind: config.ObservabilityV8DestinationConsole,
					Send: &config.ObservabilityV8SendSource{
						Signals: []observability.Signal{observability.SignalLogs},
						Buckets: []observability.Bucket{"*"}, RedactionProfile: "none",
					},
					Batch: config.ObservabilityV8BatchSource{
						MaxQueueSize: 8,
					},
				})
			}
		}, Options{DestinationAdapterFactory: factory})
		adapters := []*benchmarkAdapter{
			factory.adapter("memory-1"), factory.adapter("memory-2"), factory.adapter("memory-3"),
		}
		for index, adapter := range adapters {
			if adapter == nil {
				b.Fatalf("memory adapter %d was not prepared", index+1)
			}
		}
		metadata := benchmarkDiagnosticMetadata(b)
		builder := benchmarkLogBuilder(b)
		if delivered := emitAndDrainBenchmarkLog(b, runtime, metadata, builder, adapters); delivered != len(adapters) {
			b.Fatalf("fan-out warm-up deliveries=%d want=%d", delivered, len(adapters))
		}
		b.ReportAllocs()
		b.ResetTimer()
		delivered := 0
		for range b.N {
			delivered += emitAndDrainBenchmarkLog(b, runtime, metadata, builder, adapters)
		}
		b.StopTimer()
		if want := b.N * len(adapters); delivered != want {
			b.Fatalf("fan-out deliveries=%d want=%d", delivered, want)
		}
	})
}

func BenchmarkMetricRecord(b *testing.B) {
	sink := &benchmarkMetricSink{}
	yes, no := true, false
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "benchmark", ServiceInstanceID: "benchmark-metric",
		GenerationPipelines: func(context.Context, *config.ObservabilityV8Plan, uint64, telemetry.V8MetricReaderSpec) (telemetry.V8GenerationPipelines, error) {
			return telemetry.V8GenerationPipelines{MetricPipelines: []telemetry.V8GenerationMetricPipeline{{
				Destination: "memory-metrics", Projection: telemetry.V8MetricProjectionCanonical,
				SelectedFamilies: []observability.EventName{generatedMetricFamily}, Sink: sink,
			}}}, nil
		},
	})
	runtime, _ := newBenchmarkRuntime(b, func(source *config.ObservabilityV8Source) {
		source.Defaults.Collect.Metrics = &no
		source.Buckets = map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketAgentLifecycle: {
				Collect: config.ObservabilityV8CollectSource{Metrics: &yes},
			},
		}
	}, Options{TelemetryProviderFactory: providerFactory})
	builder := benchmarkMetricBuilder(b)
	if result, err := runtime.RecordGeneratedMetric(b.Context(), generatedMetricFamily, builder); err != nil || result != (telemetry.V8MetricRecordResult{Matched: 1, Delivered: 1}) {
		b.Fatalf("metric warm-up=%+v err=%v", result, err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := runtime.RecordGeneratedMetric(b.Context(), generatedMetricFamily, builder); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if got, want := sink.records.Load(), int64(b.N+1); got != want {
		b.Fatalf("metric records=%d want=%d", got, want)
	}
}

func newBenchmarkRuntime(
	b *testing.B,
	mutate func(*config.ObservabilityV8Source),
	overrides Options,
) (*Runtime, *audit.Store) {
	b.Helper()
	directory := b.TempDir()
	store, err := audit.NewStore(filepath.Join(directory, "audit.db"))
	if err != nil {
		b.Fatal(err)
	}
	if err := store.Init(); err != nil {
		_ = store.Close()
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = store.Close() })
	retentionDays := 0
	source := &config.ObservabilityV8Source{Local: config.ObservabilityV8LocalSource{
		Path: store.DatabasePath(), JudgeBodiesPath: filepath.Join(directory, "judge-bodies.db"),
		RetentionDays: &retentionDays,
	}}
	if mutate != nil {
		mutate(source)
	}
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		b.Fatal(err)
	}
	engine, err := redaction.NewEngine(nil)
	if err != nil {
		b.Fatal(err)
	}
	var failureIDs atomic.Uint64
	failureBuilder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("benchmark-failure-%d", failureIDs.Add(1)), nil
		}),
	)
	if err != nil {
		b.Fatal(err)
	}
	reaper, err := audit.NewRetentionReaper(store, nil, 0, audit.RetentionOptions{})
	if err != nil {
		b.Fatal(err)
	}
	// Retention has its own benchmark. Keep its startup run readiness-gated so
	// SQLite maintenance cannot perturb log/metric measurements.
	retentionReady := make(chan struct{})
	retention, err := NewRetentionController(reaper, RetentionControllerOptions{Ready: retentionReady})
	if err != nil {
		b.Fatal(err)
	}
	overrides.Store = store
	overrides.Engine = engine
	overrides.RecordBuilder = failureBuilder
	overrides.Reporter = benchmarkGraphReporter{}
	overrides.RetentionController = retention
	runtime, err := New(b.Context(), runtimegraph.ConfigFromPlan(plan, false), overrides)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			b.Errorf("close benchmark runtime: %v", err)
		}
	})
	return runtime, store
}

func benchmarkDiagnosticMetadata(b *testing.B) router.Metadata {
	b.Helper()
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		"diagnostic",
		observability.ClassificationContext{RawSeverity: "INFO"},
		observability.SourceSystem,
		"",
		"diagnostic",
	)
	if err != nil {
		b.Fatal(err)
	}
	return metadata
}

func benchmarkLogBuilder(b *testing.B) EmitBuilder {
	b.Helper()
	var ids atomic.Uint64
	builder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return time.Unix(1_800_000_001, 0).UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("benchmark-log-%d", ids.Add(1)), nil
		}),
	)
	if err != nil {
		b.Fatal(err)
	}
	return func(snapshot EmitContext, _ router.Admission) (observability.Record, error) {
		return builder.BuildClassifiedLog(observability.ClassifiedLogInput{
			ProducerKind: observability.ProducerGatewayEvent,
			ProducerKey:  "diagnostic",
			ClassificationContext: observability.ClassificationContext{
				RawSeverity: "INFO",
			},
			Source: observability.SourceSystem, Action: "diagnostic",
			Outcome: observability.OutcomeCompleted,
			Provenance: observability.Provenance{
				Producer: "benchmark", BinaryVersion: "8.0.0",
				RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
				ConfigGeneration:      int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
			},
			Body: map[string]any{"message": "benchmark event"},
			FieldClasses: map[string]observability.FieldClass{
				"/message": observability.FieldClassContent,
			},
		})
	}
}

func emitAndDrainBenchmarkLog(
	b *testing.B,
	runtime *Runtime,
	metadata router.Metadata,
	builder EmitBuilder,
	adapters []*benchmarkAdapter,
) int {
	outcome, err := runtime.Emit(b.Context(), metadata, builder)
	if err != nil || !outcome.LocalPersisted() {
		b.Fatalf("fan-out persisted=%t err=%v", outcome.LocalPersisted(), err)
	}
	delivered := 0
	for _, adapter := range adapters {
		select {
		case count := <-adapter.delivered:
			delivered += count
		case <-b.Context().Done():
			b.Fatal("benchmark context ended while waiting for in-memory destination")
		}
	}
	return delivered
}

func benchmarkMetricBuilder(b *testing.B) GeneratedMetricBuilder {
	b.Helper()
	var ids atomic.Uint64
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Unix(1_800_000_002, 0).UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("benchmark-metric-%d", ids.Add(1)), nil
		}),
	)
	if err != nil {
		b.Fatal(err)
	}
	return func(snapshot EmitContext) (observability.Record, error) {
		return builder.BuildMetricDefenseClawConnectorHookLatency(
			observability.MetricDefenseClawConnectorHookLatencyInput{
				Envelope: observability.FamilyEnvelopeInput{
					Source: observability.SourceGateway,
					Provenance: observability.FamilyProvenanceInput{
						Producer: "benchmark", BinaryVersion: "8.0.0",
						ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
					},
				},
				Value: 1.25, DefenseClawConnectorSource: observability.Present("codex"),
				DefenseClawMetricEventType: observability.Present("prompt"),
				DefenseClawMetricReason:    observability.Present("allow"),
				DefenseClawMetricResult:    observability.Present("ok"),
			},
		)
	}
}

var _ delivery.Adapter = (*benchmarkAdapter)(nil)
var _ DestinationAdapterFactory = (*benchmarkAdapterFactory)(nil)
var _ telemetry.V8CanonicalMetricSink = (*benchmarkMetricSink)(nil)
