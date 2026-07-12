// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/schemas"
)

type v8MetricManifestCatalog struct {
	Families []struct {
		EventName string `json:"event_name"`
		Signal    string `json:"signal"`
	} `json:"families"`
}

func TestV8MetricCatalogExactlyPreservesGeneratedInstrumentManifest(t *testing.T) {
	raw := schemas.TelemetryV8CompatibilityProfile("local-observability-v1")
	if len(raw) == 0 {
		t.Fatal("embedded local-observability-v1 manifest is unavailable")
	}
	var manifest v8MetricManifestCatalog
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	want := make([]string, 0)
	for _, family := range manifest.Families {
		if family.Signal == "metrics" {
			want = append(want, family.EventName)
		}
	}
	sort.Strings(want)
	catalog := V8MetricCatalog()
	got := make([]string, len(catalog))
	seen := make(map[string]struct{}, len(catalog))
	for index, item := range catalog {
		got[index] = item.Name
		if !observability.IsBucket(item.Bucket) {
			t.Errorf("metric %s has invalid bucket %s", item.Name, item.Bucket)
		}
		if _, duplicate := seen[item.Name]; duplicate {
			t.Errorf("duplicate metric %s", item.Name)
		}
		seen[item.Name] = struct{}{}
	}
	if len(got) == 0 || !reflect.DeepEqual(got, want) {
		t.Fatalf("v8 metric inventory count=%d manifest=%d equal=%v", len(got), len(want), reflect.DeepEqual(got, want))
	}
}

func TestV8MetricAttributePolicyIsGeneratedAndCoversLegacyEmitterKeys(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(current), "metrics.go"))
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`attribute\.(?:String|Int|Int64|Bool|Float64|StringSlice)\("([^"]+)"`)
	wantSet := map[string]struct{}{}
	for _, match := range pattern.FindAllStringSubmatch(string(raw), -1) {
		wantSet[match[1]] = struct{}{}
	}
	want := make([]string, 0, len(wantSet))
	for key := range wantSet {
		want = append(want, key)
	}
	sort.Strings(want)
	got := make([]string, 0, len(v8MetricAllowedAttributeKeys))
	for key := range v8MetricAllowedAttributeKeys {
		got = append(got, string(key))
	}
	sort.Strings(got)
	gotSet := make(map[string]struct{}, len(got))
	for _, key := range got {
		gotSet[key] = struct{}{}
	}
	for _, key := range want {
		if _, covered := gotSet[key]; !covered {
			t.Fatalf("generated metric attribute vocabulary omitted legacy key %q", key)
		}
	}
	descriptors, err := V8MetricDescriptorCatalog()
	if err != nil {
		t.Fatal(err)
	}
	expectedSet := make(map[string]struct{})
	for _, descriptor := range descriptors {
		for _, key := range descriptor.AllowedLabels {
			expectedSet[key] = struct{}{}
		}
		for _, mapping := range descriptor.LocalLabelMapping {
			expectedSet[mapping.Local] = struct{}{}
		}
	}
	expected := make([]string, 0, len(expectedSet))
	for key := range expectedSet {
		expected = append(expected, key)
	}
	sort.Strings(expected)
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("metric attribute vocabulary is not generated: got=%v want=%v", got, expected)
	}
}

func TestV8MetricAllowedAttributeKeysIsSortedAndDetached(t *testing.T) {
	first := V8MetricAllowedAttributeKeys()
	second := V8MetricAllowedAttributeKeys()
	if len(first) != len(v8MetricAllowedAttributeKeys) || !sort.StringsAreSorted(first) ||
		!reflect.DeepEqual(first, second) {
		t.Fatalf("public metric labels are not an exact sorted snapshot: first=%v second=%v", first, second)
	}
	if len(first) == 0 {
		t.Fatal("public metric label snapshot is empty")
	}
	first[0] = "mutated"
	third := V8MetricAllowedAttributeKeys()
	if reflect.DeepEqual(first, third) || !reflect.DeepEqual(second, third) {
		t.Fatal("public metric label snapshot aliases internal or prior state")
	}
}

func metricPlanForTest(t *testing.T, enabled ...observability.Bucket) *config.ObservabilityV8Plan {
	t.Helper()
	return v8PlanForTest(t, "always_on", "", func(source *config.ObservabilityV8Source) {
		no := false
		yes := true
		source.Defaults.Collect.Traces = &no
		source.Defaults.Collect.Metrics = &no
		source.Buckets = make(map[observability.Bucket]config.ObservabilityV8BucketPolicySource)
		for _, bucket := range enabled {
			source.Buckets[bucket] = config.ObservabilityV8BucketPolicySource{
				Collect: config.ObservabilityV8CollectSource{Metrics: &yes},
			}
		}
	})
}

func manualMetricReaderFactory(
	t *testing.T,
	captured *V8MetricReaderSpec,
) (V8MetricReaderFactory, **sdkmetric.ManualReader) {
	t.Helper()
	var reader *sdkmetric.ManualReader
	factory := func(_ uint64, spec V8MetricReaderSpec) (sdkmetric.Reader, error) {
		*captured = spec
		reader = sdkmetric.NewManualReader(
			sdkmetric.WithTemporalitySelector(func(sdkmetric.InstrumentKind) metricdata.Temporality {
				return spec.Temporality
			}),
			sdkmetric.WithCardinalityLimitSelector(func(sdkmetric.InstrumentKind) (int, bool) {
				return spec.CardinalityLimit, false
			}),
		)
		return reader, nil
	}
	return factory, &reader
}

func activeV8MetricProvider(
	t *testing.T,
	plan *config.ObservabilityV8Plan,
) (*Provider, *sdkmetric.ManualReader, V8MetricReaderSpec) {
	t.Helper()
	var spec V8MetricReaderSpec
	factory, readerPointer := manualMetricReaderFactory(t, &spec)
	provider, err := NewProviderV8Inactive(context.Background(), plan, 1, V8ProviderOptions{
		Version: "test", Environment: "test", ServiceInstanceID: "metric-test",
		MetricReaderFactories: []V8MetricReaderFactory{factory},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider.v8.active.Store(true)
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return provider, *readerPointer, spec
}

func TestV8MetricCollectionGatePrecedesSDKInstrumentConstruction(t *testing.T) {
	before := otel.GetMeterProvider()
	plan := metricPlanForTest(t, observability.BucketAssetScan)
	provider, reader, spec := activeV8MetricProvider(t, plan)
	if otel.GetMeterProvider() != before {
		t.Fatal("inactive v8 metric provider mutated the OTel global")
	}
	if spec.ExportInterval != 60*time.Second || spec.Temporality != metricdata.DeltaTemporality ||
		spec.CardinalityLimit != v8MetricCardinalityLimit {
		t.Fatalf("default metric spec=%+v", spec)
	}
	if !provider.MetricBucketEnabled(observability.BucketAssetScan) ||
		provider.MetricBucketEnabled(observability.BucketAgentLifecycle) ||
		!provider.metrics.scanCount.Enabled(context.Background()) ||
		provider.metrics.agentLifecycleTransitions.Enabled(context.Background()) {
		t.Fatal("metric collection gate did not precede instrument construction")
	}
	provider.metrics.scanCount.Add(context.Background(), 1)
	provider.metrics.agentLifecycleTransitions.Add(context.Background(), 1)
	var collected metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &collected); err != nil {
		t.Fatal(err)
	}
	names := metricNames(collected)
	if !containsMetric(names, "defenseclaw.scan.count") || containsMetric(names, "defenseclaw.agent.lifecycle.transitions") {
		t.Fatalf("collected metric names=%v", names)
	}
}

func TestV8MeterForBucketCannotBypassCatalogOrBounds(t *testing.T) {
	provider, _, _ := activeV8MetricProvider(t, metricPlanForTest(
		t, observability.BucketAssetScan, observability.BucketAgentLifecycle,
	))
	meter := provider.MeterForBucket(observability.BucketAssetScan)
	constructors := map[string]func() error{
		"int64_counter":                      func() error { _, err := meter.Int64Counter("unregistered.metric"); return err },
		"int64_up_down_counter":              func() error { _, err := meter.Int64UpDownCounter("unregistered.metric"); return err },
		"int64_histogram":                    func() error { _, err := meter.Int64Histogram("unregistered.metric"); return err },
		"int64_gauge":                        func() error { _, err := meter.Int64Gauge("unregistered.metric"); return err },
		"int64_observable_counter":           func() error { _, err := meter.Int64ObservableCounter("unregistered.metric"); return err },
		"int64_observable_up_down_counter":   func() error { _, err := meter.Int64ObservableUpDownCounter("unregistered.metric"); return err },
		"int64_observable_gauge":             func() error { _, err := meter.Int64ObservableGauge("unregistered.metric"); return err },
		"float64_counter":                    func() error { _, err := meter.Float64Counter("unregistered.metric"); return err },
		"float64_up_down_counter":            func() error { _, err := meter.Float64UpDownCounter("unregistered.metric"); return err },
		"float64_histogram":                  func() error { _, err := meter.Float64Histogram("unregistered.metric"); return err },
		"float64_gauge":                      func() error { _, err := meter.Float64Gauge("unregistered.metric"); return err },
		"float64_observable_counter":         func() error { _, err := meter.Float64ObservableCounter("unregistered.metric"); return err },
		"float64_observable_up_down_counter": func() error { _, err := meter.Float64ObservableUpDownCounter("unregistered.metric"); return err },
		"float64_observable_gauge":           func() error { _, err := meter.Float64ObservableGauge("unregistered.metric"); return err },
		"callback": func() error {
			_, err := meter.RegisterCallback(func(context.Context, metric.Observer) error { return nil })
			return err
		},
	}
	for name, construct := range constructors {
		t.Run(name, func(t *testing.T) {
			if err := construct(); err == nil {
				t.Fatal("enabled bucket meter constructed an instrument outside the generated catalog")
			}
		})
	}
	if _, err := meter.Int64Counter("defenseclaw.agent.discovery.runs"); err == nil {
		t.Fatal("asset-scan bucket meter constructed an agent-lifecycle metric")
	}
	if _, err := meter.Int64Counter("defenseclaw.scan.count"); err != nil {
		t.Fatalf("asset-scan bucket meter rejected its own catalog metric: %v", err)
	}
	disabled := provider.MeterForBucket(observability.BucketModelIO)
	unknown, err := disabled.Int64Counter("unregistered.metric")
	if err != nil || unknown.Enabled(context.Background()) {
		t.Fatalf("disabled bucket did not return a no-op meter: enabled=%v err=%v", unknown != nil && unknown.Enabled(context.Background()), err)
	}
}

func TestV8ShutdownRetryWaitsForTimedOutExporterCleanup(t *testing.T) {
	exporter := &v8BlockingShutdownExporter{started: make(chan struct{}), release: make(chan struct{})}
	provider, err := NewProviderV8Inactive(
		context.Background(), metricPlanForTest(t, observability.BucketAssetScan), 1,
		V8ProviderOptions{Version: "test", Environment: "test", MetricReaderFactories: []V8MetricReaderFactory{
			func(_ uint64, spec V8MetricReaderSpec) (sdkmetric.Reader, error) {
				return NewV8PeriodicMetricReader(exporter, spec)
			},
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	provider.v8.active.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := provider.Shutdown(ctx); err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first shutdown error=%v", err)
	}
	select {
	case <-exporter.started:
	default:
		t.Fatal("metric exporter shutdown did not start")
	}
	close(exporter.release)
	retryCtx, retryCancel := context.WithTimeout(context.Background(), time.Second)
	defer retryCancel()
	if err := provider.Shutdown(retryCtx); err != nil {
		t.Fatalf("shutdown retry did not observe completed exporter cleanup: %v", err)
	}
}

func TestV8NoSelectedMetricsBuildsNoProviderReaderOrInstruments(t *testing.T) {
	plan := metricPlanForTest(t)
	var factoryCalls int
	provider, err := NewProviderV8Inactive(context.Background(), plan, 1, V8ProviderOptions{
		Version: "test", Environment: "test",
		MetricReaderFactories: []V8MetricReaderFactory{func(uint64, V8MetricReaderSpec) (sdkmetric.Reader, error) {
			factoryCalls++
			return nil, errors.New("must not run")
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider.v8.active.Store(true)
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	if factoryCalls != 0 || provider.metrics != nil || provider.meterProvider != nil {
		t.Fatalf("disabled metrics allocated state calls=%d metrics=%p provider=%p", factoryCalls, provider.metrics, provider.meterProvider)
	}
	if provider.MetricBucketEnabled(observability.BucketAssetScan) {
		t.Fatal("disabled metrics exposed a collected bucket")
	}
}

func TestV8RejectedReaderCandidateCleansPreviouslyPreparedReaders(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	_, err := NewProviderV8Inactive(
		context.Background(), metricPlanForTest(t, observability.BucketAssetScan), 1,
		V8ProviderOptions{Version: "test", Environment: "test", MetricReaderFactories: []V8MetricReaderFactory{
			func(uint64, V8MetricReaderSpec) (sdkmetric.Reader, error) { return reader, nil },
			func(uint64, V8MetricReaderSpec) (sdkmetric.Reader, error) {
				return nil, errors.New("private reader initialization detail")
			},
		}},
	)
	var providerErr *V8ProviderError
	if !errors.As(err, &providerErr) || providerErr.Code() != V8ProviderErrorReaderInitialization ||
		strings.Contains(err.Error(), "private") {
		t.Fatalf("reader rejection error=%v", err)
	}
	if collectErr := reader.Collect(context.Background(), &metricdata.ResourceMetrics{}); !errors.Is(collectErr, sdkmetric.ErrReaderShutdown) {
		t.Fatalf("prepared reader cleanup error=%v", collectErr)
	}
}

type v8BlockingShutdownExporter struct {
	once    sync.Once
	started chan struct{}
	release chan struct{}
}

func (*v8BlockingShutdownExporter) Temporality(sdkmetric.InstrumentKind) metricdata.Temporality {
	return metricdata.DeltaTemporality
}
func (*v8BlockingShutdownExporter) Aggregation(kind sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(kind)
}
func (*v8BlockingShutdownExporter) Export(context.Context, *metricdata.ResourceMetrics) error {
	return nil
}
func (*v8BlockingShutdownExporter) ForceFlush(context.Context) error { return nil }
func (exporter *v8BlockingShutdownExporter) Shutdown(context.Context) error {
	exporter.once.Do(func() { close(exporter.started) })
	<-exporter.release
	return nil
}

func TestV8RejectedReaderCandidateCleanupIsDeadlineBounded(t *testing.T) {
	exporter := &v8BlockingShutdownExporter{started: make(chan struct{}), release: make(chan struct{})}
	defer close(exporter.release)
	started := time.Now()
	_, err := NewProviderV8Inactive(
		context.Background(), metricPlanForTest(t, observability.BucketAssetScan), 1,
		V8ProviderOptions{
			Version: "test", Environment: "test",
			PrepareCleanupTimeout: 20 * time.Millisecond,
			MetricReaderFactories: []V8MetricReaderFactory{
				func(_ uint64, spec V8MetricReaderSpec) (sdkmetric.Reader, error) {
					return NewV8PeriodicMetricReader(exporter, spec)
				},
				func(uint64, V8MetricReaderSpec) (sdkmetric.Reader, error) {
					return nil, errors.New("reject after acquisition")
				},
			},
		},
	)
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("candidate rejection err=%v duration=%s", err, time.Since(started))
	}
	select {
	case <-exporter.started:
	default:
		t.Fatal("prepared reader exporter was not defensively shut down")
	}
}

func TestV8MetricAttributesAreClosedBoundedAndDeterministic(t *testing.T) {
	provider, reader, _ := activeV8MetricProvider(t, metricPlanForTest(t, observability.BucketAssetScan))
	provider.metrics.scanCount.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("scanner", strings.Repeat("x", v8MetricMaxAttributeBytes+1)),
		attribute.String("prompt", "must-never-be-a-label"),
	))
	var bounded metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &bounded); err != nil {
		t.Fatal(err)
	}
	boundedPoint := int64Point(t, bounded, "defenseclaw.scan.count")
	if _, found := boundedPoint.Attributes.Value("prompt"); found {
		t.Fatal("unknown/content attribute survived the closed policy")
	}
	if scanner, found := boundedPoint.Attributes.Value("scanner"); !found || scanner.AsString() != v8MetricOverflowLabel {
		t.Fatalf("oversized scanner=%v found=%v", scanner, found)
	}

	attrs := make([]attribute.KeyValue, 0, len(v8MetricAllowedAttributeKeys))
	keys := make([]string, 0, len(v8MetricAllowedAttributeKeys))
	for key := range v8MetricAllowedAttributeKeys {
		keys = append(keys, string(key))
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key != "scanner" {
			attrs = append(attrs, attribute.String(key, "safe"))
		}
	}
	provider.metrics.scanCount.Add(context.Background(), 1, metric.WithAttributes(attrs...))
	var collected metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &collected); err != nil {
		t.Fatal(err)
	}
	point := int64Point(t, collected, "defenseclaw.scan.count")
	if point.Attributes.Len() != v8MetricMaxAttributes {
		t.Fatalf("attribute count=%d want=%d", point.Attributes.Len(), v8MetricMaxAttributes)
	}
}

func TestV8MetricAttributeSlicesCannotEvadeElementOrValueBounds(t *testing.T) {
	longStrings := make([]string, v8MetricMaxSliceElements+20)
	bools := make([]bool, v8MetricMaxSliceElements+20)
	integers := make([]int64, v8MetricMaxSliceElements+20)
	floats := make([]float64, v8MetricMaxSliceElements+20)
	for index := range longStrings {
		longStrings[index] = strings.Repeat("x", v8MetricMaxAttributeBytes+1)
		bools[index] = index%2 == 0
		integers[index] = int64(index)
		floats[index] = float64(index)
	}
	bounded := v8BoundMetricAttributes(attribute.NewSet(
		attribute.StringSlice("scanner", longStrings),
		attribute.BoolSlice("auto", bools),
		attribute.Int64Slice("status_code", integers),
		attribute.Float64Slice("confidence", floats),
	))
	for key, expectedType := range map[string]attribute.Type{
		"scanner": attribute.STRINGSLICE, "auto": attribute.BOOLSLICE,
		"status_code": attribute.INT64SLICE, "confidence": attribute.FLOAT64SLICE,
	} {
		value, found := bounded.Value(attribute.Key(key))
		if !found || value.Type() != expectedType {
			t.Fatalf("slice %s type=%v found=%v", key, value.Type(), found)
		}
		length := 0
		switch expectedType {
		case attribute.STRINGSLICE:
			values := value.AsStringSlice()
			length = len(values)
			for _, item := range values {
				if item != v8MetricOverflowLabel {
					t.Fatalf("oversized slice value survived: %q", item)
				}
			}
		case attribute.BOOLSLICE:
			length = len(value.AsBoolSlice())
		case attribute.INT64SLICE:
			length = len(value.AsInt64Slice())
		case attribute.FLOAT64SLICE:
			length = len(value.AsFloat64Slice())
		}
		if length != v8MetricMaxSliceElements {
			t.Fatalf("slice %s elements=%d want=%d", key, length, v8MetricMaxSliceElements)
		}
	}
}

func TestV8MetricDefaultDeltaIgnoresAmbientOTelPolicy(t *testing.T) {
	t.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "1")
	t.Setenv("OTEL_GO_X_CARDINALITY_LIMIT", "1")
	provider, reader, spec := activeV8MetricProvider(t, metricPlanForTest(t, observability.BucketAssetScan))
	if spec.ExportInterval != 60*time.Second || spec.Temporality != metricdata.DeltaTemporality || spec.CardinalityLimit != 2_048 {
		t.Fatalf("ambient OTel policy affected spec=%+v", spec)
	}
	provider.metrics.scanCount.Add(context.Background(), 2)
	var first metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &first); err != nil {
		t.Fatal(err)
	}
	if point := int64Point(t, first, "defenseclaw.scan.count"); point.Value != 2 {
		t.Fatalf("first delta=%d", point.Value)
	}
	provider.metrics.scanCount.Add(context.Background(), 1)
	var second metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &second); err != nil {
		t.Fatal(err)
	}
	if point := int64Point(t, second, "defenseclaw.scan.count"); point.Value != 1 {
		t.Fatalf("second delta=%d want=1", point.Value)
	}
}

func TestV8MetricCardinalityLimitIsEnforcedByTheReader(t *testing.T) {
	provider, reader, spec := activeV8MetricProvider(t, metricPlanForTest(t, observability.BucketAssetScan))
	for index := 0; index <= spec.CardinalityLimit; index++ {
		provider.metrics.scanCount.Add(
			context.Background(), 1,
			metric.WithAttributes(attribute.String("scanner", strconv.Itoa(index))),
		)
	}
	var collected metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &collected); err != nil {
		t.Fatal(err)
	}
	for _, scope := range collected.ScopeMetrics {
		for _, item := range scope.Metrics {
			if item.Name != "defenseclaw.scan.count" {
				continue
			}
			sum, ok := item.Data.(metricdata.Sum[int64])
			if !ok || len(sum.DataPoints) != spec.CardinalityLimit {
				t.Fatalf("cardinality data=%T points=%d want=%d", item.Data, len(sum.DataPoints), spec.CardinalityLimit)
			}
			for _, point := range sum.DataPoints {
				if overflow, found := point.Attributes.Value("otel.metric.overflow"); found && overflow.AsBool() {
					return
				}
			}
			t.Fatal("cardinality overflow stream was not collected")
		}
	}
	t.Fatal("scan count metric was not collected")
}

func TestV8MetricReadersAndProvidersAreGenerationOwnedAcrossReload(t *testing.T) {
	dir := t.TempDir()
	compile := func(bucket observability.Bucket) *config.ObservabilityV8Plan {
		no, yes := false, true
		source := &config.ObservabilityV8Source{
			Defaults: config.ObservabilityV8BucketPolicySource{
				Collect: config.ObservabilityV8CollectSource{Metrics: &no},
			},
			Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
				bucket: {Collect: config.ObservabilityV8CollectSource{Metrics: &yes}},
			},
			Local: config.ObservabilityV8LocalSource{
				Path: filepath.Join(dir, "audit.db"), JudgeBodiesPath: filepath.Join(dir, "judge.db"),
			},
		}
		plan, err := config.CompileObservabilityV8(source)
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	var mutex sync.Mutex
	readers := map[uint64]*sdkmetric.ManualReader{}
	factory := NewV8ProviderFactory(V8ProviderOptions{
		Version: "test", Environment: "test", ServiceInstanceID: "metric-reload",
		MetricReaderFactories: []V8MetricReaderFactory{func(generation uint64, spec V8MetricReaderSpec) (sdkmetric.Reader, error) {
			reader := sdkmetric.NewManualReader(sdkmetric.WithTemporalitySelector(func(sdkmetric.InstrumentKind) metricdata.Temporality {
				return spec.Temporality
			}))
			mutex.Lock()
			readers[generation] = reader
			mutex.Unlock()
			return reader, nil
		}},
	})
	firstPlan := compile(observability.BucketAssetScan)
	manager, err := runtimegraph.New(
		context.Background(), runtimegraph.ConfigFromPlan(firstPlan, false),
		[]runtimegraph.ComponentFactory{factory},
		runtimegraph.DefaultOptions(v8TestReporter{}),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close(context.Background()) })
	first, firstLease := providerFromGraph(t, manager)
	firstLease.Release()
	secondPlan := compile(observability.BucketAgentLifecycle)
	candidate := runtimegraph.ConfigFromPlan(secondPlan, false)
	result, reloadErr := manager.Reload(context.Background(), candidate)
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload=%s err=%v", result.Status(), reloadErr)
	}
	second, secondLease := providerFromGraph(t, manager)
	secondLease.Release()
	if first == second || first.MetricBucketEnabled(observability.BucketAssetScan) ||
		!second.MetricBucketEnabled(observability.BucketAgentLifecycle) ||
		second.MetricBucketEnabled(observability.BucketAssetScan) {
		t.Fatal("metric provider/collection generation leaked across reload")
	}
	mutex.Lock()
	defer mutex.Unlock()
	if len(readers) != 2 || readers[1] == readers[2] {
		t.Fatalf("generation readers=%v", readers)
	}
	if !first.shutdown.Load() {
		t.Fatal("retired graph did not invoke the registered provider shutdown acquisition")
	}
	if err := readers[1].Collect(context.Background(), &metricdata.ResourceMetrics{}); !errors.Is(err, sdkmetric.ErrReaderShutdown) {
		t.Fatalf("retired generation reader remained live: %v", err)
	}
}

type v8TestMetricExporter struct{ temporality metricdata.Temporality }

func (exporter v8TestMetricExporter) Temporality(sdkmetric.InstrumentKind) metricdata.Temporality {
	return exporter.temporality
}
func (v8TestMetricExporter) Aggregation(kind sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(kind)
}
func (v8TestMetricExporter) Export(context.Context, *metricdata.ResourceMetrics) error { return nil }
func (v8TestMetricExporter) ForceFlush(context.Context) error                          { return nil }
func (v8TestMetricExporter) Shutdown(context.Context) error                            { return nil }

func TestNewV8PeriodicMetricReaderRejectsTemporalityConflict(t *testing.T) {
	spec := V8MetricReaderSpec{
		ExportInterval: 60 * time.Second, ExportTimeout: 30 * time.Second,
		Temporality: metricdata.DeltaTemporality, CardinalityLimit: 2_048,
	}
	if _, err := NewV8PeriodicMetricReader(v8TestMetricExporter{temporality: metricdata.CumulativeTemporality}, spec); err == nil {
		t.Fatal("periodic reader accepted conflicting exporter temporality")
	}
	reader, err := NewV8PeriodicMetricReader(v8TestMetricExporter{temporality: metricdata.DeltaTemporality}, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func metricNames(resource metricdata.ResourceMetrics) []string {
	var names []string
	for _, scope := range resource.ScopeMetrics {
		for _, item := range scope.Metrics {
			names = append(names, item.Name)
		}
	}
	sort.Strings(names)
	return names
}

func containsMetric(names []string, name string) bool {
	index := sort.SearchStrings(names, name)
	return index < len(names) && names[index] == name
}

func int64Point(t *testing.T, resource metricdata.ResourceMetrics, name string) metricdata.DataPoint[int64] {
	t.Helper()
	for _, scope := range resource.ScopeMetrics {
		for _, item := range scope.Metrics {
			if item.Name != name {
				continue
			}
			sum, ok := item.Data.(metricdata.Sum[int64])
			if !ok || len(sum.DataPoints) != 1 {
				t.Fatalf("metric %s data=%T points=%d", name, item.Data, len(sum.DataPoints))
			}
			return sum.DataPoints[0]
		}
	}
	t.Fatalf("metric %s not found", name)
	return metricdata.DataPoint[int64]{}
}
