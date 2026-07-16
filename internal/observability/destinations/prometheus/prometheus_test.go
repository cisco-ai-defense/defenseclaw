// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package prometheus

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	prom "github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/protobuf/proto"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

func TestOfficialExporterNormalizationLabelsAndHistogramBuckets(t *testing.T) {
	t.Parallel()
	defaultGatherer := prom.DefaultGatherer
	factory := newTestFactory(t, allMetricsSource("metrics"), ephemeralListen, nil)
	reader, provider := activeReader(t, factory, deltaSpec())
	meter := provider.Meter("prometheus-contract")
	counter, err := meter.Int64Counter("defenseclaw.scan.count", metric.WithUnit("{scan}"))
	if err != nil {
		t.Fatal(err)
	}
	histogram, err := meter.Float64Histogram(
		"defenseclaw.scan.duration", metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries(1, 5, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	labels := metric.WithAttributes(attribute.String("scanner", "codeguard"))
	counter.Add(context.Background(), 2, labels)
	histogram.Record(context.Background(), 7, labels)

	status, body := scrape(t, reader)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%q", status, body)
	}
	for _, want := range []string{
		`defenseclaw_scan_count_total{scanner="codeguard"} 2`,
		`defenseclaw_scan_duration_milliseconds_bucket{scanner="codeguard",le="1"} 0`,
		`defenseclaw_scan_duration_milliseconds_bucket{scanner="codeguard",le="5"} 0`,
		`defenseclaw_scan_duration_milliseconds_bucket{scanner="codeguard",le="10"} 1`,
		`defenseclaw_scan_duration_milliseconds_bucket{scanner="codeguard",le="+Inf"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q\n%s", want, body)
		}
	}
	for _, forbidden := range []string{"otel_scope_name", "go_gc_", "process_cpu_", "target_info"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("private scrape contains %q", forbidden)
		}
	}
	if snapshot := reader.Health(); snapshot.State != delivery.HealthHealthy ||
		snapshot.Counters != (Counters{Scrapes: 1, Succeeded: 1}) {
		t.Fatalf("health=%+v", snapshot)
	}
	if prom.DefaultGatherer != defaultGatherer {
		t.Fatal("destination replaced the process-global Prometheus gatherer")
	}
}

func TestDeltaPolicyHasIndependentCumulativePrometheusView(t *testing.T) {
	t.Parallel()
	factory := newTestFactory(t, allMetricsSource("metrics"), ephemeralListen, nil)
	promReaderValue, err := factory.Prepare(1, deltaSpec())
	if err != nil {
		t.Fatal(err)
	}
	promReader := promReaderValue.(*Reader)
	deltaReader := sdkmetric.NewManualReader(sdkmetric.WithTemporalitySelector(func(sdkmetric.InstrumentKind) metricdata.Temporality {
		return metricdata.DeltaTemporality
	}))
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(promReader), sdkmetric.WithReader(deltaReader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	counter, err := provider.Meter("temporality").Int64Counter("defenseclaw.scan.count", metric.WithUnit("{scan}"))
	if err != nil {
		t.Fatal(err)
	}
	counter.Add(context.Background(), 2)
	if got := scrapeMetricValue(t, promReader, "defenseclaw_scan_count_total"); got != 2 {
		t.Fatalf("first Prometheus value=%v", got)
	}
	if got := collectInt64Sum(t, deltaReader, "defenseclaw.scan.count"); got != 2 {
		t.Fatalf("first delta value=%d", got)
	}
	counter.Add(context.Background(), 3)
	if got := collectInt64Sum(t, deltaReader, "defenseclaw.scan.count"); got != 3 {
		t.Fatalf("second delta value=%d", got)
	}
	if got := scrapeMetricValue(t, promReader, "defenseclaw_scan_count_total"); got != 5 {
		t.Fatalf("cumulative Prometheus value=%v", got)
	}
	if PrometheusTemporality() != metricdata.CumulativeTemporality {
		t.Fatalf("pull temporality=%v", PrometheusTemporality())
	}
}

func TestPrivateGathererRejectsUnknownDataWithoutMutatingOfficialFamilies(t *testing.T) {
	t.Parallel()
	factory := newTestFactory(t, allMetricsSource("metrics"), ephemeralListen, nil)
	registry := prom.NewPedanticRegistry()
	exporter, err := newPrivateExporter(registry)
	if err != nil {
		t.Fatal(err)
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	meter := provider.Meter("official-output")
	counter, err := meter.Int64Counter("defenseclaw.scan.count", metric.WithUnit("{scan}"))
	if err != nil {
		t.Fatal(err)
	}
	counter.Add(context.Background(), 1, metric.WithAttributes(attribute.String("scanner", "codeguard")))
	raw, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1 {
		t.Fatalf("raw families=%d", len(raw))
	}
	before := proto.Clone(raw[0])
	filtered := &filteredGatherer{source: staticGatherer{families: raw}, matcher: factory.matcher, labels: factory.labels}
	selected, err := filtered.Gather()
	if err != nil || len(selected) != 1 || selected[0] != raw[0] || !proto.Equal(before, selected[0]) {
		t.Fatalf("selected official family mutated/rebuilt: count=%d err=%v", len(selected), err)
	}

	unknown, err := meter.Int64Counter("unknown.metric")
	if err != nil {
		t.Fatal(err)
	}
	unknown.Add(context.Background(), 1)
	filtered.source = registry
	if _, err := filtered.Gather(); !IsError(err, ErrorUnknownFamily) || strings.Contains(err.Error(), "unknown.metric") {
		t.Fatalf("unknown family error=%v", err)
	}

	prefixRegistry := prom.NewPedanticRegistry()
	prefixExporter, err := newPrivateExporter(prefixRegistry)
	if err != nil {
		t.Fatal(err)
	}
	prefixProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(prefixExporter))
	t.Cleanup(func() { _ = prefixProvider.Shutdown(context.Background()) })
	prefixCounter, err := prefixProvider.Meter("prefix-confusion").Int64Counter("defenseclaw.scan.count.evil")
	if err != nil {
		t.Fatal(err)
	}
	prefixCounter.Add(context.Background(), 1)
	prefixFiltered := &filteredGatherer{source: prefixRegistry, matcher: factory.matcher, labels: factory.labels}
	if _, err := prefixFiltered.Gather(); !IsError(err, ErrorUnknownFamily) || strings.Contains(err.Error(), "evil") {
		t.Fatalf("catalog-prefix family error=%v", err)
	}

	labelRegistry := prom.NewPedanticRegistry()
	labelExporter, err := newPrivateExporter(labelRegistry)
	if err != nil {
		t.Fatal(err)
	}
	labelProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(labelExporter))
	t.Cleanup(func() { _ = labelProvider.Shutdown(context.Background()) })
	labelCounter, err := labelProvider.Meter("unknown-label").Int64Counter("defenseclaw.scan.count", metric.WithUnit("{scan}"))
	if err != nil {
		t.Fatal(err)
	}
	labelCounter.Add(context.Background(), 1, metric.WithAttributes(attribute.String("prompt", "must-not-export")))
	labelFiltered := &filteredGatherer{source: labelRegistry, matcher: factory.matcher, labels: factory.labels}
	if _, err := labelFiltered.Gather(); !IsError(err, ErrorUnknownLabel) || strings.Contains(err.Error(), "prompt") {
		t.Fatalf("unknown label error=%v", err)
	}
}

func TestCompiledRoutesUseFirstMatchAndEventSelectors(t *testing.T) {
	t.Parallel()
	metrics := []observability.Signal{observability.SignalMetrics}
	dropScanThenSend := prometheusSource("metrics")
	dropScanThenSend.Routes = []config.ObservabilityV8RouteSource{
		{Name: "drop-scan", Signals: metrics, Action: config.ObservabilityV8RouteDrop, Selector: &config.ObservabilityV8SelectorSource{Buckets: []observability.Bucket{observability.BucketAssetScan}}},
		{Name: "send-all", Signals: metrics, Action: config.ObservabilityV8RouteSend, Selector: &config.ObservabilityV8SelectorSource{Buckets: []observability.Bucket{"*"}}},
	}
	factory := newTestFactory(t, dropScanThenSend, ephemeralListen, nil)
	if containsString(factory.SelectedMetrics(), "defenseclaw.scan.count") ||
		!containsString(factory.SelectedMetrics(), "gen_ai.client.token.usage") {
		t.Fatalf("drop-first selection=%v", factory.SelectedMetrics())
	}

	sendThenDrop := prometheusSource("metrics")
	sendThenDrop.Routes = []config.ObservabilityV8RouteSource{
		{Name: "send-all", Signals: metrics, Action: config.ObservabilityV8RouteSend, Selector: &config.ObservabilityV8SelectorSource{Buckets: []observability.Bucket{"*"}}},
		{Name: "drop-scan", Signals: metrics, Action: config.ObservabilityV8RouteDrop, Selector: &config.ObservabilityV8SelectorSource{Buckets: []observability.Bucket{observability.BucketAssetScan}}},
	}
	if selected := newTestFactory(t, sendThenDrop, ephemeralListen, nil).SelectedMetrics(); !containsString(selected, "defenseclaw.scan.count") || len(selected) != len(telemetry.V8MetricCatalog()) {
		t.Fatalf("send-first count=%d", len(selected))
	}

	eventOnly := prometheusSource("metrics")
	eventOnly.Routes = []config.ObservabilityV8RouteSource{
		{Name: "one", Signals: metrics, Action: config.ObservabilityV8RouteSend, Selector: &config.ObservabilityV8SelectorSource{EventNames: []observability.EventName{"defenseclaw.scan.count"}}},
		{Name: "drop-rest", Signals: metrics, Action: config.ObservabilityV8RouteDrop, Selector: &config.ObservabilityV8SelectorSource{EventNames: []observability.EventName{"*"}}},
	}
	selected := newTestFactory(t, eventOnly, ephemeralListen, nil).SelectedMetrics()
	if !reflect.DeepEqual(selected, []string{"defenseclaw.scan.count"}) {
		t.Fatalf("event selection=%v", selected)
	}
	selected[0] = "mutated"
	if got := newTestFactory(t, eventOnly, ephemeralListen, nil).SelectedMetrics(); !reflect.DeepEqual(got, []string{"defenseclaw.scan.count"}) {
		t.Fatalf("selected snapshot aliased=%v", got)
	}
}

func TestMultipleDestinationsFilterIndependently(t *testing.T) {
	t.Parallel()
	asset := prometheusSource("asset")
	asset.Send = &config.ObservabilityV8SendSource{
		Signals: []observability.Signal{observability.SignalMetrics}, Buckets: []observability.Bucket{observability.BucketAssetScan},
	}
	model := prometheusSource("model")
	model.Send = &config.ObservabilityV8SendSource{
		Signals: []observability.Signal{observability.SignalMetrics}, Buckets: []observability.Bucket{observability.BucketModelIO},
	}
	assetFactory := newTestFactory(t, asset, ephemeralListen, nil)
	modelFactory := newTestFactory(t, model, ephemeralListen, nil)
	assetValue, err := assetFactory.Prepare(1, deltaSpec())
	if err != nil {
		t.Fatal(err)
	}
	modelValue, err := modelFactory.Prepare(1, deltaSpec())
	if err != nil {
		_ = assetValue.Shutdown(context.Background())
		t.Fatal(err)
	}
	assetReader, modelReader := assetValue.(*Reader), modelValue.(*Reader)
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(assetReader), sdkmetric.WithReader(modelReader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	meter := provider.Meter("multi-destination")
	scan, _ := meter.Int64Counter("defenseclaw.scan.count", metric.WithUnit("{scan}"))
	stream, _ := meter.Int64Counter("defenseclaw.stream.bytes_sent", metric.WithUnit("By"))
	scan.Add(context.Background(), 1)
	stream.Add(context.Background(), 2)
	_, assetBody := scrape(t, assetReader)
	_, modelBody := scrape(t, modelReader)
	if !strings.Contains(assetBody, "defenseclaw_scan_count_total") || strings.Contains(assetBody, "defenseclaw_stream_bytes_sent") {
		t.Fatalf("asset scrape=%s", assetBody)
	}
	if strings.Contains(modelBody, "defenseclaw_scan_count_total") || !strings.Contains(modelBody, "defenseclaw_stream_bytes_sent_total") {
		t.Fatalf("model scrape=%s", modelBody)
	}
}

func TestListenerPathConflictAndCleanup(t *testing.T) {
	address := freeAddress(t)
	source := prometheusSource("metrics")
	source.Listen = address
	firstFactory := newTestFactory(t, source, nil, nil)
	secondFactory := newTestFactory(t, source, nil, nil)
	firstValue, err := firstFactory.Prepare(1, deltaSpec())
	if err != nil {
		t.Fatal(err)
	}
	first := firstValue.(*Reader)
	if _, err := secondFactory.Prepare(2, deltaSpec()); !IsError(err, ErrorListenFailed) || strings.Contains(err.Error(), address) {
		t.Fatalf("listen conflict error=%v", err)
	}
	if err := first.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	secondValue, err := secondFactory.Prepare(2, deltaSpec())
	if err != nil {
		t.Fatalf("listener not released: %v", err)
	}
	second := secondValue.(*Reader)
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(second))
	counter, _ := provider.Meter("path").Int64Counter("defenseclaw.scan.count", metric.WithUnit("{scan}"))
	counter.Add(context.Background(), 1)
	client := testHTTPClient()
	base := "http://" + second.Addr().String()
	for requestPath, want := range map[string]int{"/metrics": http.StatusOK, "/metrics/": http.StatusNotFound, "/other": http.StatusNotFound} {
		response, requestErr := client.Get(base + requestPath)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != want {
			t.Errorf("path %q status=%d want=%d", requestPath, response.StatusCode, want)
		}
	}
	request, _ := http.NewRequest(http.MethodPost, base+"/metrics", nil)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed || response.Header.Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST status=%d allow=%q", response.StatusCode, response.Header.Get("Allow"))
	}
	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRejectedProviderCandidateReleasesListener(t *testing.T) {
	address := freeAddress(t)
	source := prometheusSource("metrics")
	source.Listen = address
	plan, destination := compilePrometheus(t, source, true)
	_, err := NewFactory(destination, Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = telemetry.NewProviderV8Inactive(context.Background(), plan, 1, telemetry.V8ProviderOptions{
		Version: "test", Environment: "test",
		GenerationPipelines: func(
			ctx context.Context,
			candidate *config.ObservabilityV8Plan,
			generation uint64,
			spec telemetry.V8MetricReaderSpec,
		) (telemetry.V8GenerationPipelines, error) {
			readers, prepareErr := PreparePlanReaders(ctx, candidate, generation, spec, Options{})
			if prepareErr != nil {
				return telemetry.V8GenerationPipelines{}, prepareErr
			}
			return telemetry.V8GenerationPipelines{MetricReaders: readers}, errors.New("candidate rejected")
		},
	})
	if err == nil {
		t.Fatal("candidate unexpectedly succeeded")
	}
	listener, listenErr := net.Listen("tcp", address)
	if listenErr != nil {
		t.Fatalf("rejected candidate leaked listener: %v", listenErr)
	}
	_ = listener.Close()
}

func TestGenerationDrainThenReprepareUsesNewListenPathAndRoutes(t *testing.T) {
	firstSource := prometheusSource("metrics")
	firstSource.Path = "/metrics-v1"
	firstPlan, _ := compilePrometheus(t, firstSource, true)
	firstReaders, err := PreparePlanReaders(context.Background(), firstPlan, 1, deltaSpec(), Options{Listen: ephemeralListen})
	if err != nil || len(firstReaders) != 1 {
		t.Fatalf("first readers=%d err=%v", len(firstReaders), err)
	}
	firstReader := firstReaders[0].(*Reader)
	firstProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(firstReader))
	firstCounter, _ := firstProvider.Meter("generation-one").Int64Counter("defenseclaw.scan.count", metric.WithUnit("{scan}"))
	firstCounter.Add(context.Background(), 1)
	if status, _ := scrape(t, firstReader); status != http.StatusOK {
		t.Fatalf("first generation status=%d", status)
	}
	oldAddress := firstReader.Addr().String()
	if err := firstProvider.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	secondSource := prometheusSource("metrics")
	secondSource.Path = "/metrics-v2"
	secondSource.Send = &config.ObservabilityV8SendSource{
		Signals: []observability.Signal{observability.SignalMetrics},
		Buckets: []observability.Bucket{observability.BucketModelIO},
	}
	secondPlan, secondDestination := compilePrometheus(t, secondSource, true)
	secondFactory, err := NewFactory(secondDestination, Options{Listen: ephemeralListen})
	if err != nil {
		t.Fatal(err)
	}
	secondReaders, err := PreparePlanReaders(context.Background(), secondPlan, 2, deltaSpec(), Options{Listen: ephemeralListen})
	if err != nil || len(secondReaders) != 1 {
		t.Fatalf("second readers=%d err=%v", len(secondReaders), err)
	}
	secondReader := secondReaders[0].(*Reader)
	secondProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(secondReader))
	t.Cleanup(func() { _ = secondProvider.Shutdown(context.Background()) })
	if secondReader.generation != 2 || secondReader.Path() != "/metrics-v2" ||
		containsString(secondFactory.SelectedMetrics(), "defenseclaw.scan.count") {
		t.Fatalf("second generation reader=%d path=%q selection=%v", secondReader.generation, secondReader.Path(), secondFactory.SelectedMetrics())
	}
	modelCounter, _ := secondProvider.Meter("generation-two").Int64Counter("defenseclaw.stream.bytes_sent", metric.WithUnit("By"))
	modelCounter.Add(context.Background(), 2)
	status, body := scrape(t, secondReader)
	if status != http.StatusOK || !strings.Contains(body, "defenseclaw_stream_bytes_sent_total") || strings.Contains(body, "defenseclaw_scan_count") {
		t.Fatalf("second scrape status=%d body=%s", status, body)
	}
	if _, err := testHTTPClient().Get("http://" + oldAddress + "/metrics-v1"); err == nil {
		t.Fatal("drained generation still accepted scrapes")
	}
}

func TestAmbientOTelEnvironmentCannotOverrideConfiguredEndpoint(t *testing.T) {
	address := freeAddress(t)
	t.Setenv("OTEL_EXPORTER_PROMETHEUS_HOST", "0.0.0.0")
	t.Setenv("OTEL_EXPORTER_PROMETHEUS_PORT", "1")
	t.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "1")
	t.Setenv("OTEL_METRIC_EXPORT_TIMEOUT", "1")
	source := prometheusSource("metrics")
	source.Listen = address
	source.Path = "/configured-metrics"
	factory := newTestFactory(t, source, nil, nil)
	value, err := factory.Prepare(42, deltaSpec())
	if err != nil {
		t.Fatal(err)
	}
	reader := value.(*Reader)
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	if reader.Addr().String() != address || reader.Path() != "/configured-metrics" {
		t.Fatalf("ambient environment changed endpoint: addr=%q path=%q", reader.Addr(), reader.Path())
	}
}

func TestNoCollectedMetricsDoesNotConstructReaderOrBind(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	listen := func(context.Context, string, string) (net.Listener, error) {
		calls.Add(1)
		return net.Listen("tcp", "127.0.0.1:0")
	}
	plan, destination := compilePrometheus(t, allMetricsSource("metrics"), false)
	factory, err := NewFactory(destination, Options{Listen: listen})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := telemetry.NewProviderV8Inactive(context.Background(), plan, 1, telemetry.V8ProviderOptions{
		Version: "test", Environment: "test",
		GenerationPipelines: func(
			ctx context.Context,
			candidate *config.ObservabilityV8Plan,
			generation uint64,
			spec telemetry.V8MetricReaderSpec,
		) (telemetry.V8GenerationPipelines, error) {
			readers, prepareErr := PreparePlanReaders(ctx, candidate, generation, spec, Options{Listen: listen})
			return telemetry.V8GenerationPipelines{MetricReaders: readers}, prepareErr
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatalf("listener calls=%d", calls.Load())
	}
	if len(factory.SelectedMetrics()) != len(telemetry.V8MetricCatalog()) {
		t.Fatal("factory route snapshot unexpectedly changed")
	}
	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestScrapeInFlightDrainsAndShutdownCanBeRetried(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	transitions := make(chan HealthTransition, 8)
	factory := newTestFactory(t, allMetricsSource("metrics"), ephemeralListen, ObserverFunc(func(transition HealthTransition) {
		transitions <- transition
	}))
	reader, provider := activeReader(t, factory, deltaSpec())
	meter := provider.Meter("drain")
	gauge, err := meter.Int64ObservableGauge("defenseclaw.runtime.goroutines")
	if err != nil {
		t.Fatal(err)
	}
	registration, err := meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		once.Do(func() { close(started) })
		<-release
		observer.ObserveInt64(gauge, 7)
		return nil
	}, gauge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registration.Unregister() })
	requestDone := make(chan error, 1)
	go func() {
		response, requestErr := testHTTPClient().Get("http://" + reader.Addr().String() + reader.Path())
		if requestErr == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			requestErr = response.Body.Close()
		}
		requestDone <- requestErr
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("scrape did not enter callback")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := reader.Shutdown(ctx); !IsError(err, ErrorShutdownFailed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timed shutdown error=%v", err)
	}
	if state := reader.Health().State; state != delivery.HealthDraining {
		t.Fatalf("health during drain=%s", state)
	}
	close(release)
	select {
	case err := <-requestDone:
		if err != nil {
			t.Fatalf("in-flight scrape failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight scrape did not finish")
	}
	if err := reader.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown retry=%v", err)
	}
	if state := reader.Health().State; state != delivery.HealthStopped {
		t.Fatalf("final health=%s", state)
	}
	if _, err := testHTTPClient().Get("http://" + reader.Addr().String() + reader.Path()); err == nil {
		t.Fatal("closed destination still accepted scrape")
	}
	close(transitions)
	var states []delivery.HealthState
	for transition := range transitions {
		if strings.Contains(fmt.Sprint(transition), reader.Addr().String()) {
			t.Fatal("health leaked listener")
		}
		states = append(states, transition.Current)
	}
	if !containsHealth(states, delivery.HealthDraining) || !containsHealth(states, delivery.HealthStopped) {
		t.Fatalf("health states=%v", states)
	}
}

func TestStuckScrapeIsForceClosedWithinInternalDeadline(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	factory := newTestFactory(t, allMetricsSource("metrics"), ephemeralListen, nil)
	factory.drainTimeout = 50 * time.Millisecond
	reader, provider := activeReader(t, factory, deltaSpec())
	gauge, err := provider.Meter("stuck-drain").Int64ObservableGauge("defenseclaw.runtime.goroutines")
	if err != nil {
		t.Fatal(err)
	}
	registration, err := provider.Meter("stuck-drain").RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		select {
		case <-started:
		default:
			close(started)
		}
		<-release
		observer.ObserveInt64(gauge, 1)
		return nil
	}, gauge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registration.Unregister() })
	go func() {
		response, requestErr := testHTTPClient().Get("http://" + reader.Addr().String() + reader.Path())
		if requestErr == nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("scrape did not enter stuck callback")
	}

	startedShutdown := time.Now()
	err = reader.Shutdown(context.Background())
	if !IsError(err, ErrorShutdownFailed) {
		t.Fatalf("forced shutdown error=%v", err)
	}
	if elapsed := time.Since(startedShutdown); elapsed > time.Second {
		t.Fatalf("forced shutdown exceeded bound: %s", elapsed)
	}
	if retryErr := reader.Shutdown(context.Background()); !IsError(retryErr, ErrorShutdownFailed) {
		t.Fatalf("terminal shutdown result changed on retry: %v", retryErr)
	}
	if state := reader.Health().State; state != delivery.HealthStopped {
		t.Fatalf("forced shutdown health=%s", state)
	}
	if listener, listenErr := net.Listen("tcp", reader.Addr().String()); listenErr != nil {
		t.Fatalf("forced shutdown did not release listener: %v", listenErr)
	} else {
		_ = listener.Close()
	}
	releaseOnce.Do(func() { close(release) })
}

func TestBlockingObserverCannotStallScrapeOrShutdown(t *testing.T) {
	observerStarted := make(chan struct{})
	releaseObserver := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(releaseObserver) }) })
	factory := newTestFactory(t, allMetricsSource("metrics"), ephemeralListen, ObserverFunc(func(transition HealthTransition) {
		if transition.Reason != HealthReasonScrapeFailed {
			return
		}
		select {
		case <-observerStarted:
		default:
			close(observerStarted)
		}
		<-releaseObserver
	}))
	factory.observer.timeout = 20 * time.Millisecond
	reader, provider := activeReader(t, factory, deltaSpec())
	counter, err := provider.Meter("blocked-observer").Int64Counter("defenseclaw.scan.count")
	if err != nil {
		t.Fatal(err)
	}
	counter.Add(context.Background(), 1, metric.WithAttributes(attribute.String("prompt", "not-exported")))
	startedScrape := time.Now()
	status, _ := scrape(t, reader)
	if status != http.StatusInternalServerError {
		t.Fatalf("unknown-label scrape status=%d", status)
	}
	if elapsed := time.Since(startedScrape); elapsed > time.Second {
		t.Fatalf("observer stalled scrape: %s", elapsed)
	}
	select {
	case <-observerStarted:
	default:
		t.Fatal("blocking observer was not invoked")
	}
	shutdownStarted := time.Now()
	if err := reader.Shutdown(context.Background()); err != nil {
		t.Fatalf("blocking observer shutdown=%v", err)
	}
	if elapsed := time.Since(shutdownStarted); elapsed > time.Second {
		t.Fatalf("observer stalled shutdown: %s", elapsed)
	}
	once.Do(func() { close(releaseObserver) })
}

func TestConfigRejectsUnsafeAndInvalidListenersWithoutBinding(t *testing.T) {
	t.Parallel()
	tests := []struct {
		listen string
		code   ErrorCode
	}{
		{"0.0.0.0:9464", ErrorUnsafeListen},
		{"192.168.1.20:9464", ErrorUnsafeListen},
		{"metrics.example.test:9464", ErrorUnsafeListen},
		{"127.0.0.1:0", ErrorInvalidConfig},
		{"127.0.0.1:not-port", ErrorInvalidConfig},
	}
	for _, test := range tests {
		source := prometheusSource("metrics")
		source.Listen = "127.0.0.1:9464"
		_, destination := compilePrometheus(t, source, true)
		destination.Transport.Listen = test.listen
		factory, err := NewFactory(destination, Options{})
		if factory != nil || !IsError(err, test.code) || strings.Contains(err.Error(), test.listen) {
			t.Errorf("listen=%q factory=%v error=%v", test.listen, factory != nil, err)
		}
	}
	if before, after := prom.DefaultGatherer, prom.DefaultGatherer; before != after {
		t.Fatal("default gatherer changed")
	}
	source := prometheusSource("metrics")
	factory := newTestFactory(t, source, func(context.Context, string, string) (net.Listener, error) {
		return net.Listen("tcp", "0.0.0.0:0")
	}, nil)
	if reader, err := factory.Prepare(1, deltaSpec()); reader != nil || !IsError(err, ErrorUnsafeListen) {
		t.Fatalf("unsafe bound listener reader=%T err=%v", reader, err)
	}
}

func allMetricsSource(name string) config.ObservabilityV8DestinationSource {
	return prometheusSource(name)
}

func prometheusSource(name string) config.ObservabilityV8DestinationSource {
	return config.ObservabilityV8DestinationSource{
		Name: name, Kind: config.ObservabilityV8DestinationPrometheus,
		Listen: "127.0.0.1:9464", Path: "/metrics",
	}
}

func newTestFactory(
	t *testing.T,
	source config.ObservabilityV8DestinationSource,
	listen ListenFunc,
	observer Observer,
) *Factory {
	t.Helper()
	_, destination := compilePrometheus(t, source, true)
	factory, err := NewFactory(destination, Options{Listen: listen, Observer: observer})
	if err != nil {
		t.Fatal(err)
	}
	return factory
}

func compilePrometheus(
	t *testing.T,
	destination config.ObservabilityV8DestinationSource,
	collectMetrics bool,
) (*config.ObservabilityV8Plan, config.ObservabilityV8EffectiveDestination) {
	t.Helper()
	source := &config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path: filepath.Join(t.TempDir(), "audit.db"), JudgeBodiesPath: filepath.Join(t.TempDir(), "judge.db"),
		},
		Destinations: []config.ObservabilityV8DestinationSource{destination},
	}
	if !collectMetrics {
		no := false
		source.Defaults.Collect.Metrics = &no
	}
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range plan.Snapshot().Destinations {
		if candidate.Name == destination.Name {
			return plan, candidate
		}
	}
	t.Fatalf("destination %q missing", destination.Name)
	return nil, config.ObservabilityV8EffectiveDestination{}
}

func deltaSpec() telemetry.V8MetricReaderSpec {
	return telemetry.V8MetricReaderSpec{
		ExportInterval: 60 * time.Second, ExportTimeout: 30 * time.Second,
		Temporality: metricdata.DeltaTemporality, CardinalityLimit: 2_048,
	}
}

func ephemeralListen(_ context.Context, network, _ string) (net.Listener, error) {
	return net.Listen(network, "127.0.0.1:0")
}

func activeReader(
	t *testing.T,
	factory *Factory,
	spec telemetry.V8MetricReaderSpec,
) (*Reader, *sdkmetric.MeterProvider) {
	t.Helper()
	value, err := factory.Prepare(1, spec)
	if err != nil {
		t.Fatal(err)
	}
	reader := value.(*Reader)
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return reader, provider
}

func scrape(t *testing.T, reader *Reader) (int, string) {
	t.Helper()
	response, err := testHTTPClient().Get("http://" + reader.Addr().String() + reader.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(body)
}

func testHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
}

func scrapeMetricValue(t *testing.T, reader *Reader, name string) float64 {
	t.Helper()
	status, body := scrape(t, reader)
	if status != http.StatusOK {
		t.Fatalf("scrape status=%d body=%q", status, body)
	}
	pattern := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `(?:\{[^}]*\})? ([0-9.eE+-]+)$`)
	match := pattern.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("metric %q missing in %s", name, body)
	}
	value, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func collectInt64Sum(t *testing.T, reader *sdkmetric.ManualReader, name string) int64 {
	t.Helper()
	var resource metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &resource); err != nil {
		t.Fatal(err)
	}
	for _, scope := range resource.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != name {
				continue
			}
			sum, ok := metric.Data.(metricdata.Sum[int64])
			if !ok || len(sum.DataPoints) != 1 {
				t.Fatalf("metric data=%T points=%d", metric.Data, len(sum.DataPoints))
			}
			return sum.DataPoints[0].Value
		}
	}
	t.Fatalf("metric %q missing", name)
	return 0
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func containsString(values []string, want string) bool {
	index := sort.SearchStrings(values, want)
	return index < len(values) && values[index] == want
}

func containsHealth(values []delivery.HealthState, want delivery.HealthState) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type staticGatherer struct {
	families []*dto.MetricFamily
	err      error
}

func (gatherer staticGatherer) Gather() ([]*dto.MetricFamily, error) {
	return gatherer.families, gatherer.err
}
