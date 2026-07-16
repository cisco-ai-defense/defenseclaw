// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package prometheus

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	prom "github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/exemplar"
)

const generatedMetricScope = "defenseclaw.telemetry"

// CanonicalMetricSink owns one private generated-record MeterProvider and the
// native pull reader/listener for exactly one destination generation. Despite
// the generic sink interface name, native Prometheus deliberately accepts the
// generated local-observability-v1 projection so existing dashboard labels are
// preserved without maintaining a second handwritten alias table here.
type CanonicalMetricSink struct {
	destination string
	generation  uint64
	selected    map[string]telemetry.V8MetricDescriptor
	provider    *sdkmetric.MeterProvider
	meter       metric.Meter
	timeout     time.Duration

	mu              sync.RWMutex
	closed          bool
	shutdownStarted bool
	shutdownDone    chan struct{}
	shutdownErr     error
	detach          func()
	instrumentMu    sync.Mutex
	instruments     map[string]*canonicalMetricInstrument
}

type canonicalMetricInstrument struct {
	descriptor telemetry.V8MetricDescriptor
	intCounter metric.Int64Counter
	fltCounter metric.Float64Counter
	intUpDown  metric.Int64UpDownCounter
	fltUpDown  metric.Float64UpDownCounter
	intHist    metric.Int64Histogram
	fltHist    metric.Float64Histogram
	intGauge   metric.Int64Gauge
	fltGauge   metric.Float64Gauge
}

// NewCanonicalMetricSink materializes the native generated-record pipeline.
// Listener binding happens here, after collection gating and after the exact
// generation resource has been constructed by the provider.
func (factory *Factory) NewCanonicalMetricSink(
	ctx context.Context,
	generation uint64,
	spec telemetry.V8MetricReaderSpec,
	resource telemetry.V8ResourceContext,
) (*CanonicalMetricSink, error) {
	readerValue, err := factory.PrepareContext(ctx, generation, spec)
	if err != nil {
		return nil, err
	}
	reader, ok := readerValue.(*Reader)
	if !ok || reader == nil {
		if readerValue != nil {
			_ = readerValue.Shutdown(context.Background())
		}
		return nil, newError(ErrorExporterInit, nil)
	}
	sink, err := factory.newCanonicalMetricSink(
		ctx, generation, spec, resource, reader,
	)
	if err != nil {
		_ = reader.Shutdown(context.Background())
		return nil, err
	}
	return sink, nil
}

// newSiblingCanonicalMetricSink registers a second official exporter in the
// exact private registry served by reader. The reader remains attached to the
// graph's legacy SDK provider, while the sibling exporter is owned by the
// generated-record provider. This is the no-loss cutover bridge: one endpoint
// and one route filter expose both producer generations without globals.
func (factory *Factory) newSiblingCanonicalMetricSink(
	ctx context.Context,
	generation uint64,
	spec telemetry.V8MetricReaderSpec,
	resource telemetry.V8ResourceContext,
	reader *Reader,
) (*CanonicalMetricSink, error) {
	if reader == nil || reader.gatherers == nil || reader.destination != factory.destination ||
		reader.generation != generation {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	registry := prom.NewPedanticRegistry()
	exporter, err := newPrivateExporter(registry)
	if err != nil {
		return nil, newError(ErrorExporterInit, nil)
	}
	detach, err := reader.gatherers.add(registry)
	if err != nil {
		_ = exporter.Shutdown(context.Background())
		return nil, err
	}
	sink, err := factory.newCanonicalMetricSink(ctx, generation, spec, resource, exporter)
	if err != nil {
		detach()
		_ = exporter.Shutdown(context.Background())
		return nil, err
	}
	sink.detach = detach
	return sink, nil
}

func (factory *Factory) newCanonicalMetricSink(
	ctx context.Context,
	generation uint64,
	spec telemetry.V8MetricReaderSpec,
	resource telemetry.V8ResourceContext,
	reader sdkmetric.Reader,
) (*CanonicalMetricSink, error) {
	if factory == nil || ctx == nil || generation == 0 || reader == nil ||
		spec.CardinalityLimit != 2_048 || len(factory.selected) == 0 {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	descriptors, err := telemetry.V8MetricDescriptorCatalog()
	if err != nil {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	selected := make(map[string]telemetry.V8MetricDescriptor, len(factory.selected))
	for _, descriptor := range descriptors {
		if _, enabled := factory.selected[descriptor.Name]; !enabled {
			continue
		}
		if descriptor.CardinalityLimit != spec.CardinalityLimit {
			return nil, newError(ErrorInvalidConfig, nil)
		}
		selected[descriptor.Name] = descriptor
	}
	if len(selected) != len(factory.selected) {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	providerOptions := []sdkmetric.Option{
		sdkmetric.WithResource(resource.SDKResource()),
		sdkmetric.WithReader(reader),
		sdkmetric.WithCardinalityLimit(spec.CardinalityLimit),
		sdkmetric.WithExemplarFilter(exemplar.AlwaysOffFilter),
	}
	// A non-empty generated table overrides the SDK default exactly. An authored
	// empty list deliberately retains the SDK default aggregation used by the
	// legacy producer during cutover, allowing an overlap to merge without
	// inventing bucket placement that neither source reported.
	selectedNames := make([]string, 0, len(selected))
	for name := range selected {
		selectedNames = append(selectedNames, name)
	}
	sort.Strings(selectedNames)
	for _, name := range selectedNames {
		descriptor := selected[name]
		if descriptor.InstrumentType != "histogram" || len(descriptor.Boundaries) == 0 {
			continue
		}
		providerOptions = append(providerOptions, sdkmetric.WithView(sdkmetric.NewView(
			sdkmetric.Instrument{Name: descriptor.Name},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: append([]float64(nil), descriptor.Boundaries...),
				NoMinMax:   true,
			}},
		)))
	}
	provider := sdkmetric.NewMeterProvider(providerOptions...)
	timeout := 2 * factory.drainTimeout
	if timeout < time.Second || timeout > 10*time.Minute {
		timeout = 2 * defaultDrainTimeout
	}
	return &CanonicalMetricSink{
		destination: factory.destination, generation: generation,
		selected: selected, provider: provider,
		meter: provider.Meter(generatedMetricScope), timeout: timeout,
		shutdownDone: make(chan struct{}), instruments: make(map[string]*canonicalMetricInstrument),
	}, nil
}

// PreparePlanPipelines constructs one legacy SDK reader/listener and one
// generated sibling-exporter declaration per enabled native destination. The
// sibling is materialized only after the provider supplies the exact immutable
// generation resource. No second listener is ever created.
func PreparePlanPipelines(
	ctx context.Context,
	plan *config.ObservabilityV8Plan,
	generation uint64,
	spec telemetry.V8MetricReaderSpec,
	options Options,
) (telemetry.V8GenerationPipelines, error) {
	if ctx == nil || plan == nil || generation == 0 || spec.CardinalityLimit != 2_048 {
		return telemetry.V8GenerationPipelines{}, newError(ErrorInvalidConfig, nil)
	}
	if err := ctx.Err(); err != nil {
		return telemetry.V8GenerationPipelines{}, newError(ErrorInvalidConfig, err)
	}
	snapshot := plan.Snapshot()
	metricsCollected := false
	for _, bucket := range snapshot.Buckets {
		if bucket.Collect.Metrics {
			metricsCollected = true
			break
		}
	}
	if !metricsCollected {
		return telemetry.V8GenerationPipelines{}, nil
	}
	result := telemetry.V8GenerationPipelines{}
	fail := func(err error) (telemetry.V8GenerationPipelines, error) {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for index := len(result.MetricReaders) - 1; index >= 0; index-- {
			_ = result.MetricReaders[index].Shutdown(cleanupContext)
		}
		return telemetry.V8GenerationPipelines{}, err
	}
	for _, displayed := range snapshot.Destinations {
		if !displayed.Enabled || displayed.Kind != config.ObservabilityV8DestinationPrometheus {
			continue
		}
		destination, ok := plan.RuntimeDestination(displayed.Name)
		if !ok || destination.Name != displayed.Name || destination.Kind != displayed.Kind ||
			destination.Enabled != displayed.Enabled {
			return fail(newError(ErrorInvalidConfig, nil))
		}
		factory, err := NewFactory(destination, options)
		if err != nil {
			return fail(err)
		}
		readerValue, err := factory.PrepareContext(ctx, generation, spec)
		if err != nil {
			return fail(err)
		}
		reader, ok := readerValue.(*Reader)
		if !ok || reader == nil {
			if readerValue != nil {
				_ = readerValue.Shutdown(context.Background())
			}
			return fail(newError(ErrorExporterInit, nil))
		}
		result.MetricReaders = append(result.MetricReaders, reader)
		result.HealthSources = append(result.HealthSources, reader)
		families := factory.selectedFamilies()
		if len(families) == 0 {
			continue
		}
		result.MetricPipelines = append(result.MetricPipelines, telemetry.V8GenerationMetricPipeline{
			Destination:      destination.Name,
			Projection:       telemetry.V8MetricProjectionLocal,
			SelectedFamilies: append([]observability.EventName(nil), families...),
			SinkFactory: func(
				factory *Factory,
				reader *Reader,
			) telemetry.V8CanonicalMetricSinkFactory {
				return func(
					factoryContext context.Context,
					resource telemetry.V8ResourceContext,
				) (telemetry.V8CanonicalMetricSink, error) {
					return factory.newSiblingCanonicalMetricSink(
						factoryContext, generation, spec, resource, reader,
					)
				}
			}(factory, reader),
		})
	}
	if err := ctx.Err(); err != nil {
		return fail(newError(ErrorInvalidConfig, err))
	}
	return result, nil
}

func (factory *Factory) selectedFamilies() []observability.EventName {
	if factory == nil {
		return nil
	}
	result := make([]observability.EventName, 0, len(factory.selected))
	for name := range factory.selected {
		result = append(result, observability.EventName(name))
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}

func (sink *CanonicalMetricSink) RecordMetric(ctx context.Context, projected telemetry.V8ProjectedMetric) error {
	if sink == nil || ctx == nil {
		return newError(ErrorRecordFailed, nil)
	}
	sink.mu.RLock()
	defer sink.mu.RUnlock()
	if sink.closed || projected.Destination() != sink.destination || projected.Generation() != sink.generation ||
		projected.Profile() != observability.RuntimeLocalObservabilityProfile {
		return newError(ErrorRecordFailed, nil)
	}
	descriptor := projected.Descriptor()
	authority, selected := sink.selected[descriptor.Name]
	if !selected || !reflect.DeepEqual(descriptor, authority) {
		return newError(ErrorRecordFailed, nil)
	}
	attributes, err := prometheusMetricAttributes(authority, projected.Attributes())
	if err != nil {
		return newError(ErrorRecordFailed, nil)
	}
	instrument, err := sink.instrument(authority)
	if err != nil {
		return err
	}
	if err := instrument.record(ctx, projected.Value(), attributes); err != nil {
		return newError(ErrorRecordFailed, nil)
	}
	return nil
}

func prometheusMetricAttributes(
	descriptor telemetry.V8MetricDescriptor,
	source map[string]any,
) (attribute.Set, error) {
	aliases := make(map[string]string, len(descriptor.LocalLabelMapping))
	for _, mapping := range descriptor.LocalLabelMapping {
		aliases[mapping.Canonical] = mapping.Local
	}
	allowed := make(map[string]struct{}, len(descriptor.AllowedLabels))
	for _, canonical := range descriptor.AllowedLabels {
		projected := canonical
		if alias, exists := aliases[canonical]; exists {
			projected = alias
		}
		allowed[projected] = struct{}{}
	}
	keys := make([]string, 0, len(source))
	for key := range source {
		if _, ok := allowed[key]; !ok {
			return attribute.Set{}, errors.New("unknown generated metric label")
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]attribute.KeyValue, 0, len(keys))
	for _, key := range keys {
		switch value := source[key].(type) {
		case string:
			values = append(values, attribute.String(key, value))
		case bool:
			values = append(values, attribute.Bool(key, value))
		case json.Number:
			integer, err := strconv.ParseInt(string(value), 10, 64)
			if err != nil {
				return attribute.Set{}, err
			}
			values = append(values, attribute.Int64(key, integer))
		case int64:
			values = append(values, attribute.Int64(key, value))
		case float64:
			if math.IsNaN(value) || math.IsInf(value, 0) {
				return attribute.Set{}, errors.New("invalid generated metric label")
			}
			values = append(values, attribute.Float64(key, value))
		default:
			return attribute.Set{}, errors.New("unsupported generated metric label")
		}
	}
	return attribute.NewSet(values...), nil
}

func (sink *CanonicalMetricSink) instrument(
	descriptor telemetry.V8MetricDescriptor,
) (*canonicalMetricInstrument, error) {
	sink.instrumentMu.Lock()
	defer sink.instrumentMu.Unlock()
	if existing := sink.instruments[descriptor.Name]; existing != nil {
		if !reflect.DeepEqual(existing.descriptor, descriptor) {
			return nil, newError(ErrorInvalidConfig, nil)
		}
		return existing, nil
	}
	instrument := &canonicalMetricInstrument{descriptor: descriptor}
	var err error
	switch descriptor.InstrumentType + "/" + descriptor.ValueType {
	case "counter/int64":
		instrument.intCounter, err = sink.meter.Int64Counter(
			descriptor.Name, metric.WithUnit(descriptor.Unit), metric.WithDescription(descriptor.Description),
		)
	case "counter/double":
		instrument.fltCounter, err = sink.meter.Float64Counter(
			descriptor.Name, metric.WithUnit(descriptor.Unit), metric.WithDescription(descriptor.Description),
		)
	case "updowncounter/int64":
		instrument.intUpDown, err = sink.meter.Int64UpDownCounter(
			descriptor.Name, metric.WithUnit(descriptor.Unit), metric.WithDescription(descriptor.Description),
		)
	case "updowncounter/double":
		instrument.fltUpDown, err = sink.meter.Float64UpDownCounter(
			descriptor.Name, metric.WithUnit(descriptor.Unit), metric.WithDescription(descriptor.Description),
		)
	case "histogram/int64":
		instrument.intHist, err = sink.meter.Int64Histogram(
			descriptor.Name, metric.WithUnit(descriptor.Unit), metric.WithDescription(descriptor.Description),
			metric.WithExplicitBucketBoundaries(descriptor.Boundaries...),
		)
	case "histogram/double":
		instrument.fltHist, err = sink.meter.Float64Histogram(
			descriptor.Name, metric.WithUnit(descriptor.Unit), metric.WithDescription(descriptor.Description),
			metric.WithExplicitBucketBoundaries(descriptor.Boundaries...),
		)
	case "gauge/int64":
		instrument.intGauge, err = sink.meter.Int64Gauge(
			descriptor.Name, metric.WithUnit(descriptor.Unit), metric.WithDescription(descriptor.Description),
		)
	case "gauge/double":
		instrument.fltGauge, err = sink.meter.Float64Gauge(
			descriptor.Name, metric.WithUnit(descriptor.Unit), metric.WithDescription(descriptor.Description),
		)
	default:
		return nil, newError(ErrorInvalidConfig, nil)
	}
	if err != nil {
		return nil, newError(ErrorExporterInit, err)
	}
	sink.instruments[descriptor.Name] = instrument
	return instrument, nil
}

func (instrument *canonicalMetricInstrument) record(
	ctx context.Context,
	value telemetry.V8MetricNumber,
	attributes attribute.Set,
) error {
	options := metric.WithAttributeSet(attributes)
	switch instrument.descriptor.InstrumentType + "/" + instrument.descriptor.ValueType {
	case "counter/int64":
		actual, ok := value.Int64()
		if !ok {
			return errors.New("metric type mismatch")
		}
		instrument.intCounter.Add(ctx, actual, options)
	case "counter/double":
		actual, ok := value.Double()
		if !ok {
			return errors.New("metric type mismatch")
		}
		instrument.fltCounter.Add(ctx, actual, options)
	case "updowncounter/int64":
		actual, ok := value.Int64()
		if !ok {
			return errors.New("metric type mismatch")
		}
		instrument.intUpDown.Add(ctx, actual, options)
	case "updowncounter/double":
		actual, ok := value.Double()
		if !ok {
			return errors.New("metric type mismatch")
		}
		instrument.fltUpDown.Add(ctx, actual, options)
	case "histogram/int64":
		actual, ok := value.Int64()
		if !ok {
			return errors.New("metric type mismatch")
		}
		instrument.intHist.Record(ctx, actual, options)
	case "histogram/double":
		actual, ok := value.Double()
		if !ok {
			return errors.New("metric type mismatch")
		}
		instrument.fltHist.Record(ctx, actual, options)
	case "gauge/int64":
		actual, ok := value.Int64()
		if !ok {
			return errors.New("metric type mismatch")
		}
		instrument.intGauge.Record(ctx, actual, options)
	case "gauge/double":
		actual, ok := value.Double()
		if !ok {
			return errors.New("metric type mismatch")
		}
		instrument.fltGauge.Record(ctx, actual, options)
	default:
		return errors.New("metric type mismatch")
	}
	return nil
}

func (sink *CanonicalMetricSink) ForceFlush(ctx context.Context) error {
	if sink == nil || ctx == nil {
		return newError(ErrorFlushFailed, nil)
	}
	sink.mu.RLock()
	defer sink.mu.RUnlock()
	if sink.closed {
		return newError(ErrorFlushFailed, nil)
	}
	if err := sink.provider.ForceFlush(ctx); err != nil {
		return newError(ErrorFlushFailed, err)
	}
	return nil
}

// Shutdown starts one bounded provider/HTTP drain transaction. Later callers
// can retry waiting with independent contexts without repeating lifecycle side
// effects or abandoning the generation-owned listener.
func (sink *CanonicalMetricSink) Shutdown(ctx context.Context) error {
	if sink == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorShutdownFailed, nil)
	}
	sink.mu.Lock()
	if !sink.shutdownStarted {
		sink.closed = true
		sink.shutdownStarted = true
		go sink.runShutdown()
	}
	done := sink.shutdownDone
	sink.mu.Unlock()
	select {
	case <-done:
		sink.mu.RLock()
		err := sink.shutdownErr
		sink.mu.RUnlock()
		return err
	case <-ctx.Done():
		return newError(ErrorShutdownFailed, ctx.Err())
	}
}

func (sink *CanonicalMetricSink) runShutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), sink.timeout)
	defer cancel()
	err := sink.provider.Shutdown(ctx)
	if sink.detach != nil {
		sink.detach()
	}
	sink.mu.Lock()
	if err != nil {
		sink.shutdownErr = newError(ErrorShutdownFailed, err)
	}
	close(sink.shutdownDone)
	sink.mu.Unlock()
}

var _ telemetry.V8CanonicalMetricSink = (*CanonicalMetricSink)(nil)
