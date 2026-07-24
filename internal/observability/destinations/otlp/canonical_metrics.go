// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package otlp

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

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/exemplar"
	"go.opentelemetry.io/otel/sdk/resource"
)

const generatedMetricScope = "defenseclaw.telemetry"

// CanonicalMetricSinkOptions binds one private OTLP metric provider to one
// destination and graph generation.
type CanonicalMetricSinkOptions struct {
	Destination      string
	Generation       uint64
	Resource         *resource.Resource
	SelectedFamilies []observability.EventName
	CardinalityLimit int
}

// CanonicalMetricSink owns a private SDK MeterProvider, PeriodicReader, OTLP
// exporter, instrument cache, and transport for one destination generation.
type CanonicalMetricSink struct {
	destination string
	generation  uint64
	selected    map[string]struct{}
	provider    *sdkmetric.MeterProvider
	meter       metric.Meter
	timeout     time.Duration
	health      delivery.SnapshotSource

	mu              sync.RWMutex
	closed          bool
	shutdownStarted bool
	shutdownDone    chan struct{}
	shutdownErr     error
	instrumentMu    sync.Mutex
	instruments     map[string]*canonicalMetricInstrument
}

var _ delivery.SnapshotSource = (*CanonicalMetricSink)(nil)

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

// NewCanonicalMetricSink constructs an independent generated-record pipeline.
// It deliberately does not share the legacy reader's MeterProvider.
func (factory *Factory) NewCanonicalMetricSink(
	ctx context.Context,
	options CanonicalMetricSinkOptions,
) (*CanonicalMetricSink, error) {
	if factory == nil || ctx == nil || options.Generation == 0 || options.Resource == nil ||
		options.Destination != factory.config.Destination || options.CardinalityLimit != 2_048 ||
		len(options.SelectedFamilies) == 0 {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	selected := make(map[string]struct{}, len(options.SelectedFamilies))
	descriptors, descriptorErr := telemetry.V8MetricDescriptorCatalog()
	if descriptorErr != nil {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	known := make(map[string]telemetry.V8MetricDescriptor, len(descriptors))
	for _, descriptor := range descriptors {
		known[descriptor.Name] = descriptor
	}
	for _, family := range options.SelectedFamilies {
		name := string(family)
		descriptor, ok := known[name]
		if !ok || descriptor.CardinalityLimit != options.CardinalityLimit {
			return nil, newError(ErrorInvalidConfig, nil)
		}
		if _, duplicate := selected[name]; duplicate {
			return nil, newError(ErrorInvalidConfig, nil)
		}
		selected[name] = struct{}{}
	}
	reader, err := factory.NewPeriodicMetricReader(ctx)
	if err != nil {
		return nil, err
	}
	sdkReader := reader.SDKReader()
	if sdkReader == nil {
		cleanup, cancel := cleanupContext(ctx, factory.config.Timeout)
		_ = reader.Shutdown(cleanup)
		cancel()
		return nil, newError(ErrorInitialization, nil)
	}
	health, err := reader.DeliveryHealthSource(options.Generation)
	if err != nil {
		cleanup, cancel := cleanupContext(ctx, factory.config.Timeout)
		_ = reader.Shutdown(cleanup)
		cancel()
		return nil, err
	}
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(options.Resource),
		sdkmetric.WithReader(sdkReader),
		sdkmetric.WithCardinalityLimit(options.CardinalityLimit),
		// Offer only sampled trace context to the SDK exemplar reservoir. The
		// resulting trace/span IDs remain exemplar metadata and never become
		// metric attributes or Prometheus labels.
		sdkmetric.WithExemplarFilter(exemplar.TraceBasedFilter),
	)
	timeout := factory.config.Timeout + factory.config.Batch.ExportTimeout
	if timeout <= 0 || timeout > 10*time.Minute {
		timeout = 10 * time.Minute
	}
	return &CanonicalMetricSink{
		destination: options.Destination, generation: options.Generation,
		selected: selected, provider: provider,
		meter: provider.Meter(generatedMetricScope), timeout: timeout,
		health:       health,
		shutdownDone: make(chan struct{}), instruments: make(map[string]*canonicalMetricInstrument),
	}, nil
}

// DeliveryHealthSnapshot reports the exporter that belongs to this generated
// metric sink. The separate reader attached to the process-wide meter provider
// may remain idle, so it cannot represent canonical metric delivery.
func (sink *CanonicalMetricSink) DeliveryHealthSnapshot() delivery.HealthSnapshot {
	if sink == nil || sink.health == nil {
		return delivery.HealthSnapshot{State: delivery.HealthStopped}
	}
	return sink.health.DeliveryHealthSnapshot()
}

func (sink *CanonicalMetricSink) RecordMetric(ctx context.Context, projected telemetry.V8ProjectedMetric) error {
	if sink == nil || ctx == nil {
		return newError(ErrorExport, nil)
	}
	sink.mu.RLock()
	defer sink.mu.RUnlock()
	if sink.closed || projected.Destination() != sink.destination || projected.Generation() != sink.generation {
		return newError(ErrorExport, nil)
	}
	descriptor := projected.Descriptor()
	if _, selected := sink.selected[descriptor.Name]; !selected {
		return newError(ErrorExport, nil)
	}
	attributes, err := canonicalMetricAttributes(projected.Attributes())
	if err != nil {
		return newError(ErrorExport, nil)
	}
	instrument, err := sink.instrument(descriptor)
	if err != nil {
		return err
	}
	if err := instrument.record(ctx, projected.Value(), attributes); err != nil {
		return newError(ErrorExport, nil)
	}
	return nil
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
		instrument.intCounter, err = sink.meter.Int64Counter(descriptor.Name, metric.WithUnit(descriptor.Unit))
	case "counter/double":
		instrument.fltCounter, err = sink.meter.Float64Counter(descriptor.Name, metric.WithUnit(descriptor.Unit))
	case "updowncounter/int64":
		instrument.intUpDown, err = sink.meter.Int64UpDownCounter(descriptor.Name, metric.WithUnit(descriptor.Unit))
	case "updowncounter/double":
		instrument.fltUpDown, err = sink.meter.Float64UpDownCounter(descriptor.Name, metric.WithUnit(descriptor.Unit))
	case "histogram/int64":
		instrument.intHist, err = sink.meter.Int64Histogram(
			descriptor.Name, metric.WithUnit(descriptor.Unit),
			metric.WithExplicitBucketBoundaries(descriptor.Boundaries...),
		)
	case "histogram/double":
		instrument.fltHist, err = sink.meter.Float64Histogram(
			descriptor.Name, metric.WithUnit(descriptor.Unit),
			metric.WithExplicitBucketBoundaries(descriptor.Boundaries...),
		)
	case "gauge/int64":
		instrument.intGauge, err = sink.meter.Int64Gauge(descriptor.Name, metric.WithUnit(descriptor.Unit))
	case "gauge/double":
		instrument.fltGauge, err = sink.meter.Float64Gauge(descriptor.Name, metric.WithUnit(descriptor.Unit))
	default:
		return nil, newError(ErrorInvalidConfig, nil)
	}
	if err != nil {
		return nil, newError(ErrorInitialization, err)
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

func canonicalMetricAttributes(source map[string]any) (attribute.Set, error) {
	keys := make([]string, 0, len(source))
	for key := range source {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]attribute.KeyValue, 0, len(keys))
	for _, key := range keys {
		value := source[key]
		switch typed := value.(type) {
		case string:
			values = append(values, attribute.String(key, typed))
		case bool:
			values = append(values, attribute.Bool(key, typed))
		case json.Number:
			integer, err := strconv.ParseInt(string(typed), 10, 64)
			if err != nil {
				return attribute.Set{}, err
			}
			values = append(values, attribute.Int64(key, integer))
		case int64:
			values = append(values, attribute.Int64(key, typed))
		case float64:
			if math.IsNaN(typed) || math.IsInf(typed, 0) {
				return attribute.Set{}, errors.New("invalid metric label")
			}
			values = append(values, attribute.Float64(key, typed))
		default:
			return attribute.Set{}, errors.New("unsupported metric label")
		}
	}
	return attribute.NewSet(values...), nil
}

func (sink *CanonicalMetricSink) ForceFlush(ctx context.Context) error {
	if sink == nil || ctx == nil {
		return newError(ErrorFlush, nil)
	}
	sink.mu.RLock()
	defer sink.mu.RUnlock()
	if sink.closed {
		return newError(ErrorFlush, nil)
	}
	if err := sink.provider.ForceFlush(ctx); err != nil {
		return newError(ErrorFlush, err)
	}
	return nil
}

func (sink *CanonicalMetricSink) Shutdown(ctx context.Context) error {
	if sink == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorShutdown, nil)
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
		return newError(ErrorShutdown, ctx.Err())
	}
}

func (sink *CanonicalMetricSink) runShutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), sink.timeout)
	defer cancel()
	err := sink.provider.Shutdown(ctx)
	sink.mu.Lock()
	if err != nil {
		sink.shutdownErr = newError(ErrorShutdown, err)
	}
	close(sink.shutdownDone)
	sink.mu.Unlock()
}

var _ telemetry.V8CanonicalMetricSink = (*CanonicalMetricSink)(nil)
