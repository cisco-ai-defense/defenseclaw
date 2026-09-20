// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	metricEmbedded "go.opentelemetry.io/otel/metric/embedded"
	metricNoop "go.opentelemetry.io/otel/metric/noop"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/compatibility/profilemanifest"
)

const (
	v8MetricMaxAttributes       = 32
	v8MetricMaxAttributeBytes   = 256
	v8MetricMaxSliceElements    = 16
	v8MetricCardinalityLimit    = 2_048
	v8MetricOverflowLabel       = "other"
	v8MetricInvalidUnicodeLabel = "invalid"
)

// V8MetricDefinition is the compatibility view used by route compilation.
// Its inventory is derived from the generated local-observability profile.
type V8MetricDefinition struct {
	Name   string
	Bucket observability.Bucket
}

// V8MetricLabelMapping is one generated canonical-to-local label projection.
type V8MetricLabelMapping struct {
	Canonical string
	Local     string
}

// V8MetricDescriptor is the complete generated contract for one canonical
// metric family. BoundariesNull distinguishes authored null from an authored
// empty boundary array; Boundaries is always detached from cached authority.
type V8MetricDescriptor struct {
	FamilyID          string
	Name              string
	Bucket            observability.Bucket
	InstrumentType    string
	ValueType         string
	Unit              string
	Description       string
	Temporality       string
	Boundaries        []float64
	BoundariesNull    bool
	CardinalityLimit  int
	AllowedLabels     []string
	LocalLabelMapping []V8MetricLabelMapping
}

var v8GeneratedMetricCatalog struct {
	once        sync.Once
	descriptors []V8MetricDescriptor
	byName      map[string]V8MetricDescriptor
	err         error
}

// V8MetricDescriptorCatalog returns a detached deterministic snapshot of all
// metric families from the generated local-observability-v1 manifest.
func V8MetricDescriptorCatalog() ([]V8MetricDescriptor, error) {
	v8GeneratedMetricCatalog.once.Do(loadV8GeneratedMetricCatalog)
	if v8GeneratedMetricCatalog.err != nil {
		return nil, v8GeneratedMetricCatalog.err
	}
	result := make([]V8MetricDescriptor, len(v8GeneratedMetricCatalog.descriptors))
	for index, descriptor := range v8GeneratedMetricCatalog.descriptors {
		result[index] = cloneV8MetricDescriptor(descriptor)
	}
	return result, nil
}

// V8MetricCatalog returns the compatibility routing view. Invalid generated
// authority fails closed as an empty catalog; provider construction uses the
// error-returning descriptor API and rejects the generation.
func V8MetricCatalog() []V8MetricDefinition {
	descriptors, err := V8MetricDescriptorCatalog()
	if err != nil {
		return nil
	}
	result := make([]V8MetricDefinition, len(descriptors))
	for index, descriptor := range descriptors {
		result[index] = V8MetricDefinition{Name: descriptor.Name, Bucket: descriptor.Bucket}
	}
	return result
}

func loadV8GeneratedMetricCatalog() {
	manifest, err := profilemanifest.Get(observability.RuntimeLocalObservabilityProfile)
	if err != nil {
		v8GeneratedMetricCatalog.err = errors.New("telemetry: generated metric authority unavailable")
		return
	}
	descriptors := make([]V8MetricDescriptor, 0, len(manifest.Families))
	byName := make(map[string]V8MetricDescriptor)
	for _, family := range manifest.Families {
		if family.Signal != observability.SignalMetrics {
			continue
		}
		projection := family.Projection
		descriptor := V8MetricDescriptor{
			FamilyID: family.FamilyID, Name: string(family.EventName), Bucket: family.Bucket,
			InstrumentType: projection.InstrumentType, ValueType: projection.ValueType,
			Unit: projection.Unit, Description: projection.Description, Temporality: projection.Temporality,
			Boundaries: cloneFloat64Slice(projection.Boundaries), BoundariesNull: projection.Boundaries == nil,
			CardinalityLimit: projection.CardinalityLimit,
		}
		allowed, ok := profilemanifest.FamilyAttributeKeys(
			observability.RuntimeLocalObservabilityProfile, family.Signal, family.EventName,
		)
		if !ok {
			v8GeneratedMetricCatalog.err = errors.New("telemetry: generated metric labels unavailable")
			return
		}
		descriptor.AllowedLabels = allowed
		for _, mapping := range projection.LabelProjection.Mappings {
			if len(mapping) != 2 {
				v8GeneratedMetricCatalog.err = errors.New("telemetry: invalid generated metric label projection")
				return
			}
			descriptor.LocalLabelMapping = append(descriptor.LocalLabelMapping, V8MetricLabelMapping{
				Canonical: mapping[0], Local: mapping[1],
			})
		}
		sort.Strings(descriptor.AllowedLabels)
		if err := validateV8MetricDescriptor(descriptor, projection.Mode, projection.LabelProjection.Profile); err != nil {
			v8GeneratedMetricCatalog.err = err
			return
		}
		if _, duplicate := byName[descriptor.Name]; duplicate {
			v8GeneratedMetricCatalog.err = errors.New("telemetry: duplicate generated metric family")
			return
		}
		byName[descriptor.Name] = descriptor
		descriptors = append(descriptors, descriptor)
	}
	sort.Slice(descriptors, func(left, right int) bool { return descriptors[left].Name < descriptors[right].Name })
	if len(descriptors) == 0 || len(descriptors) != len(byName) {
		v8GeneratedMetricCatalog.err = errors.New("telemetry: generated metric inventory is incomplete")
		return
	}
	v8GeneratedMetricCatalog.descriptors = descriptors
	v8GeneratedMetricCatalog.byName = byName
}

func validateV8MetricDescriptor(descriptor V8MetricDescriptor, mode, profile string) error {
	if descriptor.FamilyID == "" || descriptor.Name == "" || !observability.IsBucket(descriptor.Bucket) ||
		mode != "otel_sdk_metric_v1" || profile != observability.RuntimeLocalObservabilityProfile ||
		descriptor.CardinalityLimit != v8MetricCardinalityLimit {
		return errors.New("telemetry: invalid generated metric descriptor")
	}
	validKind := descriptor.InstrumentType == "counter" || descriptor.InstrumentType == "updowncounter" ||
		descriptor.InstrumentType == "histogram" || descriptor.InstrumentType == "gauge"
	validValue := descriptor.ValueType == "int64" || descriptor.ValueType == "double"
	validTemporality := descriptor.Temporality == "delta" || descriptor.Temporality == "unspecified"
	if !validKind || !validValue || !validTemporality || descriptor.Unit == "" || descriptor.Description == "" ||
		(descriptor.InstrumentType == "histogram") == descriptor.BoundariesNull {
		return errors.New("telemetry: invalid generated metric instrument contract")
	}
	canonical, local := make(map[string]struct{}), make(map[string]struct{})
	allowed := make(map[string]struct{}, len(descriptor.AllowedLabels))
	for _, label := range descriptor.AllowedLabels {
		if label == "" {
			return errors.New("telemetry: invalid generated canonical metric label")
		}
		if _, duplicate := allowed[label]; duplicate {
			return errors.New("telemetry: duplicate generated canonical metric label")
		}
		allowed[label] = struct{}{}
	}
	for _, mapping := range descriptor.LocalLabelMapping {
		if mapping.Canonical == "" || mapping.Local == "" {
			return errors.New("telemetry: invalid generated metric label projection")
		}
		if _, duplicate := canonical[mapping.Canonical]; duplicate {
			return errors.New("telemetry: duplicate generated canonical metric label")
		}
		if _, duplicate := local[mapping.Local]; duplicate {
			return errors.New("telemetry: duplicate generated local metric label")
		}
		if _, valid := allowed[mapping.Canonical]; !valid {
			return errors.New("telemetry: generated metric alias references an unknown canonical label")
		}
		canonical[mapping.Canonical], local[mapping.Local] = struct{}{}, struct{}{}
	}
	// A canonical label omitted from the compatibility mapping projects
	// unchanged. Validate the complete projected set so an alias cannot collide
	// with one of those unchanged labels.
	projected := make(map[string]struct{}, len(descriptor.AllowedLabels))
	aliases := make(map[string]string, len(descriptor.LocalLabelMapping))
	for _, mapping := range descriptor.LocalLabelMapping {
		aliases[mapping.Canonical] = mapping.Local
	}
	for _, label := range descriptor.AllowedLabels {
		projectedLabel := label
		if alias, exists := aliases[label]; exists {
			projectedLabel = alias
		}
		if _, duplicate := projected[projectedLabel]; duplicate {
			return errors.New("telemetry: duplicate generated projected metric label")
		}
		projected[projectedLabel] = struct{}{}
	}
	return nil
}

func cloneV8MetricDescriptor(source V8MetricDescriptor) V8MetricDescriptor {
	result := source
	result.Boundaries = cloneFloat64Slice(source.Boundaries)
	result.AllowedLabels = append([]string(nil), source.AllowedLabels...)
	result.LocalLabelMapping = append([]V8MetricLabelMapping(nil), source.LocalLabelMapping...)
	return result
}

func cloneFloat64Slice(source []float64) []float64 {
	if source == nil {
		return nil
	}
	return append(make([]float64, 0, len(source)), source...)
}

func v8MetricDescriptorByName(name string) (V8MetricDescriptor, bool) {
	v8GeneratedMetricCatalog.once.Do(loadV8GeneratedMetricCatalog)
	if v8GeneratedMetricCatalog.err != nil {
		return V8MetricDescriptor{}, false
	}
	descriptor, ok := v8GeneratedMetricCatalog.byName[name]
	return cloneV8MetricDescriptor(descriptor), ok
}

// The legacy SDK path is retained until producer cutover, but its global
// compatibility vocabulary is derived from the generated canonical and local
// projections instead of another handwritten label list.
var v8MetricAllowedAttributeKeys = generatedV8MetricAttributeKeys()

func generatedV8MetricAttributeKeys() map[attribute.Key]struct{} {
	result := make(map[attribute.Key]struct{})
	descriptors, err := V8MetricDescriptorCatalog()
	if err != nil {
		return result
	}
	for _, descriptor := range descriptors {
		for _, label := range descriptor.AllowedLabels {
			result[attribute.Key(label)] = struct{}{}
		}
		for _, mapping := range descriptor.LocalLabelMapping {
			result[attribute.Key(mapping.Local)] = struct{}{}
		}
	}
	return result
}

// V8MetricAllowedAttributeKeys returns the deterministic compatibility label
// vocabulary used by the metric construction boundary. Destination adapters
// use this detached snapshot to fail closed without maintaining a second label
// catalog.
func V8MetricAllowedAttributeKeys() []string {
	result := make([]string, 0, len(v8MetricAllowedAttributeKeys))
	for key := range v8MetricAllowedAttributeKeys {
		result = append(result, string(key))
	}
	sort.Strings(result)
	return result
}

// v8MetricMeter is the temporary SDK compatibility adapter used while legacy
// producer methods are cut over. The generated descriptor catalog above owns
// the contract; parity tests require metricsSet registration to match it.
// Enabled bucket instruments reach the graph-owned SDK Meter; disabled bucket
// fields receive no-op handles and never register an SDK instrument.
type v8MetricMeter struct {
	metricEmbedded.Meter
	real           metric.Meter
	noop           metric.Meter
	enabled        map[observability.Bucket]bool
	selectedBucket observability.Bucket
}

func newV8MetricMeter(real metric.Meter, enabled map[observability.Bucket]bool) *v8MetricMeter {
	return &v8MetricMeter{
		real: real, noop: metricNoop.NewMeterProvider().Meter("defenseclaw"), enabled: enabled,
	}
}

func (meter *v8MetricMeter) forBucket(bucket observability.Bucket) *v8MetricMeter {
	return &v8MetricMeter{
		real: meter.real, noop: meter.noop, enabled: meter.enabled, selectedBucket: bucket,
	}
}

func (meter *v8MetricMeter) selected(name string) (bool, error) {
	descriptor, ok := v8MetricDescriptorByName(name)
	if !ok {
		return false, errors.New("telemetry: metric is absent from the v8 catalog")
	}
	bucket := descriptor.Bucket
	if meter.selectedBucket != "" && bucket != meter.selectedBucket {
		return false, errors.New("telemetry: metric belongs to a different v8 bucket")
	}
	return meter.enabled[bucket], nil
}

func (meter *v8MetricMeter) Int64Counter(name string, options ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	selected, err := meter.selected(name)
	if err != nil {
		return nil, err
	}
	if !selected {
		return meter.noop.Int64Counter(name, options...)
	}
	instrument, err := meter.real.Int64Counter(name, options...)
	return v8Int64Counter{Int64Counter: instrument}, err
}

func (meter *v8MetricMeter) Int64UpDownCounter(name string, options ...metric.Int64UpDownCounterOption) (metric.Int64UpDownCounter, error) {
	selected, err := meter.selected(name)
	if err != nil {
		return nil, err
	}
	if !selected {
		return meter.noop.Int64UpDownCounter(name, options...)
	}
	instrument, err := meter.real.Int64UpDownCounter(name, options...)
	return v8Int64UpDownCounter{Int64UpDownCounter: instrument}, err
}

func (meter *v8MetricMeter) Int64Histogram(name string, options ...metric.Int64HistogramOption) (metric.Int64Histogram, error) {
	selected, err := meter.selected(name)
	if err != nil {
		return nil, err
	}
	if !selected {
		return meter.noop.Int64Histogram(name, options...)
	}
	instrument, err := meter.real.Int64Histogram(name, options...)
	return v8Int64Histogram{Int64Histogram: instrument}, err
}

func (meter *v8MetricMeter) Int64Gauge(name string, options ...metric.Int64GaugeOption) (metric.Int64Gauge, error) {
	selected, err := meter.selected(name)
	if err != nil {
		return nil, err
	}
	if !selected {
		return meter.noop.Int64Gauge(name, options...)
	}
	instrument, err := meter.real.Int64Gauge(name, options...)
	return v8Int64Gauge{Int64Gauge: instrument}, err
}

func (meter *v8MetricMeter) Float64Histogram(name string, options ...metric.Float64HistogramOption) (metric.Float64Histogram, error) {
	selected, err := meter.selected(name)
	if err != nil {
		return nil, err
	}
	if !selected {
		return meter.noop.Float64Histogram(name, options...)
	}
	instrument, err := meter.real.Float64Histogram(name, options...)
	return v8Float64Histogram{Float64Histogram: instrument}, err
}

func (meter *v8MetricMeter) Float64Gauge(name string, options ...metric.Float64GaugeOption) (metric.Float64Gauge, error) {
	selected, err := meter.selected(name)
	if err != nil {
		return nil, err
	}
	if !selected {
		return meter.noop.Float64Gauge(name, options...)
	}
	instrument, err := meter.real.Float64Gauge(name, options...)
	return v8Float64Gauge{Float64Gauge: instrument}, err
}

func (meter *v8MetricMeter) Float64Counter(name string, options ...metric.Float64CounterOption) (metric.Float64Counter, error) {
	selected, err := meter.selected(name)
	if err != nil {
		return nil, err
	}
	if !selected {
		return meter.noop.Float64Counter(name, options...)
	}
	instrument, err := meter.real.Float64Counter(name, options...)
	return v8Float64Counter{Float64Counter: instrument}, err
}

func (meter *v8MetricMeter) Float64UpDownCounter(name string, options ...metric.Float64UpDownCounterOption) (metric.Float64UpDownCounter, error) {
	selected, err := meter.selected(name)
	if err != nil {
		return nil, err
	}
	if !selected {
		return meter.noop.Float64UpDownCounter(name, options...)
	}
	instrument, err := meter.real.Float64UpDownCounter(name, options...)
	return v8Float64UpDownCounter{Float64UpDownCounter: instrument}, err
}

func (*v8MetricMeter) Int64ObservableCounter(string, ...metric.Int64ObservableCounterOption) (metric.Int64ObservableCounter, error) {
	return nil, errors.New("telemetry: observable metrics are absent from the v8 catalog")
}

func (*v8MetricMeter) Int64ObservableUpDownCounter(string, ...metric.Int64ObservableUpDownCounterOption) (metric.Int64ObservableUpDownCounter, error) {
	return nil, errors.New("telemetry: observable metrics are absent from the v8 catalog")
}

func (*v8MetricMeter) Int64ObservableGauge(string, ...metric.Int64ObservableGaugeOption) (metric.Int64ObservableGauge, error) {
	return nil, errors.New("telemetry: observable metrics are absent from the v8 catalog")
}

func (*v8MetricMeter) Float64ObservableCounter(string, ...metric.Float64ObservableCounterOption) (metric.Float64ObservableCounter, error) {
	return nil, errors.New("telemetry: observable metrics are absent from the v8 catalog")
}

func (*v8MetricMeter) Float64ObservableUpDownCounter(string, ...metric.Float64ObservableUpDownCounterOption) (metric.Float64ObservableUpDownCounter, error) {
	return nil, errors.New("telemetry: observable metrics are absent from the v8 catalog")
}

func (*v8MetricMeter) Float64ObservableGauge(string, ...metric.Float64ObservableGaugeOption) (metric.Float64ObservableGauge, error) {
	return nil, errors.New("telemetry: observable metrics are absent from the v8 catalog")
}

func (*v8MetricMeter) RegisterCallback(metric.Callback, ...metric.Observable) (metric.Registration, error) {
	return nil, errors.New("telemetry: observable metrics are absent from the v8 catalog")
}

type v8Int64Counter struct{ metric.Int64Counter }

func (instrument v8Int64Counter) Add(ctx context.Context, value int64, options ...metric.AddOption) {
	instrument.Int64Counter.Add(ctx, value, metric.WithAttributeSet(v8BoundMetricAttributes(metric.NewAddConfig(options).Attributes())))
}

type v8Int64UpDownCounter struct{ metric.Int64UpDownCounter }

func (instrument v8Int64UpDownCounter) Add(ctx context.Context, value int64, options ...metric.AddOption) {
	instrument.Int64UpDownCounter.Add(ctx, value, metric.WithAttributeSet(v8BoundMetricAttributes(metric.NewAddConfig(options).Attributes())))
}

type v8Int64Histogram struct{ metric.Int64Histogram }

func (instrument v8Int64Histogram) Record(ctx context.Context, value int64, options ...metric.RecordOption) {
	instrument.Int64Histogram.Record(ctx, value, metric.WithAttributeSet(v8BoundMetricAttributes(metric.NewRecordConfig(options).Attributes())))
}

type v8Int64Gauge struct{ metric.Int64Gauge }

func (instrument v8Int64Gauge) Record(ctx context.Context, value int64, options ...metric.RecordOption) {
	instrument.Int64Gauge.Record(ctx, value, metric.WithAttributeSet(v8BoundMetricAttributes(metric.NewRecordConfig(options).Attributes())))
}

type v8Float64Histogram struct{ metric.Float64Histogram }

func (instrument v8Float64Histogram) Record(ctx context.Context, value float64, options ...metric.RecordOption) {
	instrument.Float64Histogram.Record(ctx, value, metric.WithAttributeSet(v8BoundMetricAttributes(metric.NewRecordConfig(options).Attributes())))
}

type v8Float64Gauge struct{ metric.Float64Gauge }

func (instrument v8Float64Gauge) Record(ctx context.Context, value float64, options ...metric.RecordOption) {
	instrument.Float64Gauge.Record(ctx, value, metric.WithAttributeSet(v8BoundMetricAttributes(metric.NewRecordConfig(options).Attributes())))
}

type v8Float64Counter struct{ metric.Float64Counter }

func (instrument v8Float64Counter) Add(ctx context.Context, value float64, options ...metric.AddOption) {
	instrument.Float64Counter.Add(ctx, value, metric.WithAttributeSet(v8BoundMetricAttributes(metric.NewAddConfig(options).Attributes())))
}

type v8Float64UpDownCounter struct{ metric.Float64UpDownCounter }

func (instrument v8Float64UpDownCounter) Add(ctx context.Context, value float64, options ...metric.AddOption) {
	instrument.Float64UpDownCounter.Add(ctx, value, metric.WithAttributeSet(v8BoundMetricAttributes(metric.NewAddConfig(options).Attributes())))
}

func v8BoundMetricAttributes(source attribute.Set) attribute.Set {
	values := make([]attribute.KeyValue, 0, min(source.Len(), v8MetricMaxAttributes))
	iterator := source.Iter()
	for iterator.Next() && len(values) < v8MetricMaxAttributes {
		item := iterator.Attribute()
		if _, allowed := v8MetricAllowedAttributeKeys[item.Key]; !allowed {
			continue
		}
		values = append(values, v8BoundMetricAttribute(item))
	}
	return attribute.NewSet(values...)
}

func v8BoundMetricAttribute(item attribute.KeyValue) attribute.KeyValue {
	key := string(item.Key)
	switch item.Value.Type() {
	case attribute.STRING:
		return attribute.String(key, v8BoundMetricLabel(item.Value.AsString()))
	case attribute.STRINGSLICE:
		source := item.Value.AsStringSlice()
		if len(source) > v8MetricMaxSliceElements {
			source = source[:v8MetricMaxSliceElements]
		}
		bounded := make([]string, len(source))
		for index, value := range source {
			bounded[index] = v8BoundMetricLabel(value)
		}
		return attribute.StringSlice(key, bounded)
	case attribute.BOOLSLICE:
		values := item.Value.AsBoolSlice()
		if len(values) > v8MetricMaxSliceElements {
			values = values[:v8MetricMaxSliceElements]
		}
		return attribute.BoolSlice(key, append([]bool(nil), values...))
	case attribute.INT64SLICE:
		values := item.Value.AsInt64Slice()
		if len(values) > v8MetricMaxSliceElements {
			values = values[:v8MetricMaxSliceElements]
		}
		return attribute.Int64Slice(key, append([]int64(nil), values...))
	case attribute.FLOAT64SLICE:
		values := item.Value.AsFloat64Slice()
		if len(values) > v8MetricMaxSliceElements {
			values = values[:v8MetricMaxSliceElements]
		}
		return attribute.Float64Slice(key, append([]float64(nil), values...))
	case attribute.BOOL:
		return attribute.Bool(key, item.Value.AsBool())
	case attribute.INT64:
		return attribute.Int64(key, item.Value.AsInt64())
	case attribute.FLOAT64:
		return attribute.Float64(key, item.Value.AsFloat64())
	default:
		return attribute.String(key, v8MetricInvalidUnicodeLabel)
	}
}

func v8BoundMetricLabel(value string) string {
	if !utf8.ValidString(value) {
		return v8MetricInvalidUnicodeLabel
	}
	if len(value) > v8MetricMaxAttributeBytes {
		return v8MetricOverflowLabel
	}
	return strings.Clone(value)
}

var _ metric.Meter = (*v8MetricMeter)(nil)
var _ metric.Int64Counter = v8Int64Counter{}
var _ metric.Int64UpDownCounter = v8Int64UpDownCounter{}
var _ metric.Int64Histogram = v8Int64Histogram{}
var _ metric.Int64Gauge = v8Int64Gauge{}
var _ metric.Float64Histogram = v8Float64Histogram{}
var _ metric.Float64Gauge = v8Float64Gauge{}
var _ metric.Float64Counter = v8Float64Counter{}
var _ metric.Float64UpDownCounter = v8Float64UpDownCounter{}
