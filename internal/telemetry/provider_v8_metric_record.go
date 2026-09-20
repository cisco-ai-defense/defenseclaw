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
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// V8MetricProjection selects one generated destination label contract. The
// canonical arm retains registry label names. The local arm emits only the
// exact generated local-observability-v1 aliases for that family.
type V8MetricProjection string

const (
	V8MetricProjectionCanonical V8MetricProjection = "canonical"
	V8MetricProjectionLocal     V8MetricProjection = "local-observability-v1"
)

// V8CanonicalMetricSink is the generation-owned destination boundary. A sink
// receives an immutable projection and is retired with its graph generation.
// Implementations must not retain caller-owned mutable state.
type V8CanonicalMetricSink interface {
	RecordMetric(context.Context, V8ProjectedMetric) error
	ForceFlush(context.Context) error
	Shutdown(context.Context) error
}

// V8CanonicalMetricSinkFactory materializes a destination-private sink only
// after the provider has built the exact immutable generation resource.
type V8CanonicalMetricSinkFactory func(context.Context, V8ResourceContext) (V8CanonicalMetricSink, error)

// V8GenerationMetricPipeline binds one unique destination to one projection
// and an exact generated-family selection. SelectedFamilies is copied during
// provider construction and duplicate entries fail the candidate generation.
type V8GenerationMetricPipeline struct {
	Destination      string
	Projection       V8MetricProjection
	SelectedFamilies []observability.EventName
	Sink             V8CanonicalMetricSink
	SinkFactory      V8CanonicalMetricSinkFactory
}

// V8MetricNumber is the closed int64/double metric value union.
type V8MetricNumber struct {
	valueType string
	int64     int64
	double    float64
}

func (value V8MetricNumber) ValueType() string { return value.valueType }
func (value V8MetricNumber) Int64() (int64, bool) {
	return value.int64, value.valueType == "int64"
}
func (value V8MetricNumber) Double() (float64, bool) {
	return value.double, value.valueType == "double"
}

// V8ProjectedMetric is immutable. Accessors return immutable records, scalar
// values, or detached descriptor/attribute snapshots.
type V8ProjectedMetric struct {
	destination string
	profile     string
	generation  uint64
	digest      string
	descriptor  V8MetricDescriptor
	value       V8MetricNumber
	attributes  observability.Value
	record      observability.Record
}

func (metric V8ProjectedMetric) Destination() string { return strings.Clone(metric.destination) }
func (metric V8ProjectedMetric) Profile() string     { return strings.Clone(metric.profile) }
func (metric V8ProjectedMetric) Generation() uint64  { return metric.generation }
func (metric V8ProjectedMetric) ConfigDigest() string {
	return strings.Clone(metric.digest)
}
func (metric V8ProjectedMetric) Descriptor() V8MetricDescriptor {
	return cloneV8MetricDescriptor(metric.descriptor)
}
func (metric V8ProjectedMetric) Value() V8MetricNumber { return metric.value }
func (metric V8ProjectedMetric) CanonicalRecord() observability.Record {
	return metric.record
}
func (metric V8ProjectedMetric) Attributes() map[string]any {
	result, err := metric.attributes.Object()
	if err != nil {
		return nil
	}
	return result
}

// V8MetricRecordResult contains only bounded delivery counts. A matched route
// is counted once per unique destination; one destination can never receive a
// record twice from one recorder call.
type V8MetricRecordResult struct {
	Matched    int
	Delivered  int
	Failed     int
	Suppressed int
}

type v8MetricPipeline struct {
	destination string
	projection  V8MetricProjection
	selected    map[string]struct{}
	sink        V8CanonicalMetricSink
}

type v8MetricRecorder struct {
	generation uint64
	digest     string
	enabled    map[observability.Bucket]bool
	pipelines  []v8MetricPipeline
	active     atomic.Bool
	shutdown   atomic.Bool
}

func validateV8MetricPipelineDeclarations(pipelines []V8GenerationMetricPipeline) error {
	destinations := make(map[string]struct{}, len(pipelines))
	for _, pipeline := range pipelines {
		hasSink := !nilV8MetricSink(pipeline.Sink)
		hasFactory := pipeline.SinkFactory != nil
		if !observability.IsStableToken(pipeline.Destination) || hasSink == hasFactory ||
			(pipeline.Projection != V8MetricProjectionCanonical && pipeline.Projection != V8MetricProjectionLocal) ||
			len(pipeline.SelectedFamilies) == 0 {
			return errors.New("telemetry: invalid generated metric pipeline declaration")
		}
		if _, duplicate := destinations[pipeline.Destination]; duplicate {
			return errors.New("telemetry: duplicate generated metric destination")
		}
		destinations[pipeline.Destination] = struct{}{}
		families := make(map[observability.EventName]struct{}, len(pipeline.SelectedFamilies))
		for _, family := range pipeline.SelectedFamilies {
			if _, known := v8MetricDescriptorByName(string(family)); !known {
				return errors.New("telemetry: generated metric pipeline selects an unknown family")
			}
			if _, duplicate := families[family]; duplicate {
				return errors.New("telemetry: generated metric pipeline repeats a family")
			}
			families[family] = struct{}{}
		}
	}
	return nil
}

func materializeV8MetricPipelines(
	ctx context.Context,
	resource V8ResourceContext,
	pipelines []V8GenerationMetricPipeline,
) ([]V8GenerationMetricPipeline, error) {
	result := make([]V8GenerationMetricPipeline, len(pipelines))
	for index, source := range pipelines {
		result[index] = source
		result[index].SelectedFamilies = append([]observability.EventName(nil), source.SelectedFamilies...)
		if !nilV8MetricSink(source.Sink) {
			result[index].SinkFactory = nil
			continue
		}
		sink, err := callV8MetricSinkFactory(ctx, source.SinkFactory, resource.clone())
		if err != nil || nilV8MetricSink(sink) {
			return result, errors.New("telemetry: generated metric sink initialization failed")
		}
		result[index].Sink = sink
		result[index].SinkFactory = nil
	}
	return result, nil
}

func callV8MetricSinkFactory(
	ctx context.Context,
	factory V8CanonicalMetricSinkFactory,
	resource V8ResourceContext,
) (sink V8CanonicalMetricSink, err error) {
	defer func() {
		if recover() != nil {
			sink = nil
			err = errors.New("telemetry: generated metric sink factory panicked")
		}
	}()
	return factory(ctx, resource)
}

func newV8MetricRecorder(
	generation uint64,
	digest string,
	enabled map[observability.Bucket]bool,
	pipelines []V8GenerationMetricPipeline,
) (*v8MetricRecorder, error) {
	if generation == 0 || digest == "" {
		return nil, errors.New("telemetry: invalid generated metric recorder binding")
	}
	if _, err := V8MetricDescriptorCatalog(); err != nil {
		return nil, err
	}
	if err := validateV8MetricPipelineDeclarations(pipelines); err != nil {
		return nil, err
	}
	recorder := &v8MetricRecorder{
		generation: generation, digest: strings.Clone(digest),
		enabled:   make(map[observability.Bucket]bool, len(enabled)),
		pipelines: make([]v8MetricPipeline, 0, len(pipelines)),
	}
	for bucket, collected := range enabled {
		if collected {
			recorder.enabled[bucket] = true
		}
	}
	destinations := make(map[string]struct{}, len(pipelines))
	sinks := make(map[uintptr]struct{}, len(pipelines))
	for _, source := range pipelines {
		if !observability.IsStableToken(source.Destination) || nilV8MetricSink(source.Sink) || source.SinkFactory != nil ||
			(source.Projection != V8MetricProjectionCanonical && source.Projection != V8MetricProjectionLocal) ||
			len(source.SelectedFamilies) == 0 {
			return nil, errors.New("telemetry: invalid generated metric pipeline")
		}
		if _, duplicate := destinations[source.Destination]; duplicate {
			return nil, errors.New("telemetry: duplicate generated metric destination")
		}
		destinations[source.Destination] = struct{}{}
		identity := metricSinkIdentity(source.Sink)
		// A generation-owned sink has mutable lifecycle state and therefore
		// must have a stable pointer identity. Accepting a value receiver would
		// make reuse and exactly-once shutdown impossible to prove.
		if identity == 0 {
			return nil, errors.New("telemetry: generated metric sink has no stable identity")
		}
		if _, duplicate := sinks[identity]; duplicate {
			return nil, errors.New("telemetry: generated metric sink is reused")
		}
		sinks[identity] = struct{}{}
		pipeline := v8MetricPipeline{
			destination: strings.Clone(source.Destination), projection: source.Projection,
			selected: make(map[string]struct{}, len(source.SelectedFamilies)), sink: source.Sink,
		}
		for _, family := range source.SelectedFamilies {
			name := string(family)
			if _, known := v8MetricDescriptorByName(name); !known {
				return nil, errors.New("telemetry: generated metric pipeline selects an unknown family")
			}
			if _, duplicate := pipeline.selected[name]; duplicate {
				return nil, errors.New("telemetry: generated metric pipeline repeats a family")
			}
			pipeline.selected[name] = struct{}{}
		}
		recorder.pipelines = append(recorder.pipelines, pipeline)
	}
	return recorder, nil
}

func metricSinkIdentity(sink V8CanonicalMetricSink) uintptr {
	if nilV8MetricSink(sink) {
		return 0
	}
	value := reflect.ValueOf(sink)
	if value.Kind() == reflect.Pointer {
		return value.Pointer()
	}
	return 0
}

func nilV8MetricSink(sink V8CanonicalMetricSink) bool {
	if sink == nil {
		return true
	}
	value := reflect.ValueOf(sink)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (recorder *v8MetricRecorder) setActive(active bool) {
	if recorder == nil || recorder.shutdown.Load() {
		return
	}
	recorder.active.Store(active)
}

func (recorder *v8MetricRecorder) familyEnabled(name observability.EventName) bool {
	if recorder == nil || !recorder.active.Load() || recorder.shutdown.Load() {
		return false
	}
	descriptor, ok := v8MetricDescriptorByName(string(name))
	return ok && recorder.enabled[descriptor.Bucket]
}

func (recorder *v8MetricRecorder) record(
	ctx context.Context,
	record observability.Record,
) (V8MetricRecordResult, error) {
	return recorder.recordWithPolicy(ctx, record, V8ImportedExportPolicy{})
}

func (recorder *v8MetricRecorder) recordImported(
	ctx context.Context,
	record observability.Record,
	policy V8ImportedExportPolicy,
) (V8MetricRecordResult, error) {
	if !policy.valid() {
		return V8MetricRecordResult{}, errors.New("telemetry: invalid imported export policy")
	}
	return recorder.recordWithPolicy(ctx, record, policy)
}

func (recorder *v8MetricRecorder) recordWithPolicy(
	ctx context.Context,
	record observability.Record,
	policy V8ImportedExportPolicy,
) (V8MetricRecordResult, error) {
	if recorder == nil || ctx == nil || !recorder.active.Load() || recorder.shutdown.Load() {
		return V8MetricRecordResult{}, errors.New("telemetry: generated metric recorder is inactive")
	}
	descriptor, ok := v8MetricDescriptorByName(string(record.EventName()))
	if !ok || record.Signal() != observability.SignalMetrics || record.Bucket() != descriptor.Bucket ||
		!recorder.enabled[descriptor.Bucket] {
		return V8MetricRecordResult{}, errors.New("telemetry: generated metric record is not collected")
	}
	provenance := record.Provenance()
	if provenance.ConfigGeneration < 0 || uint64(provenance.ConfigGeneration) != recorder.generation ||
		provenance.ConfigDigest != recorder.digest {
		return V8MetricRecordResult{}, errors.New("telemetry: generated metric record generation mismatch")
	}
	value, attributes, err := decodeV8GeneratedMetric(record, descriptor)
	if err != nil {
		return V8MetricRecordResult{}, err
	}
	result := V8MetricRecordResult{}
	for _, pipeline := range recorder.pipelines {
		if _, selected := pipeline.selected[descriptor.Name]; !selected {
			continue
		}
		if policy.suppressAll || pipeline.destination == policy.originDestination {
			result.Suppressed++
			continue
		}
		result.Matched++
		projectedAttributes, profile, projectionErr := projectV8MetricAttributes(descriptor, attributes, pipeline.projection)
		if projectionErr != nil {
			result.Failed++
			continue
		}
		attributeValue, valueErr := observability.NewValue(projectedAttributes)
		if valueErr != nil {
			result.Failed++
			continue
		}
		projected := V8ProjectedMetric{
			destination: pipeline.destination, profile: profile,
			generation: recorder.generation, digest: recorder.digest,
			descriptor: cloneV8MetricDescriptor(descriptor), value: value,
			attributes: attributeValue, record: record,
		}
		if safeRecordV8Metric(ctx, pipeline.sink, projected) != nil {
			result.Failed++
			continue
		}
		result.Delivered++
	}
	if result.Failed != 0 {
		return result, errors.New("telemetry: generated metric destination rejected")
	}
	return result, nil
}

func decodeV8GeneratedMetric(
	record observability.Record,
	descriptor V8MetricDescriptor,
) (V8MetricNumber, map[string]any, error) {
	instrument, present := record.InstrumentData()
	if !present || !record.SchemaDerivedFieldClasses() {
		return V8MetricNumber{}, nil, errors.New("telemetry: generated metric instrument data is absent")
	}
	object, err := instrument.Object()
	if err != nil || len(object) != 2 {
		return V8MetricNumber{}, nil, errors.New("telemetry: generated metric instrument data is invalid")
	}
	attributes, ok := object["attributes"].(map[string]any)
	if !ok {
		return V8MetricNumber{}, nil, errors.New("telemetry: generated metric attributes are invalid")
	}
	allowed := make(map[string]struct{}, len(descriptor.AllowedLabels))
	for _, label := range descriptor.AllowedLabels {
		allowed[label] = struct{}{}
	}
	for label := range attributes {
		if _, valid := allowed[label]; !valid {
			return V8MetricNumber{}, nil, errors.New("telemetry: generated metric label is not allowed")
		}
	}
	number, ok := object["value"].(json.Number)
	if !ok {
		return V8MetricNumber{}, nil, errors.New("telemetry: generated metric value is invalid")
	}
	switch descriptor.ValueType {
	case "int64":
		value, parseErr := strconv.ParseInt(string(number), 10, 64)
		if parseErr != nil {
			return V8MetricNumber{}, nil, errors.New("telemetry: generated int64 metric value is invalid")
		}
		return V8MetricNumber{valueType: "int64", int64: value}, attributes, nil
	case "double":
		value, parseErr := strconv.ParseFloat(string(number), 64)
		if parseErr != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			return V8MetricNumber{}, nil, errors.New("telemetry: generated double metric value is invalid")
		}
		return V8MetricNumber{valueType: "double", double: value}, attributes, nil
	default:
		return V8MetricNumber{}, nil, errors.New("telemetry: generated metric value type is invalid")
	}
}

func projectV8MetricAttributes(
	descriptor V8MetricDescriptor,
	canonical map[string]any,
	projection V8MetricProjection,
) (map[string]any, string, error) {
	result := make(map[string]any, len(canonical))
	if projection == V8MetricProjectionCanonical {
		for key, value := range canonical {
			result[key] = value
		}
		return result, "", nil
	}
	if projection != V8MetricProjectionLocal {
		return nil, "", errors.New("telemetry: unknown generated metric projection")
	}
	aliases := make(map[string]string, len(descriptor.LocalLabelMapping))
	for _, mapping := range descriptor.LocalLabelMapping {
		aliases[mapping.Canonical] = mapping.Local
	}
	for canonicalKey, value := range canonical {
		projectedKey := canonicalKey
		if alias, exists := aliases[canonicalKey]; exists {
			projectedKey = alias
		}
		if _, conflict := result[projectedKey]; conflict {
			return nil, "", errors.New("telemetry: generated local metric alias conflict")
		}
		result[projectedKey] = value
	}
	return result, observability.RuntimeLocalObservabilityProfile, nil
}

func safeRecordV8Metric(ctx context.Context, sink V8CanonicalMetricSink, metric V8ProjectedMetric) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("telemetry: generated metric sink panicked")
		}
	}()
	return sink.RecordMetric(ctx, metric)
}

func (recorder *v8MetricRecorder) forceFlush(ctx context.Context) error {
	if recorder == nil {
		return nil
	}
	failed := false
	for _, pipeline := range recorder.pipelines {
		if err := safeMetricSinkLifecycle(ctx, pipeline.sink.ForceFlush); err != nil {
			failed = true
		}
	}
	if failed {
		return errors.New("telemetry: generated metric flush failed")
	}
	return nil
}

func (recorder *v8MetricRecorder) close(ctx context.Context) error {
	if recorder == nil || !recorder.shutdown.CompareAndSwap(false, true) {
		return nil
	}
	recorder.active.Store(false)
	var failed bool
	for index := len(recorder.pipelines) - 1; index >= 0; index-- {
		if err := safeMetricSinkLifecycle(ctx, recorder.pipelines[index].sink.Shutdown); err != nil {
			failed = true
		}
	}
	if failed {
		return errors.New("telemetry: generated metric shutdown failed")
	}
	return nil
}

func safeMetricSinkLifecycle(ctx context.Context, call func(context.Context) error) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("telemetry: generated metric sink lifecycle panicked")
		}
	}()
	return call(ctx)
}
