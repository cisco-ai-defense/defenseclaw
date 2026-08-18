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
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"

	prom "github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"
)

const mergedMetricCardinalityLimit = 2_048

// generationGatherer combines the legacy and generated SDK collectors owned by
// one destination generation. They intentionally use separate registries so a
// producer-by-producer overlap cannot make prometheus.Registry reject duplicate
// families before DefenseClaw applies the documented merge semantics.
type generationGatherer struct {
	mu      sync.RWMutex
	matcher familyMatcher
	nextID  uint64
	sources []generationGathererSource
}

type generationGathererSource struct {
	id       uint64
	gatherer prom.Gatherer
}

func newGenerationGatherer(primary prom.Gatherer, matcher familyMatcher) *generationGatherer {
	return &generationGatherer{
		matcher: matcher, nextID: 2,
		sources: []generationGathererSource{{id: 1, gatherer: primary}},
	}
}

func (gatherer *generationGatherer) add(source prom.Gatherer) (func(), error) {
	if gatherer == nil || source == nil {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	gatherer.mu.Lock()
	id := gatherer.nextID
	gatherer.nextID++
	gatherer.sources = append(gatherer.sources, generationGathererSource{id: id, gatherer: source})
	gatherer.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() { gatherer.remove(id) })
	}, nil
}

func (gatherer *generationGatherer) remove(id uint64) {
	if gatherer == nil || id == 1 {
		return
	}
	gatherer.mu.Lock()
	defer gatherer.mu.Unlock()
	for index, source := range gatherer.sources {
		if source.id != id {
			continue
		}
		gatherer.sources = append(gatherer.sources[:index:index], gatherer.sources[index+1:]...)
		return
	}
}

func (gatherer *generationGatherer) Gather() ([]*dto.MetricFamily, error) {
	if gatherer == nil {
		return nil, newError(ErrorGatherFailed, nil)
	}
	gatherer.mu.RLock()
	sources := append([]generationGathererSource(nil), gatherer.sources...)
	gatherer.mu.RUnlock()
	byName := make(map[string]*dto.MetricFamily)
	cloned := make(map[string]bool)
	for _, source := range sources {
		if source.gatherer == nil {
			return nil, newError(ErrorGatherFailed, nil)
		}
		families, err := source.gatherer.Gather()
		if err != nil {
			return nil, newError(ErrorGatherFailed, nil)
		}
		for _, family := range families {
			if family == nil || family.Name == nil || family.Type == nil {
				return nil, newError(ErrorGatherFailed, nil)
			}
			name := family.GetName()
			existing := byName[name]
			if existing == nil {
				byName[name] = family
				continue
			}
			if !cloned[name] {
				existing = proto.Clone(existing).(*dto.MetricFamily)
				byName[name] = existing
				cloned[name] = true
			}
			if err := mergeMetricFamily(existing, family, gatherer.matcher); err != nil {
				return nil, newError(ErrorGatherFailed, nil)
			}
		}
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]*dto.MetricFamily, 0, len(names))
	for _, name := range names {
		result = append(result, byName[name])
	}
	return result, nil
}

func mergeMetricFamily(target, source *dto.MetricFamily, matcher familyMatcher) error {
	if target == nil || source == nil || target.GetName() != source.GetName() ||
		target.Type == nil || source.Type == nil || target.GetType() != source.GetType() {
		return newError(ErrorGatherFailed, nil)
	}
	instrumentType, known := matcher.instrumentType(target.GetName(), target.GetType())
	if !known {
		return newError(ErrorUnknownFamily, nil)
	}
	if target.GetHelp() != "" && source.GetHelp() != "" && target.GetHelp() != source.GetHelp() {
		return newError(ErrorGatherFailed, nil)
	}
	if target.GetHelp() == "" && source.GetHelp() != "" {
		target.Help = cloneStringPointer(source.Help)
	}
	metrics := make(map[string]*dto.Metric, len(target.Metric))
	for _, metric := range target.Metric {
		if metric == nil {
			return newError(ErrorGatherFailed, nil)
		}
		metrics[prometheusMetricKey(metric)] = metric
	}
	for _, metric := range source.Metric {
		if metric == nil {
			return newError(ErrorGatherFailed, nil)
		}
		key := prometheusMetricKey(metric)
		existing := metrics[key]
		if existing == nil {
			cloned := proto.Clone(metric).(*dto.Metric)
			target.Metric = append(target.Metric, cloned)
			metrics[key] = cloned
			continue
		}
		if err := mergePrometheusMetric(existing, metric, target.GetType(), instrumentType); err != nil {
			return err
		}
	}
	sort.Slice(target.Metric, func(left, right int) bool {
		return prometheusMetricKey(target.Metric[left]) < prometheusMetricKey(target.Metric[right])
	})
	return enforceMergedMetricCardinality(target, instrumentType, mergedMetricCardinalityLimit)
}

// enforceMergedMetricCardinality applies the same global ceiling after two SDK
// providers are combined. Without this second boundary, two independently safe
// 2,048-stream providers could expose nearly 4,096 series during cutover.
func enforceMergedMetricCardinality(
	family *dto.MetricFamily,
	instrumentType string,
	limit int,
) error {
	if family == nil || family.Type == nil || limit < 2 || len(family.Metric) <= limit {
		return nil
	}
	metrics := append([]*dto.Metric(nil), family.Metric...)
	sort.Slice(metrics, func(left, right int) bool {
		return prometheusMetricKey(metrics[left]) < prometheusMetricKey(metrics[right])
	})
	kept := make([]*dto.Metric, 0, limit)
	var overflow *dto.Metric
	for _, metric := range metrics {
		if prometheusOverflowMetric(metric) {
			if overflow == nil {
				overflow = proto.Clone(metric).(*dto.Metric)
			} else if err := mergePrometheusMetric(overflow, metric, family.GetType(), instrumentType); err != nil {
				return err
			}
			continue
		}
		if len(kept) < limit-1 {
			kept = append(kept, metric)
			continue
		}
		if overflow == nil {
			overflow = proto.Clone(metric).(*dto.Metric)
			name, value := "otel_metric_overflow", "true"
			overflow.Label = []*dto.LabelPair{{Name: &name, Value: &value}}
			continue
		}
		if err := mergePrometheusMetric(overflow, metric, family.GetType(), instrumentType); err != nil {
			return err
		}
	}
	if overflow == nil {
		return newError(ErrorGatherFailed, nil)
	}
	family.Metric = append(kept, overflow)
	return nil
}

func prometheusOverflowMetric(metric *dto.Metric) bool {
	if metric == nil || len(metric.Label) != 1 || metric.Label[0] == nil {
		return false
	}
	return metric.Label[0].GetName() == "otel_metric_overflow" &&
		metric.Label[0].GetValue() == "true"
}

func mergePrometheusMetric(
	target, source *dto.Metric,
	metricType dto.MetricType,
	instrumentType string,
) error {
	switch metricType {
	case dto.MetricType_COUNTER:
		if target.Counter == nil || source.Counter == nil || target.Counter.Value == nil || source.Counter.Value == nil {
			return newError(ErrorGatherFailed, nil)
		}
		value := target.Counter.GetValue() + source.Counter.GetValue()
		target.Counter.Value = &value
	case dto.MetricType_GAUGE:
		if target.Gauge == nil || source.Gauge == nil || target.Gauge.Value == nil || source.Gauge.Value == nil {
			return newError(ErrorGatherFailed, nil)
		}
		// Sources are ordered legacy first, generated second. A synchronous
		// gauge is an absolute snapshot, so the generated cutover source is
		// authoritative rather than being added to the legacy snapshot.
		value := source.Gauge.GetValue()
		if instrumentType == "updowncounter" {
			value += target.Gauge.GetValue()
		} else if instrumentType != "gauge" {
			return newError(ErrorGatherFailed, nil)
		}
		target.Gauge.Value = &value
	case dto.MetricType_HISTOGRAM:
		if target.Histogram == nil || source.Histogram == nil ||
			target.Histogram.SampleCount == nil || source.Histogram.SampleCount == nil ||
			target.Histogram.SampleSum == nil || source.Histogram.SampleSum == nil {
			return newError(ErrorGatherFailed, nil)
		}
		if !samePrometheusHistogramBoundaries(target.Histogram, source.Histogram) {
			return newError(ErrorGatherFailed, nil)
		}
		mergePrometheusHistogram(target.Histogram, source.Histogram)
	default:
		return newError(ErrorGatherFailed, nil)
	}
	return nil
}

func mergePrometheusHistogram(target, source *dto.Histogram) {
	buckets := make([]*dto.Bucket, len(target.Bucket))
	for index := range target.Bucket {
		upper := target.Bucket[index].GetUpperBound()
		count := target.Bucket[index].GetCumulativeCount() + source.Bucket[index].GetCumulativeCount()
		buckets[index] = &dto.Bucket{UpperBound: &upper, CumulativeCount: &count}
	}
	count := target.GetSampleCount() + source.GetSampleCount()
	sum := target.GetSampleSum() + source.GetSampleSum()
	target.SampleCount, target.SampleSum, target.Bucket = &count, &sum, buckets
}

func samePrometheusHistogramBoundaries(left, right *dto.Histogram) bool {
	if left == nil || right == nil || len(left.Bucket) != len(right.Bucket) {
		return false
	}
	for index := range left.Bucket {
		leftBucket, rightBucket := left.Bucket[index], right.Bucket[index]
		if leftBucket == nil || rightBucket == nil || leftBucket.UpperBound == nil ||
			rightBucket.UpperBound == nil || leftBucket.CumulativeCount == nil ||
			rightBucket.CumulativeCount == nil || math.Float64bits(leftBucket.GetUpperBound()) !=
			math.Float64bits(rightBucket.GetUpperBound()) {
			return false
		}
	}
	return true
}

func prometheusMetricKey(metric *dto.Metric) string {
	if metric == nil {
		return ""
	}
	labels := append([]*dto.LabelPair(nil), metric.Label...)
	sort.Slice(labels, func(left, right int) bool {
		if labels[left].GetName() == labels[right].GetName() {
			return labels[left].GetValue() < labels[right].GetValue()
		}
		return labels[left].GetName() < labels[right].GetName()
	})
	var builder strings.Builder
	for _, label := range labels {
		name, value := label.GetName(), label.GetValue()
		builder.WriteString(strconv.Itoa(len(name)))
		builder.WriteByte(':')
		builder.WriteString(name)
		builder.WriteString(strconv.Itoa(len(value)))
		builder.WriteByte(':')
		builder.WriteString(value)
	}
	return builder.String()
}

func cloneStringPointer(source *string) *string {
	if source == nil {
		return nil
	}
	value := *source
	return &value
}

var _ prom.Gatherer = (*generationGatherer)(nil)
