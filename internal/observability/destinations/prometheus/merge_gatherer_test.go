// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package prometheus

import (
	"strconv"
	"testing"

	dto "github.com/prometheus/client_model/go"
)

func TestOverlapMergeCapsCombinedCardinalityWithOneAggregatedOverflow(t *testing.T) {
	name, help, metricType := "defenseclaw_activity_total", "activity", dto.MetricType_COUNTER
	family := &dto.MetricFamily{Name: &name, Help: &help, Type: &metricType}
	for index := 0; index < mergedMetricCardinalityLimit+2; index++ {
		labelName, labelValue, value := "action", "action-"+strconv.Itoa(index), float64(1)
		family.Metric = append(family.Metric, &dto.Metric{
			Label:   []*dto.LabelPair{{Name: &labelName, Value: &labelValue}},
			Counter: &dto.Counter{Value: &value},
		})
	}
	if err := enforceMergedMetricCardinality(family, "counter", mergedMetricCardinalityLimit); err != nil {
		t.Fatal(err)
	}
	if len(family.Metric) != mergedMetricCardinalityLimit {
		t.Fatalf("merged series=%d want %d", len(family.Metric), mergedMetricCardinalityLimit)
	}
	overflowCount, overflowValue := 0, float64(0)
	for _, metric := range family.Metric {
		if !prometheusOverflowMetric(metric) {
			continue
		}
		overflowCount++
		overflowValue = metric.Counter.GetValue()
	}
	if overflowCount != 1 || overflowValue != 3 {
		t.Fatalf("overflow count=%d value=%v want one series aggregating three", overflowCount, overflowValue)
	}
}

func TestOverlapMergeRejectsHistogramBoundaryAndHelpMismatch(t *testing.T) {
	factory := newTestFactory(t, allMetricsSource("metrics"), ephemeralListen, nil)
	for name, pair := range map[string][2]*dto.MetricFamily{
		"histogram_boundaries": {
			histogramFamily("defenseclaw_connector_hook_latency_milliseconds", "latency", []float64{1, 2}, []uint64{1, 1}),
			histogramFamily("defenseclaw_connector_hook_latency_milliseconds", "", []float64{1, 3}, []uint64{1, 1}),
		},
		"nonempty_help": {
			counterFamily("defenseclaw_activity_total", "legacy help", 1),
			counterFamily("defenseclaw_activity_total", "different generated help", 1),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := mergeMetricFamily(pair[0], pair[1], factory.matcher); err == nil {
				t.Fatal("overlap merge accepted an ambiguous family")
			}
		})
	}
}

func TestOverlapMergeUsesGeneratedGaugeAndAddsUpDownAndCounter(t *testing.T) {
	factory := newTestFactory(t, allMetricsSource("metrics"), ephemeralListen, nil)
	gaugeTarget := gaugeFamily("defenseclaw_agent_discovery_installed_ratio", "installed", 1)
	if err := mergeMetricFamily(
		gaugeTarget, gaugeFamily("defenseclaw_agent_discovery_installed_ratio", "", 4), factory.matcher,
	); err != nil || gaugeTarget.Metric[0].Gauge.GetValue() != 4 {
		t.Fatalf("generated gauge authority value=%v err=%v", gaugeTarget.Metric[0].Gauge.GetValue(), err)
	}

	upDownTarget := gaugeFamily("defenseclaw_audit_sink_circuit_state", "state", 3)
	if err := mergeMetricFamily(
		upDownTarget, gaugeFamily("defenseclaw_audit_sink_circuit_state", "", -1), factory.matcher,
	); err != nil || upDownTarget.Metric[0].Gauge.GetValue() != 2 {
		t.Fatalf("updown sum value=%v err=%v", upDownTarget.Metric[0].Gauge.GetValue(), err)
	}

	counterTarget := counterFamily("defenseclaw_activity_total", "activity", 2)
	if err := mergeMetricFamily(
		counterTarget, counterFamily("defenseclaw_activity_total", "", 3), factory.matcher,
	); err != nil || counterTarget.Metric[0].Counter.GetValue() != 5 {
		t.Fatalf("counter sum value=%v err=%v", counterTarget.Metric[0].Counter.GetValue(), err)
	}
}

func histogramFamily(name, help string, bounds []float64, counts []uint64) *dto.MetricFamily {
	metricType := dto.MetricType_HISTOGRAM
	count, sum := uint64(1), float64(1)
	buckets := make([]*dto.Bucket, len(bounds))
	for index := range bounds {
		bound, cumulative := bounds[index], counts[index]
		buckets[index] = &dto.Bucket{UpperBound: &bound, CumulativeCount: &cumulative}
	}
	return &dto.MetricFamily{
		Name: &name, Help: &help, Type: &metricType,
		Metric: []*dto.Metric{{Histogram: &dto.Histogram{
			SampleCount: &count, SampleSum: &sum, Bucket: buckets,
		}}},
	}
}

func counterFamily(name, help string, value float64) *dto.MetricFamily {
	metricType := dto.MetricType_COUNTER
	return &dto.MetricFamily{
		Name: &name, Help: &help, Type: &metricType,
		Metric: []*dto.Metric{{Counter: &dto.Counter{Value: &value}}},
	}
}

func gaugeFamily(name, help string, value float64) *dto.MetricFamily {
	metricType := dto.MetricType_GAUGE
	return &dto.MetricFamily{
		Name: &name, Help: &help, Type: &metricType,
		Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: &value}}},
	}
}
