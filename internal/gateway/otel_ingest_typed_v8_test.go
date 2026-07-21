// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"reflect"
	"testing"

	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

func otlpStringAttribute(key, value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: key, Value: &commonpb.AnyValue{
		Value: &commonpb.AnyValue_StringValue{StringValue: value},
	}}
}

func TestOTLPTypedAttributeIndexRejectsDuplicatesWithoutCoercion(t *testing.T) {
	index := newOTLPTypedAttributeIndex([]*commonpb.KeyValue{
		otlpStringAttribute("event.name", "first"),
		otlpStringAttribute("event.name", "first"),
		otlpStringAttribute("Event.Name", "case-sensitive"),
		otlpStringAttribute("token.count", "17"),
		{Key: "actual.count", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: 17}}},
		{Key: "ratio", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: 0.5}}},
		{Key: "enabled", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: true}}},
	})

	if value, state := index.stringValue("event.name"); value != "" || state != otlpTypedAttributeDuplicate {
		t.Fatalf("duplicate string value=%q state=%d", value, state)
	}
	if value, state := index.stringValue("Event.Name"); value != "case-sensitive" || state != otlpTypedAttributeUnique {
		t.Fatalf("exact string value=%q state=%d", value, state)
	}
	if value, state := index.int64Value("token.count"); value != 0 || state != otlpTypedAttributeInvalid {
		t.Fatalf("string-to-int coercion value=%d state=%d", value, state)
	}
	if value, state := index.int64Value("actual.count"); value != 17 || state != otlpTypedAttributeUnique {
		t.Fatalf("int value=%d state=%d", value, state)
	}
	if value, state := index.doubleValue("ratio"); value != 0.5 || state != otlpTypedAttributeUnique {
		t.Fatalf("double value=%v state=%d", value, state)
	}
	if value, state := index.boolValue("enabled"); !value || state != otlpTypedAttributeUnique {
		t.Fatalf("bool value=%t state=%d", value, state)
	}
	if _, state := index.lookup("missing"); state != otlpTypedAttributeAbsent {
		t.Fatalf("missing state=%d", state)
	}
	wantKeys := []string{"Event.Name", "actual.count", "enabled", "event.name", "ratio", "token.count"}
	if keys := index.keys(); !reflect.DeepEqual(keys, wantKeys) {
		t.Fatalf("keys=%v want=%v", keys, wantKeys)
	}
}

func TestOTLPTypedAttributeIndexRetainsMalformedAndNestedStates(t *testing.T) {
	index := newOTLPTypedAttributeIndex([]*commonpb.KeyValue{
		nil,
		otlpStringAttribute("", "empty-key"),
		{Key: "malformed", Value: nil},
		otlpStringAttribute("malformed", "second-value"),
		{Key: "empty-oneof", Value: &commonpb.AnyValue{}},
		{Key: "array", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{
			ArrayValue: &commonpb.ArrayValue{Values: []*commonpb.AnyValue{{
				Value: &commonpb.AnyValue_StringValue{StringValue: "content"},
			}}},
		}}},
		{Key: "object", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_KvlistValue{
			KvlistValue: &commonpb.KeyValueList{Values: []*commonpb.KeyValue{
				otlpStringAttribute("nested", "value"),
			}},
		}}},
		{Key: "bytes", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_BytesValue{BytesValue: []byte("raw")}}},
	})

	if index.invalidCount() != 4 {
		t.Fatalf("invalid count=%d want=4", index.invalidCount())
	}
	if _, state := index.lookup("malformed"); state != otlpTypedAttributeDuplicate {
		t.Fatalf("malformed duplicate state=%d", state)
	}
	if _, state := index.lookup("empty-oneof"); state != otlpTypedAttributeInvalid {
		t.Fatalf("empty oneof state=%d", state)
	}
	for key, kind := range map[string]otlpTypedAnyValueKind{
		"array": otlpTypedAnyValueArray, "object": otlpTypedAnyValueKeyValueList,
		"bytes": otlpTypedAnyValueBytes,
	} {
		value, state := index.lookup(key)
		if state != otlpTypedAttributeUnique || otlpTypedValueKind(value) != kind {
			t.Fatalf("key=%s state=%d kind=%d want=%d", key, state, otlpTypedValueKind(value), kind)
		}
		if _, state := index.stringValue(key); state != otlpTypedAttributeInvalid {
			t.Fatalf("nested/bytes key=%s was flattened to string", key)
		}
	}
}

func TestWalkDecodedOTLPLeavesPreservesTypedResourceScopeAndWireOrder(t *testing.T) {
	request := &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{
		{
			SchemaUrl: "resource-schema-a",
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
				otlpStringAttribute("service.name", "first-service"),
			}},
			ScopeLogs: []*logspb.ScopeLogs{{
				SchemaUrl: "scope-schema-a",
				Scope: &commonpb.InstrumentationScope{
					Name: "first-scope", Version: "1.0",
					Attributes: []*commonpb.KeyValue{otlpStringAttribute("scope.key", "scope-value")},
				},
				LogRecords: []*logspb.LogRecord{
					{Attributes: []*commonpb.KeyValue{otlpStringAttribute("record.id", "one")}},
					{Attributes: []*commonpb.KeyValue{otlpStringAttribute("record.id", "two")}},
				},
			}},
		},
		{
			SchemaUrl: "resource-schema-b",
			ScopeLogs: []*logspb.ScopeLogs{{
				Scope:      &commonpb.InstrumentationScope{Name: "second-scope"},
				LogRecords: []*logspb.LogRecord{{Attributes: []*commonpb.KeyValue{otlpStringAttribute("record.id", "three")}}},
			}},
		},
	}}
	var order []string
	stats, err := walkDecodedOTLPLeaves(request, otelSignalLogs, func(leaf otlpDecodedLeaf) error {
		if leaf.signal != otelSignalLogs || leaf.logRecord == nil || leaf.span != nil || leaf.metric != nil {
			t.Fatalf("invalid log leaf union: %#v", leaf)
		}
		id, state := leaf.attributes().stringValue("record.id")
		if state != otlpTypedAttributeUnique {
			t.Fatalf("record id state=%d", state)
		}
		order = append(order, id)
		switch id {
		case "one", "two":
			service, serviceState := leaf.resource.attributes.stringValue("service.name")
			scopeValue, scopeState := leaf.scope.attributes.stringValue("scope.key")
			if leaf.resource.schemaURL != "resource-schema-a" || service != "first-service" ||
				serviceState != otlpTypedAttributeUnique || leaf.scope.name != "first-scope" ||
				leaf.scope.version != "1.0" || leaf.scope.schemaURL != "scope-schema-a" ||
				scopeValue != "scope-value" || scopeState != otlpTypedAttributeUnique {
				t.Fatalf("first context lost: resource=%+v scope=%+v", leaf.resource, leaf.scope)
			}
		case "three":
			if leaf.resource.schemaURL != "resource-schema-b" || leaf.scope.name != "second-scope" {
				t.Fatalf("second context lost: resource=%+v scope=%+v", leaf.resource, leaf.scope)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats != (otelIngestStats{Records: 3, Resources: 2}) ||
		!reflect.DeepEqual(order, []string{"one", "two", "three"}) {
		t.Fatalf("stats=%+v order=%v", stats, order)
	}
}

func TestWalkDecodedOTLPMetricLeavesEmitsEveryPointShape(t *testing.T) {
	attribute := func(name string) []*commonpb.KeyValue {
		return []*commonpb.KeyValue{otlpStringAttribute("point", name)}
	}
	request := &collectormetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{
			{Name: "g", Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{Attributes: attribute("g1")}, {Attributes: attribute("g2")}}}}},
			{Name: "s", Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{DataPoints: []*metricspb.NumberDataPoint{{Attributes: attribute("s")}}}}},
			{Name: "h", Data: &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{DataPoints: []*metricspb.HistogramDataPoint{{Attributes: attribute("h")}}}}},
			{Name: "e", Data: &metricspb.Metric_ExponentialHistogram{ExponentialHistogram: &metricspb.ExponentialHistogram{DataPoints: []*metricspb.ExponentialHistogramDataPoint{{Attributes: attribute("e")}}}}},
			{Name: "q", Data: &metricspb.Metric_Summary{Summary: &metricspb.Summary{DataPoints: []*metricspb.SummaryDataPoint{{Attributes: attribute("q")}}}}},
			{Name: "empty", Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{}}},
		}}},
	}}}
	var got []struct {
		name  string
		shape otlpTypedMetricShape
		point string
	}
	stats, err := walkDecodedOTLPLeaves(request, otelSignalMetrics, func(leaf otlpDecodedLeaf) error {
		point, state := leaf.attributes().stringValue("point")
		if leaf.signal != otelSignalMetrics || leaf.metric == nil || state != otlpTypedAttributeUnique {
			t.Fatalf("invalid metric leaf: %#v state=%d", leaf, state)
		}
		got = append(got, struct {
			name  string
			shape otlpTypedMetricShape
			point string
		}{leaf.metric.GetName(), leaf.metricShape, point})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		name  string
		shape otlpTypedMetricShape
		point string
	}{
		{"g", otlpTypedMetricGauge, "g1"}, {"g", otlpTypedMetricGauge, "g2"},
		{"s", otlpTypedMetricSum, "s"}, {"h", otlpTypedMetricHistogram, "h"},
		{"e", otlpTypedMetricExponentialHistogram, "e"}, {"q", otlpTypedMetricSummary, "q"},
	}
	if stats != (otelIngestStats{Records: 6, Resources: 1}) || !reflect.DeepEqual(got, want) {
		t.Fatalf("stats=%+v got=%v want=%v", stats, got, want)
	}
}

func TestWalkDecodedOTLPLeavesRejectsNilElementsAndStopsOnVisitorError(t *testing.T) {
	request := &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{}, nil}}},
	}}}
	if _, err := walkDecodedOTLPLeaves(request, otelSignalLogs, nil); err == nil {
		t.Fatal("nil repeated message element was silently treated as an empty leaf")
	}
	stop := errors.New("stop")
	request.ResourceLogs[0].ScopeLogs[0].LogRecords = []*logspb.LogRecord{{}, {}}
	stats, err := walkDecodedOTLPLeaves(request, otelSignalLogs, func(otlpDecodedLeaf) error { return stop })
	if !errors.Is(err, stop) || stats.Records != 1 || stats.Resources != 1 {
		t.Fatalf("visitor stop stats=%+v err=%v", stats, err)
	}
}
