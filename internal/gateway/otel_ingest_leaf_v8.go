// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"

	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

type otlpTypedResourceContext struct {
	schemaURL              string
	attributes             otlpTypedAttributeIndex
	droppedAttributesCount uint32
}

type otlpTypedScopeContext struct {
	name                   string
	version                string
	schemaURL              string
	attributes             otlpTypedAttributeIndex
	droppedAttributesCount uint32
}

type otlpTypedMetricShape uint8

const (
	otlpTypedMetricInvalid otlpTypedMetricShape = iota
	otlpTypedMetricGauge
	otlpTypedMetricSum
	otlpTypedMetricHistogram
	otlpTypedMetricExponentialHistogram
	otlpTypedMetricSummary
)

// otlpDecodedLeaf is a closed typed union over one independently disposable
// OTLP protocol leaf. Exactly one log/span/metric point arm is populated. It
// references request-owned protobuf values and must not escape the inbound
// request's generation scope.
type otlpDecodedLeaf struct {
	signal   otelIngestSignal
	resource otlpTypedResourceContext
	scope    otlpTypedScopeContext

	logRecord      *logspb.LogRecord
	span           *tracepb.Span
	leafAttributes otlpTypedAttributeIndex

	metric                *metricspb.Metric
	metricShape           otlpTypedMetricShape
	numberPoint           *metricspb.NumberDataPoint
	histogramPoint        *metricspb.HistogramDataPoint
	exponentialHistogram  *metricspb.ExponentialHistogramDataPoint
	summaryPoint          *metricspb.SummaryDataPoint
	metricPointAttributes otlpTypedAttributeIndex
}

func (leaf otlpDecodedLeaf) attributes() otlpTypedAttributeIndex {
	switch leaf.signal {
	case otelSignalLogs:
		if leaf.logRecord != nil {
			return leaf.leafAttributes
		}
	case otelSignalTraces:
		if leaf.span != nil {
			return leaf.leafAttributes
		}
	case otelSignalMetrics:
		return leaf.metricPointAttributes
	}
	return newOTLPTypedAttributeIndex(nil)
}

// walkDecodedOTLPLeaves traverses the official protobuf request in wire order.
// A metric leaf is one data point; empty metric descriptors contribute no leaf.
// The visitor may be nil for exact typed accounting. Any nil repeated message
// element is an invalid decoded model and fails the whole structural walk rather
// than becoming a fabricated empty record.
func walkDecodedOTLPLeaves(
	message proto.Message,
	signal otelIngestSignal,
	visit func(otlpDecodedLeaf) error,
) (otelIngestStats, error) {
	switch signal {
	case otelSignalLogs:
		request, ok := message.(*collectorlogspb.ExportLogsServiceRequest)
		if !ok || request == nil {
			return otelIngestStats{}, errors.New("OTLP logs request type mismatch")
		}
		return walkDecodedOTLPLogLeaves(request, visit)
	case otelSignalTraces:
		request, ok := message.(*collectortracepb.ExportTraceServiceRequest)
		if !ok || request == nil {
			return otelIngestStats{}, errors.New("OTLP traces request type mismatch")
		}
		return walkDecodedOTLPTraceLeaves(request, visit)
	case otelSignalMetrics:
		request, ok := message.(*collectormetricspb.ExportMetricsServiceRequest)
		if !ok || request == nil {
			return otelIngestStats{}, errors.New("OTLP metrics request type mismatch")
		}
		return walkDecodedOTLPMetricLeaves(request, visit)
	default:
		return otelIngestStats{}, errors.New("unknown OTLP signal")
	}
}

func walkDecodedOTLPLogLeaves(
	request *collectorlogspb.ExportLogsServiceRequest,
	visit func(otlpDecodedLeaf) error,
) (otelIngestStats, error) {
	stats := otelIngestStats{Resources: int64(len(request.GetResourceLogs()))}
	for _, group := range request.GetResourceLogs() {
		if group == nil {
			return otelIngestStats{}, errors.New("nil OTLP resource logs")
		}
		resource := newOTLPTypedResourceContext(
			group.GetSchemaUrl(), group.GetResource().GetAttributes(),
			group.GetResource().GetDroppedAttributesCount(),
		)
		for _, scoped := range group.GetScopeLogs() {
			if scoped == nil {
				return otelIngestStats{}, errors.New("nil OTLP scope logs")
			}
			scope := newOTLPTypedScopeContext(scoped.GetScope(), scoped.GetSchemaUrl())
			for _, record := range scoped.GetLogRecords() {
				if record == nil {
					return otelIngestStats{}, errors.New("nil OTLP log record")
				}
				stats.Records++
				if visit != nil {
					if err := visit(otlpDecodedLeaf{
						signal: otelSignalLogs, resource: resource, scope: scope, logRecord: record,
						leafAttributes: newOTLPTypedAttributeIndex(record.GetAttributes()),
					}); err != nil {
						return stats, err
					}
				}
			}
		}
	}
	return stats, nil
}

func walkDecodedOTLPTraceLeaves(
	request *collectortracepb.ExportTraceServiceRequest,
	visit func(otlpDecodedLeaf) error,
) (otelIngestStats, error) {
	stats := otelIngestStats{Resources: int64(len(request.GetResourceSpans()))}
	for _, group := range request.GetResourceSpans() {
		if group == nil {
			return otelIngestStats{}, errors.New("nil OTLP resource spans")
		}
		resource := newOTLPTypedResourceContext(
			group.GetSchemaUrl(), group.GetResource().GetAttributes(),
			group.GetResource().GetDroppedAttributesCount(),
		)
		for _, scoped := range group.GetScopeSpans() {
			if scoped == nil {
				return otelIngestStats{}, errors.New("nil OTLP scope spans")
			}
			scope := newOTLPTypedScopeContext(scoped.GetScope(), scoped.GetSchemaUrl())
			for _, span := range scoped.GetSpans() {
				if span == nil {
					return otelIngestStats{}, errors.New("nil OTLP span")
				}
				stats.Records++
				if visit != nil {
					if err := visit(otlpDecodedLeaf{
						signal: otelSignalTraces, resource: resource, scope: scope, span: span,
						leafAttributes: newOTLPTypedAttributeIndex(span.GetAttributes()),
					}); err != nil {
						return stats, err
					}
				}
			}
		}
	}
	return stats, nil
}

func walkDecodedOTLPMetricLeaves(
	request *collectormetricspb.ExportMetricsServiceRequest,
	visit func(otlpDecodedLeaf) error,
) (otelIngestStats, error) {
	stats := otelIngestStats{Resources: int64(len(request.GetResourceMetrics()))}
	for _, group := range request.GetResourceMetrics() {
		if group == nil {
			return otelIngestStats{}, errors.New("nil OTLP resource metrics")
		}
		resource := newOTLPTypedResourceContext(
			group.GetSchemaUrl(), group.GetResource().GetAttributes(),
			group.GetResource().GetDroppedAttributesCount(),
		)
		for _, scoped := range group.GetScopeMetrics() {
			if scoped == nil {
				return otelIngestStats{}, errors.New("nil OTLP scope metrics")
			}
			scope := newOTLPTypedScopeContext(scoped.GetScope(), scoped.GetSchemaUrl())
			for _, metric := range scoped.GetMetrics() {
				if metric == nil {
					return otelIngestStats{}, errors.New("nil OTLP metric")
				}
				var err error
				stats, err = walkDecodedOTLPMetricPoints(stats, resource, scope, metric, visit)
				if err != nil {
					return stats, err
				}
			}
		}
	}
	return stats, nil
}

func walkDecodedOTLPMetricPoints(
	stats otelIngestStats,
	resource otlpTypedResourceContext,
	scope otlpTypedScopeContext,
	metric *metricspb.Metric,
	visit func(otlpDecodedLeaf) error,
) (otelIngestStats, error) {
	emitNumber := func(shape otlpTypedMetricShape, points []*metricspb.NumberDataPoint) error {
		for _, point := range points {
			if point == nil {
				return errors.New("nil OTLP number data point")
			}
			stats.Records++
			if visit != nil {
				if err := visit(otlpDecodedLeaf{
					signal: otelSignalMetrics, resource: resource, scope: scope,
					metric: metric, metricShape: shape, numberPoint: point,
					metricPointAttributes: newOTLPTypedAttributeIndex(point.GetAttributes()),
				}); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if gauge := metric.GetGauge(); gauge != nil {
		err := emitNumber(otlpTypedMetricGauge, gauge.GetDataPoints())
		return stats, err
	}
	if sum := metric.GetSum(); sum != nil {
		err := emitNumber(otlpTypedMetricSum, sum.GetDataPoints())
		return stats, err
	}
	if histogram := metric.GetHistogram(); histogram != nil {
		for _, point := range histogram.GetDataPoints() {
			if point == nil {
				return stats, errors.New("nil OTLP histogram data point")
			}
			stats.Records++
			if visit != nil {
				if err := visit(otlpDecodedLeaf{
					signal: otelSignalMetrics, resource: resource, scope: scope,
					metric: metric, metricShape: otlpTypedMetricHistogram, histogramPoint: point,
					metricPointAttributes: newOTLPTypedAttributeIndex(point.GetAttributes()),
				}); err != nil {
					return stats, err
				}
			}
		}
		return stats, nil
	}
	if histogram := metric.GetExponentialHistogram(); histogram != nil {
		for _, point := range histogram.GetDataPoints() {
			if point == nil {
				return stats, errors.New("nil OTLP exponential histogram data point")
			}
			stats.Records++
			if visit != nil {
				if err := visit(otlpDecodedLeaf{
					signal: otelSignalMetrics, resource: resource, scope: scope,
					metric: metric, metricShape: otlpTypedMetricExponentialHistogram,
					exponentialHistogram:  point,
					metricPointAttributes: newOTLPTypedAttributeIndex(point.GetAttributes()),
				}); err != nil {
					return stats, err
				}
			}
		}
		return stats, nil
	}
	if summary := metric.GetSummary(); summary != nil {
		for _, point := range summary.GetDataPoints() {
			if point == nil {
				return stats, errors.New("nil OTLP summary data point")
			}
			stats.Records++
			if visit != nil {
				if err := visit(otlpDecodedLeaf{
					signal: otelSignalMetrics, resource: resource, scope: scope,
					metric: metric, metricShape: otlpTypedMetricSummary, summaryPoint: point,
					metricPointAttributes: newOTLPTypedAttributeIndex(point.GetAttributes()),
				}); err != nil {
					return stats, err
				}
			}
		}
	}
	return stats, nil
}

func newOTLPTypedResourceContext(
	schemaURL string,
	attributes []*commonpb.KeyValue,
	droppedAttributesCount uint32,
) otlpTypedResourceContext {
	return otlpTypedResourceContext{
		schemaURL: schemaURL, attributes: newOTLPTypedAttributeIndex(attributes),
		droppedAttributesCount: droppedAttributesCount,
	}
}

func newOTLPTypedScopeContext(
	scope *commonpb.InstrumentationScope,
	schemaURL string,
) otlpTypedScopeContext {
	if scope == nil {
		return otlpTypedScopeContext{
			schemaURL: schemaURL, attributes: newOTLPTypedAttributeIndex(nil),
		}
	}
	return otlpTypedScopeContext{
		name: scope.GetName(), version: scope.GetVersion(), schemaURL: schemaURL,
		attributes:             newOTLPTypedAttributeIndex(scope.GetAttributes()),
		droppedAttributesCount: scope.GetDroppedAttributesCount(),
	}
}
