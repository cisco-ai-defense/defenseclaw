// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// metricExporterProbe wraps the OTLP metric exporter to record export health on the Provider.
type metricExporterProbe struct {
	inner sdkmetric.Exporter
	p     *Provider
}

func (w *metricExporterProbe) Temporality(k sdkmetric.InstrumentKind) metricdata.Temporality {
	return w.inner.Temporality(k)
}

func (w *metricExporterProbe) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return w.inner.Aggregation(k)
}

func (w *metricExporterProbe) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	err := w.inner.Export(ctx, rm)
	if w.p != nil {
		// Thread the underlying error into the export-failure emit so
		// operators see WHY (401 vs network vs 5xx), not just a generic
		// "export failed".
		w.p.RecordExporterHealthErr(context.Background(), "otlp_metrics", err)
	}
	return err
}

func (w *metricExporterProbe) ForceFlush(ctx context.Context) error {
	return w.inner.ForceFlush(ctx)
}

func (w *metricExporterProbe) Shutdown(ctx context.Context) error {
	return w.inner.Shutdown(ctx)
}
