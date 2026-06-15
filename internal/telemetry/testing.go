// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	logNoop "go.opentelemetry.io/otel/log/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	traceNoop "go.opentelemetry.io/otel/trace/noop"
)

// NewProviderForTest creates a Provider wired to the given ManualReader so
// that tests can call reader.Collect() to inspect emitted metrics. The
// provider reports Enabled()=true and has a fully initialised metricsSet.
func NewProviderForTest(reader *sdkmetric.ManualReader) (*Provider, error) {
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	m := mp.Meter("defenseclaw-test")

	ms, err := newMetricsSet(m)
	if err != nil {
		return nil, err
	}

	return &Provider{
		enabled:       true,
		meterProvider: mp,
		meter:         m,
		metrics:       ms,
		tracer:        traceNoop.NewTracerProvider().Tracer("test"),
		logger:        logNoop.NewLoggerProvider().Logger("test"),
	}, nil
}

// InstallGlobalForTest wires p into the package-level global so the
// helpers in global_provider.go (RecordSQLiteBusy, RecordJudgePersistDrop,
// …) see it. Returns the previous global so tests can restore it.
// Test code only — never call from production paths.
func InstallGlobalForTest(p *Provider) (prev *Provider) {
	prev = globalTelemetry.Load()
	setGlobalTelemetryProvider(p)
	return prev
}

// NewProviderForTraceTest creates a Provider wired to the given ManualReader
// and an in-memory span exporter so tests can inspect both metrics and spans.
func NewProviderForTraceTest(reader *sdkmetric.ManualReader, exporter *tracetest.InMemoryExporter) (*Provider, error) {
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	m := mp.Meter("defenseclaw-test")

	ms, err := newMetricsSet(m)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)

	return &Provider{
		enabled:        true,
		meterProvider:  mp,
		meter:          m,
		metrics:        ms,
		tracerProvider: tp,
		tracer:         tp.Tracer("defenseclaw-test"),
		logger:         logNoop.NewLoggerProvider().Logger("test"),
	}, nil
}
