// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package destinations

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/prometheus"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// GenerationPipelineFactory returns the one process-stable signal-pipeline
// callback installed on telemetry.V8ProviderOptions. Each invocation prepares
// independent OTLP processors/readers and native Prometheus legacy/generated
// bridge pipelines from the exact candidate plan, generation, context, and
// metric policy supplied by the runtime graph. It never installs an OTel or
// Prometheus process global.
func (factory *Factory) GenerationPipelineFactory(
	prometheusOptions prometheus.Options,
) telemetry.V8GenerationPipelineFactory {
	if factory == nil {
		return nil
	}
	return func(
		ctx context.Context,
		plan *config.ObservabilityV8Plan,
		generation uint64,
		metricSpec telemetry.V8MetricReaderSpec,
	) (telemetry.V8GenerationPipelines, error) {
		return factory.PrepareGenerationPipelines(
			ctx, plan, generation, metricSpec, prometheusOptions,
		)
	}
}

// PrepareGenerationPipelines composes all currently implemented v8 trace and
// metric destination transports into one generation-owned set. OTLP is
// prepared first because it owns the canary acknowledgement callback. If
// Prometheus preparation or a final context check fails, every prepared OTLP
// processor/reader and every prepared Prometheus reader/generated sink is
// released before the rejected candidate returns.
func (factory *Factory) PrepareGenerationPipelines(
	ctx context.Context,
	plan *config.ObservabilityV8Plan,
	generation uint64,
	metricSpec telemetry.V8MetricReaderSpec,
	prometheusOptions prometheus.Options,
) (telemetry.V8GenerationPipelines, error) {
	pipelines, err := factory.PrepareOTLPGenerationPipelines(ctx, plan, generation, metricSpec)
	if err != nil {
		return telemetry.V8GenerationPipelines{}, err
	}
	fail := func(err error) (telemetry.V8GenerationPipelines, error) {
		cleanupOTLPGenerationPipelines(pipelines)
		return telemetry.V8GenerationPipelines{}, err
	}

	prometheusPipelines, err := prometheus.PreparePlanPipelines(
		ctx, plan, generation, metricSpec, prometheusOptions,
	)
	if err != nil {
		return fail(err)
	}
	pipelines.MetricReaders = append(pipelines.MetricReaders, prometheusPipelines.MetricReaders...)
	pipelines.MetricPipelines = append(pipelines.MetricPipelines, prometheusPipelines.MetricPipelines...)
	pipelines.HealthSources = append(pipelines.HealthSources, prometheusPipelines.HealthSources...)
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return pipelines, nil
}
