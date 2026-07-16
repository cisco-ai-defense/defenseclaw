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
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	compatibility "github.com/defenseclaw/defenseclaw/internal/observability/compatibility/galileo"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	galileodestination "github.com/defenseclaw/defenseclaw/internal/observability/destinations/galileo"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/localobservability"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/otlp"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const (
	generationPipelineCleanupTimeout = 5 * time.Second
	maxAcknowledgedCanaryTraceIDs    = 256
)

type otlpGenerationCandidate struct {
	destination config.ObservabilityV8EffectiveDestination
	signals     []observability.Signal
	canonical   bool
	galileo     bool
	local       bool
	metrics     map[string]struct{}
}

// OTLPGenerationPipelineFactory returns the process-stable callback installed
// in telemetry.V8ProviderOptions.GenerationPipelines. Every invocation prepares
// fresh children from the exact candidate plan and generation.
func (factory *Factory) OTLPGenerationPipelineFactory() telemetry.V8GenerationPipelineFactory {
	if factory == nil {
		return nil
	}
	return factory.PrepareOTLPGenerationPipelines
}

// PrepareOTLPGenerationPipelines assembles general OTLP trace/metric pipelines
// and generated canonical general/Galileo trace projections. Logs remain owned
// by DestinationAdapterFactory. Every generated trace route passes through the
// central router and redaction engine; no v8 destination falls back to raw SDK
// span export.
func (factory *Factory) PrepareOTLPGenerationPipelines(
	ctx context.Context,
	plan *config.ObservabilityV8Plan,
	generation uint64,
	metricSpec telemetry.V8MetricReaderSpec,
) (telemetry.V8GenerationPipelines, error) {
	if factory == nil || ctx == nil || plan == nil || generation == 0 ||
		nilInterface(factory.secrets) || nilInterface(factory.caLoader) ||
		nilInterface(factory.resolver) || nilInterface(factory.dialer) || nilInterface(factory.warnings) {
		return telemetry.V8GenerationPipelines{}, newError(ErrorInvalidDependencies)
	}
	if err := ctx.Err(); err != nil {
		return telemetry.V8GenerationPipelines{}, err
	}
	snapshot := plan.Snapshot()
	tracesCollected, metricsCollected := collectedSignals(snapshot.Buckets)
	candidates := make([]otlpGenerationCandidate, 0)
	traceCandidates := 0
	for _, displayed := range snapshot.Destinations {
		if displayed.Kind != config.ObservabilityV8DestinationOTLP {
			continue
		}
		destination, ok := plan.RuntimeDestination(displayed.Name)
		if !ok || !sameOTLPPlanIdentity(displayed, destination) {
			return telemetry.V8GenerationPipelines{}, newError(ErrorInvalidDestination)
		}
		if !destination.Enabled {
			continue
		}
		signals := make([]observability.Signal, 0, 2)
		if tracesCollected && effectiveDestinationSelectsSignal(destination, observability.SignalTraces) {
			signals = append(signals, observability.SignalTraces)
		}
		if metricsCollected && effectiveDestinationSelectsSignal(destination, observability.SignalMetrics) {
			signals = append(signals, observability.SignalMetrics)
		}
		if len(signals) == 0 {
			continue
		}
		if !validOTLPAssemblyDestination(destination, signals) {
			return telemetry.V8GenerationPipelines{}, newError(ErrorInvalidDestination)
		}
		candidate := otlpGenerationCandidate{
			destination: destination, signals: signals,
			// Destination identity is signal-independent. In particular, a
			// metrics-only local destination still needs the generated local
			// metric projection once canonical metric sinks are activated.
			local: isLocalObservabilityOTLP(destination),
		}
		if containsSignal(signals, observability.SignalTraces) {
			if destination.Preset == "galileo" && destination.PresetProfile == compatibility.ProfileID {
				candidate.galileo = true
			} else if !candidate.local {
				candidate.canonical = true
			}
			traceCandidates++
		}
		if containsSignal(signals, observability.SignalMetrics) {
			selected, err := compileOTLPMetricSelection(destination)
			if err != nil {
				return telemetry.V8GenerationPipelines{}, err
			}
			candidate.metrics = selected
		}
		candidates = append(candidates, candidate)
	}
	for _, candidate := range candidates {
		if containsSignal(candidate.signals, observability.SignalTraces) &&
			(candidate.galileo || candidate.local || candidate.canonical) &&
			(factory.redaction == nil || nilInterface(factory.redaction) || nilInterface(factory.deliveryObserver)) {
			return telemetry.V8GenerationPipelines{}, newError(ErrorInvalidDependencies)
		}
		if candidate.galileo && nilInterface(factory.galileoObserver) {
			return telemetry.V8GenerationPipelines{}, newError(ErrorInvalidDependencies)
		}
		if containsSignal(candidate.signals, observability.SignalTraces) &&
			candidate.local && nilInterface(factory.localObserver) {
			return telemetry.V8GenerationPipelines{}, newError(ErrorInvalidDependencies)
		}
		if candidate.canonical && nilInterface(factory.otlpObserver) {
			return telemetry.V8GenerationPipelines{}, newError(ErrorInvalidDependencies)
		}
	}

	pipelines := telemetry.V8GenerationPipelines{}
	var canaryRegistry *otlpGenerationCanaryRegistry
	if traceCandidates > 0 {
		var err error
		canaryRegistry, err = factory.registerOTLPCanaryRegistry(generation)
		if err != nil {
			return telemetry.V8GenerationPipelines{}, err
		}
		pipelines.CanaryAcknowledged = func(destination, traceID string) bool {
			return factory.OTLPGenerationAcknowledgedCanaryTrace(generation, destination, traceID)
		}
	}
	fail := func(err error) (telemetry.V8GenerationPipelines, error) {
		cleanupOTLPGenerationPipelines(pipelines)
		factory.unregisterOTLPCanaryRegistry(generation, canaryRegistry)
		if contextErr := ctx.Err(); contextErr != nil {
			return telemetry.V8GenerationPipelines{}, contextErr
		}
		return telemetry.V8GenerationPipelines{}, err
	}
	preparedWarnings := make([]config.ObservabilityV8EffectiveDestination, 0, len(candidates))
	var traceProjection *pipeline.TraceProjectionPipeline
	canonicalConsumers := make([]*galileodestination.CanonicalTraceConsumer, 0)
	localConsumers := make([]*localobservability.Consumer, 0)
	generalCanonicalConsumers := make([]*otlp.CanonicalTraceConsumer, 0)
	for _, candidate := range candidates {
		prepared, err := factory.prepareOTLPTelemetryFactory(
			ctx, candidate.destination, candidate.signals, metricSpec, canaryRegistry,
		)
		if err != nil {
			return fail(err)
		}
		if containsSignal(candidate.signals, observability.SignalTraces) && candidate.galileo {
			if traceProjection == nil {
				evaluator, evaluatorErr := router.New(plan)
				if evaluatorErr != nil {
					return fail(newError(ErrorAdapterPrepare))
				}
				traceProjection, err = pipeline.NewTraceProjectionPipeline(plan, evaluator, factory.redaction)
				if err != nil {
					return fail(newError(ErrorAdapterPrepare))
				}
			}
			adapter, adapterErr := galileodestination.NewAdapter(ctx, prepared)
			if adapterErr != nil {
				return fail(newError(ErrorAdapterPrepare))
			}
			dispatcher, valid := observabilityruntime.CompiledDispatcherConfig(
				candidate.destination, generation, observability.SignalTraces, factory.deliveryObserver,
			)
			if !valid {
				_ = closeGalileoAdapter(adapter)
				return fail(newError(ErrorInvalidDestination))
			}
			consumer, consumerErr := galileodestination.NewCanonicalTraceConsumer(
				galileodestination.CanonicalTraceConsumerOptions{
					Destination: candidate.destination, Generation: generation,
					Pipeline: traceProjection, Adapter: adapter, Dispatcher: dispatcher,
					Limits: galileoLimits(snapshot.TracePolicy), Observer: factory.galileoObserver,
				},
			)
			if consumerErr != nil {
				_ = closeGalileoAdapter(adapter)
				return fail(newError(ErrorAdapterPrepare))
			}
			canaryRegistry.addProcessor()
			registered := &canaryRegisteredCanonicalConsumer{
				V8CanonicalSpanConsumer: consumer,
				release:                 func() { factory.releaseOTLPCanaryProcessor(generation, canaryRegistry) },
			}
			pipelines.SpanPipelines = append(pipelines.SpanPipelines, telemetry.V8GenerationSpanPipeline{
				Destination: candidate.destination.Name, Canonical: registered,
			})
			pipelines.HealthSources = append(pipelines.HealthSources, registered)
			canonicalConsumers = append(canonicalConsumers, consumer)
		} else if containsSignal(candidate.signals, observability.SignalTraces) && candidate.local {
			if traceProjection == nil {
				evaluator, evaluatorErr := router.New(plan)
				if evaluatorErr != nil {
					return fail(newError(ErrorAdapterPrepare))
				}
				traceProjection, err = pipeline.NewTraceProjectionPipeline(plan, evaluator, factory.redaction)
				if err != nil {
					return fail(newError(ErrorAdapterPrepare))
				}
			}
			adapter, adapterErr := prepared.NewProjectedTraceAdapter(ctx, localobservability.RequestBuilder{})
			if adapterErr != nil {
				return fail(newError(ErrorAdapterPrepare))
			}
			dispatcher, valid := observabilityruntime.CompiledDispatcherConfig(
				candidate.destination, generation, observability.SignalTraces, factory.deliveryObserver,
			)
			if !valid {
				_ = closeOTLPCanonicalAdapter(adapter)
				return fail(newError(ErrorInvalidDestination))
			}
			consumer, consumerErr := localobservability.NewConsumer(localobservability.ConsumerOptions{
				Destination: candidate.destination, Generation: generation,
				Profile: localobservability.ProfileID, Pipeline: traceProjection,
				Adapter: adapter, Dispatcher: dispatcher, Observer: factory.localObserver,
			})
			if consumerErr != nil {
				_ = closeOTLPCanonicalAdapter(adapter)
				return fail(newError(ErrorAdapterPrepare))
			}
			canaryRegistry.addProcessor()
			registered := &canaryRegisteredCanonicalConsumer{
				V8CanonicalSpanConsumer: consumer,
				release:                 func() { factory.releaseOTLPCanaryProcessor(generation, canaryRegistry) },
			}
			pipelines.SpanPipelines = append(pipelines.SpanPipelines, telemetry.V8GenerationSpanPipeline{
				Destination: candidate.destination.Name, Canonical: registered,
			})
			pipelines.HealthSources = append(pipelines.HealthSources, registered)
			localConsumers = append(localConsumers, consumer)
		} else if containsSignal(candidate.signals, observability.SignalTraces) && candidate.canonical {
			if traceProjection == nil {
				evaluator, evaluatorErr := router.New(plan)
				if evaluatorErr != nil {
					return fail(newError(ErrorAdapterPrepare))
				}
				traceProjection, err = pipeline.NewTraceProjectionPipeline(plan, evaluator, factory.redaction)
				if err != nil {
					return fail(newError(ErrorAdapterPrepare))
				}
			}
			adapter, adapterErr := prepared.NewCanonicalTraceAdapter(ctx)
			if adapterErr != nil {
				return fail(newError(ErrorAdapterPrepare))
			}
			dispatcher, valid := observabilityruntime.CompiledDispatcherConfig(
				candidate.destination, generation, observability.SignalTraces, factory.deliveryObserver,
			)
			if !valid {
				_ = closeOTLPCanonicalAdapter(adapter)
				return fail(newError(ErrorInvalidDestination))
			}
			consumer, consumerErr := otlp.NewCanonicalTraceConsumer(otlp.CanonicalTraceConsumerOptions{
				Destination: candidate.destination, Generation: generation, Pipeline: traceProjection,
				Adapter: adapter, Dispatcher: dispatcher, Observer: factory.otlpObserver,
			})
			if consumerErr != nil {
				_ = closeOTLPCanonicalAdapter(adapter)
				return fail(newError(ErrorAdapterPrepare))
			}
			canaryRegistry.addProcessor()
			registered := &canaryRegisteredCanonicalConsumer{
				V8CanonicalSpanConsumer: consumer,
				release:                 func() { factory.releaseOTLPCanaryProcessor(generation, canaryRegistry) },
			}
			pipelines.SpanPipelines = append(pipelines.SpanPipelines, telemetry.V8GenerationSpanPipeline{
				Destination: candidate.destination.Name, Canonical: registered,
			})
			pipelines.HealthSources = append(pipelines.HealthSources, registered)
			generalCanonicalConsumers = append(generalCanonicalConsumers, consumer)
		}
		if candidate.metrics != nil {
			generatedFactory, forkErr := prepared.ForkMetricFactory()
			if forkErr != nil {
				return fail(newError(ErrorAdapterPrepare))
			}
			reader, err := prepared.NewFilteredPeriodicMetricReader(ctx, candidate.metrics)
			if err != nil {
				return fail(newError(ErrorAdapterPrepare))
			}
			sdkReader := reader.SDKReader()
			if sdkReader == nil {
				cleanupContext, cancel := context.WithTimeout(context.Background(), generationPipelineCleanupTimeout)
				_ = reader.Shutdown(cleanupContext)
				cancel()
				return fail(newError(ErrorAdapterPrepare))
			}
			pipelines.MetricReaders = append(pipelines.MetricReaders, sdkReader)
			families := selectedMetricFamilies(candidate.metrics)
			projection := telemetry.V8MetricProjectionCanonical
			if candidate.local {
				projection = telemetry.V8MetricProjectionLocal
			}
			destinationName := candidate.destination.Name
			pipelines.MetricPipelines = append(pipelines.MetricPipelines, telemetry.V8GenerationMetricPipeline{
				Destination: destinationName, Projection: projection,
				SelectedFamilies: append([]observability.EventName(nil), families...),
				SinkFactory: func(
					factory *otlp.Factory,
					selected []observability.EventName,
				) telemetry.V8CanonicalMetricSinkFactory {
					return func(
						factoryContext context.Context,
						resource telemetry.V8ResourceContext,
					) (telemetry.V8CanonicalMetricSink, error) {
						return factory.NewCanonicalMetricSink(factoryContext, otlp.CanonicalMetricSinkOptions{
							Destination: destinationName, Generation: generation,
							Resource: resource.SDKResource(), SelectedFamilies: selected,
							CardinalityLimit: metricSpec.CardinalityLimit,
						})
					}
				}(generatedFactory, append([]observability.EventName(nil), families...)),
			})
		}
		preparedWarnings = append(preparedWarnings, candidate.destination)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	for _, destination := range preparedWarnings {
		// Log-capable destinations already emit the same warning set when their
		// log adapter is prepared for this generation.
		if !effectiveDestinationSelectsLogs(destination) {
			factory.emitOTLPWarnings(destination,
				hasSecretHeaderReferences(destination.Transport.Headers) ||
					hasAuthenticationLikeCompiledHeader(destination.Transport.Headers))
		}
	}
	// Activation is deliberately the final side effect. No rejected candidate
	// can publish intake or start a canonical delivery worker.
	for _, consumer := range canonicalConsumers {
		consumer.Activate()
	}
	for _, consumer := range localConsumers {
		consumer.Activate()
	}
	for _, consumer := range generalCanonicalConsumers {
		consumer.Activate()
	}
	return pipelines, nil
}

func selectedMetricFamilies(selected map[string]struct{}) []observability.EventName {
	result := make([]observability.EventName, 0, len(selected))
	for name := range selected {
		result = append(result, observability.EventName(name))
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}

func isLocalObservabilityOTLP(destination config.ObservabilityV8EffectiveDestination) bool {
	return destination.Kind == config.ObservabilityV8DestinationOTLP &&
		destination.Name == localobservability.DestinationName
}

func sameOTLPPlanIdentity(displayed, runtime config.ObservabilityV8EffectiveDestination) bool {
	return displayed.Name == runtime.Name && displayed.Kind == runtime.Kind &&
		displayed.Enabled == runtime.Enabled && displayed.Preset == runtime.Preset &&
		displayed.PresetProfile == runtime.PresetProfile &&
		displayed.PolicyForm == runtime.PolicyForm &&
		displayed.FirstMatchPerSignal == runtime.FirstMatchPerSignal &&
		reflect.DeepEqual(displayed.Capabilities, runtime.Capabilities) &&
		reflect.DeepEqual(displayed.CompatibilityProfiles, runtime.CompatibilityProfiles) &&
		reflect.DeepEqual(displayed.SelectedSignals, runtime.SelectedSignals) &&
		reflect.DeepEqual(displayed.Routes, runtime.Routes)
}

func (factory *Factory) prepareOTLPTelemetryFactory(
	ctx context.Context,
	destination config.ObservabilityV8EffectiveDestination,
	signals []observability.Signal,
	metricSpec telemetry.V8MetricReaderSpec,
	canary otlp.CanaryAcknowledgementObserver,
) (*otlp.Factory, error) {
	headers, err := factory.resolveHeaders(destination.Transport.Headers)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := factory.loadOTLPTLS(ctx, destination.Transport.TLS)
	if err != nil {
		return nil, err
	}
	overrides := make(map[observability.Signal]otlp.SignalOverride, len(signals))
	for _, signal := range signals {
		if source, ok := destination.Transport.SignalOverrides[signal]; ok {
			overrides[signal] = otlp.SignalOverride{Endpoint: source.Endpoint, Path: source.Path}
		}
	}
	batch := destination.Transport.Batch
	network := destination.Transport.NetworkSafety
	return prepareOTLPSafely(ctx, otlp.Config{
		Destination:    destination.Name,
		Protocol:       destination.Transport.Protocol,
		Endpoint:       destination.Transport.Endpoint,
		Selected:       append([]observability.Signal(nil), signals...),
		SignalOverride: overrides,
		Headers:        headers,
		LoggerName:     destination.Transport.LoggerName,
		Timeout:        time.Duration(destination.Transport.TimeoutMS) * time.Millisecond,
		TLS:            tlsConfig,
		NetworkSafety: otlp.NetworkSafety{
			AllowPrivateNetworks: network.AllowPrivateNetworks,
			AllowCGNAT:           network.AllowCGNAT,
		},
		Batch: otlp.BatchConfig{
			MaxQueueSize:        batch.MaxQueueSize,
			MaxQueueBytes:       batch.MaxQueueBytes,
			MaxExportBatchSize:  batch.MaxExportBatchSize,
			MaxExportBatchBytes: batch.MaxExportBatchBytes,
			ScheduledDelay:      time.Duration(batch.ScheduledDelayMS) * time.Millisecond,
			ExportInterval:      metricSpec.ExportInterval,
			ExportTimeout:       metricSpec.ExportTimeout,
		},
	}, otlp.Dependencies{
		Resolver: factory.resolver,
		Dialer:   factory.dialer,
		TemporalitySelector: func(sdkmetric.InstrumentKind) metricdata.Temporality {
			return metricSpec.Temporality
		},
		CanaryObserver: canary,
	})
}

func collectedSignals(buckets []config.ObservabilityV8EffectiveBucket) (bool, bool) {
	traces, metrics := false, false
	for _, bucket := range buckets {
		traces = traces || bucket.Collect.Traces
		metrics = metrics || bucket.Collect.Metrics
	}
	return traces, metrics
}

func validOTLPAssemblyDestination(destination config.ObservabilityV8EffectiveDestination, signals []observability.Signal) bool {
	if !observability.IsStableToken(destination.Name) || !validQueue(destination.Transport.Batch) ||
		!validOTLPTransport(destination.Transport, signals) {
		return false
	}
	for _, signal := range signals {
		if !destination.Capabilities.Supports(signal) || !effectiveDestinationSelectsSignal(destination, signal) {
			return false
		}
	}
	return true
}

func effectiveDestinationSelectsSignal(destination config.ObservabilityV8EffectiveDestination, signal observability.Signal) bool {
	return containsSignal(destination.SelectedSignals, signal)
}

func containsSignal(signals []observability.Signal, expected observability.Signal) bool {
	for _, signal := range signals {
		if signal == expected {
			return true
		}
	}
	return false
}

func compileOTLPTraceFilter(destination config.ObservabilityV8EffectiveDestination) (otlp.SpanFilter, error) {
	if destination.Preset == "galileo" || destination.PresetProfile != "" {
		return nil, newError(ErrorUnsupportedPolicy)
	}
	matcher, err := compileOTLPBucketMatcher(destination, observability.SignalTraces, true)
	if err != nil {
		return nil, err
	}
	destinationName := destination.Name
	return func(span sdktrace.ReadOnlySpan) bool {
		if span == nil {
			return false
		}
		var bucket observability.Bucket
		var canaryDestination string
		for _, item := range span.Attributes() {
			if item.Value.Type() != attribute.STRING {
				continue
			}
			switch string(item.Key) {
			case "defenseclaw.bucket":
				bucket = observability.Bucket(item.Value.AsString())
			case "defenseclaw.telemetry.canary.destination":
				canaryDestination = item.Value.AsString()
			}
		}
		if canaryDestination != "" && canaryDestination != destinationName {
			return false
		}
		return observability.IsBucket(bucket) && matcher(bucket)
	}, nil
}

func compileOTLPMetricSelection(destination config.ObservabilityV8EffectiveDestination) (map[string]struct{}, error) {
	routes := make([]config.ObservabilityV8EffectiveRoute, 0, len(destination.Routes))
	for _, route := range destination.Routes {
		if !containsSignal(route.Signals, observability.SignalMetrics) {
			continue
		}
		selector := route.Selector
		if len(selector.Sources) != 0 || len(selector.Connectors) != 0 || len(selector.Actions) != 0 ||
			selector.MinSeverity != "" {
			return nil, newError(ErrorUnsupportedPolicy)
		}
		if route.Action != config.ObservabilityV8RouteSend && route.Action != config.ObservabilityV8RouteDrop {
			return nil, newError(ErrorUnsupportedPolicy)
		}
		routes = append(routes, route)
	}
	if len(routes) == 0 {
		return nil, newError(ErrorUnsupportedPolicy)
	}
	selected := make(map[string]struct{})
	for _, definition := range telemetry.V8MetricCatalog() {
		for _, route := range routes {
			if !selectorMatchesMetric(route.Selector, definition) {
				continue
			}
			if route.Action == config.ObservabilityV8RouteSend {
				selected[definition.Name] = struct{}{}
			}
			break
		}
	}
	return selected, nil
}

func selectorMatchesMetric(
	selector config.ObservabilityV8EffectiveSelector,
	definition telemetry.V8MetricDefinition,
) bool {
	if !selectorMatchesBucket(selector, definition.Bucket) {
		return false
	}
	if len(selector.EventNames) == 0 {
		return true
	}
	for _, eventName := range selector.EventNames {
		if eventName == "*" || string(eventName) == definition.Name {
			return true
		}
	}
	return false
}

func compileOTLPBucketMatcher(
	destination config.ObservabilityV8EffectiveDestination,
	signal observability.Signal,
	requireNoRedaction bool,
) (func(observability.Bucket) bool, error) {
	routes := make([]config.ObservabilityV8EffectiveRoute, 0, len(destination.Routes))
	for _, route := range destination.Routes {
		if !containsSignal(route.Signals, signal) {
			continue
		}
		selector := route.Selector
		if len(selector.Sources) != 0 || len(selector.Connectors) != 0 || len(selector.Actions) != 0 ||
			len(selector.EventNames) != 0 || selector.MinSeverity != "" {
			return nil, newError(ErrorUnsupportedPolicy)
		}
		if requireNoRedaction && route.Action == config.ObservabilityV8RouteSend {
			if len(route.RedactionProfileByBucket) == 0 {
				return nil, newError(ErrorUnsupportedPolicy)
			}
			for _, profile := range route.RedactionProfileByBucket {
				if profile != "none" {
					return nil, newError(ErrorUnsupportedPolicy)
				}
			}
		}
		if route.Action != config.ObservabilityV8RouteSend && route.Action != config.ObservabilityV8RouteDrop {
			return nil, newError(ErrorUnsupportedPolicy)
		}
		routes = append(routes, route)
	}
	if len(routes) == 0 {
		return nil, newError(ErrorUnsupportedPolicy)
	}
	return func(bucket observability.Bucket) bool {
		for _, route := range routes {
			if !selectorMatchesBucket(route.Selector, bucket) {
				continue
			}
			return route.Action == config.ObservabilityV8RouteSend
		}
		return false
	}, nil
}

func selectorMatchesBucket(selector config.ObservabilityV8EffectiveSelector, bucket observability.Bucket) bool {
	if selector.BucketWildcard {
		return true
	}
	for _, candidate := range selector.Buckets {
		if candidate == bucket {
			return true
		}
	}
	return false
}

func galileoLimits(policy config.ObservabilityV8EffectiveTracePolicy) compatibility.Limits {
	limits := policy.Limits
	return compatibility.Limits{
		MaxAttributesPerSpan:   limits.MaxAttributesPerSpan,
		MaxEventsPerSpan:       limits.MaxEventsPerSpan,
		MaxLinksPerSpan:        limits.MaxLinksPerSpan,
		MaxAttributesPerEvent:  limits.MaxAttributesPerEvent,
		MaxAttributeValueBytes: limits.MaxAttributeValueBytes,
		MaxProjectedSpanBytes:  limits.MaxProjectedSpanBytes,
		MaxMessageItems:        limits.MaxMessageItems,
	}
}

func closeGalileoAdapter(adapter *galileodestination.Adapter) error {
	ctx, cancel := context.WithTimeout(context.Background(), generationPipelineCleanupTimeout)
	defer cancel()
	return adapter.Close(ctx)
}

func closeOTLPCanonicalAdapter(adapter *otlp.ProjectedTraceAdapter) error {
	ctx, cancel := context.WithTimeout(context.Background(), generationPipelineCleanupTimeout)
	defer cancel()
	return adapter.Close(ctx)
}

type canaryRegisteredCanonicalConsumer struct {
	telemetry.V8CanonicalSpanConsumer
	releaseOnce sync.Once
	release     func()
}

func (consumer *canaryRegisteredCanonicalConsumer) DeliveryHealthSnapshot() delivery.HealthSnapshot {
	if consumer == nil || consumer.V8CanonicalSpanConsumer == nil {
		return delivery.HealthSnapshot{State: delivery.HealthStopped}
	}
	source, ok := consumer.V8CanonicalSpanConsumer.(delivery.SnapshotSource)
	if !ok || source == nil {
		return delivery.HealthSnapshot{}
	}
	return source.DeliveryHealthSnapshot()
}

func (consumer *canaryRegisteredCanonicalConsumer) Shutdown(ctx context.Context) error {
	if consumer == nil || consumer.V8CanonicalSpanConsumer == nil {
		return nil
	}
	if err := consumer.V8CanonicalSpanConsumer.Shutdown(ctx); err != nil {
		return err
	}
	consumer.releaseOnce.Do(func() {
		if consumer.release != nil {
			consumer.release()
		}
	})
	return nil
}

func cleanupOTLPGenerationPipelines(pipelines telemetry.V8GenerationPipelines) {
	ctx, cancel := context.WithTimeout(context.Background(), generationPipelineCleanupTimeout)
	defer cancel()
	seen := make(map[otlpCleanupIdentity]struct{}, len(pipelines.MetricPipelines)+len(pipelines.SpanPipelines)*2)
	for index := len(pipelines.MetricPipelines) - 1; index >= 0; index-- {
		sink := pipelines.MetricPipelines[index].Sink
		if otlpCleanupChild(sink, seen) {
			otlpCleanupShutdown(func() error { return sink.Shutdown(ctx) })
		}
	}
	for index := len(pipelines.MetricReaders) - 1; index >= 0; index-- {
		if pipelines.MetricReaders[index] != nil {
			_ = pipelines.MetricReaders[index].Shutdown(ctx)
		}
	}
	for index := len(pipelines.SpanPipelines) - 1; index >= 0; index-- {
		pipeline := pipelines.SpanPipelines[index]
		if otlpCleanupChild(pipeline.Canonical, seen) {
			otlpCleanupShutdown(func() error { return pipeline.Canonical.Shutdown(ctx) })
		}
	}
}

func otlpCleanupShutdown(shutdown func() error) {
	defer func() { _ = recover() }()
	_ = shutdown()
}

type otlpCleanupIdentity struct {
	typeName string
	pointer  uintptr
}

func otlpCleanupChild(value any, seen map[otlpCleanupIdentity]struct{}) bool {
	if value == nil {
		return false
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() == reflect.Pointer {
		if reflected.IsNil() {
			return false
		}
		identity := otlpCleanupIdentity{typeName: reflected.Type().String(), pointer: reflected.Pointer()}
		if _, duplicate := seen[identity]; duplicate {
			return false
		}
		seen[identity] = struct{}{}
	}
	return true
}

func hasAuthenticationLikeCompiledHeader(headers map[string]config.ObservabilityV8HeaderValue) bool {
	for name := range headers {
		if hasAuthenticationLikeHeader(map[string]string{name: ""}) {
			return true
		}
	}
	return false
}

type otlpGenerationCanaryRegistry struct {
	mu         sync.RWMutex
	processors int
	ack        map[string]map[string]struct{}
	order      map[string][]string
}

func (registry *otlpGenerationCanaryRegistry) ObserveOTLPCanaryAcknowledgement(event otlp.CanaryAcknowledgement) {
	if registry == nil || !observability.IsStableToken(event.Destination) {
		return
	}
	if _, err := trace.TraceIDFromHex(event.TraceID); err != nil {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.ack == nil {
		registry.ack = make(map[string]map[string]struct{})
	}
	registry.ack[event.Destination] = nonNilTraceSet(registry.ack[event.Destination])
	if _, exists := registry.ack[event.Destination][event.TraceID]; exists {
		return
	}
	registry.ack[event.Destination][event.TraceID] = struct{}{}
	if registry.order == nil {
		registry.order = make(map[string][]string)
	}
	registry.order[event.Destination] = append(registry.order[event.Destination], event.TraceID)
	for len(registry.order[event.Destination]) > maxAcknowledgedCanaryTraceIDs {
		oldest := registry.order[event.Destination][0]
		registry.order[event.Destination] = registry.order[event.Destination][1:]
		delete(registry.ack[event.Destination], oldest)
	}
}

func nonNilTraceSet(source map[string]struct{}) map[string]struct{} {
	if source == nil {
		return make(map[string]struct{})
	}
	return source
}

func (registry *otlpGenerationCanaryRegistry) addProcessor() {
	registry.mu.Lock()
	registry.processors++
	registry.mu.Unlock()
}

func (registry *otlpGenerationCanaryRegistry) releaseProcessor() int {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.processors > 0 {
		registry.processors--
	}
	return registry.processors
}

func (registry *otlpGenerationCanaryRegistry) acknowledged(destination, traceID string) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	_, ok := registry.ack[destination][traceID]
	return ok
}

func (factory *Factory) registerOTLPCanaryRegistry(generation uint64) (*otlpGenerationCanaryRegistry, error) {
	registry := &otlpGenerationCanaryRegistry{}
	factory.canaryMu.Lock()
	defer factory.canaryMu.Unlock()
	if factory.canary == nil {
		factory.canary = make(map[uint64]*otlpGenerationCanaryRegistry)
	}
	if _, exists := factory.canary[generation]; exists {
		return nil, newError(ErrorAdapterPrepare)
	}
	factory.canary[generation] = registry
	return registry, nil
}

func (factory *Factory) unregisterOTLPCanaryRegistry(generation uint64, expected *otlpGenerationCanaryRegistry) {
	if factory == nil || expected == nil {
		return
	}
	factory.canaryMu.Lock()
	if factory.canary[generation] == expected {
		delete(factory.canary, generation)
	}
	factory.canaryMu.Unlock()
}

func (factory *Factory) releaseOTLPCanaryProcessor(generation uint64, registry *otlpGenerationCanaryRegistry) {
	if registry != nil && registry.releaseProcessor() == 0 {
		factory.unregisterOTLPCanaryRegistry(generation, registry)
	}
}

// OTLPGenerationAcknowledgedCanaryTrace is the generation-bound query seam for
// a future Provider.DestinationAcknowledgedCanaryTrace bridge. It cannot report
// acknowledgements after the owning processors have shut down.
func (factory *Factory) OTLPGenerationAcknowledgedCanaryTrace(generation uint64, destination, traceID string) bool {
	if factory == nil || generation == 0 || !observability.IsStableToken(destination) {
		return false
	}
	if _, err := trace.TraceIDFromHex(traceID); err != nil {
		return false
	}
	factory.canaryMu.RLock()
	registry := factory.canary[generation]
	factory.canaryMu.RUnlock()
	return registry != nil && registry.acknowledged(destination, traceID)
}

type canaryRegisteredSpanProcessor struct {
	sdktrace.SpanProcessor
	mu          sync.Mutex
	shutdown    bool
	releaseOnce sync.Once
	release     func()
}

func (processor *canaryRegisteredSpanProcessor) Shutdown(ctx context.Context) error {
	processor.mu.Lock()
	if processor.shutdown {
		processor.mu.Unlock()
		return nil
	}
	processor.shutdown = true
	processor.mu.Unlock()
	err := processor.SpanProcessor.Shutdown(ctx)
	if terminal, ok := processor.SpanProcessor.(interface{ TerminalDone() <-chan struct{} }); ok {
		done := terminal.TerminalDone()
		select {
		case <-done:
			processor.releaseTerminalOwnership()
		default:
			go func() {
				<-done
				processor.releaseTerminalOwnership()
			}()
		}
	} else {
		processor.releaseTerminalOwnership()
	}
	return err
}

func (processor *canaryRegisteredSpanProcessor) releaseTerminalOwnership() {
	processor.releaseOnce.Do(func() {
		if processor.release != nil {
			processor.release()
		}
	})
}
