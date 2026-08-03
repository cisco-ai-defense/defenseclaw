// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	metricgrpc "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	metrichttp "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc"
)

// ForkMetricFactory creates a claim-independent metric transport factory from
// the already resolved immutable configuration. The fork owns a fresh dial
// tracker and exporter/reader lifecycle, while TLS, headers, endpoint policy,
// temporality, and batch settings remain exact clones of the parent.
func (factory *Factory) ForkMetricFactory() (*Factory, error) {
	if factory == nil {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	factory.mu.Lock()
	defer factory.mu.Unlock()
	config, ok := factory.signals[observability.SignalMetrics]
	if !ok || factory.created[observability.SignalMetrics] {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	clone := config
	clone.url = cloneURL(config.url)
	clone.tls = cloneTLS(config.tls)
	clone.headers = cloneHeaders(config.headers)
	clone.tracker = &dialOutcomeTracker{}
	outer := factory.config
	outer.Selected = []observability.Signal{observability.SignalMetrics}
	outer.Headers = cloneHeaders(factory.config.Headers)
	return &Factory{
		config:  outer,
		signals: map[observability.Signal]signalConfig{observability.SignalMetrics: clone},
		created: make(map[observability.Signal]bool, 1),
	}, nil
}

func (factory *Factory) NewMetricExporter(ctx context.Context) (*MetricExporter, error) {
	if ctx == nil {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	config, err := factory.claim(observability.SignalMetrics)
	if err != nil {
		return nil, err
	}
	circuit, err := delivery.NewCircuit(delivery.CircuitPolicy{})
	if err != nil {
		return nil, newError(ErrorInitialization, err)
	}
	if config.protocol == ProtocolHTTP {
		initialRetry, maximumRetry := retryBounds(config.timeout)
		client, transport := newHTTPClient(config)
		exporter, buildErr := metrichttp.New(ctx,
			metrichttp.WithEndpointURL(signalURL(config)),
			metrichttp.WithURLPath(config.path),
			metrichttp.WithHeaders(cloneHeaders(config.headers)),
			metrichttp.WithTimeout(config.timeout),
			metrichttp.WithCompression(metrichttp.NoCompression),
			metrichttp.WithRetry(metrichttp.RetryConfig{
				Enabled: true, InitialInterval: initialRetry,
				MaxInterval: maximumRetry, MaxElapsedTime: config.timeout,
			}),
			metrichttp.WithHTTPClient(client),
			metrichttp.WithTemporalitySelector(config.temporality),
			metrichttp.WithAggregationSelector(config.aggregation),
		)
		if buildErr != nil {
			closeHTTPTransport(transport)
			return nil, newError(ErrorInitialization, buildErr)
		}
		return &MetricExporter{
			inner: exporter, httpTransport: transport,
			maxBytes: factory.config.Batch.MaxExportBatchBytes, config: config,
			circuit: circuit, now: time.Now,
		}, nil
	}
	connection, err := newGRPCConnection(config)
	if err != nil {
		return nil, err
	}
	initialRetry, maximumRetry := retryBounds(config.timeout)
	exporter, buildErr := metricgrpc.New(ctx,
		metricgrpc.WithGRPCConn(connection),
		metricgrpc.WithHeaders(cloneHeaders(config.headers)),
		metricgrpc.WithTimeout(config.timeout),
		metricgrpc.WithRetry(metricgrpc.RetryConfig{
			Enabled: true, InitialInterval: initialRetry,
			MaxInterval: maximumRetry, MaxElapsedTime: config.timeout,
		}),
		metricgrpc.WithTemporalitySelector(config.temporality),
		metricgrpc.WithAggregationSelector(config.aggregation),
	)
	if buildErr != nil {
		_ = connection.Close()
		return nil, newError(ErrorInitialization, buildErr)
	}
	return &MetricExporter{
		inner: exporter, connection: connection,
		maxBytes: factory.config.Batch.MaxExportBatchBytes, config: config,
		circuit: circuit, now: time.Now,
	}, nil
}

// MetricReader owns one independently shutdown periodic metric pipeline. Its
// SDKReader is registered with a MeterProvider without any package-global
// mutation; ForceFlush and Shutdown remain destination-local. Metric retry and
// backpressure stay in the SDK exporter/reader contract instead of adding a
// second DefenseClaw queue; MetricExporter still exposes final failure and
// per-item retry counts through its content-free counters and observer.
type MetricReader struct {
	reader           *sdkmetric.PeriodicReader
	exporter         *MetricExporter
	destination      string
	mu               sync.RWMutex
	closed           bool
	healthGeneration uint64
}

func (factory *Factory) NewPeriodicMetricReader(ctx context.Context) (*MetricReader, error) {
	return factory.newPeriodicMetricReader(ctx, nil)
}

// NewFilteredPeriodicMetricReader filters the immutable SDK collection by the
// exact selected metric-name set before encoding. The input set is detached.
func (factory *Factory) NewFilteredPeriodicMetricReader(ctx context.Context, selected map[string]struct{}) (*MetricReader, error) {
	if selected == nil {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	detached := make(map[string]struct{}, len(selected))
	for name := range selected {
		detached[name] = struct{}{}
	}
	return factory.newPeriodicMetricReader(ctx, detached)
}

func (factory *Factory) newPeriodicMetricReader(ctx context.Context, selected map[string]struct{}) (*MetricReader, error) {
	exporter, err := factory.NewMetricExporter(ctx)
	if err != nil {
		return nil, err
	}
	interval := factory.config.Batch.ExportInterval
	if interval <= 0 {
		cleanup, cancel := cleanupContext(ctx, factory.config.Timeout)
		_ = exporter.Shutdown(cleanup)
		cancel()
		return nil, newError(ErrorInvalidConfig, nil)
	}
	var sdkExporter sdkmetric.Exporter = exporter
	if selected != nil {
		sdkExporter = &filteredMetricExporter{inner: exporter, selected: selected}
	}
	options := []sdkmetric.PeriodicReaderOption{sdkmetric.WithInterval(interval)}
	if timeout := factory.config.Batch.ExportTimeout; timeout > 0 {
		options = append(options, sdkmetric.WithTimeout(timeout))
	}
	return &MetricReader{
		reader: sdkmetric.NewPeriodicReader(sdkExporter, options...), exporter: exporter,
		destination: factory.config.Destination,
	}, nil
}

type metricReaderHealthSource struct {
	reader     *MetricReader
	generation uint64
}

// DeliveryHealthSource binds this already generation-owned reader to the
// provider generation without exposing its SDK reader or exporter.
func (reader *MetricReader) DeliveryHealthSource(generation uint64) (delivery.SnapshotSource, error) {
	if reader == nil || reader.exporter == nil || generation == 0 ||
		!observability.IsStableToken(reader.destination) {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.healthGeneration != 0 && reader.healthGeneration != generation {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	reader.healthGeneration = generation
	return &metricReaderHealthSource{reader: reader, generation: generation}, nil
}

func (source *metricReaderHealthSource) DeliveryHealthSnapshot() delivery.HealthSnapshot {
	if source == nil || source.reader == nil || source.reader.exporter == nil {
		return delivery.HealthSnapshot{State: delivery.HealthStopped}
	}
	snapshot := source.reader.exporter.deliveryHealthSnapshot()
	snapshot.Destination = source.reader.destination
	snapshot.Generation = source.generation
	snapshot.Signal = string(observability.SignalMetrics)
	return snapshot
}

type filteredMetricExporter struct {
	inner    *MetricExporter
	selected map[string]struct{}
}

func (exporter *filteredMetricExporter) Temporality(kind sdkmetric.InstrumentKind) metricdata.Temporality {
	return exporter.inner.Temporality(kind)
}

func (exporter *filteredMetricExporter) Aggregation(kind sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return exporter.inner.Aggregation(kind)
}

func (exporter *filteredMetricExporter) Export(ctx context.Context, source *metricdata.ResourceMetrics) error {
	if source == nil {
		return exporter.inner.Export(ctx, source)
	}
	filtered := &metricdata.ResourceMetrics{Resource: source.Resource}
	filtered.ScopeMetrics = make([]metricdata.ScopeMetrics, 0, len(source.ScopeMetrics))
	for _, sourceScope := range source.ScopeMetrics {
		scope := metricdata.ScopeMetrics{Scope: sourceScope.Scope}
		scope.Metrics = make([]metricdata.Metrics, 0, len(sourceScope.Metrics))
		for _, metric := range sourceScope.Metrics {
			if _, ok := exporter.selected[metric.Name]; ok {
				scope.Metrics = append(scope.Metrics, metric)
			}
		}
		if len(scope.Metrics) > 0 {
			filtered.ScopeMetrics = append(filtered.ScopeMetrics, scope)
		}
	}
	if len(filtered.ScopeMetrics) == 0 {
		return nil
	}
	return exporter.inner.Export(ctx, filtered)
}

func (exporter *filteredMetricExporter) ForceFlush(ctx context.Context) error {
	return exporter.inner.ForceFlush(ctx)
}

func (exporter *filteredMetricExporter) Shutdown(ctx context.Context) error {
	return exporter.inner.Shutdown(ctx)
}

func (reader *MetricReader) SDKReader() sdkmetric.Reader {
	if reader == nil {
		return nil
	}
	return reader.reader
}

func (reader *MetricReader) ForceFlush(ctx context.Context) error {
	if reader == nil || reader.reader == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorFlush, nil)
	}
	reader.mu.RLock()
	defer reader.mu.RUnlock()
	if reader.closed {
		return newError(ErrorFlush, nil)
	}
	if err := reader.reader.ForceFlush(ctx); err != nil {
		return newError(ErrorFlush, err)
	}
	return nil
}

func (reader *MetricReader) Shutdown(ctx context.Context) error {
	if reader == nil || reader.reader == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorShutdown, nil)
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.closed {
		return nil
	}
	reader.closed = true
	if err := reader.reader.Shutdown(ctx); err != nil && !errors.Is(err, sdkmetric.ErrReaderShutdown) {
		return newError(ErrorShutdown, err)
	}
	return nil
}

type MetricExporter struct {
	inner         sdkmetric.Exporter
	connection    *grpc.ClientConn
	httpTransport *http.Transport
	config        signalConfig
	maxBytes      int
	counters      mutableCounters
	mu            sync.RWMutex
	closed        bool
	healthMu      sync.Mutex
	health        delivery.HealthState
	healthReason  delivery.HealthReason
	lastSuccess   time.Time
	lastFailure   time.Time
	circuit       *delivery.Circuit
	now           func() time.Time
}

func (exporter *MetricExporter) Temporality(kind sdkmetric.InstrumentKind) metricdata.Temporality {
	return exporter.inner.Temporality(kind)
}

func (exporter *MetricExporter) Aggregation(kind sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return exporter.inner.Aggregation(kind)
}

// Export preflights a strict conservative protobuf bound before invoking the
// SDK exporter, so an oversized collection is rejected before the SDK allocates
// its OTLP request. A ResourceMetrics collection is intentionally not split:
// partitioning cumulative/delta streams outside the SDK reader can change
// temporality and reset semantics. Counters and the observer expose that
// bounded rejection to destination health without retaining metric content.
func (exporter *MetricExporter) Export(ctx context.Context, metrics *metricdata.ResourceMetrics) error {
	if exporter == nil || ctx == nil {
		return newError(ErrorExport, nil)
	}
	exporter.mu.RLock()
	locked := true
	probePending := false
	unlock := func() {
		if locked {
			exporter.mu.RUnlock()
			locked = false
		}
	}
	defer func() {
		if probePending && exporter.circuit.AbortProbe() {
			exporter.setHealth(delivery.HealthFailing, delivery.HealthReasonCircuitOpen)
		}
		unlock()
	}()
	closed := exporter.closed
	if closed {
		unlock()
		return newError(ErrorExport, nil)
	}
	now := exporter.nowUTC()
	switch exporter.circuit.Admit(now) {
	case delivery.CircuitAdmissionBlocked:
		exporter.counters.circuitRejectedBatches.Add(1)
		unlock()
		// The circuit health snapshot and rejection counter remain the
		// authoritative failure signal. Returning an error here would make the
		// SDK PeriodicReader invoke the global OTel error handler on every
		// collection interval while the circuit is open (24 hours for an
		// authentication failure), producing an unbounded log loop even though
		// no export work is attempted.
		return nil
	case delivery.CircuitAdmissionProbe:
		probePending = true
		exporter.setHealth(delivery.HealthDegraded, delivery.HealthReasonCircuitHalfOpen)
	}
	count := metricCount(metrics)
	bound, ok := conservativeMetricBytes(metrics)
	if !ok || bound > exporter.maxBytes {
		if probePending {
			exporter.circuit.AbortProbe()
			probePending = false
		}
		exporter.counters.rejectedOversize.Add(count)
		exporter.recordHealth(delivery.HealthFailing, delivery.HealthReasonDeliveryFailed, false)
		unlock()
		observe(exporter.config.observer, SignalEvent{Signal: observability.SignalMetrics, Outcome: SignalOutcomeRejectedOversize, Count: count})
		return newError(ErrorExport, nil)
	}
	exporter.counters.accepted.Add(count)
	dialSequence := exporter.config.tracker.snapshot()
	attemptContext, attempts := withAttemptCounter(ctx)
	err := exporter.inner.Export(attemptContext, metrics)
	if err != nil {
		exporter.counters.failed.Add(count)
		class := otlpFailureClass(exporter.config.tracker, dialSequence, err)
		exporter.recordCircuitFailure(class, exporter.nowUTC())
		probePending = false
		unlock()
		recordRetryAttempts(&exporter.counters, exporter.config.observer, observability.SignalMetrics, count, attempts.Load())
		observe(exporter.config.observer, SignalEvent{Signal: observability.SignalMetrics, Outcome: SignalOutcomeExportFailed, Count: count})
		if class == delivery.FailureClassUnsafeEndpoint {
			return newError(ErrorUnsafeEndpoint, err)
		}
		return newError(ErrorExport, err)
	}
	exporter.counters.exported.Add(count)
	exporter.circuit.RecordSuccess()
	probePending = false
	exporter.recordHealth(delivery.HealthHealthy, delivery.HealthReasonRecovered, true)
	unlock()
	recordRetryAttempts(&exporter.counters, exporter.config.observer, observability.SignalMetrics, count, attempts.Load())
	observe(exporter.config.observer, SignalEvent{Signal: observability.SignalMetrics, Outcome: SignalOutcomeExported, Count: count})
	return nil
}

func (exporter *MetricExporter) ForceFlush(ctx context.Context) error {
	if exporter == nil || ctx == nil {
		return newError(ErrorFlush, nil)
	}
	exporter.mu.RLock()
	defer exporter.mu.RUnlock()
	if exporter.closed {
		return newError(ErrorFlush, nil)
	}
	if err := exporter.inner.ForceFlush(ctx); err != nil {
		return newError(ErrorFlush, err)
	}
	return nil
}

func (exporter *MetricExporter) Shutdown(ctx context.Context) error {
	if exporter == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorShutdown, nil)
	}
	exporter.mu.Lock()
	if exporter.closed {
		exporter.mu.Unlock()
		return nil
	}
	exporter.closed = true
	exporter.mu.Unlock()
	err := exporter.inner.Shutdown(ctx)
	closeHTTPTransport(exporter.httpTransport)
	if exporter.connection != nil {
		if closeErr := exporter.connection.Close(); err == nil {
			err = closeErr
		}
	}
	if err != nil {
		exporter.recordHealth(delivery.HealthFailing, delivery.HealthReasonDeliveryFailed, false)
		return newError(ErrorShutdown, err)
	}
	exporter.healthMu.Lock()
	exporter.health = delivery.HealthStopped
	exporter.healthReason = delivery.HealthReasonClosed
	exporter.healthMu.Unlock()
	return nil
}

func (exporter *MetricExporter) Counters() ExportCounters {
	if exporter == nil {
		return ExportCounters{}
	}
	return exporter.counters.snapshot()
}

func (exporter *MetricExporter) recordHealth(
	state delivery.HealthState,
	reason delivery.HealthReason,
	success bool,
) {
	if exporter == nil {
		return
	}
	exporter.recordHealthAt(state, reason, success, exporter.nowUTC())
}

func (exporter *MetricExporter) recordHealthAt(
	state delivery.HealthState,
	reason delivery.HealthReason,
	success bool,
	at time.Time,
) {
	exporter.healthMu.Lock()
	exporter.health = state
	exporter.healthReason = reason
	if success {
		exporter.lastSuccess = at.UTC()
	} else {
		exporter.lastFailure = at.UTC()
	}
	exporter.healthMu.Unlock()
}

func (exporter *MetricExporter) setHealth(state delivery.HealthState, reason delivery.HealthReason) {
	if exporter == nil {
		return
	}
	exporter.healthMu.Lock()
	exporter.health = state
	exporter.healthReason = reason
	exporter.healthMu.Unlock()
}

func (exporter *MetricExporter) nowUTC() time.Time {
	if exporter == nil || exporter.now == nil {
		return time.Now().UTC()
	}
	return exporter.now().UTC()
}

func (exporter *MetricExporter) recordCircuitFailure(class delivery.FailureClass, at time.Time) {
	reason := delivery.HealthReasonDeliveryFailed
	if exporter.circuit.RecordFailure(class, at) {
		reason = delivery.HealthReasonCircuitOpen
	}
	exporter.recordHealthAt(delivery.HealthFailing, reason, false, at)
}

func (exporter *MetricExporter) deliveryHealthSnapshot() delivery.HealthSnapshot {
	if exporter == nil {
		return delivery.HealthSnapshot{State: delivery.HealthStopped}
	}
	exporter.healthMu.Lock()
	state := exporter.health
	if state == "" {
		state = delivery.HealthInitializing
	}
	reason := exporter.healthReason
	lastSuccess := exporter.lastSuccess
	lastFailure := exporter.lastFailure
	exporter.healthMu.Unlock()
	circuit := exporter.circuit.Snapshot()
	counters := exporter.Counters()
	return delivery.HealthSnapshot{
		State: state, Reason: string(reason),
		CircuitState: circuit.State, ConsecutiveFailures: circuit.ConsecutiveFailures,
		CircuitOpenUntil: circuit.OpenUntil, LastFailureClass: circuit.LastFailureClass,
		Counters: delivery.Counters{
			Accepted: counters.Accepted, Delivered: counters.Exported, Retried: counters.Retried,
			Dropped: counters.DroppedQueueFull,
			Rejected: addMetricHealthCounter(
				addMetricHealthCounter(counters.RejectedPartial, counters.RejectedOversize), counters.Failed,
			),
			Failed: counters.Failed,
		},
		LastSuccess: lastSuccess, LastFailure: lastFailure,
	}
}

func addMetricHealthCounter(left, right uint64) uint64 {
	if ^uint64(0)-left < right {
		return ^uint64(0)
	}
	return left + right
}

func metricCount(metrics *metricdata.ResourceMetrics) uint64 {
	if metrics == nil {
		return 1
	}
	var count uint64
	for _, scope := range metrics.ScopeMetrics {
		count += uint64(len(scope.Metrics))
	}
	if count == 0 {
		return 1
	}
	return count
}
