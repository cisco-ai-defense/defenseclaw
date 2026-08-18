// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package prometheus

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/otlptranslator"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

const (
	readHeaderTimeout   = 5 * time.Second
	readTimeout         = 15 * time.Second
	writeTimeout        = 30 * time.Second
	idleTimeout         = 60 * time.Second
	maxHeaderBytes      = 8 * 1024
	maxConcurrent       = 8
	defaultDrainTimeout = 5 * time.Second
)

// Reader embeds the official OTel reader so the SDK's private registration,
// aggregation, and collection methods remain authoritative while Shutdown also
// owns the listener/server lifecycle.
type Reader struct {
	sdkmetric.Reader

	destination  string
	generation   uint64
	path         string
	listener     net.Listener
	server       *http.Server
	gatherers    *generationGatherer
	observer     *boundedObserver
	drainTimeout time.Duration

	serveDone chan struct{}

	shutdownOnce sync.Once
	shutdownDone chan struct{}
	shutdownErr  error

	healthMu     sync.Mutex
	health       delivery.HealthState
	healthReason HealthReason
	lastSuccess  time.Time
	lastFailure  time.Time

	scrapes   atomic.Uint64
	succeeded atomic.Uint64
	failed    atomic.Uint64
}

// Prepare binds the exact configured loopback listener and creates a private
// official OTel Prometheus exporter for one generation.
func (factory *Factory) Prepare(
	generation uint64,
	spec telemetry.V8MetricReaderSpec,
) (sdkmetric.Reader, error) {
	return factory.PrepareContext(context.Background(), generation, spec)
}

// PrepareContext is the exact generation callback boundary. The supplied
// context controls listener preparation; after success the returned Reader is
// owned and shut down by the generation's SDK MeterProvider.
func (factory *Factory) PrepareContext(
	ctx context.Context,
	generation uint64,
	spec telemetry.V8MetricReaderSpec,
) (sdkmetric.Reader, error) {
	if factory == nil || generation == 0 || factory.listenFunc == nil || factory.observer == nil ||
		ctx == nil ||
		spec.ExportInterval <= 0 || spec.ExportTimeout <= 0 || spec.CardinalityLimit <= 0 ||
		(spec.Temporality != metricdata.DeltaTemporality && spec.Temporality != metricdata.CumulativeTemporality) {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	if err := ctx.Err(); err != nil {
		return nil, newError(ErrorListenFailed, err)
	}
	registry := prom.NewPedanticRegistry()
	exporter, err := newPrivateExporter(registry)
	if err != nil {
		factory.safeObserve(HealthTransition{
			Destination: factory.destination, Generation: generation,
			Previous: delivery.HealthInitializing, Current: delivery.HealthFailing,
			Reason: HealthReasonListenerFailed, OccurredAt: time.Now().UTC(),
		})
		return nil, newError(ErrorExporterInit, nil)
	}
	listener, err := factory.listenFunc(ctx, "tcp", factory.listen)
	if err != nil {
		_ = exporter.Shutdown(context.Background())
		factory.safeObserve(HealthTransition{
			Destination: factory.destination, Generation: generation,
			Previous: delivery.HealthInitializing, Current: delivery.HealthFailing,
			Reason: HealthReasonListenerFailed, OccurredAt: time.Now().UTC(),
		})
		return nil, newError(ErrorListenFailed, nil)
	}
	if !safeBoundListener(listener) {
		_ = listener.Close()
		_ = exporter.Shutdown(context.Background())
		return nil, newError(ErrorUnsafeListen, nil)
	}
	gatherers := newGenerationGatherer(registry, factory.matcher)
	filtered := &filteredGatherer{source: gatherers, matcher: factory.matcher, labels: cloneSet(factory.labels)}
	reader := &Reader{
		Reader: exporter, destination: factory.destination, generation: generation,
		path: factory.path, listener: listener, gatherers: gatherers, observer: factory.observer,
		drainTimeout: factory.drainTimeout,
		serveDone:    make(chan struct{}), shutdownDone: make(chan struct{}),
		health: delivery.HealthInitializing,
	}
	promHandler := promhttp.HandlerFor(filtered, promhttp.HandlerOpts{
		ErrorHandling:       promhttp.HTTPErrorOnError,
		ErrorLog:            log.New(io.Discard, "", 0),
		EnableOpenMetrics:   true,
		MaxRequestsInFlight: maxConcurrent,
		Timeout:             readTimeout,
	})
	reader.server = &http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			reader.serveMetrics(promHandler, writer, request)
		}),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	reader.transition(delivery.HealthHealthy, HealthReasonListenerBound)
	go reader.serve()
	return reader, nil
}

// PreparePlanReaders prepares every enabled Prometheus destination from the
// exact immutable candidate plan. It is intended to be called by the single
// composite telemetry.V8GenerationPipelineFactory alongside OTLP preparation.
// On failure it releases every reader it prepared and returns no partial set.
func PreparePlanReaders(
	ctx context.Context,
	plan *config.ObservabilityV8Plan,
	generation uint64,
	spec telemetry.V8MetricReaderSpec,
	options Options,
) ([]sdkmetric.Reader, error) {
	if ctx == nil || plan == nil || generation == 0 {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	snapshot := plan.Snapshot()
	metricsCollected := false
	for _, bucket := range snapshot.Buckets {
		if bucket.Collect.Metrics {
			metricsCollected = true
			break
		}
	}
	if !metricsCollected {
		return nil, nil
	}
	readers := make([]sdkmetric.Reader, 0)
	cleanup := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for index := len(readers) - 1; index >= 0; index-- {
			_ = readers[index].Shutdown(cleanupCtx)
		}
	}
	for _, destination := range snapshot.Destinations {
		if !destination.Enabled || destination.Kind != config.ObservabilityV8DestinationPrometheus {
			continue
		}
		factory, err := NewFactory(destination, options)
		if err != nil {
			cleanup()
			return nil, err
		}
		reader, err := factory.PrepareContext(ctx, generation, spec)
		if err != nil {
			cleanup()
			return nil, err
		}
		readers = append(readers, reader)
	}
	return readers, nil
}

func newPrivateExporter(registry prom.Registerer) (*otelprom.Exporter, error) {
	return otelprom.New(
		otelprom.WithRegisterer(registry),
		otelprom.WithTranslationStrategy(otlptranslator.UnderscoreEscapingWithSuffixes),
		otelprom.WithoutTargetInfo(),
		otelprom.WithoutScopeInfo(),
	)
}

func safeBoundListener(listener net.Listener) bool {
	if listener == nil {
		return false
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	return ok && address.IP != nil && address.IP.IsLoopback() && address.Port > 0
}

func (reader *Reader) serve() {
	defer close(reader.serveDone)
	err := reader.server.Serve(reader.listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		reader.transition(delivery.HealthFailing, HealthReasonServerFailed)
	}
}

func (reader *Reader) serveMetrics(next http.Handler, writer http.ResponseWriter, request *http.Request) {
	if request == nil || request.URL == nil || request.URL.Path != reader.path {
		http.NotFound(writer, request)
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	state := reader.Health().State
	if state == delivery.HealthDraining || state == delivery.HealthStopped || state == delivery.HealthFailing {
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	reader.scrapes.Add(1)
	status := &statusWriter{ResponseWriter: writer, status: http.StatusOK}
	next.ServeHTTP(status, request)
	reader.observeScrape(status.status < http.StatusBadRequest)
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (writer *statusWriter) WriteHeader(status int) {
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (reader *Reader) observeScrape(success bool) {
	if success {
		reader.succeeded.Add(1)
		reader.healthMu.Lock()
		reader.lastSuccess = time.Now().UTC()
		reader.healthMu.Unlock()
		if reader.Health().State == delivery.HealthDegraded {
			reader.transition(delivery.HealthHealthy, HealthReasonRecovered)
		}
		return
	}
	reader.failed.Add(1)
	reader.healthMu.Lock()
	reader.lastFailure = time.Now().UTC()
	reader.healthMu.Unlock()
	reader.transition(delivery.HealthDegraded, HealthReasonScrapeFailed)
}

func (reader *Reader) transition(state delivery.HealthState, reason HealthReason) {
	if reader == nil {
		return
	}
	reader.healthMu.Lock()
	previous := reader.health
	if previous == state || previous == delivery.HealthStopped ||
		(previous == delivery.HealthDraining && state != delivery.HealthStopped) {
		reader.healthReason = reason
		reader.healthMu.Unlock()
		return
	}
	reader.health = state
	reader.healthReason = reason
	if state == delivery.HealthDegraded || state == delivery.HealthFailing {
		reader.lastFailure = time.Now().UTC()
	}
	transition := HealthTransition{
		Destination: reader.destination, Generation: reader.generation,
		Previous: previous, Current: state, Reason: reason,
		Counters: reader.Counters(), OccurredAt: time.Now().UTC(),
	}
	reader.healthMu.Unlock()
	reader.safeObserve(transition)
}

func (factory *Factory) safeObserve(transition HealthTransition) {
	if factory == nil || factory.observer == nil {
		return
	}
	factory.observer.observe(transition)
}

func (reader *Reader) safeObserve(transition HealthTransition) {
	if reader == nil || reader.observer == nil {
		return
	}
	reader.observer.observe(transition)
}

// Shutdown starts one drain transaction and lets later callers wait/retry with
// their own context. Existing scrapes may finish; the inner SDK reader is shut
// down only after the HTTP server has drained.
func (reader *Reader) Shutdown(ctx context.Context) error {
	if reader == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorShutdownFailed, nil)
	}
	reader.shutdownOnce.Do(func() {
		reader.transition(delivery.HealthDraining, HealthReasonDrainStarted)
		go reader.shutdown()
	})
	select {
	case <-reader.shutdownDone:
		return reader.shutdownErr
	case <-ctx.Done():
		return newError(ErrorShutdownFailed, ctx.Err())
	}
}

func (reader *Reader) shutdown() {
	defer close(reader.shutdownDone)
	drainTimeout := reader.drainTimeout
	if drainTimeout <= 0 {
		drainTimeout = defaultDrainTimeout
	}
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), drainTimeout)
	serverErr := reader.server.Shutdown(drainCtx)
	cancelDrain()
	if serverErr != nil {
		// Shutdown's deadline only stops waiting; force-close the listener and
		// active connections so an uncooperative scrape cannot own the graph.
		if closeErr := reader.server.Close(); closeErr != nil && !errors.Is(closeErr, http.ErrServerClosed) {
			serverErr = closeErr
		}
	}
	<-reader.serveDone
	readerCtx, cancelReader := context.WithTimeout(context.Background(), drainTimeout)
	readerErr := reader.Reader.Shutdown(readerCtx)
	cancelReader()
	if serverErr != nil || (readerErr != nil && !errors.Is(readerErr, sdkmetric.ErrReaderShutdown)) {
		reader.shutdownErr = newError(ErrorShutdownFailed, nil)
	}
	reader.transition(delivery.HealthStopped, HealthReasonClosed)
}

func (reader *Reader) Counters() Counters {
	if reader == nil {
		return Counters{}
	}
	return Counters{
		Scrapes: reader.scrapes.Load(), Succeeded: reader.succeeded.Load(), Failed: reader.failed.Load(),
	}
}

func (reader *Reader) Health() HealthSnapshot {
	if reader == nil {
		return HealthSnapshot{State: delivery.HealthStopped}
	}
	reader.healthMu.Lock()
	state := reader.health
	reader.healthMu.Unlock()
	return HealthSnapshot{Generation: reader.generation, State: state, Counters: reader.Counters()}
}

// DeliveryHealthSnapshot implements the common generation-owned read-only
// health seam. Prometheus is a pull destination and therefore has no queue.
func (reader *Reader) DeliveryHealthSnapshot() delivery.HealthSnapshot {
	if reader == nil {
		return delivery.HealthSnapshot{State: delivery.HealthStopped}
	}
	reader.healthMu.Lock()
	state := reader.health
	reason := reader.healthReason
	lastSuccess := reader.lastSuccess
	lastFailure := reader.lastFailure
	reader.healthMu.Unlock()
	counters := reader.Counters()
	return delivery.HealthSnapshot{
		Destination: reader.destination, Generation: reader.generation,
		Signal: string(observability.SignalMetrics), State: state, Reason: string(reason),
		Counters: delivery.Counters{
			Accepted: counters.Scrapes, Delivered: counters.Succeeded,
			Rejected: counters.Failed, Failed: counters.Failed,
		},
		LastSuccess: lastSuccess, LastFailure: lastFailure,
	}
}

// Addr is the actual bound loopback address. It is intended for operator
// surfaces/tests and is never included in safe errors or health transitions.
func (reader *Reader) Addr() net.Addr {
	if reader == nil || reader.listener == nil {
		return nil
	}
	return reader.listener.Addr()
}

func (reader *Reader) Path() string {
	if reader == nil {
		return ""
	}
	return reader.path
}

var _ sdkmetric.Reader = (*Reader)(nil)
