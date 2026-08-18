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
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	traceNoop "go.opentelemetry.io/otel/trace/noop"
)

// Provider is the SDK transport owned by one immutable Observability v8
// runtime generation. It intentionally exposes no v7 constructor, global SDK
// installer, direct family emitter, destination router, or fallback exporter.
// Canonical generated records are its only production input.
type Provider struct {
	res            *resource.Resource
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider

	tracer  trace.Tracer
	meter   metric.Meter
	metrics *metricsSet

	enabled  bool
	shutdown atomic.Bool
	v8       *v8ProviderState

	v8ShutdownMu      sync.Mutex
	v8ShutdownStarted bool
	v8ShutdownDone    chan struct{}
	v8ShutdownErr     error
}

func (p *Provider) Enabled() bool {
	return p != nil && p.enabled && !p.shutdown.Load() && p.v8 != nil && p.v8.active.Load()
}

// Tracer returns the generation-owned tracer. Callers still must evaluate the
// generated collection gate before asking it to construct a span.
func (p *Provider) Tracer() trace.Tracer {
	if p == nil || p.tracer == nil || !p.TracesEnabled() {
		return traceNoop.NewTracerProvider().Tracer("defenseclaw")
	}
	return p.tracer
}

func (p *Provider) TracesEnabled() bool {
	return p.Enabled() && p.tracerProvider != nil
}

// DestinationAcknowledgedCanaryTrace delegates exclusively to the active v8
// generation's destination-owned acknowledgement registry.
func (p *Provider) DestinationAcknowledgedCanaryTrace(destination, traceID string) bool {
	if !p.Enabled() || p.v8.canaryAck == nil || strings.TrimSpace(traceID) == "" {
		return false
	}
	acknowledged := false
	func() {
		defer func() { _ = recover() }()
		acknowledged = p.v8.canaryAck(destination, traceID)
	}()
	return acknowledged
}

// Shutdown retires one generation immediately and completes SDK shutdown once
// under an internal deadline. A Provider without v8 ownership is a test-only
// transport and is closed synchronously; it cannot become a production graph.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || !p.enabled {
		return nil
	}
	if p.v8 != nil {
		return p.shutdownV8(ctx)
	}
	if !p.shutdown.CompareAndSwap(false, true) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var errs []error
	if p.tracerProvider != nil {
		if err := p.tracerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("traces: %w", err))
		}
	}
	if p.meterProvider != nil {
		if err := p.meterProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("metrics: %w", err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("telemetry: shutdown: %v", errs)
	}
	return nil
}

func (p *Provider) shutdownV8(ctx context.Context) error {
	p.shutdown.Store(true)
	p.v8ShutdownMu.Lock()
	if !p.v8ShutdownStarted {
		p.v8ShutdownStarted = true
		p.v8ShutdownDone = make(chan struct{})
		go p.runV8Shutdown()
	}
	done := p.v8ShutdownDone
	p.v8ShutdownMu.Unlock()

	select {
	case <-done:
		p.v8ShutdownMu.Lock()
		err := p.v8ShutdownErr
		p.v8ShutdownMu.Unlock()
		return err
	case <-ctx.Done():
		return newV8ProviderError(V8ProviderErrorShutdown, ctx.Err())
	}
}

func (p *Provider) runV8Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	failed := false
	var firstCause error
	record := func(err error) {
		if err != nil {
			failed = true
			if firstCause == nil {
				firstCause = v8ContextCause(err)
			}
		}
	}
	if p.tracerProvider != nil {
		record(p.tracerProvider.Shutdown(ctx))
	}
	if p.meterProvider != nil {
		record(p.meterProvider.Shutdown(ctx))
	}
	if p.v8 != nil && p.v8.metricRecorder != nil {
		record(p.v8.metricRecorder.close(ctx))
	}

	p.v8ShutdownMu.Lock()
	if failed {
		p.v8ShutdownErr = newV8ProviderError(V8ProviderErrorShutdown, firstCause)
	}
	close(p.v8ShutdownDone)
	p.v8ShutdownMu.Unlock()
}
