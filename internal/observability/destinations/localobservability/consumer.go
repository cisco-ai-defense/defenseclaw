// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package localobservability

import (
	"context"
	"errors"
	"math"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type ErrorCode string

const (
	ErrorInvalidDependencies ErrorCode = "invalid_dependencies"
	ErrorInvalidDestination  ErrorCode = "invalid_destination"
	ErrorInvalidDispatcher   ErrorCode = "invalid_dispatcher"
	ErrorInvalidContext      ErrorCode = "invalid_context"
)

type Error struct{ code ErrorCode }

func (err *Error) Error() string {
	if err == nil {
		return "local observability trace consumer rejected"
	}
	return "local observability trace consumer rejected: " + string(err.code)
}
func (err *Error) Code() ErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}
func IsError(err error, code ErrorCode) bool {
	var target *Error
	return errors.As(err, &target) && target.code == code
}

type FailureCode string

const (
	FailureGenerationMismatch FailureCode = "generation_mismatch"
	FailurePipeline           FailureCode = "pipeline_failed"
	FailureProjection         FailureCode = "projection_failed"
	FailureRouteIdentity      FailureCode = "route_identity_mismatch"
	FailureCompatibility      FailureCode = "compatibility_projection_failed"
	FailurePayload            FailureCode = "payload_failed"
	FailureQueueFull          FailureCode = "queue_full"
	FailureQueueRejected      FailureCode = "queue_rejected"
	FailurePanic              FailureCode = "panic_isolated"
)

// Failure is intentionally content-free and safe for platform-health metrics.
type Failure struct {
	Destination string
	Generation  uint64
	Code        FailureCode
}

type Observer interface{ ObserveLocalObservabilityFailure(Failure) }

type ObserverFunc func(Failure)

func (function ObserverFunc) ObserveLocalObservabilityFailure(failure Failure) { function(failure) }

type TraceAdapter interface {
	delivery.Adapter
	Close(context.Context) error
}

type ConsumerOptions struct {
	Destination config.ObservabilityV8EffectiveDestination
	Generation  uint64
	Profile     string
	Pipeline    *pipeline.TraceProjectionPipeline
	Adapter     TraceAdapter
	Dispatcher  delivery.Config
	Observer    Observer
}

type consumerState uint32

const (
	consumerPrepared consumerState = iota
	consumerActive
	consumerStopping
	consumerClosed
)

// Consumer owns one local Collector destination in one immutable generation.
// Construction performs no I/O and starts no worker; Activate is explicit.
type Consumer struct {
	destination string
	generation  uint64
	adapter     TraceAdapter
	dispatcher  *delivery.Dispatcher
	observer    Observer

	process func(observability.Record) (pipeline.TraceProjectionOutcome, error)
	project func(redaction.Projection) Result
	payload func(Result, string) (delivery.Payload, bool)

	state        atomic.Uint32
	lifecycleMu  sync.Mutex
	shutdownGate chan struct{}
	drained      bool
	adapterDone  bool
	dispatchDone bool

	accepted     atomic.Uint64
	routeDropped atomic.Uint64
	queueDropped atomic.Uint64
	failed       atomic.Uint64
	closed       atomic.Uint64
}

var _ telemetry.V8CanonicalSpanConsumer = (*Consumer)(nil)

func NewConsumer(options ConsumerOptions) (*Consumer, error) {
	if options.Generation == 0 || options.Generation > math.MaxInt64 || options.Profile != ProfileID || options.Pipeline == nil ||
		options.Pipeline.PlanDigest() == "" || nilInterface(options.Adapter) || nilInterface(options.Observer) ||
		options.Dispatcher.Destination == "" {
		return nil, &Error{code: ErrorInvalidDependencies}
	}
	if !validDestination(options.Destination) {
		return nil, &Error{code: ErrorInvalidDestination}
	}
	if options.Dispatcher.Destination != options.Destination.Name || !options.Dispatcher.Enabled {
		return nil, &Error{code: ErrorInvalidDispatcher}
	}
	dispatcher, err := delivery.NewDispatcher(options.Dispatcher, options.Adapter)
	if err != nil {
		return nil, &Error{code: ErrorInvalidDispatcher}
	}
	consumer := &Consumer{
		destination: options.Destination.Name, generation: options.Generation,
		adapter: options.Adapter, dispatcher: dispatcher, observer: options.Observer,
		process: options.Pipeline.Process, project: Project, payload: NewPayload,
		shutdownGate: make(chan struct{}, 1),
	}
	consumer.shutdownGate <- struct{}{}
	consumer.state.Store(uint32(consumerPrepared))
	return consumer, nil
}

func validDestination(destination config.ObservabilityV8EffectiveDestination) bool {
	if !destination.Enabled || !observability.IsStableToken(destination.Name) ||
		destination.Kind != config.ObservabilityV8DestinationOTLP || destination.Preset == "galileo" ||
		!destination.FirstMatchPerSignal {
		return false
	}
	found := false
	for _, signal := range destination.SelectedSignals {
		if signal == observability.SignalTraces {
			found = true
		}
	}
	return found
}

func (consumer *Consumer) Activate() {
	if consumer == nil {
		return
	}
	consumer.lifecycleMu.Lock()
	defer consumer.lifecycleMu.Unlock()
	if consumerState(consumer.state.Load()) != consumerPrepared {
		return
	}
	consumer.dispatcher.Activate()
	consumer.state.Store(uint32(consumerActive))
}

func (consumer *Consumer) TryEnqueue(span telemetry.V8CanonicalEndedSpan) telemetry.V8CanonicalSpanEnqueueResult {
	if consumer == nil || consumerState(consumer.state.Load()) != consumerActive {
		if consumer != nil {
			consumer.closed.Add(1)
		}
		return telemetry.V8CanonicalSpanEnqueueClosed
	}
	return consumer.tryRecord(span.Record())
}

func (consumer *Consumer) tryRecord(record observability.Record) (result telemetry.V8CanonicalSpanEnqueueResult) {
	result = telemetry.V8CanonicalSpanEnqueueFailed
	defer func() {
		if recover() != nil {
			consumer.failed.Add(1)
			consumer.observe(FailurePanic)
			result = telemetry.V8CanonicalSpanEnqueueFailed
		}
	}()
	if consumerState(consumer.state.Load()) != consumerActive {
		consumer.closed.Add(1)
		return telemetry.V8CanonicalSpanEnqueueClosed
	}
	provenance := record.Provenance()
	if provenance.ConfigGeneration < 0 || uint64(provenance.ConfigGeneration) != consumer.generation {
		consumer.failed.Add(1)
		consumer.observe(FailureGenerationMismatch)
		return telemetry.V8CanonicalSpanEnqueueFailed
	}
	if target, marked, valid := observability.CanonicalTraceCanaryDestination(record); marked {
		if !valid {
			consumer.failed.Add(1)
			consumer.observe(FailureRouteIdentity)
			return telemetry.V8CanonicalSpanEnqueueFailed
		}
		if target != consumer.destination {
			consumer.routeDropped.Add(1)
			return telemetry.V8CanonicalSpanEnqueueDropped
		}
	}
	outcome, err := consumer.process(record)
	if err != nil {
		consumer.failed.Add(1)
		consumer.observe(FailurePipeline)
		return telemetry.V8CanonicalSpanEnqueueFailed
	}
	for _, failure := range outcome.OptionalFailures() {
		if failure.DestinationName() == consumer.destination {
			consumer.failed.Add(1)
			consumer.observe(FailureProjection)
			return telemetry.V8CanonicalSpanEnqueueFailed
		}
	}
	var selected *pipeline.ProjectedDelivery
	for _, work := range outcome.OptionalWork() {
		route := work.Delivery()
		if route.DestinationName != consumer.destination {
			continue
		}
		if selected != nil || route.DestinationKind != config.ObservabilityV8DestinationOTLP {
			consumer.failed.Add(1)
			consumer.observe(FailureRouteIdentity)
			return telemetry.V8CanonicalSpanEnqueueFailed
		}
		copy := work
		selected = &copy
	}
	if selected == nil {
		consumer.routeDropped.Add(1)
		return telemetry.V8CanonicalSpanEnqueueDropped
	}
	projected := consumer.project(selected.Projection())
	if !projected.Eligible() {
		consumer.failed.Add(1)
		consumer.observe(FailureCompatibility)
		return telemetry.V8CanonicalSpanEnqueueFailed
	}
	payload, ok := consumer.payload(projected, selected.Identity().OriginDestination())
	if !ok {
		consumer.failed.Add(1)
		consumer.observe(FailurePayload)
		return telemetry.V8CanonicalSpanEnqueueFailed
	}
	enqueue := consumer.dispatcher.Enqueue(payload)
	switch enqueue.Disposition {
	case delivery.EnqueueAccepted:
		consumer.accepted.Add(1)
		return telemetry.V8CanonicalSpanEnqueueAccepted
	case delivery.EnqueueDropped:
		consumer.queueDropped.Add(1)
		consumer.observe(FailureQueueFull)
		return telemetry.V8CanonicalSpanEnqueueDropped
	case delivery.EnqueueRejected:
		if enqueue.Reason == delivery.ReasonInactive || enqueue.Reason == delivery.ReasonIntakeStopped {
			consumer.closed.Add(1)
			return telemetry.V8CanonicalSpanEnqueueClosed
		}
		consumer.failed.Add(1)
		consumer.observe(FailureQueueRejected)
		return telemetry.V8CanonicalSpanEnqueueFailed
	default:
		consumer.failed.Add(1)
		consumer.observe(FailureQueueRejected)
		return telemetry.V8CanonicalSpanEnqueueFailed
	}
}

// ForceFlush preserves intake; it never calls Drain.
func (consumer *Consumer) ForceFlush(ctx context.Context) error {
	if consumer == nil {
		return nil
	}
	if ctx == nil {
		return &Error{code: ErrorInvalidContext}
	}
	return consumer.dispatcher.Flush(ctx)
}

// Shutdown is idempotent, context-bounded, and retryable after a timeout.
func (consumer *Consumer) Shutdown(ctx context.Context) error {
	if consumer == nil {
		return nil
	}
	if ctx == nil {
		return &Error{code: ErrorInvalidContext}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-consumer.shutdownGate:
	}
	defer func() { consumer.shutdownGate <- struct{}{} }()
	consumer.lifecycleMu.Lock()
	if consumerState(consumer.state.Load()) == consumerClosed {
		consumer.lifecycleMu.Unlock()
		return nil
	}
	consumer.state.Store(uint32(consumerStopping))
	consumer.lifecycleMu.Unlock()
	if !consumer.drained {
		_ = consumer.dispatcher.StopIntake(ctx)
		if err := consumer.dispatcher.Drain(ctx); err != nil {
			return err
		}
		consumer.drained = true
	}
	if !consumer.adapterDone {
		if err := consumer.adapter.Close(ctx); err != nil {
			return err
		}
		consumer.adapterDone = true
	}
	if !consumer.dispatchDone {
		if err := consumer.dispatcher.Close(ctx); err != nil {
			return err
		}
		consumer.dispatchDone = true
	}
	consumer.state.Store(uint32(consumerClosed))
	return nil
}

type Counters struct {
	Accepted, RouteDropped, QueueDropped, Failed, Closed uint64
}

func (consumer *Consumer) Counters() Counters {
	if consumer == nil {
		return Counters{}
	}
	return Counters{
		Accepted: consumer.accepted.Load(), RouteDropped: consumer.routeDropped.Load(),
		QueueDropped: consumer.queueDropped.Load(), Failed: consumer.failed.Load(), Closed: consumer.closed.Load(),
	}
}

// DeliveryHealthSnapshot returns only the generation-owned trace queue's
// bounded operational state; it cannot expose projected span contents.
func (consumer *Consumer) DeliveryHealthSnapshot() delivery.HealthSnapshot {
	if consumer == nil || consumer.dispatcher == nil {
		return delivery.HealthSnapshot{State: delivery.HealthStopped}
	}
	return consumer.dispatcher.DeliveryHealthSnapshot()
}

func (consumer *Consumer) observe(code FailureCode) {
	if consumer == nil || consumer.observer == nil {
		return
	}
	defer func() { _ = recover() }()
	consumer.observer.ObserveLocalObservabilityFailure(Failure{
		Destination: consumer.destination, Generation: consumer.generation, Code: code,
	})
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
