// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package galileo

import (
	"context"
	"errors"
	"math"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	compatibility "github.com/defenseclaw/defenseclaw/internal/observability/compatibility/galileo"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/otlp"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// CanonicalConsumerErrorCode is a bounded preparation/lifecycle failure. It
// never contains a destination endpoint, projected value, record, or backend
// response.
type CanonicalConsumerErrorCode string

const (
	CanonicalConsumerErrorInvalidDependencies CanonicalConsumerErrorCode = "invalid_dependencies"
	CanonicalConsumerErrorInvalidDestination  CanonicalConsumerErrorCode = "invalid_destination"
	CanonicalConsumerErrorInvalidDispatcher   CanonicalConsumerErrorCode = "invalid_dispatcher"
	CanonicalConsumerErrorInvalidContext      CanonicalConsumerErrorCode = "invalid_context"
)

// CanonicalConsumerError is safe for mandatory platform-health reporting.
type CanonicalConsumerError struct{ code CanonicalConsumerErrorCode }

func (err *CanonicalConsumerError) Error() string {
	if err == nil {
		return "Galileo canonical trace consumer rejected"
	}
	return "Galileo canonical trace consumer rejected: " + string(err.code)
}

func (err *CanonicalConsumerError) Code() CanonicalConsumerErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

// IsCanonicalConsumerError reports whether err has the requested bounded code.
func IsCanonicalConsumerError(err error, code CanonicalConsumerErrorCode) bool {
	var target *CanonicalConsumerError
	return errors.As(err, &target) && target.code == code
}

// CanonicalFailureCode is the complete content-free failure vocabulary for
// the canonical-to-Galileo handoff. Configured route drops are not failures and
// therefore do not emit an event.
type CanonicalFailureCode string

const (
	CanonicalFailureGenerationMismatch CanonicalFailureCode = "generation_mismatch"
	CanonicalFailurePipeline           CanonicalFailureCode = "pipeline_failed"
	CanonicalFailureProjection         CanonicalFailureCode = "projection_failed"
	CanonicalFailureSchemaIneligible   CanonicalFailureCode = "schema_ineligible"
	CanonicalFailureRouteIdentity      CanonicalFailureCode = "route_identity_mismatch"
	CanonicalFailureUnsupportedShape   CanonicalFailureCode = "unsupported_shape"
	CanonicalFailurePayload            CanonicalFailureCode = "payload_failed"
	CanonicalFailureQueueFull          CanonicalFailureCode = "queue_full"
	CanonicalFailureQueueRejected      CanonicalFailureCode = "queue_rejected"
	CanonicalFailurePanic              CanonicalFailureCode = "panic_isolated"
)

// CanonicalFailure is the bounded observer payload. It deliberately excludes
// record IDs, trace IDs, span IDs, route names, projection bytes, and errors.
type CanonicalFailure struct {
	Destination string
	Generation  uint64
	Code        CanonicalFailureCode
}

type CanonicalObserver interface{ ObserveGalileoCanonicalFailure(CanonicalFailure) }

type CanonicalObserverFunc func(CanonicalFailure)

func (function CanonicalObserverFunc) ObserveGalileoCanonicalFailure(failure CanonicalFailure) {
	function(failure)
}

// CanonicalTraceAdapter is the prepared, generation-owned Galileo transport.
// Adapter satisfies this interface. Its narrow surface also permits transport-
// free queue/lifecycle tests without exposing any alternate payload boundary.
type CanonicalTraceAdapter interface {
	delivery.Adapter
	Close(context.Context) error
}

// CanonicalTraceConsumerOptions are detached during construction. Destination
// must be the exact effective Galileo destination for Pipeline's generation.
type CanonicalTraceConsumerOptions struct {
	Destination config.ObservabilityV8EffectiveDestination
	Generation  uint64
	Pipeline    *pipeline.TraceProjectionPipeline
	Adapter     CanonicalTraceAdapter
	Dispatcher  delivery.Config
	Limits      compatibility.Limits
	Observer    CanonicalObserver
}

type canonicalConsumerState uint32

const (
	canonicalConsumerPrepared canonicalConsumerState = iota
	canonicalConsumerActive
	canonicalConsumerStopping
	canonicalConsumerClosed
)

// CanonicalTraceConsumer owns exactly one Galileo destination in exactly one
// configuration generation. NewCanonicalTraceConsumer performs no network I/O
// and starts no worker. Activate must be called only after the containing
// candidate generation has prepared successfully.
type CanonicalTraceConsumer struct {
	destination string
	generation  uint64
	pipeline    *pipeline.TraceProjectionPipeline
	adapter     CanonicalTraceAdapter
	dispatcher  *delivery.Dispatcher
	limits      compatibility.Limits
	observer    CanonicalObserver

	process func(observability.Record) (pipeline.TraceProjectionOutcome, error)
	project func(redaction.Projection, compatibility.Limits) compatibility.Result
	payload func(compatibility.Result, string) (delivery.Payload, error)

	state        atomic.Uint32
	lifecycleMu  sync.Mutex
	shutdown     chan struct{}
	drained      bool
	adapterDone  bool
	dispatchDone bool

	accepted                atomic.Uint64
	observed                atomic.Uint64
	routeDropped            atomic.Uint64
	routeUnmatched          atomic.Uint64
	projectionFailedClosed  atomic.Uint64
	schemaIneligible        atomic.Uint64
	routeTargetMismatch     atomic.Uint64
	queueDropped            atomic.Uint64
	failed                  atomic.Uint64
	closed                  atomic.Uint64
	closedBeforeObservation atomic.Uint64
	closedObserved          atomic.Uint64
}

var _ telemetry.V8CanonicalSpanConsumer = (*CanonicalTraceConsumer)(nil)

// NewCanonicalTraceConsumer validates and snapshots one prepared generation.
// It does not activate the dispatcher and cannot perform destination I/O.
func NewCanonicalTraceConsumer(options CanonicalTraceConsumerOptions) (*CanonicalTraceConsumer, error) {
	if options.Generation == 0 || options.Generation > math.MaxInt64 || options.Pipeline == nil ||
		options.Pipeline.PlanDigest() == "" || nilCanonicalInterface(options.Adapter) ||
		nilCanonicalInterface(options.Observer) {
		return nil, &CanonicalConsumerError{code: CanonicalConsumerErrorInvalidDependencies}
	}
	destination := options.Destination
	if !validGalileoCanonicalDestination(destination) {
		return nil, &CanonicalConsumerError{code: CanonicalConsumerErrorInvalidDestination}
	}
	if options.Dispatcher.Destination != destination.Name || !options.Dispatcher.Enabled ||
		options.Dispatcher.Generation != options.Generation ||
		options.Dispatcher.Signal != string(observability.SignalTraces) {
		return nil, &CanonicalConsumerError{code: CanonicalConsumerErrorInvalidDispatcher}
	}
	dispatcher, err := delivery.NewDispatcher(options.Dispatcher, options.Adapter)
	if err != nil {
		return nil, &CanonicalConsumerError{code: CanonicalConsumerErrorInvalidDispatcher}
	}
	consumer := &CanonicalTraceConsumer{
		destination: destination.Name,
		generation:  options.Generation,
		pipeline:    options.Pipeline,
		adapter:     options.Adapter,
		dispatcher:  dispatcher,
		limits:      options.Limits,
		observer:    options.Observer,
		shutdown:    make(chan struct{}, 1),
	}
	consumer.shutdown <- struct{}{}
	consumer.process = options.Pipeline.Process
	consumer.project = compatibility.Project
	consumer.payload = NewPayload
	consumer.state.Store(uint32(canonicalConsumerPrepared))
	return consumer, nil
}

func validGalileoCanonicalDestination(destination config.ObservabilityV8EffectiveDestination) bool {
	if !destination.Enabled || !observability.IsStableToken(destination.Name) ||
		destination.Kind != config.ObservabilityV8DestinationOTLP ||
		destination.Preset != "galileo" || destination.PresetProfile != compatibility.ProfileID ||
		!destination.FirstMatchPerSignal {
		return false
	}
	selected := false
	for _, signal := range destination.SelectedSignals {
		if signal != observability.SignalTraces {
			return false
		}
		selected = true
	}
	return selected
}

// Activate publishes intake and starts the common dispatcher. It is
// nonblocking and idempotent. A consumer that has begun shutdown cannot be
// reactivated.
func (consumer *CanonicalTraceConsumer) Activate() {
	if consumer == nil {
		return
	}
	consumer.lifecycleMu.Lock()
	defer consumer.lifecycleMu.Unlock()
	if canonicalConsumerState(consumer.state.Load()) != canonicalConsumerPrepared ||
		consumer.dispatcher == nil {
		return
	}
	consumer.dispatcher.Activate()
	consumer.state.Store(uint32(canonicalConsumerActive))
}

// TryEnqueue snapshots the canonical record, routes/redacts it once, selects
// only this exact Galileo route, applies the compatibility projection, and
// hands immutable bytes to the nonblocking common queue. It performs no
// destination I/O.
func (consumer *CanonicalTraceConsumer) TryEnqueue(
	span telemetry.V8CanonicalEndedSpan,
) telemetry.V8CanonicalSpanEnqueueResult {
	if consumer == nil || canonicalConsumerState(consumer.state.Load()) != canonicalConsumerActive {
		if consumer != nil {
			consumer.closed.Add(1)
			consumer.closedBeforeObservation.Add(1)
		}
		return telemetry.V8CanonicalSpanEnqueueClosed
	}
	return consumer.tryEnqueueRecord(span.Record())
}

func (consumer *CanonicalTraceConsumer) tryEnqueueRecord(
	record observability.Record,
) (result telemetry.V8CanonicalSpanEnqueueResult) {
	result = telemetry.V8CanonicalSpanEnqueueFailed
	defer func() {
		if recover() != nil {
			consumer.failed.Add(1)
			consumer.observe(CanonicalFailurePanic)
			result = telemetry.V8CanonicalSpanEnqueueFailed
		}
	}()
	if canonicalConsumerState(consumer.state.Load()) != canonicalConsumerActive {
		consumer.closed.Add(1)
		consumer.closedBeforeObservation.Add(1)
		return telemetry.V8CanonicalSpanEnqueueClosed
	}
	consumer.observed.Add(1)
	provenance := record.Provenance()
	if provenance.ConfigGeneration < 0 || uint64(provenance.ConfigGeneration) != consumer.generation {
		consumer.failed.Add(1)
		consumer.observe(CanonicalFailureGenerationMismatch)
		return telemetry.V8CanonicalSpanEnqueueFailed
	}
	if target, marked, valid := observability.CanonicalTraceCanaryDestination(record); marked {
		if !valid {
			consumer.failed.Add(1)
			consumer.observe(CanonicalFailureRouteIdentity)
			return telemetry.V8CanonicalSpanEnqueueFailed
		}
		if target != consumer.destination {
			consumer.routeTargetMismatch.Add(1)
			consumer.routeDropped.Add(1)
			return telemetry.V8CanonicalSpanEnqueueDropped
		}
	}
	outcome, err := consumer.process(record)
	if err != nil {
		consumer.failed.Add(1)
		consumer.observe(CanonicalFailurePipeline)
		return telemetry.V8CanonicalSpanEnqueueFailed
	}
	for _, failure := range outcome.OptionalFailures() {
		if failure.DestinationName() == consumer.destination {
			consumer.projectionFailedClosed.Add(1)
			consumer.failed.Add(1)
			consumer.observe(CanonicalFailureProjection)
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
			consumer.observe(CanonicalFailureRouteIdentity)
			return telemetry.V8CanonicalSpanEnqueueFailed
		}
		copy := work
		selected = &copy
	}
	if selected == nil {
		consumer.routeUnmatched.Add(1)
		consumer.routeDropped.Add(1)
		return telemetry.V8CanonicalSpanEnqueueDropped
	}
	projected := consumer.project(selected.Projection(), consumer.limits)
	if !projected.Eligible() {
		consumer.schemaIneligible.Add(1)
		consumer.routeDropped.Add(1)
		code := CanonicalFailureSchemaIneligible
		if projected.Reason() == compatibility.ReasonUnsupportedShape {
			code = CanonicalFailureUnsupportedShape
		}
		consumer.observe(code)
		return telemetry.V8CanonicalSpanEnqueueDropped
	}
	payload, err := consumer.payload(projected, selected.Identity().OriginDestination())
	if err != nil {
		consumer.failed.Add(1)
		consumer.observe(CanonicalFailurePayload)
		return telemetry.V8CanonicalSpanEnqueueFailed
	}
	enqueued := consumer.dispatcher.Enqueue(payload)
	switch enqueued.Disposition {
	case delivery.EnqueueAccepted:
		consumer.accepted.Add(1)
		return telemetry.V8CanonicalSpanEnqueueAccepted
	case delivery.EnqueueDropped:
		consumer.queueDropped.Add(1)
		consumer.observe(CanonicalFailureQueueFull)
		return telemetry.V8CanonicalSpanEnqueueDropped
	case delivery.EnqueueRejected:
		if enqueued.Reason == delivery.ReasonInactive || enqueued.Reason == delivery.ReasonIntakeStopped {
			consumer.closed.Add(1)
			consumer.closedObserved.Add(1)
			return telemetry.V8CanonicalSpanEnqueueClosed
		}
		consumer.failed.Add(1)
		consumer.observe(CanonicalFailureQueueRejected)
		return telemetry.V8CanonicalSpanEnqueueFailed
	default:
		consumer.failed.Add(1)
		consumer.observe(CanonicalFailureQueueRejected)
		return telemetry.V8CanonicalSpanEnqueueFailed
	}
}

// ForceFlush waits only for the dispatcher fence. It never calls Drain and
// therefore leaves intake open for later spans in the same generation.
func (consumer *CanonicalTraceConsumer) ForceFlush(ctx context.Context) error {
	if consumer == nil {
		return nil
	}
	if ctx == nil {
		return &CanonicalConsumerError{code: CanonicalConsumerErrorInvalidContext}
	}
	return consumer.dispatcher.Flush(ctx)
}

// Shutdown is bounded, idempotent, and retryable. A timed-out invocation may
// be retried: completed stages are not repeated, while an incomplete adapter
// or dispatcher close is attempted again. Adapter close occurs only after the
// queue has drained, so no worker can race a closed transport.
func (consumer *CanonicalTraceConsumer) Shutdown(ctx context.Context) error {
	if consumer == nil {
		return nil
	}
	if ctx == nil {
		return &CanonicalConsumerError{code: CanonicalConsumerErrorInvalidContext}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-consumer.shutdown:
	}
	defer func() { consumer.shutdown <- struct{}{} }()

	consumer.lifecycleMu.Lock()
	state := canonicalConsumerState(consumer.state.Load())
	if state == canonicalConsumerClosed {
		consumer.lifecycleMu.Unlock()
		return nil
	}
	consumer.state.Store(uint32(canonicalConsumerStopping))
	consumer.lifecycleMu.Unlock()

	if !consumer.drained {
		if err := consumer.dispatcher.StopIntake(ctx); err != nil {
			return err
		}
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
	consumer.state.Store(uint32(canonicalConsumerClosed))
	return nil
}

// CanonicalTraceConsumerCounters is a content-free monotonic snapshot. Remote
// delivery/retry counters remain available from the adapter and dispatcher.
type CanonicalTraceConsumerCounters struct {
	Observed                uint64
	Accepted                uint64
	RouteDropped            uint64
	RouteUnmatched          uint64
	ProjectionFailedClosed  uint64
	SchemaIneligible        uint64
	RouteTargetMismatch     uint64
	QueueDropped            uint64
	Failed                  uint64
	Closed                  uint64
	ClosedBeforeObservation uint64
	ClosedObserved          uint64
}

func (consumer *CanonicalTraceConsumer) Counters() CanonicalTraceConsumerCounters {
	if consumer == nil {
		return CanonicalTraceConsumerCounters{}
	}
	return CanonicalTraceConsumerCounters{
		Observed: consumer.observed.Load(), Accepted: consumer.accepted.Load(),
		RouteDropped: consumer.routeDropped.Load(), RouteUnmatched: consumer.routeUnmatched.Load(),
		ProjectionFailedClosed: consumer.projectionFailedClosed.Load(),
		SchemaIneligible:       consumer.schemaIneligible.Load(),
		RouteTargetMismatch:    consumer.routeTargetMismatch.Load(),
		QueueDropped:           consumer.queueDropped.Load(), Failed: consumer.failed.Load(),
		Closed: consumer.closed.Load(), ClosedBeforeObservation: consumer.closedBeforeObservation.Load(),
		ClosedObserved: consumer.closedObserved.Load(),
	}
}

// Reconciled proves that every active observed handoff has exactly one primary
// local disposition. Calls rejected before active observation are tracked
// separately and therefore cannot make the observed funnel appear lossy.
func (counters CanonicalTraceConsumerCounters) Reconciled() bool {
	return counters.Observed == counters.Accepted+counters.RouteDropped+
		counters.QueueDropped+counters.Failed+counters.ClosedObserved &&
		counters.Closed == counters.ClosedBeforeObservation+counters.ClosedObserved &&
		counters.SchemaIneligible+counters.RouteUnmatched+counters.RouteTargetMismatch ==
			counters.RouteDropped &&
		counters.ProjectionFailedClosed <= counters.Failed
}

// CanonicalDeliveryEvidence is one detached, content-free view of the complete
// Galileo funnel. Projection dispositions, the common bounded queue, remote
// partial success, retry, and terminal transport outcomes remain attributable
// to the same destination and configuration generation.
type CanonicalDeliveryEvidence struct {
	Destination string
	Generation  uint64
	Profile     string
	Funnel      CanonicalTraceConsumerCounters
	Delivery    delivery.HealthSnapshot
	Transport   otlp.ExportCounters
}

type transportCounterSource interface {
	Counters() otlp.ExportCounters
}

// DeliveryEvidenceSnapshot never exposes record/trace/span IDs, route names,
// endpoints, headers, response bodies, or projected values.
func (consumer *CanonicalTraceConsumer) DeliveryEvidenceSnapshot() CanonicalDeliveryEvidence {
	if consumer == nil {
		return CanonicalDeliveryEvidence{Profile: compatibility.ProfileID,
			Delivery: delivery.HealthSnapshot{State: delivery.HealthStopped}}
	}
	evidence := CanonicalDeliveryEvidence{
		Destination: consumer.destination, Generation: consumer.generation,
		Profile: compatibility.ProfileID, Funnel: consumer.Counters(),
		Delivery: consumer.DeliveryHealthSnapshot(),
	}
	if source, ok := consumer.adapter.(transportCounterSource); ok && source != nil {
		evidence.Transport = source.Counters()
	}
	return evidence
}

// DeliveryHealthSnapshot is a detached queue/counter view with no Galileo
// content, endpoint, credentials, or request diagnostics.
func (consumer *CanonicalTraceConsumer) DeliveryHealthSnapshot() delivery.HealthSnapshot {
	if consumer == nil || consumer.dispatcher == nil {
		return delivery.HealthSnapshot{State: delivery.HealthStopped}
	}
	return consumer.dispatcher.DeliveryHealthSnapshot()
}

func (consumer *CanonicalTraceConsumer) observe(code CanonicalFailureCode) {
	if consumer == nil || consumer.observer == nil {
		return
	}
	failure := CanonicalFailure{
		Destination: consumer.destination, Generation: consumer.generation, Code: code,
	}
	defer func() { _ = recover() }()
	consumer.observer.ObserveGalileoCanonicalFailure(failure)
}

func nilCanonicalInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
