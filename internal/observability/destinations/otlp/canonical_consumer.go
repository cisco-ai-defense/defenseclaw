// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"errors"
	"math"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/compatibility/profilemanifest"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type CanonicalConsumerErrorCode string

const (
	CanonicalConsumerErrorInvalidDependencies CanonicalConsumerErrorCode = "invalid_dependencies"
	CanonicalConsumerErrorInvalidDestination  CanonicalConsumerErrorCode = "invalid_destination"
	CanonicalConsumerErrorInvalidDispatcher   CanonicalConsumerErrorCode = "invalid_dispatcher"
	CanonicalConsumerErrorInvalidContext      CanonicalConsumerErrorCode = "invalid_context"
)

type CanonicalConsumerError struct{ code CanonicalConsumerErrorCode }

func (err *CanonicalConsumerError) Error() string {
	if err == nil {
		return "OTLP canonical trace consumer rejected"
	}
	return "OTLP canonical trace consumer rejected: " + string(err.code)
}

func (err *CanonicalConsumerError) Code() CanonicalConsumerErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

func IsCanonicalConsumerError(err error, code CanonicalConsumerErrorCode) bool {
	var target *CanonicalConsumerError
	return errors.As(err, &target) && target.code == code
}

type CanonicalFailureCode string

const (
	CanonicalFailureGenerationMismatch CanonicalFailureCode = "generation_mismatch"
	CanonicalFailurePipeline           CanonicalFailureCode = "pipeline_failed"
	CanonicalFailureProjection         CanonicalFailureCode = "projection_failed"
	CanonicalFailureRouteIdentity      CanonicalFailureCode = "route_identity_mismatch"
	CanonicalFailurePayload            CanonicalFailureCode = "payload_failed"
	CanonicalFailureQueueFull          CanonicalFailureCode = "queue_full"
	CanonicalFailureQueueRejected      CanonicalFailureCode = "queue_rejected"
	CanonicalFailurePanic              CanonicalFailureCode = "panic_isolated"
)

// CanonicalFailure deliberately excludes record, trace, span, endpoint,
// projected-value, and backend identities.
type CanonicalFailure struct {
	Destination string
	Generation  uint64
	Code        CanonicalFailureCode
}

type CanonicalObserver interface{ ObserveOTLPCanonicalFailure(CanonicalFailure) }

type CanonicalObserverFunc func(CanonicalFailure)

func (function CanonicalObserverFunc) ObserveOTLPCanonicalFailure(failure CanonicalFailure) {
	function(failure)
}

type CanonicalTraceAdapter interface {
	delivery.Adapter
	Close(context.Context) error
}

type CanonicalTraceConsumerOptions struct {
	Destination config.ObservabilityV8EffectiveDestination
	Generation  uint64
	Pipeline    *pipeline.TraceProjectionPipeline
	Adapter     CanonicalTraceAdapter
	Dispatcher  delivery.Config
	Observer    CanonicalObserver
}

type canonicalConsumerState uint32

const (
	canonicalConsumerPrepared canonicalConsumerState = iota
	canonicalConsumerActive
	canonicalConsumerStopping
	canonicalConsumerClosed
)

// CanonicalTraceConsumer owns one general OTLP destination in one immutable
// runtime generation. It accepts only generated canonical handoffs; it has no
// SDK ReadOnlySpan, raw-record, or pre-redaction enqueue surface.
type CanonicalTraceConsumer struct {
	destination string
	generation  uint64
	pipeline    *pipeline.TraceProjectionPipeline
	adapter     CanonicalTraceAdapter
	dispatcher  *delivery.Dispatcher
	observer    CanonicalObserver

	process func(observability.Record) (pipeline.TraceProjectionOutcome, error)
	payload func(pipeline.ProjectedDelivery) (delivery.Payload, error)

	state        atomic.Uint32
	lifecycleMu  sync.Mutex
	shutdown     chan struct{}
	drained      bool
	adapterDone  bool
	dispatchDone bool

	accepted     atomic.Uint64
	routeDropped atomic.Uint64
	queueDropped atomic.Uint64
	failed       atomic.Uint64
	closed       atomic.Uint64
}

var _ telemetry.V8CanonicalSpanConsumer = (*CanonicalTraceConsumer)(nil)

func NewCanonicalTraceConsumer(options CanonicalTraceConsumerOptions) (*CanonicalTraceConsumer, error) {
	if options.Generation == 0 || options.Generation > math.MaxInt64 || options.Pipeline == nil ||
		options.Pipeline.PlanDigest() == "" || nilCanonicalInterface(options.Adapter) ||
		nilCanonicalInterface(options.Observer) {
		return nil, &CanonicalConsumerError{code: CanonicalConsumerErrorInvalidDependencies}
	}
	if !validGeneralCanonicalDestination(options.Destination) {
		return nil, &CanonicalConsumerError{code: CanonicalConsumerErrorInvalidDestination}
	}
	if options.Dispatcher.Destination != options.Destination.Name || !options.Dispatcher.Enabled {
		return nil, &CanonicalConsumerError{code: CanonicalConsumerErrorInvalidDispatcher}
	}
	dispatcher, err := delivery.NewDispatcher(options.Dispatcher, options.Adapter)
	if err != nil {
		return nil, &CanonicalConsumerError{code: CanonicalConsumerErrorInvalidDispatcher}
	}
	consumer := &CanonicalTraceConsumer{
		destination: options.Destination.Name, generation: options.Generation,
		pipeline: options.Pipeline, adapter: options.Adapter, dispatcher: dispatcher,
		observer: options.Observer, shutdown: make(chan struct{}, 1),
	}
	consumer.shutdown <- struct{}{}
	consumer.process = options.Pipeline.Process
	consumer.payload = func(work pipeline.ProjectedDelivery) (delivery.Payload, error) {
		identity := work.Identity()
		return newCanonicalTracePayload(work.Projection(), delivery.RoutingIdentity{
			RecordID: identity.RecordID(), Bucket: string(identity.Bucket()), Signal: string(identity.Signal()),
			EventName: string(identity.EventName()), OriginDestination: identity.OriginDestination(),
		})
	}
	consumer.state.Store(uint32(canonicalConsumerPrepared))
	return consumer, nil
}

func validGeneralCanonicalDestination(destination config.ObservabilityV8EffectiveDestination) bool {
	if !destination.Enabled || !observability.IsStableToken(destination.Name) ||
		destination.Kind != config.ObservabilityV8DestinationOTLP || destination.Preset != "" ||
		destination.PresetProfile != "" || !destination.FirstMatchPerSignal ||
		!destination.Capabilities.Supports(observability.SignalTraces) {
		return false
	}
	if !validOpenInferenceCapability(destination) {
		return false
	}
	for _, signal := range destination.SelectedSignals {
		if signal == observability.SignalTraces {
			return true
		}
	}
	return false
}

func validOpenInferenceCapability(destination config.ObservabilityV8EffectiveDestination) bool {
	if len(destination.CompatibilityProfiles) != 1 {
		return false
	}
	capability := destination.CompatibilityProfiles[0]
	if capability.ID != observability.RuntimeOpenInferenceCompatibilityProfile ||
		capability.Availability != "available" {
		return false
	}
	manifest, err := profilemanifest.Get(observability.RuntimeOpenInferenceCompatibilityProfile)
	if err != nil || manifest.Availability != "available" ||
		manifest.RuntimeProjection.Status != "available" ||
		len(capability.EligibleSpanFamilies) != len(manifest.Families) {
		return false
	}
	expected := make(map[observability.EventName]observability.Bucket, len(manifest.Families))
	for _, family := range manifest.Families {
		if family.Signal != observability.SignalTraces || family.Eligibility != "eligible" {
			return false
		}
		expected[family.EventName] = family.Bucket
	}
	if len(expected) != len(manifest.Families) {
		return false
	}
	for _, family := range capability.EligibleSpanFamilies {
		if family.Availability != "available" || expected[family.EventName] != family.Bucket {
			return false
		}
		delete(expected, family.EventName)
	}
	return len(expected) == 0
}

func (consumer *CanonicalTraceConsumer) Activate() {
	if consumer == nil {
		return
	}
	consumer.lifecycleMu.Lock()
	defer consumer.lifecycleMu.Unlock()
	if canonicalConsumerState(consumer.state.Load()) != canonicalConsumerPrepared || consumer.dispatcher == nil {
		return
	}
	consumer.dispatcher.Activate()
	consumer.state.Store(uint32(canonicalConsumerActive))
}

func (consumer *CanonicalTraceConsumer) TryEnqueue(span telemetry.V8CanonicalEndedSpan) telemetry.V8CanonicalSpanEnqueueResult {
	if consumer == nil || canonicalConsumerState(consumer.state.Load()) != canonicalConsumerActive {
		if consumer != nil {
			consumer.closed.Add(1)
		}
		return telemetry.V8CanonicalSpanEnqueueClosed
	}
	return consumer.tryEnqueueRecord(span.Record())
}

func (consumer *CanonicalTraceConsumer) tryEnqueueRecord(record observability.Record) (result telemetry.V8CanonicalSpanEnqueueResult) {
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
		return telemetry.V8CanonicalSpanEnqueueClosed
	}
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
		consumer.routeDropped.Add(1)
		return telemetry.V8CanonicalSpanEnqueueDropped
	}
	payload, err := consumer.payload(*selected)
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

func (consumer *CanonicalTraceConsumer) ForceFlush(ctx context.Context) error {
	if consumer == nil {
		return nil
	}
	if ctx == nil {
		return &CanonicalConsumerError{code: CanonicalConsumerErrorInvalidContext}
	}
	return consumer.dispatcher.Flush(ctx)
}

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

type CanonicalTraceConsumerCounters struct {
	Accepted     uint64
	RouteDropped uint64
	QueueDropped uint64
	Failed       uint64
	Closed       uint64
}

func (consumer *CanonicalTraceConsumer) Counters() CanonicalTraceConsumerCounters {
	if consumer == nil {
		return CanonicalTraceConsumerCounters{}
	}
	return CanonicalTraceConsumerCounters{
		Accepted: consumer.accepted.Load(), RouteDropped: consumer.routeDropped.Load(),
		QueueDropped: consumer.queueDropped.Load(), Failed: consumer.failed.Load(), Closed: consumer.closed.Load(),
	}
}

// DeliveryHealthSnapshot exposes only the consumer's bounded dispatcher
// state. Projection records and transport details remain unreachable.
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
	failure := CanonicalFailure{Destination: consumer.destination, Generation: consumer.generation, Code: code}
	defer func() { _ = recover() }()
	consumer.observer.ObserveOTLPCanonicalFailure(failure)
}

func nilCanonicalInterface(value any) bool {
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
