// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// DestinationDispatchComponentName is the generation-owned optional-log
// handoff resolved by Runtime.Emit after mandatory local persistence.
const DestinationDispatchComponentName = "destination-dispatch"

const (
	defaultDestinationAttemptTimeout = 10 * time.Second
	defaultDestinationMaxAttempts    = 3
	defaultDestinationInitialBackoff = 100 * time.Millisecond
	defaultDestinationMaxBackoff     = 5 * time.Second
	defaultDestinationHealthInterval = time.Second
	maxDestinationBatchBytes         = 64 * 1024 * 1024
)

// DestinationAdapterCleanup releases one adapter acquisition. Runtime wraps
// it so a successful cleanup is invoked at most once while a failed cleanup
// remains retryable under runtimegraph's bounded cleanup ownership.
type DestinationAdapterCleanup func(context.Context) error

// DestinationAdapterFactory is process-stable. PrepareDestination receives an
// unmasked, detached runtime destination and the exact resource snapshot
// resolved by the plan generation's TelemetryProviderFactory. The resource is
// required for OTLP logs and is the zero value for other destination kinds.
// Preparation must finish all fallible adapter initialization before returning
// and must not retain or mutate supplied values. Concrete transports remain
// outside the common dispatch runtime.
type DestinationAdapterFactory interface {
	PrepareDestination(
		context.Context,
		config.ObservabilityV8EffectiveDestination,
		telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error)
}

type destinationDispatchFactory struct {
	adapters  DestinationAdapterFactory
	resources *telemetry.V8ProviderFactory
	observer  *safeDeliveryObserver
}

func (*destinationDispatchFactory) Name() string { return DestinationDispatchComponentName }

func (factory *destinationDispatchFactory) Prepare(
	ctx context.Context,
	input runtimegraph.BuildInput,
	acquisitions *runtimegraph.Acquisitions,
) (runtimegraph.Component, error) {
	if factory == nil || ctx == nil || input.Config.Plan == nil || acquisitions == nil {
		return nil, &destinationDispatchError{}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	component := &destinationDispatchComponent{
		digest: input.Config.PlanDigest, generation: input.Generation,
		byName:   make(map[string]*destinationDispatcher),
		observer: factory.observer,
	}
	var resourceContext telemetry.V8ResourceContext
	resourceReady := false
	for _, displayed := range input.Config.Plan.Destinations() {
		if displayed.Kind == config.ObservabilityV8DestinationLocalSQLite ||
			!displayed.Enabled || !destinationSelectsLogs(displayed) {
			continue
		}
		if factory.adapters == nil || nilInterface(factory.adapters) {
			return nil, &destinationDispatchError{}
		}
		destination, ok := input.Config.Plan.RuntimeDestination(displayed.Name)
		if !ok || destination.Name != displayed.Name || destination.Kind != displayed.Kind ||
			!destination.Enabled || !destinationSelectsLogs(destination) {
			return nil, &destinationDispatchError{}
		}
		if destination.Kind == config.ObservabilityV8DestinationOTLP && !resourceReady {
			if factory.resources == nil {
				return nil, &destinationDispatchError{}
			}
			var err error
			resourceContext, err = factory.resources.ResourceContext(input.Config.Plan)
			if err != nil {
				return nil, &destinationDispatchError{}
			}
			resourceReady = true
		}
		adapter, cleanup, err := factory.adapters.PrepareDestination(ctx, destination, resourceContext)
		if cleanup == nil {
			return nil, &destinationDispatchError{}
		}
		cleanup = idempotentAdapterCleanup(cleanup)
		if err := acquisitions.Register("adapter-"+destination.Name, runtimegraph.CleanupFunc(cleanup)); err != nil {
			_ = cleanup(ctx)
			return nil, &destinationDispatchError{}
		}
		if err != nil || nilInterface(adapter) {
			return nil, &destinationDispatchError{}
		}
		dispatcherConfig, ok := CompiledDispatcherConfig(
			destination, input.Generation, observability.SignalLogs, component.observer,
		)
		if !ok {
			return nil, &destinationDispatchError{}
		}
		dispatcher, err := delivery.NewDispatcher(dispatcherConfig, adapter)
		if err != nil {
			return nil, &destinationDispatchError{}
		}
		entry := &destinationDispatcher{
			kind: destination.Kind, dispatcher: dispatcher,
		}
		component.order = append(component.order, destination.Name)
		component.byName[destination.Name] = entry
	}
	return component, nil
}

func destinationSelectsLogs(destination config.ObservabilityV8EffectiveDestination) bool {
	for _, signal := range destination.SelectedSignals {
		if signal == observability.SignalLogs {
			return true
		}
	}
	return false
}

// CompiledDispatcherConfig maps one compiler-validated destination transport
// to the common bounded delivery runtime. Signal-specific destination
// assemblers use the same mapping so logs and canonical trace projections do
// not silently diverge in queue, batching, retry, or timeout behavior.
func CompiledDispatcherConfig(
	destination config.ObservabilityV8EffectiveDestination,
	generation uint64,
	signal observability.Signal,
	observer delivery.Observer,
) (delivery.Config, bool) {
	if generation == 0 || !observability.IsSignal(signal) {
		return delivery.Config{}, false
	}
	batch := destination.Transport.Batch
	if batch == nil || batch.MaxQueueSize <= 0 || batch.MaxQueueBytes <= 0 {
		return delivery.Config{}, false
	}
	maxBatchItems := batch.MaxExportBatchSize
	maxBatchBytes := batch.MaxExportBatchBytes
	scheduledDelay := time.Duration(batch.ScheduledDelayMS) * time.Millisecond
	if maxBatchItems == 0 {
		// Queue-only destinations serialize one projection per adapter call.
		maxBatchItems = 1
	}
	if maxBatchBytes == 0 {
		// Queue bytes count only immutable projected payloads. JSONL adds a
		// newline and console may escape each projected byte, so reusing a small
		// queue-byte ceiling as an encoded-write ceiling would reject one valid
		// maximum-sized projection. Queue-only adapters write one record at a
		// time and the canonical projection bound keeps that encoded record below
		// this process constant.
		maxBatchBytes = maxDestinationBatchBytes
	}
	attemptTimeout := defaultDestinationAttemptTimeout
	if destination.Transport.TimeoutMS > 0 {
		attemptTimeout = time.Duration(destination.Transport.TimeoutMS) * time.Millisecond
	}
	return delivery.Config{
		Destination: destination.Name, Generation: generation, Signal: string(signal), Enabled: true,
		MaxQueueItems: batch.MaxQueueSize, MaxQueueBytes: batch.MaxQueueBytes,
		MaxBatchItems: maxBatchItems, MaxBatchBytes: maxBatchBytes,
		ScheduledDelay: scheduledDelay, AttemptTimeout: attemptTimeout,
		Retry: delivery.RetryPolicy{
			MaxAttempts:    defaultDestinationMaxAttempts,
			InitialBackoff: defaultDestinationInitialBackoff,
			MaxBackoff:     defaultDestinationMaxBackoff,
		},
		Observer: observer, ObserverInterval: defaultDestinationHealthInterval,
	}, true
}

func idempotentAdapterCleanup(cleanup DestinationAdapterCleanup) DestinationAdapterCleanup {
	var mutex sync.Mutex
	complete := false
	return func(ctx context.Context) error {
		mutex.Lock()
		defer mutex.Unlock()
		if complete {
			return nil
		}
		if err := cleanup(ctx); err != nil {
			return err
		}
		complete = true
		return nil
	}
}

type destinationDispatchError struct{}

func (*destinationDispatchError) Error() string {
	return "observability destination dispatch initialization failed"
}

type destinationDispatcher struct {
	kind       config.ObservabilityV8DestinationKind
	dispatcher *delivery.Dispatcher
}

// destinationDispatchComponent owns only immutable destination identities and
// independent dispatchers. Queued payload bytes therefore remain attached to
// the graph lease generation that projected them during reload.
type destinationDispatchComponent struct {
	digest     string
	generation uint64
	order      []string
	byName     map[string]*destinationDispatcher
	observer   *safeDeliveryObserver
}

func (component *destinationDispatchComponent) deliveryHealthSnapshots() []delivery.HealthSnapshot {
	if component == nil {
		return nil
	}
	result := make([]delivery.HealthSnapshot, 0, len(component.order))
	for _, name := range component.order {
		entry := component.byName[name]
		if entry == nil || entry.dispatcher == nil {
			continue
		}
		snapshot := entry.dispatcher.DeliveryHealthSnapshot()
		if snapshot.Generation != component.generation || snapshot.Destination != name {
			continue
		}
		result = append(result, snapshot)
	}
	return result
}

func (component *destinationDispatchComponent) Activate() {
	if component == nil {
		return
	}
	for _, name := range component.order {
		component.byName[name].dispatcher.Activate()
	}
}

func (component *destinationDispatchComponent) StopIntake(ctx context.Context) error {
	return component.reverseLifecycle(func(dispatcher *delivery.Dispatcher) error {
		return dispatcher.StopIntake(ctx)
	})
}

func (component *destinationDispatchComponent) Drain(ctx context.Context) error {
	return component.reverseLifecycle(func(dispatcher *delivery.Dispatcher) error {
		return dispatcher.Drain(ctx)
	})
}

func (component *destinationDispatchComponent) Close(ctx context.Context) error {
	return component.reverseLifecycle(func(dispatcher *delivery.Dispatcher) error {
		return dispatcher.Close(ctx)
	})
}

func (component *destinationDispatchComponent) reverseLifecycle(
	operation func(*delivery.Dispatcher) error,
) error {
	if component == nil || operation == nil {
		return &destinationDispatchError{}
	}
	// Always visit every dispatcher in reverse construction order. Returning
	// only the first bounded failure is intentional: runtimegraph needs a
	// failure signal, while joining transport errors would widen the diagnostic
	// surface and retain details from every destination.
	var first error
	for index := len(component.order) - 1; index >= 0; index-- {
		entry := component.byName[component.order[index]]
		if entry == nil || entry.dispatcher == nil {
			if first == nil {
				first = &destinationDispatchError{}
			}
			continue
		}
		if err := operation(entry.dispatcher); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (component *destinationDispatchComponent) Enqueue(work pipeline.ProjectedDelivery) {
	if component == nil {
		return
	}
	route := work.Delivery()
	entry := component.byName[route.DestinationName]
	if entry == nil || entry.dispatcher == nil || entry.kind != route.DestinationKind {
		component.observeBoundedFailure(route.DestinationName)
		return
	}
	encoded, err := work.Projection().Bytes()
	if err != nil {
		component.observeBoundedFailure(route.DestinationName)
		return
	}
	identity := work.Identity()
	payload, err := delivery.NewPayload(encoded, delivery.RoutingIdentity{
		RecordID: identity.RecordID(), Bucket: string(identity.Bucket()),
		Signal: string(identity.Signal()), EventName: string(identity.EventName()),
		OriginDestination: identity.OriginDestination(),
	})
	if err != nil {
		component.observeBoundedFailure(route.DestinationName)
		return
	}
	result := entry.dispatcher.Enqueue(payload)
	if result.Disposition == delivery.EnqueueRejected {
		component.observeBoundedFailure(route.DestinationName)
	}
}

func (component *destinationDispatchComponent) ObserveProjectionFailure(failure pipeline.OptionalFailure) {
	if component == nil {
		return
	}
	component.observeBoundedFailure(failure.DestinationName())
}

func (component *destinationDispatchComponent) observeBoundedFailure(destination string) {
	observeBoundedDestinationFailure(component.observer, destination)
}

func observeBoundedDestinationFailure(observer *safeDeliveryObserver, destination string) {
	if !observability.IsStableToken(destination) {
		return
	}
	observer.Observe(delivery.HealthTransition{
		Destination: destination,
		Previous:    delivery.HealthHealthy,
		Current:     delivery.HealthDegraded,
		Reason:      delivery.HealthReasonDeliveryFailed,
		OccurredAt:  time.Now().UTC(),
	})
}

// safeDeliveryObserver makes the process-stable observer seam nonblocking and
// panic-safe. At most one callback can be outstanding; another transition is
// dropped rather than retaining an unbounded queue or stalling a producer.
type safeDeliveryObserver struct {
	next delivery.Observer

	mu       sync.Mutex
	slots    chan struct{}
	wait     sync.WaitGroup
	stopped  atomic.Bool
	doneOnce sync.Once
	done     chan struct{}
}

func newSafeDeliveryObserver(next delivery.Observer) *safeDeliveryObserver {
	return &safeDeliveryObserver{
		next: next, slots: make(chan struct{}, 1), done: make(chan struct{}),
	}
}

func (observer *safeDeliveryObserver) Observe(transition delivery.HealthTransition) {
	if observer == nil || observer.next == nil || nilInterface(observer.next) || observer.stopped.Load() {
		return
	}
	observer.mu.Lock()
	if observer.stopped.Load() {
		observer.mu.Unlock()
		return
	}
	select {
	case observer.slots <- struct{}{}:
		observer.wait.Add(1)
	default:
		observer.mu.Unlock()
		return
	}
	observer.mu.Unlock()
	go func() {
		defer observer.wait.Done()
		defer func() {
			<-observer.slots
			_ = recover()
		}()
		observer.next.Observe(transition)
	}()
}

func (observer *safeDeliveryObserver) Close(ctx context.Context) error {
	if observer == nil {
		return nil
	}
	if ctx == nil {
		return &destinationDispatchError{}
	}
	observer.mu.Lock()
	observer.stopped.Store(true)
	observer.doneOnce.Do(func() {
		go func() {
			observer.wait.Wait()
			close(observer.done)
		}()
	})
	observer.mu.Unlock()
	select {
	case <-observer.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var _ runtimegraph.ComponentFactory = (*destinationDispatchFactory)(nil)
var _ runtimegraph.Component = (*destinationDispatchComponent)(nil)
var _ delivery.Observer = (*safeDeliveryObserver)(nil)
