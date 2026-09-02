// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/google/uuid"
)

const destinationCircuitV8Producer = "gateway.destination_circuit"

// recordDestinationCircuitHealthLogsV8 is the sibling of
// recordExporterHealthMetricsV8: it shares the same 15s destination-health
// poll but is intentionally NOT gated behind the exporter-error metric
// family. A destination circuit opening is a durable health transition in
// its own right, and disabling the (unrelated) exporter-error metric family
// must not silently blind an operator to circuit state.
func (s *Sidecar) recordDestinationCircuitHealthLogsV8(
	ctx context.Context,
	observedAt time.Time,
	health observabilityruntime.DestinationHealthSnapshot,
) {
	if s == nil || ctx == nil || observedAt.IsZero() {
		return
	}
	emitter := s.observabilityV8Emitter()
	if emitter == nil {
		return
	}
	s.recordDestinationCircuitTransitionsV8(ctx, observedAt, emitter, health)
}

// recordDestinationCircuitTransitionsV8 diffs the current per-destination
// circuit state against the last-observed state for the active graph
// generation and emits exactly one durable health log per open or close
// transition. Half-open (probe) states are intentionally not logged: a
// cooldown probe firing every few seconds during an outage would flood the
// durable log with events that carry no new operator-facing information
// beyond the open/closed boundary already captured.
//
// A fresh config generation resets the tracked baseline instead of carrying
// state forward, so a destination that reloads into an already-open circuit
// is correctly reported as newly open rather than silently treated as a
// continuation of a prior generation's outage.
func (s *Sidecar) recordDestinationCircuitTransitionsV8(
	ctx context.Context,
	observedAt time.Time,
	emitter sidecarRuntimeEmitter,
	health observabilityruntime.DestinationHealthSnapshot,
) {
	if s == nil || ctx == nil || emitter == nil || observedAt.IsZero() ||
		health.Generation == 0 || health.PlanDigest == "" {
		return
	}

	s.destinationCircuitMu.Lock()
	if s.destinationCircuitGeneration != health.Generation {
		s.destinationCircuitGeneration = health.Generation
		s.destinationCircuitState = make(map[string]delivery.CircuitState, len(health.Destinations))
	}
	if s.destinationCircuitState == nil {
		s.destinationCircuitState = make(map[string]delivery.CircuitState, len(health.Destinations))
	}

	type transition struct {
		name                string
		kind                string
		state               delivery.CircuitState
		previous            delivery.CircuitState
		consecutiveFailures uint64
		lastFailureClass    delivery.FailureClass
	}
	var transitions []transition

	for _, destination := range health.Destinations {
		if !destination.Enabled || !observability.IsStableToken(destination.Name) {
			continue
		}
		current := destination.CircuitState
		if current == "" {
			current = delivery.CircuitClosed
		}
		if current != delivery.CircuitOpen && current != delivery.CircuitClosed {
			// Half-open: a cooldown probe in flight. Never becomes the
			// tracked baseline, so a failed probe that reopens the circuit
			// is still recognized as a genuine transition instead of being
			// compared against a stale "half-open" baseline and missed.
			continue
		}
		previous, seen := s.destinationCircuitState[destination.Name]
		if !seen {
			// First observation for this destination in this generation.
			// Only report it if it starts life already open -- a routine
			// first-seen "closed" baseline is not a transition.
			if current != delivery.CircuitOpen {
				continue
			}
			previous = delivery.CircuitClosed
		}
		if previous == current {
			continue
		}
		transitions = append(transitions, transition{
			name: destination.Name, kind: string(destination.Kind),
			state: current, previous: previous,
			consecutiveFailures: destination.ConsecutiveFailures,
			lastFailureClass:    destination.LastFailureClass,
		})
	}
	s.destinationCircuitMu.Unlock()

	for _, t := range transitions {
		if err := emitDestinationCircuitTransitionV8(ctx, emitter, observedAt, t.name, t.kind, t.state, t.consecutiveFailures, t.lastFailureClass); err != nil {
			// Do not commit the new baseline: leave the prior state in
			// place so the next poll re-observes this as an unreported
			// transition and retries, instead of silently losing it.
			continue
		}
		s.destinationCircuitMu.Lock()
		s.destinationCircuitState[t.name] = t.state
		s.destinationCircuitMu.Unlock()
	}
}

func emitDestinationCircuitTransitionV8(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	observedAt time.Time,
	destinationName string,
	destinationKind string,
	state delivery.CircuitState,
	consecutiveFailures uint64,
	lastFailureClass delivery.FailureClass,
) error {
	if ctx == nil || emitter == nil {
		return &sidecarObservabilityError{code: sidecarObservabilityInvalidBinding}
	}

	opened := state == delivery.CircuitOpen
	action := "circuit_breaker_closed"
	eventName := observability.TelemetryEventSubsystemRestored
	severity := observability.SeverityMedium
	// DefenseClawHealthState is a schema-enforced enum
	// ({ready,starting,stopped,degraded,failed,restored}); the specific
	// circuit-open/circuit-closed distinction lives in the free-form action
	// field below instead, which is what the Splunk macro keys off.
	healthState := "restored"
	var errorCode observability.Optional[string]
	var errorSummary observability.Optional[string]
	if opened {
		action = "circuit_breaker_open"
		eventName = observability.TelemetryEventSubsystemDegraded
		severity = observability.SeverityHigh
		healthState = "degraded"
		errorCode = observability.Present("destination_circuit_open")
		errorSummary = observability.Present(fmt.Sprintf(
			"destination_kind=%s consecutive_failures=%d last_failure_class=%s",
			destinationKind, consecutiveFailures, string(lastFailureClass),
		))
	}

	producerKey := observability.ProducerKey(gatewaylog.EventError)
	classification := observability.ClassificationContext{
		Bucket:      observability.BucketPlatformHealth,
		EventName:   observability.EventName(eventName),
		RawSeverity: string(severity),
		MandatoryFacts: observability.MandatoryFacts{
			DurableHealthTransition: true,
		},
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		producerKey,
		classification,
		observability.SourceGateway,
		"",
		observability.ProducerKey(action),
	)
	if err != nil {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}

	_, err = emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if snapshot.Generation() > math.MaxInt64 ||
			(admission != router.AdmissionOrdinary && admission != router.AdmissionFloor) {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := observability.NewFamilyBuilder(
			observability.ClockFunc(func() time.Time { return observedAt }),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
		)
		if buildErr != nil {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		envelope := gatewayGeneratedEnvelope(
			ctx, snapshot, observability.SourceGateway, "", destinationCircuitV8Producer, action, "delivery",
		)
		if opened {
			return builder.BuildLogSubsystemDegraded(observability.LogSubsystemDegradedInput{
				Envelope:                         envelope,
				Severity:                         observability.Present(severity),
				LogLevel:                         observability.Present(observability.LogLevelWarn),
				Outcome:                          observability.OutcomeFailed,
				DefenseClawHealthSubsystem:       destinationName,
				DefenseClawHealthState:           healthState,
				DefenseClawHealthErrorSummary:    errorSummary,
				DefenseClawSchemaErrorCode:       errorCode,
				MandatoryDurableHealthTransition: true,
			})
		}
		return builder.BuildLogSubsystemRestored(observability.LogSubsystemRestoredInput{
			Envelope:                         envelope,
			Severity:                         observability.Present(severity),
			LogLevel:                         observability.Present(observability.LogLevelInfo),
			Outcome:                          observability.OutcomeCompleted,
			DefenseClawHealthSubsystem:       destinationName,
			DefenseClawHealthState:           healthState,
			MandatoryDurableHealthTransition: true,
		})
	})
	return err
}
