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
	"math"
	"sort"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// DestinationHealth is a detached operator-safe view of one effective
// destination. Sources contains at most one entry per selected signal. Queue
// is the exact sum of only non-nil source queues and remains nil for a
// destination with no DefenseClaw-owned queue.
type DestinationHealth struct {
	Name        string
	Kind        config.ObservabilityV8DestinationKind
	Enabled     bool
	Signals     []observability.Signal
	State       delivery.HealthState
	Reason      string
	Queue       *delivery.QueueSnapshot
	Counters    delivery.Counters
	LastSuccess time.Time
	LastFailure time.Time
	Sources     []delivery.HealthSnapshot
}

// DestinationHealthSnapshot is pinned to exactly one active graph generation.
// Every slice and queue pointer is detached from the runtime graph.
type DestinationHealthSnapshot struct {
	Generation   uint64
	PlanDigest   string
	Destinations []DestinationHealth
}

// DestinationHealthSnapshot acquires one graph lease, joins the complete
// effective destination inventory to read-only generation components, and
// releases the lease only after all source snapshots have been copied.
func (runtime *Runtime) DestinationHealthSnapshot(
	ctx context.Context,
) (DestinationHealthSnapshot, error) {
	if runtime == nil || runtime.manager == nil || ctx == nil {
		return DestinationHealthSnapshot{}, &Error{code: ErrorInvalidDependency}
	}
	lease, err := runtime.manager.Acquire(ctx)
	if err != nil {
		return DestinationHealthSnapshot{}, err
	}
	defer lease.Release()
	graph := lease.Graph()
	if graph == nil || graph.Plan() == nil || graph.Generation() == 0 {
		return DestinationHealthSnapshot{}, &Error{code: ErrorComponentUnavailable}
	}
	localValue, localOK := lease.Component(LocalLogComponentName)
	local, localTyped := localValue.(*localLogComponent)
	if !localOK || !localTyped || local == nil || local.digest != graph.Digest() {
		return DestinationHealthSnapshot{}, &Error{code: ErrorComponentUnavailable}
	}

	displayed := graph.Plan().Destinations()
	if len(displayed) == 0 || len(displayed) > config.ObservabilityV8MaxDestinations+1 {
		return DestinationHealthSnapshot{}, &Error{code: ErrorComponentUnavailable}
	}
	rows := make([]DestinationHealth, 0, len(displayed))
	byName := make(map[string]int, len(displayed))
	for _, destination := range displayed {
		if !observability.IsStableToken(destination.Name) || len(destination.Name) > 64 {
			return DestinationHealthSnapshot{}, &Error{code: ErrorComponentUnavailable}
		}
		signals := append([]observability.Signal(nil), destination.SelectedSignals...)
		row := DestinationHealth{
			Name: destination.Name, Kind: destination.Kind, Enabled: destination.Enabled,
			Signals: signals,
		}
		if !destination.Enabled {
			row.State = delivery.HealthDisabled
		} else if destination.Kind == config.ObservabilityV8DestinationLocalSQLite {
			// The graph lease can resolve only after the mandatory local component
			// was initialized and activated for this generation.
			row.State = delivery.HealthHealthy
			row.Reason = string(delivery.HealthReasonActivated)
		}
		byName[destination.Name] = len(rows)
		rows = append(rows, row)
	}

	sources := make([]delivery.HealthSnapshot, 0, len(rows)*2)
	if value, ok := lease.Component(DestinationDispatchComponentName); ok {
		if dispatch, typed := value.(*destinationDispatchComponent); typed && dispatch != nil &&
			dispatch.digest == graph.Digest() && dispatch.generation == graph.Generation() {
			sources = append(sources, dispatch.deliveryHealthSnapshots()...)
		}
	}
	if value, ok := lease.Component(telemetry.V8ProviderComponentName); ok {
		if provider, typed := value.(*telemetry.V8ProviderComponent); typed && provider != nil {
			sources = append(sources, provider.DeliveryHealthSnapshots()...)
		}
	}

	sort.Slice(sources, func(left, right int) bool {
		if sources[left].Destination != sources[right].Destination {
			return sources[left].Destination < sources[right].Destination
		}
		return sources[left].Signal < sources[right].Signal
	})
	seen := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		index, exists := byName[source.Destination]
		if !exists || source.Generation != graph.Generation() ||
			!validDeliveryHealthState(source.State) ||
			!validDeliveryHealthReason(source.Reason) {
			continue
		}
		row := &rows[index]
		signal := observability.Signal(source.Signal)
		if !row.Enabled || !containsHealthSignal(row.Signals, signal) {
			continue
		}
		identity := source.Destination + "\x00" + source.Signal
		if _, duplicate := seen[identity]; duplicate {
			continue
		}
		seen[identity] = struct{}{}
		if source.Queue != nil {
			if !validQueueSnapshot(*source.Queue) {
				continue
			}
			queue := *source.Queue
			source.Queue = &queue
			mergeQueue(row, queue)
		}
		row.Sources = append(row.Sources, source)
		row.Counters = addCounters(row.Counters, source.Counters)
		if healthStateRank(source.State) > healthStateRank(row.State) {
			row.State = source.State
			row.Reason = source.Reason
		}
		if source.LastSuccess.After(row.LastSuccess) {
			row.LastSuccess = source.LastSuccess.UTC()
		}
		if source.LastFailure.After(row.LastFailure) {
			row.LastFailure = source.LastFailure.UTC()
		}
	}

	return DestinationHealthSnapshot{
		Generation: graph.Generation(), PlanDigest: graph.Digest(), Destinations: rows,
	}, nil
}

func validDeliveryHealthReason(reason string) bool {
	switch reason {
	case "", string(delivery.HealthReasonActivated), string(delivery.HealthReasonQueueFull),
		string(delivery.HealthReasonRetryable), string(delivery.HealthReasonPartial),
		string(delivery.HealthReasonDeliveryFailed), string(delivery.HealthReasonRecovered),
		string(delivery.HealthReasonIntakeStopped), string(delivery.HealthReasonClosed),
		string(delivery.HealthReasonOriginLoop),
		"listener_bound", "listener_failed", "scrape_failed", "scrape_recovered",
		"server_failed", "drain_started":
		return true
	default:
		return false
	}
}

func containsHealthSignal(signals []observability.Signal, wanted observability.Signal) bool {
	if !observability.IsSignal(wanted) {
		return false
	}
	for _, signal := range signals {
		if signal == wanted {
			return true
		}
	}
	return false
}

func validDeliveryHealthState(state delivery.HealthState) bool {
	switch state {
	case delivery.HealthDisabled, delivery.HealthInitializing, delivery.HealthHealthy,
		delivery.HealthDegraded, delivery.HealthFailing, delivery.HealthDraining,
		delivery.HealthStopped:
		return true
	default:
		return false
	}
}

func healthStateRank(state delivery.HealthState) int {
	switch state {
	case delivery.HealthFailing:
		return 7
	case delivery.HealthDegraded:
		return 6
	case delivery.HealthStopped:
		return 5
	case delivery.HealthDraining:
		return 4
	case delivery.HealthInitializing:
		return 3
	case delivery.HealthHealthy:
		return 2
	case delivery.HealthDisabled:
		return 1
	default:
		return 0
	}
}

func validQueueSnapshot(queue delivery.QueueSnapshot) bool {
	return queue.Items >= 0 && queue.Bytes >= 0 && queue.InFlightItems >= 0 &&
		queue.InFlightBytes >= 0 && queue.MaxItems > 0 && queue.MaxBytes > 0 &&
		queue.Items <= queue.MaxItems && queue.Bytes <= queue.MaxBytes &&
		queue.InFlightItems <= queue.Items && queue.InFlightBytes <= queue.Bytes
}

func mergeQueue(row *DestinationHealth, source delivery.QueueSnapshot) {
	if row.Queue == nil {
		copy := source
		row.Queue = &copy
		return
	}
	row.Queue.Items = addInt(row.Queue.Items, source.Items)
	row.Queue.Bytes = addInt(row.Queue.Bytes, source.Bytes)
	row.Queue.InFlightItems = addInt(row.Queue.InFlightItems, source.InFlightItems)
	row.Queue.InFlightBytes = addInt(row.Queue.InFlightBytes, source.InFlightBytes)
	row.Queue.MaxItems = addInt(row.Queue.MaxItems, source.MaxItems)
	row.Queue.MaxBytes = addInt(row.Queue.MaxBytes, source.MaxBytes)
}

func addInt(left, right int) int {
	if right > math.MaxInt-left {
		return math.MaxInt
	}
	return left + right
}

func addCounters(left, right delivery.Counters) delivery.Counters {
	return delivery.Counters{
		Accepted:  addUint64(left.Accepted, right.Accepted),
		Delivered: addUint64(left.Delivered, right.Delivered),
		Retried:   addUint64(left.Retried, right.Retried),
		Dropped:   addUint64(left.Dropped, right.Dropped),
		Rejected:  addUint64(left.Rejected, right.Rejected),
		Failed:    addUint64(left.Failed, right.Failed),
	}
}

func addUint64(left, right uint64) uint64 {
	if right > math.MaxUint64-left {
		return math.MaxUint64
	}
	return left + right
}
