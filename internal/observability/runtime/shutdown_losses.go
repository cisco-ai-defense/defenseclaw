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
	"sort"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// shutdownLossSettle bounds how long Close waits, after its flush deadline,
// for cancelled destination workers to count the work they abandon.
const shutdownLossSettle = 500 * time.Millisecond

// ShutdownLoss counts one destination signal's records that Close dropped or
// left unsent: work still queued or in flight when the flush deadline passed,
// and records dropped during the flush itself. It carries no content.
type ShutdownLoss struct {
	Destination string
	Signal      observability.Signal
	Records     uint64
}

type shutdownLossSource struct {
	source      delivery.SnapshotSource
	destination string
	signal      string
	baseDropped uint64
}

// carriedShutdownLosses are records an earlier gateway process lost at
// shutdown. They are added to the dropped counters of the generation that was
// active when they were carried, so a reload does not report them again.
type carriedShutdownLosses struct {
	mu         sync.Mutex
	generation uint64
	records    map[string]uint64
}

func shutdownLossKey(destination, signal string) string {
	return destination + "\x00" + signal
}

// beginShutdownLossCount records every destination signal's dropped counter
// in the active graph before Close starts flushing. Secure Client keeps
// origin/main's shutdown and counts nothing (#1092).
func (runtime *Runtime) beginShutdownLossCount(ctx context.Context) []shutdownLossSource {
	if runtime == nil || runtime.secureClient || runtime.manager == nil || ctx == nil {
		return nil
	}
	lease, err := runtime.manager.Acquire(ctx)
	if err != nil {
		return nil
	}
	defer lease.Release()
	graph := lease.Graph()
	if graph == nil {
		return nil
	}
	var sources []delivery.SnapshotSource
	if value, ok := lease.Component(DestinationDispatchComponentName); ok {
		if dispatch, typed := value.(*destinationDispatchComponent); typed && dispatch != nil {
			for _, name := range dispatch.order {
				if entry := dispatch.byName[name]; entry != nil && entry.dispatcher != nil {
					sources = append(sources, entry.dispatcher)
				}
			}
		}
	}
	if value, ok := lease.Component(telemetry.V8ProviderComponentName); ok {
		if provider, typed := value.(*telemetry.V8ProviderComponent); typed && provider != nil {
			sources = append(sources, provider.DeliverySources()...)
		}
	}
	counted := make([]shutdownLossSource, 0, len(sources))
	for _, source := range sources {
		snapshot, ok := shutdownLossSnapshot(source)
		if !ok || snapshot.Generation != graph.Generation() || !observability.IsStableToken(snapshot.Destination) ||
			!observability.IsSignal(observability.Signal(snapshot.Signal)) {
			continue
		}
		counted = append(counted, shutdownLossSource{
			source: source, destination: snapshot.Destination, signal: snapshot.Signal,
			baseDropped: snapshot.Counters.Dropped,
		})
	}
	return counted
}

// countShutdownLosses waits up to settle for the queues to empty, then returns
// what each destination signal dropped since the count began plus what it
// still holds. A dispatcher counts a record as dropped before it leaves the
// queue, so an emptied queue's records are all in the dropped delta.
func countShutdownLosses(sources []shutdownLossSource, settle time.Duration) []ShutdownLoss {
	deadline := time.Now().Add(settle)
	for {
		queued := false
		for _, counted := range sources {
			if snapshot, ok := shutdownLossSnapshot(counted.source); ok && snapshot.Queue != nil && snapshot.Queue.Items > 0 {
				queued = true
				break
			}
		}
		if !queued || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	byKey := make(map[string]*ShutdownLoss, len(sources))
	for _, counted := range sources {
		snapshot, ok := shutdownLossSnapshot(counted.source)
		if !ok {
			continue
		}
		var records uint64
		if snapshot.Counters.Dropped > counted.baseDropped {
			records = snapshot.Counters.Dropped - counted.baseDropped
		}
		if snapshot.Queue != nil && snapshot.Queue.Items > 0 {
			records = addUint64(records, uint64(snapshot.Queue.Items))
		}
		if records == 0 {
			continue
		}
		key := shutdownLossKey(counted.destination, counted.signal)
		if loss := byKey[key]; loss != nil {
			loss.Records = addUint64(loss.Records, records)
			continue
		}
		byKey[key] = &ShutdownLoss{
			Destination: counted.destination, Signal: observability.Signal(counted.signal), Records: records,
		}
	}
	losses := make([]ShutdownLoss, 0, len(byKey))
	for _, loss := range byKey {
		losses = append(losses, *loss)
	}
	sort.Slice(losses, func(left, right int) bool {
		if losses[left].Destination != losses[right].Destination {
			return losses[left].Destination < losses[right].Destination
		}
		return losses[left].Signal < losses[right].Signal
	})
	return losses
}

func shutdownLossSnapshot(source delivery.SnapshotSource) (snapshot delivery.HealthSnapshot, ok bool) {
	if source == nil || nilInterface(source) {
		return delivery.HealthSnapshot{}, false
	}
	defer func() {
		if recover() != nil {
			snapshot, ok = delivery.HealthSnapshot{}, false
		}
	}()
	return source.DeliveryHealthSnapshot(), true
}

// ShutdownLosses returns, per destination signal, what the first Close that
// found an active graph dropped or left unsent.
func (runtime *Runtime) ShutdownLosses() []ShutdownLoss {
	if runtime == nil {
		return nil
	}
	runtime.lifecycleMu.Lock()
	defer runtime.lifecycleMu.Unlock()
	return append([]ShutdownLoss(nil), runtime.shutdownLosses...)
}

// CarryShutdownLosses adds the records an earlier gateway process lost at
// shutdown to the dropped counters that gateway health, doctor and the
// defenseclaw.queue.drops delta metric read for the active generation, so they
// are reported once after the restart (GAP-1096). It returns the losses it
// applied; a loss whose destination signal is not active is left out.
func (runtime *Runtime) CarryShutdownLosses(ctx context.Context, losses []ShutdownLoss) ([]ShutdownLoss, error) {
	if runtime == nil || runtime.manager == nil || ctx == nil {
		return nil, &Error{code: ErrorInvalidDependency}
	}
	if runtime.secureClient || len(losses) == 0 {
		return nil, nil
	}
	snapshot, err := runtime.DestinationHealthSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	active := map[string]bool{}
	for _, destination := range snapshot.Destinations {
		for _, source := range destination.Sources {
			active[shutdownLossKey(source.Destination, source.Signal)] = true
		}
	}
	runtime.carried.mu.Lock()
	defer runtime.carried.mu.Unlock()
	if runtime.carried.generation != snapshot.Generation || runtime.carried.records == nil {
		runtime.carried.generation = snapshot.Generation
		runtime.carried.records = map[string]uint64{}
	}
	applied := make([]ShutdownLoss, 0, len(losses))
	for _, loss := range losses {
		key := shutdownLossKey(loss.Destination, string(loss.Signal))
		if loss.Records == 0 || !active[key] {
			continue
		}
		runtime.carried.records[key] = addUint64(runtime.carried.records[key], loss.Records)
		applied = append(applied, loss)
	}
	return applied, nil
}

func (runtime *Runtime) carriedDropped(generation uint64, destination, signal string) uint64 {
	if runtime == nil {
		return 0
	}
	runtime.carried.mu.Lock()
	defer runtime.carried.mu.Unlock()
	if runtime.carried.generation != generation {
		return 0
	}
	return runtime.carried.records[shutdownLossKey(destination, signal)]
}
