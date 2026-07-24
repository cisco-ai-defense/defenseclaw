// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type e2e6RuntimeBlockingAdapter struct {
	delivered chan runtimeDeliveredItem
	started   chan struct{}
	release   <-chan struct{}
	startOnce sync.Once
}

func (*e2e6RuntimeBlockingAdapter) EncodedSize(sizes []int) (int, bool) {
	return delivery.DelimitedEncodedSize(sizes, 0, 1, 0)
}

func (adapter *e2e6RuntimeBlockingAdapter) Deliver(
	ctx context.Context,
	batch delivery.Batch,
) delivery.DeliveryResult {
	adapter.startOnce.Do(func() { close(adapter.started) })
	select {
	case <-adapter.release:
		for _, item := range batch.Items() {
			adapter.delivered <- runtimeDeliveredItem{
				destination: batch.Destination(), bytes: item.Bytes(), identity: item.Identity(),
			}
		}
		return delivery.DeliveryResult{Outcome: delivery.OutcomeDelivered}
	case <-ctx.Done():
		return delivery.DeliveryResult{Outcome: delivery.OutcomeTransient}
	}
}

func TestE2E6RuntimeQueuePressurePreservesSQLiteSiblingAndRecovery(t *testing.T) {
	for _, test := range []struct {
		name          string
		queueItems    int
		queueBytes    int
		contents      []string
		acceptedCount int
	}{
		{
			name: "count", queueItems: 2,
			contents: []string{"first", "second", "newest"}, acceptedCount: 2,
		},
		{
			name: "projected_bytes", queueItems: 8, queueBytes: 4_198_400,
			contents: []string{
				strings.Repeat("a", 990_000), strings.Repeat("b", 990_000),
				strings.Repeat("c", 990_000), strings.Repeat("d", 990_000),
				strings.Repeat("e", 300_000),
			},
			acceptedCount: 4,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dependencies := newRuntimeTestDependencies(t)
			plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
				func(source *config.ObservabilityV8Source) {
					blocked := runtimeConsoleDestination("blocked", "none", test.queueItems)
					blocked.Batch.MaxQueueBytes = test.queueBytes
					source.Destinations = []config.ObservabilityV8DestinationSource{
						blocked, runtimeConsoleDestination("healthy", "none", len(test.contents)+1),
					}
				},
			)
			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseBlocked := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(releaseBlocked)
			blocked := &e2e6RuntimeBlockingAdapter{
				delivered: make(chan runtimeDeliveredItem, test.acceptedCount+1),
				started:   make(chan struct{}), release: release,
			}
			healthy := newRuntimeRecordingAdapter(len(test.contents) + 1)
			factory := runtimeAdapterFactoryFunc(func(
				_ context.Context,
				destination config.ObservabilityV8EffectiveDestination,
				_ telemetry.V8ResourceContext,
			) (delivery.Adapter, DestinationAdapterCleanup, error) {
				if destination.Name == "blocked" {
					return blocked, func(context.Context) error { return nil }, nil
				}
				return healthy, func(context.Context) error { return nil }, nil
			})
			runtime := runtimeWithAdapterFactory(t, dependencies, plan, factory, nil)

			ids := make([]string, len(test.contents))
			for index, content := range test.contents {
				ids[index] = "e2e6-" + test.name + "-" + string(rune('a'+index))
				outcome, err := runtime.Emit(
					t.Context(), diagnosticMetadata(t), runtimeContentRecordBuilder(ids[index], content),
				)
				if err != nil || !outcome.LocalPersisted() {
					t.Fatalf("emit %d persisted=%t err=%v", index, outcome.LocalPersisted(), err)
				}
				if index == 0 {
					select {
					case <-blocked.started:
					case <-time.After(10 * time.Second):
						t.Fatal("blocked destination did not enter delivery")
					}
				}
			}

			waitE2E6Runtime(t, func() bool {
				health := e2e6RuntimeHealth(t, runtime, "healthy")
				return health.Counters.Delivered == uint64(len(test.contents))
			})
			local := e2e6RuntimeHealth(t, runtime, config.ObservabilityV8LocalDestinationName)
			if local.State != delivery.HealthHealthy || local.Queue != nil {
				t.Fatalf("local SQLite health=%+v", local)
			}
			degraded := e2e6RuntimeHealth(t, runtime, "blocked")
			if degraded.State != delivery.HealthDegraded ||
				degraded.Reason != string(delivery.HealthReasonQueueFull) ||
				degraded.Counters.Accepted != uint64(test.acceptedCount) ||
				degraded.Counters.Dropped != 1 || degraded.Counters.Delivered != 0 ||
				degraded.Queue == nil || degraded.Queue.Items != test.acceptedCount {
				t.Fatalf("blocked degraded health=%+v", degraded)
			}
			if test.queueBytes > 0 && degraded.Queue.Bytes > test.queueBytes {
				t.Fatalf("blocked projected bytes=%d exceed max=%d", degraded.Queue.Bytes, test.queueBytes)
			}
			healthyIDs := receiveE2E6RuntimeIDs(t, healthy.delivered, len(test.contents))
			if !reflect.DeepEqual(healthyIDs, ids) {
				t.Fatalf("healthy sibling FIFO=%v want=%v", healthyIDs, ids)
			}
			events, err := dependencies.store.ListEvents(len(test.contents) + 8)
			if err != nil {
				t.Fatal(err)
			}
			localCounts := make(map[string]int, len(ids))
			for _, event := range events {
				localCounts[event.ID]++
			}
			for _, id := range ids {
				if localCounts[id] != 1 {
					t.Fatalf("SQLite count for %s=%d", id, localCounts[id])
				}
			}

			releaseBlocked()
			blockedIDs := receiveE2E6RuntimeIDs(t, blocked.delivered, test.acceptedCount)
			if want := ids[:test.acceptedCount]; !reflect.DeepEqual(blockedIDs, want) {
				t.Fatalf("blocked retained FIFO=%v want=%v", blockedIDs, want)
			}
			waitE2E6Runtime(t, func() bool {
				health := e2e6RuntimeHealth(t, runtime, "blocked")
				return health.State == delivery.HealthHealthy &&
					health.Reason == string(delivery.HealthReasonRecovered) &&
					health.Counters.Delivered == uint64(test.acceptedCount)
			})
			recovered := e2e6RuntimeHealth(t, runtime, "blocked")
			if recovered.LastFailure.IsZero() || recovered.LastSuccess.IsZero() ||
				recovered.LastSuccess.Before(recovered.LastFailure) {
				t.Fatalf("blocked recovered health=%+v", recovered)
			}
		})
	}
}

func e2e6RuntimeHealth(t *testing.T, runtime *Runtime, name string) DestinationHealth {
	t.Helper()
	snapshot, err := runtime.DestinationHealthSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, health := range snapshot.Destinations {
		if health.Name == name {
			return health
		}
	}
	t.Fatalf("destination %s missing from health snapshot", name)
	return DestinationHealth{}
}

func receiveE2E6RuntimeIDs(
	t *testing.T,
	deliveries <-chan runtimeDeliveredItem,
	count int,
) []string {
	t.Helper()
	ids := make([]string, 0, count)
	for range count {
		select {
		case item := <-deliveries:
			ids = append(ids, item.identity.RecordID)
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for E2E-6 delivery")
		}
	}
	return ids
}

func waitE2E6Runtime(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("E2E-6 runtime condition did not become true")
		}
		time.Sleep(time.Millisecond)
	}
}
