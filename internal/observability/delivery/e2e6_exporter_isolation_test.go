// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package delivery_test

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

func TestE2E6QueueDropsNewestAtByteLimitAndRetainsOlderFIFO(t *testing.T) {
	release := make(chan struct{})
	adapter := &fakeAdapter{started: make(chan struct{}, 1), release: release}
	config := testConfig("byte-only-limited")
	config.MaxQueueItems = 4
	config.MaxBatchItems = 1
	config.MaxQueueBytes = 6
	dispatcher, err := delivery.NewDispatcher(config, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	if result := dispatcher.Enqueue(payload(t, "older-a", "abc")); !result.Accepted() {
		t.Fatalf("older A=%+v", result)
	}
	<-adapter.started
	if result := dispatcher.Enqueue(payload(t, "older-b", "def")); !result.Accepted() {
		t.Fatalf("older B=%+v", result)
	}
	if result := dispatcher.Enqueue(payload(t, "newest", "z")); result.Disposition != delivery.EnqueueDropped || result.Reason != delivery.ReasonByteLimit {
		t.Fatalf("newest=%+v, want byte-only drop", result)
	}
	items, projectedBytes, inFlightItems, inFlightBytes := dispatcher.QueueUsage()
	if items != 2 || projectedBytes != 6 || inFlightItems != 1 || inFlightBytes != 3 {
		t.Fatalf("usage=(%d,%d,%d,%d), want (2,6,1,3)",
			items, projectedBytes, inFlightItems, inFlightBytes)
	}
	degraded := dispatcher.DeliveryHealthSnapshot()
	if degraded.State != delivery.HealthDegraded || degraded.Reason != string(delivery.HealthReasonQueueFull) ||
		degraded.Counters.Accepted != 2 || degraded.Counters.Dropped != 1 {
		t.Fatalf("degraded health=%+v", degraded)
	}

	close(release)
	waitFor(t, func() bool {
		snapshot := dispatcher.DeliveryHealthSnapshot()
		return snapshot.State == delivery.HealthHealthy &&
			snapshot.Reason == string(delivery.HealthReasonRecovered) &&
			snapshot.Counters.Delivered == 2
	})
	recovered := dispatcher.DeliveryHealthSnapshot()
	if recovered.LastSuccess.IsZero() || recovered.LastFailure.IsZero() ||
		recovered.LastSuccess.Before(recovered.LastFailure) {
		t.Fatalf("recovered health=%+v", recovered)
	}
	closeDispatcher(t, dispatcher)
	attempts := adapter.snapshot()
	if len(attempts) != 2 || len(attempts[0].ids) != 1 || len(attempts[1].ids) != 1 ||
		attempts[0].ids[0] != "older-a" || attempts[1].ids[0] != "older-b" {
		t.Fatalf("retained FIFO attempts=%#v", attempts)
	}
	if counters := dispatcher.Counters(); counters.Accepted != 2 || counters.Delivered != 2 ||
		counters.Dropped != 1 || counters.Rejected != 0 {
		t.Fatalf("terminal counters=%+v", counters)
	}
}
