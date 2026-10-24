// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package delivery_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

type payloadOutcomes struct {
	mu  sync.Mutex
	got map[string][]bool
}

func (outcomes *payloadOutcomes) track(t *testing.T, id string) delivery.Payload {
	t.Helper()
	return payload(t, id, "value-"+id).WithCompletion(func(delivered bool) {
		outcomes.mu.Lock()
		defer outcomes.mu.Unlock()
		if outcomes.got == nil {
			outcomes.got = map[string][]bool{}
		}
		outcomes.got[id] = append(outcomes.got[id], delivered)
	})
}

func (outcomes *payloadOutcomes) of(id string) []bool {
	outcomes.mu.Lock()
	defer outcomes.mu.Unlock()
	return append([]bool(nil), outcomes.got[id]...)
}

func (outcomes *payloadOutcomes) waitFor(t *testing.T, id string, want bool) {
	t.Helper()
	waitFor(t, func() bool { return len(outcomes.of(id)) > 0 })
	time.Sleep(20 * time.Millisecond)
	if got := outcomes.of(id); len(got) != 1 || got[0] != want {
		t.Fatalf("%s outcomes = %v, want exactly [%t]", id, got, want)
	}
}

// A payload with a completion learns its terminal outcome exactly once,
// and it is delivered only when the destination acknowledged all of it: a
// refusal, exhausted retries, a partial result, a full queue, an inactive
// dispatcher and a shutdown are all "not delivered". The change reporter
// keeps a change event queued until every destination acknowledged it.
func TestDispatcherReportsEachPayloadOutcomeOnce(t *testing.T) {
	start := func(t *testing.T, config delivery.Config, adapter delivery.Adapter) *delivery.Dispatcher {
		t.Helper()
		dispatcher, err := delivery.NewDispatcher(config, adapter)
		if err != nil {
			t.Fatal(err)
		}
		dispatcher.Activate()
		return dispatcher
	}
	t.Run("acknowledged", func(t *testing.T) {
		var outcomes payloadOutcomes
		dispatcher := start(t, testConfig("acks"), &fakeAdapter{})
		dispatcher.Enqueue(outcomes.track(t, "a"))
		outcomes.waitFor(t, "a", true)
		closeDispatcher(t, dispatcher)
		outcomes.waitFor(t, "a", true)
	})
	for name, results := range map[string][]delivery.DeliveryOutcome{
		"refused":           {delivery.OutcomePermanentPayload},
		"retries exhausted": {delivery.OutcomeTransient, delivery.OutcomeTransient, delivery.OutcomeTransient},
		"auth refused":      {delivery.OutcomeAuthentication},
	} {
		t.Run(name, func(t *testing.T) {
			var outcomes payloadOutcomes
			dispatcher := start(t, testConfig("refuses"), &fakeAdapter{outcomes: results})
			dispatcher.Enqueue(outcomes.track(t, "a"))
			outcomes.waitFor(t, "a", false)
			closeDispatcher(t, dispatcher)
		})
	}
	t.Run("partial", func(t *testing.T) {
		var outcomes payloadOutcomes
		config := testConfig("partial")
		config.ScheduledDelay = 25 * time.Millisecond
		dispatcher := start(t, config, &fixedResultAdapter{result: delivery.DeliveryResult{
			Outcome: delivery.OutcomePartial, DeliveredItems: 1, RejectedItems: 1,
		}})
		dispatcher.Enqueue(outcomes.track(t, "a"))
		dispatcher.Enqueue(outcomes.track(t, "b"))
		outcomes.waitFor(t, "a", false)
		outcomes.waitFor(t, "b", false)
		closeDispatcher(t, dispatcher)
	})
	t.Run("queue full", func(t *testing.T) {
		var outcomes payloadOutcomes
		release := make(chan struct{})
		adapter := &fakeAdapter{started: make(chan struct{}, 1), release: release}
		config := testConfig("full")
		config.MaxQueueItems, config.MaxBatchItems = 1, 1
		dispatcher := start(t, config, adapter)
		dispatcher.Enqueue(outcomes.track(t, "a"))
		<-adapter.started
		if result := dispatcher.Enqueue(outcomes.track(t, "b")); result.Accepted() {
			t.Fatalf("a full queue accepted b: %+v", result)
		}
		if got := outcomes.of("b"); len(got) != 1 || got[0] {
			t.Fatalf("a dropped payload's outcomes = %v, want [false] at once", got)
		}
		close(release)
		outcomes.waitFor(t, "a", true)
		closeDispatcher(t, dispatcher)
	})
	t.Run("inactive", func(t *testing.T) {
		var outcomes payloadOutcomes
		dispatcher, err := delivery.NewDispatcher(testConfig("inactive"), &fakeAdapter{})
		if err != nil {
			t.Fatal(err)
		}
		if result := dispatcher.Enqueue(outcomes.track(t, "a")); result.Accepted() {
			t.Fatalf("an inactive dispatcher accepted a: %+v", result)
		}
		if got := outcomes.of("a"); len(got) != 1 || got[0] {
			t.Fatalf("outcomes = %v, want [false]", got)
		}
	})
	t.Run("abandoned at shutdown", func(t *testing.T) {
		var outcomes payloadOutcomes
		release := make(chan struct{})
		adapter := &cancelAwareAdapter{started: make(chan struct{}, 1), canceled: make(chan struct{}, 1), release: release}
		config := testConfig("shutdown")
		config.MaxBatchItems = 1
		dispatcher := start(t, config, adapter)
		dispatcher.Enqueue(outcomes.track(t, "in-flight"))
		<-adapter.started
		dispatcher.Enqueue(outcomes.track(t, "queued"))
		done := make(chan error, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done <- dispatcher.Close(ctx)
		}()
		<-adapter.canceled
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		outcomes.waitFor(t, "in-flight", false)
		outcomes.waitFor(t, "queued", false)
	})
}
