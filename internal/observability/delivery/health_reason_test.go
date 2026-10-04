// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package delivery_test

import (
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

// GAP-2557: a routine success is not a recovery.
func TestSettledHealthReasonOnlyRecoversFromFailure(t *testing.T) {
	healthy, recovered := delivery.HealthHealthy, delivery.HealthReasonRecovered
	cases := []struct {
		previous delivery.HealthState
		reason   delivery.HealthReason
		want     delivery.HealthReason
	}{
		{"", "", delivery.HealthReasonActivated},
		{delivery.HealthInitializing, "", delivery.HealthReasonActivated},
		{healthy, delivery.HealthReasonActivated, delivery.HealthReasonActivated},
		{healthy, recovered, recovered},
		{delivery.HealthDegraded, delivery.HealthReasonRetryable, recovered},
		{delivery.HealthFailing, delivery.HealthReasonDeliveryFailed, recovered},
	}
	for _, tc := range cases {
		if got := delivery.SettledHealthReason(tc.previous, tc.reason, healthy, recovered); got != tc.want {
			t.Errorf("SettledHealthReason(%q, %q)=%q, want %q", tc.previous, tc.reason, got, tc.want)
		}
	}
	if got := delivery.SettledHealthReason(healthy, delivery.HealthReasonActivated,
		delivery.HealthFailing, delivery.HealthReasonDeliveryFailed); got != delivery.HealthReasonDeliveryFailed {
		t.Errorf("failure reason rewritten to %q", got)
	}
}

func TestDispatcherFirstDeliveryAfterActivateIsNotARecovery(t *testing.T) {
	var mu sync.Mutex
	var transitions []delivery.HealthTransition
	config := testConfig("first-delivery")
	config.Signal = "traces"
	config.ObserverInterval = 0
	config.Observer = delivery.ObserverFunc(func(transition delivery.HealthTransition) {
		mu.Lock()
		transitions = append(transitions, transition)
		mu.Unlock()
	})
	dispatcher, err := delivery.NewDispatcher(config, &fakeAdapter{
		outcomes: []delivery.DeliveryOutcome{delivery.OutcomeDelivered, delivery.OutcomeDelivered},
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	dispatcher.Enqueue(payload(t, "one", "value"))
	dispatcher.Enqueue(payload(t, "two", "value"))
	waitFor(t, func() bool { return dispatcher.Counters().Delivered == 2 })
	if snapshot := dispatcher.DeliveryHealthSnapshot(); snapshot.State != delivery.HealthHealthy ||
		snapshot.Reason != string(delivery.HealthReasonActivated) {
		t.Fatalf("health after routine deliveries=%s/%s", snapshot.State, snapshot.Reason)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, transition := range transitions {
		if transition.Reason == delivery.HealthReasonRecovered {
			t.Fatalf("routine delivery reported a recovery: %+v", transition)
		}
	}
}
