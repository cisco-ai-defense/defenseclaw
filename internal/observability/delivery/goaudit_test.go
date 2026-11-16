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
	"context"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

type nilReceiverAdapter struct{}

func (*nilReceiverAdapter) EncodedSize([]int) (int, bool) { return 0, false }
func (*nilReceiverAdapter) Deliver(context.Context, delivery.Batch) delivery.DeliveryResult {
	return delivery.DeliveryResult{Outcome: delivery.OutcomeDelivered}
}

func TestDispatcherRejectsTypedNilAdapter(t *testing.T) {
	var adapter *nilReceiverAdapter
	if _, err := delivery.NewDispatcher(testConfig("nil-adapter"), adapter); !delivery.IsError(err, delivery.ErrorInvalidConfig) {
		t.Fatalf("enabled dispatcher error=%v, want invalid config", err)
	}

	disabledConfig := testConfig("disabled-nil-adapter")
	disabledConfig.Enabled = false
	disabled, err := delivery.NewDispatcher(disabledConfig, adapter)
	if err != nil {
		t.Fatalf("disabled dispatcher: %v", err)
	}
	closeDispatcher(t, disabled)
}

var nilObserverCalls atomic.Uint64

type nilReceiverObserver struct{}

func (*nilReceiverObserver) Observe(delivery.HealthTransition) {
	nilObserverCalls.Add(1)
}

func TestDispatcherSkipsTypedNilObserver(t *testing.T) {
	nilObserverCalls.Store(0)
	config := testConfig("nil-observer")
	var observer *nilReceiverObserver
	config.Observer = observer
	dispatcher, err := delivery.NewDispatcher(config, &fakeAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	closeDispatcher(t, dispatcher)
	if got := nilObserverCalls.Load(); got != 0 {
		t.Fatalf("typed nil observer calls=%d, want zero", got)
	}
}

func TestDispatcherAcceptsLiveDeliveryDependencies(t *testing.T) {
	var observerCalls atomic.Uint64
	config := testConfig("live-dependencies")
	config.Observer = delivery.ObserverFunc(func(delivery.HealthTransition) {
		observerCalls.Add(1)
	})
	adapter := &fakeAdapter{}
	dispatcher, err := delivery.NewDispatcher(config, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	if result := dispatcher.Enqueue(payload(t, "live", "record")); !result.Accepted() {
		t.Fatalf("enqueue: %+v", result)
	}
	closeDispatcher(t, dispatcher)
	if got := dispatcher.Counters().Delivered; got != 1 {
		t.Fatalf("delivered=%d, want one", got)
	}
	if got := observerCalls.Load(); got == 0 {
		t.Fatal("live observer was not called")
	}
}
