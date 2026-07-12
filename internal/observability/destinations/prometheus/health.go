// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package prometheus

import (
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

// HealthReason is a closed pull-destination reason vocabulary.
type HealthReason string

const (
	HealthReasonListenerBound  HealthReason = "listener_bound"
	HealthReasonListenerFailed HealthReason = "listener_failed"
	HealthReasonScrapeFailed   HealthReason = "scrape_failed"
	HealthReasonRecovered      HealthReason = "scrape_recovered"
	HealthReasonServerFailed   HealthReason = "server_failed"
	HealthReasonDrainStarted   HealthReason = "drain_started"
	HealthReasonClosed         HealthReason = "closed"
)

// Counters contain no request metadata or metric identities.
type Counters struct {
	Scrapes   uint64
	Succeeded uint64
	Failed    uint64
}

// HealthTransition contains only bounded destination/generation identities,
// closed enums, aggregate counters, and a timestamp.
type HealthTransition struct {
	Destination string
	Generation  uint64
	Previous    delivery.HealthState
	Current     delivery.HealthState
	Reason      HealthReason
	Counters    Counters
	OccurredAt  time.Time
}

type Observer interface{ Observe(HealthTransition) }

type ObserverFunc func(HealthTransition)

func (function ObserverFunc) Observe(transition HealthTransition) { function(transition) }

const defaultObserverTimeout = 100 * time.Millisecond

// boundedObserver prevents an injected health observer from stalling listener,
// scrape, or shutdown progress. Only one callback may be in flight. If it does
// not return before the bound, the runtime proceeds and later transitions are
// dropped until it returns. Observer implementations should still be
// non-blocking; Go cannot forcibly stop an uncooperative callback.
type boundedObserver struct {
	target  Observer
	timeout time.Duration
	permit  chan struct{}
}

func newBoundedObserver(target Observer) *boundedObserver {
	return &boundedObserver{target: target, timeout: defaultObserverTimeout, permit: make(chan struct{}, 1)}
}

func (observer *boundedObserver) observe(transition HealthTransition) {
	if observer == nil || observer.target == nil {
		return
	}
	select {
	case observer.permit <- struct{}{}:
	default:
		return
	}
	done := make(chan struct{}, 1)
	go func() {
		defer func() {
			_ = recover()
			<-observer.permit
			done <- struct{}{}
		}()
		observer.target.Observe(transition)
	}()
	timeout := observer.timeout
	if timeout <= 0 {
		timeout = defaultObserverTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}

// HealthSnapshot is the immutable current reader state.
type HealthSnapshot struct {
	Generation uint64
	State      delivery.HealthState
	Counters   Counters
}
