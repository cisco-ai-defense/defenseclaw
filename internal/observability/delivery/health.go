// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import "time"

func (dispatcher *Dispatcher) setOperationalHealth(state HealthState, reason HealthReason) {
	dispatcher.transitionHealth(state, reason, true)
}

func (dispatcher *Dispatcher) setHealth(state HealthState, reason HealthReason) {
	dispatcher.transitionHealth(state, reason, false)
}

func (dispatcher *Dispatcher) transitionHealth(state HealthState, reason HealthReason, operational bool) {
	if dispatcher == nil {
		return
	}
	dispatcher.healthMu.Lock()
	previous := dispatcher.health
	if operational && (previous == HealthDraining || previous == HealthStopped || previous == HealthDisabled) {
		dispatcher.healthMu.Unlock()
		return
	}
	if previous == state {
		dispatcher.healthReason = reason
		dispatcher.healthMu.Unlock()
		return
	}
	dispatcher.health = state
	dispatcher.healthReason = reason
	now := time.Now().UTC()
	if state == HealthDegraded || state == HealthFailing {
		dispatcher.lastFailure = now
	}
	dispatcher.healthSequence++
	transition := HealthTransition{
		Destination: dispatcher.config.Destination,
		Generation:  dispatcher.config.Generation,
		Previous:    previous, Current: state, Reason: reason,
		Counters: dispatcher.Counters(), OccurredAt: now,
		sequence: dispatcher.healthSequence,
	}
	dispatcher.pendingTransition = &transition
	dispatcher.healthMu.Unlock()
	select {
	case dispatcher.healthNotify <- struct{}{}:
	default:
	}
}

func (dispatcher *Dispatcher) observeHealth() {
	defer dispatcher.finishObserver()
	var lastEmission time.Time
	for {
		transition, pending := dispatcher.peekTransition()
		if !pending {
			select {
			case <-dispatcher.observerStop:
				dispatcher.emitPendingTransition()
				return
			case <-dispatcher.healthNotify:
				continue
			}
		}
		remaining := time.Duration(0)
		if !lastEmission.IsZero() && dispatcher.config.ObserverInterval > 0 {
			remaining = dispatcher.config.ObserverInterval - time.Since(lastEmission)
		}
		if remaining <= 0 {
			if dispatcher.consumeTransition(transition) {
				dispatcher.safeObserve(transition)
				lastEmission = time.Now()
			}
			continue
		}
		timer := time.NewTimer(remaining)
		select {
		case <-dispatcher.observerStop:
			if !timer.Stop() {
				<-timer.C
			}
			dispatcher.emitPendingTransition()
			return
		case <-dispatcher.healthNotify:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
			if latest, ok := dispatcher.peekTransition(); ok && dispatcher.consumeTransition(latest) {
				dispatcher.safeObserve(latest)
				lastEmission = time.Now()
			}
		}
	}
}

func (dispatcher *Dispatcher) peekTransition() (HealthTransition, bool) {
	dispatcher.healthMu.Lock()
	defer dispatcher.healthMu.Unlock()
	if dispatcher.pendingTransition == nil {
		return HealthTransition{}, false
	}
	return *dispatcher.pendingTransition, true
}

func (dispatcher *Dispatcher) consumeTransition(expected HealthTransition) bool {
	dispatcher.healthMu.Lock()
	defer dispatcher.healthMu.Unlock()
	if dispatcher.pendingTransition == nil ||
		dispatcher.pendingTransition.sequence != expected.sequence {
		return false
	}
	dispatcher.pendingTransition = nil
	return true
}

func (dispatcher *Dispatcher) emitPendingTransition() {
	transition, ok := dispatcher.peekTransition()
	if ok && dispatcher.consumeTransition(transition) {
		dispatcher.safeObserve(transition)
	}
}

func (dispatcher *Dispatcher) safeObserve(transition HealthTransition) {
	if dispatcher.config.Observer == nil {
		return
	}
	defer func() { _ = recover() }()
	dispatcher.config.Observer.Observe(transition)
}
