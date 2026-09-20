// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"sync"
	"time"
)

const (
	maxCircuitFailureThreshold     = 32
	maxCircuitOpenDuration         = 24 * time.Hour
	defaultCircuitFailureThreshold = 3
	defaultCircuitOpenDuration     = 30 * time.Second
	immediateCircuitOpenDuration   = maxCircuitOpenDuration
	// authenticationCircuitOpenDuration bounds how long the circuit stays
	// open after an authentication failure. A single failed token mint or
	// a transient identity-service hiccup would otherwise trip the shared
	// immediateCircuitOpenDuration (24h) on first hit and suppress the
	// destination for a full day. Five minutes is long enough to let the
	// upstream cache / rotation cycle recover but short enough that a
	// recoverable auth error clears within the same operator session.
	authenticationCircuitOpenDuration = 5 * time.Minute

	// halfOpenProbeDeadline bounds how long a granted probe may remain
	// unresolved. A correct caller always reports the probe outcome through
	// RecordSuccess, RecordFailure, or AbortProbe, so this deadline never
	// fires for them. It exists so that a caller which loses a probe -- an
	// early return that skips its defer, a panic recovered upstream, a
	// goroutine that never reports -- degrades to a delayed retry instead of
	// silently suppressing a destination for the process lifetime.
	halfOpenProbeDeadline = 10 * time.Minute
)

// CircuitAdmission is the bounded result of consulting a delivery circuit
// before doing record counting, size-estimation, adapter, or network work.
type CircuitAdmission uint8

const (
	CircuitAdmissionNormal CircuitAdmission = iota
	CircuitAdmissionBlocked
	CircuitAdmissionProbe
)

// CircuitSnapshot is a detached, content-free view of one generation-owned
// circuit.
type CircuitSnapshot struct {
	State               CircuitState
	ConsecutiveFailures uint64
	OpenUntil           time.Time
	LastFailureClass    FailureClass
}

// Circuit is a race-safe generation-owned delivery circuit for exporters that
// do not use Dispatcher. New generations intentionally receive a fresh
// circuit; callers must not share it across configuration generations.
type Circuit struct {
	mu                  sync.Mutex
	policy              CircuitPolicy
	state               CircuitState
	consecutiveFailures uint64
	openUntil           time.Time
	halfOpenUntil       time.Time
	lastFailureClass    FailureClass
}

// NewCircuit validates and snapshots policy without starting work.
func NewCircuit(policy CircuitPolicy) (*Circuit, error) {
	normalized, ok := normalizedCircuitPolicy(policy)
	if !ok {
		return nil, newError(ErrorInvalidConfig)
	}
	return &Circuit{policy: normalized, state: CircuitClosed}, nil
}

// Admit rejects while open, atomically grants exactly one post-cooldown probe,
// and admits normal work while closed. A probe that is never resolved expires
// after halfOpenProbeDeadline and the next caller reclaims it, so a lost
// admission cannot suppress a destination indefinitely.
func (circuit *Circuit) Admit(now time.Time) CircuitAdmission {
	if circuit == nil {
		return CircuitAdmissionBlocked
	}
	circuit.mu.Lock()
	defer circuit.mu.Unlock()
	switch circuit.state {
	case CircuitClosed:
		return CircuitAdmissionNormal
	case CircuitOpen:
		if now.Before(circuit.openUntil) {
			return CircuitAdmissionBlocked
		}
		circuit.grantProbeLocked(now)
		return CircuitAdmissionProbe
	case CircuitHalfOpen:
		if now.Before(circuit.halfOpenUntil) {
			return CircuitAdmissionBlocked
		}
		// The previous probe was granted but never reported an outcome.
		// Reclaiming it is safe: a late RecordSuccess/RecordFailure from the
		// lost probe still transitions this circuit correctly, and a late
		// AbortProbe becomes a no-op because the state it expects is gone.
		circuit.grantProbeLocked(now)
		return CircuitAdmissionProbe
	default:
		return CircuitAdmissionBlocked
	}
}

// grantProbeLocked moves the circuit into a deadline-bounded half-open probe.
// The caller must hold circuit.mu.
func (circuit *Circuit) grantProbeLocked(now time.Time) {
	circuit.state = CircuitHalfOpen
	circuit.halfOpenUntil = now.UTC().Add(halfOpenProbeDeadline)
}

// RecordSuccess closes the circuit and clears the active failure streak. The
// last bounded failure class remains available for post-recovery diagnosis.
func (circuit *Circuit) RecordSuccess() {
	if circuit == nil {
		return
	}
	circuit.mu.Lock()
	circuit.state = CircuitClosed
	circuit.consecutiveFailures = 0
	circuit.openUntil = time.Time{}
	circuit.halfOpenUntil = time.Time{}
	circuit.mu.Unlock()
}

// AbortProbe releases a half-open admission that could not reach a destination
// outcome, for example because local validation rejected the batch or the
// owning operation was canceled. The prior deadline is retained, so the next
// eligible record may probe immediately without falsely counting a destination
// failure.
func (circuit *Circuit) AbortProbe() bool {
	if circuit == nil {
		return false
	}
	circuit.mu.Lock()
	defer circuit.mu.Unlock()
	if circuit.state != CircuitHalfOpen {
		return false
	}
	circuit.state = CircuitOpen
	circuit.halfOpenUntil = time.Time{}
	return true
}

// RecordFailure records one terminal batch failure and reports whether the
// circuit is open after the update. Authentication and unsafe-endpoint
// failures open immediately; other bounded classes use the configured
// threshold. Any failed half-open probe reopens immediately.
func (circuit *Circuit) RecordFailure(class FailureClass, at time.Time) bool {
	if circuit == nil {
		return true
	}
	switch class {
	case FailureClassTransient, FailureClassAuthentication,
		FailureClassPermanentPayload, FailureClassUnsafeEndpoint:
	default:
		class = FailureClassPermanentPayload
	}
	circuit.mu.Lock()
	defer circuit.mu.Unlock()
	if circuit.consecutiveFailures < ^uint64(0) {
		circuit.consecutiveFailures++
	}
	circuit.lastFailureClass = class
	immediateFailure := class == FailureClassAuthentication ||
		class == FailureClassUnsafeEndpoint
	shouldOpen := circuit.state == CircuitHalfOpen ||
		immediateFailure ||
		circuit.consecutiveFailures >= uint64(circuit.policy.TransientFailureThreshold)
	if !shouldOpen {
		return false
	}
	circuit.state = CircuitOpen
	circuit.halfOpenUntil = time.Time{}
	openDuration := circuit.policy.OpenDuration
	if immediateFailure {
		openDuration = immediateCircuitOpenDurationFor(class)
	}
	circuit.openUntil = at.UTC().Add(openDuration)
	return true
}

// immediateCircuitOpenDurationFor selects the "open-immediately" cool-down
// per failure class. Authentication failures use a bounded few-minute window
// so a single failed token mint or a transient identity-service hiccup does
// not suppress the destination for a full 24-hour period. Unsafe-endpoint
// failures retain the 24-hour trap because a broken endpoint is not expected
// to self-heal within a session.
func immediateCircuitOpenDurationFor(class FailureClass) time.Duration {
	if class == FailureClassAuthentication {
		return authenticationCircuitOpenDuration
	}
	return immediateCircuitOpenDuration
}

// Snapshot returns a detached, content-free circuit view.
func (circuit *Circuit) Snapshot() CircuitSnapshot {
	if circuit == nil {
		return CircuitSnapshot{}
	}
	circuit.mu.Lock()
	defer circuit.mu.Unlock()
	return CircuitSnapshot{
		State:               circuit.state,
		ConsecutiveFailures: circuit.consecutiveFailures,
		OpenUntil:           circuit.openUntil,
		LastFailureClass:    circuit.lastFailureClass,
	}
}

func normalizedCircuitPolicy(policy CircuitPolicy) (CircuitPolicy, bool) {
	if policy.TransientFailureThreshold == 0 && policy.OpenDuration == 0 {
		return CircuitPolicy{
			TransientFailureThreshold: defaultCircuitFailureThreshold,
			OpenDuration:              defaultCircuitOpenDuration,
		}, true
	}
	if policy.TransientFailureThreshold <= 0 ||
		policy.TransientFailureThreshold > maxCircuitFailureThreshold ||
		policy.OpenDuration <= 0 || policy.OpenDuration > maxCircuitOpenDuration {
		return CircuitPolicy{}, false
	}
	return policy, true
}
