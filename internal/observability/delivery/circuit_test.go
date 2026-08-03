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
	"testing"
	"time"
)

func openedCircuit(t *testing.T, base time.Time) *Circuit {
	t.Helper()
	circuit, err := NewCircuit(CircuitPolicy{
		TransientFailureThreshold: 1,
		OpenDuration:              30 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	if !circuit.RecordFailure(FailureClassTransient, base) {
		t.Fatal("threshold-1 transient failure should open the circuit")
	}
	if state := circuit.Snapshot().State; state != CircuitOpen {
		t.Fatalf("state = %q, want %q", state, CircuitOpen)
	}
	return circuit
}

// A caller that is granted a probe and never reports its outcome must not be
// able to suppress the route forever. Before the half-open deadline existed,
// this left Admit returning Blocked for the process lifetime.
func TestCircuitReclaimsAbandonedHalfOpenProbeAfterDeadline(t *testing.T) {
	base := time.Unix(1_800_000_000, 0).UTC()
	circuit := openedCircuit(t, base)

	cooled := base.Add(30 * time.Second)
	if admission := circuit.Admit(cooled); admission != CircuitAdmissionProbe {
		t.Fatalf("post-cooldown admission = %v, want probe", admission)
	}

	// The probe is deliberately abandoned: no RecordSuccess, RecordFailure,
	// or AbortProbe. Work stays suppressed right up to the deadline.
	if admission := circuit.Admit(cooled.Add(time.Second)); admission != CircuitAdmissionBlocked {
		t.Fatalf("in-flight probe admission = %v, want blocked", admission)
	}
	justBefore := cooled.Add(halfOpenProbeDeadline - time.Nanosecond)
	if admission := circuit.Admit(justBefore); admission != CircuitAdmissionBlocked {
		t.Fatalf("pre-deadline admission = %v, want blocked", admission)
	}

	reclaimed := cooled.Add(halfOpenProbeDeadline)
	if admission := circuit.Admit(reclaimed); admission != CircuitAdmissionProbe {
		t.Fatalf("expired-probe admission = %v, want probe", admission)
	}
	// The reclaimed probe carries a fresh deadline rather than staying expired.
	if admission := circuit.Admit(reclaimed.Add(time.Second)); admission != CircuitAdmissionBlocked {
		t.Fatalf("reclaimed probe admission = %v, want blocked", admission)
	}
}

// A late outcome from the abandoned probe must still land correctly on the
// circuit that replaced it, and must not resurrect stale state.
func TestCircuitLateOutcomeFromReclaimedProbeIsSafe(t *testing.T) {
	base := time.Unix(1_800_000_000, 0).UTC()

	t.Run("late success closes", func(t *testing.T) {
		circuit := openedCircuit(t, base)
		cooled := base.Add(30 * time.Second)
		circuit.Admit(cooled)
		circuit.Admit(cooled.Add(halfOpenProbeDeadline))
		circuit.RecordSuccess()
		if state := circuit.Snapshot().State; state != CircuitClosed {
			t.Fatalf("state = %q, want %q", state, CircuitClosed)
		}
	})

	t.Run("late abort is a no-op once state moved on", func(t *testing.T) {
		circuit := openedCircuit(t, base)
		cooled := base.Add(30 * time.Second)
		circuit.Admit(cooled)
		circuit.RecordSuccess()
		if circuit.AbortProbe() {
			t.Fatal("AbortProbe should not fire against a closed circuit")
		}
		if state := circuit.Snapshot().State; state != CircuitClosed {
			t.Fatalf("late abort changed state to %q", state)
		}
	})
}

// AbortProbe keeps the earlier cooldown deadline so a locally-rejected batch
// does not cost the route its next probe.
func TestCircuitAbortProbeAllowsImmediateReprobe(t *testing.T) {
	base := time.Unix(1_800_000_000, 0).UTC()
	circuit := openedCircuit(t, base)
	cooled := base.Add(30 * time.Second)

	if admission := circuit.Admit(cooled); admission != CircuitAdmissionProbe {
		t.Fatalf("admission = %v, want probe", admission)
	}
	if !circuit.AbortProbe() {
		t.Fatal("AbortProbe should release a half-open admission")
	}
	if admission := circuit.Admit(cooled); admission != CircuitAdmissionProbe {
		t.Fatalf("post-abort admission = %v, want probe", admission)
	}
}

// Only one concurrent caller may hold the probe, even at the reclaim boundary.
func TestCircuitGrantsSingleProbeUnderConcurrency(t *testing.T) {
	base := time.Unix(1_800_000_000, 0).UTC()
	circuit := openedCircuit(t, base)
	cooled := base.Add(30 * time.Second)

	const callers = 64
	var (
		wait   sync.WaitGroup
		mu     sync.Mutex
		probes int
	)
	start := make(chan struct{})
	wait.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wait.Done()
			<-start
			if circuit.Admit(cooled) == CircuitAdmissionProbe {
				mu.Lock()
				probes++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wait.Wait()

	if probes != 1 {
		t.Fatalf("concurrent probes granted = %d, want 1", probes)
	}
}

// An authentication failure opens for the maximum duration, and the deadline
// clears so a later reclaim cannot be triggered by stale half-open state.
func TestCircuitAuthenticationFailureOpensImmediately(t *testing.T) {
	base := time.Unix(1_800_000_000, 0).UTC()
	circuit, err := NewCircuit(CircuitPolicy{})
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	if !circuit.RecordFailure(FailureClassAuthentication, base) {
		t.Fatal("authentication failure should open immediately")
	}
	snapshot := circuit.Snapshot()
	if snapshot.State != CircuitOpen {
		t.Fatalf("state = %q, want %q", snapshot.State, CircuitOpen)
	}
	if want := base.Add(immediateCircuitOpenDuration); !snapshot.OpenUntil.Equal(want) {
		t.Fatalf("OpenUntil = %v, want %v", snapshot.OpenUntil, want)
	}
	if admission := circuit.Admit(base.Add(time.Hour)); admission != CircuitAdmissionBlocked {
		t.Fatalf("admission one hour in = %v, want blocked", admission)
	}
}
