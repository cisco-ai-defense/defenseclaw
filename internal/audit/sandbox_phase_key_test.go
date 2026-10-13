// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// The managed gateway's one recorder sees every account's sandboxes, and two
// people may each name a sandbox dc-claude-1. Their phases are tracked by
// registration, so one's phase change is never the other's previous phase
// and both count in the active gauge; a per-user gateway's sandboxes, which
// carry no registration, are still tracked by name.
func TestSandboxPhasesOfSameNamedManagedSandboxesStayApart(t *testing.T) {
	_, runtime, recorder := newSandboxTestRecorder(t, router.AdmissionOrdinary)
	ctx := context.Background()
	alice, bob := testSandboxIdentity(), testSandboxIdentity()
	alice.Managed.RegistrationID, bob.Managed.RegistrationID = "reg-alice-0001", "reg-bob-0001"
	record := func(identity SandboxIdentity, phase SandboxPhase) {
		t.Helper()
		identity.Phase = phase
		if err := recorder.RecordSandboxLifecycle(ctx, SandboxLifecycleEvent{Sandbox: identity}); err != nil {
			t.Fatalf("%s %s: %v", identity.Managed.RegistrationID, phase, err)
		}
	}
	previous := func() any {
		t.Helper()
		_, records := runtime.snapshot()
		return sandboxBody(t, records[len(records)-1])["defenseclaw.sandbox.phase.previous"]
	}

	record(alice, SandboxPhaseCreating)
	record(bob, SandboxPhaseReady)
	record(alice, SandboxPhaseProvisioning)
	if got := previous(); got != "creating" {
		t.Fatalf("alice's previous phase is %v, want her own creating (not bob's ready)", got)
	}
	if active := lastActiveGauges(t, runtime)[alice.Connector]; active != 2 {
		t.Fatalf("active sandboxes %d, want alice's and bob's", active)
	}
	record(alice, SandboxPhaseDeleted)
	if len(recorder.phases) != 1 {
		t.Fatalf("tracked %v, want bob's sandbox alone", recorder.phases)
	}
	if active := lastActiveGauges(t, runtime)[alice.Connector]; active != 1 {
		t.Fatalf("active sandboxes %d after alice's delete, want bob's", active)
	}

	// The per-user path: no registration, keyed by name.
	oss := testSandboxIdentity()
	record(oss, SandboxPhaseCreating)
	if _, ok := recorder.phases[oss.Name]; !ok || sandboxPhaseKey(oss) != oss.Name {
		t.Fatalf("a per-user sandbox is not tracked by its name: %v", recorder.phases)
	}
	record(oss, SandboxPhaseProvisioning)
	if got := previous(); got != "creating" {
		t.Fatalf("per-user previous phase %v, want creating", got)
	}
}
