// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// The managed gateway ends a managed sandbox's tracked phase itself
// (ForgetManagedSandbox, republishing the active gauge), a TrackedOnly
// record (a revoked registration's) never tracks a sandbox again, and one
// account tracks at most LimitManagedPhases sandboxes.
func TestManagedSandboxPhasesForgetTrackedOnlyAndLimit(t *testing.T) {
	_, runtime, recorder := newSandboxTestRecorder(t, router.AdmissionOrdinary)
	ctx := context.Background()
	managed := func(registration string) SandboxIdentity {
		identity := testSandboxIdentity()
		identity.Managed.RegistrationID = registration
		return identity
	}
	record := func(identity SandboxIdentity, phase SandboxPhase, user string, trackedOnly bool) error {
		identity.Phase = phase
		return recorder.RecordSandboxLifecycle(ctx, SandboxLifecycleEvent{Sandbox: identity, UserID: user, TrackedOnly: trackedOnly})
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	a, b := managed("reg-a"), managed("reg-b")
	must(record(a, SandboxPhaseReady, "1001", false))
	must(record(b, SandboxPhaseReady, "1001", false))
	if active := lastActiveGauges(t, runtime)[a.Connector]; active != 2 {
		t.Fatalf("active %d, want 2", active)
	}

	if !recorder.ForgetManagedSandbox(ctx, "reg-a") || recorder.TrackedSandboxes() != 1 {
		t.Fatalf("forget reg-a: tracked %v", recorder.phases)
	}
	if active := lastActiveGauges(t, runtime)[a.Connector]; active != 1 {
		t.Fatalf("active %d after the forget, want the gauge republished at 1", active)
	}
	if recorder.ForgetManagedSandbox(ctx, "reg-a") || recorder.ForgetManagedSandbox(ctx, "") {
		t.Fatal("forgetting an untracked sandbox reported one")
	}

	// A revoked registration's records never track its sandbox again, but
	// move or end a phase still tracked.
	must(record(a, SandboxPhaseStopped, "1001", true))
	if _, ok := recorder.phases[sandboxManagedPhaseKey("reg-a")]; ok || recorder.TrackedSandboxes() != 1 {
		t.Fatalf("a TrackedOnly record tracked a forgotten sandbox again: %v", recorder.phases)
	}
	must(record(b, SandboxPhaseStopping, "1001", true))
	if got := recorder.phases[sandboxManagedPhaseKey("reg-b")].phase; got != SandboxPhaseStopping {
		t.Fatalf("reg-b phase %s, want stopping", got)
	}
	must(record(b, SandboxPhaseDeleted, "1001", true))
	if recorder.TrackedSandboxes() != 0 {
		t.Fatalf("tracked %v after reg-b's delete", recorder.phases)
	}

	// At the limit, a record that would track one more of the account's
	// sandboxes is refused and not emitted; other accounts, tracked
	// sandboxes and deletes go on.
	recorder.LimitManagedPhases(2)
	must(record(managed("reg-1"), SandboxPhaseReady, "1001", false))
	must(record(managed("reg-2"), SandboxPhaseReady, "1001", false))
	_, before := runtime.snapshot()
	if err := record(managed("reg-3"), SandboxPhaseReady, "1001", false); !errors.Is(err, ErrSandboxPhaseLimit) {
		t.Fatalf("a third sandbox of the account: %v, want ErrSandboxPhaseLimit", err)
	}
	if _, after := runtime.snapshot(); len(after) != len(before) {
		t.Fatalf("a refused record was emitted (%d -> %d records)", len(before), len(after))
	}
	must(record(managed("reg-3"), SandboxPhaseDeleted, "1001", false))
	must(record(managed("reg-1"), SandboxPhaseStopping, "1001", false))
	must(record(managed("reg-4"), SandboxPhaseReady, "1002", false))
	// A per-user gateway's sandboxes (no registration) are not bounded.
	must(record(testSandboxIdentity(), SandboxPhaseReady, "1001", false))
	if recorder.TrackedSandboxes() != 4 {
		t.Fatalf("tracked %v, want reg-1, reg-2, reg-4 and the per-user sandbox", recorder.phases)
	}
}
