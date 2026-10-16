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

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// #1241: after the managed gateway starts again its recorder tracks no
// sandbox, and a sandbox that runs on quietly sends no lifecycle record,
// so it was in no sandbox.active point until its next phase change. The
// gateway now tracks it from its registration (TrackManagedSandbox): the
// gauge is exported at once and on every interval, follows the
// registration until a lifecycle record comes, never becomes a lifecycle
// record's previous phase, and keeps the account bound.
func TestManagedSandboxIsTrackedFromItsRegistration(t *testing.T) {
	_, runtime, recorder := newSandboxTestRecorder(t, router.AdmissionOrdinary)
	ctx := context.Background()
	active := func() []int64 {
		t.Helper()
		var out []int64
		for _, metric := range sandboxMetrics(t, runtime, observability.TelemetryInstrumentDefenseClawSandboxActive) {
			out = append(out, sandboxMetricValue(t, metric))
		}
		return out
	}
	track := func(phase SandboxPhase, wantChanged bool) {
		t.Helper()
		changed, err := recorder.TrackManagedSandbox(ctx, "reg-a", "claudecode", "1001", phase)
		if err != nil || changed != wantChanged {
			t.Fatalf("track %s: changed %v (%v), want %v", phase, changed, err, wantChanged)
		}
	}
	track(SandboxPhaseReady, true)
	if got := active(); len(got) != 1 || got[0] != 1 || recorder.ActiveSandboxes("claudecode") != 1 {
		t.Fatalf("a running registration after the restart: %v", got)
	}
	// The same state again exports nothing new; the interval exports it.
	track(SandboxPhaseReady, false)
	if err := recorder.RecordActiveSandboxes(ctx); err != nil {
		t.Fatal(err)
	}
	if got := active(); len(got) != 2 || got[1] != 1 {
		t.Fatalf("on the next interval: %v", got)
	}
	// It follows the registration: stopped is 0 at once, running 1 again.
	track(SandboxPhaseStopped, true)
	track(SandboxPhaseReady, true)
	if got := active(); len(got) != 4 || got[2] != 0 || got[3] != 1 {
		t.Fatalf("stopped then running: %v", got)
	}
	// A lifecycle record decides from then on, and the registration's
	// phase was not its previous phase: no ready -> stopping transition.
	identity := testSandboxIdentity()
	identity.Connector, identity.Managed.RegistrationID, identity.Phase = "claudecode", "reg-a", SandboxPhaseStopping
	if err := recorder.RecordSandboxLifecycle(ctx, SandboxLifecycleEvent{Sandbox: identity, UserID: "1001"}); err != nil {
		t.Fatal(err)
	}
	if transitions := sandboxMetrics(t, runtime, observability.TelemetryInstrumentDefenseClawSandboxTransitions); len(transitions) != 0 {
		t.Fatalf("%d transitions from the registration's phase, want none", len(transitions))
	}
	identity.Phase = SandboxPhaseStopped
	if err := recorder.RecordSandboxLifecycle(ctx, SandboxLifecycleEvent{Sandbox: identity, UserID: "1001"}); err != nil {
		t.Fatal(err)
	}
	track(SandboxPhaseReady, false)
	if recorder.ActiveSandboxes("claudecode") != 0 {
		t.Fatal("the registration overrode the lifecycle record's stop")
	}
	// The account bound holds for the registrations too.
	recorder.LimitManagedPhases(2)
	if _, err := recorder.TrackManagedSandbox(ctx, "reg-b", "claudecode", "1001", SandboxPhaseReady); err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.TrackManagedSandbox(ctx, "reg-c", "claudecode", "1001", SandboxPhaseReady); !errors.Is(err, ErrSandboxPhaseLimit) {
		t.Fatalf("a third sandbox of the account: %v, want ErrSandboxPhaseLimit", err)
	}
	if recorder.TrackedSandboxes() != 2 {
		t.Fatalf("tracked %v, want reg-a and reg-b", recorder.phases)
	}
}
