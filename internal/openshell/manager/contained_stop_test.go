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

//go:build !windows

package manager

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// wantContained checks that the MicroVM name keeps running contained after
// a stop it needed was held back for a failed sync (why is the reason it
// was needed for): no stop call since stops, its network rules (an
// approved host port among them) and DefenseClaw's egress proxy closed to
// it, its view, the feed and the status name it unprotected, and no new
// sandbox is created beside it.
func wantContained(t *testing.T, e *harnessEnv, name, why string, stops int) {
	t.Helper()
	if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
		t.Fatalf("stopped a MicroVM whose sync failed: %d stop calls", got-stops)
	}
	v := e.get(name)
	if v.Phase != "ready" {
		t.Fatalf("the contained MicroVM did not keep running: %s", v.Phase)
	}
	if e.hasRule(name, "defenseclaw_egress") || e.hasRule(name, "hostport") {
		t.Fatal("the contained MicroVM kept its network rules")
	}
	if p, ok := e.m.creds.Lookup(e.binding(name).ID); ok && p.Decider != nil {
		t.Fatal("the egress proxy still serves the contained MicroVM")
	}
	warned := false
	for _, w := range v.Warnings {
		warned = warned || strings.HasPrefix(w, containedUnprotected) && strings.Contains(w, why) && strings.Contains(w, "`defenseclaw sandbox stop "+name+"`")
	}
	if !warned {
		t.Fatalf("the view does not say it is contained: %q", v.Warnings)
	}
	found := e.events(name, sandboxapi.ActivityFinding, sandboxapi.ReasonContained)
	if len(found) == 0 || !strings.Contains(found[len(found)-1].Message, why) || strings.Contains(found[len(found)-1].Message, "could not confirm it contained") {
		t.Fatalf("the feed does not say it is contained: %+v", found)
	}
	st, err := e.m.Status(t.Context())
	must(t, err)
	if len(st.Unprotected) != 1 || st.Unprotected[0] != (sandboxapi.UnprotectedSandbox{Name: name, Phase: "ready",
		Stop: "defenseclaw sandbox stop " + name, Reason: sandboxapi.UnprotectedContained}) {
		t.Fatalf("unprotected = %+v", st.Unprotected)
	}
	_, err = e.tryCreate(sandboxapi.CreateRequest{Name: "beside", Copy: true, Project: e.otherProject("beside")})
	if apiErr := wantCode(t, err, sandboxapi.CodeConflict); !strings.Contains(apiErr.Message, "while "+name+" runs ("+containedUnprotected+")") ||
		!strings.Contains(apiErr.Detail, "`defenseclaw sandbox stop "+name+"`") {
		t.Fatalf("create beside a contained MicroVM = %+v", apiErr)
	}
}

// wantReleased checks that the user's stop of the contained MicroVM name,
// accepting the loss, ends the containment, and that its next session,
// whose guest syncs, gets its create-time network and egress proxy back.
func wantReleased(t *testing.T, e *harnessEnv, name string) {
	t.Helper()
	e.stopBoxAcceptingLoss(name)
	if st, err := e.m.Status(t.Context()); err != nil || len(st.Unprotected) != 0 {
		t.Fatalf("a stopped contained MicroVM is still named unprotected: %+v, %v", st, err)
	}
	e.fake.HandleExec(e.workloadChecks(nil, nil))
	e.startBox(name, sandboxapi.StartRequest{})
	if !e.hasRule(name, "defenseclaw_egress") {
		t.Fatal("the next session started without its create-time network rules")
	}
	if p, ok := e.m.creds.Lookup(e.binding(name).ID); !ok || p.Decider == nil {
		t.Fatal("the next session has no egress proxy")
	}
	b := e.boxOf(name)
	e.m.mu.Lock()
	rec := b.rec
	e.m.mu.Unlock()
	if rec.Contained != "" || rec.OldSupervisorNetworkRestore || rec.OldSupervisorNetworkClosed {
		t.Fatalf("the next session is still recorded contained: %+v", rec)
	}
	e.create(sandboxapi.CreateRequest{Name: "after", Copy: true, Project: e.otherProject("after")})
}

// GAP-0902 review: a stop DefenseClaw makes for a security alarm (a hook
// tamper or silence, repeated foreign network rules, a lost hook or egress
// listener, a revoked registration) was refused after a failed sync and
// left the MicroVM ready with nothing isolating it. It now never stops the
// VM (that would lose what the guest has not synced) and contains it
// instead: DefenseClaw's egress proxy closes to it, its ingress token is
// rotated, and every network rule (an approved host port among them) and
// provider it added is withdrawn. The VM is named unprotected in its view,
// the feed and the status, no new sandbox is created beside it, and a
// restarted daemon keeps it so. The user's stop ends it, and the next
// session gets its network back.
func TestASecurityStopThatCannotSyncContainsTheVM(t *testing.T) {
	stoppers := []struct {
		name, why string
		stop      func(e *harnessEnv, b *box) error
	}{
		{name: "hook tamper", why: "hook tamper", stop: func(e *harnessEnv, b *box) error {
			e.m.stopForAlarm("vmbox", b.rec.BindingID, audit.SandboxFindingHookTamper)
			return nil
		}},
		{name: "silent hooks", why: "silent hooks", stop: func(e *harnessEnv, b *box) error {
			e.m.stopForAlarm("vmbox", b.rec.BindingID, audit.SandboxFindingHookSilence)
			return nil
		}},
		{name: "foreign network rules", why: "repeated network rules added outside DefenseClaw", stop: func(e *harnessEnv, b *box) error {
			e.m.scheduleForeignStop("vmbox", b.rec.BindingID)
			e.m.tamperStops.Wait()
			return nil
		}},
		{name: "a lost listener", why: "the sandbox ingress listener is not running", stop: func(e *harnessEnv, _ *box) error {
			_, err := e.m.Stop(WithEmergencyStop(context.Background(), "the sandbox ingress listener is not running"), "vmbox")
			return err
		}},
		{name: "a revoked registration", why: "its managed registration was revoked", stop: func(e *harnessEnv, _ *box) error {
			_, err := e.m.Stop(WithEmergencyStop(context.Background(), "its managed registration was revoked"), "vmbox")
			return err
		}},
	}
	for _, s := range stoppers {
		for _, restart := range []bool{false, true} {
			t.Run(s.name+"/restart="+map[bool]string{false: "no", true: "yes"}[restart], func(t *testing.T) {
				e := newVMEnv(t, nil)
				e.create(sandboxapi.CreateRequest{Name: "vmbox", Copy: true})
				e.addNetworkRule("vmbox", "hostport", "host.openshell.internal", 8080)
				b := e.boxOf("vmbox")
				generation := e.binding("vmbox").Generation
				e.fake.HandleExec(e.workloadChecks(nil, guestAnswers("exited\n", false)))
				stops := e.fake.Calls(openshelltest.MethodStopSandbox)
				if err := s.stop(e, b); err != nil {
					apiErr := wantCode(t, err, sandboxapi.CodeUnsynced)
					if !strings.Contains(apiErr.Message, "so it keeps running, "+containedUnprotected+"; DefenseClaw contained it instead") {
						t.Fatalf("the security stop's error = %+v", apiErr)
					}
				}
				if got := e.binding("vmbox").Generation; got == generation {
					t.Fatal("the contained MicroVM's ingress token was not rotated")
				}
				wantContained(t, e, "vmbox", s.why, stops)
				if restart {
					e.restartDaemon()
					e.fake.HandleExec(e.workloadChecks(nil, guestAnswers("exited\n", false)))
					wantContained(t, e, "vmbox", s.why, stops)
				}
				wantReleased(t, e, "vmbox")
			})
		}
	}

	// The user's own stop is refused, and contains nothing.
	e := newVMEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "mine", Copy: true})
	e.fake.HandleExec(e.workloadChecks(nil, guestAnswers("exited\n", false)))
	_, err := e.m.Stop(context.Background(), "mine")
	if apiErr := wantCode(t, err, sandboxapi.CodeUnsynced); strings.Contains(apiErr.Message, containedUnprotected) {
		t.Fatalf("the user's stop contained the MicroVM: %+v", apiErr)
	}
	if !e.hasRule("mine", "defenseclaw_egress") || len(e.events("mine", sandboxapi.ActivityFinding, sandboxapi.ReasonContained)) != 0 {
		t.Fatal("the user's refused stop withdrew the MicroVM's network")
	}
	if st, err := e.m.Status(t.Context()); err != nil || len(st.Unprotected) != 0 {
		t.Fatalf("the user's refused stop named the MicroVM unprotected: %+v, %v", st, err)
	}
}

// GAP-0902 review: a start that must not leave its MicroVM running (it
// failed its workload check, or its network did not come back on the new
// supervisor after a legacy session) stopped the VM even when its sync
// failed. It now keeps it running, contained as a security stop does
// (TestASecurityStopThatCannotSyncContainsTheVM), and the start fails
// saying the VM still runs.
func TestAFailedStartThatCannotSyncKeepsItsVMContained(t *testing.T) {
	var failSync atomic.Bool
	guest := func(e *harnessEnv, edit func(string, *workloadAnswer)) openshelltest.ExecHandler {
		return e.workloadChecks(edit, func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
			if len(call.Command) == 1 && call.Command[0] == "/bin/sync" && failSync.Load() {
				return openshelltest.ExecResponse{Err: context.DeadlineExceeded}
			}
			return openshelltest.DefaultExec(call)
		})
	}
	t.Run("its workload check fails", func(t *testing.T) {
		failSync.Store(false)
		e := newVMEnv(t, nil)
		e.create(sandboxapi.CreateRequest{Name: "vmstart", Copy: true})
		e.addNetworkRule("vmstart", "hostport", "host.openshell.internal", 8080)
		e.stopBox("vmstart")
		e.fake.HandleExec(guest(e, func(_ string, a *workloadAnswer) { a.uid = 0 }))
		failSync.Store(true)
		stops := e.fake.Calls(openshelltest.MethodStopSandbox)
		_, err := e.m.Start(t.Context(), "vmstart", sandboxapi.StartRequest{})
		if apiErr := wantCode(t, err, sandboxapi.CodePolicyRejected); strings.Contains(apiErr.Message, "stopped it again") ||
			!strings.Contains(apiErr.Message, "so it is still running") {
			t.Fatalf("the failed start = %+v", apiErr)
		}
		wantContained(t, e, "vmstart", "its start failed", stops)
		failSync.Store(false)
		wantReleased(t, e, "vmstart")
	})
	t.Run("its network does not come back on the new supervisor", func(t *testing.T) {
		failSync.Store(false)
		e := newVMEnv(t, nil)
		e.create(sandboxapi.CreateRequest{Name: "vmstart", Copy: true})
		e.fake.HandleExec(guest(e, nil))
		b := e.boxOf("vmstart")
		e.m.mu.Lock()
		b.rec.SessionRelease = "0.1.3"
		e.m.mu.Unlock()
		must(t, e.m.saveRecord(b))
		e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
		e.m.tamperStops.Wait()
		e.stopBox("vmstart")
		// The first policy update after the start, the restore of the
		// create-time network, fails; the guest's sync fails too.
		var started, refused atomic.Bool
		e.fake.Intercept(func(method string) error {
			if method == openshelltest.MethodStartSandbox {
				started.Store(true)
			}
			if method == openshelltest.MethodUpdateConfig && started.Load() && refused.CompareAndSwap(false, true) {
				return &types.StatusError{Code: types.ErrorInternal, Message: "policy update failed"}
			}
			return nil
		})
		failSync.Store(true)
		stops := e.fake.Calls(openshelltest.MethodStopSandbox)
		_, err := e.m.Start(t.Context(), "vmstart", sandboxapi.StartRequest{})
		if apiErr := wantCode(t, err, sandboxapi.CodeUnavailable); !strings.Contains(apiErr.Message, "did not restore its network on the new OpenShell supervisor") ||
			!strings.Contains(apiErr.Detail, "DefenseClaw did not stop the new session, so it is still running") {
			t.Fatalf("the failed start = %+v", apiErr)
		}
		wantContained(t, e, "vmstart", "its start failed", stops)
		failSync.Store(false)
		wantReleased(t, e, "vmstart")
	})
}

// GAP-0902 review (loop round 3): a contained VM counted as live only when
// ready or when its workload ended with its VM held. A start whose check
// failed and whose sync failed is contained, but when OpenShell could not
// be asked for its phase after it (restorePhase's lookup failed) the box
// kept the start's own phase, starting: the status left the VM out, a new
// sandbox was created beside it and reconcile never retried the withdrawal
// of its network. A contained VM now stays unprotected in every phase that
// may hold its VM (holdsCompute), and only OpenShell's account of it gone
// releases it.
func TestAContainedVMStaysUnprotectedInEveryPhaseThatMayHoldIt(t *testing.T) {
	vm := string(openshell.DriverVM)
	for _, c := range []struct {
		phase  audit.SandboxPhase
		reason string
		live   bool
		stop   string
	}{
		{phase: audit.SandboxPhaseReady, live: true, stop: "stop"},
		{phase: audit.SandboxPhaseStarting, live: true, stop: "stop"},
		{phase: audit.SandboxPhaseProvisioning, live: true, stop: "stop"},
		{phase: audit.SandboxPhaseStopping, live: true, stop: "stop"},
		{phase: audit.SandboxPhaseUnknown, live: true, stop: "stop"},
		{phase: "", live: true, stop: "stop"},
		{phase: "suspended", live: true, stop: "stop"},
		{phase: audit.SandboxPhaseCompleted, live: true, stop: "delete"},
		{phase: audit.SandboxPhaseError, reason: "MainProcessFailed: exit 1", live: true, stop: "delete"},
		{phase: audit.SandboxPhaseError, reason: "ProcessExited: the VM exited"},
		{phase: audit.SandboxPhaseStopped},
		{phase: audit.SandboxPhaseDeleting},
		{phase: audit.SandboxPhaseDeleted},
		{phase: phaseMissing},
	} {
		rec := record{Name: "vm", Driver: vm, Contained: "its start failed", PhaseReason: c.reason}
		if got := containedLive(c.phase, rec); got != c.live {
			t.Errorf("containedLive(%q, %q) = %v, want %v", c.phase, c.reason, got, c.live)
		}
		if got := unprotectedLive(c.phase, rec); got != c.live {
			t.Errorf("unprotectedLive(%q, %q) = %v, want %v", c.phase, c.reason, got, c.live)
		}
		if containedLive(c.phase, record{Name: "vm", Driver: vm, PhaseReason: c.reason}) {
			t.Errorf("an uncontained MicroVM in %q is contained", c.phase)
		}
		if c.live {
			if got, want := legacyStopCommand("vm", c.phase), "defenseclaw sandbox "+c.stop+" vm"; got != want {
				t.Errorf("legacyStopCommand(%q) = %q, want %q", c.phase, got, want)
			}
			if way := legacyWayOn("vm", c.phase, vm); !strings.Contains(way, "`defenseclaw sandbox "+c.stop+" vm") {
				t.Errorf("legacyWayOn(%q) = %q", c.phase, way)
			}
		}
	}

	// The start whose check fails, then its sync, then OpenShell's lookup
	// of its phase and the first withdrawal of its network.
	var failSync, syncFailed atomic.Bool
	var lookups atomic.Int32
	e := newVMEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "vmstart", Copy: true})
	e.addNetworkRule("vmstart", "hostport", "host.openshell.internal", 8080)
	e.stopBox("vmstart")
	e.fake.HandleExec(e.workloadChecks(func(_ string, a *workloadAnswer) { a.uid = 0 },
		func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
			if len(call.Command) == 1 && call.Command[0] == "/bin/sync" && failSync.Load() {
				syncFailed.Store(true)
				return openshelltest.ExecResponse{Err: context.DeadlineExceeded}
			}
			return openshelltest.DefaultExec(call)
		}))
	e.fake.Intercept(func(method string) error {
		if method == openshelltest.MethodGetSandbox && syncFailed.Load() && lookups.Add(1) <= 2 {
			return &types.StatusError{Code: types.ErrorInternal, Message: "the gateway is busy"}
		}
		return nil
	})
	failSync.Store(true)
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	_, err := e.m.Start(t.Context(), "vmstart", sandboxapi.StartRequest{})
	if apiErr := wantCode(t, err, sandboxapi.CodePolicyRejected); !strings.Contains(apiErr.Message, "so it is still running") {
		t.Fatalf("the failed start = %+v", apiErr)
	}
	if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
		t.Fatalf("stopped a MicroVM whose sync failed: %d stop calls", got-stops)
	}
	b := e.boxOf("vmstart")
	e.m.mu.Lock()
	phase, contained := b.phase, b.rec.Contained
	e.m.mu.Unlock()
	if phase != audit.SandboxPhaseStarting || contained != "its start failed" {
		t.Fatalf("the scenario was not reached: phase %q, contained %q", phase, contained)
	}
	st, err := e.m.Status(t.Context())
	must(t, err)
	if len(st.Unprotected) != 1 || st.Unprotected[0] != (sandboxapi.UnprotectedSandbox{Name: "vmstart", Phase: "starting",
		Stop: "defenseclaw sandbox stop vmstart", Reason: sandboxapi.UnprotectedContained}) {
		t.Fatalf("unprotected = %+v", st.Unprotected)
	}
	_, err = e.tryCreate(sandboxapi.CreateRequest{Name: "beside", Copy: true, Project: e.otherProject("beside")})
	if apiErr := wantCode(t, err, sandboxapi.CodeConflict); !strings.Contains(apiErr.Message, "while vmstart runs ("+containedUnprotected+")") ||
		!strings.Contains(apiErr.Detail, "`defenseclaw sandbox stop vmstart`") {
		t.Fatalf("create beside a contained MicroVM = %+v", apiErr)
	}
	warned := false
	for _, w := range e.get("vmstart").Warnings {
		warned = warned || strings.HasPrefix(w, containedUnprotected) && strings.Contains(w, "`defenseclaw sandbox stop vmstart`")
	}
	if !warned {
		t.Fatal("the view does not say the MicroVM is contained")
	}
	// Its network withdrawal failed with the lookup: reconcile retries it.
	if !e.hasRule("vmstart", "hostport") {
		t.Fatal("the scenario was not reached: the first withdrawal did not fail")
	}
	e.m.reconcileOldSupervisor(t.Context(), b)
	if e.hasRule("vmstart", "hostport") || e.hasRule("vmstart", "defenseclaw_egress") {
		t.Fatal("reconcile did not retry the withdrawal of the contained MicroVM's network")
	}
	failSync.Store(false)
	wantReleased(t, e, "vmstart")
}
