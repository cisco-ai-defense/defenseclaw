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
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

// newEndedVM is a MicroVM gateway running the sandbox name, with the
// manager on a fake clock (advance moves it on).
func newEndedVM(t *testing.T, name string) (e *harnessEnv, advance func(time.Duration)) {
	t.Helper()
	e = newVMEnv(t, nil)
	useOpenCode(t, e)
	e.run()
	e.create(sandboxapi.CreateRequest{Name: name, Harness: "opencode", Copy: true})
	e.watch.waitStarted(t, name)
	_, advance = e.fakeClock(time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC))
	return e, advance
}

// endIn puts the sandbox name in phase, in OpenShell and as the manager
// saw it.
func endIn(t *testing.T, e *harnessEnv, name string, phase openshell.SandboxPhase, conds ...stream.Condition) {
	t.Helper()
	must(t, e.fake.SetPhase(openshell.DefaultWorkspace, name, phase))
	e.m.statusEvent(t.Context(), e.boxOf(name), &stream.Status{Phase: phase, Conditions: conds})
}

// exitedWith gives the sandbox name in OpenShell the exit code of a main
// process that failed, whose stop OpenShell returns as it is.
func exitedWith(t *testing.T, e *harnessEnv, name string, code int32) {
	t.Helper()
	sb, err := e.fake.Sandboxes().Get(t.Context(), openshell.DefaultWorkspace, name)
	must(t, err)
	sb.Status.ExitCode = &code
	sb.ResourceVersion++
	e.fake.SDK().AddSandbox(openshell.DefaultWorkspace, sb)
}

// busy is what the status says a stop of the gateway waits for.
func busy(t *testing.T, e *harnessEnv) int {
	t.Helper()
	st, err := e.m.Status(t.Context())
	if err != nil || st.Live == nil {
		t.Fatalf("status = %+v, %v", st, err)
	}
	return st.Busy()
}

// syncsIn counts the sync(1) commands tried in the sandbox name since the
// first n exec calls: OpenShell refuses a command in a sandbox that is not
// ready (the fake too), so DefenseClaw must not count on one there.
func syncsIn(e *harnessEnv, name string, n int) int {
	got := 0
	for _, c := range e.fake.ExecCalls()[n:] {
		if c.Sandbox == name && len(c.Command) == 1 && c.Command[0] == "/bin/sync" {
			got++
		}
	}
	return got
}

var (
	mainFailed  = stream.Condition{Type: "Ready", Status: "False", Reason: "MainProcessFailed", Message: "Canonical main process exited with status 1"}
	vmExited    = stream.Condition{Type: "Ready", Status: "False", Reason: "ProcessExited", Message: "VM process exited with status 1"}
	vmUnpolled  = stream.Condition{Type: "Ready", Status: "False", Reason: "ProcessPollFailed", Message: "Bad file descriptor"}
	provTimeout = stream.Condition{Type: "Ready", Status: "False", Reason: "ProvisioningTimedOut", Message: "Provisioning repair window expired after 300 seconds"}
)

// A MicroVM whose workload ended still runs its VM (GAP-0012), with
// whatever its workload left running (a background process its main one
// forked), and nothing in OpenShell flushes or stops it: it runs no
// command in it, and its stop returns it as it is. The rounds before let
// such a MicroVM go two minutes after DefenseClaw saw its workload end,
// then on its user's own stop, so a managed pin switch, the daemon's idle
// stop or an upgrade could kill that process with its last writes
// unflushed. Now only OpenShell's own state releases it: the status
// counts it (they wait for it) however long it has been so, and whoever
// stops it, until OpenShell reports it stopped, deleting or with its VM
// gone. A completed, failed, unpolled or timed-out MicroVM holds; a
// stopped or deleting one does not. On docker a completed sandbox is an
// exited container: nothing waits.
func TestAnEndedMicroVMHoldsTheGatewayUntilOpenShellReportsItStopped(t *testing.T) {
	e, advance := newEndedVM(t, "donebox")
	n := len(e.fake.ExecCalls())
	endIn(t, e, "donebox", openshell.PhaseCompleted)
	if got := busy(t, e); got != 1 {
		t.Fatalf("a completed MicroVM: busy %d, want 1", got)
	}
	advance(24 * time.Hour)
	if got := busy(t, e); got != 1 {
		t.Fatalf("a completed MicroVM a day on: busy %d, want 1", got)
	}

	// No stop releases it, the user's own included: OpenShell returns it
	// as it is.
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	e.stopBox("donebox")
	b := e.boxOf("donebox")
	if e.fake.Calls(openshelltest.MethodStopSandbox) != stops+1 || b.phase != audit.SandboxPhaseCompleted || busy(t, e) != 1 {
		t.Fatalf("a session's stop: phase %s, busy %d", b.phase, busy(t, e))
	}
	v, err := e.m.Stop(t.Context(), "donebox")
	if err != nil || v.Phase != "completed" || !HoldsCompute(*v) || busy(t, e) != 1 {
		t.Fatalf("the user's stop of a completed MicroVM = %+v, %v (busy %d)", v, err, busy(t, e))
	}
	if got := syncsIn(e, "donebox", n); got != 0 {
		t.Fatalf("%d sync(1) tried in a completed MicroVM", got)
	}

	for _, tc := range []struct {
		cond stream.Condition
		busy int
	}{{mainFailed, 1}, {vmUnpolled, 1}, {provTimeout, 1}, {vmExited, 0}} {
		endIn(t, e, "donebox", openshell.PhaseProvisioning)
		endIn(t, e, "donebox", openshell.PhaseError, tc.cond)
		advance(24 * time.Hour)
		if got := busy(t, e); got != tc.busy {
			t.Errorf("a MicroVM in the error state (%s) a day on: busy %d, want %d", tc.cond.Reason, got, tc.busy)
		}
	}
	// A daemon restart's reconcile republishes the error state without its
	// conditions: the reason stays.
	endIn(t, e, "donebox", openshell.PhaseProvisioning)
	endIn(t, e, "donebox", openshell.PhaseError, vmExited)
	e.m.lifecycle(t.Context(), b, audit.SandboxPhaseError, audit.SandboxTriggerReconcile, true, nil, nil)
	if got := busy(t, e); got != 0 || !strings.Contains(e.boxOf("donebox").rec.PhaseReason, "ProcessExited") {
		t.Fatalf("a republished error state: busy %d, reason %q", got, e.boxOf("donebox").rec.PhaseReason)
	}

	// Its main process failed: OpenShell returns its stop as it is, and it
	// still holds.
	endIn(t, e, "donebox", openshell.PhaseProvisioning)
	endIn(t, e, "donebox", openshell.PhaseError, mainFailed)
	exitedWith(t, e, "donebox", 1)
	if v, err := e.m.Stop(t.Context(), "donebox"); err != nil || v.Phase != "error" || busy(t, e) != 1 {
		t.Fatalf("the user's stop of a failed main process = %+v, %v (busy %d)", v, err, busy(t, e))
	}
	// OpenShell reports it stopped, or deleting: it holds nothing.
	for _, phase := range []openshell.SandboxPhase{openshell.PhaseStopped, openshell.PhaseDeleting} {
		endIn(t, e, "donebox", phase)
		if got := busy(t, e); got != 0 {
			t.Errorf("a MicroVM OpenShell reports %s: busy %d", phase, got)
		}
	}

	d := newEnv(t, nil)
	d.create(sandboxapi.CreateRequest{Name: "dockerdone"})
	endIn(t, d, "dockerdone", openshell.PhaseCompleted)
	if got := busy(t, d); got != 0 {
		t.Fatalf("a completed docker sandbox: busy %d", got)
	}
	m := len(d.fake.ExecCalls())
	if v, err := d.m.Stop(t.Context(), "dockerdone"); err != nil || HoldsCompute(*v) {
		t.Fatalf("the user's stop of a completed docker sandbox = %+v, %v", v, err)
	}
	if got := syncsIn(d, "dockerdone", m); got != 0 {
		t.Fatalf("a completed docker sandbox: %d sync(1) tried", got)
	}
}

// An OpenShell before 0.1.5 (the 0.1.3 of DefenseClaw 1.0.3) neither stops
// nor starts a MicroVM in its error state, and DefenseClaw starts no
// sandbox on it. The rounds before let the upgrade go ahead after two
// minutes, then on the user's refused stop, under a VM that may still
// write. Now the upgrade (per user, or the managed pin move) is refused
// while OpenShell does not report the MicroVM stopped, whoever asked for a
// stop, and the feed and the refused stop say that only its delete lets
// the upgrade go ahead. One whose VM is gone runs nothing, and the way on
// is the upgrade, then stop and start.
func TestOldGatewayErrorMicroVMHoldsTheUpgradeUntilOpenShellReportsItGone(t *testing.T) {
	e, advance := newEndedVM(t, "box")
	connectAtFakeRelease(e)
	e.fake.SetRelease("0.1.3")
	if _, err := e.tryCreate(sandboxapi.CreateRequest{Name: "fresh", Harness: "opencode", Copy: true, Project: e.otherProject("other")}); err == nil {
		t.Fatal("a create on 0.1.3 succeeded")
	}
	if got := e.m.gatewayRelease(); got != "0.1.3" {
		t.Fatalf("gateway release = %q", got)
	}
	upgrade := "upgrade OpenShell 0.1.3 to " + openshell.InstallerVersion + " in place with `defenseclaw sandbox setup --install-openshell`"
	deleteFirst := "this OpenShell can neither stop nor start a sandbox in its error state, and DefenseClaw stops no OpenShell gateway, so upgrades none, " +
		"while OpenShell has not reported a MicroVM on it stopped: `defenseclaw sandbox delete box` deletes it and its work, after which " + upgrade
	n := len(e.fake.ExecCalls())
	feedLine := func() string {
		var line string
		for _, ev := range e.events("box", sandboxapi.ActivityLifecycle, "") {
			if ev.Phase == string(audit.SandboxPhaseError) {
				line = ev.Message
			}
		}
		return line
	}
	for _, cond := range []stream.Condition{mainFailed, vmUnpolled, provTimeout} {
		endIn(t, e, "box", openshell.PhaseProvisioning)
		endIn(t, e, "box", openshell.PhaseError, cond)
		if line := feedLine(); !strings.Contains(line, deleteFirst) || strings.Contains(line, "disk back") || strings.Contains(line, "lets the upgrade") {
			t.Fatalf("the feed's line (%s): %q", cond.Reason, line)
		}
		advance(24 * time.Hour)
		if got := busy(t, e); got != 1 {
			t.Fatalf("a MicroVM in the error state (%s) a day on: busy %d", cond.Reason, got)
		}
	}

	refused := &types.StatusError{Code: types.ErrorConflict, Message: "sandbox must be Ready or in an automatic restart to stop (current phase: Error)"}
	// The user's stop is refused by OpenShell and releases nothing.
	e.fake.FailNext(openshelltest.MethodStopSandbox, refused)
	_, err := e.m.Stop(t.Context(), "box")
	apiErr := wantCode(t, err, sandboxapi.CodeConflict)
	if !strings.Contains(apiErr.Message, "box is in OpenShell's error state") || !strings.Contains(apiErr.Detail, deleteFirst) {
		t.Fatalf("the user's refused stop = %+v", apiErr)
	}
	if got := syncsIn(e, "box", n); got != 0 {
		t.Fatalf("%d sync(1) tried in a MicroVM in the error state, which OpenShell refuses", got)
	}
	if got := busy(t, e); got != 1 {
		t.Fatalf("a MicroVM whose stop OpenShell refused: busy %d, want the upgrade held", got)
	}

	// Its VM is gone: nothing runs, nothing waits.
	endIn(t, e, "box", openshell.PhaseProvisioning)
	endIn(t, e, "box", openshell.PhaseError, vmExited)
	if line := feedLine(); !strings.Contains(line, "this OpenShell can neither stop nor start a sandbox in its error state: "+upgrade+
		", then fix why its MicroVM exited; then `defenseclaw sandbox stop box` and `defenseclaw sandbox start box`") ||
		!strings.Contains(line, "last successful disk sync") || strings.Contains(line, "which keep the sandbox and its work") {
		t.Fatalf("the feed's line for a MicroVM whose VM is gone: %q", line)
	}
	if got := busy(t, e); got != 0 {
		t.Fatalf("a MicroVM whose VM is gone: busy %d", got)
	}
}

// A create or a start that DefenseClaw made after a restart's or an
// upgrade's check of the sandboxes ran into that restart unflushed. Each
// now takes the gateway's lifecycle lock over OpenShell's call: while a
// restart or an upgrade holds it, the call is refused with nothing sent
// to OpenShell and the sandbox as it was; it is held only over the call.
func TestCreateAndStartWaitOutAGatewayRestart(t *testing.T) {
	e := newEnv(t, nil)
	dir := t.TempDir()
	held := false
	e.m.opts.StartLock = func() (func(), error) {
		unlock, err := openshell.LockSandboxStart(dir)
		if err == nil {
			held = true
			return func() { held = false; unlock() }, nil
		}
		return nil, err
	}
	restart, err := openshell.LockGatewayLifecycle(context.Background(), dir)
	must(t, err)
	creates := e.fake.Calls(openshelltest.MethodCreateSandbox)
	_, err = e.tryCreate(sandboxapi.CreateRequest{Name: "box"})
	if apiErr := wantCode(t, err, sandboxapi.CodeUnavailable); !strings.Contains(apiErr.Message, "DefenseClaw is restarting or upgrading the OpenShell gateway") ||
		e.fake.Calls(openshelltest.MethodCreateSandbox) != creates {
		t.Fatalf("a create during a restart = %+v (creates %d)", apiErr, e.fake.Calls(openshelltest.MethodCreateSandbox)-creates)
	}
	restart()
	e.create(sandboxapi.CreateRequest{Name: "box"})
	if held {
		t.Fatal("the create kept the lock after OpenShell's call")
	}
	e.stopBox("box")

	restart, err = openshell.LockGatewayLifecycle(context.Background(), dir)
	must(t, err)
	starts := e.fake.Calls(openshelltest.MethodStartSandbox)
	_, err = e.m.Start(t.Context(), "box", sandboxapi.StartRequest{})
	wantCode(t, err, sandboxapi.CodeUnavailable)
	if e.fake.Calls(openshelltest.MethodStartSandbox) != starts || e.boxOf("box").phase != audit.SandboxPhaseStopped {
		t.Fatalf("a start during a restart reached OpenShell or moved the sandbox to %s", e.boxOf("box").phase)
	}
	restart()
	e.startBox("box", sandboxapi.StartRequest{})
	if held {
		t.Fatal("the start kept the lock after OpenShell's call")
	}
}

// TestAStartOfAnEndedMicroVMLosesNothingUnasked: the MicroVM of a
// workload that completed, or whose main process failed, still runs, with
// a writer that workload left running whose last writes are not on its
// disk. OpenShell's start of it ends that VM with no flush first, and the
// rounds before told the user to start it, then stop it, as if that kept
// its work (and `sandbox start`, `connect` and `pull` started it unasked).
// Now a start of such a MicroVM is refused, before OpenShell is called,
// with the loss named and `start --end-vm` as the way on, which then loses
// those writes as it said. A MicroVM whose VM is gone, a provisioning that
// timed out (which never ran the workload) and a completed docker sandbox
// (an exited container keeps its writes) start as before.
func TestAStartOfAnEndedMicroVMLosesNothingUnasked(t *testing.T) {
	for _, tc := range []struct {
		name  string
		phase openshell.SandboxPhase
		cond  []stream.Condition
		code  int32
	}{
		{"completed", openshell.PhaseCompleted, nil, 0},
		{"main process failed", openshell.PhaseError, []stream.Condition{mainFailed}, 1},
		{"unpolled", openshell.PhaseError, []stream.Condition{vmUnpolled}, 0},
		{"no reason", openshell.PhaseError, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newEndedVM(t, "donebox")
			endIn(t, e, "donebox", tc.phase, tc.cond...)
			if tc.code != 0 {
				exitedWith(t, e, "donebox", tc.code)
			}
			e.fake.LeaveWriter(openshell.DefaultWorkspace, "donebox", "bg.log: the last 30 seconds")
			starts := e.fake.Calls(openshelltest.MethodStartSandbox)
			_, err := e.m.Start(t.Context(), "donebox", sandboxapi.StartRequest{})
			var apiErr *sandboxapi.Error
			if !errors.As(err, &apiErr) || apiErr.Code != sandboxapi.CodeConflict || !strings.Contains(apiErr.Message, "no flush first") ||
				!strings.Contains(apiErr.Message, "is lost") || !strings.Contains(apiErr.Detail, "`defenseclaw sandbox start donebox --end-vm`") ||
				strings.Contains(apiErr.Message+apiErr.Detail, "keeps its work") || strings.Contains(apiErr.Message+apiErr.Detail, "work is kept") {
				t.Fatalf("a start of a MicroVM that is %s = %v", tc.name, err)
			}
			if e.fake.Calls(openshelltest.MethodStartSandbox) != starts || len(e.fake.LostWrites()) != 0 {
				t.Fatalf("the refused start called OpenShell (%d starts) or lost %v", e.fake.Calls(openshelltest.MethodStartSandbox)-starts, e.fake.LostWrites())
			}
			// Asked for: OpenShell's start ends the VM, and the writes go.
			if _, err := e.m.Start(t.Context(), "donebox", sandboxapi.StartRequest{EndVM: true}); err != nil {
				t.Fatalf("start --end-vm: %v", err)
			}
			// The fake models the loss where OpenShell's own stop is a no-op
			// (completed, a main process that failed).
			wantLost := 0
			if tc.phase == openshell.PhaseCompleted || tc.code != 0 {
				wantLost = 1
			}
			if e.fake.Calls(openshelltest.MethodStartSandbox) != starts+1 || len(e.fake.LostWrites()) != wantLost {
				t.Fatalf("start --end-vm: %d starts, lost %v", e.fake.Calls(openshelltest.MethodStartSandbox)-starts, e.fake.LostWrites())
			}
		})
	}
	for _, tc := range []struct {
		name string
		cond stream.Condition
	}{{"VM gone", vmExited}, {"provisioning timed out", provTimeout}} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newEndedVM(t, "donebox")
			endIn(t, e, "donebox", openshell.PhaseError, tc.cond)
			if _, err := e.m.Start(t.Context(), "donebox", sandboxapi.StartRequest{}); err != nil && strings.Contains(err.Error(), "--end-vm") {
				t.Fatalf("a start of a MicroVM whose %s: %v", tc.name, err)
			}
		})
	}
	d := newEnv(t, nil)
	d.create(sandboxapi.CreateRequest{Name: "dockerdone"})
	endIn(t, d, "dockerdone", openshell.PhaseCompleted)
	if _, err := d.m.Start(t.Context(), "dockerdone", sandboxapi.StartRequest{}); err != nil {
		t.Fatalf("a start of a completed docker sandbox: %v", err)
	}
}
