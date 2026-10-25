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
	"sync"
	"sync/atomic"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

// legacyWarned reports whether the view v warns that its legacy guest is
// not protected, that DefenseClaw does not contain the old broker, and
// names way, the command that ends it.
func legacyWarned(v *sandboxapi.Sandbox, way string) bool {
	for _, w := range v.Warnings {
		if strings.HasPrefix(w, legacyUnprotected) && strings.Contains(w, "does not contain the old broker") && strings.Contains(w, way) {
			return true
		}
	}
	return false
}

// legacyGuest is a ready sandbox named name whose session runs the 0.1.3
// supervisor, with a direct network rule: on a MicroVM gateway when vm,
// whose guest answers exec, else on docker. Its record is saved, so a
// restarted daemon finds it.
func legacyGuest(t *testing.T, name string, vm bool, exec openshelltest.ExecHandler) (*harnessEnv, *box) {
	t.Helper()
	e := newEnv(t, nil)
	if vm {
		e = newVMEnv(t, nil)
	}
	e.create(sandboxapi.CreateRequest{Name: name, Copy: true})
	e.addNetworkRule(name, "direct", "background.example.org", 443)
	b := e.boxOf(name)
	e.m.mu.Lock()
	b.rec.SessionRelease = "0.1.3"
	e.m.mu.Unlock()
	must(t, e.m.saveRecord(b))
	if exec != nil {
		e.fake.HandleExec(e.workloadChecks(nil, exec))
	}
	return e, b
}

// guestAnswers is a legacy MicroVM guest whose harness exit and flush
// answer out; failSync fails a sync(1) on its own.
func guestAnswers(out string, failSync bool) openshelltest.ExecHandler {
	return func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		if len(call.Command) > 0 && call.Command[0] == "/bin/sync" && failSync {
			return openshelltest.ExecResponse{Err: errors.New("sync failed")}
		}
		return openshelltest.ExecResponse{Stdout: []byte(out)}
	}
}

// refuseUpdates has OpenShell refuse every policy update.
func refuseUpdates(e *harnessEnv) {
	e.fake.Intercept(func(method string) error {
		if method == openshelltest.MethodUpdateConfig {
			return &types.StatusError{Code: types.ErrorConflict, Message: "policy update refused"}
		}
		return nil
	})
}

// DefenseClaw never stops a legacy guest on its own: a ready session on
// the 0.1.3 supervisor, on docker or a MicroVM, whatever its guest's sync
// does, whether or not DefenseClaw could withdraw the network rules it
// added (a gateway-global policy, OpenShell refusing the update, a global
// policy that comes only after a first withdrawal), and for a restarted
// daemon too. It closes the egress proxy and withdraws those rules, which
// does not contain that release's broker (GAP-0831), so it reports the
// guest unprotected with the command that ends it, says once that a
// withdrawal failed, and creates no sandbox while the guest runs. Only the
// user's stop ends it; then a create goes ahead and the next session gets
// its create-time network back.
func TestDefenseClawStopsNoLegacyGuest(t *testing.T) {
	globalPolicy := func(e *harnessEnv) { e.fake.SetGlobalPolicy(&openshell.SandboxPolicy{Version: 1}) }
	for _, tc := range []struct {
		name    string
		vm      bool
		exec    openshelltest.ExecHandler
		restart bool
		// before breaks the withdrawal before the session is seen ready;
		// later only after a first withdrawal went through.
		before, later func(*harnessEnv)
		cause         string
	}{
		{name: "docker session", vm: false},
		{name: "docker session after a daemon restart", vm: false, restart: true},
		{name: "MicroVM, guest synced", vm: true, exec: guestAnswers("exited\nsynced\n", false)},
		{name: "MicroVM, sync fails", vm: true, exec: guestAnswers("exited\n", true)},
		{name: "MicroVM, gateway-global policy", vm: true, exec: guestAnswers("exited\nsynced\n", false), before: globalPolicy, cause: "gateway-global policy"},
		{name: "MicroVM, policy update refused", vm: true, exec: guestAnswers("exited\nsynced\n", false), before: refuseUpdates, cause: "policy update refused"},
		{name: "MicroVM, global policy after the rules were withdrawn", vm: true, exec: guestAnswers("exited\nsynced\n", false), later: globalPolicy, cause: "gateway-global policy"},
		{name: "docker, policy update refused", vm: false, before: refuseUpdates, cause: "policy update refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, b := legacyGuest(t, "kept", tc.vm, tc.exec)
			if tc.before != nil {
				tc.before(e)
			}
			stops := e.fake.Calls(openshelltest.MethodStopSandbox)
			if tc.restart {
				e.restartDaemon()
				b = e.boxOf("kept")
			} else {
				e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
			}
			e.m.tamperStops.Wait()
			if tc.later != nil {
				e.m.mu.Lock()
				withdrawn := b.rec.OldSupervisorNetworkClosed
				e.m.mu.Unlock()
				if !withdrawn || e.hasRule("kept", "direct") {
					t.Fatalf("precondition: the first withdrawal went through; record %+v", b.rec)
				}
				tc.later(e)
			}
			for range 3 {
				must(t, e.m.Reconcile(t.Context()))
				e.m.tamperStops.Wait()
			}
			if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
				t.Fatalf("DefenseClaw stopped the legacy guest on its own: %d stop calls", got-stops)
			}
			got := e.get("kept")
			if got.Phase != "ready" || !got.OldSupervisor || !legacyWarned(got, "run `defenseclaw sandbox stop kept`") {
				t.Fatalf("the legacy guest was not kept and named unprotected: %+v", got)
			}
			if tc.vm != strings.Contains(strings.Join(got.Warnings, " "), "syncs the VM's disk first") {
				t.Fatalf("the MicroVM note of the stop (vm %v): %v", tc.vm, got.Warnings)
			}
			if found := findingsSaying(e, "kept", "kept: "+legacyUnprotected+": its session started on OpenShell 0.1.3"); len(found) != 1 || found[0].Severity != "HIGH" ||
				!strings.Contains(found[0].Message, "does not contain the old broker") || !strings.Contains(found[0].Message, "`defenseclaw sandbox stop kept`") {
				t.Fatalf("no single HIGH finding naming the guest unprotected: %+v", e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor))
			}
			kept := findingsSaying(e, "kept", legacyRulesKept)
			if tc.cause == "" {
				if len(kept) != 0 || e.hasRule("kept", "direct") {
					t.Fatalf("the withdrawal: findings %+v, direct rule kept %v", kept, e.hasRule("kept", "direct"))
				}
			} else if len(kept) != 1 || !strings.Contains(kept[0].Message, tc.cause) || !strings.Contains(strings.Join(got.Warnings, " "), legacyRulesKept) {
				t.Fatalf("the failed withdrawal (%s) was not said once, loudly: findings %+v, warnings %v", tc.cause, kept, got.Warnings)
			}
			if got := e.events("kept", sandboxapi.ActivityLifecycle, "stop_unflushed"); len(got) != 0 {
				t.Fatalf("a guest nobody stopped was reported as an unflushed stop: %+v", got)
			}
			// No new sandbox while it runs.
			_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "fresh", Copy: true, Project: e.otherProject("other")})
			apiErr := wantCode(t, err, sandboxapi.CodeConflict)
			if !strings.Contains(apiErr.Message, "DefenseClaw runs no new sandbox while kept runs ("+legacyUnprotected+")") ||
				!strings.Contains(apiErr.Detail, "kept: save the work you need, then run `defenseclaw sandbox stop kept`") {
				t.Fatalf("create beside a legacy guest = %+v", apiErr)
			}
			if e.boxOf("fresh") != nil {
				t.Fatal("the refused create left a sandbox behind")
			}
			// The user's stop ends it once its guest's sync works (a stop
			// whose sync fails is held: GAP-1163); then a sandbox runs again,
			// and the next session of this one gets its create-time network
			// back.
			if tc.cause != "" {
				e.fake.SetGlobalPolicy(nil)
				e.fake.Intercept(nil)
			}
			e.fake.HandleExec(e.workloadChecks(nil, guestAnswers("exited\nsynced\n", false)))
			e.stopBox("kept")
			if got := e.get("kept"); got.Phase != "stopped" || got.OldSupervisor {
				t.Fatalf("the user's stop: %+v", got)
			}
			e.create(sandboxapi.CreateRequest{Name: "fresh", Copy: true, Project: e.otherProject("other")})
			e.startBox("kept", sandboxapi.StartRequest{})
			// A withdrawal that never began changed nothing to restore.
			if got := e.get("kept"); got.Phase != "ready" || got.OldSupervisor || !e.hasRule("kept", "defenseclaw_egress") || tc.before == nil && e.hasRule("kept", "direct") {
				t.Fatalf("the next session: %+v", got)
			}
		})
	}
}

// While a legacy guest lives, DefenseClaw starts no other sandbox, nor
// creates one, and the refusal names the guest with the command that ends
// it: the stop of a ready one, the delete of a MicroVM whose workload
// ended, which OpenShell does not stop. The start that ends that MicroVM
// itself (--end-vm) goes ahead, but not while another legacy guest runs.
func TestALegacyGuestHoldsBackEveryNewRun(t *testing.T) {
	e, b := legacyGuest(t, "kept", true, guestAnswers("exited\nsynced\n", false))
	sessionRelease := func(b *box, release string) {
		e.m.mu.Lock()
		b.rec.SessionRelease = release
		e.m.mu.Unlock()
	}
	sessionRelease(b, openshell.SupportedMin)
	e.create(sandboxapi.CreateRequest{Name: "other", Copy: true, Project: e.otherProject("other")})
	e.create(sandboxapi.CreateRequest{Name: "third", Copy: true, Project: e.otherProject("third")})
	e.stopBox("third")
	sessionRelease(b, "0.1.3")
	e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
	e.m.tamperStops.Wait()
	_, err := e.m.Start(t.Context(), "third", sandboxapi.StartRequest{})
	if apiErr := wantCode(t, err, sandboxapi.CodeConflict); !strings.Contains(apiErr.Message, "DefenseClaw runs no new sandbox while kept runs") ||
		!strings.Contains(apiErr.Detail, "`defenseclaw sandbox stop kept`") {
		t.Fatalf("start beside a ready legacy guest = %+v", apiErr)
	}
	if got := e.get("third").Phase; got != "stopped" {
		t.Fatalf("the refused start left third %s", got)
	}

	// Its workload ends: the VM may still run, so it still holds every new
	// run back.
	endIn(t, e, "kept", openshell.PhaseCompleted)
	if got := e.get("kept"); !got.OldSupervisor || !legacyWarned(got, "`defenseclaw sandbox delete kept` deletes it and its work") {
		t.Fatalf("the ended legacy MicroVM: %+v", got)
	}
	_, err = e.tryCreate(sandboxapi.CreateRequest{Name: "fresh", Copy: true, Project: e.otherProject("fresh")})
	if apiErr := wantCode(t, err, sandboxapi.CodeConflict); !strings.Contains(apiErr.Detail, "kept: OpenShell does not stop this VM, whose workload ended: `defenseclaw sandbox delete kept`") {
		t.Fatalf("create beside an ended legacy MicroVM = %+v", apiErr)
	}
	// A second legacy guest holds the first one's own start (--end-vm,
	// which ends it) back too; once it is stopped, that start goes ahead.
	ob := e.boxOf("other")
	sessionRelease(ob, "0.1.3")
	e.m.lifecycle(t.Context(), ob, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
	e.m.tamperStops.Wait()
	_, err = e.m.Start(t.Context(), "kept", sandboxapi.StartRequest{EndVM: true})
	if apiErr := wantCode(t, err, sandboxapi.CodeConflict); !strings.Contains(apiErr.Message, "while other runs") {
		t.Fatalf("the ended MicroVM's start beside another legacy guest = %+v", apiErr)
	}
	e.stopBox("other")
	e.startBox("kept", sandboxapi.StartRequest{EndVM: true})
	if got := e.get("kept"); got.Phase != "ready" || got.OldSupervisor {
		t.Fatalf("the start that ended the legacy MicroVM: %+v", got)
	}
	e.create(sandboxapi.CreateRequest{Name: "fresh", Copy: true, Project: e.otherProject("fresh")})
}

// TestAHostLeftOnAnOlderOpenShellUpgradesInPlace: DefenseClaw 1.0.0 to
// 1.0.3 left hosts on OpenShell 0.1.1 to 0.1.3, whose network broker can let
// a sandbox's connections bypass its policy (NVIDIA/OpenShell#4494). The
// daemon still connects to such a gateway and drives the sandboxes there
// (status, stop), so their work is kept, but creates and starts none,
// naming the in-place upgrade. A sandbox whose session runs that release's
// supervisor is named unprotected and kept until its user stops it
// (GAP-0415), and starts again on the upgraded gateway only.
func TestAHostLeftOnAnOlderOpenShellUpgradesInPlace(t *testing.T) {
	e := newEnv(t, nil)
	e.m.opts.Connect = func(ctx context.Context) (*Gateway, error) {
		h, err := e.client.Health(ctx)
		if err != nil {
			return nil, err
		}
		gw := *e.gw
		gw.Version = h.RawVersion
		return &gw, nil
	}
	e.create(sandboxapi.CreateRequest{Name: "kept"})
	if got := e.boxOf("kept").rec.SessionRelease; got != openshell.SupportedMin {
		t.Fatalf("session release = %q, want %s", got, openshell.SupportedMin)
	}
	oldSupervisor := func() []sandboxapi.ActivityEvent {
		return e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor)
	}
	if n := len(oldSupervisor()); n != 0 || legacyWarned(e.get("kept"), "") {
		t.Fatalf("a session on %s is named: %d findings, warnings %v", openshell.SupportedMin, n, e.get("kept").Warnings)
	}

	// The host as 1.0.3 left it: its gateway runs 0.1.3.
	e.fake.SetRelease("0.1.3")
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "fresh", Project: e.otherProject("other")})
	apiErr := wantCode(t, err, sandboxapi.CodeUnavailable)
	if !strings.Contains(apiErr.Message, "OpenShell 0.1.3 runs no DefenseClaw sandbox") || !strings.Contains(apiErr.Message, "NVIDIA/OpenShell#4494") ||
		apiErr.Detail != "upgrade OpenShell 0.1.3 to "+openshell.InstallerVersion+" in place with `defenseclaw sandbox setup --install-openshell`" {
		t.Fatalf("create on 0.1.3 = %+v", apiErr)
	}
	if e.boxOf("fresh") != nil {
		t.Fatal("the refused create left a sandbox behind")
	}
	// A session that starts on it (outside DefenseClaw) runs its
	// supervisor: DefenseClaw names it unprotected and leaves it to its
	// user, and the old gateway starts it no more.
	e.m.statusEvent(t.Context(), e.boxOf("kept"), &stream.Status{Phase: openshell.PhaseProvisioning})
	e.m.statusEvent(t.Context(), e.boxOf("kept"), &stream.Status{Phase: openshell.PhaseReady})
	e.m.tamperStops.Wait()
	found := oldSupervisor()
	if len(found) != 1 || found[0].Severity != "HIGH" || !strings.Contains(found[0].Message, "kept: "+legacyUnprotected+": its session started on OpenShell 0.1.3") ||
		!strings.Contains(found[0].Message, "save the work you need, then run `defenseclaw sandbox stop kept`; then upgrade OpenShell 0.1.3 to "+openshell.InstallerVersion) ||
		!strings.HasSuffix(found[0].Message, "and `defenseclaw sandbox start kept` starts it on that release's supervisor") {
		t.Fatalf("old-supervisor findings = %+v", found)
	}
	if got := e.get("kept"); got.Phase != "ready" || !got.OldSupervisor || !legacyWarned(got, "`defenseclaw sandbox stop kept`") {
		t.Fatalf("a session on the 0.1.3 supervisor: phase %s, old supervisor %v, warnings %v", got.Phase, got.OldSupervisor, got.Warnings)
	}
	e.stopBox("kept")
	_, err = e.m.Start(t.Context(), "kept", sandboxapi.StartRequest{})
	if apiErr := wantCode(t, err, sandboxapi.CodeUnavailable); !strings.Contains(apiErr.Message, "OpenShell 0.1.3 runs no DefenseClaw sandbox") {
		t.Fatalf("start on 0.1.3 = %+v", apiErr)
	}

	// The in-place upgrade: the start goes on the new release's supervisor.
	e.fake.SetRelease(openshell.InstallerVersion)
	e.startBox("kept", sandboxapi.StartRequest{})
	if got := e.boxOf("kept").rec.SessionRelease; got != openshell.InstallerVersion {
		t.Fatalf("session release after the upgrade = %q", got)
	}
	if legacyWarned(e.get("kept"), "") || len(oldSupervisor()) != 1 {
		t.Fatalf("after the upgrade: warnings %v, findings %d", e.get("kept").Warnings, len(oldSupervisor()))
	}
}

// A record from before DefenseClaw kept the session's release names no
// release, an ended legacy MicroVM's way on is its delete, and the managed
// way on is the administrator's.
func TestOldSupervisorWordsForARecordWithoutARelease(t *testing.T) {
	msg := oldSupervisorMessage("box", "", audit.SandboxPhaseReady, "", "")
	if !strings.HasPrefix(msg, "⚠ box: "+legacyUnprotected+": its session started before DefenseClaw kept the OpenShell release a session starts on, so it may run a supervisor older than "+openshell.SupportedMin) ||
		!strings.Contains(msg, "does not contain the old broker") ||
		!strings.HasSuffix(msg, "save the work you need, then run `defenseclaw sandbox stop box`; then `defenseclaw sandbox start box` (or `connect`) starts it again on this gateway's supervisor") {
		t.Fatalf("message = %q", msg)
	}
	ended := oldSupervisorMessage("box", "0.1.3", audit.SandboxPhaseCompleted, string(openshell.DriverVM), "")
	if !strings.Contains(ended, "its MicroVM may still run background work; its session started on OpenShell 0.1.3") ||
		!strings.HasSuffix(ended, "`defenseclaw sandbox delete box` deletes it and its work, or on OpenShell "+openshell.SupportedMin+
			" or later `defenseclaw sandbox start box --end-vm` ends the VM, losing what it has not written to its disk") {
		t.Fatalf("ended message = %q", ended)
	}
	e := newEnv(t, nil)
	if got := e.m.upgradeWayOn(openshell.SupportedMin); got != "" {
		t.Fatalf("upgrade way on %s = %q", openshell.SupportedMin, got)
	}
	if got := e.m.upgradeWayOn("dev"); got != "" {
		t.Fatalf("upgrade way on an unreadable release = %q", got)
	}
	managed, _ := managedEnv(t, nil)
	got := managed.m.upgradeWayOn("0.1.3")
	stop, del := strings.Index(got, "`defenseclaw sandbox stop NAME`"), strings.Index(got, "`defenseclaw sandbox delete NAME`")
	if save := strings.Index(got, "save or sync any accessible work first"); save < 0 || stop < save || del < save ||
		!strings.Contains(got, "requests a disk sync") || !strings.Contains(got, "a failed sync can lose later changes") || strings.Contains(got, "flushes") {
		t.Fatalf("managed upgrade advice risks guest work: %q", got)
	}
}

// TestALegacySessionOfAnOlderRecordIsKeptUntilItsUsersStop (GAP-0415): a
// session that began on the supervisor of an OpenShell older than
// SupportedMin, or one a 1.0.3 record names no release for, keeps that
// supervisor's network broker for as long as it runs, whatever the gateway
// runs now. DefenseClaw names it, on an upgraded gateway too, and stops it
// for nobody however often it looks again; the user's stop ends it, and the
// next start runs the gateway's own supervisor, which is not named.
func TestALegacySessionOfAnOlderRecordIsKeptUntilItsUsersStop(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "kept"})
	b := e.boxOf("kept")
	e.m.mu.Lock()
	b.rec.SessionRelease = ""
	e.m.mu.Unlock()
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
	for range 2 {
		must(t, e.m.Reconcile(t.Context()))
	}
	e.m.tamperStops.Wait()
	if got := e.get("kept"); got.Phase != "ready" || !got.OldSupervisor || e.fake.Calls(openshelltest.MethodStopSandbox) != stops {
		t.Fatalf("a 1.0.3 session on a %s gateway: phase %s, old supervisor %v, stops %d", openshell.SupportedMin, got.Phase, got.OldSupervisor,
			e.fake.Calls(openshelltest.MethodStopSandbox)-stops)
	}
	if n := len(findingsSaying(e, "kept", "kept's session started before DefenseClaw kept the OpenShell release")) +
		len(findingsSaying(e, "kept", "its session started before DefenseClaw kept the OpenShell release")); n != 1 {
		t.Fatalf("findings = %+v", e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor))
	}
	e.stopBox("kept")
	e.startBox("kept", sandboxapi.StartRequest{})
	e.m.tamperStops.Wait()
	if got := e.get("kept"); got.Phase != "ready" || got.OldSupervisor || e.boxOf("kept").rec.SessionRelease != openshell.SupportedMin {
		t.Fatalf("after the start: phase %s, old supervisor %v, release %q", got.Phase, got.OldSupervisor, e.boxOf("kept").rec.SessionRelease)
	}
}

// legacyMicroVMWithBrokenSync is a ready 0.1.3 MicroVM named name with a
// direct network rule, whose guest sync(1) fails.
func legacyMicroVMWithBrokenSync(t *testing.T, name string) (*harnessEnv, *box) {
	t.Helper()
	return legacyGuest(t, name, true, guestAnswers("exited\n", true))
}

// findingsSaying are the sandbox's old-supervisor findings that contain text.
func findingsSaying(e *harnessEnv, name, text string) []sandboxapi.ActivityEvent {
	var out []sandboxapi.ActivityEvent
	for _, ev := range e.events(name, sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor) {
		if strings.Contains(ev.Message, text) {
			out = append(out, ev)
		}
	}
	return out
}

// A legacy MicroVM whose guest sync is broken is not stopped by
// DefenseClaw: the feed names it once however often reconcile looks again,
// and never says a stop lost its writes. A user's stop is held while the
// sync fails (GAP-1163): the VM keeps running with its work, and the
// refusal says how to save it first.
func TestALegacyMicroVMIsNamedOnceAndOnlyItsUsersStopEndsIt(t *testing.T) {
	e, b := legacyMicroVMWithBrokenSync(t, "kept")
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
	e.m.tamperStops.Wait()
	for range 3 {
		must(t, e.m.Reconcile(t.Context()))
		e.m.tamperStops.Wait()
	}
	if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
		t.Fatalf("stopped a legacy MicroVM on its own: %d stop calls", got-stops)
	}
	if got := e.events("kept", sandboxapi.ActivityLifecycle, "stop_unflushed"); len(got) != 0 {
		t.Fatalf("a stop nobody made was reported as one that lost writes: %+v", got)
	}
	if got := findingsSaying(e, "kept", "kept: "+legacyUnprotected); len(got) != 1 {
		t.Fatalf("the legacy MicroVM was not named exactly once over four looks: %+v", got)
	}

	// The user's stop while the sync fails is held: OpenShell is not
	// asked, and nothing was lost.
	_, err := e.m.Stop(t.Context(), "kept")
	if !sandboxapi.IsCode(err, sandboxapi.CodeConflict) || !strings.Contains(err.Error(), "keeps running") ||
		!strings.Contains(err.Error(), "defenseclaw sandbox pull kept") {
		t.Fatalf("the user's stop with a broken sync = %v", err)
	}
	if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
		t.Fatalf("a held stop called OpenShell's stop: %d calls", got-stops)
	}
	if got := e.events("kept", sandboxapi.ActivityLifecycle, "stop_unflushed"); len(got) != 0 {
		t.Fatalf("a held stop was reported as one that lost writes: %+v", got)
	}
}

// lateWriterGuest is a legacy MicroVM's guest in which a process starts
// after the stop's exec has looked at the guest and synced (an exec
// OpenShell let in while the VM was ready, for one), and writes: a stop
// OpenShell takes then, which 0.1.3 makes without a flush, loses that
// write, whatever the exec answered. failHarnessExec fails the harness's
// exit exec, so a stop flushes on its own.
type lateWriterGuest struct {
	mu              sync.Mutex
	failHarnessExec bool
	flushes         int
}

func (g *lateWriterGuest) exec(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
	g.mu.Lock()
	defer g.mu.Unlock()
	cmd := call.Command
	switch {
	case len(cmd) == 1 && cmd[0] == "/bin/sync":
		g.flushes++
	case len(cmd) >= 4 && cmd[0] == "/bin/sh" && cmd[3] == "defenseclaw-end-harness":
		if g.failHarnessExec {
			return openshelltest.ExecResponse{Err: errors.New("exec relay closed")}
		}
		g.flushes++
		return openshelltest.ExecResponse{Stdout: []byte("exited\nsynced\n")}
	case len(cmd) >= 4 && cmd[0] == "/bin/sh" && cmd[3] == "defenseclaw-flush":
		g.flushes++
		return openshelltest.ExecResponse{Stdout: []byte("synced\n")}
	}
	return openshelltest.ExecResponse{}
}

// legacyMicroVMWithALateWriter is a ready 0.1.3 MicroVM named name, with a
// direct network rule, whose guest is g; edit changes the daemon's
// configuration. Its record is saved, so a restarted daemon finds it.
func legacyMicroVMWithALateWriter(t *testing.T, name string, g *lateWriterGuest, edit func(*config.Config)) (*harnessEnv, *box) {
	t.Helper()
	e := newVMEnv(t, edit)
	e.create(sandboxapi.CreateRequest{Name: name, Copy: true})
	e.addNetworkRule(name, "direct", "background.example.org", 443)
	b := e.boxOf(name)
	e.m.mu.Lock()
	b.rec.SessionRelease = "0.1.3"
	e.m.mu.Unlock()
	must(t, e.m.saveRecord(b))
	e.fake.HandleExec(e.workloadChecks(nil, g.exec))
	return e, b
}

// No automatic stop of a legacy MicroVM can lose a guest write silently:
// whatever the stop's exec can prove about the guest (its disk synced), a
// process an exec starts after it still writes before 0.1.3 stops the VM
// without a flush. So DefenseClaw stops no such VM itself, whichever way
// the flush would go (the harness's exit exec, the flush on its own after
// that exec failed, a sandbox with no known harness) and after a daemon
// restart too; the user's own stop, which the feed told them may lose
// unsynced writes, flushes first and goes ahead.
func TestNoAutomaticStopOfALegacyMicroVM(t *testing.T) {
	for _, tc := range []struct {
		name              string
		failExec, unknown bool
		restart           bool
	}{
		{name: "the harness exits and the guest syncs"},
		{name: "harness exec failed, flush on its own", failExec: true},
		{name: "no known harness", unknown: true},
		{name: "after a daemon restart", restart: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &lateWriterGuest{failHarnessExec: tc.failExec}
			e, b := legacyMicroVMWithALateWriter(t, "busy", g, nil)
			if tc.unknown {
				e.m.mu.Lock()
				b.rec.Harness = "retired-agent"
				e.m.mu.Unlock()
				must(t, e.m.saveRecord(b))
			}
			stops := e.fake.Calls(openshelltest.MethodStopSandbox)
			if tc.restart {
				e.restartDaemon()
				b = e.boxOf("busy")
			} else {
				e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
			}
			e.m.tamperStops.Wait()
			for range 2 {
				must(t, e.m.Reconcile(t.Context()))
				e.m.tamperStops.Wait()
			}
			if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
				t.Fatal("DefenseClaw stopped a legacy MicroVM on its own, while a process an exec started after its flush could still write")
			}
			if got := e.get("busy"); got.Phase != "ready" || !got.OldSupervisor {
				t.Fatalf("the legacy VM was not kept: %+v", got)
			}
			e.m.mu.Lock()
			withdrawn := b.rec.OldSupervisorNetworkClosed
			e.m.mu.Unlock()
			if !withdrawn || e.hasRule("busy", "direct") {
				t.Fatalf("DefenseClaw's rules of the legacy VM are still in place: %+v", b.rec)
			}
			if got := findingsSaying(e, "busy", "busy: "+legacyUnprotected); len(got) != 1 {
				t.Fatalf("the legacy VM was not named once: %+v", e.events("busy", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor))
			}
			e.stopBox("busy")
			if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops+1 || e.get("busy").Phase != "stopped" {
				t.Fatalf("the user's stop: %d stop calls, phase %s", got-stops, e.get("busy").Phase)
			}
			g.mu.Lock()
			flushes := g.flushes
			g.mu.Unlock()
			if flushes == 0 {
				t.Fatal("the user's stop of a MicroVM did not flush first")
			}
		})
	}
}

// A withdrawal of a legacy MicroVM's rules can remove every network rule
// and then fail to confirm it (OpenShell does not report the policy
// loaded) on a sandbox with no provider whose detach would be recorded, so
// the withdrawn-rules checkpoint is never reached. The record said before
// the first change that the next session must get its create-time network
// back, so the start after the user's stop restores it before the session
// counts as ready, across a daemon restart too.
func TestAWithdrawalCutShortStillRestoresTheNextSessionsNetwork(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(map[bool]string{false: "same daemon", true: "after a daemon restart"}[restart], func(t *testing.T) {
			// token_delivery env: no provider, so no detached provider can
			// stand in for the record of what to restore.
			e, b := legacyMicroVMWithALateWriter(t, "cut", &lateWriterGuest{}, func(c *config.Config) { c.OpenShell.TokenDelivery = config.OpenShellTokenDeliveryEnv })
			if len(b.rec.Providers) != 0 {
				t.Fatalf("precondition: a sandbox without providers; got %v", b.rec.Providers)
			}
			// The fake answers a global-policy read as a policy status too:
			// only the status after the rules were removed fails.
			var failStatus, merged atomic.Bool
			failStatus.Store(true)
			e.fake.Intercept(func(method string) error {
				if method == openshelltest.MethodUpdateConfig {
					merged.Store(true)
				}
				if method == openshelltest.MethodPolicyStatus && merged.Load() && failStatus.Load() {
					return &types.StatusError{Code: types.ErrorInternal, Message: "policy status unavailable"}
				}
				return nil
			})
			e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
			e.m.tamperStops.Wait()
			if got := e.get("cut"); got.Phase != "ready" || b.rec.OldSupervisorNetworkClosed || !b.rec.OldSupervisorNetworkRestore || e.hasRule("cut", "defenseclaw_egress") {
				t.Fatalf("precondition: a kept VM whose rules were removed unconfirmed; got %s, %+v", got.Phase, b.rec)
			}
			failStatus.Store(false)
			e.stopBox("cut")
			if restart {
				e.restartDaemon()
			}
			e.startBox("cut", sandboxapi.StartRequest{})
			if !e.hasRule("cut", "defenseclaw_egress") {
				t.Fatal("the next session started without its create-time network rules")
			}
			nb := e.boxOf("cut")
			e.m.mu.Lock()
			rec, phase := nb.rec, nb.phase
			e.m.mu.Unlock()
			if phase != audit.SandboxPhaseReady || rec.OldSupervisorNetworkRestore || rec.OldSupervisorNetworkClosed {
				t.Fatalf("restored session = %s, %+v", phase, rec)
			}
		})
	}
}
