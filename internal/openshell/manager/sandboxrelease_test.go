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
	"slices"
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

// A 0.1.3 MicroVM does not flush on stop, so DefenseClaw does not stop a
// ready one itself while its network is closed, however its guest sync
// went: it keeps the VM contained, says so once however often reconcile
// looks again, and the user's own stop ends it. The next session restores
// its create-time network.
func TestLegacyMicroVMIsKeptContainedUntilTheUsersStop(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer openshelltest.ExecResponse
	}{
		{"guest synced", openshelltest.ExecResponse{Stdout: []byte("exited\nsynced\n")}},
		{"no sync confirmation", openshelltest.ExecResponse{Stdout: []byte("exited\n")}},
		{"sync exec failed", openshelltest.ExecResponse{Err: errors.New("sync failed")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newVMEnv(t, nil)
			e.create(sandboxapi.CreateRequest{Name: "kept", Copy: true})
			e.addNetworkRule("kept", "direct", "background.example.org", 443)
			b := e.boxOf("kept")
			e.m.mu.Lock()
			b.rec.SessionRelease = "0.1.3"
			e.m.mu.Unlock()
			e.fake.HandleExec(e.workloadChecks(nil, func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
				if len(call.Command) > 0 && call.Command[0] == "/bin/sync" {
					return openshelltest.ExecResponse{Err: errors.New("sync failed")}
				}
				return tc.answer
			}))
			stops := e.fake.Calls(openshelltest.MethodStopSandbox)
			e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
			e.m.tamperStops.Wait()
			for range 2 {
				must(t, e.m.Reconcile(t.Context()))
				e.m.tamperStops.Wait()
			}
			if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
				t.Fatalf("stopped a contained legacy MicroVM by itself: %d stop calls", got-stops)
			}
			if got := e.get("kept"); got.Phase != "ready" || !got.OldSupervisor {
				t.Fatalf("legacy MicroVM was not retained: %+v", got)
			}
			if e.hasRule("kept", "direct") || !b.rec.OldSupervisorNetworkClosed {
				t.Fatalf("legacy MicroVM still has network access: %+v", b.rec)
			}
			if found := findingsSaying(e, "kept", "DefenseClaw kept kept's legacy MicroVM"); len(found) != 1 || found[0].Severity != "HIGH" ||
				!strings.Contains(found[0].Message, "explicitly run `defenseclaw sandbox stop kept`") ||
				!strings.Contains(found[0].Message, "may lose unsynced writes") {
				t.Fatalf("no single loss-aware keep decision: %+v", e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor))
			}
			if got := e.events("kept", sandboxapi.ActivityLifecycle, "stop_unflushed"); len(got) != 0 {
				t.Fatalf("a VM that was not stopped was reported as an unflushed stop: %+v", got)
			}
			// The user's stop ends it; the next session restores only its
			// create-time policy.
			e.stopBox("kept")
			if got := e.get("kept"); got.Phase != "stopped" || got.OldSupervisor {
				t.Fatalf("the explicit stop did not stop the old session: %+v", got)
			}
			e.startBox("kept", sandboxapi.StartRequest{})
			if !e.hasRule("kept", "defenseclaw_egress") || e.hasRule("kept", "direct") || b.rec.OldSupervisorNetworkClosed {
				t.Fatalf("new session did not restore its create-time network: %+v", b.rec)
			}
		})
	}
}

// TestAHostLeftOnAnOlderOpenShellUpgradesInPlace: DefenseClaw 1.0.0 to
// 1.0.3 left hosts on OpenShell 0.1.1 to 0.1.3, whose network broker can let
// a sandbox's connections bypass its policy (NVIDIA/OpenShell#4494). The
// daemon still connects to such a gateway and drives the sandboxes there
// (status, stop), so their work is kept, but creates and starts none,
// naming the in-place upgrade. A sandbox whose session runs that release's
// supervisor is stopped (GAP-0415) and starts again on the upgraded gateway
// only.
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
	if n := len(oldSupervisor()); n != 0 || slices.Contains(e.get("kept").Warnings, oldSupervisorWarning) {
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
	// supervisor: DefenseClaw stops it (GAP-0415), keeping its work, and the
	// old gateway starts it no more.
	e.m.statusEvent(t.Context(), e.boxOf("kept"), &stream.Status{Phase: openshell.PhaseProvisioning})
	e.m.statusEvent(t.Context(), e.boxOf("kept"), &stream.Status{Phase: openshell.PhaseReady})
	e.m.tamperStops.Wait()
	found := oldSupervisor()
	if len(found) != 1 || found[0].Severity != "HIGH" || !strings.Contains(found[0].Message, "kept's session started on OpenShell 0.1.3") ||
		!strings.Contains(found[0].Message, "DefenseClaw closes a legacy MicroVM's network and keeps the VM until an explicit `defenseclaw sandbox stop kept`, which may lose unsynced writes (it stops the VM itself only if its network cannot be closed); upgrade OpenShell 0.1.3 to "+openshell.InstallerVersion) ||
		!strings.HasSuffix(found[0].Message, "then `defenseclaw sandbox start kept` starts it on that release's supervisor") {
		t.Fatalf("old-supervisor findings = %+v", found)
	}
	if got := e.get("kept"); got.Phase != "stopped" || got.OldSupervisor || slices.Contains(got.Warnings, oldSupervisorWarning) {
		t.Fatalf("a session on the 0.1.3 supervisor: phase %s, old supervisor %v, warnings %v", got.Phase, got.OldSupervisor, got.Warnings)
	}
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
	if slices.Contains(e.get("kept").Warnings, oldSupervisorWarning) || len(oldSupervisor()) != 1 {
		t.Fatalf("after the upgrade: warnings %v, findings %d", e.get("kept").Warnings, len(oldSupervisor()))
	}
}

// A record from before DefenseClaw kept the session's release names no
// release, and the managed way on is the administrator's.
func TestOldSupervisorWordsForARecordWithoutARelease(t *testing.T) {
	msg := oldSupervisorMessage("box", "", "")
	if !strings.Contains(msg, "box's session started before DefenseClaw kept the OpenShell release a session starts on, so it may run a supervisor older than "+openshell.SupportedMin) ||
		!strings.HasSuffix(msg, "DefenseClaw closes a legacy MicroVM's network and keeps the VM until an explicit `defenseclaw sandbox stop box`, which may lose unsynced writes (it stops the VM itself only if its network cannot be closed); `defenseclaw sandbox start box` (or `connect`) starts it again on this gateway's supervisor") {
		t.Fatalf("message = %q", msg)
	}
	e := newEnv(t, nil)
	if got := e.m.upgradeWayOn(openshell.SupportedMin); got != "" {
		t.Fatalf("upgrade way on %s = %q", openshell.SupportedMin, got)
	}
	if got := e.m.upgradeWayOn("dev"); got != "" {
		t.Fatalf("upgrade way on an unreadable release = %q", got)
	}
}

// TestAnOldSupervisorIsStoppedBeforeAnySandboxRunsOnIt (GAP-0415): a session
// that began on the supervisor of an OpenShell older than SupportedMin, or
// one a 1.0.3 record names no release for, keeps that supervisor's network
// broker, which can let its connections bypass its policy, for as long as it
// runs, whatever the gateway runs now. DefenseClaw stops it as soon as it
// sees it, also on an upgraded gateway and for a restarted daemon, and the
// next start runs the gateway's own supervisor. A stop that fails keeps the
// session's release, says so, names it in the view for the CLI, and is tried again on each
// reconcile until the session stops.
func TestAnOldSupervisorIsStoppedBeforeAnySandboxRunsOnIt(t *testing.T) {
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
	sight := func(release string) {
		t.Helper()
		b := e.boxOf("kept")
		e.m.mu.Lock()
		b.rec.SessionRelease = release
		e.m.mu.Unlock()
		// The daemon restarted on 1.0.4 republishes what it finds.
		e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
		e.m.tamperStops.Wait()
	}
	finding := func(text string) int {
		n := 0
		for _, ev := range e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor) {
			if strings.Contains(ev.Message, text) {
				n++
			}
		}
		return n
	}

	// A record 1.0.3 wrote names no release: the session is stopped on the
	// upgraded gateway, and its start runs that gateway's supervisor.
	sight("")
	if got := e.get("kept"); got.Phase != "stopped" || got.OldSupervisor {
		t.Fatalf("a 1.0.3 session on a %s gateway: phase %s, old supervisor %v", openshell.SupportedMin, got.Phase, got.OldSupervisor)
	}
	if finding("kept's session started before DefenseClaw kept the OpenShell release") != 1 ||
		finding("`defenseclaw sandbox start kept` (or `connect`) starts it again on this gateway's supervisor") != 1 {
		t.Fatalf("findings = %+v", e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor))
	}
	e.startBox("kept", sandboxapi.StartRequest{})
	e.m.tamperStops.Wait()
	if got := e.get("kept"); got.Phase != "ready" || got.OldSupervisor || e.boxOf("kept").rec.SessionRelease != openshell.SupportedMin {
		t.Fatalf("after the start: phase %s, old supervisor %v, release %q", got.Phase, got.OldSupervisor, e.boxOf("kept").rec.SessionRelease)
	}

	// A session on 0.1.3 whose stop fails: it still runs on that supervisor,
	// which the failed stop does not mistake for a new session, the feed
	// says so, and the view names it.
	e.fake.FailNext(openshelltest.MethodStopSandbox, &types.StatusError{Code: types.ErrorInternal, Message: "the gateway is busy"})
	sight("0.1.3")
	got := e.get("kept")
	if got.Phase != "ready" || !got.OldSupervisor || !slices.Contains(got.Warnings, oldSupervisorWarning) || e.boxOf("kept").rec.SessionRelease != "0.1.3" {
		t.Fatalf("after a failed stop: phase %s, old supervisor %v, warnings %v, release %q", got.Phase, got.OldSupervisor, got.Warnings, e.boxOf("kept").rec.SessionRelease)
	}
	if finding("DefenseClaw could not stop kept, whose session still runs the supervisor of OpenShell 0.1.3") != 1 {
		t.Fatalf("findings = %+v", e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor))
	}
	// The daemon's next periodic reconcile, which forces no transition on a
	// sandbox still ready, tries the stop again, and it stops it.
	must(t, e.m.Reconcile(t.Context()))
	e.m.tamperStops.Wait()
	if got := e.get("kept"); got.Phase != "stopped" || got.OldSupervisor {
		t.Fatalf("the next reconcile: phase %s, old supervisor %v", got.Phase, got.OldSupervisor)
	}

	// A session on the gateway's own supervisor is left running.
	e.startBox("kept", sandboxapi.StartRequest{})
	sight(openshell.SupportedMin)
	if got := e.get("kept"); got.Phase != "ready" || got.OldSupervisor {
		t.Fatalf("a session on %s: phase %s, old supervisor %v", openshell.SupportedMin, got.Phase, got.OldSupervisor)
	}
}

// legacyMicroVMWithBrokenSync is a ready 0.1.3 MicroVM named name with a
// direct network rule, whose guest sync(1) fails.
func legacyMicroVMWithBrokenSync(t *testing.T, name string) (*harnessEnv, *box) {
	t.Helper()
	e := newVMEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: name, Copy: true})
	e.addNetworkRule(name, "direct", "background.example.org", 443)
	b := e.boxOf(name)
	e.m.mu.Lock()
	b.rec.SessionRelease = "0.1.3"
	e.m.mu.Unlock()
	e.fake.HandleExec(e.workloadChecks(nil, func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		if len(call.Command) > 0 && call.Command[0] == "/bin/sync" {
			return openshelltest.ExecResponse{Err: errors.New("sync failed")}
		}
		return openshelltest.ExecResponse{Stdout: []byte("exited\n")}
	}))
	return e, b
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

// A ready legacy MicroVM is kept only while its network is proven closed.
// When its containment fails (a gateway-global policy, under which
// DefenseClaw cannot change the sandbox's rules; OpenShell refusing the
// policy update; a refusal that only comes after the first containment
// succeeded), the automatic stop goes ahead and the feed says what that may
// have lost, whether the guest's sync went through or not (what the guest
// writes after it is not flushed): a legacy supervisor never keeps running
// with open egress (fail closed).
func TestLegacyMicroVMWhoseNetworkStaysOpenIsStoppedWithoutAFlush(t *testing.T) {
	refuseUpdates := func(e *harnessEnv) {
		e.fake.Intercept(func(method string) error {
			if method == openshelltest.MethodUpdateConfig {
				return &types.StatusError{Code: types.ErrorConflict, Message: "policy update refused"}
			}
			return nil
		})
	}
	for _, tc := range []struct {
		name string
		// before breaks containment before the session is seen ready;
		// later, when set, only after a first containment kept the VM.
		before, later func(e *harnessEnv)
		cause         string
		// syncs: the guest's sync works, so only the HIGH finding speaks
		// of a loss, not stop_unflushed.
		syncs bool
	}{
		{name: "gateway-global policy", before: func(e *harnessEnv) { e.fake.SetGlobalPolicy(&openshell.SandboxPolicy{Version: 1}) },
			cause: "gateway-global policy"},
		{name: "policy update refused", before: refuseUpdates, cause: "policy update refused"},
		{name: "global policy after the VM was kept", later: func(e *harnessEnv) { e.fake.SetGlobalPolicy(&openshell.SandboxPolicy{Version: 1}) },
			cause: "gateway-global policy"},
		{name: "gateway-global policy, guest synced", before: func(e *harnessEnv) { e.fake.SetGlobalPolicy(&openshell.SandboxPolicy{Version: 1}) },
			cause: "gateway-global policy", syncs: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, b := legacyMicroVMWithBrokenSync(t, "leaky")
			if tc.syncs {
				e.fake.HandleExec(e.workloadChecks(nil, func(context.Context, openshelltest.ExecCall) openshelltest.ExecResponse {
					return openshelltest.ExecResponse{Stdout: []byte("exited\nsynced\n")}
				}))
			}
			if tc.before != nil {
				tc.before(e)
			}
			stops := e.fake.Calls(openshelltest.MethodStopSandbox)
			e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
			e.m.tamperStops.Wait()
			if tc.later != nil {
				if got := e.get("leaky"); got.Phase != "ready" || !b.rec.OldSupervisorNetworkClosed {
					t.Fatalf("a contained VM was not kept first: %+v", got)
				}
				tc.later(e)
				must(t, e.m.Reconcile(t.Context()))
				e.m.tamperStops.Wait()
			}
			if got := e.fake.Calls(openshelltest.MethodStopSandbox); got == stops {
				t.Fatalf("a legacy MicroVM whose network could not be closed kept running: %+v", e.get("leaky"))
			}
			if got := e.get("leaky"); got.Phase != "stopped" {
				t.Fatalf("legacy MicroVM with an open network = %+v", got)
			}
			if got, want := len(e.events("leaky", sandboxapi.ActivityLifecycle, "stop_unflushed")), map[bool]int{false: 1, true: 0}[tc.syncs]; got != want {
				t.Fatalf("stop_unflushed reported %d times, want %d", got, want)
			}
			if got := findingsSaying(e, "leaky", "stopped leaky's legacy MicroVM because its network could not be closed"); len(got) != 1 ||
				!strings.Contains(got[0].Message, tc.cause) || got[0].Severity != "HIGH" {
				t.Fatalf("no loss-aware finding naming %q: %+v", tc.cause, got)
			}
			if tc.later == nil {
				if got := findingsSaying(e, "leaky", "DefenseClaw kept leaky's"); len(got) != 0 {
					t.Fatalf("said the VM was kept: %+v", got)
				}
			}
		})
	}
}

// A contained legacy MicroVM whose guest sync is broken is not stopped by
// DefenseClaw: the feed says once that the VM was kept, however often
// reconcile looks again, and never that a stop lost its writes. A manual
// stop that OpenShell refused lost nothing either; one it took says so.
func TestAnAbortedLegacyAutoStopSaysItKeptTheVMOnce(t *testing.T) {
	e, b := legacyMicroVMWithBrokenSync(t, "kept")
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
	e.m.tamperStops.Wait()
	for range 3 {
		must(t, e.m.Reconcile(t.Context()))
		e.m.tamperStops.Wait()
	}
	if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
		t.Fatalf("stopped an unflushed, contained MicroVM: %d stop calls", got-stops)
	}
	if got := e.events("kept", sandboxapi.ActivityLifecycle, "stop_unflushed"); len(got) != 0 {
		t.Fatalf("an aborted stop was reported as a stop that lost writes: %+v", got)
	}
	if got := findingsSaying(e, "kept", "DefenseClaw kept kept's legacy MicroVM"); len(got) != 1 {
		t.Fatalf("the kept VM was not reported exactly once over four attempts: %+v", got)
	}

	// The user accepts the loss: OpenShell refuses the first stop, which
	// lost nothing, and takes the second, which says what it may have lost.
	e.fake.FailNext(openshelltest.MethodStopSandbox, &types.StatusError{Code: types.ErrorInternal, Message: "stop refused"})
	if _, err := e.m.Stop(t.Context(), "kept"); err == nil {
		t.Fatal("the refused stop succeeded")
	}
	if got := e.events("kept", sandboxapi.ActivityLifecycle, "stop_unflushed"); len(got) != 0 {
		t.Fatalf("a refused stop was reported as one that lost writes: %+v", got)
	}
	e.stopBox("kept")
	if got := e.events("kept", sandboxapi.ActivityLifecycle, "stop_unflushed"); len(got) != 1 {
		t.Fatalf("the explicit unflushed stop was not reported once: %+v", got)
	}
}

// lateWriterGuest is a legacy MicroVM's guest in which a process starts
// after the stop's exec has looked at the guest, paused what it found and
// synced (an exec OpenShell let in while the VM was ready, for one), and
// writes: a stop OpenShell takes then, which 0.1.3 makes without a flush,
// loses that write, whatever the exec answered. failHarnessExec fails the
// harness's exit exec, so a stop flushes on its own.
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
		return openshelltest.ExecResponse{Stdout: []byte("exited\nquiesced\nsynced\n")}
	case len(cmd) >= 4 && cmd[0] == "/bin/sh" && cmd[3] == "defenseclaw-flush":
		g.flushes++
		return openshelltest.ExecResponse{Stdout: []byte("quiesced\nsynced\n")}
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

// No automatic stop of a contained legacy MicroVM can lose a guest write
// silently: whatever the stop's exec can prove about the guest (its
// processes paused, its disk synced), a process an exec starts after it
// still writes before 0.1.3 stops the VM without a flush. So DefenseClaw
// stops no such VM itself while its network is closed, whichever way the
// flush would go (the harness's exit exec, the flush on its own after that
// exec failed, a sandbox with no known harness) and after a daemon restart
// too; the user's own stop, which the feed told them may lose unsynced
// writes, goes ahead.
func TestNoAutomaticStopOfAContainedLegacyMicroVM(t *testing.T) {
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
				t.Fatal("the automatic stop took the VM down while a process an exec started after its flush could still write")
			}
			if got := e.get("busy"); got.Phase != "ready" || !got.OldSupervisor {
				t.Fatalf("the contained VM was not kept: %+v", got)
			}
			e.m.mu.Lock()
			closed := b.rec.OldSupervisorNetworkClosed
			e.m.mu.Unlock()
			if !closed || e.hasRule("busy", "direct") {
				t.Fatalf("the kept VM's network is open: %+v", b.rec)
			}
			if got := findingsSaying(e, "busy", "DefenseClaw kept busy's legacy MicroVM"); len(got) != 1 {
				t.Fatalf("the kept VM was not reported once: %+v", e.events("busy", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor))
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

// A containment of a legacy MicroVM can remove every network rule and then
// fail to confirm it (OpenShell does not report the closed policy loaded)
// on a sandbox with no provider whose detach would be recorded,
// so the closed-network checkpoint is never reached, and the automatic
// stop of a VM whose network is not proven closed goes ahead. The record said before
// the first change that the next session must get its create-time network
// back, so the next start restores it before the session counts as ready,
// across a daemon restart too.
func TestAContainmentCutShortStillRestoresTheNextSessionsNetwork(t *testing.T) {
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
			if got := e.get("cut"); got.Phase != "stopped" || b.rec.OldSupervisorNetworkClosed || e.hasRule("cut", "defenseclaw_egress") {
				t.Fatalf("precondition: a stopped VM whose containment removed its rules unconfirmed; got %s, %+v", got.Phase, b.rec)
			}
			failStatus.Store(false)
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
