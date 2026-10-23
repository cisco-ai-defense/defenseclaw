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

package openshell_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

// TestHoldsGateway: only OpenShell's own state releases a MicroVM for a
// stop of its gateway: stopped, deleting, or the error state with its VM
// process gone. The rounds before let a MicroVM whose workload ended go
// after two minutes, then on its user's stop, which OpenShell does not
// make for it: what its workload left running may still write. Every
// other phase holds, completed and every other error state included (a
// failed main process, an unpolled VM, a provisioning that timed out, a
// failed image, no reason), and so do an unknown phase and one this build
// does not name. On docker an ended sandbox holds nothing: an exited
// container keeps its writes.
func TestHoldsGateway(t *testing.T) {
	for _, tc := range []struct {
		phase  openshell.SandboxPhase
		said   string
		vm     bool
		docker bool
	}{
		{openshell.PhaseReady, "", true, true},
		{openshell.PhaseProvisioning, "", true, true},
		{openshell.PhaseStarting, "", true, true},
		{openshell.PhaseStopping, "", true, true},
		{openshell.PhaseUnknown, "", true, true},
		{"Hibernating", "", true, true},
		{"", "", true, true},
		{openshell.PhaseCompleted, "", true, false},
		{openshell.PhaseCompleted, "MainProcessCompleted: Canonical main process exited", true, false},
		{openshell.PhaseError, "", true, false},
		{openshell.PhaseError, "MainProcessFailed: Canonical main process exited with status 1", true, false},
		{openshell.PhaseError, "ProcessPollFailed: Bad file descriptor", true, false},
		{openshell.PhaseError, "ImagePreparationFailed: no space left on device", true, false},
		{openshell.PhaseError, "ProvisioningTimedOut: Provisioning repair window expired after 300 seconds", true, false},
		{openshell.PhaseError, "ImagePreparationTimedOut: image preparation exceeded 600 seconds", true, false},
		{openshell.PhaseError, "MainProcessFailed: the VM process exited with status 1", true, false},
		{openshell.PhaseError, "ContainerExited: ProcessExited later", true, false},
		{openshell.PhaseError, "ProcessExited: VM process exited with status 1", false, false},
		{openshell.PhaseError, "ProcessExited: Canonical main process exited before VM driver restart", false, false},
		{openshell.PhaseError, "MainProcessFailed: exited 1; ProcessExited: host supervisor process exited", false, false},
		{openshell.PhaseError, "ProcessExited", false, false},
		{openshell.PhaseStopped, "", false, false},
		{openshell.PhaseDeleting, "", false, false},
	} {
		if got := openshell.HoldsGateway(tc.phase, tc.said, false); got != tc.vm {
			t.Errorf("HoldsGateway(%q, %q, MicroVM) = %v", tc.phase, tc.said, got)
		}
		if got := openshell.HoldsGateway(tc.phase, tc.said, true); got != tc.docker {
			t.Errorf("HoldsGateway(%q, %q, docker) = %v", tc.phase, tc.said, got)
		}
	}
	for said, gone := range map[string]bool{
		"ProcessExited": true, "ProcessExited: VM process exited": true, "MainProcessFailed: x; ProcessExited: y": true,
		"": false, "ProcessExitedLate": false, "ContainerExited: ProcessExited later": false, "MainProcessFailed: exited 1": false,
	} {
		if got := openshell.VMGone(said); got != gone {
			t.Errorf("VMGone(%q) = %v", said, got)
		}
	}
}

// TestStopWayOn: every refusal names the exact commands that bring the
// sandbox to a phase in which OpenShell reports it stopped. A ready one
// stops (OpenShell's stop flushes it); one in a passing phase is waited
// for. OpenShell returns its stop of a completed MicroVM, or of one whose
// main process failed, as it is, and refuses that of one whose
// provisioning timed out: for that one a start, then the stop of the ready
// sandbox, or a delete. For a completed or failed MicroVM the way on says
// what each costs: nothing in OpenShell writes its disk back, and the start
// (which needs --end-vm) ends the VM with no flush first, so what it has
// not written is lost; it never says the work is kept. Any other error
// state stops on a gateway that runs sandboxes.
// An older gateway neither stops nor starts an ended sandbox, and
// DefenseClaw starts none on it: a delete.
func TestStopWayOn(t *testing.T) {
	const (
		stop      = "`defenseclaw sandbox stop dc-x` (DefenseClaw sandbox), or `openshell sandbox stop dc-x` (raw OpenShell sandbox)"
		oldStop   = "`defenseclaw sandbox stop dc-x` (DefenseClaw sandbox), or save its work before `openshell sandbox stop dc-x` (raw OpenShell sandbox) on an older or unknown gateway release; raw stop may not flush the guest"
		startStop = "`defenseclaw sandbox start dc-x`, then `defenseclaw sandbox stop dc-x` once it is ready"
		del       = "`defenseclaw sandbox delete dc-x` (DefenseClaw sandbox) or `openshell sandbox delete dc-x` (raw OpenShell sandbox), which deletes it and its work"
		ended     = "nothing in OpenShell writes this MicroVM's disk back or stops it: its VM still runs what its workload left running, " +
			"and its start ends that VM with no flush first, so what the VM has not written to its disk is lost: " +
			"`defenseclaw sandbox start dc-x --end-vm` ends the VM that way, then `defenseclaw sandbox stop dc-x` once it is ready; or " + del
	)
	for _, tc := range []struct {
		phase openshell.SandboxPhase
		said  string
		runs  bool
		want  string
	}{
		{openshell.PhaseReady, "", true, stop},
		{openshell.PhaseReady, "", false, oldStop},
		{openshell.PhaseStarting, "", true, "wait until `openshell sandbox list` shows it ready or stopped, then " + stop + " if it is ready"},
		{openshell.PhaseUnknown, "", false, "wait until `openshell sandbox list` shows it ready or stopped, then " + oldStop + " if it is ready"},
		{openshell.PhaseCompleted, "", true, ended},
		{openshell.PhaseError, "MainProcessFailed: exited 1", true, ended},
		{openshell.PhaseError, "ProvisioningTimedOut: window expired", true, "wait a minute for OpenShell's cleanup of the provisioning that timed out, then " + startStop +
			" (OpenShell refuses to stop a sandbox whose provisioning timed out), or " + del},
		{openshell.PhaseError, "ProcessPollFailed: Bad file descriptor", true, stop},
		{openshell.PhaseError, "", true, stop},
		{openshell.PhaseCompleted, "", false, del + " (this OpenShell neither stops nor starts a completed MicroVM)"},
		{openshell.PhaseError, "MainProcessFailed: exited 1", false, del + " (this OpenShell neither stops nor starts a sandbox in its error state)"},
		{openshell.PhaseError, "", false, del + " (this OpenShell neither stops nor starts a sandbox in its error state)"},
	} {
		got := openshell.StopWayOn("dc-x", tc.phase, tc.said, tc.runs)
		if got != tc.want {
			t.Errorf("StopWayOn(%q, %q, runs %v) =\n  %s\nwant\n  %s", tc.phase, tc.said, tc.runs, got, tc.want)
		}
		// No way on presents a start of an ended MicroVM as one that keeps
		// its work.
		if strings.Contains(got, "start dc-x") && strings.Contains(got, "work is kept") || strings.Contains(got, "keeps its work") {
			t.Errorf("StopWayOn(%q, %q) says the work is kept: %s", tc.phase, tc.said, got)
		}
	}
}

// A raw OpenShell sandbox holds its gateway too, and DefenseClaw's
// commands refuse it ("no DefenseClaw sandbox named"): every way on names
// an OpenShell command that acts on it (GAP-0370, GAP-0623).
func TestRawMicroVMRestartAdviceNamesItsControlSurface(t *testing.T) {
	for _, p := range []openshell.SandboxPhase{openshell.PhaseReady, openshell.PhaseStarting, openshell.PhaseCompleted, openshell.PhaseError} {
		for _, said := range []string{"", "MainProcessFailed: exited 3", "ProvisioningTimedOut: window expired", "ProcessPollFailed: x"} {
			for _, runs := range []bool{true, false} {
				got := openshell.StopWayOn("raw-box", p, said, runs)
				if !strings.Contains(got, "`openshell sandbox stop raw-box`") && !strings.Contains(got, "`openshell sandbox delete raw-box`") {
					t.Errorf("raw MicroVM (%s, %q, runs %v) cannot follow the printed advice: %s", p, said, runs, got)
				}
			}
		}
	}
}

// OpenShell before 0.1.5 does not flush a raw MicroVM on stop. An unknown
// gateway release receives the same conservative advice as an older one.
func TestRawMicroVMRestartAdviceSavesWorkBeforeLegacyStop(t *testing.T) {
	for _, phase := range []openshell.SandboxPhase{openshell.PhaseReady, openshell.PhaseStarting, openshell.PhaseProvisioning, openshell.PhaseUnknown} {
		got := openshell.StopWayOn("raw-box", phase, "", false)
		if !strings.Contains(got, "`openshell sandbox stop raw-box`") ||
			!strings.Contains(got, "save its work before") || !strings.Contains(got, "older or unknown") {
			t.Errorf("legacy or unknown gateway, %s: unsafe raw stop advice: %s", phase, got)
		}
	}
}

// computeGateway is a gateway on driver d with a sandbox in each phase,
// conds giving the conditions of some.
func computeGateway(t *testing.T, d openshell.ComputeDriver, phases map[string]openshell.SandboxPhase, conds map[string]v1.SandboxCondition) (openshell.Client, *openshelltest.Fake) {
	t.Helper()
	f := openshelltest.New(openshelltest.WithDriver(d))
	f.SetRelease(openshell.SupportedMin)
	c := f.Client(openshell.ClientOptions{})
	for name, phase := range phases {
		if _, err := c.CreateSandbox(context.Background(), name, &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := f.SetPhase(openshell.DefaultWorkspace, name, phase); err != nil {
			t.Fatal(err)
		}
		if cond, ok := conds[name]; ok {
			setConditions(t, f, name, cond)
		}
	}
	return c, f
}

func setConditions(t *testing.T, f *openshelltest.Fake, name string, conds ...v1.SandboxCondition) {
	t.Helper()
	sb, err := f.Sandboxes().Get(context.Background(), openshell.DefaultWorkspace, name)
	if err != nil {
		t.Fatal(err)
	}
	sb.Status.Conditions = conds
	sb.ResourceVersion++
	f.SDK().AddSandbox(openshell.DefaultWorkspace, sb)
}

// execsIn names the sandboxes the fake was asked to run a command in.
func execsIn(f *openshelltest.Fake) []string {
	var out []string
	for _, c := range f.ExecCalls() {
		out = append(out, c.Sandbox)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

var (
	failedMain = v1.SandboxCondition{Type: "Ready", Status: "False", Reason: "MainProcessFailed", Message: "Canonical main process exited with status 1"}
	unpolled   = v1.SandboxCondition{Type: "Ready", Status: "False", Reason: "ProcessPollFailed", Message: "Bad file descriptor"}
	vmGone     = v1.SandboxCondition{Type: "Ready", Status: "False", Reason: "ProcessExited", Message: "VM process exited with status 1"}
	timedOut   = v1.SandboxCondition{Type: "Ready", Status: "False", Reason: "ProvisioningTimedOut", Message: "Provisioning repair window expired after 300 seconds"}
)

// The fake does what OpenShell does to a MicroVM whose workload ended: it
// runs no command in it (exec only in a ready sandbox), and its stop
// returns a completed one, or one whose main process failed, as it is.
func TestFakeLeavesAnEndedSandboxAsOpenShellDoes(t *testing.T) {
	c, f := computeGateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{
		"dc-done": openshell.PhaseCompleted, "dc-failed": openshell.PhaseError, "dc-starting": openshell.PhaseStarting, "dc-up": openshell.PhaseReady,
	}, nil)
	for _, name := range []string{"dc-done", "dc-failed", "dc-starting"} {
		if _, err := c.Exec(context.Background(), name, []string{"/bin/sync"}, openshell.ExecOptions{Attempts: 1}); err == nil || !strings.Contains(err.Error(), "sandbox is not ready") {
			t.Errorf("exec in %s: %v, want OpenShell's refusal", name, err)
		}
	}
	if _, err := c.Exec(context.Background(), "dc-up", []string{"/bin/sync"}, openshell.ExecOptions{Attempts: 1}); err != nil {
		t.Errorf("exec in a ready sandbox: %v", err)
	}
	sb, err := c.StopSandbox(context.Background(), "dc-done")
	if err != nil || sb.Status.Phase != openshell.PhaseCompleted {
		t.Fatalf("stop of a completed sandbox: %+v, %v", sb, err)
	}
	sb, err = f.Sandboxes().Get(context.Background(), openshell.DefaultWorkspace, "dc-failed")
	if err != nil {
		t.Fatal(err)
	}
	code := int32(1)
	sb.Status.ExitCode = &code
	sb.ResourceVersion++
	f.SDK().AddSandbox(openshell.DefaultWorkspace, sb)
	if sb, err = c.StopSandbox(context.Background(), "dc-failed"); err != nil || sb.Status.Phase != openshell.PhaseError {
		t.Fatalf("stop of a failed main process: %+v, %v", sb, err)
	}
}

// heldVariants are MicroVMs that OpenShell does not report stopped, each
// with what the refusal tells its user to run.
var heldVariants = []struct {
	name  string
	phase openshell.SandboxPhase
	cond  *v1.SandboxCondition
	way   string
}{
	{"ready", openshell.PhaseReady, nil, "dc-x (ready): `defenseclaw sandbox stop dc-x`"},
	{"starting", openshell.PhaseStarting, nil, "dc-x (starting): wait until"},
	{"provisioning", openshell.PhaseProvisioning, nil, "dc-x (provisioning): wait until"},
	{"stopping", openshell.PhaseStopping, nil, "dc-x (stopping): wait until"},
	{"unknown", openshell.PhaseUnknown, nil, "dc-x (unknown): wait until"},
	{"unnamed", "Hibernating", nil, "dc-x (hibernating): wait until"},
	{"completed", openshell.PhaseCompleted, nil, "dc-x (completed): nothing in OpenShell writes this MicroVM's disk back or stops it"},
	{"failed", openshell.PhaseError, &failedMain, "dc-x (error): nothing in OpenShell writes this MicroVM's disk back or stops it"},
	{"unpolled", openshell.PhaseError, &unpolled, "dc-x (error): `defenseclaw sandbox stop dc-x`"},
	{"timedout", openshell.PhaseError, &timedOut, "dc-x (error): wait a minute for OpenShell's cleanup"},
	{"imagefail", openshell.PhaseError, &v1.SandboxCondition{Type: "Ready", Status: "False", Reason: "ImagePreparationFailed", Message: "no space left on device"}, "dc-x (error): `defenseclaw sandbox stop dc-x`"},
	{"noreason", openshell.PhaseError, nil, "dc-x (error): `defenseclaw sandbox stop dc-x`"},
}

// heldGateway is a MicroVM gateway with the sandbox dc-x as v, plus a
// stopped one.
func heldGateway(t *testing.T, phase openshell.SandboxPhase, cond *v1.SandboxCondition) (openshell.Client, *openshelltest.Fake) {
	t.Helper()
	conds := map[string]v1.SandboxCondition{}
	if cond != nil {
		conds["dc-x"] = *cond
	}
	return computeGateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{"dc-x": phase, "dc-off": openshell.PhaseStopped}, conds)
}

// TestTheGatewayStopsOnlyOnceOpenShellReportsEveryMicroVMStopped: on the
// MicroVM driver the upgrade's gateway restart and every gateway restart
// DefenseClaw makes (doctor --fix, setup) stop every sandbox with no
// flush, so each is refused while OpenShell does not report a sandbox
// stopped: running, unknown and ended alike, each named with its way on,
// and nothing is stopped or run in any of them. A stop that OpenShell
// returns as it is releases nothing. A MicroVM OpenShell reports stopped,
// deleting, or with its VM gone lets both go ahead; so does a gateway with
// no MicroVM. On docker none of this applies.
func TestTheGatewayStopsOnlyOnceOpenShellReportsEveryMicroVMStopped(t *testing.T) {
	pull := func(context.Context) error { return nil }
	gates := []struct {
		name string
		base error
		run  func(openshell.Client) error
	}{
		{"upgrade", openshell.ErrSandboxesRunning, func(c openshell.Client) error {
			return openshell.PrepareUpgrade(context.Background(), c, pull, noMicroVMs)
		}},
		{"restart", openshell.ErrUnflushed, func(c openshell.Client) error {
			return openshell.CheckSandboxesStopped(context.Background(), c, noMicroVMs)
		}},
	}
	for _, g := range gates {
		for _, v := range heldVariants {
			c, f := heldGateway(t, v.phase, v.cond)
			err := g.run(c)
			if !errors.Is(err, g.base) || !strings.Contains(err.Error(), "OpenShell has not reported these stopped: "+v.way) || strings.Contains(err.Error(), "dc-off") {
				t.Errorf("%s under a MicroVM that is %s: %v", g.name, v.name, err)
			}
			if n := f.Calls(openshelltest.MethodStopSandbox); n != 0 || len(execsIn(f)) != 0 {
				t.Errorf("%s under a MicroVM that is %s: %d stops, commands in %v", g.name, v.name, n, execsIn(f))
			}
		}

		// OpenShell returns the stop of a completed MicroVM as it is: the
		// gate still refuses.
		c, _ := heldGateway(t, openshell.PhaseCompleted, nil)
		if sb, err := c.StopSandbox(context.Background(), "dc-x"); err != nil || sb.Status.Phase != openshell.PhaseCompleted {
			t.Fatalf("stop of a completed MicroVM: %+v, %v", sb, err)
		}
		if err := g.run(c); !errors.Is(err, g.base) {
			t.Errorf("%s after a stop OpenShell did not make: %v", g.name, err)
		}

		// Confirmed stopped by OpenShell's own state.
		for _, ok := range []struct {
			phase openshell.SandboxPhase
			cond  *v1.SandboxCondition
		}{{openshell.PhaseStopped, nil}, {openshell.PhaseDeleting, nil}, {openshell.PhaseError, &vmGone}} {
			c, f := heldGateway(t, ok.phase, ok.cond)
			if err := g.run(c); err != nil || len(execsIn(f)) != 0 || f.Calls(openshelltest.MethodStopSandbox) != 0 {
				t.Errorf("%s with dc-x %s (%v): %v", g.name, ok.phase, ok.cond, err)
			}
		}
	}

	// A gateway older than the release that runs sandboxes: an ended one
	// can only be deleted, a ready one still stops.
	c, f := heldGateway(t, openshell.PhaseCompleted, nil)
	f.SetRelease("0.1.3")
	if err := openshell.PrepareUpgrade(context.Background(), c, pull, noMicroVMs); !errors.Is(err, openshell.ErrSandboxesRunning) ||
		!strings.Contains(err.Error(), "dc-x (completed): `defenseclaw sandbox delete dc-x` (DefenseClaw sandbox) or `openshell sandbox delete dc-x` (raw OpenShell sandbox), which deletes it and its work (this OpenShell neither stops nor starts a completed MicroVM)") {
		t.Errorf("upgrade from 0.1.3 under a completed MicroVM: %v", err)
	}

	// Docker keeps its sandboxes through the restart.
	pulls := 0
	c, f = computeGateway(t, openshell.DriverDocker, map[string]openshell.SandboxPhase{"dc-done": openshell.PhaseCompleted, "dc-x": openshell.PhaseStarting}, nil)
	if err := openshell.PrepareUpgrade(context.Background(), c, func(context.Context) error { pulls++; return nil }, noMicroVMs); err != nil || pulls != 1 || len(execsIn(f)) != 0 {
		t.Fatalf("docker upgrade: %v, pulled %d, ran in %v", err, pulls, execsIn(f))
	}
	if err := openshell.CheckSandboxesStopped(context.Background(), c, noMicroVMs); err != nil || f.Calls(openshelltest.MethodStopSandbox) != 0 {
		t.Fatalf("docker restart: %v", err)
	}
}

// TestLifecycleLock: a restart or an upgrade holds the lock exclusively,
// and a create or a start shares it: one is refused at once while the
// other holds it, the exclusive one waits for the shared ones up to its
// bound or its context, and either goes once the other let go. The lock
// file is the owner's only, in a configuration directory the exclusive
// one makes; a start where none exists holds nothing.
func TestLifecycleLock(t *testing.T) {
	skipOnWindows(t)
	openshell.SetLifecycleLockWait(t, 300*time.Millisecond)
	dir := filepath.Join(t.TempDir(), "openshell")
	none, err := openshell.LockSandboxStart(dir)
	if err != nil {
		t.Fatal(err)
	}
	none()
	if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a start made the configuration directory: %v", err)
	}

	restart, err := openshell.LockGatewayLifecycle(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(dir, ".defenseclaw-lifecycle.lock")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("lock file: %v, %v", info, err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("configuration directory: %v, %v", info, err)
	}
	if _, err := openshell.LockSandboxStart(dir); !errors.Is(err, openshell.ErrGatewayBusy) {
		t.Fatalf("a start during a restart: %v", err)
	}
	if _, err := openshell.LockGatewayLifecycle(context.Background(), dir); !errors.Is(err, openshell.ErrGatewayBusy) {
		t.Fatalf("a second restart: %v", err)
	}
	restart()

	a, err := openshell.LockSandboxStart(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := openshell.LockSandboxStart(dir)
	if err != nil {
		t.Fatalf("two starts at once: %v", err)
	}
	if _, err := openshell.LockGatewayLifecycle(context.Background(), dir); !errors.Is(err, openshell.ErrGatewayBusy) {
		t.Fatalf("a restart under starts held past the wait: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := openshell.LockGatewayLifecycle(ctx, dir); !errors.Is(err, context.Canceled) {
		t.Fatalf("a restart whose context ended: %v", err)
	}
	a()
	go func() { time.Sleep(50 * time.Millisecond); b() }()
	restart, err = openshell.LockGatewayLifecycle(context.Background(), dir)
	if err != nil {
		t.Fatalf("a restart once the starts ended: %v", err)
	}
	restart()
}

// A sandbox attach, stop or delete holds the account's lifecycle lock
// shared (LockGatewayShared): it waits for a restart or a rollback that
// holds it, gets it once that is done, shares it with the others and with
// creates and starts, keeps a restart out while it holds it, and gives up
// with ErrGatewayBusy after the bounded wait.
func TestSandboxCommandWaitsForGatewayRollbackLock(t *testing.T) {
	dir := t.TempDir()
	unlock, err := openshell.LockGatewayLifecycle(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	var held func()
	go func() {
		u, err := openshell.LockGatewayShared(context.Background(), dir)
		held = u
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("sandbox command crossed the rollback lock: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sandbox command did not resume after rollback")
	}
	start, err := openshell.LockSandboxStart(dir)
	if err != nil {
		t.Fatalf("a start beside a held attach: %v", err)
	}
	start()
	openshell.SetLifecycleLockWait(t, 200*time.Millisecond)
	if _, err := openshell.LockGatewayLifecycle(context.Background(), dir); !errors.Is(err, openshell.ErrGatewayBusy) {
		t.Fatalf("a restart while an attach holds the lock: %v", err)
	}
	held()
	unlock, err = openshell.LockGatewayLifecycle(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := openshell.LockGatewayShared(context.Background(), dir); !errors.Is(err, openshell.ErrGatewayBusy) {
		t.Fatalf("an attach after the bounded wait: %v, want ErrGatewayBusy", err)
	}
}

// TestAGatewayThatCannotBeReadHoldsItsMicroVMs: a gateway whose
// registration or mTLS broke, or that refuses both calls, still runs its
// MicroVMs, which the restart or the upgrade would end with no flush. The
// checks used to take it for down and let both go ahead. They now refuse,
// unless the account's processes show that no MicroVM runs (VMCount), and
// a count that fails refuses too. The lone fallback is that evidence:
// nothing else, and no timer, releases it.
func TestAGatewayThatCannotBeReadHoldsItsMicroVMs(t *testing.T) {
	pull := func(context.Context) error { return nil }
	one := func(context.Context) (int, error) { return 1, nil }
	cannot := func(context.Context) (int, error) { return 0, errors.New("ps: not found") }
	refused := &v1.StatusError{Code: v1.ErrorUnavailable, Message: "connection refused"}
	gates := []struct {
		name string
		base error
		run  func(openshell.Client, openshell.VMCount) error
	}{
		{"upgrade", openshell.ErrSandboxesRunning, func(c openshell.Client, vms openshell.VMCount) error {
			return openshell.PrepareUpgrade(context.Background(), c, pull, vms)
		}},
		{"restart", openshell.ErrUnflushed, func(c openshell.Client, vms openshell.VMCount) error {
			return openshell.CheckSandboxesStopped(context.Background(), c, vms)
		}},
	}
	for _, g := range gates {
		down := func() openshell.Client {
			c, f := heldGateway(t, openshell.PhaseReady, nil)
			f.FailNext(openshelltest.MethodGatewayInfo, refused)
			f.FailNext(openshelltest.MethodListSandboxes, refused)
			return c
		}
		for name, vms := range map[string]openshell.VMCount{"a live MicroVM": one, "no count": cannot, "nothing to count with": nil} {
			if err := g.run(down(), vms); !errors.Is(err, g.base) || !strings.Contains(err.Error(), "could not be read") ||
				!strings.Contains(err.Error(), "make the gateway answer DefenseClaw again") {
				t.Errorf("%s, gateway refuses both calls, %s: %v", g.name, name, err)
			}
		}
		if err := g.run(down(), one); !strings.Contains(err.Error(), "1 MicroVM run as this account, which the gateway's stop would end with no flush") {
			t.Errorf("%s: %v", g.name, err)
		}
		// Only the account's own processes release it.
		if err := g.run(down(), noMicroVMs); err != nil {
			t.Errorf("%s, gateway down and no MicroVM runs: %v", g.name, err)
		}
	}
}

// TestCountMicroVMs: each process of the account that runs a MicroVM
// (OpenShell's launcher, started with --internal-run-vm) counts; a ps that
// fails is an error, never a zero.
func TestCountMicroVMs(t *testing.T) {
	r := &openshelltest.Runner{}
	r.On("ps -ww -u", "/usr/libexec/openshell/openshell-driver-vm --internal-run-vm --vm-root-disk /x\n"+
		"/usr/bin/openshell-gateway --drivers vm\n"+
		"/opt/homebrew/libexec/openshell-driver-vm --internal-run-vm --vm-overlay-disk /y\n"+
		"grep internal-run-vm\n", nil)
	if n, err := openshell.CountMicroVMs(context.Background(), r); err != nil || n != 2 {
		t.Fatalf("CountMicroVMs = %d, %v, want 2", n, err)
	}
	r = &openshelltest.Runner{}
	r.On("ps -ww -u", "", nil)
	if n, err := openshell.CountMicroVMs(context.Background(), r); err != nil || n != 0 {
		t.Fatalf("no MicroVM: %d, %v", n, err)
	}
	r = &openshelltest.Runner{}
	r.On("ps -ww -u", "", errors.New("exec: ps: not found"))
	if _, err := openshell.CountMicroVMs(context.Background(), r); err == nil {
		t.Fatal("a ps that fails counted nothing")
	}
}

// noMicroVMs is a VMCount for a host on which no MicroVM runs as this
// account.
func noMicroVMs(context.Context) (int, error) { return 0, nil }

// TestCheckAccountGateways: the managed drain's check refuses while a
// MicroVM runs as the account, whatever started it and whether or not a
// gateway answers, and when the MicroVMs cannot be counted; a registered
// gateway that does not answer refuses only with a MicroVM running.
func TestCheckAccountGateways(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	one := func(context.Context) (int, error) { return 1, nil }
	cannot := func(context.Context) (int, error) { return 0, errors.New("ps failed") }
	check := func(vms openshell.VMCount) error { return openshell.CheckAccountGateways(context.Background(), vms) }
	if err := check(noMicroVMs); err != nil {
		t.Fatalf("nothing registered, nothing runs: %v", err)
	}
	for name, vms := range map[string]openshell.VMCount{"a live MicroVM": one, "no count": cannot} {
		if err := check(vms); !errors.Is(err, openshell.ErrUnflushed) {
			t.Fatalf("nothing registered, %s: %v", name, err)
		}
	}
	writeRegistration(t, filepath.Join(cfg, "openshell"), "openshell", nil, nil)
	if err := check(one); !errors.Is(err, openshell.ErrUnflushed) || !strings.Contains(err.Error(), "1 MicroVM") {
		t.Fatalf("a gateway that does not answer, a live MicroVM: %v", err)
	}
	if err := check(noMicroVMs); err != nil {
		t.Fatalf("a gateway that does not answer, nothing runs: %v", err)
	}
}
