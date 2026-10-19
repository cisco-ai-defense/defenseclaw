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

//go:build linux || darwin

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// rel-1-0-2:GAP-0462: after an rpm upgrade deferred the daemon's restart,
// `sandbox stop` of the last running sandbox failed with "wait ... to stop:
// context canceled (last poll: ... connection refused 127.0.0.1:17670)"
// although the sandbox stopped. Its phase left the running ones before
// OpenShell said it stopped, so the supervision stopped the account's
// OpenShell gateway and exited for the restart under the stop's wait. A
// stop or delete in flight now holds both off; the restart follows once it
// ends.
func TestSandboxDaemonDeferredRestartWaitsForAStop(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.run(t)
	ctx := context.Background()
	if err := os.WriteFile(f.exe, []byte("v2-upgraded"), 0o700); err != nil {
		t.Fatal(err)
	}
	f.running.Store(1)
	if stop, _ := f.d.check(ctx); stop || !f.d.pendingRestart.Load() {
		t.Fatal("the upgrade was not deferred while a sandbox runs")
	}
	f.os.holder.Store(int64(os.Getuid()))
	f.d.openShellUsed.Store(time.Now().Add(-2 * openShellGatewayLinger).UnixNano())

	// The sandbox is stopping: no longer counted as running, the stop still
	// waits on the gateway.
	f.running.Store(0)
	f.d.stops.Add(1)
	if stop, err := f.d.check(ctx); stop || err != nil {
		t.Fatalf("restarted under a stop in flight: %v %v", stop, err)
	}
	if n := f.os.stopped.Load(); n != 0 {
		t.Fatalf("stopped the account's gateway under a stop in flight (%d)", n)
	}
	f.d.stops.Add(-1)
	if stop, err := f.d.check(ctx); !stop || !errors.Is(err, ErrSandboxDaemonRestart) {
		t.Fatalf("after the stop: %v %v, want the deferred restart", stop, err)
	}
	if n := f.os.stopped.Load(); n != 1 {
		t.Fatalf("after the stop the idle gateway was stopped %d times", n)
	}
}

// Stop and delete hold the in-flight count for their whole call: here the
// readying of the account's gateway, which runs before the manager's stop
// or delete and its wait.
func TestSandboxDaemonStopAndDeleteCountAsInFlight(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.run(t)
	ctx := context.Background()
	var during []int64
	f.os.prepare = func(sandboxrelay.DaemonSettings) (bool, error) {
		during = append(during, f.d.stops.Load())
		return false, nil
	}
	ctl := &managedSandboxController{sandboxRuntimeController: f.d.rt.manager, d: f.d}
	_, _ = ctl.Stop(ctx, "kept1")
	_, _ = ctl.Delete(ctx, "kept1", sandboxapi.DeleteRequest{})
	if len(during) != 2 || during[0] != 1 || during[1] != 1 {
		t.Fatalf("in-flight count while the stop and the delete ran: %v, want [1 1]", during)
	}
	if n := f.d.stops.Load(); n != 0 {
		t.Fatalf("in-flight count after them: %d", n)
	}
}

// A stop that begins while the supervision check lists the sandboxes (its
// sandbox already stopping, so not counted) holds the release and the
// restart off too: the in-flight count read before the list alone left that
// window. A real stop runs concurrently with the check here.
func TestSandboxDaemonCheckWaitsForAStopBegunDuringTheList(t *testing.T) {
	var during func()
	f := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		o.countRunning = func(context.Context) (int, error) {
			if during != nil {
				during()
			}
			return 0, nil
		}
	})
	ctx := context.Background()
	if err := os.WriteFile(f.exe, []byte("v2-upgraded"), 0o700); err != nil {
		t.Fatal(err)
	}
	ctl := &managedSandboxController{sandboxRuntimeController: f.d.rt.manager, d: f.d}
	var once sync.Once
	stopped := make(chan struct{})
	during = func() {
		once.Do(func() {
			go func() {
				defer close(stopped)
				_, _ = ctl.Stop(ctx, "dc-stopping")
			}()
			// The stop has counted itself and now waits for the lifecycle
			// this check holds, to ready the account's gateway.
			deadline := time.Now().Add(5 * time.Second)
			for f.d.stops.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
		})
	}
	if stop, err := f.d.check(ctx); stop || err != nil {
		t.Fatalf("restarted under a stop begun during the list: %v %v", stop, err)
	}
	if !f.d.pendingRestart.Load() {
		t.Fatal("the upgrade was not noticed")
	}
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("the stop did not end")
	}
	if stop, err := f.d.check(ctx); !stop || !errors.Is(err, ErrSandboxDaemonRestart) {
		t.Fatalf("after the stop: %v %v, want the deferred restart", stop, err)
	}
}

// A stop whose wait failed (the gateway lost during a deferred restart:
// "context canceled ... connection refused 127.0.0.1:17670") reads the
// sandbox again, with its own bound since the stop's context may be what
// ended, and reports it stopped when OpenShell says so (GAP-0462).
func TestSandboxDaemonStopRechecksTheStateAfterAFailedWait(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.os.holder.Store(int64(os.Getuid()))
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	phase := "stopped"
	var asked []string
	get := func(ctx context.Context, name string) (*sandboxapi.Sandbox, error) {
		if err := ctx.Err(); err != nil {
			t.Fatalf("re-read on an ended context: %v", err)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("re-read without a bound")
		}
		asked = append(asked, name)
		return &sandboxapi.Sandbox{Name: name, Phase: phase}, nil
	}
	if sb := f.d.stoppedAfterFailedStop(canceled, "dc-a", get); sb == nil || sb.Phase != "stopped" {
		t.Fatalf("a stopped sandbox after a failed wait = %+v, want it stopped", sb)
	}
	for _, p := range []string{"stopping", "ready", "unknown"} {
		phase = p
		if sb := f.d.stoppedAfterFailedStop(canceled, "dc-a", get); sb != nil {
			t.Fatalf("phase %s reported stopped: %+v", p, sb)
		}
	}
	gone := func(context.Context, string) (*sandboxapi.Sandbox, error) {
		return nil, errors.New("connection refused")
	}
	if sb := f.d.stoppedAfterFailedStop(canceled, "dc-a", gone); sb != nil {
		t.Fatalf("an unreadable sandbox reported stopped: %+v", sb)
	}
	if len(asked) != 4 {
		t.Fatalf("re-reads = %v", asked)
	}
}

// The other half of GAP-0462: right after the restart, `sandbox status`
// said "your organization does not let you run sandboxes
// (openshell.admin.allowed)" and a strict, deny-all policy for a sandbox the
// organization allows: the closed start-up floor the manager judges with
// until a confirmed registration's floor is adopted. While the managed
// gateway does not answer, the status and list say the policy is being
// confirmed and show the policy the sandbox was created with; once it
// answers, the same status shows the organization's policy (not after the
// configuration check's next tick).
func TestSandboxDaemonStatusConfirmsAgainOnTheClosedFloor(t *testing.T) {
	created := map[string]any{"pack": "balanced", "profile": "balanced", "network_mode": "allowlist", "approvals": "triage"}
	f := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) { seedSandboxRecord(t, o.StateDir, "dc-a", created) })
	runPastRevalidate(t, f)
	ctx := context.Background()
	floor := config.OpenShellAdminConfig{MinProfile: "balanced", RequestAccess: "it-help@example.com"}
	// On file but not confirmed: the managed gateway did not answer at start.
	if err := f.d.regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", Floor: floor, UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if admin := f.d.config().OpenShell.Admin; admin.Allowed == nil || *admin.Allowed {
		t.Fatalf("the fixture does not start on the closed floor: %+v", admin)
	}
	// The configuration check's resolution on the closed floor: the deny the
	// evidence showed.
	f.d.rt.manager.RefreshPolicies()
	raw, err := f.d.rt.manager.Get(ctx, "dc-a")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(raw.Violations, closedFloorDeny) || raw.NetworkMode != "deny" || raw.Profile != "strict" {
		t.Fatalf("the closed floor's view is not the deny of the evidence: %+v %s/%s", raw.Violations, raw.Profile, raw.NetworkMode)
	}
	ctl := &managedSandboxController{sandboxRuntimeController: f.d.rt.manager, d: f.d}

	// Still no answer: the closed floor stays, and the views say the policy
	// is being confirmed instead of the deny.
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{}, errors.New("connect: connection refused")
	}
	sb, err := ctl.Get(ctx, "dc-a")
	if err != nil {
		t.Fatal(err)
	}
	list, err := ctl.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	for _, v := range []sandboxapi.Sandbox{*sb, list[0]} {
		if slices.ContainsFunc(v.Violations, func(x sandboxapi.Violation) bool { return x.Admin }) ||
			v.Profile != "balanced" || v.NetworkMode != "allowlist" || v.Approvals != "triage" {
			t.Fatalf("while confirming: %+v %s/%s/%s, want the created policy and no organization violation",
				v.Violations, v.Profile, v.NetworkMode, v.Approvals)
		}
		if !slices.Contains(v.Warnings, sandboxConfirmingNote) || slices.ContainsFunc(v.Warnings, func(w string) bool {
			return strings.Contains(w, "now runs under") || strings.Contains(w, "your organization disabled")
		}) {
			t.Fatalf("while confirming, warnings = %q", v.Warnings)
		}
	}
	if admin := f.d.config().OpenShell.Admin; admin.Allowed == nil || *admin.Allowed {
		t.Fatalf("adopted an unconfirmed registration's floor: %+v", admin)
	}

	// The managed gateway answers: the same status shows the
	// organization's policy at once.
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{V: 1, Generation: 3}, nil
	}
	sb, err = ctl.Get(ctx, "dc-a")
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(sb.Violations, func(x sandboxapi.Violation) bool { return x.Admin }) ||
		sb.Profile == "strict" || sb.NetworkMode == "deny" || slices.Contains(sb.Warnings, sandboxConfirmingNote) {
		t.Fatalf("after the confirmation: %+v %s/%s %q", sb.Violations, sb.Profile, sb.NetworkMode, sb.Warnings)
	}
	admin := f.d.config().OpenShell.Admin
	if admin.Allowed != nil || admin.MinProfile != "balanced" {
		t.Fatalf("status kept the closed floor after the registration was confirmed: %+v", admin)
	}
	if r, _ := f.d.regs.get("dc-a"); !r.Confirmed {
		t.Fatal("the registration was not confirmed")
	}

	// A list confirms too; a revoked registration's sandbox is stopped as at
	// start, on a bound of its own (not the status's ended context), and its
	// floor is never adopted.
	g := newSandboxDaemonFixture(t)
	runPastRevalidate(t, g)
	if err := g.d.regs.put(daemonRegistration{ID: "reg-2", Sandbox: "dc-b", Floor: floor, UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	g.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{V: 1, Revoked: true, RevokedReason: "profile removed"}, nil
	}
	gctl := &managedSandboxController{sandboxRuntimeController: g.d.rt.manager, d: g.d}
	_, _ = gctl.List(ctx)
	if r, _ := g.d.regs.get("dc-b"); !r.Revoked {
		t.Fatalf("the revoked registration was not marked: %+v", r)
	}
	if admin := g.d.config().OpenShell.Admin; admin.Allowed == nil || *admin.Allowed {
		t.Fatalf("adopted a revoked registration's floor: %+v", admin)
	}
}

// closedFloorDeny is the closed floor's "your organization does not let you
// run sandboxes" violation.
func closedFloorDeny(v sandboxapi.Violation) bool {
	return v.Admin && v.Constraint == "openshell.admin.allowed"
}

// seedSandboxRecord writes the manager's record of a sandbox created
// before the daemon's restart into its state dir, with the policy fields
// it was created with.
func seedSandboxRecord(t *testing.T, stateDir, name string, policy map[string]any) {
	t.Helper()
	rec := map[string]any{
		"version": 1, "name": name, "harness": "codex", "binding_id": "bind-" + name,
		"flags": map[string]any{"copy": true}, "workdir_mode": "copy", "workdir": "/sandbox/work",
		"created_at": time.Now().UTC(), "image": "defenseclaw/sandbox-codex:test", "registration_id": "reg-1",
	}
	maps.Copy(rec, policy)
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(stateDir, "sandboxes", "manager")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The managed gateway's answers in a closedFloorFixture.
const (
	relayDown int32 = iota
	relayAnswers
	relayRevokes
)

// closedFloorFixture is a daemon restarted while the managed gateway did not
// answer, with the stopped sandbox dc-a (created balanced, allowlist,
// triage) and its registration reg-1 on file: the manager judges against
// the closed start-up floor, and its view of dc-a is the deny of the
// evidence. relay is what the managed gateway's policy/current answers.
type closedFloorFixture struct {
	*sandboxDaemonFixture
	ctl   *managedSandboxController
	relay atomic.Int32
	// unlisted: the manager cannot list the sandboxes.
	unlisted atomic.Bool
}

// closedFloorRegFloor is reg-1's floor: the organization's, which allows
// dc-a's policy.
var closedFloorRegFloor = config.OpenShellAdminConfig{MinProfile: "balanced", RequestAccess: "it-help@example.com"}

// newClosedFloorFixture seeds dc-a and the other sandboxes named (each
// listed stopped by OpenShell; only dc-a has a registration) and runs the
// daemon past its start-up confirmation.
func newClosedFloorFixture(t *testing.T, others ...string) *closedFloorFixture {
	t.Helper()
	c := &closedFloorFixture{}
	created := map[string]any{"pack": "balanced", "profile": "balanced", "network_mode": "allowlist", "approvals": "triage"}
	names := append([]string{"dc-a"}, others...)
	f := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		for _, name := range names {
			seedSandboxRecord(t, o.StateDir, name, created)
		}
		o.listPhases = func(context.Context) (map[string]string, bool) {
			if c.unlisted.Load() {
				return nil, false
			}
			phases := make(map[string]string, len(names))
			for _, name := range names {
				phases[name] = "stopped"
			}
			return phases, true
		}
	})
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		switch c.relay.Load() {
		case relayAnswers:
			return sandboxrelay.CurrentPolicy{V: 1, Generation: 3}, nil
		case relayRevokes:
			return sandboxrelay.CurrentPolicy{V: 1, Revoked: true, RevokedReason: "profile removed"}, nil
		}
		return sandboxrelay.CurrentPolicy{}, errors.New("connect: connection refused")
	}
	if err := f.d.regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", Floor: closedFloorRegFloor, UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	c.sandboxDaemonFixture = f
	runPastRevalidate(t, f)
	c.ctl = &managedSandboxController{sandboxRuntimeController: f.d.rt.manager, d: f.d}
	if !f.d.floorClosed() {
		t.Fatal("the fixture's start-up confirmation adopted a floor")
	}
	if r, _ := f.d.regs.get("dc-a"); r.Confirmed {
		t.Fatal("the fixture's registration is confirmed at start")
	}
	// The configuration check's resolution on the closed floor.
	f.d.rt.manager.RefreshPolicies()
	raw, err := f.d.rt.manager.Get(context.Background(), "dc-a")
	if err != nil {
		t.Fatal(err)
	}
	assertClosedFloorDeny(t, "the closed floor's view", *raw)
	return c
}

// runPastRevalidate runs the daemon and waits for its start-up
// confirmation to end (the sandbox subsystem reports running after it), so
// a test's later relay answers are not the start-up's.
func runPastRevalidate(t *testing.T, f *sandboxDaemonFixture) {
	t.Helper()
	f.run(t)
	waitFor(t, "the daemon's start-up confirmation", func() bool {
		s := f.d.opts.Health.Snapshot().Sandbox
		return s != nil && s.State == StateRunning
	})
}

// assertClosedFloorDeny fails unless v is judged against the closed floor:
// "your organization does not let you run sandboxes", strict, deny.
func assertClosedFloorDeny(t *testing.T, what string, v sandboxapi.Sandbox) {
	t.Helper()
	if !slices.ContainsFunc(v.Violations, closedFloorDeny) || v.Profile != "strict" || v.NetworkMode != "deny" ||
		slices.Contains(v.Warnings, sandboxConfirmingNote) {
		t.Fatalf("%s: %+v %s/%s %q, want the closed floor's deny", what, v.Violations, v.Profile, v.NetworkMode, v.Warnings)
	}
}

// assertOrganizationPolicy fails unless v is judged against the
// registration's floor: no organization violation, no strict or deny-all
// policy, no confirming note.
func assertOrganizationPolicy(t *testing.T, what string, v sandboxapi.Sandbox) {
	t.Helper()
	if slices.ContainsFunc(v.Violations, func(x sandboxapi.Violation) bool { return x.Admin }) ||
		v.Profile == "strict" || v.NetworkMode == "deny" || slices.Contains(v.Warnings, sandboxConfirmingNote) {
		t.Fatalf("%s: %+v %s/%s %q, want the organization's policy", what, v.Violations, v.Profile, v.NetworkMode, v.Warnings)
	}
}

// statusAndList are the controller's status of name and its list entry.
func (c *closedFloorFixture) statusAndList(t *testing.T, name string) []sandboxapi.Sandbox {
	t.Helper()
	ctx := context.Background()
	sb, err := c.ctl.Get(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	list, err := c.ctl.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(list, func(v sandboxapi.Sandbox) bool { return v.Name == name })
	if i < 0 {
		t.Fatalf("list has no %s: %+v", name, list)
	}
	return []sandboxapi.Sandbox{*sb, list[i]}
}

// assertRegistrationFloor fails unless the manager's floor is reg-1's.
func (c *closedFloorFixture) assertRegistrationFloor(t *testing.T, what string) {
	t.Helper()
	if admin := c.d.config().OpenShell.Admin; c.d.floorClosed() || admin.Allowed != nil || admin.MinProfile != closedFloorRegFloor.MinProfile {
		t.Fatalf("%s: the manager's floor is %+v, want the confirmed registration's", what, admin)
	}
}

// assertClosed fails unless the manager still judges against the closed
// floor.
func (c *closedFloorFixture) assertClosed(t *testing.T, what string) {
	t.Helper()
	if admin := c.d.config().OpenShell.Admin; !c.d.floorClosed() || admin.Allowed == nil || *admin.Allowed || admin.MinProfile != "strict" {
		t.Fatalf("%s: the manager's floor is %+v, want the closed one", what, admin)
	}
}

// rel-1-0-2:GAP-0462 part 3 (verify r2, TST-2014): the managed gateway did
// not answer when the daemon started, so the floor stayed the closed one;
// the 60 s poll then confirmed the registration of a STOPPED sandbox, whose
// floor adoptRunningFloor skips (only a running sandbox's floor is adopted),
// and with no registration left unconfirmed neither the status's
// re-confirmation nor the confirming view applied: `sandbox status` and
// `list` said "your organization does not let you run sandboxes" (strict,
// deny) until a start or a restart. The poll now opens the closed floor with
// the newest confirmed registration's, as revalidate does at start, and
// re-resolves the views at once.
func TestSandboxDaemonPollOfAStoppedSandboxOpensTheClosedFloor(t *testing.T) {
	c := newClosedFloorFixture(t)
	c.relay.Store(relayAnswers)
	c.d.pollOnce(context.Background())
	if got := c.sandboxDaemonFixture.relay.reported(); !slices.Contains(got, "reg-1=stopped") {
		t.Fatalf("reports = %v, want the poll to report dc-a stopped", got)
	}
	if r, _ := c.d.regs.get("dc-a"); !r.Confirmed || r.Revoked {
		t.Fatalf("the poll did not confirm the registration: %+v", r)
	}
	c.assertRegistrationFloor(t, "after the poll")
	// The manager's own view, before any status asks: re-resolved at once,
	// not on the configuration check's next tick.
	raw, err := c.d.rt.manager.Get(context.Background(), "dc-a")
	if err != nil {
		t.Fatal(err)
	}
	assertOrganizationPolicy(t, "the manager's view after the poll", *raw)
	for _, v := range c.statusAndList(t, "dc-a") {
		assertOrganizationPolicy(t, "status and list after the poll", v)
	}
}

// A registration the managed gateway confirmed without its floor being
// adopted (a start that then failed: Start confirms the registration before
// it readies OpenShell and adopts the floor) opens the closed floor at the
// next status or list, with the managed gateway down by then: the status's
// re-confirmation keys on any live registration on the closed floor, not
// only on an unconfirmed one.
func TestSandboxDaemonStatusOpensTheClosedFloorForAConfirmedRegistration(t *testing.T) {
	for _, via := range []string{"status", "list"} {
		t.Run(via, func(t *testing.T) {
			c := newClosedFloorFixture(t)
			c.d.regs.applyLive("dc-a", sandboxrelay.CurrentPolicy{V: 1, Generation: 3})
			c.assertClosed(t, "confirmed, before the "+via)
			ctx := context.Background()
			if via == "status" {
				sb, err := c.ctl.Get(ctx, "dc-a")
				if err != nil {
					t.Fatal(err)
				}
				assertOrganizationPolicy(t, "the first status", *sb)
			} else {
				list, err := c.ctl.List(ctx)
				if err != nil || len(list) != 1 {
					t.Fatalf("list = %+v, %v", list, err)
				}
				assertOrganizationPolicy(t, "the first list", list[0])
			}
			c.assertRegistrationFloor(t, "after the "+via)
			for _, v := range c.statusAndList(t, "dc-a") {
				assertOrganizationPolicy(t, "status and list after the "+via, v)
			}
		})
	}
}

// Adopting a confirmed registration's floor (Start's adoptFloor)
// re-resolves every sandbox's policy at once, not only the started one's
// and not on the configuration check's next tick.
func TestSandboxDaemonAdoptFloorReResolvesAtOnce(t *testing.T) {
	c := newClosedFloorFixture(t, "dc-x")
	c.d.regs.applyLive("dc-a", sandboxrelay.CurrentPolicy{V: 1, Generation: 3})
	c.d.adoptFloor("dc-a")
	c.assertRegistrationFloor(t, "after adoptFloor")
	for _, name := range []string{"dc-a", "dc-x"} {
		raw, err := c.d.rt.manager.Get(context.Background(), name)
		if err != nil {
			t.Fatal(err)
		}
		assertOrganizationPolicy(t, "the manager's view of "+name+" after adoptFloor", *raw)
	}
}

// The negative case: no registration the managed gateway confirmed, so the
// floor stays closed. The poll and the status ask the managed gateway and
// adopt nothing; the manager keeps the closed floor's deny, the
// registration's sandbox says its policy is being confirmed (never the
// organization's policy as if confirmed), and a sandbox without a
// registration keeps the deny.
func TestSandboxDaemonClosedFloorStaysWithoutAConfirmedRegistration(t *testing.T) {
	c := newClosedFloorFixture(t, "dc-x")
	ctx := context.Background()
	c.d.pollOnce(ctx)
	c.assertClosed(t, "after the poll")
	views := c.statusAndList(t, "dc-a")
	c.assertClosed(t, "after the status")
	for _, v := range views {
		if !slices.Contains(v.Warnings, sandboxConfirmingNote) {
			t.Fatalf("an unconfirmed registration's sandbox: %q, want the confirming note", v.Warnings)
		}
	}
	raw, err := c.d.rt.manager.Get(ctx, "dc-a")
	if err != nil {
		t.Fatal(err)
	}
	assertClosedFloorDeny(t, "the manager's view without a confirmation", *raw)
	for _, v := range c.statusAndList(t, "dc-x") {
		assertClosedFloorDeny(t, "a sandbox without a registration", v)
	}
	if r, _ := c.d.regs.get("dc-a"); r.Confirmed {
		t.Fatalf("a registration the gateway never answered for is confirmed: %+v", r)
	}
}

// A revoked registration keeps the closed floor and its deny: revoked by
// the poll's answer, or confirmed and then revoked before its floor was
// adopted (a start the managed gateway refused), even with the managed
// gateway answering again.
func TestSandboxDaemonRevokedRegistrationKeepsTheClosedFloor(t *testing.T) {
	t.Run("revoked by the poll", func(t *testing.T) {
		c := newClosedFloorFixture(t)
		c.relay.Store(relayRevokes)
		c.d.pollOnce(context.Background())
		if r, _ := c.d.regs.get("dc-a"); !r.Revoked {
			t.Fatalf("the poll did not mark the registration revoked: %+v", r)
		}
		c.relay.Store(relayAnswers)
		c.d.pollOnce(context.Background())
		c.assertClosed(t, "after the polls")
		for _, v := range c.statusAndList(t, "dc-a") {
			assertClosedFloorDeny(t, "a revoked registration's sandbox", v)
		}
		c.assertClosed(t, "after the status")
	})
	t.Run("confirmed then revoked", func(t *testing.T) {
		c := newClosedFloorFixture(t)
		c.d.regs.applyLive("dc-a", sandboxrelay.CurrentPolicy{V: 1, Generation: 3})
		c.d.regs.markRevoked("dc-a", "profile removed")
		c.relay.Store(relayAnswers)
		c.d.pollOnce(context.Background())
		c.assertClosed(t, "after the poll")
		for _, v := range c.statusAndList(t, "dc-a") {
			assertClosedFloorDeny(t, "a revoked registration's sandbox", v)
		}
		c.assertClosed(t, "after the status")
	})
}

// A poll that could not list the sandboxes (nothing counts as running then)
// still opens the closed floor with a registration it confirmed, as
// revalidate does at start without a list; an open floor is left as it is.
func TestSandboxDaemonUnlistedPollOpensOnlyTheClosedFloor(t *testing.T) {
	c := newClosedFloorFixture(t)
	c.unlisted.Store(true)
	c.relay.Store(relayAnswers)
	c.d.pollOnce(context.Background())
	if r, _ := c.d.regs.get("dc-a"); !r.Confirmed {
		t.Fatalf("the poll did not confirm the registration: %+v", r)
	}
	c.assertRegistrationFloor(t, "after an unlisted poll")
	for _, v := range c.statusAndList(t, "dc-a") {
		assertOrganizationPolicy(t, "status and list after an unlisted poll", v)
	}

	// An open floor: an unlisted poll changes nothing.
	g := newClosedFloorFixture(t)
	open := config.OpenShellAdminConfig{MinProfile: "permissive"}
	g.d.floorMu.Lock()
	g.d.floor = &open
	g.d.floorMu.Unlock()
	g.d.reloadConfig()
	g.unlisted.Store(true)
	g.relay.Store(relayAnswers)
	g.d.pollOnce(context.Background())
	if admin := g.d.config().OpenShell.Admin; admin.MinProfile != "permissive" {
		t.Fatalf("an unlisted poll replaced the open floor: %+v", admin)
	}
}

// The status's re-confirmation (revalidate) replaces only the closed floor:
// a create or a start that adopted its floor meanwhile keeps it, instead of
// an older registration's floor put back over it.
func TestSandboxDaemonRevalidateKeepsAnAdoptedFloor(t *testing.T) {
	c := newClosedFloorFixture(t)
	c.relay.Store(relayAnswers)
	created := config.OpenShellAdminConfig{MinProfile: "permissive", RequestAccess: "new@example.com"}
	c.d.floorMu.Lock()
	c.d.floor = &created
	c.d.floorMu.Unlock()
	c.d.reloadConfig()
	if revoked := c.d.revalidate(context.Background()); len(revoked) != 0 {
		t.Fatalf("revoked = %+v", revoked)
	}
	if r, _ := c.d.regs.get("dc-a"); !r.Confirmed {
		t.Fatalf("revalidate did not confirm the registration: %+v", r)
	}
	if admin := c.d.config().OpenShell.Admin; admin.MinProfile != "permissive" || admin.RequestAccess != "new@example.com" {
		t.Fatalf("revalidate replaced the adopted floor with %+v", admin)
	}
}
