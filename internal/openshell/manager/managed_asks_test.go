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
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/policy"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// fakeAuthority is the managed gateway's decisions and events routes: it
// re-checks every decision against its own copy of the floor
// (sandboxreg.CheckDecision, as the route does) and keeps what lasts.
type fakeAuthority struct {
	t *testing.T
	// cfgFloor is the floor of the person's profile while profile is
	// unset: the daemon's configuration, which on a managed daemon carries
	// the floor of the newest registration.
	cfgFloor func() config.OpenShellAdminConfig
	// profile, when set, is the floor of the profile the registrations
	// resolved: the gateway's and each sandbox's own (effectiveFloor).
	// gatewayOnly, when set, is the gateway's alone (it changed after the
	// sandbox's policy resolved). noFloor gives the sandboxes' policies
	// no floor.
	profile, gatewayOnly atomic.Pointer[config.OpenShellAdminConfig]
	noFloor              atomic.Bool

	mu      sync.Mutex
	decided []sandboxrelay.DecisionRequest
	saved   map[string][]sandboxrelay.Decision
	events  []sandboxrelay.Event
	batches []sandboxrelay.EventBatch
	// down is a gateway out of reach, gone the registrations it no
	// longer knows, byName the daemon's registrations by sandbox name.
	down   bool
	gone   map[string]bool
	byName map[string]string
}

// floor is the floor of the person's profile.
func (a *fakeAuthority) floor() config.OpenShellAdminConfig {
	if f := a.profile.Load(); f != nil {
		return *f
	}
	return a.cfgFloor()
}

func (a *fakeAuthority) set(edit func(*fakeAuthority)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	edit(a)
}

func (a *fakeAuthority) SandboxRegistration(sandbox string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.byName[sandbox]
	return r, ok
}

var errGatewayDown = &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Message: "the managed gateway can't be reached"}

func (a *fakeAuthority) AllowAlways(context.Context, string) error {
	a.t.Error("a managed manager wrote an always decision to the configuration")
	return errors.New("no configuration on a managed host")
}

func (a *fakeAuthority) BlockAlways(context.Context, string) error {
	a.t.Error("a managed manager wrote a block to the configuration")
	return errors.New("no configuration on a managed host")
}

func (a *fakeAuthority) Decide(_ context.Context, req sandboxrelay.DecisionRequest) (sandboxrelay.DecisionResult, error) {
	f := a.floor()
	if g := a.gatewayOnly.Load(); g != nil {
		f = *g
	}
	if err := sandboxreg.CheckDecision(f, req); err != nil {
		var refusal *sandboxreg.DecisionRefusedError
		errors.As(err, &refusal)
		return sandboxrelay.DecisionResult{}, &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: refusal.Message}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.decided = append(a.decided, req)
	stored := req.Scope == sandboxrelay.DecisionScopeAlways || req.Kind == sandboxrelay.DecisionEgressBlock
	d := sandboxrelay.Decision{ID: "d" + string(rune('a'+len(a.decided))), Registration: req.Registration, Kind: req.Kind, Host: req.Host, Scope: req.Scope}
	if stored {
		if a.saved == nil {
			a.saved = map[string][]sandboxrelay.Decision{}
		}
		a.saved[req.Registration] = append(a.saved[req.Registration], d)
	}
	return sandboxrelay.DecisionResult{V: 1, Stored: stored, Decision: d}, nil
}

func (a *fakeAuthority) Decisions(_ context.Context, registration string) ([]sandboxrelay.Decision, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.down:
		return nil, errGatewayDown
	case a.gone[registration]:
		return nil, &sandboxapi.Error{Code: sandboxapi.CodeConflict, Message: "the managed gateway no longer knows this sandbox"}
	}
	return append([]sandboxrelay.Decision(nil), a.saved[registration]...), nil
}

func (a *fakeAuthority) Events(_ context.Context, batch sandboxrelay.EventBatch) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.down {
		return errGatewayDown
	}
	if batch.Registration == "" && slices.ContainsFunc(batch.Events, func(ev sandboxrelay.Event) bool { return !eventWithoutRegistration(ev) }) {
		a.t.Errorf("a batch without a registration holds a record that needs one: %+v", batch.Events)
	}
	if batch.Registration != "" && a.gone[batch.Registration] {
		// The gateway refuses a batch under a registration it no longer
		// knows (sandbox_registration_unknown) and records nothing of it.
		return &sandboxapi.Error{Code: sandboxapi.CodeNotFound, Message: "This sandbox is not registered for your account."}
	}
	a.events = append(a.events, batch.Events...)
	a.batches = append(a.batches, batch)
	return nil
}

// registrationsOf are the registrations the batches holding a kind of
// record were posted under.
func (a *fakeAuthority) registrationsOf(kind string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, b := range a.batches {
		if slices.ContainsFunc(b.Events, func(ev sandboxrelay.Event) bool { return ev.Kind == kind }) {
			out = append(out, b.Registration)
		}
	}
	return out
}

func (a *fakeAuthority) eventsOf(kind string) []sandboxrelay.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []sandboxrelay.Event
	for _, ev := range a.events {
		if ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}

func (a *fakeAuthority) decisions() []sandboxrelay.DecisionRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]sandboxrelay.DecisionRequest(nil), a.decided...)
}

// managedEnv is a managed host's daemon: the managed gateway is its
// Persist, and every sandbox it runs is registered. Each sandbox's resolved
// policy carries the floor of its registration's profile (as
// packs.Effective.Floor does), which the manager reads, never its own
// configuration's.
func managedEnv(t *testing.T, edit func(*config.Config)) (*harnessEnv, *fakeAuthority) {
	t.Helper()
	auth := &fakeAuthority{t: t}
	prev := effectiveFloor
	effectiveFloor = func(eff *packs.Effective) (config.OpenShellAdminConfig, bool) {
		if eff == nil || auth.noFloor.Load() {
			return config.OpenShellAdminConfig{}, false
		}
		return auth.floor(), true
	}
	t.Cleanup(func() { effectiveFloor = prev })
	e := newEnv(t, edit)
	auth.cfgFloor = func() config.OpenShellAdminConfig { return e.config().OpenShell.Admin }
	e.m.opts.Persist = auth
	// A managed daemon's reconcile looks into the user's containers: never
	// this machine's in a test.
	containerScan = func(context.Context) ([]foreignContainer, error) { return nil, nil }
	t.Cleanup(func() { containerScan = dockerAgentContainers })
	return e, auth
}

// register gives a sandbox its managed gateway registration (the daemon's
// create does, L4) and rebuilds its decider.
func (e *harnessEnv) register(name string) string {
	e.t.Helper()
	id := sandboxreg.IDPrefix + strings.Repeat("a", sandboxreg.IDRandomChars-len(name)) + name
	e.m.mu.Lock()
	e.m.boxes[name].rec.RegistrationID = id
	e.m.mu.Unlock()
	e.m.refreshEgress()
	return id
}

// The plan's §6.2 truth table on a managed daemon: what the floor's
// user_approvals and allow_unblock leave the person (answering an ask for
// the session or always, unblocking for the session or always) reaches the
// managed gateway; the rest is refused with the organization's sentence and
// the request-access contact before anything is decided; under none the
// agent's proposals are refused instead of asking.
func TestManagedAsksTruthTable(t *testing.T) {
	e, auth := managedEnv(t, func(c *config.Config) {
		c.OpenShell.Profile = config.OpenShellProfileBalanced
		c.OpenShell.Admin.RequestAccess = "it-security@example.com"
	})
	e.live(sandboxapi.CreateRequest{Name: "askbox"})
	reg := e.register("askbox")
	no := boolPtr(false)
	n := 0
	for _, row := range []struct {
		approvals                     string
		unblock                       *bool
		session, always, ub, ubAlways bool
	}{
		{"", nil, true, true, true, true},
		{"", no, true, false, false, false},
		{config.OpenShellUserApprovalsSession, nil, true, false, true, false},
		{config.OpenShellUserApprovalsSession, no, true, false, false, false},
	} {
		e.setConfig(func(c *config.Config) {
			c.OpenShell.Admin.UserApprovals, c.OpenShell.Admin.AllowUnblock = row.approvals, row.unblock
		})
		name := row.approvals + "/" + map[bool]string{true: "unset", false: "false"}[row.unblock == nil]
		for _, always := range []bool{false, true} {
			n++
			host := "h" + string(rune('a'+n)) + ".example.org"
			e.propose("askbox", host)
			e.draft("askbox")
			asks := e.waitAsks("askbox", 1)
			err := e.decide(asks[0].ID, sandboxapi.ApprovalDecision{Decision: "approve", Always: always})
			want := row.session
			if always {
				want = row.always
			}
			if allowed := err == nil; allowed != want {
				t.Fatalf("%s: approve (always %v) = %v, want allowed %v", name, always, err, want)
			}
			if err != nil {
				// The one managed shape (GAP-0508): the organization's
				// sentence, then the contact and the Quote line.
				if apiErr := wantCode(t, err, sandboxapi.CodeAdminViolation); !sandboxapi.IsPolicyRefusal(apiErr.Message) ||
					!strings.Contains(apiErr.Message, "\nRequest access: it-security@example.com. Quote: ") {
					t.Fatalf("%s: refusal %+v lacks the organization's sentence or the contact", name, apiErr)
				}
				must(t, e.decide(asks[0].ID, sandboxapi.ApprovalDecision{Decision: "reject"}))
			}
			e.waitAsks("askbox", 0)
		}
		for _, always := range []bool{false, true} {
			_, err := e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "webhook.site", Sandbox: "askbox", Always: always})
			want := row.ub
			if always {
				want = row.ubAlways
			}
			if allowed := err == nil; allowed != want {
				t.Fatalf("%s: unblock (always %v) = %v, want allowed %v", name, always, err, want)
			}
		}
	}
	for _, d := range auth.decisions() {
		if d.Registration != reg {
			t.Fatalf("decision %+v was not made for the sandbox's registration", d)
		}
	}
	if got := len(auth.decisions()); got != 8 {
		t.Fatalf("the managed gateway decided %d times, want the 8 allowed cells", got)
	}
	// none: the agent's proposals are refused at once, with the contact.
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.UserApprovals = config.OpenShellUserApprovalsNone })
	id := e.propose("askbox", "late.example.org")
	e.draft("askbox")
	e.waitChunk("askbox", id, "rejected")
	if asks, _ := e.m.Approvals(t.Context(), "askbox"); len(asks) != 0 {
		t.Fatalf("asks under user_approvals none = %+v", asks)
	}
	if got := e.events("askbox", sandboxapi.ActivityEgressBlocked, "admin_violation"); len(got) == 0 ||
		!strings.Contains(got[len(got)-1].Message, "it-security@example.com") {
		t.Fatalf("the refused proposal's feed line = %+v, want the contact", got)
	}
}

// Decisions the managed gateway keeps decide the sandbox's egress, capped
// by the floor whenever the policy resolves; the daemon's configuration is
// never written, the default decider refuses everything, and a decision a
// daemon sends past the floor (its own check bypassed) is refused by the
// gateway.
func TestManagedDecisionsKeptByTheGateway(t *testing.T) {
	e, auth := managedEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "keepbox"})
	reg := e.register("keepbox")
	if e.decideEgress("keepbox", "webhook.site").Allowed {
		t.Fatal("the blocklist feed does not apply")
	}
	res, err := e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "webhook.site", Sandbox: "keepbox", Always: true})
	if err != nil || !res.Persisted || !strings.Contains(res.Message, "organization's DefenseClaw gateway") {
		t.Fatalf("always unblock = %+v, %v", res, err)
	}
	if !e.decideEgress("keepbox", "webhook.site").Allowed {
		t.Fatal("the kept unblock does not reach the sandbox's decider")
	}
	// A user block only tightens, and is kept.
	e.setConfig(func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileBalanced })
	e.m.refreshEgress()
	e.propose("keepbox", "example.org")
	e.draft("keepbox")
	asks := e.waitAsks("keepbox", 1)
	if r, err := e.m.DecideApproval(t.Context(), asks[0].ID, sandboxapi.ApprovalDecision{Decision: "reject", Always: true}); err != nil || !r.Persisted {
		t.Fatalf("reject always = %+v, %v", r, err)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileOpen })
	e.m.refreshEgress()
	if e.decideEgress("keepbox", "example.org").Allowed {
		t.Fatal("the kept user block does not reach the sandbox's decider")
	}
	// The floor tightens: the next resolve takes the always unblock back.
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.UserApprovals = config.OpenShellUserApprovalsSession })
	must(t, e.m.Reconcile(t.Context()))
	if e.decideEgress("keepbox", "webhook.site").Allowed {
		t.Fatal("an always unblock the floor no longer allows still opens the host")
	}
	// The direct route past the floor: the gateway refuses it.
	b := e.boxOf("keepbox")
	if _, err := e.m.keepDecision(t.Context(), b, sandboxrelay.DecisionUnblock, "pastebin.com", sandboxrelay.DecisionScopeAlways, ""); !sandboxapi.IsCode(err, sandboxapi.CodeAdminViolation) {
		t.Fatalf("a decision past the floor = %v, want the gateway's refusal", err)
	}
	if got := auth.decisions(); len(got) != 2 || got[0].Registration != reg {
		t.Fatalf("decisions = %+v", got)
	}
	// The egress proxy's default decider refuses everything.
	d, err := e.m.Decider()
	must(t, err)
	if dec := d.Decide(egress.Principal{BindingID: "probe"}, "example.com", 443); dec.Allowed {
		t.Fatalf("the managed default decider allowed example.com: %+v", dec)
	}
	// Outside managed mode it is the configured posture.
	if d, err = newEnv(t, nil).m.Decider(); err != nil || !d.Decide(egress.Principal{BindingID: "probe"}, "example.com", 443).Allowed {
		t.Fatalf("the default decider outside managed mode refused example.com: %v", err)
	}
}

// A sandbox on the person's OpenShell gateway that DefenseClaw did not
// create and register is stopped at the next reconcile (alert only when
// the floor says so, reported once), whether it has no labels or labels
// and no registration; registered sandboxes are left alone.
func TestManagedForeignSandboxes(t *testing.T) {
	e, auth := managedEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "mine"})
	e.register("mine")
	_, err := e.client.CreateSandbox(t.Context(), "rawclaude", &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{})
	must(t, err)
	_, err = e.client.CreateSandbox(t.Context(), "unregistered", &openshell.SandboxSpec{},
		openshell.CreateSandboxOptions{Labels: map[string]string{LabelManaged: "true", LabelOwner: testOwner, LabelHarness: "claudecode"}})
	must(t, err)
	must(t, e.m.Reconcile(t.Context()))
	for _, name := range []string{"rawclaude", "unregistered"} {
		sb, err := e.client.GetSandbox(t.Context(), name)
		must(t, err)
		if p := auditPhase(sb.Status.Phase); p != audit.SandboxPhaseStopped && p != audit.SandboxPhaseStopping {
			t.Fatalf("foreign sandbox %s is %s, want stopped", name, p)
		}
	}
	if sb := e.get("mine"); sb.Phase != string(audit.SandboxPhaseReady) {
		t.Fatalf("the registered sandbox is %s", sb.Phase)
	}
	if got := auth.eventsOf(sandboxrelay.EventForeignSandbox); len(got) != 2 || !strings.Contains(string(got[0].Payload), `"action":"stop"`) {
		t.Fatalf("foreign sandbox events = %+v", got)
	}
	// GAP-0263: stopped foreign sandboxes leave the gateway free to stop as
	// idle; an alerted one, below, keeps it.
	if e.m.ForeignSandboxesRunning() {
		t.Fatal("stopped foreign sandboxes reported running")
	}
	if got := e.events("rawclaude", sandboxapi.ActivityFinding, sandboxrelay.EventForeignSandbox); len(got) != 1 ||
		!strings.Contains(got[0].Message, "wasn't started with defenseclaw sandbox run") {
		t.Fatalf("feed = %+v", got)
	}
	// alert: reported once, left running.
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.ForeignSandboxes = config.OpenShellForeignSandboxesAlert })
	_, err = e.client.CreateSandbox(t.Context(), "devbox", &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{})
	must(t, err)
	must(t, e.m.Reconcile(t.Context()))
	must(t, e.m.Reconcile(t.Context()))
	sb, err := e.client.GetSandbox(t.Context(), "devbox")
	must(t, err)
	if p := auditPhase(sb.Status.Phase); p == audit.SandboxPhaseStopped || p == audit.SandboxPhaseStopping {
		t.Fatal("alert stopped the foreign sandbox")
	}
	if got := auth.eventsOf(sandboxrelay.EventForeignSandbox); len(got) != 3 || !strings.Contains(string(got[2].Payload), `"action":"alert"`) {
		t.Fatalf("foreign sandbox events after alert = %+v", got)
	}
	if !e.m.ForeignSandboxesRunning() {
		t.Fatal("an alerted foreign sandbox left running is not reported")
	}
}

// GAP-0678: a gateway the person started by hand and registered with the
// OpenShell CLI ran a raw MicroVM the reconcile never saw, since it listed
// only the managed gateway. Every sandbox running on another gateway of the
// account is foreign: stopped under foreign_sandboxes stop and recorded,
// even one carrying DefenseClaw's labels and the name of a managed sandbox,
// and the managed gateway is not kept up by what runs there.
func TestManagedForeignSandboxOnAnotherGateway(t *testing.T) {
	e, auth := managedEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "mine"})
	e.register("mine")
	private := openshelltest.New(openshelltest.WithDriver(openshell.DriverVM))
	pc := private.Client(openshell.ClientOptions{PollInterval: time.Millisecond, ReadyTimeout: 5 * time.Second})
	for name, labels := range map[string]map[string]string{
		"cx4k2-private-vm": nil,
		"mine":             {LabelManaged: "true", LabelOwner: testOwner, LabelHarness: "claudecode"},
	} {
		_, err := pc.CreateSandbox(t.Context(), name, &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{Labels: labels})
		must(t, err)
	}
	closed := 0
	var managedSeen *Gateway
	e.m.opts.OtherGateways = func(_ context.Context, managed *Gateway) []*Gateway {
		managedSeen = managed
		return []*Gateway{{Client: pc, Name: "bob-private", Close: func() error { closed++; return nil }}}
	}
	must(t, e.m.Reconcile(t.Context()))
	if managedSeen == nil || managedSeen.Name == "bob-private" || closed != 1 {
		t.Fatalf("other gateways asked with %+v, closed %d", managedSeen, closed)
	}
	for _, name := range []string{"cx4k2-private-vm", "mine"} {
		sb, err := pc.GetSandbox(t.Context(), name)
		must(t, err)
		if p := auditPhase(sb.Status.Phase); p != audit.SandboxPhaseStopped && p != audit.SandboxPhaseStopping {
			t.Fatalf("%s on the private gateway is %s, want stopped", name, p)
		}
	}
	if sb := e.get("mine"); sb.Phase != string(audit.SandboxPhaseReady) {
		t.Fatalf("the managed sandbox is %s", sb.Phase)
	}
	if got := auth.eventsOf(sandboxrelay.EventForeignSandbox); len(got) != 2 ||
		!strings.Contains(string(got[0].Payload)+string(got[1].Payload), `"sandbox":"cx4k2-private-vm"`) {
		t.Fatalf("foreign sandbox events = %+v", got)
	}
	// alert: reported once, left running, and not counted against the
	// managed gateway's idle stop.
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.ForeignSandboxes = config.OpenShellForeignSandboxesAlert })
	_, err := pc.CreateSandbox(t.Context(), "raw2", &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{})
	must(t, err)
	must(t, e.m.Reconcile(t.Context()))
	must(t, e.m.Reconcile(t.Context()))
	if got := auth.eventsOf(sandboxrelay.EventForeignSandbox); len(got) != 3 || !strings.Contains(string(got[2].Payload), `"action":"alert"`) {
		t.Fatalf("foreign sandbox events after alert = %+v", got)
	}
	if e.m.ForeignSandboxesRunning() {
		t.Fatal("a sandbox alerted on another gateway keeps the managed gateway up")
	}
}

// GAP-0557: the OpenShell sandbox of a create the daemon rolled back (a
// Ctrl-C while the image built) that outlived the rollback is the daemon's
// own leftover: the reconcile removes it without announcing a foreign
// sandbox, and the same name can be created again at once.
func TestRolledBackCreateLeftoverIsNotForeign(t *testing.T) {
	e, auth := managedEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "mine"})
	e.register("mine")
	labels := map[string]string{LabelManaged: "true", LabelOwner: testOwner, LabelHarness: "claudecode"}
	for _, name := range []string{"ghostbox", "strangerbox"} {
		_, err := e.client.CreateSandbox(t.Context(), name, &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{Labels: labels})
		must(t, err)
	}
	e.m.noteUndone("ghostbox")
	must(t, e.m.Reconcile(t.Context()))
	if _, err := e.client.GetSandbox(t.Context(), "ghostbox"); !openshell.IsNotFound(err) {
		if sb, gerr := e.client.GetSandbox(t.Context(), "ghostbox"); gerr == nil && auditPhase(sb.Status.Phase) != audit.SandboxPhaseDeleting {
			t.Fatalf("the leftover of the rolled-back create is %s, want it removed", sb.Status.Phase)
		}
	}
	if got := e.events("ghostbox", sandboxapi.ActivityFinding, sandboxrelay.EventForeignSandbox); len(got) != 0 {
		t.Fatalf("the leftover was announced as foreign: %+v", got)
	}
	// A sandbox nobody rolled back is still foreign.
	if got := e.events("strangerbox", sandboxapi.ActivityFinding, sandboxrelay.EventForeignSandbox); len(got) != 1 {
		t.Fatalf("foreign events of the unregistered sandbox = %+v", got)
	}
	if got := auth.eventsOf(sandboxrelay.EventForeignSandbox); len(got) != 1 {
		t.Fatalf("foreign sandbox events = %+v, want only the stranger", got)
	}
}

// GAP-0658: a leftover whose delete fails still runs, so it is stopped and
// recorded like any foreign sandbox rather than skipped for the whole
// rollback window.
func TestRolledBackCreateLeftoverDeleteFailedIsStoppedAndRecorded(t *testing.T) {
	e, auth := managedEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "mine"})
	e.register("mine")
	labels := map[string]string{LabelManaged: "true", LabelOwner: testOwner, LabelHarness: "claudecode"}
	_, err := e.client.CreateSandbox(t.Context(), "ghostbox", &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{Labels: labels})
	must(t, err)
	e.m.noteUndone("ghostbox")
	e.fake.FailNext(openshelltest.MethodDeleteSandbox, &types.StatusError{Code: types.ErrorUnavailable, Message: "driver busy"})
	must(t, e.m.Reconcile(t.Context()))
	sb, err := e.client.GetSandbox(t.Context(), "ghostbox")
	if err == nil && auditPhase(sb.Status.Phase) == audit.SandboxPhaseReady {
		t.Fatalf("the leftover whose delete failed still runs: %s", sb.Status.Phase)
	}
	if got := auth.eventsOf(sandboxrelay.EventForeignSandbox); len(got) != 1 {
		t.Fatalf("foreign sandbox events = %+v, want the leftover recorded", got)
	}
	if got := e.events("ghostbox", sandboxapi.ActivityFinding, sandboxrelay.EventForeignSandbox); len(got) != 1 {
		t.Fatalf("foreign findings of the leftover = %+v", got)
	}
}

// GAP-0676: on a managed computer a session unblock (the answer to a proxy
// ask without --always) ends when the sandbox stops: its next session asks
// again. A stored "always" one is what outlives the stop.
func TestManagedSessionUnblockEndsAtStop(t *testing.T) {
	e, _ := managedEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "sessbox"})
	e.register("sessbox")
	if _, err := e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "webhook.site", Sandbox: "sessbox"}); err != nil {
		t.Fatalf("session unblock = %v", err)
	}
	if _, err := e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "example.org", Sandbox: "sessbox", Always: true}); err != nil {
		t.Fatalf("always unblock = %v", err)
	}
	if !e.decideEgress("sessbox", "webhook.site").Allowed {
		t.Fatal("the session unblock does not apply while the sandbox runs")
	}
	e.stopBox("sessbox")
	e.startBox("sessbox", sandboxapi.StartRequest{})
	if e.decideEgress("sessbox", "webhook.site").Allowed {
		t.Fatal("a session unblock outlived the stop")
	}
	if !e.decideEgress("sessbox", "example.org").Allowed {
		t.Fatal("an always unblock did not outlive the stop")
	}
}

// GAP-0676: the answer to a proxy ask for the session ends when the sandbox
// stops, like a session unblock: after the start the host is refused again
// and asks again. An answer for always is what outlives the stop.
func TestManagedSessionApprovalEndsAtStop(t *testing.T) {
	e, _ := managedEnv(t, func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileBalanced })
	_, advance := e.fakeClock(time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC))
	proxy := startLiveProxyWith(t, e, func(o *egress.Options) { o.Sink = e.m.EgressSink() })
	e.live(sandboxapi.CreateRequest{Name: "pabox"})
	e.register("pabox")
	answer := func(host string, always bool) {
		t.Helper()
		if status, _ := proxy.connect(t, "pabox", host+":443"); status != http.StatusForbidden {
			t.Fatalf("CONNECT %s = %d, want the proxy's refusal", host, status)
		}
		asks := e.waitAsks("pabox", 1)
		must(t, e.decide(asks[0].ID, sandboxapi.ApprovalDecision{Decision: "approve", Always: always}))
		e.waitAsks("pabox", 0)
		if !e.decideEgress("pabox", host).Allowed {
			t.Fatalf("the proxy still refuses %s after the approval", host)
		}
	}
	answer("example.org", false)
	answer("kept.example.net", true)
	e.stopBox("pabox")
	e.startBox("pabox", sandboxapi.StartRequest{})
	if e.decideEgress("pabox", "example.org").Allowed {
		t.Fatal("a session approval outlived the stop")
	}
	if rec := e.boxOf("pabox").rec; len(rec.Approved) != 0 {
		t.Fatalf("the record keeps the last session's approvals: %q", rec.Approved)
	}
	if !e.decideEgress("pabox", "kept.example.net").Allowed {
		t.Fatal("an always approval did not outlive the stop")
	}
	// The new session asks again, within the minutes an answer given moments
	// ago holds off a repeat ask (collapseWindow): the last session's answer
	// is not one. (Past the refusal log's own folding window.)
	advance(time.Minute)
	if status, _ := proxy.connect(t, "pabox", "example.org:443"); status != http.StatusForbidden {
		t.Fatalf("CONNECT example.org after the start = %d, want the proxy's refusal", status)
	}
	if asks := e.waitAsks("pabox", 1); asks[0].Host != "example.org" {
		t.Fatalf("ask after the start = %+v", asks[0])
	}
}

// GAP-0676 (decision 6b): a rule the person approved for the session (an
// OpenShell draft proposal) ends when the sandbox stops too; one approved
// for always, which the managed gateway keeps, stays, and so does one
// DefenseClaw approved on its own.
func TestManagedSessionRuleEndsAtStop(t *testing.T) {
	e, _ := managedEnv(t, func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileBalanced })
	e.live(sandboxapi.CreateRequest{Name: "srbox"})
	e.register("srbox")
	approveRule := func(host string, always bool) string {
		t.Helper()
		e.propose("srbox", host)
		e.draft("srbox")
		asks := e.waitAsks("srbox", 1)
		must(t, e.decide(asks[0].ID, sandboxapi.ApprovalDecision{Decision: "approve", Always: always}))
		rule := ruleFor(host)
		eventually(t, "the approved rule "+rule, func() bool {
			return e.approvedRules("srbox")[rule] == actorOperator && e.hasRule("srbox", rule)
		})
		e.waitAsks("srbox", 0)
		return rule
	}
	session := approveRule("session.example.org", false)
	always := approveRule("always.example.org", true)
	e.stopBox("srbox")
	e.startBox("srbox", sandboxapi.StartRequest{})
	if e.hasRule("srbox", session) {
		t.Fatal("a rule approved for the session outlived the stop")
	}
	if _, kept := e.approvedRules("srbox")[session]; kept {
		t.Fatal("the record keeps the approver of the removed rule")
	}
	if !e.tel.removed(session, policyReasonApprovalRequired) {
		t.Fatal("the removed rule has no policy record")
	}
	if !e.hasRule("srbox", always) || e.approvedRules("srbox")[always] != actorOperator {
		t.Fatal("a rule approved for always did not outlive the stop")
	}
}

// Outside managed mode an approval for the session lasts as long as the
// sandbox: nothing ends at a stop.
func TestUnmanagedSessionApprovalsOutliveAStop(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileBalanced })
	e.live(sandboxapi.CreateRequest{Name: "ombox"})
	e.propose("ombox", "session.example.org")
	e.draft("ombox")
	asks := e.waitAsks("ombox", 1)
	must(t, e.decide(asks[0].ID, approve))
	rule := ruleFor("session.example.org")
	eventually(t, "the approved rule", func() bool { return e.hasRule("ombox", rule) })
	e.stopBox("ombox")
	e.startBox("ombox", sandboxapi.StartRequest{})
	if !e.hasRule("ombox", rule) || e.approvedRules("ombox")[rule] != actorOperator {
		t.Fatal("outside managed mode a session rule ended at the stop")
	}
}

func TestRunAgainAfterARolledBackCreate(t *testing.T) {
	e := newEnv(t, nil)
	_, err := e.client.CreateSandbox(t.Context(), "again", &openshell.SandboxSpec{},
		openshell.CreateSandboxOptions{Labels: map[string]string{LabelManaged: "true", LabelOwner: testOwner, LabelHarness: "claudecode"}})
	must(t, err)
	if _, err := e.tryCreate(sandboxapi.CreateRequest{Name: "again"}); err == nil {
		t.Fatal("create over a sandbox nobody rolled back succeeded")
	}
	e.m.noteUndone("again")
	if _, err := e.tryCreate(sandboxapi.CreateRequest{Name: "again"}); err != nil {
		t.Fatalf("create over the leftover of a rolled-back create: %v", err)
	}
}

// A foreign sandbox OpenShell won't stop in its phase (one still
// provisioning: "sandbox must be Ready to stop") is deleted instead, and the
// person is told; one whose delete fails too is tried again at the next
// reconcile (GAP-0264).
func TestManagedForeignSandboxNotReadyIsRemoved(t *testing.T) {
	e, auth := managedEnv(t, nil)
	_, err := e.client.CreateSandbox(t.Context(), "rawprov", &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{})
	must(t, err)
	must(t, e.fake.SetPhase(openshell.DefaultWorkspace, "rawprov", types.SandboxProvisioning))
	notReady := &types.StatusError{Code: types.ErrorConflict, Message: "sandbox must be Ready to stop (current phase: Provisioning)"}
	e.fake.FailNext(openshelltest.MethodStopSandbox, notReady)
	e.fake.FailNext(openshelltest.MethodDeleteSandbox, &types.StatusError{Code: types.ErrorUnavailable, Message: "driver busy"})
	must(t, e.m.Reconcile(t.Context()))
	if _, err := e.client.GetSandbox(t.Context(), "rawprov"); err != nil || len(auth.eventsOf(sandboxrelay.EventForeignSandbox)) != 0 {
		t.Fatalf("after a failed stop and delete: %v, events %+v", err, auth.eventsOf(sandboxrelay.EventForeignSandbox))
	}
	e.fake.FailNext(openshelltest.MethodStopSandbox, notReady)
	must(t, e.m.Reconcile(t.Context()))
	if _, err := e.client.GetSandbox(t.Context(), "rawprov"); !openshell.IsNotFound(err) {
		t.Fatalf("the provisioning foreign sandbox is still there: %v", err)
	}
	if got := auth.eventsOf(sandboxrelay.EventForeignSandbox); len(got) != 1 || !strings.Contains(string(got[0].Payload), `"action":"stop"`) {
		t.Fatalf("foreign sandbox events = %+v", got)
	}
	if got := e.events("rawprov", sandboxapi.ActivityFinding, sandboxrelay.EventForeignSandbox); len(got) != 1 ||
		!strings.Contains(got[0].Message, "was removed") {
		t.Fatalf("feed = %+v", got)
	}
}

// Network rules: every rule DefenseClaw did not render is judged, not only
// the triaged allow_* ones; on a managed daemon a rule it neither rendered
// nor approved (added through OpenShell's own API) is removed and
// reported, and a repeat stops the sandbox; under user_approvals none
// every rule the person approved goes, while DefenseClaw's own stay.
func TestManagedForeignRules(t *testing.T) {
	e, auth := managedEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "rulebox"})
	e.register("rulebox")
	approved := e.approveRule("rulebox", "api.example.org")
	addRule := func(rule, host string) {
		t.Helper()
		_, err := e.client.MergePolicy(t.Context(), "rulebox", []openshell.PolicyMergeOperation{{AddRule: &types.AddNetworkRule{
			RuleName: rule, Rule: types.NetworkPolicyRule{Name: rule, Endpoints: []types.PolicyNetworkEndpoint{{Host: host, Port: 443}},
				Binaries: []types.PolicyNetworkBinary{{Path: "/usr/bin/curl"}}}}}}, openshell.PolicyUpdateOptions{})
		must(t, err)
	}
	addRule("corp_tunnel", "tunnel.example.net")
	e.m.enforceAll(t.Context())
	if e.hasRule("rulebox", "corp_tunnel") || !e.hasRule("rulebox", approved) {
		t.Fatalf("after one pass: foreign %v, approved %v", e.hasRule("rulebox", "corp_tunnel"), e.hasRule("rulebox", approved))
	}
	if !e.tel.removed("corp_tunnel", policyReasonForeignRule) {
		t.Fatal("the removed foreign rule has no policy record")
	}
	if got := auth.eventsOf(sandboxrelay.EventForeignRule); len(got) != 1 || !strings.Contains(string(got[0].Payload), `"action":"removed"`) {
		t.Fatalf("foreign rule events = %+v", got)
	}
	addRule("allow_tunnel_example_net_443", "tunnel.example.net")
	e.m.enforceAll(t.Context())
	eventually(t, "the sandbox stopped for a repeat", func() bool {
		return e.get("rulebox").Phase == string(audit.SandboxPhaseStopped)
	})
	e.m.tamperStops.Wait() // the stop has saved its record
	if got := auth.eventsOf(sandboxrelay.EventForeignRule); len(got) != 2 || !strings.Contains(string(got[1].Payload), `"action":"stopped"`) {
		t.Fatalf("foreign rule events = %+v", got)
	}
}

// Under user_approvals none, the rules the person approved are removed,
// and outside managed mode a rule of any name is judged by the policy.
func TestUserApprovalsNoneRemovesUserRules(t *testing.T) {
	e := liveEnv(t, "nonebox", func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileBalanced })
	e.propose("nonebox", "user.example.org")
	e.draft("nonebox")
	asks := e.waitAsks("nonebox", 1)
	must(t, e.decide(asks[0].ID, approve))
	rule := ruleFor("user.example.org")
	eventually(t, "the approved rule", func() bool { return e.approvedRules("nonebox")[rule] == actorOperator })
	_, err := e.client.MergePolicy(t.Context(), "nonebox", []openshell.PolicyMergeOperation{{AddRule: &types.AddNetworkRule{
		RuleName: "corp_paste", Rule: types.NetworkPolicyRule{Name: "corp_paste", Endpoints: []types.PolicyNetworkEndpoint{{Host: "paste.example.net", Port: 443}},
			Binaries: []types.PolicyNetworkBinary{{Path: "/usr/bin/curl"}}}}}}, openshell.PolicyUpdateOptions{})
	must(t, err)
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.EgressBlock = []string{"paste.example.net"} })
	e.m.enforceAll(t.Context())
	if e.hasRule("nonebox", "corp_paste") {
		t.Fatal("a rule named outside allow_* to a host the organization blocks was kept")
	}
	if !e.hasRule("nonebox", rule) {
		t.Fatal("the user's rule went before user_approvals none")
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.UserApprovals = config.OpenShellUserApprovalsNone })
	e.m.enforceAll(t.Context())
	if e.hasRule("nonebox", rule) {
		t.Fatal("the user's rule survived user_approvals none")
	}
	// GAP-0468: the feed names the destination whose rule went, with the
	// managed refusal, not "✗  (admin policy)".
	if !slices.ContainsFunc(e.events("nonebox", sandboxapi.ActivityEgressBlocked, "admin_policy"), func(ev sandboxapi.ActivityEvent) bool {
		return ev.Host == "user.example.org" && strings.Contains(ev.Message, "removed the rule you approved for user.example.org") &&
			strings.HasSuffix(ev.Refusal, "Quote: rule user_approvals, host user.example.org, sandbox nonebox.")
	}) {
		t.Fatalf("feed = %+v", e.events("nonebox", sandboxapi.ActivityEgressBlocked, ""))
	}
}

// GAP-0502: a proposal the organization's allowed list refuses tells the
// feed and the agent the managed refusal: the rule, that the user can't
// approve it, and the request-access Quote line.
func TestAllowOnlyRejectionCarriesTheManagedRefusal(t *testing.T) {
	e := liveEnv(t, "listbox", func(c *config.Config) {
		c.OpenShell.Profile = config.OpenShellProfileBalanced
		c.OpenShell.Admin.EgressAllowOnly = []string{"github.com"}
		c.OpenShell.Admin.RequestAccess = "it-security@example.com"
	})
	e.propose("listbox", "api.example.net")
	e.draft("listbox")
	quote := "Request access: it-security@example.com. Quote: rule egress_allow_only, host api.example.net, sandbox listbox."
	eventually(t, "the refusal on the feed", func() bool {
		return slices.ContainsFunc(e.events("listbox", sandboxapi.ActivityEgressBlocked, ""), func(ev sandboxapi.ActivityEvent) bool {
			return ev.Host == "api.example.net" && strings.Contains(ev.Refusal, "api.example.net is not on your profile's allowed hosts (rule egress_allow_only). You can't approve this.") &&
				strings.HasSuffix(ev.Refusal, quote)
		})
	})
	b := e.binding("listbox")
	if got := e.m.EgressRefusals(b.ID, "listbox"); !slices.ContainsFunc(got, func(r EgressRefusal) bool {
		return r.Note == NoteAccessRefused && r.Host == "api.example.net" && strings.HasSuffix(r.Remedy, quote)
	}) {
		t.Fatalf("refusals = %+v", got)
	}
}

// GAP-0605: on a managed daemon a connection the organization's allowed
// list refuses also goes to the managed gateway as an access_refused record
// under the sandbox's registration, with the host and the rule.
func TestManagedAllowOnlyRefusalIsRecorded(t *testing.T) {
	e, auth := managedEnv(t, func(c *config.Config) {
		c.OpenShell.Profile = config.OpenShellProfileBalanced
		c.OpenShell.Admin.EgressAllowOnly = []string{"github.com"}
	})
	e.live(sandboxapi.CreateRequest{Name: "listbox"})
	reg := e.register("listbox")
	e.propose("listbox", "api.example.net")
	e.draft("listbox")
	eventually(t, "the access_refused record", func() bool {
		got := auth.eventsOf(sandboxrelay.EventAccessRefused)
		return len(got) == 1 && strings.Contains(string(got[0].Payload), `"host":"api.example.net"`) &&
			strings.Contains(string(got[0].Payload), `"rule":"egress_allow_only"`)
	})
	if regs := auth.registrationsOf(sandboxrelay.EventAccessRefused); !slices.Equal(regs, []string{reg}) {
		t.Fatalf("posted under %v, want %s", regs, reg)
	}
}

// Containers that run an agent outside DefenseClaw's sandboxes are
// reported once each, never stopped: without a registration while none of
// the person's sandboxes is registered (GAP-0318), and while the OpenShell
// gateway can't be reached, at most once a reconcile interval (GAP-0326,
// GAP-0370).
func TestManagedForeignContainers(t *testing.T) {
	e, auth := managedEnv(t, nil)
	_, advance := e.fakeClock(time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC))
	var scans atomic.Int32
	var found atomic.Value
	found.Store([]foreignContainer{{ID: strings.Repeat("c", 64), Image: "node:22", Name: "devcontainer", Agent: "claudecode"}})
	containerScan = func(context.Context) ([]foreignContainer, error) {
		scans.Add(1)
		return found.Load().([]foreignContainer), nil
	}
	must(t, e.m.Reconcile(t.Context()))
	must(t, e.m.Reconcile(t.Context()))
	got := auth.eventsOf(sandboxrelay.EventForeignContainer)
	if scans.Load() != 2 || len(got) != 1 || !strings.Contains(string(got[0].Payload), `"container_id":"cccccccccccc"`) ||
		!strings.Contains(string(got[0].Payload), `"harness":"claudecode"`) {
		t.Fatalf("scans %d, events %+v", scans.Load(), got)
	}
	if regs := auth.registrationsOf(sandboxrelay.EventForeignContainer); len(regs) != 1 || regs[0] != "" {
		t.Fatalf("posted under %q, want no registration", regs)
	}
	// Outside managed mode nothing is scanned.
	e.m.opts.Persist = e.persist
	must(t, e.m.Reconcile(t.Context()))
	if scans.Load() != 2 {
		t.Fatal("an unmanaged daemon looked into the user's containers")
	}
	e.m.opts.Persist = auth
	// The OpenShell gateway goes away: a new container is still reported.
	e.m.gwMu.RLock()
	gw := e.m.gw
	e.m.gwMu.RUnlock()
	down := errors.New("connection refused")
	e.m.opts.Connect = func(context.Context) (*Gateway, error) { return nil, down }
	e.m.forgetGateway(gw, down)
	found.Store([]foreignContainer{{ID: strings.Repeat("d", 64), Image: "node:22", Name: "other", Agent: "claudecode"}})
	advance(e.m.opts.ReconcileInterval)
	if err := e.m.Reconcile(t.Context()); err == nil {
		t.Fatal("reconcile without the OpenShell gateway succeeded")
	}
	e.m.reportWithoutGateway(t.Context()) // a reconnect right after: no scan
	if got := auth.eventsOf(sandboxrelay.EventForeignContainer); scans.Load() != 3 || len(got) != 2 ||
		!strings.Contains(string(got[1].Payload), `"container_id":"dddddddddddd"`) {
		t.Fatalf("with the OpenShell gateway down: scans %d, events %+v", scans.Load(), got)
	}
	commands := map[string]string{"claude": "claudecode"}
	if h, uid := agentProcess("PID ARGS\n12 node /usr/local/bin/claude --print\n", commands, false); h != "claudecode" || uid != -1 {
		t.Fatalf("agentProcess = %q, %d", h, uid)
	}
	if h, _ := agentProcess("PID ARGS\n12 /usr/bin/python3 app.py\n", commands, false); h != "" {
		t.Fatal("agentProcess found an agent in python")
	}
	if h, uid := agentProcess("PID UID COMMAND\n7 0 sleep 9\n12 94404077 claude\n", commands, true); h != "claudecode" || uid != 94404077 {
		t.Fatalf("agentProcess with uids = %q, %d", h, uid)
	}
}

// On a rootful engine every account in the docker group sees every
// container: one whose agent runs as another account whose sandbox daemon
// runs is that daemon's to report, never stamped with this person
// (GAP-0503). Root, an unknown uid and an account without a daemon are
// reported here, as are the person's own.
func TestManagedForeignContainersOfOtherAccounts(t *testing.T) {
	e, auth := managedEnv(t, nil)
	prev := sandboxDaemonUIDs
	sandboxDaemonUIDs = func() map[int]bool { return map[int]bool{1000: true, 94404089: true} }
	t.Cleanup(func() { sandboxDaemonUIDs = prev })
	containerScan = func(context.Context) ([]foreignContainer, error) {
		return []foreignContainer{
			{ID: strings.Repeat("a", 64), Name: "erins", Agent: "claudecode", UID: 94404089},
			{ID: strings.Repeat("b", 64), Name: "own", Agent: "claudecode", UID: 1000},
			{ID: strings.Repeat("c", 64), Name: "root", Agent: "claudecode", UID: 0},
			{ID: strings.Repeat("d", 64), Name: "unknown", Agent: "codex", UID: -1},
			{ID: strings.Repeat("e", 64), Name: "nodaemon", Agent: "claudecode", UID: 4242},
		}, nil
	}
	must(t, e.m.Reconcile(t.Context()))
	got := auth.eventsOf(sandboxrelay.EventForeignContainer)
	if len(got) != 4 {
		t.Fatalf("foreign container events = %+v, want 4", got)
	}
	for _, ev := range got {
		if strings.Contains(string(ev.Payload), "erins") {
			t.Fatalf("reported another account's container: %s", ev.Payload)
		}
	}
}

// stuckDeleteClient takes the deletes of the names in stuck without
// deleting them, as OpenShell did with a MicroVM still provisioning.
type stuckDeleteClient struct {
	openshell.Client
	stuck map[string]bool
}

func (c stuckDeleteClient) DeleteSandbox(ctx context.Context, name string) (*openshell.DeletionResult, error) {
	if c.stuck[name] {
		return &openshell.DeletionResult{Outcome: types.DeletionAccepted}, nil
	}
	return c.Client.DeleteSandbox(ctx, name)
}

// A foreign sandbox that outlives the delete OpenShell took is not
// announced removed: it is recorded once and the person told it is being
// removed, it is deleted again at every reconcile, and after
// foreignRemoveTries the person is told to remove it; once it goes nothing
// more is recorded (GAP-0264, GAP-0235).
func TestManagedForeignSandboxOutlivingItsDelete(t *testing.T) {
	e, auth := managedEnv(t, nil)
	_, err := e.client.CreateSandbox(t.Context(), "rawvm", &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{})
	must(t, err)
	must(t, e.fake.SetPhase(openshell.DefaultWorkspace, "rawvm", types.SandboxProvisioning))
	stuck := stuckDeleteClient{Client: e.gw.Client, stuck: map[string]bool{"rawvm": true}}
	e.gw.Client = stuck
	t.Cleanup(func() { e.gw.Client = stuck.Client })
	notReady := &types.StatusError{Code: types.ErrorConflict, Message: "sandbox must be Ready to stop (current phase: Provisioning)"}
	for range foreignRemoveTries {
		e.fake.FailNext(openshelltest.MethodStopSandbox, notReady)
		must(t, e.m.Reconcile(t.Context()))
	}
	if got := auth.eventsOf(sandboxrelay.EventForeignSandbox); len(got) != 1 || !strings.Contains(string(got[0].Payload), `"action":"stop"`) {
		t.Fatalf("foreign sandbox events = %+v", got)
	}
	feed := e.events("rawvm", sandboxapi.ActivityFinding, sandboxrelay.EventForeignSandbox)
	if len(feed) != 2 || !strings.Contains(feed[0].Message, "is being removed") ||
		!strings.Contains(feed[1].Message, "openshell sandbox delete rawvm") {
		t.Fatalf("feed = %+v", feed)
	}
	delete(stuck.stuck, "rawvm")
	e.fake.FailNext(openshelltest.MethodStopSandbox, notReady)
	must(t, e.m.Reconcile(t.Context()))
	if _, err := e.client.GetSandbox(t.Context(), "rawvm"); !openshell.IsNotFound(err) {
		t.Fatalf("the foreign sandbox is still there: %v", err)
	}
	must(t, e.m.Reconcile(t.Context()))
	if got := auth.eventsOf(sandboxrelay.EventForeignSandbox); len(got) != 1 {
		t.Fatalf("foreign sandbox events after it went = %+v", got)
	}
	if feed := e.events("rawvm", sandboxapi.ActivityFinding, sandboxrelay.EventForeignSandbox); len(feed) != 2 {
		t.Fatalf("feed after it went = %+v", feed)
	}
}

// allowed_credentials: the --llm credential's provider and any
// --credential binding must be allowed; [none] allows none; unset allows
// all. A create is refused before anything is imported, and a start of a
// sandbox made before the floor tightened is refused too.
func TestAllowedCredentials(t *testing.T) {
	for profile, provider := range map[string]string{
		profiles.ClaudeBedrockMantleID: "bedrock", profiles.CodexBedrockMantleID: "bedrock", profiles.BedrockMantleOpenAIID: "bedrock",
		profiles.AnthropicID: "anthropic", profiles.OpenCodeAnthropicID: "anthropic", profiles.CopilotAnthropicID: "anthropic",
		profiles.OpenAIID: "openai", profiles.OpenCodeOpenAIID: "openai", profiles.CopilotGitHubID: "github",
		profiles.ClaudeOAuthID: "claude-oauth", profiles.CursorID: "cursor", "": "",
	} {
		if got := credentialProvider(profile); got != provider {
			t.Errorf("credentialProvider(%q) = %q, want %q", profile, got, provider)
		}
	}
	only := func(names ...string) config.OpenShellAdminConfig {
		return config.OpenShellAdminConfig{AllowedCredentials: names}
	}
	for _, tc := range []struct {
		f       config.OpenShellAdminConfig
		llm     string
		custom  bool
		refused bool
	}{
		{config.OpenShellAdminConfig{}, profiles.AnthropicID, true, false},
		{only("bedrock"), profiles.ClaudeBedrockMantleID, false, false},
		{only("bedrock"), profiles.AnthropicID, false, true},
		{only("bedrock"), "", true, true},
		{only("bedrock", "credential"), "", true, false},
		{only(config.OpenShellCredentialsNone), "", false, false},
		{only(config.OpenShellCredentialsNone), profiles.ClaudeBedrockMantleID, false, true},
	} {
		v := credentialsRefusal(tc.f, tc.llm, tc.custom)
		if (v != nil) != tc.refused || (v != nil && (!v.Admin() || v.Constraint != "openshell.admin.allowed_credentials")) {
			t.Errorf("credentialsRefusal(%v, %q, %v) = %+v, want refused %v", tc.f.AllowedCredentials, tc.llm, tc.custom, v, tc.refused)
		}
	}
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Admin.AllowedCredentials = []string{"bedrock"} })
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "credbox",
		LLM: &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "dccert-block-marker"}}})
	if apiErr := wantCode(t, err, sandboxapi.CodeAdminViolation); !strings.Contains(apiErr.Detail, "anthropic") {
		t.Fatalf("refusal = %+v", apiErr)
	}
	if len(e.providers()) != 0 {
		t.Fatalf("a refused create imported providers: %v", e.providers())
	}
}

// addNetworkRule adds a rule through OpenShell's own API, as a person with
// the user's OpenShell credentials can.
func (e *harnessEnv) addNetworkRule(sandbox, rule, host string, port uint32) {
	e.t.Helper()
	_, err := e.client.MergePolicy(e.t.Context(), sandbox, []openshell.PolicyMergeOperation{{AddRule: &types.AddNetworkRule{
		RuleName: rule, Rule: types.NetworkPolicyRule{Name: rule, Endpoints: []types.PolicyNetworkEndpoint{{Host: host, Port: port}},
			Binaries: []types.PolicyNetworkBinary{{Path: "/usr/bin/curl"}}}}}}, openshell.PolicyUpdateOptions{})
	must(e.t, err)
}

// The floor that bounds a managed sandbox is its own resolved policy's (the
// profile its registration resolved), never the daemon's configuration:
// with no floor there, a profile floor that allows only Bedrock refuses an
// --llm anthropic create, and its user_approvals none removes a rule the
// person approved. A managed sandbox whose policy carries no floor gets
// none of it (closedFloor); outside managed mode openshell.admin bounds it.
func TestManagedFloorIsTheSandboxs(t *testing.T) {
	e, auth := managedEnv(t, func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileBalanced })
	e.live(sandboxapi.CreateRequest{Name: "floorbox"})
	e.register("floorbox")
	e.propose("floorbox", "user.example.org")
	e.draft("floorbox")
	asks := e.waitAsks("floorbox", 1)
	must(t, e.decide(asks[0].ID, approve))
	rule := ruleFor("user.example.org")
	eventually(t, "the person's rule", func() bool {
		return e.approvedRules("floorbox")[rule] == actorOperator && e.hasRule("floorbox", rule)
	})
	auth.profile.Store(&config.OpenShellAdminConfig{AllowedCredentials: []string{"bedrock"}, UserApprovals: config.OpenShellUserApprovalsNone})
	if !e.config().OpenShell.Admin.IsZero() {
		t.Fatal("the daemon's configuration carries a floor")
	}
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "credbox", Project: e.otherProject("cred"),
		LLM: &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "dccert-block-marker"}}})
	if apiErr := wantCode(t, err, sandboxapi.CodeAdminViolation); !strings.Contains(apiErr.Detail, "anthropic") {
		t.Fatalf("refusal = %+v", apiErr)
	}
	e.m.enforceAll(t.Context())
	if e.hasRule("floorbox", rule) {
		t.Fatal("the rule the person approved survived the profile's user_approvals none")
	}
	if !e.tel.removed(rule, policyReasonAdmin) {
		t.Fatal("the removed rule has no policy record")
	}
	auth.noFloor.Store(true)
	for _, eff := range []*packs.Effective{nil, {}} {
		if got := e.m.floor(eff); !reflect.DeepEqual(got, closedFloor()) {
			t.Fatalf("a managed floor without one of its own = %+v, want the closed floor", got)
		}
	}
	if v := credentialsRefusal(e.m.floor(nil), profiles.ClaudeBedrockMantleID, false); v == nil {
		t.Fatal("the closed floor hands over a credential")
	}
	if err := sandboxreg.CheckApprovals(e.m.floor(nil), sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeSession); err == nil {
		t.Fatal("the closed floor lets the person approve")
	}
	oss := newEnv(t, func(c *config.Config) { c.OpenShell.Admin.RequestAccess = "desk@example.com" })
	if got := oss.m.floor(nil); got.RequestAccess != "desk@example.com" {
		t.Fatalf("the floor outside managed mode = %+v, want openshell.admin", got)
	}
}

// A rule's name proves nothing on a managed daemon: a rule in DefenseClaw's
// name (defenseclaw_*) that it did not render, a provider rule of a
// provider not attached to the sandbox, and an edit of the endpoints of
// DefenseClaw's own egress rule are each foreign, removed and reported,
// and the repeat stops the sandbox; DefenseClaw's own rules and the rules
// of the providers it attached stay.
func TestManagedForeignReservedRules(t *testing.T) {
	e, auth := managedEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "resbox"})
	e.register("resbox")
	if !e.hasRule("resbox", policy.EgressRuleName) {
		t.Fatal("the sandbox has no egress rule")
	}
	box := e.boxOf("resbox")
	e.m.mu.Lock()
	providers := slices.Clone(box.rec.Providers)
	e.m.mu.Unlock()
	if len(providers) == 0 {
		t.Fatal("the sandbox has no providers")
	}
	attached := providerRulePrefix + strings.ReplaceAll(providers[0], "-", "_")
	e.addNetworkRule("resbox", attached, "api.example.org", 443)
	e.m.enforceAll(t.Context())
	if !e.hasRule("resbox", policy.EgressRuleName) || !e.hasRule("resbox", attached) || len(auth.eventsOf(sandboxrelay.EventForeignRule)) != 0 {
		t.Fatalf("DefenseClaw's own rules: egress %v, %s %v, foreign events %d", e.hasRule("resbox", policy.EgressRuleName),
			attached, e.hasRule("resbox", attached), len(auth.eventsOf(sandboxrelay.EventForeignRule)))
	}
	e.addNetworkRule("resbox", "defenseclaw_tunnel", "tunnel.example.net", 443)
	e.addNetworkRule("resbox", providerRulePrefix+"x", "tunnel.example.net", 443)
	e.m.enforceAll(t.Context())
	for _, rule := range []string{"defenseclaw_tunnel", providerRulePrefix + "x"} {
		if e.hasRule("resbox", rule) || !e.tel.removed(rule, policyReasonForeignRule) {
			t.Fatalf("foreign rule %s: kept %v", rule, e.hasRule("resbox", rule))
		}
	}
	if !e.hasRule("resbox", policy.EgressRuleName) || !e.hasRule("resbox", attached) {
		t.Fatal("a pass that removed foreign rules removed DefenseClaw's own")
	}
	if got := auth.eventsOf(sandboxrelay.EventForeignRule); len(got) != 1 || !strings.Contains(string(got[0].Payload), `"action":"removed"`) {
		t.Fatalf("foreign rule events = %+v", got)
	}
	// OpenShell's AddRule merges into the rule of that name.
	e.addNetworkRule("resbox", policy.EgressRuleName, "tunnel.example.net", 443)
	e.m.enforceAll(t.Context())
	if e.hasRule("resbox", policy.EgressRuleName) || !e.tel.removed(policy.EgressRuleName, policyReasonForeignRule) {
		t.Fatal("the altered egress rule was kept")
	}
	eventually(t, "the sandbox stopped for a repeat", func() bool {
		return e.get("resbox").Phase == string(audit.SandboxPhaseStopped)
	})
	e.m.tamperStops.Wait() // the stop has saved its record
	if got := auth.eventsOf(sandboxrelay.EventForeignRule); len(got) != 2 || !strings.Contains(string(got[1].Payload), `"action":"stopped"`) {
		t.Fatalf("foreign rule events = %+v", got)
	}
}

// A foreign sandbox found while none of the person's sandboxes is
// registered (the usual raw `openshell sandbox create`) is stopped at once
// and its record posted without a registration, so a person who only runs
// raw OpenShell is audited too (GAP-0235, GAP-0263); a record that needs a
// registration is kept for the next one. A sandbox the daemon created is
// not foreign while its bind is due, nor once the daemon names its
// registration (RegistrationLookup); past the bind window without one it
// is.
func TestManagedForeignSandboxBeforeAnyRegistration(t *testing.T) {
	e, auth := managedEnv(t, nil)
	_, err := e.client.CreateSandbox(t.Context(), "rawclaude", &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{})
	must(t, err)
	e.m.managedEvent(t.Context(), "", sandboxrelay.EventSettingsDrift, map[string]any{"field": "egress"})
	must(t, e.m.Reconcile(t.Context()))
	sb, err := e.client.GetSandbox(t.Context(), "rawclaude")
	must(t, err)
	if p := auditPhase(sb.Status.Phase); p != audit.SandboxPhaseStopped && p != audit.SandboxPhaseStopping {
		t.Fatalf("foreign sandbox is %s, want stopped", p)
	}
	if got := auth.registrationsOf(sandboxrelay.EventForeignSandbox); len(got) != 1 || got[0] != "" {
		t.Fatalf("the foreign sandbox went out under %q, want no registration", got)
	}
	if got := auth.eventsOf(sandboxrelay.EventForeignSandbox); len(got) != 1 || !strings.Contains(string(got[0].Payload), `"sandbox":"rawclaude"`) ||
		len(auth.eventsOf(sandboxrelay.EventSettingsDrift)) != 0 {
		t.Fatalf("foreign sandbox events = %+v, drift %+v", got, auth.eventsOf(sandboxrelay.EventSettingsDrift))
	}
	reg := sandboxreg.IDPrefix + strings.Repeat("b", sandboxreg.IDRandomChars)
	auth.set(func(a *fakeAuthority) { a.byName = map[string]string{"mine": reg} })
	e.live(sandboxapi.CreateRequest{Name: "mine"})
	e.live(sandboxapi.CreateRequest{Name: "pending", Project: e.otherProject("pending")})
	must(t, e.m.Reconcile(t.Context()))
	for _, name := range []string{"mine", "pending"} {
		if p := e.get(name).Phase; p != string(audit.SandboxPhaseReady) {
			t.Fatalf("the daemon's own sandbox %s is %s", name, p)
		}
	}
	if got := auth.registrationsOf(sandboxrelay.EventSettingsDrift); len(got) != 1 || got[0] != reg {
		t.Fatalf("the kept record went out under %v, want %s", got, reg)
	}
	if got := auth.eventsOf(sandboxrelay.EventForeignSandbox); len(got) != 1 {
		t.Fatalf("foreign sandbox events = %+v", got)
	}
	mine, b := e.boxOf("mine"), e.boxOf("pending")
	e.m.mu.Lock()
	recorded := mine.rec.RegistrationID
	b.rec.CreatedAt = time.Now().Add(-2 * registrationBindGrace)
	b.rec.ReadyAt = b.rec.CreatedAt
	e.m.mu.Unlock()
	if recorded != reg {
		t.Fatalf("the daemon's registration of mine is %q on its record", recorded)
	}
	must(t, e.m.Reconcile(t.Context()))
	sb, err = e.client.GetSandbox(t.Context(), "pending")
	must(t, err)
	if p := auditPhase(sb.Status.Phase); p != audit.SandboxPhaseStopped && p != audit.SandboxPhaseStopping {
		t.Fatalf("a sandbox never registered past its bind window is %s, want stopped", p)
	}
}

// A host-port ask's answer reaches the managed gateway, which judges it
// against the floor as it is now and records the person; its policy
// record names the person, not "operator".
func TestManagedHostPortAsksReachTheGateway(t *testing.T) {
	e, auth := managedEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "hpbox", HostPorts: []int{38830}})
	reg := e.register("hpbox")
	e.ocsf("hpbox", "CONFIG:PUBLISHED [INFO] Policy DNS mapped host.openshell.internal resolved=127.0.0.1 synthetic=198.18.0.2 ports=18971,18972 mapping_id=m1", time.Now())
	e.ocsf("hpbox", "NET:OPEN [MED] DENIED /usr/bin/curl(0) -> 198.18.0.2:38830 [reason:transparent_tcp_mapping_denied]", time.Now())
	ask := e.waitAsks("hpbox", 1)[0]
	auth.gatewayOnly.Store(&config.OpenShellAdminConfig{AllowHostPorts: boolPtr(false)})
	if _, err := e.m.DecideApproval(t.Context(), ask.ID, approve); !sandboxapi.IsCode(err, sandboxapi.CodeAdminViolation) {
		t.Fatalf("approve past the gateway's floor = %v", err)
	}
	auth.gatewayOnly.Store(nil)
	if _, err := e.m.DecideApproval(t.Context(), ask.ID, approve); err != nil {
		t.Fatalf("approve = %v", err)
	}
	eventually(t, "the host port rule", func() bool { return e.hasRule("hpbox", hostPortRule(38830)) })
	got := auth.decisions()
	if len(got) != 1 || got[0].Registration != reg || got[0].Kind != sandboxrelay.DecisionEgressAllow ||
		got[0].Host != openshellHostAlias || got[0].Scope != sandboxrelay.DecisionScopeSession {
		t.Fatalf("decisions = %+v, want the session answer for this computer", got)
	}
	eventually(t, "the rule's policy record", func() bool {
		return len(where(&e.tel.mu, &e.tel.policy, func(p audit.SandboxPolicyEvent) bool {
			return p.Operation == audit.SandboxPolicyRuleAdd && p.Target == openshellHostAlias && p.Actor == e.m.person()
		})) > 0
	})
}

// A foreign sandbox is announced to the person and recorded whatever
// registration the daemon holds: the one the batch would have gone out under
// may be one the managed gateway no longer knows, which refuses the whole
// batch and drops the record (GAP-0633).
func TestManagedForeignSandboxIsRecordedUnderAGoneRegistration(t *testing.T) {
	e, auth := managedEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "mine"})
	reg := e.register("mine")
	auth.set(func(a *fakeAuthority) { a.gone = map[string]bool{reg: true} })
	_, err := e.client.CreateSandbox(t.Context(), "rawvm", &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{})
	must(t, err)
	must(t, e.m.Reconcile(t.Context()))
	if got := e.events("rawvm", sandboxapi.ActivityFinding, sandboxrelay.EventForeignSandbox); len(got) != 1 {
		t.Fatalf("the person was not told: %+v", got)
	}
	got := auth.eventsOf(sandboxrelay.EventForeignSandbox)
	if len(got) != 1 || !strings.Contains(string(got[0].Payload), `"sandbox":"rawvm"`) {
		t.Fatalf("foreign sandbox events = %+v", got)
	}
	if regs := auth.registrationsOf(sandboxrelay.EventForeignSandbox); len(regs) != 1 || regs[0] != "" {
		t.Fatalf("the foreign sandbox went out under %q, want no registration", regs)
	}
}

// GAP-0674: a new sandbox follows the person's saved "always" decisions
// from its first request, before any reconcile refreshed them.
func TestManagedSavedDecisionsApplyToANewSandboxAtOnce(t *testing.T) {
	e, auth := managedEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "freshbox"})
	id := sandboxreg.IDPrefix + strings.Repeat("a", sandboxreg.IDRandomChars-len("freshbox")) + "freshbox"
	auth.set(func(a *fakeAuthority) {
		if a.saved == nil {
			a.saved = map[string][]sandboxrelay.Decision{}
		}
		a.saved[id] = []sandboxrelay.Decision{{ID: "dec-1", Registration: id, Kind: sandboxrelay.DecisionUnblock, Host: "webhook.site",
			Scope: sandboxrelay.DecisionScopeAlways}}
	})
	if reg := e.register("freshbox"); reg != id {
		t.Fatalf("registration %s, want %s", reg, id)
	}
	if !e.decideEgress("freshbox", "webhook.site").Allowed {
		t.Fatal("a saved always unblock does not reach a new sandbox before the next reconcile")
	}
}

// A registration the managed gateway no longer knows (revoked, expired)
// loses its saved decisions at the next reconcile; one the gateway could
// not answer for keeps them.
func TestManagedDecisionsOfAGoneRegistration(t *testing.T) {
	e, auth := managedEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "gonebox"})
	reg := e.register("gonebox")
	if _, err := e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "webhook.site", Sandbox: "gonebox", Always: true}); err != nil {
		t.Fatalf("always unblock = %v", err)
	}
	if !e.decideEgress("gonebox", "webhook.site").Allowed {
		t.Fatal("the kept unblock does not reach the decider")
	}
	auth.set(func(a *fakeAuthority) { a.down = true })
	must(t, e.m.Reconcile(t.Context()))
	if !e.decideEgress("gonebox", "webhook.site").Allowed {
		t.Fatal("a gateway out of reach took the saved decisions back")
	}
	auth.set(func(a *fakeAuthority) { a.down, a.gone = false, map[string]bool{reg: true} })
	must(t, e.m.Reconcile(t.Context()))
	if e.decideEgress("gonebox", "webhook.site").Allowed {
		t.Fatal("a revoked registration's unblock still opens the host")
	}
}

// GAP-0609: on a managed computer an "always" unblock without --sandbox is
// kept through the person's one sandbox; with none it says to start one,
// and with several it asks for the one whose policy checks it.
func TestManagedAlwaysUnblockFindsThePersonsSandbox(t *testing.T) {
	e, auth := managedEnv(t, nil)
	always := sandboxapi.UnblockRequest{Host: "webhook.site", Always: true}
	if _, err := e.m.Unblock(t.Context(), always); err == nil || !strings.Contains(err.Error(), "none is running") {
		t.Fatalf("always unblock without a sandbox = %v", err)
	}
	e.live(sandboxapi.CreateRequest{Name: "onebox"})
	reg := e.register("onebox")
	res, err := e.m.Unblock(t.Context(), always)
	if err != nil || !res.Persisted || res.Sandbox != "onebox" {
		t.Fatalf("always unblock = %+v, %v", res, err)
	}
	if got := auth.decisions(); len(got) != 1 || got[0].Registration != reg || got[0].Scope != sandboxrelay.DecisionScopeAlways {
		t.Fatalf("decisions = %+v, want the always unblock through onebox", got)
	}
	e.live(sandboxapi.CreateRequest{Name: "twobox", Copy: true})
	e.register("twobox")
	always.Host = "pastebin.com"
	if _, err := e.m.Unblock(t.Context(), always); err == nil || !strings.Contains(err.Error(), "--sandbox NAME --always") {
		t.Fatalf("always unblock with two sandboxes = %v", err)
	}
	if _, err := e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "pastebin.com", Sandbox: "twobox", Always: true}); err != nil {
		t.Fatalf("always unblock naming the sandbox = %v", err)
	}
}
