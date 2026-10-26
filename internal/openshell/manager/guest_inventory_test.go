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
	"sync/atomic"
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// homeGatewayAt has e's manager open own, the gateway a record names, as
// Options.GatewayAt does a registration, unless down says it does not
// answer. Every other registration is unknown.
func homeGatewayAt(e *harnessEnv, own *Gateway, down *atomic.Bool) {
	e.m.opts.GatewayAt = func(_ context.Context, name, _ string) (*Gateway, error) {
		if down.Load() || name != own.Name {
			return nil, errors.New("connection refused")
		}
		g := *own
		return &g, nil
	}
}

// forgetReads has the next account read every guest's place again, as it
// does once a read is proofFresh old.
func forgetReads(e *harnessEnv) {
	e.m.mu.Lock()
	defer e.m.mu.Unlock()
	for _, b := range e.m.boxes {
		b.read.at = time.Time{}
	}
}

// guestAccount is the status's unprotected entry for name (nil when none),
// whether a create beside it is refused naming it, and its view's warnings.
func guestAccount(t *testing.T, e *harnessEnv, name string) (entry *sandboxapi.UnprotectedSandbox, refusal string, warnings []string) {
	t.Helper()
	st, err := e.m.Status(t.Context())
	must(t, err)
	for i := range st.Unprotected {
		if st.Unprotected[i].Name == name {
			entry = &st.Unprotected[i]
		}
	}
	if err := e.m.legacyRunRefusal(t.Context(), ""); err != nil && strings.Contains(err.Error(), name) {
		refusal = err.Error() + " " + sandboxapi.AsError(err).Detail
	}
	b := e.boxOf(name)
	e.m.mu.Lock()
	v := e.m.view(b)
	e.m.mu.Unlock()
	return entry, refusal, v.Warnings
}

func hasPrefix(list []string, prefix string) bool {
	for _, s := range list {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// GAP-1089 (G-openshell continuation 2): the account of a guest followed
// whatever gateway DefenseClaw was connected to. A contained VM missing
// from that one stayed named, and every new run refused, after its own
// gateway had deleted it, since nothing read that gateway; a legacy
// session no lookup had found since the daemon started was not named at
// all. The guest inventory reads each guest at the place its record names:
// its own gateway's word decides, once read; a guest it cannot read is kept
// as last seen running, and one never seen is unknown. Both refuse new
// runs, and none is stopped.
func TestTheGuestInventoryReadsEveryGuestWhereItLives(t *testing.T) {
	t.Run("a contained VM on its own gateway", func(t *testing.T) {
		e := newVMEnv(t, nil)
		b := containedVM(t, e, "vmaway")
		own := e.gw
		var down atomic.Bool
		homeGatewayAt(e, own, &down)
		away, _ := awayGateway(e)
		switchGateway(t, e, away)
		stops := e.fake.Calls(openshelltest.MethodStopSandbox)

		entry, refusal, warnings := guestAccount(t, e, "vmaway")
		if entry == nil || entry.Reason != sandboxapi.UnprotectedContained || entry.Phase != string(audit.SandboxPhaseReady) ||
			!strings.Contains(entry.Detail, "connect DefenseClaw to that gateway") || refusal == "" || !hasPrefix(warnings, containedUnprotected) {
			t.Fatalf("running on its own gateway: entry %+v, refusal %q, warnings %q", entry, refusal, warnings)
		}

		// Its own gateway deleted it: no longer named, and runs go ahead.
		_, err := e.client.DeleteSandbox(t.Context(), "vmaway")
		must(t, err)
		forgetReads(e)
		if entry, refusal, _ := guestAccount(t, e, "vmaway"); entry != nil || refusal != "" {
			t.Fatalf("its own gateway says it is gone, yet: entry %+v, refusal %q", entry, refusal)
		}
		// A gateway that stops answering does not bring a gone guest back.
		down.Store(true)
		forgetReads(e)
		if entry, refusal, _ := guestAccount(t, e, "vmaway"); entry != nil || refusal != "" {
			t.Fatalf("a gone guest whose gateway no longer answers: entry %+v, refusal %q", entry, refusal)
		}
		e.m.mu.Lock()
		place := b.rec.Gateway
		e.m.mu.Unlock()
		if place != own.Name || e.fake.Calls(openshelltest.MethodStopSandbox) != stops {
			t.Fatalf("record place %q, %d stops", place, e.fake.Calls(openshelltest.MethodStopSandbox)-stops)
		}
	})

	t.Run("a contained VM whose gateway does not answer", func(t *testing.T) {
		e := newVMEnv(t, nil)
		containedVM(t, e, "vmdown")
		var down atomic.Bool
		down.Store(true)
		homeGatewayAt(e, e.gw, &down)
		away, _ := awayGateway(e)
		switchGateway(t, e, away)
		entry, refusal, warnings := guestAccount(t, e, "vmdown")
		if entry == nil || entry.Reason != sandboxapi.UnprotectedContained || refusal == "" || !hasPrefix(warnings, containedUnprotected) {
			t.Fatalf("last seen running, its gateway unread: entry %+v, refusal %q, warnings %q", entry, refusal, warnings)
		}
	})

	t.Run("a legacy session of a restarted daemon", func(t *testing.T) {
		e, _ := legacyGuest(t, "oldaway", true, nil)
		own := e.gw
		// A restarted daemon: no lookup has found it yet.
		e.m = e.newManager()
		var down atomic.Bool
		down.Store(true)
		homeGatewayAt(e, own, &down)
		away, _ := awayGateway(e)
		e.gw = away

		entry, refusal, warnings := guestAccount(t, e, "oldaway")
		if entry == nil || entry.Reason != sandboxapi.UnprotectedUnknown || entry.Stop != "" || entry.Phase != string(audit.SandboxPhaseUnknown) ||
			!strings.Contains(entry.Detail, "could not read (connection refused)") ||
			!strings.Contains(refusal, "("+unknownUnprotected+")") || !hasPrefix(warnings, unknownUnprotected) {
			t.Fatalf("never seen, its gateway unread: entry %+v, refusal %q, warnings %q", entry, refusal, warnings)
		}

		down.Store(false)
		forgetReads(e)
		entry, refusal, warnings = guestAccount(t, e, "oldaway")
		if entry == nil || entry.Reason != "" || entry.Phase != string(audit.SandboxPhaseReady) || entry.Stop != "defenseclaw sandbox stop oldaway" ||
			!strings.Contains(refusal, "("+legacyUnprotected+")") || !hasPrefix(warnings, legacyUnprotected) {
			t.Fatalf("read running on its own gateway: entry %+v, refusal %q, warnings %q", entry, refusal, warnings)
		}

		// Its user stopped it there: released.
		_, err := e.client.StopSandbox(t.Context(), "oldaway")
		must(t, err)
		forgetReads(e)
		if entry, refusal, _ := guestAccount(t, e, "oldaway"); entry != nil || refusal != "" {
			t.Fatalf("stopped on its own gateway: entry %+v, refusal %q", entry, refusal)
		}
	})
}

// GAP-1085: after a restart the daemon knew no phase of a sandbox until its
// first reconcile, so a legacy session still running on an old supervisor
// was left out of the status and a new run was let through. The account
// now asks the gateway first, and one the gateway cannot answer for is
// unknown, which refuses, until it does.
func TestARestartedDaemonAccountsForALegacySessionBeforeItsFirstReconcile(t *testing.T) {
	e, _ := legacyGuest(t, "oldsession", false, nil)
	e.m = e.newManager()
	entry, refusal, _ := guestAccount(t, e, "oldsession")
	if entry == nil || entry.Reason != "" || entry.Phase != string(audit.SandboxPhaseReady) || refusal == "" {
		t.Fatalf("a ready legacy session, before any reconcile: entry %+v, refusal %q", entry, refusal)
	}

	e.m = e.newManager()
	e.fake.Intercept(func(method string) error {
		if method == openshelltest.MethodGetSandbox {
			return &types.StatusError{Code: types.ErrorInternal, Message: "the gateway is busy"}
		}
		return nil
	})
	entry, refusal, _ = guestAccount(t, e, "oldsession")
	e.fake.Intercept(nil)
	if entry == nil || entry.Reason != sandboxapi.UnprotectedUnknown || !strings.Contains(entry.Detail, "has not said whether it runs") ||
		!strings.Contains(refusal, unknownUnprotected) {
		t.Fatalf("a legacy session the gateway cannot answer for: entry %+v, refusal %q", entry, refusal)
	}

	_, err := e.client.StopSandbox(t.Context(), "oldsession")
	must(t, err)
	e.m = e.newManager()
	if entry, refusal, _ := guestAccount(t, e, "oldsession"); entry != nil || refusal != "" {
		t.Fatalf("a stopped legacy session: entry %+v, refusal %q", entry, refusal)
	}
}

// GAP-1089: a sandbox labelled for this data dir under the name of a box
// that recorded another sandbox's ID (one on another gateway than the
// box's) was adopted as that box by the reconcile: it took the other
// sandbox's phase and moved the record to this gateway, which hid the
// guest where it runs. A box is one guest: the other sandbox is not it.
func TestAReconcileDoesNotTakeAnotherSandboxForAGuestOfTheSameName(t *testing.T) {
	e := newVMEnv(t, nil)
	b := containedVM(t, e, "twin")
	own := e.gw
	var down atomic.Bool
	homeGatewayAt(e, own, &down)
	away, other := awayGateway(e)
	// The fake gateway gives sandboxes no IDs: the box records one and the
	// twin gets another.
	e.m.mu.Lock()
	b.rec.ID = "id-twin"
	e.m.mu.Unlock()
	labels := map[string]string{LabelManaged: "true", LabelOwner: e.owner}
	_, err := other.SDK().Sandboxes().Create(t.Context(), openshell.DefaultWorkspace, "twin", &types.SandboxSpec{}, labels)
	must(t, err)
	twin, err := away.Client.GetSandbox(t.Context(), "twin")
	must(t, err)
	twin.ID = "id-other-twin"
	other.SDK().AddSandbox(openshell.DefaultWorkspace, twin)
	switchGateway(t, e, away)
	must(t, e.m.Reconcile(t.Context()))
	e.m.mu.Lock()
	place, id := b.rec.Gateway, b.rec.ID
	adopted := b.sb != nil && b.sb.ID == twin.ID
	e.m.mu.Unlock()
	if place != own.Name || id != "id-twin" || adopted {
		t.Fatalf("the reconcile took the other gateway's twin for the guest: record place %q, id %q, adopted %v", place, id, adopted)
	}
	if entry, refusal, _ := guestAccount(t, e, "twin"); entry == nil || entry.Reason != sandboxapi.UnprotectedContained || refusal == "" {
		t.Fatalf("the guest on its own gateway: entry %+v, refusal %q", entry, refusal)
	}
}

// G-openshell review (continuation 2, loop round 2): a read of a guest's
// own gateway, taken while DefenseClaw was connected to another one, was
// outranked by the phase cached before the switch once DefenseClaw
// connected back. A guest its gateway had deleted, or its user had stopped
// there, was named running and refused every new run until a reconcile,
// and one its user had started there was not named. The newest word of the
// guest's own place decides: a read no lookup of that place, or phase given
// there, came after; else the lookups. None is stopped.
func TestTheNewestWordOfAGuestsOwnGatewayDecidesAfterASwitchBack(t *testing.T) {
	t.Run("a contained VM its own gateway deleted", func(t *testing.T) {
		e := newVMEnv(t, nil)
		containedVM(t, e, "vmback")
		own := e.gw
		var down atomic.Bool
		homeGatewayAt(e, own, &down)
		away, _ := awayGateway(e)
		switchGateway(t, e, away)
		_, err := e.client.DeleteSandbox(t.Context(), "vmback")
		must(t, err)
		if entry, refusal, _ := guestAccount(t, e, "vmback"); entry != nil || refusal != "" {
			t.Fatalf("its own gateway says it is gone, read from another: entry %+v, refusal %q", entry, refusal)
		}
		// A failed read of its gateway keeps the proof, on whichever gateway
		// DefenseClaw connects to next.
		down.Store(true)
		forgetReads(e)
		if entry, refusal, _ := guestAccount(t, e, "vmback"); entry != nil || refusal != "" {
			t.Fatalf("a gone guest whose gateway no longer answers: entry %+v, refusal %q", entry, refusal)
		}
		stops := e.fake.Calls(openshelltest.MethodStopSandbox)
		switchGateway(t, e, own)
		if entry, refusal, warnings := guestAccount(t, e, "vmback"); entry != nil || refusal != "" || hasPrefix(warnings, containedUnprotected) {
			t.Fatalf("back on the gateway that deleted it: entry %+v, refusal %q, warnings %q", entry, refusal, warnings)
		}
		if n := e.fake.Calls(openshelltest.MethodStopSandbox) - stops; n != 0 {
			t.Fatalf("%d stops", n)
		}
	})

	t.Run("a legacy session its user stopped there", func(t *testing.T) {
		e, _ := legacyGuest(t, "oldstop", true, nil)
		own := e.gw
		var down atomic.Bool
		homeGatewayAt(e, own, &down)
		away, _ := awayGateway(e)
		switchGateway(t, e, away)
		if entry, refusal, _ := guestAccount(t, e, "oldstop"); entry == nil || refusal == "" {
			t.Fatalf("running on its own gateway, read from another: entry %+v, refusal %q", entry, refusal)
		}
		_, err := e.client.StopSandbox(t.Context(), "oldstop")
		must(t, err)
		forgetReads(e)
		if entry, refusal, _ := guestAccount(t, e, "oldstop"); entry != nil || refusal != "" {
			t.Fatalf("stopped on its own gateway, read from another: entry %+v, refusal %q", entry, refusal)
		}
		switchGateway(t, e, own)
		if entry, refusal, _ := guestAccount(t, e, "oldstop"); entry != nil || refusal != "" {
			t.Fatalf("back on the gateway it was stopped on: entry %+v, refusal %q", entry, refusal)
		}
		// A lookup of its place after the read outranks it: started there
		// again, the next get finds it running.
		_, err = e.client.StartSandbox(t.Context(), "oldstop")
		must(t, err)
		_, err = e.m.Get(t.Context(), "oldstop")
		must(t, err)
		if entry, refusal, _ := guestAccount(t, e, "oldstop"); entry == nil || entry.Phase != string(audit.SandboxPhaseReady) || refusal == "" {
			t.Fatalf("found running by a later lookup: entry %+v, refusal %q", entry, refusal)
		}
	})

	t.Run("a legacy session its user started there", func(t *testing.T) {
		e, _ := legacyGuest(t, "oldstart", false, nil)
		_, err := e.m.Stop(t.Context(), "oldstart")
		must(t, err)
		if entry, refusal, _ := guestAccount(t, e, "oldstart"); entry != nil || refusal != "" {
			t.Fatalf("stopped: entry %+v, refusal %q", entry, refusal)
		}
		own := e.gw
		var down atomic.Bool
		homeGatewayAt(e, own, &down)
		away, _ := awayGateway(e)
		switchGateway(t, e, away)
		_, err = e.client.StartSandbox(t.Context(), "oldstart")
		must(t, err)
		if entry, refusal, _ := guestAccount(t, e, "oldstart"); entry == nil || entry.Reason != "" || refusal == "" {
			t.Fatalf("started on its own gateway, read from another: entry %+v, refusal %q", entry, refusal)
		}
		switchGateway(t, e, own)
		if entry, refusal, _ := guestAccount(t, e, "oldstart"); entry == nil || entry.Reason != "" || entry.Phase != string(audit.SandboxPhaseReady) || refusal == "" {
			t.Fatalf("back on the gateway it was started on: entry %+v, refusal %q", entry, refusal)
		}
	})
}

// G-openshell review (continuation 2, loop round 3): a lookup of a guest's
// own gateway that had nothing of it proved it gone only until a lookup of
// another gateway: the proof was kept as where the last lookup missed it,
// which the next lookup elsewhere (a get, a stop or get of a name another
// sandbox holds there, a reconcile) overwrote. On that gateway, with its
// own one not answering, the guest was named again, and back on its own
// gateway the phase cached before it went named it running: either way
// every new run was refused until a reconcile of its own gateway. Its
// identity does not come back, so the guest keeps the proof whatever
// gateway DefenseClaw is connected to and whatever a lookup elsewhere
// finds. None is stopped.
func TestAGuestItsOwnGatewayProvedGoneStaysGoneOnEveryGateway(t *testing.T) {
	get := func(e *harnessEnv, name string) { _, _ = e.m.Get(e.t.Context(), name) }
	for _, kind := range []struct {
		name  string
		guest func(t *testing.T, name string) *harnessEnv
	}{
		{"a contained VM", func(t *testing.T, name string) *harnessEnv {
			e := newVMEnv(t, nil)
			containedVM(t, e, name)
			return e
		}},
		{"a legacy docker session", func(t *testing.T, name string) *harnessEnv {
			e, _ := legacyGuest(t, name, false, nil)
			return e
		}},
		{"a legacy MicroVM session", func(t *testing.T, name string) *harnessEnv {
			e, _ := legacyGuest(t, name, true, nil)
			return e
		}},
	} {
		for _, away := range []struct {
			name     string
			replaced bool // the other gateway has another sandbox under the name
			look     func(e *harnessEnv, name string)
		}{
			{"get", false, get},
			{"get of a name another sandbox has there", true, get},
			{"stop of a name another sandbox has there", true, func(e *harnessEnv, name string) { _, _ = e.m.Stop(e.t.Context(), name) }},
			{"reconcile", false, func(e *harnessEnv, _ string) { _ = e.m.Reconcile(e.t.Context()) }},
		} {
			t.Run(kind.name+", then a "+away.name+" on another gateway", func(t *testing.T) {
				const name = "gonehome"
				e := kind.guest(t, name)
				b := e.boxOf(name)
				if entry, refusal, _ := guestAccount(t, e, name); entry == nil || refusal == "" {
					t.Fatalf("the scenario was not reached: running, it is not named (entry %+v, refusal %q)", entry, refusal)
				}
				// Its own gateway proves it gone: deleted there, then a get.
				_, err := e.client.DeleteSandbox(t.Context(), name)
				must(t, err)
				get(e, name)
				if entry, refusal, _ := guestAccount(t, e, name); entry != nil || refusal != "" {
					t.Fatalf("its own gateway says it is gone: entry %+v, refusal %q", entry, refusal)
				}
				own := e.gw
				var down atomic.Bool
				down.Store(true) // nothing reads its own gateway from elsewhere
				homeGatewayAt(e, own, &down)
				gw, other := awayGateway(e)
				if away.replaced {
					_, err := other.SDK().Sandboxes().Create(t.Context(), openshell.DefaultWorkspace, name, &types.SandboxSpec{}, nil)
					must(t, err)
				}
				stops := e.fake.Calls(openshelltest.MethodStopSandbox)
				switchGateway(t, e, gw)
				away.look(e, name)
				e.m.mu.Lock()
				elsewhere := b.elsewhere
				e.m.mu.Unlock()
				if elsewhere == "" {
					t.Fatal("the scenario was not reached: the lookup elsewhere did not find it missing there")
				}
				if entry, refusal, _ := guestAccount(t, e, name); entry != nil || refusal != "" {
					t.Errorf("gone from its own gateway, then missing from another: entry %+v, refusal %q", entry, refusal)
				}
				switchGateway(t, e, own)
				if entry, refusal, warnings := guestAccount(t, e, name); entry != nil || refusal != "" ||
					hasPrefix(warnings, containedUnprotected) || hasPrefix(warnings, unknownUnprotected) {
					t.Fatalf("back on the gateway that proved it gone: entry %+v, refusal %q, warnings %q", entry, refusal, warnings)
				}
				if n := e.fake.Calls(openshelltest.MethodStopSandbox) - stops; n != 0 {
					t.Fatalf("%d stops", n)
				}
			})
		}
	}

	// A word of its own gateway after the read that proved it gone (a
	// phase given there) does not bring it back either.
	t.Run("a read proved it gone, then a phase given on its own gateway", func(t *testing.T) {
		const name = "goneread"
		e := newVMEnv(t, nil)
		b := containedVM(t, e, name)
		own := e.gw
		var down atomic.Bool
		homeGatewayAt(e, own, &down)
		gw, _ := awayGateway(e)
		switchGateway(t, e, gw)
		_, err := e.client.DeleteSandbox(t.Context(), name)
		must(t, err)
		if entry, refusal, _ := guestAccount(t, e, name); entry != nil || refusal != "" {
			t.Fatalf("its own gateway says it is gone, read from another: entry %+v, refusal %q", entry, refusal)
		}
		down.Store(true)
		switchGateway(t, e, own)
		_, err = e.m.gateway(t.Context())
		must(t, err)
		e.m.mu.Lock()
		heardLocked(b, e.m.lastGw.Load())
		e.m.mu.Unlock()
		if entry, refusal, _ := guestAccount(t, e, name); entry != nil || refusal != "" {
			t.Fatalf("proved gone by a read, then a word of its own gateway: entry %+v, refusal %q", entry, refusal)
		}
	})
}
