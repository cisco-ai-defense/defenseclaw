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
