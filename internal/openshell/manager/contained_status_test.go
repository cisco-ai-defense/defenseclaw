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
	"slices"
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

// wantNamedUnprotected checks that the status names the guest name, in
// phase, unprotected for kind (sandboxapi.UnprotectedContained, or "" for
// a legacy one) with the command stop, that a create beside it is refused
// naming it, and that its view warns.
func wantNamedUnprotected(t *testing.T, e *harnessEnv, name string, phase audit.SandboxPhase, kind, stop string) {
	t.Helper()
	st, err := e.m.Status(t.Context())
	must(t, err)
	if len(st.Unprotected) != 1 || st.Unprotected[0] != (sandboxapi.UnprotectedSandbox{Name: name, Phase: string(phase),
		Stop: "defenseclaw sandbox " + stop + " " + name, Reason: kind}) {
		t.Fatalf("unprotected = %+v", st.Unprotected)
	}
	words := legacyUnprotected
	if kind == sandboxapi.UnprotectedContained {
		words = containedUnprotected
	}
	_, err = e.tryCreate(sandboxapi.CreateRequest{Name: "beside", Copy: true, Project: e.otherProject("beside")})
	if apiErr := wantCode(t, err, sandboxapi.CodeConflict); !strings.Contains(apiErr.Message, "while "+name+" runs ("+words+")") {
		t.Fatalf("create beside an unprotected guest = %+v", apiErr)
	}
	b := e.boxOf(name)
	e.m.mu.Lock()
	v := e.m.view(b)
	e.m.mu.Unlock()
	warned := false
	for _, w := range v.Warnings {
		warned = warned || strings.HasPrefix(w, words)
	}
	if !warned {
		t.Fatalf("the view does not say it is unprotected: %q", v.Warnings)
	}
}

// containedVM creates the MicroVM name and contains it: a security stop
// (a revoked registration) whose sync fails. Its guest's sync keeps
// failing.
func containedVM(t *testing.T, e *harnessEnv, name string) *box {
	t.Helper()
	e.create(sandboxapi.CreateRequest{Name: name, Copy: true})
	e.fake.HandleExec(e.workloadChecks(nil, guestAnswers("exited\n", true)))
	_, err := e.m.Stop(WithEmergencyStop(context.Background(), "its managed registration was revoked"), name)
	wantCode(t, err, sandboxapi.CodeUnsynced)
	b := e.boxOf(name)
	e.m.mu.Lock()
	contained := b.rec.Contained
	e.m.mu.Unlock()
	if contained == "" {
		t.Fatal("the scenario was not reached: the MicroVM is not contained")
	}
	return b
}

// GAP-0902 review (loop round 4): the status, the run refusal and the view
// each decided on their own which guest to leave out, and a contained VM
// was left out while it may still run: in the deleting phase a delete
// that failed leaves when OpenShell cannot be asked after it, and when it
// was missing from a gateway or compute driver other than the one it was
// created on, which proves nothing. One account (unprotectedKind) now
// serves all three, and only the gateway the VM runs on saying it is gone,
// stopped or deleted releases it.
func TestEveryAccountNamesAContainedVMUntilOpenShellShowsItGone(t *testing.T) {
	vm := string(openshell.DriverVM)
	contained := record{Name: "vm", Driver: vm, SessionRelease: openshell.SupportedMin, Contained: "its start failed"}
	legacy := record{Name: "vm", Driver: vm, SessionRelease: "0.1.3"}
	type flags struct {
		phase                                      audit.SandboxPhase
		missing, gone, deleted, retained, creating bool
		elsewhere                                  string
	}
	ready := audit.SandboxPhaseReady
	for _, c := range []struct {
		name string
		rec  record
		box  flags
		want string
	}{
		{name: "contained, ready", rec: contained, box: flags{phase: ready}, want: sandboxapi.UnprotectedContained},
		{name: "contained, deleting", rec: contained, box: flags{phase: audit.SandboxPhaseDeleting}, want: sandboxapi.UnprotectedContained},
		{name: "contained, missing elsewhere", rec: contained, box: flags{phase: ready, missing: true, elsewhere: "gateway other"},
			want: sandboxapi.UnprotectedContained},
		{name: "contained, gone from its gateway", rec: contained, box: flags{phase: ready, missing: true, gone: true}},
		{name: "contained, stopped", rec: contained, box: flags{phase: audit.SandboxPhaseStopped}},
		{name: "contained, deleted", rec: contained, box: flags{phase: ready, deleted: true}},
		{name: "contained, retained", rec: contained, box: flags{phase: ready, retained: true}},
		{name: "contained, creating", rec: contained, box: flags{phase: ready, creating: true}},
		{name: "legacy, ready", rec: legacy, box: flags{phase: ready}, want: unprotectedLegacy},
		{name: "legacy, missing elsewhere", rec: legacy, box: flags{phase: ready, missing: true, elsewhere: "gateway other"},
			want: unprotectedLegacy},
		{name: "legacy, gone from its gateway", rec: legacy, box: flags{phase: ready, missing: true, gone: true}},
		{name: "protected", rec: record{Name: "vm", Driver: vm, SessionRelease: openshell.SupportedMin}, box: flags{phase: ready}},
	} {
		b := &box{rec: c.rec, phase: c.box.phase, missing: c.box.missing, gone: c.box.gone, deleted: c.box.deleted, retained: c.box.retained,
			creating: c.box.creating, elsewhere: c.box.elsewhere}
		if got, _ := unprotectedKind(b, nil); got != c.want {
			t.Errorf("%s: unprotectedKind = %q, want %q", c.name, got, c.want)
		}
	}

	t.Run("a failed delete OpenShell cannot be asked about", func(t *testing.T) {
		e := newVMEnv(t, nil)
		containedVM(t, e, "vmdel")
		var deleting atomic.Bool
		e.fake.Intercept(func(method string) error {
			switch {
			case method == openshelltest.MethodDeleteSandbox:
				deleting.Store(true)
				return &types.StatusError{Code: types.ErrorInternal, Message: "the gateway is busy"}
			case method == openshelltest.MethodGetSandbox && deleting.Load():
				return &types.StatusError{Code: types.ErrorInternal, Message: "the gateway is busy"}
			}
			return nil
		})
		if _, err := e.m.Delete(t.Context(), "vmdel", sandboxapi.DeleteRequest{}); err == nil {
			t.Fatal("the delete OpenShell refused succeeded")
		}
		// GAP-1084: the delete OpenShell refused leaves the VM as it was,
		// in a phase DefenseClaw does not know, which holds its compute:
		// not DefenseClaw's own deleting, which let a stop skip the sync
		// and the status count it idle for the gateway's stop.
		b := e.boxOf("vmdel")
		e.m.mu.Lock()
		phase := b.phase
		e.m.mu.Unlock()
		if phase != audit.SandboxPhaseUnknown {
			t.Fatalf("after a delete OpenShell refused and cannot be asked about: phase %q", phase)
		}
		e.fake.Intercept(nil)
		wantNamedUnprotected(t, e, "vmdel", audit.SandboxPhaseUnknown, sandboxapi.UnprotectedContained, "stop")
		if st, err := e.m.Status(t.Context()); err != nil || st.Live == nil || *st.Live != 1 {
			t.Fatalf("its VM is not counted live: %+v, %v", st, err)
		}
		stops := e.fake.Calls(openshelltest.MethodStopSandbox)
		_, err := e.m.Stop(t.Context(), "vmdel")
		wantCode(t, err, sandboxapi.CodeUnsynced)
		if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
			t.Fatal("a stop ended it without the sync")
		}
	})

	t.Run("missing from another gateway", func(t *testing.T) {
		e := newVMEnv(t, nil)
		b := containedVM(t, e, "vmaway")
		e.m.mu.Lock()
		b.missing, b.elsewhere = true, "gateway other (https://other:8080, workspace -)"
		e.m.mu.Unlock()
		wantNamedUnprotected(t, e, "vmaway", audit.SandboxPhaseReady, sandboxapi.UnprotectedContained, "stop")
		// Its own gateway no longer having it is what releases it.
		e.m.mu.Lock()
		b.missing, b.elsewhere, b.gone = true, "", true
		e.m.mu.Unlock()
		if st, err := e.m.Status(t.Context()); err != nil || len(st.Unprotected) != 0 {
			t.Fatalf("a contained VM its gateway no longer has is named: %+v, %v", st, err)
		}
	})
}

// GAP-0902 review (loop round 4): a stop synced a MicroVM's disk only when
// the sandbox was ready. One in another phase that may still run its VM (a
// contained one whose start OpenShell could not be asked about after it,
// which the status tells the user to stop, or one whose phase a restarted
// daemon has not learned) was stopped with no sync at all: by the user's
// stop, without asking, and by a security stop and the stop-sandboxes of
// a sign-out alike. Its disk is now synced first in every such phase, and
// a sync that fails holds the stop back as for a ready one.
func TestAStopOfAMicroVMThatIsNotReadySyncsItFirst(t *testing.T) {
	for _, phase := range []audit.SandboxPhase{audit.SandboxPhaseStarting, audit.SandboxPhaseProvisioning,
		audit.SandboxPhaseStopping, audit.SandboxPhaseUnknown, ""} {
		t.Run("phase="+string(phase), func(t *testing.T) {
			e := newVMEnv(t, nil)
			e.create(sandboxapi.CreateRequest{Name: "vmu", Copy: true, Project: e.otherProject("vmu")})
			// A contained one, which its user stops as the status says.
			b := containedVM(t, e, "vmc")
			e.m.mu.Lock()
			b.phase = phase
			e.m.mu.Unlock()
			stops := e.fake.Calls(openshelltest.MethodStopSandbox)
			syncs := 0
			e.fake.HandleExec(func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
				if len(call.Command) > 0 && call.Command[0] == "/bin/sync" {
					syncs++
					return openshelltest.ExecResponse{Err: context.DeadlineExceeded}
				}
				return openshelltest.ExecResponse{Stdout: []byte("exited\n")}
			})
			_, err := e.m.Stop(context.Background(), "vmc")
			wantCode(t, err, sandboxapi.CodeUnsynced)
			if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops || syncs == 0 {
				t.Fatalf("the user's stop of a contained MicroVM in %q: %d stop calls, %d syncs", phase, got-stops, syncs)
			}

			// An uncontained one, which a lost listener's stop must contain
			// rather than stop.
			u := e.boxOf("vmu")
			e.m.mu.Lock()
			u.phase = phase
			e.m.mu.Unlock()
			_, err = e.m.Stop(WithEmergencyStop(context.Background(), "the sandbox ingress listener is not running"), "vmu")
			if apiErr := wantCode(t, err, sandboxapi.CodeUnsynced); !strings.Contains(apiErr.Message, containedUnprotected) {
				t.Fatalf("the security stop of a MicroVM in %q = %+v", phase, apiErr)
			}
			if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
				t.Fatalf("a security stop stopped a MicroVM in %q whose sync failed", phase)
			}
			// And the stop-sandboxes of a sign-out: no stop either.
			_, err = e.m.Stop(context.Background(), "vmu")
			wantCode(t, err, sandboxapi.CodeUnsynced)
			if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
				t.Fatalf("a plain stop stopped a MicroVM in %q whose sync failed", phase)
			}

			// A sync that works lets the user's stop go ahead.
			e.fake.HandleExec(e.workloadChecks(nil, nil))
			e.stopBox("vmc")
		})
	}
}

// awayGateway is a gateway other than e's own (another registration and
// endpoint) running the same driver, and the fake behind it.
func awayGateway(e *harnessEnv) (*Gateway, *openshelltest.Fake) {
	other := openshelltest.New(openshelltest.WithDriver(e.gw.Driver.Name))
	away := *e.gw
	away.Client = other.Client(openshell.ClientOptions{PollInterval: time.Millisecond})
	away.Name, away.Endpoint, away.Port = "other", "https://127.0.0.1:27670", 27670
	return &away, other
}

// unprotectedNames is who the status names unprotected, and whether the
// run refusal and b's view name the contained guest b too.
func unprotectedNames(t *testing.T, e *harnessEnv, b *box) (names []string, refused, warned bool) {
	t.Helper()
	st, err := e.m.Status(t.Context())
	must(t, err)
	for _, u := range st.Unprotected {
		names = append(names, u.Name)
	}
	e.m.mu.Lock()
	name := b.rec.Name
	v := e.m.view(b)
	e.m.mu.Unlock()
	if err := e.m.legacyRunRefusal(t.Context(), ""); err != nil {
		refused = strings.Contains(err.Error(), name)
	}
	for _, w := range v.Warnings {
		warned = warned || strings.HasPrefix(w, containedUnprotected)
	}
	return names, refused, warned
}

// G-openshell review (loop round 2): a lookup that found a contained VM
// missing marked it so without saying which gateway had not found it.
// Asked on another gateway than its own (a get, or a stop that found
// another sandbox under its name there), it was released from the status,
// the run refusal and its view while it may still run on its own gateway;
// asked on its own gateway after a pass elsewhere, the place that pass had
// left kept it named, and every new run refused, though that gateway says
// it is gone (and warned it lives elsewhere once found there again). Every
// lookup now sets where the sandbox was created with missing, and one that
// finds it sets its place too.
func TestALookupOnAnotherGatewayNeitherHidesNorKeepsAContainedVM(t *testing.T) {
	const name = "vmaway"
	get := func(e *harnessEnv) { _, _ = e.m.Get(e.t.Context(), name) }
	for _, away := range []struct {
		name     string
		replaced bool // the other gateway has another sandbox under the name
		look     func(e *harnessEnv)
	}{
		{"get", false, get},
		{"get of a name another sandbox has there", true, get},
		{"stop of a name another sandbox has there", true, func(e *harnessEnv) { _, _ = e.m.Stop(e.t.Context(), name) }},
		{"reconcile", false, func(e *harnessEnv) { _ = e.m.Reconcile(e.t.Context()) }},
	} {
		for _, home := range []string{"gone there", "still there"} {
			t.Run(away.name+", then back where it is "+home, func(t *testing.T) {
				e := newVMEnv(t, nil)
				b := containedVM(t, e, name)
				own := e.gw
				gw, other := awayGateway(e)
				if away.replaced {
					_, err := other.SDK().Sandboxes().Create(t.Context(), openshell.DefaultWorkspace, name, &types.SandboxSpec{}, nil)
					must(t, err)
				}
				switchGateway(t, e, gw)
				away.look(e)
				e.m.mu.Lock()
				missing := b.missing
				e.m.mu.Unlock()
				if !missing {
					t.Fatal("the scenario was not reached: the lookup elsewhere did not find it missing")
				}
				if names, refused, warned := unprotectedNames(t, e, b); !slices.Equal(names, []string{name}) || !refused || !warned {
					t.Fatalf("missing from another gateway than its own: unprotected %q, run refused %v, view warns %v", names, refused, warned)
				}

				if home == "gone there" {
					_, err := e.fake.Client(openshell.ClientOptions{PollInterval: time.Millisecond}).DeleteSandbox(t.Context(), name)
					must(t, err)
				}
				switchGateway(t, e, own)
				get(e)
				names, refused, warned := unprotectedNames(t, e, b)
				e.m.mu.Lock()
				v := e.m.view(b)
				e.m.mu.Unlock()
				if home == "gone there" {
					if len(names) != 0 || refused {
						t.Fatalf("its own gateway says it is gone, yet: unprotected %q, run refused %v", names, refused)
					}
					return
				}
				if !slices.Equal(names, []string{name}) || !refused || !warned || v.Phase != string(audit.SandboxPhaseReady) {
					t.Fatalf("found running on its own gateway: unprotected %q, run refused %v, view warns %v, phase %q", names, refused, warned, v.Phase)
				}
				for _, w := range v.Warnings {
					if strings.Contains(w, "not the gateway DefenseClaw is connected to") {
						t.Fatalf("found on its own gateway, the view still says it lives elsewhere: %q", w)
					}
				}
			})
		}
	}
}
