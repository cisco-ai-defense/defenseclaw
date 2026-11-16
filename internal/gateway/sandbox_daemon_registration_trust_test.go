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
	"net/http"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// GAP-0028: the registrations file is the account's own. A daemon restarted
// with a registration whose floor fields were edited there (every
// credential, the loosest pack, yolo) takes the whole floor from the managed
// gateway's first answer for it, through the real policy/current route; none
// of the edited fields reaches a decision. An answer without a floor (a
// managed gateway of an earlier release) leaves the registration unconfirmed,
// on the closed floor.
func TestSandboxDaemonRestartTakesTheFloorFromTheGateway(t *testing.T) {
	f, _, gate, gateway := upgradeFloorFixture(t, false)
	r, _ := f.d.regs.get("dc-claude-1")
	yes := true
	r.Floor.AllowedCredentials = []string{"*"}
	r.Floor.MinProfile = "open"
	r.Floor.AllowYolo = &yes
	r.Floor.ForeignSandboxes = config.OpenShellForeignSandboxesAlert
	if err := f.d.regs.put(r); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadDaemonRegistrations(filepath.Join(f.d.opts.StateDir, sandboxDaemonRegistrationsFile))
	if err != nil {
		t.Fatal(err)
	}
	f.d.regs = loaded

	// A managed gateway that answers without the floor confirms nothing.
	// rawCurrent: the fake relay passes the answer on as it is, instead of
	// completing it with an empty floor.
	f.relay.rawCurrent = true
	real := f.relay.current
	f.relay.current = func(id string) (sandboxrelay.CurrentPolicy, error) {
		cp, err := real(id)
		cp.Floor, cp.RequiredPack = nil, nil
		return cp, err
	}
	gateway(true)
	f.d.revalidate(context.Background())
	f.d.pollOnce(context.Background())
	if reg, _ := f.d.regs.get("dc-claude-1"); reg.Confirmed || !f.d.floorClosed() {
		t.Fatalf("an answer without the floor confirmed the edited registration: %+v", reg)
	}

	f.relay.current, f.relay.rawCurrent = real, false
	f.d.revalidate(context.Background())
	f.d.pollOnce(context.Background())
	reg, _ := f.d.regs.get("dc-claude-1")
	if !reg.Confirmed {
		t.Fatal("the managed gateway's answer did not confirm the registration")
	}
	want, _, err := gate.cfg.SandboxManagedFloor(reg.Profile)
	if err != nil {
		t.Fatal(err)
	}
	got := f.d.configForSandbox("dc-claude-1").OpenShell.Admin
	if slices.Contains(got.AllowedCredentials, "*") || !slices.Equal(got.AllowedCredentials, want.AllowedCredentials) ||
		got.MinProfile != want.MinProfile || !reflect.DeepEqual(got.AllowYolo, want.AllowYolo) ||
		got.ForeignSandboxes != want.ForeignSandboxes {
		t.Fatalf("the restarted daemon resolves under %+v, want the gateway's floor %+v", got, want)
	}
}

// GAP-0058: foreign_sandboxes alert reports a sandbox DefenseClaw did not
// start and leaves it running. Before any registration names a floor the
// daemon judges such a sandbox under the person's own setting, which the
// managed gateway's settings carry, instead of the closed floor's stop; once
// the gateway confirmed a registration, its floor carries it. Without the
// setting, the closed floor still stops.
func TestSandboxDaemonForeignSandboxesFollowThePersonsFloor(t *testing.T) {
	f, _, gate, gateway := upgradeFloorFixture(t, false)
	settings := func() sandboxrelay.DaemonSettings {
		t.Helper()
		rec := gate.do(upgradeFloorPeer, http.MethodGet, sandboxrelay.PathSettings, nil, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("settings: %d %s", rec.Code, rec.Body.String())
		}
		var s sandboxrelay.DaemonSettings
		if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	f.relay.settings = func() (sandboxrelay.DaemonSettings, error) { return settings(), nil }
	f.d.refreshSettings(context.Background())
	if !f.d.floorClosed() {
		t.Fatal("the fixture must start on the closed floor")
	}
	if got := f.d.config().OpenShell.Admin.ForeignSandboxes; got == config.OpenShellForeignSandboxesAlert {
		t.Fatalf("the closed floor without the person's alert says %q", got)
	}

	gate.cfg.OpenShell.Admin.ForeignSandboxes = config.OpenShellForeignSandboxesAlert
	if s := settings(); s.ForeignSandboxes != config.OpenShellForeignSandboxesAlert {
		t.Fatalf("settings carry foreign_sandboxes %q", s.ForeignSandboxes)
	}
	f.d.refreshSettings(context.Background())
	closed := f.d.config().OpenShell.Admin
	if closed.ForeignSandboxes != config.OpenShellForeignSandboxesAlert || closed.Allowed == nil || *closed.Allowed {
		t.Fatalf("the closed floor = %+v, want it closed with the person's alert", closed)
	}

	gateway(true)
	f.d.revalidate(context.Background())
	f.d.pollOnce(context.Background())
	if f.d.floorClosed() {
		t.Fatal("the gateway confirmed the registration, but the floor stayed closed")
	}
	if got := f.d.configForSandbox("dc-claude-1").OpenShell.Admin.ForeignSandboxes; got != config.OpenShellForeignSandboxesAlert {
		t.Fatalf("the registration floor says foreign_sandboxes %q", got)
	}
	if got := f.d.config().OpenShell.Admin.ForeignSandboxes; got != config.OpenShellForeignSandboxesAlert {
		t.Fatalf("the daemon's floor says foreign_sandboxes %q", got)
	}
}

// GAP-0132: an unblock or an ask's answer for a sandbox confirms the
// sandbox's policy first, as a new connection does: the managed gateway's
// answer (here the looser profile the administrator restored) is in force
// before the decision is judged, and within the lease nothing is asked again.
func TestSandboxDaemonDecisionConfirmsTheSandboxPolicy(t *testing.T) {
	f := newFreshFixture(t)
	no := false
	strict := config.OpenShellAdminConfig{EgressBlock: []string{"example.org"}, AllowUnblock: &no}
	if err := f.d.regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", Profile: "strict", Digest: "sha256:v1", Generation: 7,
		Floor: strict, UpdatedAt: time.Now(), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 8, Digest: "sha256:v2", Profile: "loose"}, nil)
	f.d.confirmSandboxPolicy(context.Background(), "dc-a")
	admin := f.d.configForSandbox("dc-a").OpenShell.Admin
	if len(admin.EgressBlock) != 0 || admin.AllowUnblock != nil || f.calls.Load() != 1 {
		t.Fatalf("after the confirmation the sandbox resolves under %+v (calls %d)", admin, f.calls.Load())
	}
	if r, _ := f.d.regs.get("dc-a"); r.Profile != "loose" {
		t.Fatalf("registration profile %q, want loose", r.Profile)
	}
	f.d.confirmSandboxPolicy(context.Background(), "dc-a")
	if f.calls.Load() != 1 {
		t.Fatalf("asked again within the lease: %d calls", f.calls.Load())
	}
	f.d.confirmSandboxPolicy(context.Background(), "dc-unknown")
	if f.calls.Load() != 1 {
		t.Fatalf("asked for a sandbox without a registration: %d calls", f.calls.Load())
	}
}
