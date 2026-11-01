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
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// GAP-0673: a start runs the sandbox under a new registration the managed
// gateway answers (registrations/{id}/restart). The daemon keeps it in the
// old one's place, in memory and in its registrations file, and reports
// the new one running.
func TestSandboxDaemonStartRegistersAgain(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	ctl := &managedSandboxController{Manager: f.d.rt.manager, d: f.d}
	if err := f.d.regs.put(daemonRegistration{ID: "reg-a", Sandbox: "dc-a", UpdatedAt: time.Now(), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	f.relay.restart = func(id string) (sandboxrelay.RegistrationView, error) {
		return sandboxrelay.RegistrationView{V: 1, ID: "reg-b", State: "live"}, nil
	}
	// No such sandbox in OpenShell: the start fails after the registration.
	_, _ = ctl.Start(context.Background(), "dc-a", sandboxapi.StartRequest{})
	if got := f.relay.restarts; !slices.Equal(got, []string{"reg-a"}) {
		t.Fatalf("restarts = %v", got)
	}
	if got := f.relay.reported(); len(got) == 0 || got[0] != "reg-b=running" || slices.Contains(got, "reg-a=running") {
		t.Fatalf("reports = %v, want the new registration's first", got)
	}
	if r, _ := f.d.regs.get("dc-a"); r.ID != "reg-b" || r.Revoked {
		t.Fatalf("registration = %+v", r)
	}
	reloaded, err := loadDaemonRegistrations(f.d.regs.path)
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := reloaded.get("dc-a"); r.ID != "reg-b" {
		t.Fatalf("registrations file keeps %q", r.ID)
	}
	// A late answer for the replaced registration changes nothing.
	if f.d.regs.markRevokedIfID("dc-a", "reg-a", sandboxrelay.ReasonRegistrationRevoked, "") {
		t.Fatal("an answer for the replaced registration revoked the new one")
	}
}

// A managed gateway without the route (after a rollback) keeps the
// registration, whose running report starts the sandbox as before; one
// that ended the registration refuses the start.
func TestSandboxDaemonStartWithoutRestartRouteOrEndedRegistration(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	ctl := &managedSandboxController{Manager: f.d.rt.manager, d: f.d}
	if err := f.d.regs.put(daemonRegistration{ID: "reg-a", Sandbox: "dc-a", UpdatedAt: time.Now(), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	_, _ = ctl.Start(context.Background(), "dc-a", sandboxapi.StartRequest{})
	if got := f.relay.reported(); len(got) == 0 || got[0] != "reg-a=running" {
		t.Fatalf("reports without the route = %v", got)
	}
	f.relay.restart = func(string) (sandboxrelay.RegistrationView, error) {
		return sandboxrelay.RegistrationView{}, &sandboxrelay.Error{Status: http.StatusGone, Reason: sandboxrelay.ReasonRegistrationRevoked}
	}
	if _, err := ctl.Start(context.Background(), "dc-a", sandboxapi.StartRequest{}); !sandboxapi.IsCode(err, sandboxapi.CodeAdminViolation) {
		t.Fatalf("start of an ended registration: %v", err)
	}
	if r, _ := f.d.regs.get("dc-a"); !r.Revoked {
		t.Fatalf("ended registration kept live: %+v", r)
	}
	for _, status := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		if !restartUnsupported(&sandboxrelay.Error{Status: status}) {
			t.Fatalf("%d without a reason is not a missing route", status)
		}
	}
	if restartUnsupported(&sandboxrelay.Error{Status: http.StatusNotFound, Reason: sandboxrelay.ReasonRegistrationUnknown}) {
		t.Fatal("an unknown registration counts as a missing route")
	}
}

// A sandbox that runs while its registration was reported stopped (started
// outside the daemon, or listed stopped while it ran) keeps working: the
// poll registers it again instead of leaving its hooks refused.
func TestSandboxDaemonPollRegistersARunningStoppedSandboxAgain(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	if err := f.d.regs.put(daemonRegistration{ID: "reg-a", Sandbox: "dc-a", UpdatedAt: time.Now(), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	f.d.opts.listPhases = func(context.Context) (map[string]string, bool) {
		return map[string]string{"dc-a": "ready"}, true
	}
	f.relay.current = func(id string) (sandboxrelay.CurrentPolicy, error) {
		if id == "reg-a" {
			return sandboxrelay.CurrentPolicy{}, &sandboxrelay.Error{Status: http.StatusForbidden, Reason: sandboxrelay.ReasonRegistrationStopped}
		}
		return sandboxrelay.CurrentPolicy{V: 1}, nil
	}
	f.relay.restart = func(string) (sandboxrelay.RegistrationView, error) {
		return sandboxrelay.RegistrationView{V: 1, ID: "reg-b", State: "live"}, nil
	}
	f.d.pollOnce(context.Background())
	if got := f.relay.reported(); !slices.Equal(got, []string{"reg-a=running", "reg-b=running"}) {
		t.Fatalf("reports = %v", got)
	}
	if r, _ := f.d.regs.get("dc-a"); r.ID != "reg-b" || r.Revoked {
		t.Fatalf("registration = %+v", r)
	}
	// While a start holds the lifecycle, the poll leaves it to the start.
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{}, &sandboxrelay.Error{Status: http.StatusForbidden, Reason: sandboxrelay.ReasonRegistrationStopped}
	}
	if err := f.d.lockLifecycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.d.pollOnce(context.Background())
	f.d.unlockLifecycle()
	if got := f.relay.restarts; !slices.Equal(got, []string{"reg-a"}) {
		t.Fatalf("restarts = %v", got)
	}
}
