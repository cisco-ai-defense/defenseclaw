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
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// restartedRegistration starts the sandbox of peer's registration id again
// (registrations/{id}/restart) and returns the new registration's id.
func restartedRegistration(t *testing.T, f *sandboxFixture, peer managedHookPeer, id string) string {
	t.Helper()
	rec := f.do(peer, http.MethodPost, sandboxrelay.PathRegistrations+id+sandboxrelay.RegistrationRestartSub,
		map[string]int{"v": 1}, nil)
	var view sandboxrelay.RegistrationView
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &view) != nil || view.ID == "" || view.ID == id {
		t.Fatalf("restart %s: %d %s", id, rec.Code, rec.Body.String())
	}
	return view.ID
}

// GAP-0673: on the hook socket, a state report only moves a registration
// toward stopped. A running report after a reported stop is refused, the
// registration stays stopped and the refusal is recorded; a start
// (registrations/{id}/restart) runs the sandbox under a new registration
// and the old one authorizes nothing. A lapsed lease (a lost connection)
// is not a stop: the next running report keeps the sandbox working.
func TestSandboxStateReportsOnlyMoveTowardStopped(t *testing.T) {
	g := newGuestSignalFixture(t)
	id := g.f.resolve(sbxAlice, claudeResolve()).Registration.ID
	if rec := g.f.bind(sbxAlice, id, 1); rec.Code != http.StatusOK {
		t.Fatalf("bind: %d %s", rec.Code, rec.Body.String())
	}
	report := func(peer managedHookPeer, reg string, running bool) (int, string) {
		rec := g.f.do(peer, http.MethodPost, sandboxrelay.PathRegistrations+reg+sandboxrelay.RegistrationStateSub,
			sandboxrelay.StateReport{V: 1, Running: running}, nil)
		return rec.Code, rec.Body.String()
	}
	restart := func(peer managedHookPeer, reg string) (int, sandboxrelay.RegistrationView, string) {
		rec := g.f.do(peer, http.MethodPost, sandboxrelay.PathRegistrations+reg+sandboxrelay.RegistrationRestartSub,
			map[string]int{"v": 1}, nil)
		var view sandboxrelay.RegistrationView
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
				t.Fatal(err)
			}
		}
		return rec.Code, view, rec.Body.String()
	}
	state := func(reg string) string {
		t.Helper()
		got, ok, err := g.auth.store.Get(sbxAlice.UID, reg)
		if err != nil || !ok {
			t.Fatalf("registration %s: %v %v", reg, ok, err)
		}
		return sandboxreg.EffectiveState(got, g.now)
	}

	// A lost connection: the lease lapses, the next running report keeps it.
	g.now = g.now.Add(sandboxreg.LiveLease + time.Minute)
	if code, body := report(sbxAlice, id, true); code != http.StatusOK || state(id) != sandboxreg.StateLive {
		t.Fatalf("running report after a lapsed lease: %d %s state=%s", code, body, state(id))
	}
	// A reported stop is final for the registration.
	if code, body := report(sbxAlice, id, false); code != http.StatusOK || state(id) != sandboxreg.StateStopped {
		t.Fatalf("stopped report: %d %s", code, body)
	}
	for range 2 {
		g.now = g.now.Add(time.Minute)
		code, body := report(sbxAlice, id, true)
		if code != http.StatusForbidden || !strings.Contains(body, sandboxrelay.ReasonRegistrationStopped) {
			t.Fatalf("running report after a stop: %d %s", code, body)
		}
	}
	if state(id) != sandboxreg.StateStopped {
		t.Fatalf("a running report revived the registration: %s", state(id))
	}
	if rec := g.f.hook(sbxAlice, id, "claudecode", nil); rec.Code == http.StatusOK {
		t.Fatalf("stopped registration admitted a relayed hook: %d", rec.Code)
	}
	g.auth.guestSignals.wg.Wait()
	refusals := 0
	for _, row := range auditEventsOf(t, g.store, audit.ActionSandboxManaged) {
		if row.Structured["defenseclaw.sandbox.managed.reason"] == audit.SandboxGuestRunningAfterStop &&
			row.Structured["defenseclaw.sandbox.registration.id"] == id {
			refusals++
		}
	}
	if refusals != 1 {
		t.Fatalf("%d refused-report records, want one (rate-limited)", refusals)
	}

	// Another account cannot restart it; a pending registration has no sandbox.
	if code, _, body := restart(sbxBob, id); code != http.StatusNotFound {
		t.Fatalf("restart from another account: %d %s", code, body)
	}
	pending := g.f.resolve(sbxAlice, claudeResolve()).Registration.ID
	if code, _, body := restart(sbxAlice, pending); code != http.StatusForbidden {
		t.Fatalf("restart of a pending registration: %d %s", code, body)
	}

	// A start registers the sandbox again.
	code, view, body := restart(sbxAlice, id)
	if code != http.StatusOK || view.ID == id || !sandboxreg.ValidID(view.ID) || view.State != sandboxreg.StateLive ||
		view.SandboxID != "sbx-1" || view.SandboxName != "dc-claude-1" {
		t.Fatalf("restart: %d %+v %s", code, view, body)
	}
	fresh, _, _ := g.auth.store.Get(sbxAlice.UID, view.ID)
	if !fresh.GuestWatch || !fresh.GuestSeenAt.IsZero() {
		t.Fatalf("restarted registration is not watched: %+v", fresh)
	}
	if code, body := report(sbxAlice, view.ID, true); code != http.StatusOK {
		t.Fatalf("running report of the new registration: %d %s", code, body)
	}
	if rec := g.f.hook(sbxAlice, view.ID, "claudecode", nil); rec.Code != http.StatusOK {
		t.Fatalf("relayed hook of the new registration: %d %s", rec.Code, rec.Body.String())
	}
	if rec := g.f.hook(sbxAlice, id, "claudecode", nil); rec.Code == http.StatusOK {
		t.Fatalf("the replaced registration still admits a relayed hook")
	}
	if code, _, _ := restart(sbxAlice, id); code == http.StatusOK {
		t.Fatal("the replaced registration restarted again")
	}
	if old, _, _ := g.auth.store.Get(sbxAlice.UID, id); old.State != sandboxreg.StateRevoked || old.RevokedReason != sandboxreg.ReasonRestarted {
		t.Fatalf("replaced registration: %+v", old)
	}
}
