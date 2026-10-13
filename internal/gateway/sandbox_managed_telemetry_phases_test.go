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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// The second review of the managed sandbox telemetry relay (8d9cd41f7).

func reportDeleted(t *testing.T, f *sandboxFixture, peer managedHookPeer, id string) {
	t.Helper()
	if rec := f.do(peer, http.MethodPost, sandboxrelay.PathRegistrations+id+sandboxrelay.RegistrationDelSub, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("report %s deleted: %d %s", id, rec.Code, rec.Body.String())
	}
}

func phaseClaim(t *testing.T, name, phase string) sandboxrelay.Event {
	return telemetryEvent(t, sandboxrelay.EventSandboxLifecycle, time.Now(), map[string]any{"sandbox": name, "phase": phase})
}

func lifecyclePhases(t *testing.T, store *audit.Store) []string {
	t.Helper()
	var phases []string
	for _, row := range auditEventsOf(t, store, audit.ActionSandboxLifecycle) {
		phase, _ := row.Structured["defenseclaw.sandbox.phase"].(string)
		phases = append(phases, phase)
	}
	slices.Reverse(phases) // oldest first
	return phases
}

// P2-A: registration churn (resolve, bind phantom-N, post ready, report it
// deleted twice) left one ready phase per cycle in the managed recorder,
// counted in sandbox.active fleet-wide and scanned under its one lock.
// Every way a registration goes ends its phase on the gateway's side, and
// a record under a tombstone (a stopped after the delete) never tracks the
// sandbox again.
func TestManagedSandboxPhasesEndWithTheirRegistration(t *testing.T) {
	// The churn is the request budgets' to slow; here it runs at once.
	for _, class := range []string{sandboxBudgetPolicy, sandboxBudgetEvents} {
		prev := sandboxBudgetLimits[class]
		sandboxBudgetLimits[class] = sandboxBudgetLimit{Rate: 1000, Burst: 1000, InFlight: prev.InFlight}
		t.Cleanup(func() { sandboxBudgetLimits[class] = prev })
	}
	f, _ := managedTelemetryFixture(t)
	auth, err := f.api.sandboxAuth()
	if err != nil {
		t.Fatal(err)
	}
	recorder := f.api.managedSandboxRecorder()
	tracked := func(when string, want int) {
		t.Helper()
		if got := recorder.TrackedSandboxes(); got != want {
			t.Fatalf("%s: the managed recorder tracks %d sandboxes, want %d", when, got, want)
		}
	}
	for n := range 60 {
		id := f.resolve(sbxAlice, claudeResolve()).Registration.ID
		name := fmt.Sprintf("phantom-%d", n)
		if rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathRegistrations+id+sandboxrelay.RegistrationBindSub, sandboxrelay.BindRequest{
			V: 1, SandboxName: name, SandboxID: fmt.Sprintf("sbx-ph-%d", n), BindingID: fmt.Sprintf("sb_%032x", n+1),
		}, nil); rec.Code != http.StatusOK {
			t.Fatalf("cycle %d bind: %d %s", n, rec.Code, rec.Body.String())
		}
		if rec := postEvents(f, sbxAlice, id, phaseClaim(t, name, "ready")); rec.Code != http.StatusAccepted {
			t.Fatalf("cycle %d ready: %d %s", n, rec.Code, rec.Body.String())
		}
		tracked(fmt.Sprintf("cycle %d ready", n), 1)
		reportDeleted(t, f, sbxAlice, id)
		tracked(fmt.Sprintf("cycle %d deleted", n), 0)
		if rec := postEvents(f, sbxAlice, id, phaseClaim(t, name, "stopped")); rec.Code != http.StatusAccepted {
			t.Fatalf("cycle %d stopped under the tombstone: %d %s", n, rec.Code, rec.Body.String())
		}
		tracked(fmt.Sprintf("cycle %d stopped under the tombstone", n), 0)
		reportDeleted(t, f, sbxAlice, id)
	}
	if regs, err := auth.store.List(sbxAlice.UID); err != nil || len(regs) != 0 {
		t.Fatalf("store: %d registrations (%v), want none", len(regs), err)
	}
	tracked("after the churn", 0)

	// A gateway revocation (a changed subject, a re-match stop, a foreign
	// sandbox) ends the phase too, whatever path stores it.
	id := boundRegistration(t, f, sbxAlice, 1)
	if rec := postEvents(f, sbxAlice, id, phaseClaim(t, "dc-claude-1", "ready")); rec.Code != http.StatusAccepted {
		t.Fatalf("ready: %d %s", rec.Code, rec.Body.String())
	}
	tracked("ready", 1)
	if rec := postEvents(f, sbxAlice, "", sandboxrelay.Event{Kind: sandboxrelay.EventForeignSandbox, Time: time.Now(),
		Payload: json.RawMessage(`{"sandbox":"dc-claude-1","sandbox_id":"sbx-1"}`)}); rec.Code != http.StatusAccepted {
		t.Fatalf("foreign sandbox: %d %s", rec.Code, rec.Body.String())
	}
	if reg, _, _ := auth.store.Get(sbxAlice.UID, id); reg.State != sandboxreg.StateRevoked {
		t.Fatalf("the foreign sandbox's registration is %s, want revoked", reg.State)
	}
	tracked("after the foreign sandbox revocation", 0)
}

// P2-B: after a gateway revocation (policy_changed) the honest daemon's
// stopping and stopped records got 410, then its deleted report removed the
// tombstone and its deleting and deleted got 404: the sandbox stayed
// ready, active, until the gateway restarted. The revocation ends the
// phase, the shutdown records and connection ends land within the window,
// and no live phase does.
func TestManagedSandboxTelemetryAfterAGatewayRevocation(t *testing.T) {
	f, store := managedTelemetryFixture(t)
	auth, err := f.api.sandboxAuth()
	if err != nil {
		t.Fatal(err)
	}
	recorder := f.api.managedSandboxRecorder()
	id := boundRegistration(t, f, sbxAlice, 1)
	post := func(events ...sandboxrelay.Event) *httptest.ResponseRecorder {
		t.Helper()
		return postEvents(f, sbxAlice, id, events...)
	}
	if rec := post(phaseClaim(t, "dc-claude-1", "creating"), phaseClaim(t, "dc-claude-1", "ready")); rec.Code != http.StatusAccepted {
		t.Fatalf("live: %d %s", rec.Code, rec.Body.String())
	}
	if recorder.TrackedSandboxes() != 1 {
		t.Fatalf("tracked %d, want the ready sandbox", recorder.TrackedSandboxes())
	}
	if err := auth.store.Revoke(sbxAlice.UID, id, sandboxreg.ReasonPolicyChanged); err != nil {
		t.Fatal(err)
	}
	if recorder.TrackedSandboxes() != 0 {
		t.Fatal("the revocation left the sandbox tracked (and active)")
	}
	end := telemetryEvent(t, sandboxrelay.EventSandboxEgress, time.Now(), map[string]any{"sandbox": "dc-claude-1",
		"source": "dc-egress-proxy", "host": "github.com", "port": 443, "end": "completed", "duration_ms": 1200})
	if rec := post(phaseClaim(t, "dc-claude-1", "ready"), phaseClaim(t, "dc-claude-1", "stopping"),
		phaseClaim(t, "dc-claude-1", "stopped"), end); rec.Code != http.StatusAccepted {
		t.Fatalf("stopping and stopped after a policy_changed revocation: %d %s, want 202", rec.Code, rec.Body.String())
	}
	if rec := post(phaseClaim(t, "dc-claude-1", "deleting"), phaseClaim(t, "dc-claude-1", "deleted")); rec.Code != http.StatusAccepted {
		t.Fatalf("deleting and deleted: %d %s, want 202", rec.Code, rec.Body.String())
	}
	if got, want := strings.Join(lifecyclePhases(t, store), ","), "creating,ready,stopping,stopped,deleting,deleted"; got != want {
		t.Fatalf("lifecycle rows %s, want %s (no live phase after the revocation)", got, want)
	}
	if rows := auditEventsOf(t, store, audit.ActionSandboxEgress); len(rows) != 1 {
		t.Fatalf("%d egress rows, want the connection end", len(rows))
	}
	if recorder.TrackedSandboxes() != 0 {
		t.Fatal("a record under the tombstone tracked the sandbox again")
	}

	// The daemon's deleted report removes the tombstone; nothing lands
	// after it, and nothing is left tracked.
	reportDeleted(t, f, sbxAlice, id)
	if rec := post(phaseClaim(t, "dc-claude-1", "deleted")); rec.Code != http.StatusNotFound {
		t.Fatalf("after the tombstone went: %d %s, want 404", rec.Code, rec.Body.String())
	}

	// Past the window, a gateway revocation's tombstone takes nothing.
	other := boundRegistration(t, f, sbxAlice, 2)
	if err := auth.store.Revoke(sbxAlice.UID, other, sandboxreg.ReasonPolicyChanged); err != nil {
		t.Fatal(err)
	}
	auth.now = func() time.Time { return time.Now().Add(sandboxTelemetryAfterRevoke + time.Minute) }
	defer func() { auth.now = nil }()
	if rec := postEvents(f, sbxAlice, other, phaseClaim(t, "dc-claude-2", "stopped")); rec.Code != http.StatusGone {
		t.Fatalf("past the window: %d %s, want 410", rec.Code, rec.Body.String())
	}
}

// P3: the line and paragraph separators become a space; the zero-width,
// invisible, bidi-mark and tag characters go.
func TestSandboxClaimTextInvisibleCharacters(t *testing.T) {
	for in, want := range map[string]string{
		"a\u2028b\u2029c": "a b c",
		"x\u200by\u200c\u200d\u200e\u200f\ufeff\u061c\u2060\u2061\u2062\u2063\u2064z": "xyz",
		"tag\U000E0001\U000E0041\U000E007Fs":                                          "tags",
		"plain text, caf\u00e9":                                                       "plain text, caf\u00e9",
	} {
		if got := sandboxClaimText(in); got != want {
			t.Errorf("sandboxClaimText(%q) = %q, want %q", in, got, want)
		}
	}
	clean, err := sandboxClaimPayload(json.RawMessage(`{"ho\u200bst":"a\u2028b"}`))
	if err != nil || string(clean) != `{"host":"a b"}` {
		t.Fatalf("sandboxClaimPayload: %s %v", clean, err)
	}
}

// P3: a payload two of whose keys are one once cleaned is refused (400):
// which of them a record took would be the daemon's pick.
func TestManagedSandboxEventsRefuseCollidingKeys(t *testing.T) {
	f, store := managedTelemetryFixture(t)
	id := boundRegistration(t, f, sbxAlice, 1)
	if _, err := sandboxClaimPayload(json.RawMessage(`{"phase":"ready","pha\u0000se":"error"}`)); !errors.Is(err, errSandboxClaimKeyCollision) {
		t.Fatalf("colliding keys: %v, want errSandboxClaimKeyCollision", err)
	}
	if _, err := sandboxClaimPayload(json.RawMessage(`{"a":[{"k":1,"k\u200b":2}]}`)); !errors.Is(err, errSandboxClaimKeyCollision) {
		t.Fatalf("nested colliding keys: %v, want errSandboxClaimKeyCollision", err)
	}
	rec := postEvents(f, sbxAlice, id,
		phaseClaim(t, "dc-claude-1", "ready"),
		sandboxrelay.Event{Kind: sandboxrelay.EventSandboxLifecycle, Time: time.Now(),
			Payload: json.RawMessage(`{"sandbox":"dc-claude-1","phase":"ready","ph\u200base":"error"}`)})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a batch with colliding keys: %d %s, want 400", rec.Code, rec.Body.String())
	}
	if rows := auditEventsOf(t, store, audit.ActionSandboxLifecycle); len(rows) != 0 {
		t.Fatalf("%d lifecycle rows from a refused batch", len(rows))
	}
}

// P3: the other event kinds have a records budget too, counted by the
// record: a foreign_rule event is one record per rule (at most 16), so a
// request could carry 4,096 rows.
func TestManagedSandboxEventRecordsBudget(t *testing.T) {
	f, _ := managedTelemetryFixture(t)
	emitted := captureSandboxEvents(t)
	auth, err := f.api.sandboxAuth()
	if err != nil {
		t.Fatal(err)
	}
	id := boundRegistration(t, f, sbxAlice, 1)
	frozen := time.Now().Add(time.Second)
	auth.now = func() time.Time { return frozen }
	defer func() { auth.now = nil }()
	rules := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("rule-%d", i)
		}
		return out
	}
	foreignRules := func(events, perEvent int) []sandboxrelay.Event {
		out := make([]sandboxrelay.Event, events)
		for i := range out {
			out[i] = telemetryEvent(t, sandboxrelay.EventForeignRule, time.Time{},
				map[string]any{"sandbox": "dc-claude-1", "rules": rules(perEvent), "action": "removed"})
		}
		return out
	}
	if got := sandboxEventRows(foreignRules(1, 100)[0]); got != sandboxEventRulesMax {
		t.Fatalf("a foreign_rule event of 100 rules is %d records, want %d", got, sandboxEventRulesMax)
	}
	// More records than the daemon ever holds (64 events of 16 rules) is
	// refused outright, before any budget is spent.
	if rec := postEvents(f, sbxAlice, id, foreignRules(sandboxrelay.MaxUnregisteredEventRecords+1, sandboxEventRulesMax)...); rec.Code != http.StatusBadRequest {
		t.Fatalf("%d records in one batch: %d %s, want 400", (sandboxrelay.MaxUnregisteredEventRecords+1)*sandboxEventRulesMax, rec.Code, rec.Body.String())
	}
	if rec := postEvents(f, sbxAlice, id, foreignRules(sandboxrelay.MaxUnregisteredEventRecords, 100)...); rec.Code != http.StatusAccepted {
		t.Fatalf("the burst (%d records): %d %s", sandboxEventRecordBurst, rec.Code, rec.Body.String())
	}
	rec := postEvents(f, sbxAlice, id, foreignRules(1, sandboxEventRulesMax)...)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("past the records budget: %d Retry-After %q, want 429 and 1 s", rec.Code, rec.Header().Get("Retry-After"))
	}
	if got := emitted(sandboxrelay.EventForeignRule); got != sandboxrelay.MaxUnregisteredEventRecords {
		t.Fatalf("%d foreign_rule events recorded, want the admitted batch's %d", got, sandboxrelay.MaxUnregisteredEventRecords)
	}
	// Telemetry keeps its own budget.
	if rec := postEvents(f, sbxAlice, id, phaseClaim(t, "dc-claude-1", "ready")); rec.Code != http.StatusAccepted {
		t.Fatalf("telemetry with the other budget spent: %d %s", rec.Code, rec.Body.String())
	}
	frozen = frozen.Add(time.Second)
	if rec := postEvents(f, sbxAlice, id, foreignRules(3, sandboxEventRulesMax)...); rec.Code != http.StatusAccepted {
		t.Fatalf("after a second's refill (48 of 64 records): %d %s", rec.Code, rec.Body.String())
	}
}
