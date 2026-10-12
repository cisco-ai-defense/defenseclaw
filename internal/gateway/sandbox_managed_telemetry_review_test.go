// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// The review of the managed sandbox telemetry relay (253fe7f6d): the daemon
// runs as the user, so everything it posts is the user's claim.

func telemetryEvent(t *testing.T, kind string, at time.Time, claim map[string]any) sandboxrelay.Event {
	t.Helper()
	raw, err := json.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	return sandboxrelay.Event{Kind: kind, Time: at, Payload: raw}
}

func postEvents(f *sandboxFixture, peer managedHookPeer, registration string, events ...sandboxrelay.Event) *httptest.ResponseRecorder {
	return f.do(peer, http.MethodPost, sandboxrelay.PathEvents,
		sandboxrelay.EventBatch{V: sandboxrelay.WireVersion, Registration: registration, Events: events}, nil)
}

// managedTelemetryFixture is a managed gateway fixture whose sandbox records
// land in a real audit store.
func managedTelemetryFixture(t *testing.T) (*sandboxFixture, *audit.Store) {
	t.Helper()
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	f.setGroups(sbxBob, "dc-sbx-devs")
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger
	t.Cleanup(func() { managedSandboxRecorders.Delete(f.api) })
	return f, store
}

func boundRegistration(t *testing.T, f *sandboxFixture, peer managedHookPeer, n int) string {
	t.Helper()
	id := f.resolve(peer, claudeResolve()).Registration.ID
	if rec := f.bind(peer, id, n); rec.Code != http.StatusOK {
		t.Fatalf("bind: %d %s", rec.Code, rec.Body.String())
	}
	return id
}

func auditEventsOf(t *testing.T, store *audit.Store, action audit.Action) []audit.Event {
	t.Helper()
	events, err := store.ListEvents(500)
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Event
	for _, ev := range events {
		if ev.Action == string(action) {
			out = append(out, ev)
		}
	}
	return out
}

// captureSandboxEvents replaces the recording of admitted daemon records
// with a count, by kind.
func captureSandboxEvents(t *testing.T) func(kind string) int {
	t.Helper()
	var mu sync.Mutex
	counts := map[string]int{}
	prev := sandboxEmitEvent
	sandboxEmitEvent = func(_ context.Context, _ *APIServer, _ managedHookPeer, _ sandboxreg.Registration, ev sandboxrelay.Event) {
		mu.Lock()
		counts[ev.Kind]++
		mu.Unlock()
	}
	t.Cleanup(func() { sandboxEmitEvent = prev })
	return func(kind string) int {
		mu.Lock()
		defer mu.Unlock()
		return counts[kind]
	}
}

// P1-1, P2-3: a pending registration names no sandbox, and its daemon could
// name any: every made-up name would be a phase the one managed recorder
// tracks for all accounts. A batch under it is refused; under a bound one, a
// record naming another sandbox or sandbox id is dropped, and the name, id,
// image digest, network profile and policy revision of the row come from the
// registration, never the claim, as does the severity of a phase.
func TestManagedSandboxTelemetryNeedsABoundRegistration(t *testing.T) {
	f, store := managedTelemetryFixture(t)
	pending := f.resolve(sbxAlice, claudeResolve()).Registration.ID
	now := time.Now()
	var phantoms []sandboxrelay.Event
	for _, name := range []string{"phantom-1", "phantom-2", "phantom-3"} {
		phantoms = append(phantoms, telemetryEvent(t, sandboxrelay.EventSandboxLifecycle, now, map[string]any{"sandbox": name, "sandbox_id": name, "phase": "ready"}))
	}
	if rec := postEvents(f, sbxAlice, pending, phantoms...); rec.Code != http.StatusForbidden || errorReason(t, rec) != sandboxrelay.ReasonNotAllowed {
		t.Fatalf("telemetry under a pending registration: %d %s, want 403 %s", rec.Code, rec.Body.String(), sandboxrelay.ReasonNotAllowed)
	}
	if rows := auditEventsOf(t, store, audit.ActionSandboxLifecycle); len(rows) != 0 {
		t.Fatalf("a pending registration recorded %d lifecycle rows", len(rows))
	}

	if rec := f.bind(sbxAlice, pending, 1); rec.Code != http.StatusOK {
		t.Fatalf("bind: %d %s", rec.Code, rec.Body.String())
	}
	digest := "sha256:" + strings.Repeat("e", 64)
	now = time.Now() // after the registration was made
	rec := postEvents(f, sbxAlice, pending, append(phantoms,
		telemetryEvent(t, sandboxrelay.EventSandboxLifecycle, now, map[string]any{"sandbox": "dc-claude-1", "sandbox_id": "sbx-evil", "phase": "ready"}),
		telemetryEvent(t, sandboxrelay.EventSandboxLifecycle, now, map[string]any{"sandbox": "dc-claude-1", "phase": "ready", "severity": "CRITICAL",
			"image_digest": digest, "profile": "open", "policy_version": 7}))...)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("bound batch: %d %s", rec.Code, rec.Body.String())
	}
	rows := auditEventsOf(t, store, audit.ActionSandboxLifecycle)
	if len(rows) != 1 {
		t.Fatalf("%d lifecycle rows, want the registration's sandbox's alone: %+v", len(rows), rows)
	}
	row := rows[0]
	if row.Structured["defenseclaw.sandbox.name"] != "dc-claude-1" || row.Structured["defenseclaw.sandbox.id"] != "sbx-1" {
		t.Fatalf("row sandbox %v / %v, want the registration's dc-claude-1 / sbx-1", row.Structured["defenseclaw.sandbox.name"], row.Structured["defenseclaw.sandbox.id"])
	}
	for _, key := range []string{"defenseclaw.sandbox.image_digest", "defenseclaw.sandbox.profile", "defenseclaw.sandbox.policy_version"} {
		if v, ok := row.Structured[key]; ok {
			t.Fatalf("%s = %v came from the claim", key, v)
		}
	}
	if row.Severity == "CRITICAL" {
		t.Fatalf("a claimed CRITICAL reached the row: %+v", row)
	}
}

// P2-2: two people's sandboxes of the same name on one managed gateway
// keep their own phase: alice's phase change follows her own previous
// phase, not bob's.
func TestManagedSandboxTelemetrySameNameOfTwoAccounts(t *testing.T) {
	f, store := managedTelemetryFixture(t)
	alice, bob := boundRegistration(t, f, sbxAlice, 1), boundRegistration(t, f, sbxBob, 1)
	post := func(peer managedHookPeer, reg, phase string) {
		t.Helper()
		if rec := postEvents(f, peer, reg, telemetryEvent(t, sandboxrelay.EventSandboxLifecycle, time.Now(),
			map[string]any{"sandbox": "dc-claude-1", "phase": phase})); rec.Code != http.StatusAccepted {
			t.Fatalf("post %s: %d %s", phase, rec.Code, rec.Body.String())
		}
	}
	post(sbxAlice, alice, "creating")
	post(sbxBob, bob, "ready")
	post(sbxAlice, alice, "provisioning")
	var got []string
	for _, row := range auditEventsOf(t, store, audit.ActionSandboxLifecycle) {
		if row.Structured["defenseclaw.sandbox.phase"] == "provisioning" {
			got = append(got, row.Structured["defenseclaw.sandbox.registration.id"].(string)+"<-"+
				func() string { s, _ := row.Structured["defenseclaw.sandbox.phase.previous"].(string); return s }())
		}
	}
	if len(got) != 1 || got[0] != alice+"<-creating" {
		t.Fatalf("alice's provisioning row %v, want her own previous phase creating", got)
	}
}

// P2-4: a revoked registration takes only the records of its sandbox going
// away, only when its daemon reported the sandbox deleted, and only for a
// while; no registration takes a record dated before it was made.
func TestManagedSandboxTelemetryUnderARevokedRegistration(t *testing.T) {
	f, store := managedTelemetryFixture(t)
	auth, err := f.api.sandboxAuth()
	if err != nil {
		t.Fatal(err)
	}
	id := boundRegistration(t, f, sbxAlice, 1)
	now := time.Now()
	lifecycle := func(phase string, at time.Time) sandboxrelay.Event {
		return telemetryEvent(t, sandboxrelay.EventSandboxLifecycle, at, map[string]any{"sandbox": "dc-claude-1", "phase": phase})
	}
	egress := func(end string) sandboxrelay.Event {
		claim := map[string]any{"sandbox": "dc-claude-1", "source": "dc-egress-proxy", "host": "github.com", "port": 443}
		if end != "" {
			claim["end"], claim["duration_ms"] = end, int64(math.MaxInt64)
		}
		return telemetryEvent(t, sandboxrelay.EventSandboxEgress, now, claim)
	}
	if rec := postEvents(f, sbxAlice, id, lifecycle("ready", now), lifecycle("ready", now.Add(-24*time.Hour))); rec.Code != http.StatusAccepted {
		t.Fatalf("live: %d %s", rec.Code, rec.Body.String())
	}
	if rows := auditEventsOf(t, store, audit.ActionSandboxLifecycle); len(rows) != 1 {
		t.Fatalf("%d lifecycle rows, want the backdated one refused", len(rows))
	}

	if rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathRegistrations+id+sandboxrelay.RegistrationDelSub, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("deleted: %d %s", rec.Code, rec.Body.String())
	}
	rec := postEvents(f, sbxAlice, id, lifecycle("ready", now), lifecycle("deleting", now), lifecycle("deleted", now),
		egress(""), egress("completed"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("tombstone batch: %d %s", rec.Code, rec.Body.String())
	}
	if rows := auditEventsOf(t, store, audit.ActionSandboxLifecycle); len(rows) != 3 {
		t.Fatalf("%d lifecycle rows, want ready, deleting and deleted (not a ready under the tombstone)", len(rows))
	}
	egressRows := auditEventsOf(t, store, audit.ActionSandboxEgress)
	if len(egressRows) != 1 || egressRows[0].Structured["defenseclaw.network.duration_ms"] != float64(sandboxClaimMaxDuration.Milliseconds()) {
		t.Fatalf("egress rows %+v, want the connection end alone, its duration bounded", egressRows)
	}

	// Past the window, the tombstone takes nothing.
	auth.now = func() time.Time { return now.Add(sandboxTelemetryAfterRevoke + time.Minute) }
	if rec := postEvents(f, sbxAlice, id, lifecycle("deleted", time.Time{})); rec.Code != http.StatusGone {
		t.Fatalf("after the window: %d %s, want 410", rec.Code, rec.Body.String())
	}
	auth.now = nil

	// A registration the gateway revoked (a foreign sandbox) takes nothing.
	other := boundRegistration(t, f, sbxAlice, 2)
	if err := auth.store.Revoke(sbxAlice.UID, other, sandboxreg.ReasonForeign); err != nil {
		t.Fatal(err)
	}
	if rec := postEvents(f, sbxAlice, other, telemetryEvent(t, sandboxrelay.EventSandboxLifecycle, time.Now(),
		map[string]any{"sandbox": "dc-claude-2", "phase": "deleted"})); rec.Code != http.StatusGone {
		t.Fatalf("under a gateway revocation: %d %s, want 410", rec.Code, rec.Body.String())
	}
	if rows := auditEventsOf(t, store, audit.ActionSandboxLifecycle); len(rows) != 3 {
		t.Fatalf("%d lifecycle rows after the refusals, want 3", len(rows))
	}
}

// P2-5: no control character a daemon puts in its text (ESC, NUL, BEL, C1,
// line breaks) reaches the managed audit.
func TestManagedSandboxTelemetryStripsControlCharacters(t *testing.T) {
	f, store := managedTelemetryFixture(t)
	id := boundRegistration(t, f, sbxAlice, 1)
	now := time.Now()
	rec := postEvents(f, sbxAlice, id,
		telemetryEvent(t, sandboxrelay.EventSandboxEgress, now, map[string]any{"sandbox": "dc-claude-1", "source": "dc-egress-proxy",
			"host": "pastebin.com", "port": 443, "blocked": true, "decision_code": "SANDBOX_EGRESS\x1b_BLOCKLIST",
			"reason": "floor\x1b[31m red\x00\u009b2J", "executable": "/usr/bin/cu\x1b]0;pwn\x07rl", "path": "/x\x1b[2Jy\u202e",
			"policy_outcome": "deny\r\nFAKE LINE", "pid": 42}),
		telemetryEvent(t, sandboxrelay.EventSandboxLifecycle, now, map[string]any{"sandbox": "dc-claude-1", "phase": "error",
			"condition": map[string]any{"type": "Ready", "status": "False", "reason": "Crash\x1b[0m", "message": "line1\nline2\x00\x7f"}}))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("post: %d %s", rec.Code, rec.Body.String())
	}
	rows := append(auditEventsOf(t, store, audit.ActionSandboxEgress), auditEventsOf(t, store, audit.ActionSandboxLifecycle)...)
	if len(rows) != 2 {
		t.Fatalf("%d rows, want the egress and lifecycle records", len(rows))
	}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch t2 := v.(type) {
		case string:
			if strings.ContainsFunc(t2, sandboxClaimControl) {
				t.Fatalf("%s carries a control character: %q", path, t2)
			}
		case map[string]any:
			for k, e := range t2 {
				walk(path+"."+k, e)
			}
		case []any:
			for _, e := range t2 {
				walk(path, e)
			}
		}
	}
	for _, row := range rows {
		raw, _ := json.Marshal(row)
		var v any
		_ = json.Unmarshal(raw, &v)
		walk(row.Action, v)
	}
	if got, _ := rows[0].Structured["defenseclaw.sandbox.process.executable"].(string); got != "/usr/bin/cu]0;pwnrl" {
		t.Fatalf("executable %q, want the text without its control characters", got)
	}

	clean, err := sandboxClaimPayload(json.RawMessage(`{"a":"x\u001by","n":9007199254740993,"k\u0000":["\u009b ok"]}`))
	if err != nil || string(clean) != `{"a":"xy","k":[" ok"],"n":9007199254740993}` {
		t.Fatalf("sandboxClaimPayload: %s %v", clean, err)
	}
	if _, err := sandboxClaimPayload(json.RawMessage(`{"a":1} {"b":2}`)); err == nil {
		t.Fatal("a payload with trailing data was taken")
	}
}

// P2-6: the request budget counts batches, so the records one account posts
// have their own budget (64 a second, burst two batches) and a batch carrying
// telemetry holds at most 128 records.
func TestManagedSandboxTelemetryRecordBudgetAndBatchCap(t *testing.T) {
	f, _ := managedTelemetryFixture(t)
	emitted := captureSandboxEvents(t)
	auth, err := f.api.sandboxAuth()
	if err != nil {
		t.Fatal(err)
	}
	id := boundRegistration(t, f, sbxAlice, 1)
	frozen := time.Now().Add(time.Second)
	auth.now = func() time.Time { return frozen }
	batch := func(kind string, n int) []sandboxrelay.Event {
		events := make([]sandboxrelay.Event, n)
		for i := range events {
			events[i] = telemetryEvent(t, kind, time.Time{}, map[string]any{"sandbox": "dc-claude-1", "phase": "ready", "field": "x"})
		}
		return events
	}
	if rec := postEvents(f, sbxAlice, id, batch(sandboxrelay.EventSandboxLifecycle, sandboxrelay.MaxTelemetryBatchRecords+1)...); rec.Code != http.StatusBadRequest {
		t.Fatalf("a telemetry batch of %d: %d, want 400", sandboxrelay.MaxTelemetryBatchRecords+1, rec.Code)
	}
	if rec := postEvents(f, sbxAlice, id, batch(sandboxrelay.EventSettingsDrift, sandboxrelay.MaxTelemetryBatchRecords+1)...); rec.Code != http.StatusAccepted {
		t.Fatalf("a batch of %d other records: %d %s, want the telemetry cap alone", sandboxrelay.MaxTelemetryBatchRecords+1, rec.Code, rec.Body.String())
	}
	for i := range 2 {
		if rec := postEvents(f, sbxAlice, id, batch(sandboxrelay.EventSandboxLifecycle, sandboxrelay.MaxTelemetryBatchRecords)...); rec.Code != http.StatusAccepted {
			t.Fatalf("batch %d within the burst: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	rec := postEvents(f, sbxAlice, id, batch(sandboxrelay.EventSandboxLifecycle, sandboxrelay.MaxTelemetryBatchRecords)...)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("a batch past the records budget: %d Retry-After %q, want 429 and 2 s", rec.Code, rec.Header().Get("Retry-After"))
	}
	if got := emitted(sandboxrelay.EventSandboxLifecycle); got != 2*sandboxrelay.MaxTelemetryBatchRecords {
		t.Fatalf("%d telemetry records recorded, want the two admitted batches", got)
	}
	frozen = frozen.Add(2 * time.Second)
	if rec := postEvents(f, sbxAlice, id, batch(sandboxrelay.EventSandboxLifecycle, sandboxrelay.MaxTelemetryBatchRecords)...); rec.Code != http.StatusAccepted {
		t.Fatalf("after the refill: %d %s", rec.Code, rec.Body.String())
	}
	// Each account has its own records budget.
	var b sandboxRecordBudget
	if _, ok := b.take(1, sandboxTelemetryRecordBurst, frozen); !ok {
		t.Fatal("a full budget refused its burst")
	}
	if _, ok := b.take(2, sandboxTelemetryRecordBurst, frozen); !ok {
		t.Fatal("one account's records spent another's budget")
	}
	if wait, ok := b.take(1, 64, frozen); ok || wait != time.Second {
		t.Fatalf("an empty budget: ok=%v wait=%s, want refused for 1 s", ok, wait)
	}
}

// P3: the daemon stops its flush pass at the first 429, so one busy answer
// does not turn into a post for every other registration.
func TestDaemonRelayTelemetryStopsThePassWhenBusy(t *testing.T) {
	relay := &eventsRecorder{fail: []error{&sandboxrelay.Error{Status: http.StatusTooManyRequests}}}
	regs := map[string]string{"a": "reg-aaaaaaaaaaaaaaaaaaaaaaaaaa", "b": "reg-bbbbbbbbbbbbbbbbbbbbbbbbbb"}
	tel := newDaemonRelayTelemetry(relay, func(name string) (string, bool) { id, ok := regs[name]; return id, ok }, t.Logf)
	tel.flushEvery = time.Hour
	ctx := context.Background()
	for _, name := range []string{"a", "b", "b"} {
		_ = tel.RecordSandboxLifecycle(ctx, audit.SandboxLifecycleEvent{Sandbox: audit.SandboxIdentity{Name: name, Phase: audit.SandboxPhaseReady}})
	}
	if !tel.flush(ctx) || len(relay.batches) != 0 || len(tel.pending) != 3 {
		t.Fatalf("after a 429: %d batches posted, %d kept, want none posted and all kept", len(relay.batches), len(tel.pending))
	}
	if tel.flush(ctx) || len(relay.batches) != 2 {
		t.Fatalf("next pass: %d batches, want a's and b's", len(relay.batches))
	}
	var claim map[string]any
	_ = json.Unmarshal(relay.batches[0].Events[0].Payload, &claim)
	for _, key := range []string{"image_digest", "profile", "policy_version"} {
		if _, ok := claim[key]; ok {
			t.Fatalf("the daemon still sends %s: %v", key, claim)
		}
	}
}

// P3: a claimed severity is bounded (a block at least MEDIUM, nothing above
// HIGH) and a claimed duration can't overflow.
func TestSandboxClaimSeverityAndDuration(t *testing.T) {
	for _, tc := range []struct {
		claimed string
		floor   observability.Severity
		want    string
	}{
		{"CRITICAL", observability.SeverityInfo, "HIGH"},
		{"critical", observability.SeverityMedium, "HIGH"},
		{"INFO", observability.SeverityMedium, "MEDIUM"},
		{"", observability.SeverityMedium, "MEDIUM"},
		{"bogus", observability.SeverityInfo, "INFO"},
		{"HIGH", observability.SeverityMedium, "HIGH"},
		{"LOW", observability.SeverityInfo, "LOW"},
	} {
		if got := sandboxClaimSeverity(tc.claimed, tc.floor); got != tc.want {
			t.Errorf("sandboxClaimSeverity(%q, %s) = %q, want %q", tc.claimed, tc.floor, got, tc.want)
		}
	}
	for ms, want := range map[int64]time.Duration{
		-5: 0, 0: 0, 120: 120 * time.Millisecond, math.MaxInt64: sandboxClaimMaxDuration, math.MaxInt64 / 1000: sandboxClaimMaxDuration,
	} {
		if got := sandboxClaimDuration(ms); got != want {
			t.Errorf("sandboxClaimDuration(%d) = %s, want %s", ms, got, want)
		}
	}
}
