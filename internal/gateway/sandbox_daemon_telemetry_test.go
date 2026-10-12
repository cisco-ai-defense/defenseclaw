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
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// fixtureEventsRelay is a daemon's relay whose Events posts to the managed
// gateway fixture's hook-socket routes as peer.
type fixtureEventsRelay struct {
	sandboxrelay.Client
	f    *sandboxFixture
	peer managedHookPeer
}

func (r fixtureEventsRelay) Events(_ context.Context, batch sandboxrelay.EventBatch) error {
	rec := r.f.do(r.peer, http.MethodPost, sandboxrelay.PathEvents, batch, nil)
	if rec.Code != http.StatusAccepted {
		return &sandboxrelay.Error{Status: rec.Code}
	}
	return nil
}

// sandboxAuditRows are the managed gateway's audit rows of action, as JSON.
func sandboxAuditRows(t *testing.T, store *audit.Store, action audit.Action) []string {
	t.Helper()
	events, err := store.ListEvents(200)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, ev := range events {
		if ev.Action == string(action) {
			raw, _ := json.Marshal(ev)
			out = append(out, string(raw))
		}
	}
	return out
}

func waitForAuditRows(t *testing.T, store *audit.Store, action audit.Action, n int) []string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		rows := sandboxAuditRows(t, store, action)
		if len(rows) >= n || time.Now().After(deadline) {
			return rows
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// GAP-0003: on a managed computer the user's sandbox daemon records a
// sandbox's phase changes and egress decisions, and before the fix they
// went to no recorder at all, so neither the managed audit nor its OTLP
// export ever had a log.sandbox.lifecycle or log.egress.* record. They now
// travel to the managed gateway (POST sandbox/events) and are recorded
// there with the registration's sandbox, profile and person, never the
// person the daemon claims. A deleted sandbox's last phases still land,
// and a record naming a sandbox that is not the registration's does not.
func TestManagedSandboxLifecycleAndEgressReachTheManagedAudit(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger
	t.Cleanup(func() { managedSandboxRecorders.Delete(f.api) })

	resp := f.resolve(sbxAlice, claudeResolve())
	id := resp.Registration.ID
	if rec := f.bind(sbxAlice, id, 1); rec.Code != http.StatusOK {
		t.Fatalf("bind: %d %s", rec.Code, rec.Body.String())
	}
	const name = "dc-claude-1"
	// The lookup answers alice's registration for any name, as a daemon
	// that lies about which sandbox a record describes would.
	tel := newDaemonRelayTelemetry(fixtureEventsRelay{f: f, peer: sbxAlice},
		func(string) (string, bool) { return id, true }, t.Logf)
	tel.flushEvery = 10 * time.Millisecond

	ctx := context.Background()
	claimed := func(e *audit.SandboxIdentity) { e.Connector, e.Runtime = "claudecode", audit.SandboxRuntimeOpenShell }
	ready := audit.SandboxIdentity{Name: name, ID: "sbx-1", Phase: audit.SandboxPhaseReady}
	claimed(&ready)
	_ = tel.RecordSandboxLifecycle(ctx, audit.SandboxLifecycleEvent{Sandbox: ready, PreviousPhase: audit.SandboxPhaseStarting,
		Trigger: audit.SandboxTriggerCreate, UserID: "4242", UserName: "mallory"})
	box := audit.SandboxIdentity{Name: name}
	claimed(&box)
	_ = tel.RecordSandboxEgress(ctx, audit.SandboxEgressEvent{Sandbox: box, Source: audit.SandboxEgressSourceProxy,
		Host: "github.com", Port: 443, Scheme: "https", UserID: "4242", UserName: "mallory"})
	_ = tel.RecordSandboxEgress(ctx, audit.SandboxEgressEvent{Sandbox: box, Source: audit.SandboxEgressSourceProxy,
		Host: "pastebin.com", Port: 443, Blocked: true, DecisionCode: "SANDBOX_EGRESS_BLOCKLIST", Reason: "organization floor"})
	_ = tel.RecordSandboxEgress(ctx, audit.SandboxEgressEvent{Sandbox: box, Source: audit.SandboxEgressSourceProxy,
		End: audit.SandboxEgressCompleted, Host: "github.com", Port: 443, BytesUp: 512, BytesDown: 4096, Duration: 120 * time.Millisecond})
	other := audit.SandboxIdentity{Name: "someone-elses", Phase: audit.SandboxPhaseReady}
	claimed(&other)
	_ = tel.RecordSandboxLifecycle(ctx, audit.SandboxLifecycleEvent{Sandbox: other})

	lifecycle := waitForAuditRows(t, store, audit.ActionSandboxLifecycle, 1)
	egress := waitForAuditRows(t, store, audit.ActionSandboxEgress, 3)
	if len(lifecycle) != 1 || len(egress) != 3 {
		t.Fatalf("managed audit: %d lifecycle and %d egress rows, want 1 and 3\nlifecycle %v\negress %v", len(lifecycle), len(egress), lifecycle, egress)
	}
	for _, row := range append(append([]string(nil), lifecycle...), egress...) {
		if !strings.Contains(row, name) || strings.Contains(row, "mallory") || strings.Contains(row, "4242") || strings.Contains(row, "someone-elses") {
			t.Fatalf("row does not carry only the registration's sandbox and person: %s", row)
		}
	}

	// The sandbox is deleted: the daemon reports the registration gone, and
	// the deleted phase it recorded just before still reaches the audit.
	if rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathRegistrations+id+sandboxrelay.RegistrationDelSub, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("deleted: %d %s", rec.Code, rec.Body.String())
	}
	deleted := audit.SandboxIdentity{Name: name, ID: "sbx-1", Phase: audit.SandboxPhaseDeleted}
	claimed(&deleted)
	_ = tel.RecordSandboxLifecycle(ctx, audit.SandboxLifecycleEvent{Sandbox: deleted, Trigger: audit.SandboxTriggerDelete})
	if rows := waitForAuditRows(t, store, audit.ActionSandboxLifecycle, 2); len(rows) != 2 {
		t.Fatalf("the deleted phase did not reach the audit: %v", rows)
	}

	// Privacy: another account can't post records under alice's
	// registration; nothing of bob's lands as hers.
	bob := newDaemonRelayTelemetry(fixtureEventsRelay{f: f, peer: sbxBob}, func(string) (string, bool) { return id, true }, t.Logf)
	if err := bob.relay.Events(ctx, sandboxrelay.EventBatch{V: sandboxrelay.WireVersion, Registration: id,
		Events: []sandboxrelay.Event{{Kind: sandboxrelay.EventSandboxLifecycle, Time: time.Now(), Payload: json.RawMessage(`{"sandbox":"dc-claude-1","phase":"ready"}`)}}}); err == nil {
		t.Fatal("bob posted a record under alice's registration")
	}
	if rows := sandboxAuditRows(t, store, audit.ActionSandboxLifecycle); len(rows) != 2 {
		t.Fatalf("%d lifecycle rows after bob's post, want 2", len(rows))
	}
}

// eventsRecorder is a relay whose Events answers what the test sets.
type eventsRecorder struct {
	sandboxrelay.Client
	mu      sync.Mutex
	batches []sandboxrelay.EventBatch
	fail    []error
}

func (r *eventsRecorder) Events(_ context.Context, batch sandboxrelay.EventBatch) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.fail) > 0 {
		err := r.fail[0]
		r.fail = r.fail[1:]
		if err != nil {
			return err
		}
	}
	r.batches = append(r.batches, batch)
	return nil
}

// The daemon's relay posts one batch per registration, keeps a record of a
// sandbox not registered yet (a create before its bind) until it is, keeps
// a batch the gateway could not take (out of reach, over budget) for the
// next post, and drops one the gateway refused.
func TestDaemonRelayTelemetryQueue(t *testing.T) {
	relay := &eventsRecorder{fail: []error{sandboxrelay.ErrGatewayUnreachable, &sandboxrelay.Error{Status: http.StatusTooManyRequests}}}
	var mu sync.Mutex
	regs := map[string]string{"a": "reg-aaaaaaaaaaaaaaaaaaaaaaaaaa"}
	tel := newDaemonRelayTelemetry(relay, func(name string) (string, bool) {
		mu.Lock()
		defer mu.Unlock()
		id, ok := regs[name]
		return id, ok
	}, t.Logf)
	tel.flushEvery = time.Hour // flushed by hand
	ctx := context.Background()
	for _, name := range []string{"a", "b", "a"} {
		_ = tel.RecordSandboxLifecycle(ctx, audit.SandboxLifecycleEvent{Sandbox: audit.SandboxIdentity{Name: name, Phase: audit.SandboxPhaseReady}})
	}
	if !tel.flush(ctx) || len(relay.batches) != 0 {
		t.Fatalf("an unreachable gateway: %d batches, want the records kept", len(relay.batches))
	}
	if !tel.flush(ctx) || len(relay.batches) != 0 {
		t.Fatalf("an over-budget gateway: %d batches, want the records kept", len(relay.batches))
	}
	if !tel.flush(ctx) || len(relay.batches) != 1 || relay.batches[0].Registration != regs["a"] || len(relay.batches[0].Events) != 2 {
		t.Fatalf("batches %+v, want a's two records and b's kept", relay.batches)
	}
	mu.Lock()
	regs["b"] = "reg-bbbbbbbbbbbbbbbbbbbbbbbbbb"
	mu.Unlock()
	if tel.flush(ctx) || len(relay.batches) != 2 || relay.batches[1].Registration != regs["b"] {
		t.Fatalf("batches %+v, want b's record once its registration came", relay.batches)
	}
	var claim sandboxTelemetryClaim
	if err := json.Unmarshal(relay.batches[1].Events[0].Payload, &claim); err != nil || claim.Sandbox != "b" || claim.Phase != "ready" ||
		relay.batches[1].Events[0].Kind != sandboxrelay.EventSandboxLifecycle {
		t.Fatalf("payload %s: %+v %v", relay.batches[1].Events[0].Payload, claim, err)
	}

	relay.fail = []error{&sandboxrelay.Error{Status: http.StatusNotFound, Reason: sandboxrelay.ReasonRegistrationUnknown}}
	_ = tel.RecordSandboxEgress(ctx, audit.SandboxEgressEvent{Sandbox: audit.SandboxIdentity{Name: "a"}, Host: "github.com"})
	if tel.flush(ctx) || len(relay.batches) != 2 || tel.dropped != 1 {
		t.Fatalf("a refused batch: %d batches, %d dropped, want it dropped", len(relay.batches), tel.dropped)
	}
	if !daemonTelemetryRetryable(errors.Join(sandboxrelay.ErrGatewayUnreachable)) || daemonTelemetryRetryable(errors.New("other")) {
		t.Fatal("retryable classification")
	}
}

// The managed daemon's sandbox runtime records through the relay, not into
// nothing (GAP-0003).
func TestSandboxDaemonRuntimeRelaysTelemetry(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	if _, ok := f.d.rt.tel.(*daemonRelayTelemetry); !ok {
		t.Fatalf("the daemon's sandbox telemetry is %T, want the managed gateway relay", f.d.rt.tel)
	}
}
