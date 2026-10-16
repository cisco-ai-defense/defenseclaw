// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

type guestSignalFixture struct {
	f     *sandboxFixture
	store *audit.Store
	auth  *sandboxAuthority
	now   time.Time
}

func newGuestSignalFixture(t *testing.T) *guestSignalFixture {
	t.Helper()
	f, store := managedTelemetryFixture(t)
	auth, err := f.api.sandboxAuth()
	if err != nil {
		t.Fatal(err)
	}
	g := &guestSignalFixture{f: f, store: store, auth: auth, now: time.Now().UTC().Truncate(time.Second)}
	auth.now = func() time.Time { return g.now }
	auth.store.(*sandboxreg.FileStore).Now = auth.clock
	t.Cleanup(auth.guestSignals.wg.Wait)
	return g
}

func (g *guestSignalFixture) rows(t *testing.T) []audit.Event {
	t.Helper()
	g.auth.guestSignals.wg.Wait()
	var out []audit.Event
	for _, row := range auditEventsOf(t, g.store, audit.ActionSandboxManaged) {
		if row.Structured["defenseclaw.sandbox.managed.reason"] == audit.SandboxGuestRelayWithoutGuest ||
			row.Structured["defenseclaw.sandbox.managed.reason"] == audit.SandboxGuestRunningWithoutGuest {
			out = append(out, row)
		}
	}
	return out
}

type guestResponse struct {
	status int
	header http.Header
	body   string
}

func guestSnapshot(rec *httptest.ResponseRecorder) guestResponse {
	return guestResponse{status: rec.Code, header: rec.Header().Clone(), body: rec.Body.String()}
}

// guestCallPromptly checks that alert persistence is not on an admitted
// response path. The channel makes the assertion independent of sleeps.
func guestCallPromptly(t *testing.T, calls *sync.WaitGroup, call func() *httptest.ResponseRecorder) guestResponse {
	t.Helper()
	result := make(chan guestResponse, 1)
	calls.Add(1)
	go func() {
		defer calls.Done()
		result <- guestSnapshot(call())
	}()
	select {
	case response := <-result:
		return response
	case <-time.After(2 * time.Second):
		t.Fatal("admitted response waited for the alert recorder")
		return guestResponse{}
	}
}

func TestSandboxGuestBlockedRecorderDoesNotHoldResponses(t *testing.T) {
	g := newGuestSignalFixture(t)
	alice := boundRegistration(t, g.f, sbxAlice, 1)
	bob := boundRegistration(t, g.f, sbxBob, 2)
	g.now = g.now.Add(sandboxGuestGrace)
	started := make(chan audit.SandboxRegistrationWithoutGuestEvent, 8)
	release := make(chan struct{})
	var once sync.Once
	var calls sync.WaitGroup
	t.Cleanup(func() { once.Do(func() { close(release) }); calls.Wait() })
	recorder := g.f.api.managedSandboxRecorder()
	g.auth.guestSignals.record = func(ctx context.Context, event audit.SandboxRegistrationWithoutGuestEvent) error {
		started <- event
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		return recorder.RecordSandboxRegistrationWithoutGuest(ctx, event)
	}
	for _, item := range []struct {
		peer managedHookPeer
		id   string
	}{
		{sbxAlice, alice}, {sbxBob, bob},
	} {
		peer, id := item.peer, item.id
		for attempt := range 2 {
			if got := guestCallPromptly(t, &calls, func() *httptest.ResponseRecorder {
				return g.f.do(peer, http.MethodPost, sandboxrelay.PathRegistrations+id+sandboxrelay.RegistrationStateSub,
					sandboxrelay.StateReport{V: 1, Running: true}, nil)
			}); got.status != http.StatusOK {
				t.Fatalf("state response: %+v", got)
			}
			if peer.UID == sbxAlice.UID && attempt == 0 {
				select {
				case <-started:
				case <-time.After(2 * time.Second):
					t.Fatal("first reserved record did not reach the recorder")
				}
			}
			if got := guestCallPromptly(t, &calls, func() *httptest.ResponseRecorder {
				return g.f.hook(peer, id, "claudecode", nil)
			}); got.status != http.StatusOK {
				t.Fatalf("relay response: %+v", got)
			}
		}
	}
	g.auth.guestSignals.mu.Lock()
	inFlight := g.auth.guestSignals.inFlight
	g.auth.guestSignals.mu.Unlock()
	if inFlight != 4 {
		t.Fatalf("reserved %d records, want one per reason and account", inFlight)
	}
	for range 3 {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("reserved record did not reach the recorder")
		}
	}
	once.Do(func() { close(release) })
	g.auth.guestSignals.wg.Wait()
	if rows := g.rows(t); len(rows) != 4 {
		t.Fatalf("recorded %d rows, want one per reason and account", len(rows))
	}
}

func TestSandboxGuestFailedRecorderRetriesAfterDelay(t *testing.T) {
	g := newGuestSignalFixture(t)
	id := boundRegistration(t, g.f, sbxAlice, 1)
	g.now = g.now.Add(sandboxGuestGrace)
	attempts := 0
	g.auth.guestSignals.record = func(context.Context, audit.SandboxRegistrationWithoutGuestEvent) error {
		attempts++
		return errors.New("recorder unavailable")
	}
	call := func() {
		if code, body := g.f.report(sbxAlice, id, true); code != http.StatusOK {
			t.Fatalf("state: %d %v", code, body)
		}
		g.auth.guestSignals.wg.Wait()
	}
	call()
	call()
	if attempts != 1 {
		t.Fatalf("immediate retry attempts = %d", attempts)
	}
	g.now = g.now.Add(sandboxGuestSignalRetry - time.Nanosecond)
	call()
	if attempts != 1 {
		t.Fatalf("early retry attempts = %d", attempts)
	}
	g.now = g.now.Add(time.Nanosecond)
	call()
	if attempts != 2 {
		t.Fatalf("retry attempts = %d", attempts)
	}
}

func TestSandboxGuestRecorderUsesIndependentDeadline(t *testing.T) {
	g := newGuestSignalFixture(t)
	id := boundRegistration(t, g.f, sbxAlice, 1)
	g.now = g.now.Add(sandboxGuestGrace)
	type deadlineObservation struct {
		deadline time.Time
		at       time.Time
		present  bool
		err      error
	}
	observed := make(chan deadlineObservation, 1)
	g.auth.guestSignals.record = func(ctx context.Context, _ audit.SandboxRegistrationWithoutGuestEvent) error {
		deadline, present := ctx.Deadline()
		observed <- deadlineObservation{deadline: deadline, at: time.Now(), present: present, err: ctx.Err()}
		return nil
	}
	reg, _, err := g.auth.store.Get(sbxAlice.UID, id)
	if err != nil {
		t.Fatal(err)
	}
	request, cancel := context.WithCancel(context.Background())
	cancel()
	g.f.api.sandboxGuestSignal(request, g.auth, reg, audit.SandboxGuestRelayWithoutGuest)
	g.auth.guestSignals.wg.Wait()
	select {
	case got := <-observed:
		if !got.present || got.err != nil || got.deadline.Before(got.at) ||
			got.deadline.After(got.at.Add(sandboxGuestRecordTimeout)) {
			t.Fatalf("recorder deadline/cancellation: %+v", got)
		}
	default:
		t.Fatal("recorder was not started")
	}
}

func TestSandboxGuestRecorderInFlightCap(t *testing.T) {
	g := newGuestSignalFixture(t)
	ids := make([]string, sandboxGuestRecordMax+1)
	for i := range ids {
		ids[i] = boundRegistration(t, g.f, sbxAlice, i+1)
	}
	g.now = g.now.Add(sandboxGuestGrace)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	started := make(chan struct{}, len(ids))
	g.auth.guestSignals.record = func(ctx context.Context, event audit.SandboxRegistrationWithoutGuestEvent) error {
		started <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for _, id := range ids {
		reg, _, err := g.auth.store.Get(sbxAlice.UID, id)
		if err != nil {
			t.Fatal(err)
		}
		g.f.api.sandboxGuestSignal(context.Background(), g.auth, reg, audit.SandboxGuestRelayWithoutGuest)
	}
	g.auth.guestSignals.mu.Lock()
	inFlight := g.auth.guestSignals.inFlight
	last := g.auth.guestSignals.last[sandboxGuestSignalKey{uid: sbxAlice.UID, id: ids[len(ids)-1], reason: audit.SandboxGuestRelayWithoutGuest}]
	g.auth.guestSignals.mu.Unlock()
	if inFlight != sandboxGuestRecordMax || last.pending || !last.next.Equal(g.now.Add(sandboxGuestSignalRetry)) {
		t.Fatalf("capacity state: in-flight=%d last=%+v", inFlight, last)
	}
	once.Do(func() { close(release) })
	g.auth.guestSignals.wg.Wait()
	if len(started) != sandboxGuestRecordMax {
		t.Fatalf("started %d recorders", len(started))
	}
	g.now = g.now.Add(sandboxGuestSignalRetry)
	reg, _, err := g.auth.store.Get(sbxAlice.UID, ids[len(ids)-1])
	if err != nil {
		t.Fatal(err)
	}
	g.f.api.sandboxGuestSignal(context.Background(), g.auth, reg, audit.SandboxGuestRelayWithoutGuest)
	g.auth.guestSignals.wg.Wait()
	if len(started) != len(ids) {
		t.Fatalf("retry started %d recorders", len(started))
	}
}

func TestSandboxGuestSignalAdmittedPathsKeepResponses(t *testing.T) {
	g := newGuestSignalFixture(t)
	id := g.f.resolve(sbxAlice, claudeResolve()).Registration.ID
	bind := g.f.bind(sbxAlice, id, 1)
	if bind.Code != http.StatusOK || !strings.Contains(bind.Body.String(), id) {
		t.Fatalf("bind: %d %s", bind.Code, bind.Body.String())
	}
	bound, ok, err := g.auth.store.Get(sbxAlice.UID, id)
	if err != nil || !ok {
		t.Fatalf("bound registration: %+v %v %v", bound, ok, err)
	}
	wantBind, err := json.Marshal(sandboxRegistrationView(bound))
	if err != nil {
		t.Fatal(err)
	}
	if got := bind.Body.String(); got != string(wantBind)+"\n" || bind.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("bind response changed: %d %q %v", bind.Code, got, bind.Header())
	}
	g.now = g.now.Add(sandboxGuestGrace - time.Nanosecond)
	stateBefore := guestSnapshot(g.f.do(sbxAlice, http.MethodPost,
		sandboxrelay.PathRegistrations+id+sandboxrelay.RegistrationStateSub,
		sandboxrelay.StateReport{V: 1, Running: true}, nil))
	hookBefore := guestSnapshot(g.f.hook(sbxAlice, id, "claudecode", nil))
	if stateBefore.status != http.StatusOK || hookBefore.status != http.StatusOK || len(g.rows(t)) != 0 {
		t.Fatalf("before grace: state=%+v hook=%+v rows=%d", stateBefore, hookBefore, len(g.rows(t)))
	}
	g.now = g.now.Add(time.Nanosecond) // The boundary is inclusive.
	stateAfter := guestSnapshot(g.f.do(sbxAlice, http.MethodPost,
		sandboxrelay.PathRegistrations+id+sandboxrelay.RegistrationStateSub,
		sandboxrelay.StateReport{V: 1, Running: true}, nil))
	hookAfter := guestSnapshot(g.f.hook(sbxAlice, id, "claudecode", nil))
	if !reflect.DeepEqual(stateBefore, stateAfter) || !reflect.DeepEqual(hookBefore, hookAfter) {
		t.Fatalf("response changed at the signal boundary: state %v -> %v, relay %v -> %v",
			stateBefore, stateAfter, hookBefore, hookAfter)
	}
	rows := g.rows(t)
	if len(rows) != 2 {
		t.Fatalf("got %d guest alert rows, want state and relay", len(rows))
	}
	for _, row := range rows {
		body := row.Structured
		for key, want := range map[string]any{
			"user.id": fmt.Sprint(sbxAlice.UID), "defenseclaw.user.name": sbxAlice.Name,
			"defenseclaw.sandbox.registration.id": id, "defenseclaw.sandbox.id": "sbx-1",
			"defenseclaw.sandbox.name": "dc-claude-1", "defenseclaw.sandbox.phase": "ready",
		} {
			if got := body[key]; got != want {
				t.Errorf("%s = %v, want %v; row=%+v", key, got, want, row)
			}
		}
		if row.Connector != "claudecode" {
			t.Errorf("connector = %q", row.Connector)
		}
	}
	if rows[0].Structured["defenseclaw.sandbox.managed.reason"] == rows[1].Structured["defenseclaw.sandbox.managed.reason"] {
		t.Fatalf("two paths got the same reason: %+v", rows)
	}
	// An unavailable recorder is logged by the signal path; the caller still
	// receives the same policy and relay bytes on later attempts.
	g.now = g.now.Add(sandboxGuestSignalEvery)
	g.f.api.logger.SetRuntimeV8Emitter(nil)
	if got := guestSnapshot(g.f.do(sbxAlice, http.MethodPost,
		sandboxrelay.PathRegistrations+id+sandboxrelay.RegistrationStateSub,
		sandboxrelay.StateReport{V: 1, Running: true}, nil)); !reflect.DeepEqual(stateAfter, got) {
		t.Fatalf("state response changed on recorder failure: %+v -> %+v", stateAfter, got)
	}
	if got := guestSnapshot(g.f.hook(sbxAlice, id, "claudecode", nil)); !reflect.DeepEqual(hookAfter, got) {
		t.Fatalf("relay response changed on recorder failure: %+v -> %+v", hookAfter, got)
	}
	if got := len(g.rows(t)); got != 2 {
		t.Fatalf("recorder failure created %d alert rows", got)
	}
}

func TestSandboxGuestSightingSurvivesQuietRestart(t *testing.T) {
	for _, kind := range []string{sandboxrelay.EventSandboxLifecycle, sandboxrelay.EventSandboxEgress} {
		t.Run(kind, func(t *testing.T) {
			g := newGuestSignalFixture(t)
			// Creation queues the first lifecycle records before bind; the
			// events route accepts them only after the registration is bound.
			created := g.now
			id := g.f.resolve(sbxAlice, claudeResolve()).Registration.ID
			g.now = g.now.Add(time.Minute)
			if rec := g.f.bind(sbxAlice, id, 1); rec.Code != http.StatusOK {
				t.Fatalf("bind: %d %s", rec.Code, rec.Body.String())
			}
			claim := map[string]any{"sandbox": "dc-claude-1", "sandbox_id": "sbx-1"}
			if kind == sandboxrelay.EventSandboxLifecycle {
				claim["phase"] = "ready"
			} else {
				claim["source"], claim["host"], claim["port"] = "dc-egress-proxy", "example.com", 443
			}
			stamp := g.now
			if kind == sandboxrelay.EventSandboxLifecycle {
				stamp = created
			}
			events := []sandboxrelay.Event{telemetryEvent(t, kind, stamp, claim)}
			if kind == sandboxrelay.EventSandboxLifecycle {
				creating := map[string]any{"sandbox": "dc-claude-1", "sandbox_id": "sbx-1", "phase": "creating"}
				events = append([]sandboxrelay.Event{telemetryEvent(t, kind, created, creating)}, events...)
			}
			if rec := postEvents(g.f, sbxAlice, id, events...); rec.Code != http.StatusAccepted {
				t.Fatalf("event: %d %s", rec.Code, rec.Body.String())
			}
			file := sandboxreg.NewFileStore(sandboxreg.RegistrationsDir(g.f.cfg.DataDir))
			reg, ok, err := file.Get(sbxAlice.UID, id)
			if err != nil || !ok || !reg.GuestSeenAt.Equal(g.now) {
				t.Fatalf("persisted sighting: %+v %v %v", reg, ok, err)
			}
			g.now = g.now.Add(sandboxGuestGrace)
			if code, _ := g.f.report(sbxAlice, id, true); code != http.StatusOK {
				t.Fatalf("running state: %d", code)
			}
			if rec := g.f.hook(sbxAlice, id, "claudecode", nil); rec.Code != http.StatusOK {
				t.Fatalf("relay: %d %s", rec.Code, rec.Body.String())
			}
			if len(g.rows(t)) != 0 {
				t.Fatalf("guest with sighting alerted: %+v", g.rows(t))
			}
			restarted := newSandboxFixtureOn(t, g.f)
			newStore, newLogger := testStoreAndLogger(t)
			restarted.api.store, restarted.api.logger = newStore, newLogger
			restartedAuth, err := restarted.api.sandboxAuth()
			if err != nil {
				t.Fatal(err)
			}
			restartedAuth.now = func() time.Time { return g.now }
			restartedAuth.store.(*sandboxreg.FileStore).Now = restartedAuth.clock
			t.Cleanup(restartedAuth.guestSignals.wg.Wait)
			if code, _ := restarted.report(sbxAlice, id, true); code != http.StatusOK {
				t.Fatalf("restart running state: %d", code)
			}
			if rec := restarted.hook(sbxAlice, id, "claudecode", nil); rec.Code != http.StatusOK {
				t.Fatalf("restart relay: %d %s", rec.Code, rec.Body.String())
			}
			if rows := auditEventsOf(t, newStore, audit.ActionSandboxManaged); len(rows) != 0 {
				t.Fatalf("restart emitted %d managed rows", len(rows))
			}
		})
	}
}

func TestSandboxGuestSightingRequiresAcceptedMatchingBoundRecord(t *testing.T) {
	g := newGuestSignalFixture(t)
	id := g.f.resolve(sbxAlice, claudeResolve()).Registration.ID
	pendingEvent := telemetryEvent(t, sandboxrelay.EventSandboxLifecycle, g.now,
		map[string]any{"sandbox": "dc-claude-1", "phase": "ready"})
	if rec := postEvents(g.f, sbxAlice, id, pendingEvent); rec.Code != http.StatusForbidden {
		t.Fatalf("pending event: %d %s", rec.Code, rec.Body.String())
	}
	g.now = g.now.Add(time.Minute)
	if rec := g.f.bind(sbxAlice, id, 1); rec.Code != http.StatusOK {
		t.Fatalf("bind: %d %s", rec.Code, rec.Body.String())
	}
	for _, ev := range []sandboxrelay.Event{
		telemetryEvent(t, sandboxrelay.EventSandboxLifecycle, g.now, map[string]any{"sandbox": "another-box", "phase": "ready"}),
		telemetryEvent(t, sandboxrelay.EventSandboxLifecycle, g.now, map[string]any{"sandbox": "dc-claude-1", "sandbox_id": "another-id", "phase": "ready"}),
	} {
		if rec := postEvents(g.f, sbxAlice, id, ev); rec.Code != http.StatusAccepted {
			t.Fatalf("post accepted but not sighted: %d %s", rec.Code, rec.Body.String())
		}
	}
	reg, _, err := g.auth.store.Get(sbxAlice.UID, id)
	if err != nil || !reg.GuestSeenAt.IsZero() {
		t.Fatalf("unmatched record counted: %+v %v", reg, err)
	}
	g.now = g.now.Add(sandboxGuestGrace)
	if code, _ := g.f.report(sbxAlice, id, true); code != http.StatusOK {
		t.Fatalf("state report: %d", code)
	}
	if rows := g.rows(t); len(rows) != 1 || rows[0].Structured["defenseclaw.sandbox.managed.reason"] != audit.SandboxGuestRunningWithoutGuest {
		t.Fatalf("unmatched records suppressed the expected alert: %d rows", len(rows))
	}
	if err := g.auth.store.Revoke(sbxAlice.UID, id, sandboxreg.ReasonPolicyChanged); err != nil {
		t.Fatal(err)
	}
	if rec := postEvents(g.f, sbxAlice, id, telemetryEvent(t, sandboxrelay.EventSandboxLifecycle, g.now,
		map[string]any{"sandbox": "dc-claude-1", "phase": "stopped"})); rec.Code != http.StatusAccepted {
		t.Fatalf("tombstone event: %d %s", rec.Code, rec.Body.String())
	}
	reg, _, _ = g.auth.store.Get(sbxAlice.UID, id)
	if !reg.GuestSeenAt.IsZero() {
		t.Fatalf("tombstone marked: %+v", reg)
	}
}

func TestSandboxGuestFailedRecordIsNotASighting(t *testing.T) {
	g := newGuestSignalFixture(t)
	id := boundRegistration(t, g.f, sbxAlice, 1)
	g.f.api.logger.SetRuntimeV8Emitter(nil)
	if rec := postEvents(g.f, sbxAlice, id, telemetryEvent(t, sandboxrelay.EventSandboxLifecycle, g.now,
		map[string]any{"sandbox": "dc-claude-1", "sandbox_id": "sbx-1", "phase": "ready"})); rec.Code != http.StatusAccepted {
		t.Fatalf("event route: %d %s", rec.Code, rec.Body.String())
	}
	reg, _, err := g.auth.store.Get(sbxAlice.UID, id)
	if err != nil || !reg.GuestSeenAt.IsZero() {
		t.Fatalf("failed record counted: %+v %v", reg, err)
	}
}

func TestSandboxGuestFirstSightingEndsWatch(t *testing.T) {
	g := newGuestSignalFixture(t)
	id := boundRegistration(t, g.f, sbxAlice, 1)
	if rec := postEvents(g.f, sbxAlice, id, telemetryEvent(t, sandboxrelay.EventSandboxLifecycle, g.now,
		map[string]any{"sandbox": "dc-claude-1", "sandbox_id": "sbx-1", "phase": "ready"})); rec.Code != http.StatusAccepted {
		t.Fatalf("event route: %d %s", rec.Code, rec.Body.String())
	}
	for range 2 {
		g.now = g.now.Add(sandboxGuestGrace + sandboxGuestSignalEvery)
		g.f.report(sbxAlice, id, true)
		g.f.hook(sbxAlice, id, "claudecode", nil)
	}
	if rows := g.rows(t); len(rows) != 0 {
		t.Fatalf("sighted registration alerted again: %d rows", len(rows))
	}
}

func TestSandboxGuestSignalRatePruningAndOlderRegistration(t *testing.T) {
	g := newGuestSignalFixture(t)
	id := boundRegistration(t, g.f, sbxAlice, 1)
	g.now = g.now.Add(sandboxGuestGrace)
	if rec := g.f.hook(sbxAlice, id, "claudecode", nil); rec.Code != http.StatusForbidden {
		// The live lease also expires at the grace boundary. Renew first.
		if rec.Code != http.StatusOK {
			t.Fatalf("relay: %d %s", rec.Code, rec.Body.String())
		}
	}
	if code, _ := g.f.report(sbxAlice, id, true); code != http.StatusOK {
		t.Fatalf("state: %d", code)
	}
	if rec := g.f.hook(sbxAlice, id, "claudecode", nil); rec.Code != http.StatusOK {
		t.Fatalf("relay after renewal: %d", rec.Code)
	}
	before := len(g.rows(t))
	if before == 0 {
		t.Fatal("no guest alert")
	}
	g.f.hook(sbxAlice, id, "claudecode", nil)
	if got := len(g.rows(t)); got != before {
		t.Fatalf("second hit made %d rows, want %d", got, before)
	}
	g.now = g.now.Add(sandboxGuestSignalEvery)
	g.f.report(sbxAlice, id, true)
	g.f.hook(sbxAlice, id, "claudecode", nil)
	if got := len(g.rows(t)); got != before+2 {
		t.Fatalf("after rate window: %d rows, want %d", got, before+2)
	}
	if err := g.auth.store.Deleted(sbxAlice.UID, id); err != nil {
		t.Fatal(err)
	}
	g.auth.guestSignals.mu.Lock()
	remaining := len(g.auth.guestSignals.last)
	g.auth.guestSignals.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("gone registration left %d rate keys", remaining)
	}
	// An older store file has no watch marker and is never evaluated.
	oldID := boundRegistration(t, g.f, sbxAlice, 2)
	path := filepath.Join(sandboxreg.RegistrationsDir(g.f.cfg.DataDir), fmt.Sprintf("%d.json", sbxAlice.UID))
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err := json.Unmarshal(blob, &data); err != nil {
		t.Fatal(err)
	}
	for _, item := range data["registrations"].([]any) {
		reg := item.(map[string]any)
		if reg["id"] == oldID {
			delete(reg, "guest_watch")
		}
	}
	blob, _ = json.Marshal(data)
	if err := os.WriteFile(path, blob, 0600); err != nil {
		t.Fatal(err)
	}
	oldStore := sandboxreg.NewFileStore(sandboxreg.RegistrationsDir(g.f.cfg.DataDir))
	oldStore.Now = g.auth.clock
	g.auth.store = oldStore
	g.now = g.now.Add(sandboxGuestGrace)
	g.f.report(sbxAlice, oldID, true)
	g.f.hook(sbxAlice, oldID, "claudecode", nil)
	if got := len(g.rows(t)); got != before+2 {
		t.Fatalf("older registration alerted: %d rows", got)
	}
	// The rate map remains bounded even when it was filled by many accounts.
	g.auth.guestSignals.mu.Lock()
	for i := range sandboxGuestSignalMax {
		g.auth.guestSignals.last[sandboxGuestSignalKey{uid: i + 1, id: fmt.Sprint(i), reason: audit.SandboxGuestRelayWithoutGuest}] = sandboxGuestRate{next: g.now.Add(sandboxGuestSignalEvery)}
	}
	g.auth.guestSignals.mu.Unlock()
	newID := boundRegistration(t, g.f, sbxAlice, 3)
	newReg, _, err := g.auth.store.Get(sbxAlice.UID, newID)
	if err != nil {
		t.Fatal(err)
	}
	g.now = g.now.Add(sandboxGuestGrace)
	g.f.api.sandboxGuestSignal(context.Background(), g.auth, newReg, audit.SandboxGuestRelayWithoutGuest)
	g.auth.guestSignals.wg.Wait()
	g.auth.guestSignals.mu.Lock()
	rateCount := len(g.auth.guestSignals.last)
	_, rateOK := g.auth.guestSignals.last[sandboxGuestSignalKey{uid: sbxAlice.UID, id: newID, reason: audit.SandboxGuestRelayWithoutGuest}]
	g.auth.guestSignals.mu.Unlock()
	if rateCount != sandboxGuestSignalMax {
		t.Fatalf("rate map length = %d", rateCount)
	}
	if !rateOK {
		t.Fatal("bounded rate map omitted the current registration")
	}
}

func TestSandboxGuestSignalRejectsOtherRegistrationsUnchanged(t *testing.T) {
	g := newGuestSignalFixture(t)
	live := boundRegistration(t, g.f, sbxAlice, 1)
	pending := g.f.resolve(sbxAlice, claudeResolve()).Registration.ID
	unknown, _ := sandboxreg.NewID()
	g.now = g.now.Add(sandboxGuestGrace)
	for _, id := range []string{live, unknown, pending} {
		rec := g.f.hook(sbxBob, id, "claudecode", nil)
		if rec.Code != http.StatusNotFound || errorReason(t, rec) != sandboxrelay.ReasonRegistrationUnknown {
			t.Fatalf("other account or unknown %q: %d %s", id, rec.Code, rec.Body.String())
		}
	}
	if rec := g.f.hook(sbxAlice, pending, "claudecode", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("pending relay: %d %s", rec.Code, rec.Body.String())
	}
	if len(g.rows(t)) != 0 {
		t.Fatalf("refused routes emitted %d guest alerts", len(g.rows(t)))
	}
	if code, _ := g.f.report(sbxAlice, live, true); code != http.StatusOK {
		t.Fatalf("live state report: %d", code)
	}
	if rows := g.rows(t); len(rows) != 1 || rows[0].Structured["defenseclaw.sandbox.managed.reason"] != audit.SandboxGuestRunningWithoutGuest {
		t.Fatalf("admitted state omitted the expected alert: %d rows", len(rows))
	}
}
