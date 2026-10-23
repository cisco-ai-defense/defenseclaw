// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// pendingHookAttempts is the most recovery tries any journal row records.
func pendingHookAttempts(t *testing.T, f managedHookAuditFixture) int {
	t.Helper()
	most := 0
	for _, entry := range journalEntries(t, f) {
		var p pendingHookOccurrence
		if err := json.Unmarshal(entry.Occurrence, &p); err != nil {
			t.Fatal(err)
		}
		most = max(most, p.Attempts)
	}
	return most
}

// A restart after an outage that left more journal rows than one recovery
// pass takes audits every row while the gateway serves: the recovery loop
// runs the next bounded pass at once. Before, the start ran one pass, and
// the rows past its bound stayed unaudited until the journal filled or the
// gateway restarted.
func TestPendingHookRecoveryLoopAuditsAJournalLargerThanOnePass(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	passRows := pendingHookRecoveryPassRows
	t.Cleanup(func() { pendingHookRecoveryPassRows = passRows })
	pendingHookRecoveryPassRows = 7
	total := 3*pendingHookRecoveryPassRows + 2
	sessions := make([]string, 0, total)
	for i := range total {
		session := fmt.Sprintf("larger-than-a-pass-%02d", i)
		orphanPendingHook(t, f, session, pendingAllow)
		sessions = append(sessions, session)
	}
	runAPIUntil(t, f.restartedAPI(t, true), func() bool { return len(pendingEntries(t, f)) == 0 })
	audited := f.audited(t, sessions...)
	for _, session := range sessions {
		if audited[session] != "unconfirmed/no_answer" {
			t.Fatalf("%s: recovered audit = %q, want unconfirmed/no_answer", session, audited[session])
		}
		if got := f.hookRows(t, session); got != 1 {
			t.Fatalf("%s: connector rows = %d, want one", session, got)
		}
	}
	if evicted, alerts := f.evictedRows(t), f.evictionAlerts(t); len(evicted) != 0 || len(alerts) != 0 {
		t.Fatalf("evicted rows %v, eviction alerts %v; want none", evicted, alerts)
	}
}

// A row whose records the store refuses at start is tried again, a retry
// interval later, while the gateway serves; once the store takes records
// it is audited, not evicted. Before, the start ran one pass, and the row
// stayed until the journal filled or the gateway restarted.
func TestPendingHookRecoveryLoopRetriesARowTheStoreRefusedAtStart(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	interval := pendingHookRecoveryRetryInterval
	t.Cleanup(func() { pendingHookRecoveryRetryInterval = interval })
	pendingHookRecoveryRetryInterval = time.Second
	const session = "refused-at-start"
	orphanPendingHook(t, f, session, pendingAllow)
	lift := refuseAuditInserts(t, f, "audit_events", `NEW.session_id = '`+session+`' AND NEW.action <> 'alert'`)
	lifted := false
	defer func() {
		if !lifted {
			lift()
		}
	}()
	runAPIUntil(t, f.restartedAPI(t, true), func() bool {
		if !lifted {
			if pendingHookAttempts(t, f) < 1 {
				return false
			}
			lift()
			lifted = true
			return false
		}
		return len(pendingEntries(t, f)) == 0
	})
	if got := f.audited(t, session)[session]; got != "unconfirmed/no_answer" {
		t.Fatalf("recovered audit = %q, want unconfirmed/no_answer", got)
	}
	if got := f.hookRows(t, session); got != 1 {
		t.Fatalf("connector rows = %d, want one", got)
	}
	if alerts := f.evictionAlerts(t); alerts[session] != 0 {
		t.Fatalf("eviction alerts = %v, want none: the store took the records", alerts)
	}
}

// A handler whose records the store refused leaves its journal row; the
// recovery loop of the running gateway audits it, with the verdict the
// handler pinned, once the store takes records again. Before, the row
// stayed until the journal filled or the gateway restarted.
func TestPendingHookRecoveryLoopAuditsARowALiveHandlerLeft(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	interval := pendingHookRecoveryRetryInterval
	t.Cleanup(func() { pendingHookRecoveryRetryInterval = interval })
	pendingHookRecoveryRetryInterval = 300 * time.Millisecond
	// A row an earlier process left: once the start's pass audited it, that
	// pass is over, and the call below is made.
	const earlier, session = "left-before-the-start", "left-by-a-live-handler"
	orphanPendingHook(t, f, earlier, pendingAllow)
	running := f.restartedAPI(t, true)
	called := false
	runAPIUntil(t, running, func() bool {
		if !called {
			if f.hookRows(t, earlier) != 1 || len(pendingEntries(t, f)) != 0 {
				return false
			}
			lift := refuseAuditInserts(t, f, "audit_events", `NEW.session_id = '`+session+`' AND NEW.action <> 'alert'`)
			reply := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
			ackedHookCall(t, running, session, reply)
			left := len(pendingEntries(t, f))
			lift()
			called = true
			if !strings.Contains(reply.Body.String(), hookexec.HookDeliveryConfirmed) || left != 1 {
				t.Fatalf("call against a refusing store: response %q, journal rows %d; want the confirmed answer and its row",
					reply.Body.String(), left)
			}
			return false
		}
		return len(pendingEntries(t, f)) == 0
	})
	if got := f.audited(t, session)[session]; got != "allow" {
		t.Fatalf("recovered audit = %q, want the pinned allow", got)
	}
	if got := f.hookRows(t, session); got != 1 {
		t.Fatalf("connector rows = %d, want one", got)
	}
	if alerts := f.evictionAlerts(t); alerts[session] != 0 {
		t.Fatalf("eviction alerts = %v, want none", alerts)
	}
}

// While the store keeps refusing the records of a row, the loop spaces its
// tries: the first retry comes a retry interval after the first try, the
// next one twice that later, and the row is evicted after its last try, so
// its tries span a store outage instead of following each other.
func TestPendingHookRecoveryLoopSpacesTheTriesOfARefusedRow(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	interval := pendingHookRecoveryRetryInterval
	t.Cleanup(func() { pendingHookRecoveryRetryInterval = interval })
	pendingHookRecoveryRetryInterval = 300 * time.Millisecond
	const session = "refused-for-good"
	orphanPendingHook(t, f, session, pendingAllow)
	lift := refuseAuditInserts(t, f, "audit_events", `NEW.session_id = '`+session+`' AND NEW.action <> 'alert'`)
	defer lift()
	seen := map[int]time.Time{}
	runAPIUntil(t, f.restartedAPI(t, true), func() bool {
		now := time.Now()
		if len(pendingEntries(t, f)) == 0 {
			seen[pendingHookRecoveryAttempts+1] = now
			return true
		}
		if tries := pendingHookAttempts(t, f); seen[tries].IsZero() {
			seen[tries] = now
		}
		return false
	})
	slack := 60 * time.Millisecond
	second, last := seen[2].Sub(seen[1]), seen[pendingHookRecoveryAttempts+1].Sub(seen[2])
	if seen[1].IsZero() || seen[2].IsZero() || second < pendingHookRecoveryRetryInterval-slack ||
		last < 2*pendingHookRecoveryRetryInterval-slack {
		t.Fatalf("tries seen at %v: second try %v after the first, eviction %v after it; want at least %v and %v",
			seen, second, last, pendingHookRecoveryRetryInterval, 2*pendingHookRecoveryRetryInterval)
	}
	if alerts := f.evictionAlerts(t); alerts[session] != 1 {
		t.Fatalf("eviction alerts = %v, want one for the row", alerts)
	}
}
