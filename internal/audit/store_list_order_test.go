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

package audit

import (
	"strings"
	"testing"
	"time"
)

// ListEvents lists newest first by the exact time,
// not by the RFC3339Nano text (rel-1-0-2:GAP-0484). That text drops trailing
// zeros and keeps the zone offset, so ".12345Z" sorts after ".123451Z" and a
// "+02:00" row sorts after a later UTC row. macOS clocks tick in whole
// microseconds, which made sandbox lifecycle phases list out of order there.
func TestListEventsOrdersByExactTimeNotText(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	base := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	plus2 := time.FixedZone("plus2", 2*60*60)
	rows := []struct {
		id string
		ts time.Time
	}{
		{"trailing-zero", base.Add(123450 * time.Microsecond)}, // ...00.12345Z
		{"one-us-later", base.Add(123451 * time.Microsecond)},  // ...00.123451Z
		{"tie-first", base.Add(time.Second)},
		{"tie-second", base.Add(time.Second)},
		{"offset-zone", base.Add(2 * time.Second).In(plus2)}, // 14:00:02+02:00
		{"later-utc", base.Add(3 * time.Second)},
	}
	for _, row := range rows {
		if err := store.LogEvent(Event{ID: row.id, Timestamp: row.ts, Action: "order-probe",
			Target: "sbx-order", Actor: "test", Severity: "INFO"}); err != nil {
			t.Fatalf("LogEvent %s: %v", row.id, err)
		}
	}
	want := "later-utc,offset-zone,tie-second,tie-first,one-us-later,trailing-zero"

	ids := func(events []Event) string {
		out := make([]string, 0, len(events))
		for _, e := range events {
			out = append(out, e.ID)
		}
		return strings.Join(out, ",")
	}
	events, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if got := ids(events); got != want {
		t.Fatalf("ListEvents order %s, want %s", got, want)
	}

	// A store over a database from before the v8 retention migration has
	// no exact-instant column; ListEvents still answers, in time order.
	for _, statement := range []string{
		`DROP TRIGGER retention_audit_events_timestamp_insert`,
		`DROP TRIGGER retention_audit_events_timestamp_update`,
		`DROP INDEX idx_retention_audit_events_timestamp`,
		`ALTER TABLE audit_events DROP COLUMN retention_timestamp_unix_nano`,
	} {
		if _, err := store.db.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	events, err = store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents without the retention column: %v", err)
	}
	if got := ids(events); got != want {
		t.Fatalf("ListEvents order without the retention column %s, want %s", got, want)
	}
}

func TestListAlertsOrdersByExactTime(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	for _, row := range []struct{ id, timestamp string }{
		{"earlier", "2026-10-13T12:00:00.12345Z"},
		{"later", "2026-10-13T12:00:00.123451Z"},
	} {
		if _, err := store.db.Exec(`INSERT INTO audit_events
			(id, timestamp, action, actor, severity, bucket, event_name)
			VALUES (?, ?, 'scan-finding', 'test', 'HIGH', 'security.finding', 'finding.observed')`, row.id, row.timestamp); err != nil {
			t.Fatal(err)
		}
	}
	alerts, err := store.ListAlerts(2)
	if err != nil || len(alerts) != 2 || alerts[0].ID != "later" || alerts[1].ID != "earlier" {
		t.Fatalf("alerts = %+v, %v", alerts, err)
	}
}

func TestActivityAndScanReadersUseExactTimeAndInsertTies(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	base := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	stamps := []struct {
		id string
		ts time.Time
	}{
		{"short", base.Add(123450 * time.Microsecond)},
		{"long", base.Add(123451 * time.Microsecond)},
		{"tie-first", base.Add(time.Second)},
		{"tie-second", base.Add(time.Second)},
		{"offset", base.Add(2 * time.Second).In(time.FixedZone("plus2", 7200))},
	}
	for _, item := range stamps {
		if err := store.InsertActivityEvent(ActivityEventRow{ID: item.id, Timestamp: item.ts, Actor: "operator", Action: "change", TargetType: "policy", TargetID: item.id}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec(`INSERT INTO scan_results (id, scanner, target, timestamp, duration_ms, finding_count) VALUES (?, 'scan', 'same', ?, 0, 1)`, item.id, item.ts.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	want := "offset,tie-second,tie-first,long,short"
	activity, err := store.ListActivityEvents(5)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(activity))
	for _, row := range activity {
		ids = append(ids, row.ID)
	}
	if got := strings.Join(ids, ","); got != want {
		t.Fatalf("activity: %s want %s", got, want)
	}
	scans, err := store.ListScanResults(5)
	if err != nil {
		t.Fatal(err)
	}
	ids = ids[:0]
	for _, row := range scans {
		ids = append(ids, row.ID)
	}
	if got := strings.Join(ids, ","); got != want {
		t.Fatalf("scan results: %s want %s", got, want)
	}
	latest, err := store.LatestScansByScanner("scan")
	if err != nil {
		t.Fatal(err)
	}
	if len(latest) != 1 || latest[0].ID != "offset" {
		t.Fatalf("latest scan: %+v", latest)
	}
}

func TestRecentSessionFindingsUseExactTimeAndInsertTies(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	if _, err := store.db.Exec(`INSERT INTO scan_results (id, scanner, target, timestamp)
		VALUES ('scan', 'hook', 'target', '2026-10-13T12:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ id, stamp string }{
		{"short", "2026-10-13T12:00:00.12345Z"},
		{"long", "2026-10-13T12:00:00.123451Z"},
		{"tie-first", "2026-10-13T12:00:01Z"},
		{"tie-second", "2026-10-13T12:00:01Z"},
		{"offset", "2026-10-13T14:00:02+02:00"},
	} {
		_, err := store.db.Exec(`INSERT INTO scan_findings
   (id, scan_id, scanner, target, severity, tags, timestamp, session_id, agent_instance_id)
   VALUES (?, 'scan', 'hook', 'target', 'HIGH', '[]', ?, 'session', 'agent')`, row.id, row.stamp)
		if err != nil {
			t.Fatal(err)
		}
	}
	rows, err := store.ListRecentFindingsInSession("session", "agent", "", 5)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	if got, want := strings.Join(ids, ","), "offset,tie-second,tie-first,long,short"; got != want {
		t.Fatalf("recent findings: %s want %s", got, want)
	}
}

// The network egress readers list newest first by the exact instant, with
// insert order on a tie, not by the timestamp text (GAP-0251): one instant
// written in two zones, or with a shorter fraction, sorted by its text.
func TestNetworkEgressReadersUseExactTimeAndInsertTies(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	base := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	stamps := []struct {
		id string
		ts time.Time
	}{
		{"short", base.Add(120 * time.Millisecond)},
		{"long", base.Add(123 * time.Millisecond)},
		{"tie-utc", base.Add(time.Second)},
		{"tie-offset", base.Add(time.Second).In(time.FixedZone("minus4", -4*60*60))},
		{"offset", base.Add(2 * time.Second).In(time.FixedZone("plus2", 7200))},
	}
	for _, item := range stamps {
		if err := store.InsertNetworkEgressEvent(NetworkEgressRow{ID: item.id, Timestamp: item.ts,
			Hostname: "egress.example", PolicyOutcome: "allowed"}); err != nil {
			t.Fatal(err)
		}
	}
	want := "offset,tie-offset,tie-utc,long,short"
	ids := func(rows []NetworkEgressRow) string {
		out := make([]string, 0, len(rows))
		for _, row := range rows {
			out = append(out, row.ID)
		}
		return strings.Join(out, ",")
	}
	for _, hostname := range []string{"", "egress.example"} {
		rows, err := store.ListNetworkEgressEvents(10, hostname)
		if err != nil {
			t.Fatal(err)
		}
		if got := ids(rows); got != want {
			t.Fatalf("list (host %q): %s want %s", hostname, got, want)
		}
	}
	rows, err := store.QueryNetworkEgressEvents(NetworkEgressFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(rows); got != want {
		t.Fatalf("query: %s want %s", got, want)
	}
}
