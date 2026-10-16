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
