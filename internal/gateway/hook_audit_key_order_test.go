// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"fmt"
	"regexp"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// uuidV7Prefix matches a time-ordered UUIDv7 at the start of a key.
var uuidV7Prefix = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`)

// GAP-0286: the audit rows of a journaled managed hook call are keyed by
// its pending occurrence ID (the connector-hook row by the ID, the
// hook_decision row by ID+"-decision"). A random UUIDv4 there put every
// insert on a random leaf of the audit_events primary key: once the store
// outgrew the page cache, each call read a cold page and dirtied another,
// on the one writer every hook waits for (cold insert on the grown 6.4 GB
// dc-ent-rhel store 1.9-2.3 ms with v4 keys, 0.2-0.3 ms with v7). The keys
// are time ordered, so new rows append to the index.
func TestJournaledManagedHookRowsHaveTimeOrderedKeys(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	const calls = 6
	for index := range calls {
		f.offer(t, fmt.Sprintf("keys-%d", index), hookexec.HookDeliveryConfirmed)
	}
	db, err := sql.Open("sqlite", "file:"+f.path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id, action FROM audit_events
		WHERE action IN ('connector-hook', 'hook_decision') AND session_id LIKE 'keys-%' ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	journaled, previous := 0, ""
	for rows.Next() {
		var id, action string
		if err := rows.Scan(&id, &action); err != nil {
			t.Fatal(err)
		}
		if !uuidV7Prefix.MatchString(id) {
			t.Errorf("%s row id %q is not a time-ordered UUIDv7", action, id)
		}
		if len(id) > 36 && id[36:] == "-decision" {
			journaled++
		}
		if key := id[:min(36, len(id))]; key < previous {
			t.Errorf("%s row id %q sorts before the row written before it (%q)", action, id, previous)
		} else {
			previous = key
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	// The calls went through the delivery journal: their hook_decision rows
	// carry the pending occurrence ID, so this test checks that path.
	if journaled != calls {
		t.Fatalf("journaled hook_decision rows = %d, want %d", journaled, calls)
	}
}
