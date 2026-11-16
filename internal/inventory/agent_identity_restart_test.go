// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// Review of GAP-0947 (loop 2): a sighting of an agent ID recorded for an
// account of other domains is another account's (one bare name, uid and home
// in two domains that nothing else tells apart): the row starts again from
// it instead of keeping the former account's first_seen, last session and
// session count. A sighting without a domain, or of one of the row's
// domains, adds to the row as before.
func TestAgentIdentityRowStartsAgainForAnotherDomainsAccount(t *testing.T) {
	st, err := NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	t0 := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	sighting := func(domains, session string, at time.Time) AgentIdentityRecord {
		return AgentIdentityRecord{AgentID: "agt-0123456789abcdef", UserID: "5000", UserName: "alice", UserDomain: domains,
			Connector: "codex", MachineHash: "m", FirstSeen: at, LastSeen: at, SessionsSeen: 1,
			SessionIDs: []string{session}, LastSessionID: session}
	}
	row := func() AgentIdentityRecord {
		t.Helper()
		rows, _, err := st.ListAgentIdentities(ctx, AgentIdentityFilter{})
		if err != nil || len(rows) != 1 {
			t.Fatalf("rows = %+v, %v", rows, err)
		}
		return rows[0]
	}
	for _, rec := range []AgentIdentityRecord{sighting("corp.example corp", "s1", t0), sighting("", "s2", t0.Add(time.Minute)),
		sighting("corp", "s3", t0.Add(2*time.Minute))} {
		if err := st.UpsertAgentIdentities(ctx, []AgentIdentityRecord{rec}); err != nil {
			t.Fatal(err)
		}
	}
	if got := row(); !got.FirstSeen.Equal(t0) || got.SessionsSeen != 3 || got.UserDomain != "corp" {
		t.Fatalf("row after the same account's sightings = %+v", got)
	}
	later := t0.Add(time.Hour)
	if err := st.UpsertAgentIdentities(ctx, []AgentIdentityRecord{sighting("other.example other", "s1", later)}); err != nil {
		t.Fatal(err)
	}
	if got := row(); !got.FirstSeen.Equal(later) || got.SessionsSeen != 1 || got.LastSessionID != "s1" || got.UserDomain != "other.example other" {
		t.Fatalf("row after another domain's account = %+v; want it started again from that account's sighting", got)
	}
}
