// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// Review of GAP-1263 (loop 1): a row keeps the domains of the account it was
// recorded for, a later sighting without them keeps them, and a qualified
// filter that resolves to the uid lists only the rows of its domain (and the
// rows an older build wrote without a domain).
func TestAgentIdentityRowsKeepTheirAccountDomain(t *testing.T) {
	st, err := NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	t0 := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	row := func(id, connector, domains string, seen time.Duration) AgentIdentityRecord {
		return AgentIdentityRecord{
			AgentID: id, UserID: "5000", UserName: "alice", UserDomain: domains, Connector: connector,
			MachineHash: "m", FirstSeen: t0, LastSeen: t0.Add(seen),
		}
	}
	corp, other := row("agt-corp", "codex", "corp.example corp", 0), row("agt-other", "claudecode", "other.example other", time.Minute)
	legacy := row("agt-legacy", "opencode", "", 2*time.Minute)
	if err := st.UpsertAgentIdentities(ctx, []AgentIdentityRecord{corp, other, legacy}); err != nil {
		t.Fatal(err)
	}
	again := other
	again.UserDomain, again.LastSeen = "", t0.Add(time.Hour)
	if err := st.UpsertAgentIdentities(ctx, []AgentIdentityRecord{again}); err != nil {
		t.Fatal(err)
	}
	list := func(filter AgentIdentityFilter) []string {
		t.Helper()
		rows, total, err := st.ListAgentIdentities(ctx, filter)
		if err != nil || total != len(rows) {
			t.Fatalf("list = %d rows of %d, %v", len(rows), total, err)
		}
		var ids []string
		for _, rec := range rows {
			ids = append(ids, rec.AgentID)
			if rec.AgentID == "agt-other" && rec.UserDomain != "other.example other" {
				t.Fatalf("agt-other domains = %q after a sighting without them", rec.UserDomain)
			}
		}
		slices.Sort(ids)
		return ids
	}
	if got := list(AgentIdentityFilter{User: "alice@other.example", UserIDs: []string{"5000"}}); !slices.Equal(got, []string{"agt-legacy", "agt-other"}) {
		t.Errorf("alice@other.example lists %v; want OTHER's row and the row without a domain", got)
	}
	if got := list(AgentIdentityFilter{User: `CORP\alice`, UserIDs: []string{"5000"}}); !slices.Equal(got, []string{"agt-corp", "agt-legacy"}) {
		t.Errorf(`CORP\alice lists %v`, got)
	}
	if got := list(AgentIdentityFilter{User: "alice"}); len(got) != 3 {
		t.Errorf("the bare name lists %v; want every row", got)
	}
}
