// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestAgentIdentitiesUpsertMergesBatchesAndFilters(t *testing.T) {
	st, err := NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	t0 := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	alice := AgentIdentityRecord{
		AgentID: "agt-00000000000000a1", UserID: "1001", UserName: "alice", Connector: "claudecode",
		InstallFP: "/home/alice/.claude", MachineHash: "m", FirstSeen: t0, LastSeen: t0.Add(time.Second),
		LastSessionID: "s1", SessionsSeen: 1, SessionIDs: []string{"s1"},
	}
	bob := AgentIdentityRecord{
		AgentID: "agt-00000000000000b1", UserID: "1002", UserName: "bob@dclab.test", Connector: "codex",
		MachineHash: "m", FirstSeen: t0, LastSeen: t0, LastSessionID: "s9", SessionsSeen: 1,
	}
	if err := st.UpsertAgentIdentities(ctx, []AgentIdentityRecord{alice, bob}); err != nil {
		t.Fatal(err)
	}
	// A later batch for alice: a second session, plus a stale first_seen
	// from a flush that raced the first one.
	later := alice
	later.FirstSeen, later.LastSeen, later.LastSessionID, later.UserName = t0.Add(-time.Minute), t0.Add(time.Hour), "s2", ""
	later.SessionIDs = []string{"s2"}
	if err := st.UpsertAgentIdentities(ctx, []AgentIdentityRecord{later}); err != nil {
		t.Fatal(err)
	}
	// GAP-0139: after a gateway restart the in-memory registry sees every
	// open session as new. Both are named again with one genuinely new one;
	// only that one is counted.
	restarted := alice
	restarted.LastSeen, restarted.LastSessionID = t0.Add(2*time.Hour), "s3"
	restarted.SessionsSeen, restarted.SessionIDs = 3, []string{"s1", "s2", "s3"}
	if err := st.UpsertAgentIdentities(ctx, []AgentIdentityRecord{restarted}); err != nil {
		t.Fatal(err)
	}

	rows, _, err := st.ListAgentIdentities(ctx, AgentIdentityFilter{User: "ALICE"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("user filter rows = %+v, want alice only", rows)
	}
	got := rows[0]
	if got.SessionsSeen != 3 || got.LastSessionID != "s3" || got.UserName != "alice" ||
		!got.FirstSeen.Equal(t0.Add(-time.Minute)) || !got.LastSeen.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("merged row = %+v", got)
	}
	if removed, err := st.PruneAgentIdentitySessions(ctx); err != nil || removed != 0 {
		t.Fatalf("session prune removed %d, err %v; active identity must keep its session ids", removed, err)
	}
	// The first chat stays active beyond retention and resumes after a restart.
	resumed := alice
	resumed.LastSeen = t0.Add(3 * time.Hour)
	if err := st.UpsertAgentIdentities(ctx, []AgentIdentityRecord{resumed}); err != nil {
		t.Fatal(err)
	}
	if rows, _, err := st.ListAgentIdentities(ctx, AgentIdentityFilter{User: "alice"}); err != nil || len(rows) != 1 || rows[0].SessionsSeen != 3 {
		t.Fatalf("resumed chat counted again: rows = %+v, err %v", rows, err)
	}
	// GAP-0366: a qualified filter lists only the account of that domain,
	// not the local alice whose row carries no domain.
	if rows, _, err = st.ListAgentIdentities(ctx, AgentIdentityFilter{User: "bob@DCLAB.TEST"}); err != nil || len(rows) != 1 || rows[0].UserID != "1002" {
		t.Fatalf("qualified user filter rows = %+v, err %v", rows, err)
	}
	if rows, _, err = st.ListAgentIdentities(ctx, AgentIdentityFilter{User: "alice@DCLAB.TEST"}); err != nil || len(rows) != 0 {
		t.Fatalf("qualified user filter selected a local account: rows = %+v, err %v", rows, err)
	}
	// GAP-0097: an SSSD account is stored by its qualified name; the bare
	// name still selects it.
	if rows, _, err = st.ListAgentIdentities(ctx, AgentIdentityFilter{User: "bob"}); err != nil || len(rows) != 1 || rows[0].UserID != "1002" {
		t.Fatalf("bare user filter rows = %+v, err %v", rows, err)
	}
	if rows, _, err = st.ListAgentIdentities(ctx, AgentIdentityFilter{Connector: "codex"}); err != nil || len(rows) != 1 || rows[0].UserID != "1002" {
		t.Fatalf("connector filter rows = %+v, err %v", rows, err)
	}
	if _, err := st.PruneAgentIdentities(ctx, t0.Add(4*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if removed, err := st.PruneAgentIdentitySessions(ctx); err != nil || removed != 3 {
		t.Fatalf("orphan session prune removed %d, err %v; want 3", removed, err)
	}
}

// A resumed older chat is already counted and cannot replace the last new chat.
func TestAgentIdentityResumedOlderSessionKeepsLastSession(t *testing.T) {
	st, err := NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	rec := AgentIdentityRecord{AgentID: "agt-resumed", UserID: "1001", Connector: "codex", MachineHash: "m", FirstSeen: now, LastSeen: now, SessionsSeen: 1, SessionIDs: []string{"s-old"}, LastSessionID: "s-old"}
	for _, session := range []string{"s-old", "s-new", "s-old"} {
		rec.SessionIDs = []string{session}
		rec.LastSessionID = session
		if err := st.UpsertAgentIdentities(ctx, []AgentIdentityRecord{rec}); err != nil {
			t.Fatal(err)
		}
		rec.LastSeen = rec.LastSeen.Add(time.Minute)
	}
	rows, _, err := st.ListAgentIdentities(ctx, AgentIdentityFilter{})
	if err != nil || len(rows) != 1 || rows[0].SessionsSeen != 2 || rows[0].LastSessionID != "s-new" {
		t.Fatalf("rows = %+v, err %v; want 2 sessions, last s-new", rows, err)
	}
}
