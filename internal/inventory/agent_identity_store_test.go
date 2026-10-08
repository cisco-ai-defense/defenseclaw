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
	if removed, err := st.PruneAgentIdentitySessions(ctx, time.Time{}); err != nil || removed != 0 {
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
	if removed, err := st.PruneAgentIdentitySessions(ctx, time.Time{}); err != nil || removed != 3 {
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

// Active identities keep only sessions seen inside the retention window.
func TestAgentIdentitySessionRetentionForActiveAgent(t *testing.T) {
	st, err := NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	old := now.Add(-40 * 24 * time.Hour)
	rec := AgentIdentityRecord{
		AgentID: "agt-active", UserID: "1001", Connector: "codex", MachineHash: "m",
		FirstSeen: old, LastSeen: old, SessionsSeen: 1,
	}
	for _, id := range []string{"expired", "ongoing"} {
		rec.SessionIDs, rec.LastSessionID = []string{id}, id
		if err := st.UpsertAgentIdentities(ctx, []AgentIdentityRecord{rec}); err != nil {
			t.Fatal(err)
		}
	}
	// A resumed session must refresh its retention clock without changing
	// the cumulative distinct-session count.
	rec.LastSeen = now.Add(-time.Hour)
	rec.SessionIDs, rec.LastSessionID = []string{"ongoing"}, "ongoing"
	if err := st.UpsertAgentIdentities(ctx, []AgentIdentityRecord{rec}); err != nil {
		t.Fatal(err)
	}
	pruneAgentLedger(ctx, st, now.Add(-30*24*time.Hour), 30, &inventoryHistorySweeper{}, now, "test")
	rows, err := st.db.QueryContext(ctx, `SELECT session_id FROM agent_identity_sessions WHERE agent_id = ?`, rec.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var sessions []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0] != "ongoing" {
		t.Fatalf("retained session ids = %v, want only ongoing", sessions)
	}
	agents, _, err := st.ListAgentIdentities(ctx, AgentIdentityFilter{AgentIDs: []string{rec.AgentID}})
	if err != nil || len(agents) != 1 || agents[0].SessionsSeen != 2 {
		t.Fatalf("active agent after prune = %+v, err %v; want cumulative count 2", agents, err)
	}
	if err := st.UpsertAgentIdentities(ctx, []AgentIdentityRecord{rec}); err != nil {
		t.Fatal(err)
	}
	agents, _, err = st.ListAgentIdentities(ctx, AgentIdentityFilter{AgentIDs: []string{rec.AgentID}})
	if err != nil || len(agents) != 1 || agents[0].SessionsSeen != 2 {
		t.Fatalf("resumed session counted twice: %+v, err %v", agents, err)
	}
}
