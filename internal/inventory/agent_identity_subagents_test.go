// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// rel-1-0-4 GAP-0596: an agent identity row names the account's UPN and
// counts the sub-agent instances the agent ran, each once, on every OS. A
// 1.0.3 (v8) inventory.db is upgraded in place: its rows stay, with no UPN
// and no sub-agents until the agent is seen again.
func TestAgentIdentitiesRecordUPNAndSubagentsAcrossTheV9Upgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.db")
	st, err := NewInventoryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Make the store a v8 one, as 1.0.3 left it, holding one identity.
	for _, stmt := range []string{
		`DROP TABLE IF EXISTS agent_identity_subagents`,
		`ALTER TABLE agent_identities DROP COLUMN user_upn`,
		`ALTER TABLE agent_identities DROP COLUMN subagents_seen`,
		`ALTER TABLE agent_identities DROP COLUMN last_subagent_id`,
		`DELETE FROM schema_version WHERE version = 9`,
		`INSERT INTO agent_identities (agent_id, user_id, user_name, connector, install_fp, machine_hash, first_seen, last_seen, last_session_id, sessions_seen)
			VALUES ('agt-00000000000000c1', 'S-1-5-21-1-2-3-1104', 'carol', 'codex', '', 'm', '2026-10-01T00:00:00.000000000Z', '2026-10-01T00:00:00.000000000Z', 's0', 4)`,
	} {
		if _, err := st.db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	_ = st.Close()
	if st, err = NewInventoryStore(path); err != nil {
		t.Fatalf("upgrade the v8 store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if v, _ := st.SchemaVersion(); v != len(inventoryMigrations) {
		t.Fatalf("schema version after the upgrade = %d, want %d", v, len(inventoryMigrations))
	}
	rows, _, err := st.ListAgentIdentities(ctx, AgentIdentityFilter{})
	if err != nil || len(rows) != 1 || rows[0].SessionsSeen != 4 || rows[0].UPN != "" || rows[0].SubagentsSeen != 0 {
		t.Fatalf("1.0.3 row after the upgrade = %+v, err %v", rows, err)
	}

	t0 := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	carol := AgentIdentityRecord{
		AgentID: "agt-00000000000000c1", UserID: "S-1-5-21-1-2-3-1104", UserName: "carol", UPN: "carol@corp.example.com",
		Connector: "codex", MachineHash: "m", FirstSeen: t0, LastSeen: t0, LastSessionID: "s1", SessionsSeen: 1, SessionIDs: []string{"s1"},
	}
	subagents := []AgentIdentitySubagent{
		{AgentID: carol.AgentID, InstanceID: "ais-00000000000000b2", FirstSeen: t0.Add(2 * time.Second), LastSeen: t0.Add(2 * time.Second)},
		{AgentID: carol.AgentID, InstanceID: "ais-00000000000000a1", FirstSeen: t0.Add(time.Second), LastSeen: t0.Add(time.Second)},
		// An identity the store has no row for gets none.
		{AgentID: "agt-0000000000000099", InstanceID: "ais-0000000000000099", FirstSeen: t0, LastSeen: t0},
	}
	if err := st.UpsertAgentIdentityBatch(ctx, []AgentIdentityRecord{carol}, nil, subagents); err != nil {
		t.Fatal(err)
	}
	// After a gateway restart the same sub-agent hooks again: counted once.
	// A later sighting without a UPN clears the one recorded.
	again := carol
	again.UPN, again.SessionIDs, again.SessionsSeen, again.LastSeen = "", nil, 0, t0.Add(time.Hour)
	if err := st.UpsertAgentIdentityBatch(ctx, []AgentIdentityRecord{again}, nil,
		[]AgentIdentitySubagent{{AgentID: carol.AgentID, InstanceID: "ais-00000000000000a1", FirstSeen: t0.Add(time.Hour), LastSeen: t0.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	rows, _, err = st.ListAgentIdentities(ctx, AgentIdentityFilter{})
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %+v, err %v", rows, err)
	}
	got := rows[0]
	if got.UPN != "" || got.SubagentsSeen != 2 || got.LastSubagentID != "ais-00000000000000b2" || got.SessionsSeen != 5 {
		t.Fatalf("row = %+v; want no UPN, two sub-agents (last ais-00000000000000b2) and five sessions", got)
	}
	var orphans int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_identity_subagents WHERE agent_id = 'agt-0000000000000099'`).Scan(&orphans); err != nil || orphans != 0 {
		t.Fatalf("sub-agent rows of an unknown identity = %d, err %v", orphans, err)
	}

	// A retained identity keeps every sub-agent deduplication row, including
	// one whose last hook preceded the retention cutoff.
	if _, err := st.PruneAgentIdentitySessions(ctx, t0.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var kept []string
	list, err := st.db.QueryContext(ctx, `SELECT instance_id FROM agent_identity_subagents ORDER BY instance_id`)
	if err != nil {
		t.Fatal(err)
	}
	for list.Next() {
		var id string
		if err := list.Scan(&id); err != nil {
			t.Fatal(err)
		}
		kept = append(kept, id)
	}
	_ = list.Close()
	if len(kept) != 2 || kept[0] != "ais-00000000000000a1" || kept[1] != "ais-00000000000000b2" {
		t.Fatalf("sub-agent rows after the prune = %v, want both counted instances", kept)
	}
	if rows, _, err = st.ListAgentIdentities(ctx, AgentIdentityFilter{}); err != nil || rows[0].SubagentsSeen != 2 {
		t.Fatalf("count after the prune = %+v, err %v; want 2", rows, err)
	}
}

func TestAgentIdentitySubagentsOrderByFirstSeenAndRetainByLastSeen(t *testing.T) {
	st, err := NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	t0 := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	const (
		agentID = "agt-00000000000000c1"
		firstID = "ais-00000000000000a1"
		lastID  = "ais-00000000000000b2"
	)
	identity := AgentIdentityRecord{AgentID: agentID, UserID: "u1", Connector: "codex", MachineHash: "m", FirstSeen: t0, LastSeen: t0}
	subagents := []AgentIdentitySubagent{
		{AgentID: agentID, InstanceID: firstID, FirstSeen: t0, LastSeen: t0.Add(3 * time.Second)},
		{AgentID: agentID, InstanceID: lastID, FirstSeen: t0.Add(time.Second), LastSeen: t0.Add(time.Second)},
	}
	if err := st.UpsertAgentIdentityBatch(ctx, []AgentIdentityRecord{identity}, nil, subagents); err != nil {
		t.Fatal(err)
	}
	rows, _, err := st.ListAgentIdentities(ctx, AgentIdentityFilter{})
	if err != nil || len(rows) != 1 || rows[0].SubagentsSeen != 2 || rows[0].LastSubagentID != lastID {
		t.Fatalf("stored identities = %+v, err %v; want two sub-agents, last %s", rows, err, lastID)
	}
	var firstAt, lastAt string
	if err := st.db.QueryRowContext(ctx, `SELECT first_seen, last_seen FROM agent_identity_subagents WHERE agent_id = ? AND instance_id = ?`,
		agentID, firstID).Scan(&firstAt, &lastAt); err != nil {
		t.Fatal(err)
	}
	if firstAt != formatAgentIdentityTime(t0) || lastAt != formatAgentIdentityTime(t0.Add(3*time.Second)) {
		t.Fatalf("first sub-agent sighting range = %q..%q; want %q..%q", firstAt, lastAt,
			formatAgentIdentityTime(t0), formatAgentIdentityTime(t0.Add(3*time.Second)))
	}
	if removed, err := st.PruneAgentIdentitySessions(ctx, t0.Add(2*time.Second)); err != nil || removed != 0 {
		t.Fatalf("prune removed %d rows, err %v; want both retained while the identity exists", removed, err)
	}
}

func TestAgentIdentitySubagentRetentionPreservesDistinctOrder(t *testing.T) {
	st, err := NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	t0 := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	const agentID, firstID, lastID = "agt-00000000000000c1", "ais-00000000000000a1", "ais-00000000000000b2"
	identity := AgentIdentityRecord{AgentID: agentID, UserID: "u1", Connector: "codex", MachineHash: "m", FirstSeen: t0, LastSeen: t0.Add(time.Hour)}
	first := AgentIdentitySubagent{AgentID: agentID, InstanceID: firstID, FirstSeen: t0, LastSeen: t0}
	last := AgentIdentitySubagent{AgentID: agentID, InstanceID: lastID, FirstSeen: t0.Add(time.Hour), LastSeen: t0.Add(time.Hour)}
	if err := st.UpsertAgentIdentityBatch(ctx, []AgentIdentityRecord{identity}, nil, []AgentIdentitySubagent{first, last}); err != nil {
		t.Fatal(err)
	}
	if removed, err := st.PruneAgentIdentitySessions(ctx, t0.Add(30*time.Minute)); err != nil || removed != 0 {
		t.Fatalf("prune removed %d rows, err %v; want both instances while their identity remains", removed, err)
	}
	first.LastSeen = t0.Add(2 * time.Hour)
	first.FirstSeen = first.LastSeen // a resumed hook has no memory of the original first sighting
	identity.LastSeen = first.LastSeen
	if err := st.UpsertAgentIdentityBatch(ctx, []AgentIdentityRecord{identity}, nil, []AgentIdentitySubagent{first}); err != nil {
		t.Fatal(err)
	}
	rows, _, err := st.ListAgentIdentities(ctx, AgentIdentityFilter{})
	if err != nil || len(rows) != 1 || rows[0].SubagentsSeen != 2 || rows[0].LastSubagentID != lastID {
		t.Fatalf("resumed older instance = %+v, err %v; want count 2 and newest %s", rows, err, lastID)
	}
	var firstAt, lastAt string
	if err := st.db.QueryRowContext(ctx, `SELECT first_seen, last_seen FROM agent_identity_subagents WHERE agent_id = ? AND instance_id = ?`,
		agentID, firstID).Scan(&firstAt, &lastAt); err != nil {
		t.Fatal(err)
	}
	if firstAt != formatAgentIdentityTime(t0) || lastAt != formatAgentIdentityTime(first.LastSeen) {
		t.Fatalf("resumed instance sightings = %q..%q; want original first and refreshed last", firstAt, lastAt)
	}
	if _, err := st.db.ExecContext(ctx, `DELETE FROM agent_identities WHERE agent_id = ?`, agentID); err != nil {
		t.Fatal(err)
	}
	if removed, err := st.PruneAgentIdentitySessions(ctx, time.Time{}); err != nil || removed != 2 {
		t.Fatalf("orphan prune removed %d rows, err %v; want both sub-agent keys", removed, err)
	}
}

func TestAgentIdentitySubagentDelayedFirstSightingKeepsNewest(t *testing.T) {
	st, err := NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	t0 := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	const agentID, firstID, lastID = "agt-00000000000000c1", "ais-00000000000000a1", "ais-00000000000000b2"
	identity := AgentIdentityRecord{AgentID: agentID, UserID: "u1", Connector: "codex", MachineHash: "m", FirstSeen: t0, LastSeen: t0}
	first := AgentIdentitySubagent{AgentID: agentID, InstanceID: firstID, FirstSeen: t0, LastSeen: t0}
	last := AgentIdentitySubagent{AgentID: agentID, InstanceID: lastID, FirstSeen: t0.Add(time.Second), LastSeen: t0.Add(time.Second)}
	if err := st.UpsertAgentIdentityBatch(ctx, []AgentIdentityRecord{identity}, nil, []AgentIdentitySubagent{last}); err != nil {
		t.Fatal(err)
	}
	// A delayed older first sighting can be written after the newer one.
	if err := st.UpsertAgentIdentityBatch(ctx, nil, nil, []AgentIdentitySubagent{first}); err != nil {
		t.Fatal(err)
	}
	rows, _, err := st.ListAgentIdentities(ctx, AgentIdentityFilter{})
	if err != nil || len(rows) != 1 || rows[0].SubagentsSeen != 2 || rows[0].LastSubagentID != lastID {
		t.Fatalf("delayed older instance = %+v, err %v; want count 2 and newest %s", rows, err, lastID)
	}
}
