// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// listedAgentIdentityRows reads GET /api/v1/agents/identities as an
// administrator view prints it: the raw JSON object of each row.
func listedAgentIdentityRows(t *testing.T) map[string]map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	(&APIServer{}).handleAgentIdentities(rec, httptest.NewRequest(http.MethodGet, "/api/v1/agents/identities", nil))
	var body struct {
		Identities []map[string]any `json:"identities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("identities response %d %s", rec.Code, rec.Body.String())
	}
	rows := map[string]map[string]any{}
	for _, row := range body.Identities {
		id, _ := row["agent_id"].(string)
		rows[id] = row
	}
	return rows
}

// rel-1-0-4 GAP-0596: agent-identities names the sub-agents an agent ran,
// on every OS: a sub-agent that shares its parent's session (a Claude Code
// Task) and one in a child session (a Codex thread) are each counted once,
// also when they hook again after a gateway restart, and the row names the
// newest one's instance (ais-), the id the audit records of that sub-agent
// carry.
func TestAgentIdentitiesListTheSubagentsOfEachAgent(t *testing.T) {
	agentIdentityTestSetup(t)
	store, err := inventory.NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	prev := sharedAgentIdentities
	t.Cleanup(func() { sharedAgentIdentities = prev })
	restart := func() {
		sharedAgentIdentities = &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{}, hints: map[string]string{}}
		sharedAgentIdentities.setStoreSource(func() *inventory.InventoryStore { return store }, nil, nil)
		InstallSharedAgentRegistry("", "")
	}
	restart()
	peer := withManagedHookPeer(context.Background(), managedHookPeer{UID: 4949, Name: "frank", Home: t.TempDir()})
	main := agentHookRequest{ConnectorName: "claudecode", SessionID: "sess-main", HookEventName: "PreToolUse", Payload: map[string]interface{}{}}
	task := main
	task.AgentID = "task-1"
	task.Payload = map[string]interface{}{"agent_id": "task-1"}
	child := main
	child.SessionID = "sess-child"

	parent := agentIdentityForGenericHook(peer, main)
	inSession := agentIdentityForGenericHook(peer, task).AgentInstanceID
	if parent.IdentityID == "" || inSession != agentidentity.SubagentInstanceID(parent.AgentInstanceID, "task-1") {
		t.Fatalf("hooks gave identity %q and sub-agent instance %q", parent.IdentityID, inSession)
	}
	// The child session hooks before and after its link to the parent is
	// learned; it is one sub-agent, with the instance its hooks carry.
	time.Sleep(20 * time.Millisecond) // the child session is the newest sub-agent
	agentIdentityForGenericHook(peer, child)
	sharedAgentIdentities.markSubagentSession(parent.IdentityID, child.SessionID)
	childInstance := agentIdentityForGenericHook(peer, child).AgentInstanceID
	if childInstance != agentidentity.InstanceID(parent.IdentityID, child.SessionID) {
		t.Fatalf("child session instance = %q", childInstance)
	}
	// A sub-agent link to a session that never hooks again names no
	// instance the records carry, so it adds none.
	sharedAgentIdentities.markSubagentSession(parent.IdentityID, "sess-never-hooks")

	check := func(when string) {
		t.Helper()
		row := listedAgentIdentityRows(t)[parent.IdentityID]
		if row == nil {
			t.Fatalf("%s: identity %s not listed", when, parent.IdentityID)
		}
		if row["subagents_seen"] != float64(2) || row["last_subagent_id"] != childInstance || row["sessions_seen"] != float64(1) {
			t.Fatalf("%s: row = %v; want subagents_seen 2, last_subagent_id %s and the one chat", when, row, childInstance)
		}
	}
	check("first listing")
	restart()
	agentIdentityForGenericHook(peer, main)
	agentIdentityForGenericHook(peer, task)
	sharedAgentIdentities.markSubagentSession(parent.IdentityID, child.SessionID)
	agentIdentityForGenericHook(peer, child)
	check("after a restart")
}

// A repeat hook of an older instance must not make it the newest distinct
// sub-agent, including while an inventory write is in flight and restored.
func TestAgentIdentityRecorderOrdersSubagentsByFirstSighting(t *testing.T) {
	const (
		agentID = "agt-00000000000000c1"
		firstID = "ais-00000000000000a1"
		lastID  = "ais-00000000000000b2"
	)
	t0 := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	for _, restore := range []bool{false, true} {
		name := "ordinary flush"
		if restore {
			name = "failed write restored after a newer hook"
		}
		t.Run(name, func(t *testing.T) {
			r := &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{
				agentID: {AgentID: agentID, UserID: "u1", Connector: "codex", MachineHash: "m", FirstSeen: t0, LastSeen: t0},
			}}
			first := inventory.AgentIdentitySubagent{AgentID: agentID, InstanceID: firstID, FirstSeen: t0, LastSeen: t0}
			last := inventory.AgentIdentitySubagent{AgentID: agentID, InstanceID: lastID, FirstSeen: t0.Add(time.Second), LastSeen: t0.Add(time.Second)}
			r.noteSubagentLocked(first)
			r.noteSubagentLocked(last)
			if restore {
				batch, excluded, subagents := r.take()
				r.noteSubagentLocked(inventory.AgentIdentitySubagent{AgentID: agentID, InstanceID: firstID, FirstSeen: t0.Add(3 * time.Second), LastSeen: t0.Add(3 * time.Second)})
				r.restore(batch, excluded, subagents)
			} else {
				r.noteSubagentLocked(inventory.AgentIdentitySubagent{AgentID: agentID, InstanceID: firstID, FirstSeen: t0.Add(2 * time.Second), LastSeen: t0.Add(2 * time.Second)})
			}
			wantLast := t0.Add(2 * time.Second)
			if restore {
				wantLast = t0.Add(3 * time.Second)
			}
			if got := r.subagents[subSessionKey(agentID, firstID)]; !got.FirstSeen.Equal(t0) || !got.LastSeen.Equal(wantLast) {
				t.Errorf("first sub-agent sightings = %s..%s; want %s..%s", got.FirstSeen, got.LastSeen, t0, wantLast)
			}
			pending, _, _ := r.snapshot()
			if got := pending[agentID]; got.SubagentsSeen != 2 || got.LastSubagentID != lastID {
				t.Errorf("buffered identity = %+v; want two sub-agents, last %s", got, lastID)
			}
			store, err := inventory.NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			if err := r.flush(context.Background(), store); err != nil {
				t.Fatal(err)
			}
			rows, _, err := store.ListAgentIdentities(context.Background(), inventory.AgentIdentityFilter{})
			if err != nil || len(rows) != 1 || rows[0].SubagentsSeen != 2 || rows[0].LastSubagentID != lastID {
				t.Errorf("stored identities = %+v, err %v; want two sub-agents, last %s", rows, err, lastID)
			}
		})
	}
}

// A failed write leaves sightings in memory while the store still has the
// previous batch. The API must reconcile instance IDs and original first
// sightings before overlaying the buffered count and newest ID.
func TestAgentIdentityAPIReconcilesBufferedSubagentsAfterFailedWrite(t *testing.T) {
	agentIdentityTestSetup(t)
	previous := sharedAgentIdentities
	t.Cleanup(func() { sharedAgentIdentities = previous })
	t0 := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	const agentID, firstID, lastID, middleID, newID = "agt-00000000000000c1", "ais-00000000000000a1", "ais-00000000000000b2", "ais-00000000000000c3", "ais-00000000000000d4"
	for _, tc := range []struct {
		name        string
		storedFirst time.Time
		buffered    inventory.AgentIdentitySubagent
		extra       []inventory.AgentIdentitySubagent
		wantCount   int64
		wantLast    string
		clearUPN    bool
	}{
		{"resumed older instance", t0, inventory.AgentIdentitySubagent{AgentID: agentID, InstanceID: firstID, FirstSeen: t0.Add(2 * time.Second), LastSeen: t0.Add(2 * time.Second)}, nil, 2, lastID, false},
		{"new instance before stored newest", t0, inventory.AgentIdentitySubagent{AgentID: agentID, InstanceID: middleID, FirstSeen: t0.Add(500 * time.Millisecond), LastSeen: t0.Add(2 * time.Second)}, nil, 3, lastID, false},
		{"new instance after stored newest", t0, inventory.AgentIdentitySubagent{AgentID: agentID, InstanceID: newID, FirstSeen: t0.Add(2 * time.Second), LastSeen: t0.Add(2 * time.Second)}, nil, 3, newID, false},
		{"earlier first sighting corrects stored newest", t0.Add(3 * time.Second), inventory.AgentIdentitySubagent{AgentID: agentID, InstanceID: firstID, FirstSeen: t0, LastSeen: t0.Add(3 * time.Second)}, nil, 2, lastID, false},
		{"mixed resumed and new older instances", t0, inventory.AgentIdentitySubagent{AgentID: agentID, InstanceID: firstID, FirstSeen: t0.Add(2 * time.Second), LastSeen: t0.Add(2 * time.Second)},
			[]inventory.AgentIdentitySubagent{{AgentID: agentID, InstanceID: middleID, FirstSeen: t0.Add(500 * time.Millisecond), LastSeen: t0.Add(2 * time.Second)}}, 3, lastID, false},
		{"UPN removed after an older sub-agent resumed", t0, inventory.AgentIdentitySubagent{AgentID: agentID, InstanceID: firstID, FirstSeen: t0.Add(2 * time.Second), LastSeen: t0.Add(2 * time.Second)}, nil, 2, lastID, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "inventory.db")
			store, err := inventory.NewInventoryStore(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			identity := inventory.AgentIdentityRecord{AgentID: agentID, UserID: "u1", Connector: "codex", MachineHash: "m", FirstSeen: t0, LastSeen: t0.Add(time.Second), UPN: "old@corp.example"}
			stored := []inventory.AgentIdentitySubagent{
				{AgentID: agentID, InstanceID: firstID, FirstSeen: tc.storedFirst, LastSeen: tc.storedFirst},
				{AgentID: agentID, InstanceID: lastID, FirstSeen: t0.Add(time.Second), LastSeen: t0.Add(time.Second)},
			}
			if err := store.UpsertAgentIdentityBatch(ctx, []inventory.AgentIdentityRecord{identity}, nil, stored); err != nil {
				t.Fatal(err)
			}
			if _, err := store.PruneAgentIdentitySessions(ctx, t0.Add(500*time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			currentUPN := "new@corp.example"
			if tc.clearUPN {
				currentUPN = ""
			}
			r := &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{
				agentID: {AgentID: agentID, UserID: "u1", Connector: "codex", MachineHash: "m", FirstSeen: t0.Add(2 * time.Second), LastSeen: t0.Add(3 * time.Second), UPN: currentUPN},
			}}
			r.noteSubagentLocked(tc.buffered)
			for _, sub := range tc.extra {
				r.noteSubagentLocked(sub)
			}
			r.setStoreSource(func() *inventory.InventoryStore { return store }, nil, nil)
			sharedAgentIdentities = r
			// The trigger rejects writes only; listing can still read the
			// persisted rows and must merge the buffered sighting correctly.
			if _, err := db.ExecContext(ctx, `CREATE TRIGGER fail_identity_write BEFORE INSERT ON agent_identities BEGIN SELECT RAISE(FAIL, 'forced write failure'); END`); err != nil {
				t.Fatal(err)
			}
			if err := r.flush(ctx, store); err == nil {
				t.Fatal("expected the inventory write to fail")
			}
			row := listedAgentIdentityRows(t)[agentID]
			if row == nil || row["subagents_seen"] != float64(tc.wantCount) || row["last_subagent_id"] != tc.wantLast ||
				(currentUPN == "" && row["upn"] != nil) || (currentUPN != "" && row["upn"] != currentUPN) {
				t.Errorf("API row after failed write = %v; want count %d, newest %s, UPN %q", row, tc.wantCount, tc.wantLast, currentUPN)
			}
			if _, err := db.ExecContext(ctx, `DROP TRIGGER fail_identity_write`); err != nil {
				t.Fatal(err)
			}
			if err := r.flush(ctx, store); err != nil {
				t.Fatal(err)
			}
			row = listedAgentIdentityRows(t)[agentID]
			if row == nil || row["subagents_seen"] != float64(tc.wantCount) || row["last_subagent_id"] != tc.wantLast ||
				(currentUPN == "" && row["upn"] != nil) || (currentUPN != "" && row["upn"] != currentUPN) {
				t.Errorf("API row after recovery = %v; want count %d, newest %s, UPN %q", row, tc.wantCount, tc.wantLast, currentUPN)
			}
		})
	}
}
