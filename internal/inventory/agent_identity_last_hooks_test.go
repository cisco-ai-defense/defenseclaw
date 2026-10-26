// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-2024: the root guardian reads the uid's last hook from the gateway's
// agent ledger without writing to it (no new file, no migration), with the
// reduction the gateway uses (AgentLastHooksByUID).
func TestReadAgentLastHooksIsTheNewestHookPerUIDWithoutWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.db")
	if _, err := ReadAgentLastHooks(context.Background(), path); err == nil {
		t.Fatal("a missing ledger read without an error")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("reading a missing ledger created it: %v", err)
	}
	st, err := NewInventoryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	records := []AgentIdentityRecord{
		{AgentID: "agt-00000000000000a1", UserID: "1001", Connector: "codex", MachineHash: "m", FirstSeen: t0, LastSeen: t0.Add(time.Hour)},
		{AgentID: "agt-00000000000000a2", UserID: "1001", Connector: "claudecode", MachineHash: "m", FirstSeen: t0, LastSeen: t0.Add(2 * time.Hour)},
		{AgentID: "agt-00000000000000b1", UserID: "1002", Connector: "codex", MachineHash: "m", FirstSeen: t0, LastSeen: t0},
		{AgentID: "agt-00000000000000c1", UserID: "S-1-5-21-1-2-3-1104", Connector: "codex", MachineHash: "m", FirstSeen: t0, LastSeen: t0},
	}
	if err := st.UpsertAgentIdentities(context.Background(), records); err != nil {
		t.Fatal(err)
	}
	listed, _, err := st.ListAgentIdentities(context.Background(), AgentIdentityFilter{Retired: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	hooks, err := ReadAgentLastHooks(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]int64{1001: t0.Add(2 * time.Hour).UnixNano(), 1002: t0.UnixNano()}
	if len(hooks) != len(want) || hooks[1001] != want[1001] || hooks[1002] != want[1002] {
		t.Fatalf("last hooks %v; want %v", hooks, want)
	}
	if shared := AgentLastHooksByUID(listed); len(shared) != len(want) || shared[1001] != want[1001] || shared[1002] != want[1002] {
		t.Fatalf("the gateway's reduction %v; want %v", shared, want)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
		t.Fatal("reading the ledger wrote to it")
	}
}
