// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"
)

// The runtime provenance is written with the runtime disable it describes and
// never outlives it: a plain runtime write drops it, and clearing runtime
// removes it, so the row of a released decision is deleted as before.
func TestRuntimeSourceGoesWithItsRuntimeDisable(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	get := func() *ActionEntry {
		t.Helper()
		row, err := store.GetActionForConnector("mcp", "key", "claudecode")
		if err != nil {
			t.Fatal(err)
		}
		return row
	}
	if err := store.SetActionFieldForConnector("mcp", "key", "claudecode", "install", "block", "failed"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetRuntimeDisableForConnector("mcp", "key", "claudecode", "key", "failed"); err != nil {
		t.Fatal(err)
	}
	if row := get(); row == nil || row.Actions != (ActionState{Runtime: "disable", Install: "block"}) ||
		row.RuntimeSource != "key" || row.SourcePath != "key" {
		t.Fatalf("runtime disable with provenance: %+v", row)
	}
	rows, err := store.ListActionsByType("mcp")
	if err != nil || len(rows) != 1 || rows[0].RuntimeSource != "key" {
		t.Fatalf("listed rows lost the provenance: %+v %v", rows, err)
	}
	if err := store.SetActionFieldForConnector("mcp", "key", "claudecode", "runtime", "disable", "plain"); err != nil {
		t.Fatal(err)
	}
	if row := get(); row == nil || row.Actions.Runtime != "disable" || row.RuntimeSource != "" {
		t.Fatalf("plain runtime write kept the provenance: %+v", row)
	}
	if err := store.SetRuntimeDisableForConnector("mcp", "key", "claudecode", "key", "failed"); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearActionFieldForConnector("mcp", "key", "claudecode", "install"); err != nil {
		t.Fatal(err)
	}
	if row := get(); row == nil || row.RuntimeSource != "key" {
		t.Fatalf("clearing install dropped the runtime provenance: %+v", row)
	}
	if err := store.ClearActionFieldForConnector("mcp", "key", "claudecode", "runtime"); err != nil {
		t.Fatal(err)
	}
	if row := get(); row != nil {
		t.Fatalf("released decision left its row: %+v", row)
	}
}

// The block of an enrolled account MCP server lives under its own target type
// and still counts as a blocked MCP server; an ordinary server twin counts
// once as before.
func TestGetCountsIncludesBlockedAccountMCPServers(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionFieldForConnector("mcp", "plain", "claudecode", "install", "block", "scan"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionFieldForConnector(AccountMCPActionType, "account-key", "claudecode", "install", "block", "scan"); err != nil {
		t.Fatal(err)
	}
	counts, err := store.GetCounts()
	if err != nil {
		t.Fatal(err)
	}
	if counts.BlockedMCPs != 2 || counts.AllowedMCPs != 0 {
		t.Fatalf("counts = blocked %d, allowed %d; want 2, 0", counts.BlockedMCPs, counts.AllowedMCPs)
	}
}
