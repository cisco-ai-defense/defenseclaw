// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestMCPAdvertisedToolsReplaceAndSurviveRestart(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	now := time.Date(2026, 11, 18, 1, 2, 3, 0, time.UTC)
	snapshot := MCPAdvertisedToolSnapshot{
		ParentComponentID: "endpoint-mcp-entry-parent", Connector: "claudecode",
		ServerName: "docs", ToolNames: []string{"read", "search"}, ListedAt: now,
	}
	if err := store.ReplaceMCPAdvertisedToolsIf(context.Background(), snapshot, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListMCPAdvertisedToolSnapshots(context.Background())
	if err != nil || len(rows) != 1 || len(rows[0].ToolNames) != 2 {
		t.Fatalf("listed snapshots=%+v err=%v", rows, err)
	}
	snapshot.ToolNames = nil
	snapshot.ListedAt = now.Add(time.Minute)
	if err := store.ReplaceMCPAdvertisedToolsIf(context.Background(), snapshot, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	rows, err = store.ListMCPAdvertisedToolSnapshots(context.Background())
	if err != nil || len(rows) != 1 || len(rows[0].ToolNames) != 0 || !rows[0].ListedAt.Equal(snapshot.ListedAt) {
		t.Fatalf("authoritative empty snapshot=%+v err=%v", rows, err)
	}
}

func TestMCPAdvertisedToolsRejectRetiredParentWrite(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	err := store.ReplaceMCPAdvertisedToolsIf(context.Background(), MCPAdvertisedToolSnapshot{
		ParentComponentID: "endpoint-mcp-entry-parent", Connector: "codex",
		ServerName: "docs", ToolNames: []string{"search"}, ListedAt: time.Now(),
	}, func() bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListMCPAdvertisedToolSnapshots(context.Background())
	if err != nil || len(rows) != 0 {
		t.Fatalf("retired parent persisted: %+v err=%v", rows, err)
	}
}
