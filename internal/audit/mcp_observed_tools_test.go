// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMCPObservedToolsPreserveSiblingsAndSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store := openTestStore(t, path)
	first := time.Date(2026, 11, 17, 1, 2, 3, 0, time.UTC)
	base := MCPObservedTool{
		ParentComponentID: "endpoint-mcp-entry-parent",
		Connector:         "claudecode",
		ServerName:        "notes",
		FirstObservedAt:   first,
		LastObservedAt:    first,
	}
	ctx := WithCallWriteBatch(context.Background(), store)
	search := base
	search.ToolName = "search"
	if err := store.UpsertMCPObservedTool(ctx, search); err != nil {
		t.Fatal(err)
	}
	read := base
	read.ToolName = "read"
	read.LastObservedAt = first.Add(time.Minute)
	if err := store.UpsertMCPObservedTool(ctx, read); err != nil {
		t.Fatal(err)
	}
	if rows, err := store.ListMCPObservedTools(context.Background()); err != nil || len(rows) != 0 {
		t.Fatalf("unflushed rows=%+v err=%v", rows, err)
	}
	FlushCallWrites(ctx)

	search.LastObservedAt = first.Add(2 * time.Minute)
	if err := store.UpsertMCPObservedTool(context.Background(), search); err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListMCPObservedTools(context.Background())
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	got := map[string]MCPObservedTool{}
	for _, row := range rows {
		got[row.ToolName] = row
	}
	if !got["search"].LastObservedAt.Equal(search.LastObservedAt) ||
		!got["read"].LastObservedAt.Equal(read.LastObservedAt) {
		t.Fatalf("sibling timestamps=%+v", got)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.Init(); err != nil {
		t.Fatal(err)
	}
	rows, err = reopened.ListMCPObservedTools(context.Background())
	if err != nil || len(rows) != 2 {
		t.Fatalf("restored rows=%+v err=%v", rows, err)
	}
	if err := reopened.DeleteMCPObservedToolsForParents(context.Background(), []string{base.ParentComponentID}); err != nil {
		t.Fatal(err)
	}
	if rows, err = reopened.ListMCPObservedTools(context.Background()); err != nil || len(rows) != 0 {
		t.Fatalf("retired rows=%+v err=%v", rows, err)
	}
}

func TestMCPObservedToolDeferredUpsertRevalidatesParent(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	ctx := WithCallWriteBatch(context.Background(), store)
	current := true
	if err := store.UpsertMCPObservedToolIf(ctx, MCPObservedTool{
		ParentComponentID: "retired-parent", Connector: "claudecode", ServerName: "notes",
		ToolName: "search", LastObservedAt: time.Now(),
	}, func() bool { return current }); err != nil {
		t.Fatal(err)
	}
	current = false
	FlushCallWrites(ctx)
	rows, err := store.ListMCPObservedTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("retired parent was recreated: %+v", rows)
	}
}

func TestMCPObservedToolOverflowIsDurableAndDoesNotReplaceSiblings(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	at := time.Date(2026, 11, 17, 1, 2, 3, 0, time.UTC)
	for index := 0; index <= maxMCPObservedToolsPerParent; index++ {
		if err := store.UpsertMCPObservedTool(context.Background(), MCPObservedTool{
			ParentComponentID: "parent", Connector: "claudecode", ServerName: "notes",
			ToolName: fmt.Sprintf("tool-%03d", index), LastObservedAt: at.Add(time.Duration(index) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := store.ListMCPObservedTools(context.Background())
	if err != nil || len(rows) != maxMCPObservedToolsPerParent {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	for _, row := range rows {
		if !row.Overflowed {
			t.Fatal("overflow state was not retained")
		}
		if row.ToolName == "tool-256" {
			t.Fatal("overflow replaced an existing sibling")
		}
	}
}

func TestMCPObservedToolRejectsContentLikeOversizedNames(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	err := store.UpsertMCPObservedTool(context.Background(), MCPObservedTool{
		ParentComponentID: "parent", Connector: "claudecode", ServerName: "notes",
		ToolName: strings.Repeat("a", maxMCPObservedToolName+1), LastObservedAt: time.Now(),
	})
	if err == nil {
		t.Fatal("oversized tool name was accepted")
	}
}
