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
		ObservationGroupID: "endpoint-mcp-entry-parent",
		Connector:          "claudecode",
		ServerName:         "notes",
		UserID:             "S-1-5-21-1000",
		UserIDKind:         "windows_sid",
		UserName:           `EXAMPLE\alice`,
		FirstObservedAt:    first,
		LastObservedAt:     first,
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
		!got["read"].LastObservedAt.Equal(read.LastObservedAt) ||
		got["search"].UserID != base.UserID || got["search"].UserIDKind != base.UserIDKind ||
		got["search"].UserName != base.UserName {
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
	if err := reopened.DeleteMCPAdvertisedToolsForParents(context.Background(), []string{base.ObservationGroupID}); err != nil {
		t.Fatal(err)
	}
	if rows, err = reopened.ListMCPObservedTools(context.Background()); err != nil || len(rows) != 2 {
		t.Fatalf("observed rows changed by advertised-parent delete=%+v err=%v", rows, err)
	}
}

func TestMCPObservedToolCorrelationMigrationIsIdempotent(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	tool := MCPObservedTool{
		ObservationGroupID: "observation-group", Connector: "codex", ServerName: "notes",
		ToolName: "search", UserID: "501", UserIDKind: "uid", LastObservedAt: time.Now(),
	}
	if err := store.UpsertMCPObservedTool(t.Context(), tool); err != nil {
		t.Fatal(err)
	}
	if err := migrateMCPObservedToolCorrelationFields(store.db); err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListMCPObservedTools(t.Context())
	if err != nil || len(rows) != 1 || rows[0].UserID != tool.UserID {
		t.Fatalf("idempotent migration changed current rows=%+v err=%v", rows, err)
	}
}

func TestMCPObservedToolReverseUpsertPreservesEarliestFirstSeen(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	newer := time.Date(2026, 11, 18, 2, 0, 0, 0, time.UTC)
	older := newer.Add(-time.Hour)
	tool := MCPObservedTool{
		ObservationGroupID: "endpoint-mcp-entry-parent", Connector: "claudecode",
		ServerName: "notes", ToolName: "search", FirstObservedAt: newer, LastObservedAt: newer,
	}
	if err := store.UpsertMCPObservedTool(t.Context(), tool); err != nil {
		t.Fatal(err)
	}
	tool.FirstObservedAt, tool.LastObservedAt = older, older
	if err := store.UpsertMCPObservedTool(t.Context(), tool); err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListMCPObservedTools(t.Context())
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	if !rows[0].FirstObservedAt.Equal(older) || !rows[0].LastObservedAt.Equal(newer) {
		t.Fatalf("reverse upsert timestamps=%+v, want first=%v last=%v", rows[0], older, newer)
	}
}

func TestMCPObservedToolDeferredUpsertRevalidatesParent(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	ctx := WithCallWriteBatch(context.Background(), store)
	current := true
	if err := store.UpsertMCPObservedToolIf(ctx, MCPObservedTool{
		ObservationGroupID: "retired-parent", Connector: "claudecode", ServerName: "notes",
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

func TestMCPObservedToolDeferredUpsertReportsCommit(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	ctx := WithCallWriteBatch(context.Background(), store)
	settled := make(chan error, 1)
	writeCtx, report := WithCallWriteReport(ctx, store, func(err error) { settled <- err })
	if err := store.UpsertMCPObservedToolIf(writeCtx, MCPObservedTool{
		ObservationGroupID: "parent", Connector: "claudecode", ServerName: "notes",
		ToolName: "search", LastObservedAt: time.Now(),
	}, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	if !report.Deferred() {
		t.Fatal("deferred observed-tool write did not claim its commit report")
	}
	select {
	case err := <-settled:
		t.Fatalf("write settled before the batch flush: %v", err)
	default:
	}
	FlushCallWrites(ctx)
	select {
	case err := <-settled:
		if err != nil {
			t.Fatalf("deferred observed-tool write failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("deferred observed-tool write did not report its commit")
	}
}

func TestMCPObservedToolOverflowIsDurableAndDoesNotReplaceSiblings(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	at := time.Date(2026, 11, 17, 1, 2, 3, 0, time.UTC)
	for index := 0; index <= maxMCPToolsPerGroup; index++ {
		if err := store.UpsertMCPObservedTool(context.Background(), MCPObservedTool{
			ObservationGroupID: "parent", Connector: "claudecode", ServerName: "notes",
			ToolName: fmt.Sprintf("tool-%03d", index), LastObservedAt: at.Add(time.Duration(index) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := store.ListMCPObservedTools(context.Background())
	if err != nil || len(rows) != maxMCPToolsPerGroup {
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
		ObservationGroupID: "parent", Connector: "claudecode", ServerName: "notes",
		ToolName: strings.Repeat("a", maxMCPObservedToolName+1), LastObservedAt: time.Now(),
	})
	if err == nil {
		t.Fatal("oversized tool name was accepted")
	}
}
