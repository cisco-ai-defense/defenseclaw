// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

type testMCPObservedToolStore struct {
	tools             []audit.MCPObservedTool
	advertised        []audit.MCPAdvertisedToolSnapshot
	listErr           error
	advertisedListErr error
	deleteErr         error
	deleteCalls       [][]string
	deleteStarted     chan struct{}
	releaseDelete     chan struct{}
	deleteOnce        sync.Once
	stillCurrent      func() bool
	observedWrite     audit.MCPObservedTool
	upsertCalls       int
	deferUpsert       bool
	upsertErr         error
	advertisedCurrent func() bool
	advertisedWrite   audit.MCPAdvertisedToolSnapshot
	advertisedErr     error
}

type coordinatedAdvertisedStore struct {
	testMCPObservedToolStore
	mu           sync.Mutex
	calls        int
	firstStarted chan struct{}
	releaseFirst chan struct{}
	writes       []audit.MCPAdvertisedToolSnapshot
}

// components keeps the pre-split test vocabulary local to this file. Runtime
// code calls the independent advertised and observed projections directly.
func (m *mcpToolInventory) components(servers []endpointInventoryComponent, remote bool, source ...string) ([]endpointInventoryComponent, bool) {
	if len(source) > 0 && source[0] == "observed" {
		return m.observedComponents()
	}
	if len(source) > 0 && source[0] == "advertised" {
		return m.advertisedComponents(servers, remote)
	}
	return m.advertisedComponents(servers, remote)
}

func (s *coordinatedAdvertisedStore) ReplaceMCPAdvertisedToolsIf(_ context.Context, snapshot audit.MCPAdvertisedToolSnapshot, stillCurrent func() bool) error {
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.mu.Unlock()
	if call == 1 {
		close(s.firstStarted)
		<-s.releaseFirst
	}
	if call == 2 {
		return fmt.Errorf("temporary write failure")
	}
	if stillCurrent != nil && !stillCurrent() {
		return nil
	}
	s.mu.Lock()
	s.writes = append(s.writes, snapshot)
	s.mu.Unlock()
	return nil
}

func (s *coordinatedAdvertisedStore) snapshots() []audit.MCPAdvertisedToolSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.MCPAdvertisedToolSnapshot(nil), s.writes...)
}

func (s *testMCPObservedToolStore) UpsertMCPObservedToolIf(_ context.Context, tool audit.MCPObservedTool, stillCurrent func() bool) error {
	s.stillCurrent = stillCurrent
	if s.deferUpsert {
		return s.upsertErr
	}
	if stillCurrent != nil && !stillCurrent() {
		return nil
	}
	s.observedWrite = tool
	s.upsertCalls++
	return s.upsertErr
}

func (s *testMCPObservedToolStore) ListMCPObservedTools(context.Context) ([]audit.MCPObservedTool, error) {
	return s.tools, s.listErr
}

func (s *testMCPObservedToolStore) ReplaceMCPAdvertisedToolsIf(_ context.Context, snapshot audit.MCPAdvertisedToolSnapshot, stillCurrent func() bool) error {
	s.advertisedCurrent = stillCurrent
	if stillCurrent != nil && !stillCurrent() {
		return nil
	}
	s.advertisedWrite = snapshot
	return s.advertisedErr
}

func TestMCPToolListingFailurePersistsPartialState(t *testing.T) {
	store := &testMCPObservedToolStore{}
	tools := &mcpToolInventory{store: store}
	parent := endpointInventoryComponent{id: "server-a", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	tools.recordAdvertised("codex", "notes", []string{"search"}, time.Now())
	tools.recordListingFailure("codex", "notes")
	if !store.advertisedWrite.Partial || len(store.advertisedWrite.ToolNames) != 1 ||
		store.advertisedWrite.ParentComponentID != parent.id {
		t.Fatalf("persisted failed listing=%+v", store.advertisedWrite)
	}
}

func TestMCPToolListingFailureRetriesVersionedPartialState(t *testing.T) {
	store := &testMCPObservedToolStore{}
	tools := &mcpToolInventory{store: store}
	parent := endpointInventoryComponent{id: "server-a", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	listed := time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC)
	tools.recordAdvertised("codex", "notes", []string{"search"}, listed)
	store.advertisedErr = fmt.Errorf("database busy")
	tools.recordListingFailure("codex", "notes")
	key := mcpToolServerKey("codex", "notes")
	if tools.pendingAdvertised[key] == 0 {
		t.Fatal("failed partial listing was not retained for retry")
	}
	store.advertisedErr = nil
	if err := tools.flushPendingAdvertised(t.Context()); err != nil {
		t.Fatal(err)
	}
	if tools.pendingAdvertised[key] != 0 || !store.advertisedWrite.Partial ||
		fmt.Sprint(store.advertisedWrite.ToolNames) != "[search]" || !store.advertisedWrite.ListedAt.Equal(listed) {
		t.Fatalf("retried partial listing=%+v pending=%d", store.advertisedWrite, tools.pendingAdvertised[key])
	}
}

func TestMCPToolFirstListingFailureRetriesWithNonzeroTimestamp(t *testing.T) {
	store := &testMCPObservedToolStore{advertisedErr: fmt.Errorf("database busy")}
	tools := &mcpToolInventory{store: store}
	parent := endpointInventoryComponent{id: "server-a", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	tools.recordListingFailure("codex", "notes")
	key := mcpToolServerKey("codex", "notes")
	if tools.advertisedListedAt[key].IsZero() || tools.pendingAdvertised[key] == 0 {
		t.Fatalf("first failed listing timestamp=%v pending=%d", tools.advertisedListedAt[key], tools.pendingAdvertised[key])
	}
	store.advertisedErr = nil
	if err := tools.flushPendingAdvertised(t.Context()); err != nil {
		t.Fatal(err)
	}
	if store.advertisedWrite.ListedAt.IsZero() || tools.pendingAdvertised[key] != 0 {
		t.Fatalf("retried listing=%+v pending=%d", store.advertisedWrite, tools.pendingAdvertised[key])
	}
}

func TestMCPToolAmbiguousAliasRetainsLastAdvertisedListing(t *testing.T) {
	store := &testMCPObservedToolStore{}
	tools := &mcpToolInventory{store: store}
	parent := endpointInventoryComponent{id: "server-a", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	tools.recordAdvertised("codex", "notes", []string{"search"}, time.Now())
	tools.refreshParents([]endpointInventoryComponent{
		parent, {id: "server-b", itemName: "notes", agentConnector: "codex"},
	})
	tools.recordAdvertised("codex", "notes", []string{"delete"}, time.Now())
	tools.recordListingFailure("codex", "notes")
	rows, partial := tools.components([]endpointInventoryComponent{parent}, false, "advertised")
	if partial || len(rows) != 1 || rows[0].itemName != "search" {
		t.Fatalf("blocked alias did not retain last valid listing: rows=%+v partial=%v", rows, partial)
	}
	tools.refreshParents([]endpointInventoryComponent{parent})
	rows, partial = tools.components([]endpointInventoryComponent{parent}, false, "advertised")
	if partial || len(rows) != 1 || rows[0].itemName != "search" {
		t.Fatalf("last valid listing was replaced while blocked: rows=%+v partial=%v", rows, partial)
	}
}

func TestMCPToolPendingObservationKeepsMaximumTimestamp(t *testing.T) {
	store := &testMCPObservedToolStore{}
	tools := &mcpToolInventory{store: store}
	parent := endpointInventoryComponent{id: "server-a", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	newer := time.Date(2026, 11, 18, 2, 0, 0, 0, time.UTC)
	older := newer.Add(-time.Hour)
	if _, ok := tools.beginObservedWrite("codex", "notes", "search", newer); !ok {
		t.Fatal("newer pending write rejected")
	}
	pending, ok := tools.beginObservedWrite("codex", "notes", "search", older)
	if !ok || !pending.firstAt.Equal(older) || !pending.lastAt.Equal(newer) {
		t.Fatalf("pending bounds=(%v,%v) ok=%v, want (%v,%v)", pending.firstAt, pending.lastAt, ok, older, newer)
	}
	if err := tools.flushPendingObserved(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !store.observedWrite.FirstObservedAt.Equal(older) || !store.observedWrite.LastObservedAt.Equal(newer) {
		t.Fatalf("durable bounds=(%v,%v), want (%v,%v)", store.observedWrite.FirstObservedAt, store.observedWrite.LastObservedAt, older, newer)
	}
}

func TestMCPToolObservationIsQueuedBeforeItBecomesVisible(t *testing.T) {
	tools := &mcpToolInventory{store: &testMCPObservedToolStore{}}
	parent := endpointInventoryComponent{id: "server-a", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	pending, recorded, queued := tools.recordObservedAndBeginWrite("codex", "notes", "search", time.Now())
	if !recorded || !queued || pending.version == 0 {
		t.Fatalf("atomic observation recorded=%v queued=%v pending=%+v", recorded, queued, pending)
	}
	key := mcpObservedToolKey("codex", "", "notes")
	tools.mu.Lock()
	_, visible := tools.observed[key]["search"]
	current := tools.pendingObserved[key]["search"]
	tools.mu.Unlock()
	if !visible || current.version != pending.version {
		t.Fatalf("visible=%v pending=%+v want version=%d", visible, current, pending.version)
	}
}

func TestMCPToolFullPersistenceQueueDoesNotExposeObservation(t *testing.T) {
	store := &testMCPObservedToolStore{}
	tools := &mcpToolInventory{store: store}
	parent := endpointInventoryComponent{id: "server-a", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	for index := range maxMCPToolObservations {
		tool := fmt.Sprintf("queued-%03d", index)
		if _, recorded, queued := tools.recordObservedAndBeginWrite("codex", "notes", tool, time.Now()); !recorded || !queued {
			t.Fatalf("fill pending queue at %d", index)
		}
	}
	if _, recorded, queued := tools.recordObservedAndBeginWrite("codex", "notes", "not-durable", time.Now()); !recorded || queued {
		t.Fatalf("full queue recorded=%v queued=%v", recorded, queued)
	}
	key := mcpToolServerKey("codex", "notes")
	if _, visible := tools.observed[key]["not-durable"]; visible {
		t.Fatal("observation became visible without a pending durable write")
	}
	if err := tools.flushPendingObserved(t.Context()); err != nil {
		t.Fatal(err)
	}
	rows, partial := tools.components([]endpointInventoryComponent{parent}, false, "observed")
	if !partial || len(rows) != maxMCPToolObservations {
		t.Fatalf("drained queue rows=%d partial=%v, want rows=%d partial=true", len(rows), partial, maxMCPToolObservations)
	}
}

func (s *testMCPObservedToolStore) ListMCPAdvertisedToolSnapshots(context.Context) ([]audit.MCPAdvertisedToolSnapshot, error) {
	return s.advertised, s.advertisedListErr
}

func (s *testMCPObservedToolStore) DeleteMCPAdvertisedToolsForParents(_ context.Context, parentIDs []string) error {
	s.deleteCalls = append(s.deleteCalls, append([]string(nil), parentIDs...))
	if s.deleteStarted != nil {
		s.deleteOnce.Do(func() { close(s.deleteStarted) })
	}
	if s.releaseDelete != nil {
		<-s.releaseDelete
	}
	return s.deleteErr
}

func TestObservedMCPToolRequiresAuthenticatedExactHookEvidence(t *testing.T) {
	var tools mcpToolInventory
	api := &APIServer{mcpTools: &tools}
	req := agentHookRequest{
		ConnectorName: "codex", ConnectorInstanceID: syntheticToolResourceConnectorID,
		ToolName: "mcp__notes__search", Payload: map[string]interface{}{"mcp_server_name": "notes"},
	}
	at := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	parent := endpointInventoryComponent{id: "parent", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	api.recordObservedMCPTool(context.Background(), req, at)
	if rows, _ := tools.components([]endpointInventoryComponent{parent}, false, "observed"); len(rows) != 0 {
		t.Fatalf("untrusted hook recorded tool: %+v", rows)
	}
	ctx := withAuthenticatedToolResource(withAuthenticatedHookConnector(context.Background(), "codex"), req,
		[]byte(`{"tool_name":"mcp__notes__search"}`))
	api.recordObservedMCPTool(ctx, req, at)
	rows, partial := tools.components([]endpointInventoryComponent{parent}, false, "observed")
	if partial || len(rows) != 1 || rows[0].itemName != "search" || rows[0].mcpToolSource != "observed" {
		t.Fatalf("authenticated observation=%+v partial=%v", rows, partial)
	}
	changed := req
	changed.ToolName = "mcp__notes__other"
	api.recordObservedMCPTool(ctx, changed, at)
	rows, _ = tools.components([]endpointInventoryComponent{parent}, false, "observed")
	if len(rows) != 1 {
		t.Fatalf("modified tool name crossed pinned hook projection: %+v", rows)
	}
}

func TestObservedMCPToolCostsNothingWhenManagedInventoryIsOff(t *testing.T) {
	previous := ManagedEnterpriseActive()
	SetManagedEnterpriseActive(false)
	t.Cleanup(func() { SetManagedEnterpriseActive(previous) })
	var tools mcpToolInventory
	api := &APIServer{mcpTools: &tools}
	parent := endpointInventoryComponent{id: "parent", itemName: "notes", agentConnector: "claudecode"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	req := agentHookRequest{
		ConnectorName: "claudecode", ConnectorInstanceID: syntheticToolResourceConnectorID,
		ToolName: "mcp__notes__search", Payload: map[string]interface{}{"mcp_server_name": "notes"},
	}
	ctx := withAuthenticatedToolResource(withAuthenticatedHookConnector(context.Background(), "claudecode"), req,
		[]byte(`{"tool_name":"mcp__notes__search","mcp_server_name":"notes"}`))
	api.recordObservedMCPToolIfManaged(ctx, req)
	if rows, _ := tools.components([]endpointInventoryComponent{parent}, false, "observed"); len(rows) != 0 {
		t.Fatalf("unmanaged hook recorded observed MCP evidence: %+v", rows)
	}
	SetManagedEnterpriseActive(true)
	api.recordObservedMCPToolIfManaged(ctx, req)
	if rows, _ := tools.components([]endpointInventoryComponent{parent}, false, "observed"); len(rows) != 1 {
		t.Fatalf("managed hook did not record observed MCP evidence: %+v", rows)
	}
}

func TestObservedMCPToolExactReplayDoesNotAdvanceTimestamp(t *testing.T) {
	withManagedEnterprise(t, true)
	var tools mcpToolInventory
	api := &APIServer{mcpTools: &tools}
	parent := endpointInventoryComponent{id: "parent", itemName: "notes", agentConnector: "claudecode"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	req := agentHookRequest{
		ConnectorName: "claudecode", ConnectorInstanceID: syntheticToolResourceConnectorID,
		ToolName: "mcp__notes__search", Payload: map[string]interface{}{"mcp_server_name": "notes"},
	}
	ctx := withAuthenticatedToolResource(withAuthenticatedHookConnector(context.Background(), "claudecode"), req,
		[]byte(`{"tool_name":"mcp__notes__search","mcp_server_name":"notes"}`))
	api.recordObservedMCPToolIfManaged(ctx, req)
	rows, _ := tools.components([]endpointInventoryComponent{parent}, false, "observed")
	if len(rows) != 1 {
		t.Fatalf("first observation rows=%+v", rows)
	}
	first := rows[0].mcpToolObservedAt
	req.SuppressCorrelationEmit = true
	api.recordObservedMCPToolIfManaged(ctx, req)
	rows, _ = tools.components([]endpointInventoryComponent{parent}, false, "observed")
	if len(rows) != 1 || rows[0].mcpToolObservedAt != first {
		t.Fatalf("exact replay advanced observation: first=%q rows=%+v", first, rows)
	}
	// A suppressed event with no correlation evidence is not a proven replay and
	// remains eligible for observation.
	unavailable := req
	unavailable.ToolName = "mcp__notes__read"
	unavailable.CorrelationUnavailable = true
	unavailableCtx := withAuthenticatedToolResource(withAuthenticatedHookConnector(context.Background(), "claudecode"), unavailable,
		[]byte(`{"tool_name":"mcp__notes__read","mcp_server_name":"notes"}`))
	api.recordObservedMCPToolIfManaged(unavailableCtx, unavailable)
	rows, _ = tools.components([]endpointInventoryComponent{parent}, false, "observed")
	if len(rows) != 2 || rows[0].itemName != "read" && rows[1].itemName != "read" {
		t.Fatalf("correlation-unavailable event was lost: first=%q rows=%+v", first, rows)
	}
}

func TestObservedMCPToolUsesRuntimeServerNameWithoutConfiguredAlias(t *testing.T) {
	store := &testMCPObservedToolStore{}
	tools := &mcpToolInventory{store: store}
	api := &APIServer{mcpTools: tools}
	parent := endpointInventoryComponent{id: "parent", itemName: "acme-notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	req := agentHookRequest{
		ConnectorName: "codex", ConnectorInstanceID: syntheticToolResourceConnectorID,
		ToolName: "mcp__acme_notes__search", Payload: map[string]interface{}{"mcp_server_name": "acme_notes"},
	}
	ctx := withAuthenticatedToolResource(withAuthenticatedHookConnector(context.Background(), "codex"), req,
		[]byte(`{"tool_name":"mcp__acme_notes__search"}`))
	api.recordObservedMCPTool(ctx, req, time.Now())
	if store.upsertCalls != 1 || store.observedWrite.ServerName != "acme_notes" || store.observedWrite.ObservationGroupID == parent.id {
		t.Fatalf("runtime server correlation write=%+v calls=%d", store.observedWrite, store.upsertCalls)
	}
}

func TestObservedMCPToolDoesNotDependOnConfiguredAliasAmbiguity(t *testing.T) {
	store := &testMCPObservedToolStore{}
	tools := &mcpToolInventory{store: store}
	api := &APIServer{mcpTools: tools}
	parents := []endpointInventoryComponent{
		{id: "one", itemName: "acme-notes", agentConnector: "codex"},
		{id: "two", itemName: "acme.notes", agentConnector: "codex"},
	}
	tools.refreshParents(parents)
	req := agentHookRequest{
		ConnectorName: "codex", ConnectorInstanceID: syntheticToolResourceConnectorID,
		ToolName: "mcp__acme_notes__search", Payload: map[string]interface{}{"mcp_server_name": "acme_notes"},
	}
	ctx := withAuthenticatedToolResource(withAuthenticatedHookConnector(context.Background(), "codex"), req,
		[]byte(`{"tool_name":"mcp__acme_notes__search"}`))
	api.recordObservedMCPTool(ctx, req, time.Now())
	if store.upsertCalls != 1 || store.observedWrite.ServerName != "acme_notes" {
		t.Fatalf("runtime observation depended on configured aliases: %+v", store.observedWrite)
	}
}

func TestObservedMCPToolDoesNotRequireConfiguredParent(t *testing.T) {
	tools := &mcpToolInventory{}
	api := &APIServer{mcpTools: tools}
	req := agentHookRequest{
		ConnectorName: "claudecode", ConnectorInstanceID: syntheticToolResourceConnectorID,
		ToolName: "mcp__notes__search", Payload: map[string]interface{}{"mcp_server_name": "notes"},
	}
	ctx := withAuthenticatedToolResource(withAuthenticatedHookConnector(context.Background(), "claudecode"), req,
		[]byte(`{"tool_name":"mcp__notes__search","mcp_server_name":"notes"}`))
	api.recordObservedMCPTool(ctx, req, time.Now())
	rows, partial := tools.observedComponents()
	if partial || len(rows) != 1 || rows[0].mcpRuntimeServerName != "notes" {
		t.Fatalf("parent-independent observation rows=%+v partial=%v", rows, partial)
	}
}

func TestObservedMCPToolDeferredWriteRejectsRetiredParent(t *testing.T) {
	store := &testMCPObservedToolStore{deferUpsert: true}
	tools := &mcpToolInventory{store: store}
	api := &APIServer{mcpTools: tools}
	oldParent := endpointInventoryComponent{id: "old-parent", itemName: "notes", agentConnector: "claudecode"}
	tools.refreshParents([]endpointInventoryComponent{oldParent})
	req := agentHookRequest{
		ConnectorName: "claudecode", ConnectorInstanceID: syntheticToolResourceConnectorID,
		ToolName: "mcp__notes__search", Payload: map[string]interface{}{"mcp_server_name": "notes"},
	}
	ctx := withAuthenticatedToolResource(withAuthenticatedHookConnector(context.Background(), "claudecode"), req,
		[]byte(`{"tool_name":"mcp__notes__search","mcp_server_name":"notes"}`))
	api.recordObservedMCPTool(ctx, req, time.Now())
	if store.stillCurrent == nil || !store.stillCurrent() {
		t.Fatal("current parent was rejected before retirement")
	}
	tools.refreshParents([]endpointInventoryComponent{{id: "new-parent", itemName: "notes", agentConnector: "claudecode"}})
	if !store.stillCurrent() {
		t.Fatal("configured-parent refresh invalidated independent runtime evidence")
	}
}

func TestObservedMCPToolStaysPartialUntilRetryCommits(t *testing.T) {
	store := &testMCPObservedToolStore{upsertErr: fmt.Errorf("database busy")}
	tools := &mcpToolInventory{store: store}
	api := &APIServer{mcpTools: tools}
	parent := endpointInventoryComponent{id: "parent", itemName: "notes", agentConnector: "claudecode"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	req := agentHookRequest{
		ConnectorName: "claudecode", ConnectorInstanceID: syntheticToolResourceConnectorID,
		ToolName: "mcp__notes__search", Payload: map[string]interface{}{"mcp_server_name": "notes"},
	}
	ctx := withAuthenticatedToolResource(withAuthenticatedHookConnector(context.Background(), "claudecode"), req,
		[]byte(`{"tool_name":"mcp__notes__search","mcp_server_name":"notes"}`))
	api.recordObservedMCPTool(ctx, req, time.Now())
	if rows, partial := tools.components([]endpointInventoryComponent{parent}, false, "observed"); len(rows) != 1 || !partial {
		t.Fatalf("uncommitted observation rows=%+v partial=%v", rows, partial)
	}
	store.upsertErr = nil
	if err := tools.flushPendingObserved(t.Context()); err != nil {
		t.Fatal(err)
	}
	if rows, partial := tools.components([]endpointInventoryComponent{parent}, false, "observed"); len(rows) != 1 || partial {
		t.Fatalf("retried observation rows=%+v partial=%v", rows, partial)
	}
}

func TestObservedMCPToolBatchReportClearsPendingAfterCommit(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	tools := &mcpToolInventory{store: store}
	api := &APIServer{store: store, mcpTools: tools}
	parent := endpointInventoryComponent{id: "parent", itemName: "notes", agentConnector: "claudecode"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	req := agentHookRequest{
		ConnectorName: "claudecode", ConnectorInstanceID: syntheticToolResourceConnectorID,
		ToolName: "mcp__notes__search", Payload: map[string]interface{}{"mcp_server_name": "notes"},
	}
	ctx := audit.WithCallWriteBatch(context.Background(), store)
	ctx = withAuthenticatedToolResource(withAuthenticatedHookConnector(ctx, "claudecode"), req,
		[]byte(`{"tool_name":"mcp__notes__search","mcp_server_name":"notes"}`))
	api.recordObservedMCPTool(ctx, req, time.Now())
	if rows, partial := tools.components([]endpointInventoryComponent{parent}, false, "observed"); len(rows) != 1 || !partial {
		t.Fatalf("deferred observation rows=%+v partial=%v", rows, partial)
	}
	audit.FlushCallWrites(ctx)
	if rows, partial := tools.components([]endpointInventoryComponent{parent}, false, "observed"); len(rows) != 1 || partial {
		t.Fatalf("committed observation rows=%+v partial=%v", rows, partial)
	}
	if rows, err := store.ListMCPObservedTools(t.Context()); err != nil || len(rows) != 1 {
		t.Fatalf("durable observations=%+v err=%v", rows, err)
	}
}

func TestObservedMCPToolRestoreIsIndependentOfConfiguredParentCleanup(t *testing.T) {
	now := time.Now().UTC()
	store := &testMCPObservedToolStore{tools: []audit.MCPObservedTool{
		{ObservationGroupID: "old-parent", Connector: "claudecode", ServerName: "notes", ToolName: "old", LastObservedAt: now},
		{ObservationGroupID: "new-parent", Connector: "claudecode", ServerName: "notes", ToolName: "current", LastObservedAt: now},
	}, advertised: []audit.MCPAdvertisedToolSnapshot{{
		ParentComponentID: "new-parent", Connector: "claudecode", ServerName: "notes",
		ToolNames: []string{"listed"}, ListedAt: now,
	}}}
	tools := &mcpToolInventory{store: store}
	if err := tools.restoreFromStore(t.Context()); err != nil {
		t.Fatal(err)
	}
	server := endpointInventoryComponent{id: "new-parent", itemName: "notes", agentConnector: "claudecode"}
	removed := tools.refreshParents([]endpointInventoryComponent{server})
	rows, _ := tools.components([]endpointInventoryComponent{server}, false, "observed")
	if len(rows) != 2 {
		t.Fatalf("restored rows=%+v", rows)
	}
	advertised, partial := tools.components([]endpointInventoryComponent{server}, false, "advertised")
	if partial || len(advertised) != 1 || advertised[0].itemName != "listed" {
		t.Fatalf("restored advertised rows=%+v partial=%v", advertised, partial)
	}
	if err := store.DeleteMCPAdvertisedToolsForParents(t.Context(), removed); err != nil {
		t.Fatal(err)
	}
	tools.acknowledgeRemovedParents(removed)
	rows, partial = tools.components([]endpointInventoryComponent{server}, false, "observed")
	if partial || len(rows) != 2 {
		t.Fatalf("advertised cleanup changed observations: rows=%+v partial=%v", rows, partial)
	}
}

func TestObservedMCPToolRestoreFailureRetriesToAuthoritativeEmpty(t *testing.T) {
	store := &testMCPObservedToolStore{listErr: fmt.Errorf("database busy")}
	tools := &mcpToolInventory{store: store}
	server := endpointInventoryComponent{id: "parent", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{server})
	if err := tools.restoreFromStore(t.Context()); err == nil {
		t.Fatal("restore unexpectedly succeeded")
	}
	if !tools.observedIncomplete() {
		t.Fatal("failed restore did not keep observed inventory partial")
	}
	if rows, partial := tools.components([]endpointInventoryComponent{server}, false, "advertised"); len(rows) != 0 || !partial {
		t.Fatalf("failed restore advertised rows=%+v partial=%v", rows, partial)
	}
	store.listErr = nil
	tools.retryRestoreFromStore(t.Context())
	tools.refreshParents([]endpointInventoryComponent{server})
	if tools.observedIncomplete() {
		t.Fatal("successful empty restore was not authoritative")
	}
	if rows, partial := tools.components([]endpointInventoryComponent{server}, false, "advertised"); len(rows) != 0 || partial {
		t.Fatalf("successful empty restore advertised rows=%+v partial=%v", rows, partial)
	}
}

func TestAdvertisedRestoreBacklogDoesNotDegradeObservedInventory(t *testing.T) {
	var tools mcpToolInventory
	tools.restoreAdvertised([]audit.MCPAdvertisedToolSnapshot{{
		ParentComponentID: "parent", Connector: "codex", ServerName: "notes",
		ToolNames: []string{"search"}, ListedAt: time.Now(),
	}})
	if tools.observedIncomplete() {
		t.Fatal("advertised-only restore state degraded observed inventory")
	}
}

func TestAdvertisedRestoreFailureDoesNotDegradeObservedInventory(t *testing.T) {
	store := &testMCPObservedToolStore{advertisedListErr: fmt.Errorf("advertised table busy")}
	tools := &mcpToolInventory{store: store}
	parent := endpointInventoryComponent{id: "parent", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	if err := tools.restoreFromStore(t.Context()); err == nil {
		t.Fatal("advertised restore unexpectedly succeeded")
	}
	if tools.observedIncomplete() {
		t.Fatal("advertised restore failure degraded observed inventory")
	}
	if rows, partial := tools.components([]endpointInventoryComponent{parent}, false, "advertised"); len(rows) != 0 || !partial {
		t.Fatalf("advertised restore failure rows=%+v partial=%v", rows, partial)
	}
}

func TestObservedRestoreOverflowSurvivesFullLiveSet(t *testing.T) {
	var tools mcpToolInventory
	key := mcpObservedToolKey("claudecode", "", "notes")
	tools.observed = map[string]map[string]time.Time{key: {}}
	for index := range maxMCPToolObservations {
		tools.observed[key][fmt.Sprintf("live-%03d", index)] = time.Now()
	}
	tools.restoreToolLocked(key, audit.MCPObservedTool{
		ObservationGroupID: "parent", Connector: "claudecode", ServerName: "notes",
		ToolName: "durable-only", LastObservedAt: time.Now(), Overflowed: true,
	})
	if !tools.observedPartial[key] {
		t.Fatal("durable overflow was hidden by the full live set")
	}
	if _, exists := tools.observed[key]["durable-only"]; exists {
		t.Fatal("restore exceeded the bounded live set")
	}
}

func TestMCPToolInventoryKeepsObservedCallsAcrossParentCleanup(t *testing.T) {
	store := &testMCPObservedToolStore{}
	tools := &mcpToolInventory{store: store}
	parent := endpointInventoryComponent{id: "parent", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	if _, recorded := tools.recordObserved("codex", "notes", "old", time.Now()); !recorded {
		t.Fatal("initial observation was not recorded")
	}
	removed := tools.refreshParents(nil)
	if fmt.Sprint(removed) != "[parent]" {
		t.Fatalf("retired parents=%v", removed)
	}
	if retry := tools.refreshParents([]endpointInventoryComponent{parent}); fmt.Sprint(retry) != "[parent]" {
		t.Fatalf("pending cleanup was not retained: %v", retry)
	}
	if _, recorded := tools.recordObserved("codex", "notes", "new", time.Now()); !recorded {
		t.Fatal("configured-parent cleanup blocked independent runtime evidence")
	}
	tools.acknowledgeRemovedParents(removed)
	tools.refreshParents([]endpointInventoryComponent{parent})
	rows, partial := tools.observedComponents()
	if partial || len(rows) != 2 {
		t.Fatalf("observed calls across cleanup=%+v partial=%v", rows, partial)
	}
}

func TestMCPToolInventoryRetainsListingUntilParentRefresh(t *testing.T) {
	store := &testMCPObservedToolStore{}
	tools := mcpToolInventory{store: store}
	listed := time.Date(2026, 11, 18, 1, 2, 3, 0, time.UTC)
	parent := endpointInventoryComponent{id: "parent", itemName: "notes", agentConnector: "codex"}
	tools.recordAdvertised("codex", "notes", []string{"search"}, listed)
	if rows, partial := tools.components([]endpointInventoryComponent{parent}, false, "advertised"); len(rows) != 0 || !partial {
		t.Fatalf("pre-parent rows=%+v partial=%v", rows, partial)
	}
	tools.refreshParents([]endpointInventoryComponent{parent})
	if err := tools.flushPendingAdvertised(t.Context()); err != nil {
		t.Fatal(err)
	}
	rows, partial := tools.components([]endpointInventoryComponent{parent}, false, "advertised")
	if partial || len(rows) != 1 || rows[0].itemName != "search" || rows[0].mcpToolParentID != parent.id {
		t.Fatalf("retained listing rows=%+v partial=%v", rows, partial)
	}
	if store.advertisedWrite.ParentComponentID != parent.id ||
		len(store.advertisedWrite.ToolNames) != 1 || store.advertisedWrite.ToolNames[0] != "search" {
		t.Fatalf("flushed listing=%+v", store.advertisedWrite)
	}
}

func TestMCPToolInventoryFreshListingWinsOverRestoredSnapshot(t *testing.T) {
	store := &testMCPObservedToolStore{}
	tools := mcpToolInventory{store: store}
	parent := endpointInventoryComponent{id: "parent", itemName: "notes", agentConnector: "codex"}
	oldListed := time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC)
	newListed := oldListed.Add(time.Minute)
	tools.restoreAdvertised([]audit.MCPAdvertisedToolSnapshot{{
		ParentComponentID: parent.id, Connector: "codex", ServerName: "notes",
		ToolNames: []string{"old"}, ListedAt: oldListed,
	}})
	tools.recordAdvertised("codex", "notes", []string{"fresh"}, newListed)
	tools.refreshParents([]endpointInventoryComponent{parent})
	if err := tools.flushPendingAdvertised(t.Context()); err != nil {
		t.Fatal(err)
	}
	rows, partial := tools.components([]endpointInventoryComponent{parent}, false, "advertised")
	if partial || len(rows) != 1 || rows[0].itemName != "fresh" || rows[0].mcpToolObservedAt != newListed.Format(time.RFC3339Nano) {
		t.Fatalf("fresh listing rows=%+v partial=%v", rows, partial)
	}
	if fmt.Sprint(store.advertisedWrite.ToolNames) != "[fresh]" {
		t.Fatalf("persisted listing=%+v", store.advertisedWrite)
	}
}

func TestMCPToolInventoryNewerFailedWriteRemainsPending(t *testing.T) {
	store := &coordinatedAdvertisedStore{
		firstStarted: make(chan struct{}),
		releaseFirst: make(chan struct{}),
	}
	tools := mcpToolInventory{store: store}
	parent := endpointInventoryComponent{id: "parent", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		tools.recordAdvertised("codex", "notes", []string{"old"}, time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC))
	}()
	select {
	case <-store.firstStarted:
	case <-firstDone:
		close(store.releaseFirst)
		t.Fatal("first listing returned without starting its durable write")
	case <-time.After(2 * time.Second):
		close(store.releaseFirst)
		t.Fatal("first listing did not start its durable write")
	}
	tools.recordAdvertised("codex", "notes", []string{"fresh"}, time.Date(2026, 11, 18, 1, 1, 0, 0, time.UTC))
	close(store.releaseFirst)
	<-firstDone
	if err := tools.flushPendingAdvertised(t.Context()); err != nil {
		t.Fatal(err)
	}
	writes := store.snapshots()
	if len(writes) != 1 || fmt.Sprint(writes[0].ToolNames) != "[fresh]" {
		t.Fatalf("durable writes=%+v", writes)
	}
	rows, partial := tools.components([]endpointInventoryComponent{parent}, false, "advertised")
	if partial || len(rows) != 1 || rows[0].itemName != "fresh" {
		t.Fatalf("fresh listing rows=%+v partial=%v", rows, partial)
	}
}

func TestMCPToolInventoryDropsUnboundListingWhenParentIsAbsent(t *testing.T) {
	store := &testMCPObservedToolStore{}
	tools := mcpToolInventory{store: store}
	tools.recordAdvertised("codex", "notes", []string{"stale"}, time.Now())
	tools.refreshParents(nil)
	parent := endpointInventoryComponent{id: "different-parent", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	if err := tools.flushPendingAdvertised(t.Context()); err != nil {
		t.Fatal(err)
	}
	rows, partial := tools.components([]endpointInventoryComponent{parent}, false, "advertised")
	if partial || len(rows) != 0 {
		t.Fatalf("stale listing attached to new parent: rows=%+v partial=%v", rows, partial)
	}
	if store.advertisedWrite.ParentComponentID != "" {
		t.Fatalf("stale listing was persisted: %+v", store.advertisedWrite)
	}
}

func TestMCPToolInventoryRestoresAdvertisedPartialState(t *testing.T) {
	var tools mcpToolInventory
	listed := time.Date(2026, 11, 18, 1, 2, 3, 0, time.UTC)
	parent := endpointInventoryComponent{id: "parent", itemName: "notes", agentConnector: "codex"}
	tools.restoreAdvertised([]audit.MCPAdvertisedToolSnapshot{{
		ParentComponentID: parent.id, Connector: "codex", ServerName: "notes",
		ToolNames: []string{"search"}, ListedAt: listed, Partial: true,
	}})
	tools.refreshParents([]endpointInventoryComponent{parent})
	rows, partial := tools.components([]endpointInventoryComponent{parent}, false, "advertised")
	if !partial || len(rows) != 1 || rows[0].itemName != "search" {
		t.Fatalf("restored partial listing rows=%+v partial=%v", rows, partial)
	}
}

func TestManagedMCPToolInventoryJoinsConfiguredLocalServer(t *testing.T) {
	withManagedEnterprise(t, true)
	home := t.TempDir()
	t.Setenv("CODEX_HOME", t.TempDir())
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("[mcp_servers.notes]\ncommand = 'uvx'\nargs = ['notes-mcp']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AIDiscovery: config.AIDiscoveryConfig{HomeDirs: []string{home}}, Gateway: config.GatewayConfig{Token: "tool-test-key"}}
	registry := connector.NewRegistry()
	if err := registry.RegisterPlugin(&endpointInventoryPluginConnector{name: "codex", description: "test"}); err != nil {
		t.Fatal(err)
	}
	var tools mcpToolInventory
	servers, readPartial := perConnectorMCPEntriesWithStatus(cfg, registry)
	if readPartial {
		t.Fatal("fixture MCP config was partial")
	}
	tools.refreshParents(servers)
	tools.recordAdvertised("codex", "notes", []string{"search"}, time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC))
	capture := &endpointInventoryCapture{}
	if err := emitEndpointInventory(t.Context(), cfg, registry, capture, false, nil, nil, &tools); err != nil {
		t.Fatal(err)
	}
	var parent, child string
	for _, record := range capture.snapshot() {
		if record.EventName() != "ai_component.observed" {
			continue
		}
		body, ok := record.Body()
		if !ok {
			continue
		}
		fields, err := body.Object()
		if err != nil {
			t.Fatal(err)
		}
		switch fields[observability.TelemetryAttributeDefenseClawAIComponentType] {
		case "mcp_server":
			if fields[observability.TelemetryAttributeDefenseClawInventoryItemName] == "notes" &&
				fields[observability.TelemetryAttributeDefenseClawAIDiscoverySource] == "endpoint_per_connector_mcp_inventory" {
				parent, _ = fields[observability.TelemetryAttributeDefenseClawAIComponentID].(string)
			}
		case "mcp_tool":
			child, _ = fields[observability.TelemetryAttributeDefenseClawInventoryMcpToolParentID].(string)
		}
	}
	if parent == "" || child != parent {
		t.Fatalf("parent=%q tool parent=%q", parent, child)
	}
	configPath := filepath.Join(home, ".codex", "config.toml")
	if err := os.WriteFile(configPath, []byte("[mcp_servers.notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := emitEndpointInventory(t.Context(), cfg, registry, &endpointInventoryCapture{}, false, nil, nil, &tools); err != nil {
		t.Fatal(err)
	}
	if rows, _ := tools.components(servers, false); len(rows) != 1 {
		t.Fatalf("partial config read cleared last complete tool listing: %+v", rows)
	}
	if err := os.WriteFile(configPath, []byte("[mcp_servers.notes]\ncommand = 'uvx'\nargs = ['notes-mcp']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered := &endpointInventoryCapture{}
	if err := emitEndpointInventory(t.Context(), cfg, registry, recovered, false, nil, nil, &tools); err != nil {
		t.Fatal(err)
	}
	var recoveredTool bool
	for _, record := range recovered.snapshot() {
		if record.EventName() != "ai_component.observed" {
			continue
		}
		body, ok := record.Body()
		if !ok {
			continue
		}
		fields, err := body.Object()
		if err != nil {
			t.Fatal(err)
		}
		if fields[observability.TelemetryAttributeDefenseClawAIComponentType] == "mcp_tool" {
			recoveredTool = true
		}
	}
	if !recoveredTool {
		t.Fatal("recovered config did not republish retained tool")
	}
}

func TestManagedMCPParentRefreshIgnoresUnrelatedConnectorDiscoveryPartial(t *testing.T) {
	withManagedEnterprise(t, true)
	home := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CODEX_HOME", filepath.Join(t.TempDir(), ".codex"))
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("[mcp_servers.notes]\ncommand = 'uvx'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		AIDiscovery: config.AIDiscoveryConfig{HomeDirs: []string{home}},
		Gateway:     config.GatewayConfig{Token: "tool-test-key"},
	}
	registry := connector.NewRegistry()
	if err := registry.RegisterPlugin(&endpointInventoryPluginConnector{name: "codex", description: "test"}); err != nil {
		t.Fatal(err)
	}
	var tools mcpToolInventory
	if err := emitEndpointInventory(t.Context(), cfg, registry, &endpointInventoryCapture{}, true, nil, nil, &tools); err != nil {
		t.Fatal(err)
	}
	if parent, recorded := tools.recordObserved("codex", "notes", "search", time.Now()); !recorded || parent == "" {
		t.Fatalf("unrelated connector discovery partial state suppressed MCP parent: parent=%q recorded=%v", parent, recorded)
	}
}

func TestManagedRemoteMCPToolInventoryUsesConfiguredURLIdentity(t *testing.T) {
	withManagedEnterprise(t, true)
	home := t.TempDir()
	t.Setenv("CODEX_HOME", t.TempDir())
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(home, ".codex", "config.toml")
	if err := os.WriteFile(configPath, []byte("[mcp_servers.notes]\nurl = 'https://user:password@mcp.example.com/v1?token=secret'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AIDiscovery: config.AIDiscoveryConfig{HomeDirs: []string{home}}, Gateway: config.GatewayConfig{Token: "tool-test-key"}}
	registry := connector.NewRegistry()
	if err := registry.RegisterPlugin(&endpointInventoryPluginConnector{name: "codex", description: "test"}); err != nil {
		t.Fatal(err)
	}
	servers, readPartial := perConnectorMCPEntriesWithStatus(cfg, registry)
	if readPartial || len(servers) != 1 || !servers[0].mcpIsRemote || servers[0].mcpServerURL != "https://mcp.example.com" {
		t.Fatalf("remote parents=%+v partial=%v", servers, readPartial)
	}
	var tools mcpToolInventory
	tools.refreshParents(servers)
	listed := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	tools.recordAdvertised("codex", "notes", []string{"search"}, listed)
	tools.recordObserved("codex", "notes", "read", listed.Add(time.Minute))
	if local, _ := tools.components(servers, false); len(local) != 0 {
		t.Fatalf("remote evidence appeared in local collection: %+v", local)
	}
	capture := &endpointInventoryCapture{}
	if err := emitEndpointInventory(t.Context(), cfg, registry, capture, false, nil, nil, &tools); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"advertised:search": "", "observed:read": ""}
	for _, record := range capture.snapshot() {
		if record.EventName() != "ai_component.observed" {
			continue
		}
		body, ok := record.Body()
		if !ok {
			continue
		}
		fields, err := body.Object()
		if err != nil {
			t.Fatal(err)
		}
		if fields[observability.TelemetryAttributeDefenseClawAIComponentType] != "mcp_tool" {
			continue
		}
		wantSource := "endpoint_remote_mcp_tool_inventory"
		observed := fields[observability.TelemetryAttributeDefenseClawInventoryMcpToolSource] == "observed"
		if observed {
			wantSource = "endpoint_mcp_observed_tool_inventory"
		}
		if fields[observability.TelemetryAttributeDefenseClawAIDiscoverySource] != wantSource ||
			observed && (fields[observability.TelemetryAttributeDefenseClawInventoryMcpToolParentID] != nil ||
				fields[observability.TelemetryAttributeDefenseClawInventoryMcpRuntimeServerName] != "notes") ||
			!observed && fields[observability.TelemetryAttributeDefenseClawInventoryMcpToolParentID] != servers[0].id {
			t.Fatalf("remote lineage=%v", fields)
		}
		key := fields[observability.TelemetryAttributeDefenseClawInventoryMcpToolSource].(string) + ":" + fields[observability.TelemetryAttributeDefenseClawInventoryItemName].(string)
		if _, ok := want[key]; !ok {
			t.Fatalf("unexpected tool key %q", key)
		}
		want[key], _ = fields[observability.TelemetryAttributeDefenseClawAIComponentID].(string)
		encoded, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"password", "token=secret", "user:"} {
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("remote tool leaked %q: %s", secret, encoded)
			}
		}
	}
	for key, id := range want {
		if id == "" {
			t.Fatalf("missing remote tool %s", key)
		}
	}
	tools.recordAdvertised("codex", "notes", nil, listed.Add(2*time.Minute))
	rows, partial := tools.components(servers, true)
	if partial || len(rows) != 0 {
		t.Fatalf("empty remote listing=%+v partial=%v", rows, partial)
	}
	observedRows, observedPartial := tools.observedComponents()
	if observedPartial || len(observedRows) != 1 || observedRows[0].mcpToolSource != "observed" {
		t.Fatalf("empty listing changed runtime observation=%+v partial=%v", observedRows, observedPartial)
	}
	tools.recordListingFailure("codex", "notes")
	rows, partial = tools.components(servers, true)
	if !partial || len(rows) != 0 {
		t.Fatalf("failed remote listing cleared evidence: %+v partial=%v", rows, partial)
	}
}

func TestMCPToolInventoryMetricUsesOnlyBoundedLabels(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	recordMCPToolInventoryMetric(t.Context(), runtime, "list", "success", "none")
	recordMCPToolInventoryMetric(t.Context(), runtime, "observe", "partial", "incomplete")
	recordMCPToolInventoryMetric(t.Context(), runtime, "export", "error", "publish_error")
	recordMCPToolInventoryMetric(t.Context(), runtime, "list", "error", "server-secret")
	metrics := generatedMetricByName(capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawInventoryMcpToolEvents)
	if len(metrics) != 3 {
		t.Fatalf("metric count=%d, want three bounded outcomes", len(metrics))
	}
	if got := metrics[0].Attributes()[observability.TelemetryAttributeDefenseClawInventoryMcpToolStage]; got != "list" {
		t.Fatalf("listing stage=%v", got)
	}
	if got := metrics[1].Attributes()[observability.TelemetryAttributeDefenseClawInventoryMcpToolReason]; got != "incomplete" {
		t.Fatalf("observation reason=%v", got)
	}
	if got := metrics[2].Attributes()[observability.TelemetryAttributeDefenseClawInventoryMcpToolReason]; got != "publish_error" {
		t.Fatalf("export reason=%v", got)
	}
}

func TestMCPToolInventoryKeepsListedAndObservedEvidenceSeparate(t *testing.T) {
	var tools mcpToolInventory
	listed := time.Date(2026, 11, 2, 1, 2, 3, 0, time.UTC)
	called := listed.Add(time.Minute)
	parent := endpointInventoryComponent{
		id: "endpoint-mcp-entry-0123456789abcdef", componentType: "mcp_server",
		itemName: "notes", agentConnector: "codex", active: true,
	}
	tools.refreshParents([]endpointInventoryComponent{parent})
	tools.recordAdvertised("codex", "notes", []string{"search", "search", "read", "bad/name", "secret\n"}, listed)
	tools.recordObserved("codex", "notes", "search", called)
	advertised, advertisedPartial := tools.advertisedComponents([]endpointInventoryComponent{parent}, false)
	observed, observedPartial := tools.observedComponents()
	if !advertisedPartial || observedPartial || len(advertised) != 2 || len(observed) != 1 {
		t.Fatalf("advertised=%+v/%v observed=%+v/%v", advertised, advertisedPartial, observed, observedPartial)
	}
	if advertised[0].mcpToolParentID != parent.id || observed[0].mcpToolParentID != "" ||
		observed[0].mcpRuntimeServerName != "notes" {
		t.Fatalf("correlation contract advertised=%+v observed=%+v", advertised, observed)
	}
	tools.recordAdvertised("codex", "notes", nil, called)
	advertised, advertisedPartial = tools.advertisedComponents([]endpointInventoryComponent{parent}, false)
	observed, observedPartial = tools.observedComponents()
	if advertisedPartial || len(advertised) != 0 || observedPartial || len(observed) != 1 {
		t.Fatalf("empty listing changed independent observations: advertised=%+v/%v observed=%+v/%v",
			advertised, advertisedPartial, observed, observedPartial)
	}
	tools.recordListingFailure("codex", "notes")
	_, advertisedPartial = tools.advertisedComponents([]endpointInventoryComponent{parent}, false)
	if !advertisedPartial {
		t.Fatal("failed listing was reported as complete")
	}
}

func TestMCPToolInventorySkipsParentsThatWereNeverListed(t *testing.T) {
	withManagedEnterprise(t, true)
	var tools mcpToolInventory
	parent := endpointInventoryComponent{id: "server-a", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	rows, partial := tools.components([]endpointInventoryComponent{parent}, false)
	if len(rows) != 0 || partial {
		t.Fatalf("pre-watcher snapshot rows=%+v partial=%v", rows, partial)
	}
	capture := &endpointInventoryCapture{}
	if err := emitEndpointInventorySnapshot(t.Context(), capture, "endpoint_local_mcp_tool_inventory", rows, partial,
		config.ObservabilityV8ManagedMCPInventoryAction, endpointInventoryCycle{}); err != nil {
		t.Fatal(err)
	}
	for _, record := range capture.snapshot() {
		if record.Action() == string(config.ObservabilityV8LocalInventoryDiagnosticAction) {
			t.Fatal("never-listed parent made the advertised collection partial")
		}
	}
	tools.recordObserved("codex", "notes", "read", time.Now())
	rows, partial = tools.components([]endpointInventoryComponent{parent}, false, "observed")
	if len(rows) != 1 || partial {
		t.Fatalf("observed-only snapshot rows=%+v partial=%v", rows, partial)
	}
	tools.recordAdvertised("codex", "notes", nil, time.Now())
	rows, partial = tools.components([]endpointInventoryComponent{parent}, false, "advertised")
	if len(rows) != 0 || partial {
		t.Fatalf("completed empty listing rows=%+v partial=%v", rows, partial)
	}
}

func TestMCPToolInventoryBoundsNamesPerParentNotPerCollection(t *testing.T) {
	var tools mcpToolInventory
	parents := []endpointInventoryComponent{
		{id: "server-a", itemName: "one", agentConnector: "codex"},
		{id: "server-b", itemName: "two", agentConnector: "codex"},
	}
	tools.refreshParents(parents)
	for _, parent := range parents {
		names := make([]string, maxMCPToolObservations)
		for index := range names {
			names[index] = fmt.Sprintf("tool-%03d", index)
		}
		tools.recordAdvertised("codex", parent.itemName, names, time.Now())
	}
	rows, partial := tools.components(parents, false, "advertised")
	if partial || len(rows) != 2*maxMCPToolObservations {
		t.Fatalf("multi-parent rows=%d partial=%v", len(rows), partial)
	}
}

func TestMCPToolInventoryRequiresManagedParentEligibility(t *testing.T) {
	parents := make([]endpointInventoryComponent, 0, maxManagedMCPInventory+1)
	for index := 0; index <= maxManagedMCPInventory; index++ {
		parents = append(parents, endpointInventoryComponent{id: fmt.Sprintf("parent-%03d", index)})
	}
	toolRows := []endpointInventoryComponent{{mcpToolParentID: parents[0].id}}
	if mcpToolParentsManaged(toolRows, managedMCPParentIDs(parents, nil, true)) {
		t.Fatal("tool was eligible while its parent collection was over the managed limit")
	}
	parents = parents[:maxManagedMCPInventory]
	if !mcpToolParentsManaged(toolRows, managedMCPParentIDs(parents, nil, true)) {
		t.Fatal("tool was rejected with an eligible managed parent")
	}
	if mcpToolParentsManaged(toolRows, managedMCPParentIDs(parents, nil, false)) {
		t.Fatal("tool was eligible without an accepted parent submission")
	}
	accepted := map[string]struct{}{parents[0].id: {}}
	if !mcpToolParentsManaged(toolRows, managedMCPParentIDs(parents, accepted, false)) {
		t.Fatal("tool was rejected after its parent submission was accepted")
	}
}

func TestObservedMCPToolInventoryDoesNotWaitForToolsListAndPreservesSiblings(t *testing.T) {
	withManagedEnterprise(t, true)
	var tools mcpToolInventory
	parent := endpointInventoryComponent{id: "server-a", itemName: "notes", agentConnector: "claudecode"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	first := time.Date(2026, 11, 17, 1, 2, 3, 0, time.UTC)
	tools.recordObserved("claudecode", "notes", "search", first)
	tools.recordObserved("claudecode", "notes", "read", first.Add(time.Minute))
	tools.recordObserved("claudecode", "notes", "search", first.Add(2*time.Minute))
	tools.recordObserved("claudecode", "notes", "search", first.Add(time.Minute))

	rows, partial := tools.components([]endpointInventoryComponent{parent}, false, "observed")
	if partial || len(rows) != 2 {
		t.Fatalf("observed rows=%+v partial=%v", rows, partial)
	}
	got := map[string]string{}
	for _, row := range rows {
		got[row.itemName] = row.mcpToolObservedAt
		if row.mcpToolSource != "observed" || row.mcpToolParentID != "" || row.mcpRuntimeServerName != "notes" {
			t.Fatalf("invalid observed lineage: %+v", row)
		}
	}
	if got["search"] != first.Add(2*time.Minute).Format(time.RFC3339Nano) ||
		got["read"] != first.Add(time.Minute).Format(time.RFC3339Nano) {
		t.Fatalf("sibling observations=%v", got)
	}

	advertised, advertisedPartial := tools.components([]endpointInventoryComponent{parent}, false, "advertised")
	if len(advertised) != 0 || advertisedPartial {
		t.Fatalf("advertised rows=%+v partial=%v", advertised, advertisedPartial)
	}
}

func TestMCPToolInventoryDoesNotProjectEvidenceUnderDifferentParent(t *testing.T) {
	var tools mcpToolInventory
	current := endpointInventoryComponent{id: "parent-a", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{current})
	tools.recordAdvertised("codex", "notes", []string{"search"}, time.Now())
	tools.recordObserved("codex", "notes", "read", time.Now())

	replacement := current
	replacement.id = "parent-b"
	replacement.userID = "different-user"
	rows, partial := tools.advertisedComponents([]endpointInventoryComponent{replacement}, false)
	if len(rows) != 0 || !partial {
		t.Fatalf("stale advertised parent evidence was reattributed: rows=%+v partial=%v", rows, partial)
	}
	observed, observedPartial := tools.observedComponents()
	if observedPartial || len(observed) != 1 || observed[0].mcpRuntimeServerName != "notes" {
		t.Fatalf("runtime evidence depended on replacement parent: rows=%+v partial=%v", observed, observedPartial)
	}
}

func TestMCPToolInventoryRestoreDoesNotMoveObservationTimeBackward(t *testing.T) {
	var tools mcpToolInventory
	parent := endpointInventoryComponent{id: "parent", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	newer := time.Date(2026, 11, 18, 2, 0, 0, 0, time.UTC)
	tools.recordObserved("codex", "notes", "search", newer)
	tools.restoreObserved([]audit.MCPObservedTool{{
		ObservationGroupID: parent.id, Connector: "codex", ServerName: "notes",
		ToolName: "search", LastObservedAt: newer.Add(-time.Hour),
	}})
	tools.refreshParents([]endpointInventoryComponent{parent})
	rows, partial := tools.components([]endpointInventoryComponent{parent}, false, "observed")
	if partial || len(rows) != 1 || rows[0].mcpToolObservedAt != newer.Format(time.RFC3339Nano) {
		t.Fatalf("restored observation rows=%+v partial=%v", rows, partial)
	}
}

func TestObservedMCPToolIgnoresConfigurationReadCompleteness(t *testing.T) {
	var tools mcpToolInventory
	parent := endpointInventoryComponent{id: "server-a", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	if _, recorded := tools.recordObserved("codex", "notes", "search", time.Now()); !recorded {
		t.Fatal("fixture observation was not recorded")
	}
	if tools.observedIncomplete() {
		t.Fatal("configuration completeness degraded independent observed evidence")
	}
}

func TestObservedMCPToolOverflowStaysSeparateFromListingState(t *testing.T) {
	var tools mcpToolInventory
	parent := endpointInventoryComponent{id: "server-a", itemName: "notes", agentConnector: "claudecode"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	for index := 0; index <= maxMCPToolObservations; index++ {
		tools.recordObserved("claudecode", "notes", fmt.Sprintf("tool-%03d", index), time.Now())
	}
	tools.recordAdvertised("claudecode", "notes", nil, time.Now())
	rows, partial := tools.components([]endpointInventoryComponent{parent}, false, "observed")
	if len(rows) != maxMCPToolObservations || !partial {
		t.Fatalf("observed rows=%d partial=%v", len(rows), partial)
	}
	advertised, advertisedPartial := tools.components([]endpointInventoryComponent{parent}, false, "advertised")
	if len(advertised) != 0 || advertisedPartial {
		t.Fatalf("advertised rows=%+v partial=%v", advertised, advertisedPartial)
	}
}

func TestMCPToolInventoryUsesCurrentParentAndAvoidsAmbiguousAliases(t *testing.T) {
	var tools mcpToolInventory
	parent := endpointInventoryComponent{id: "server-a", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	tools.recordAdvertised("codex", "notes", []string{"search"}, time.Now())
	tools.refreshParents([]endpointInventoryComponent{parent, {id: "server-b", itemName: "notes", agentConnector: "codex"}})
	rows, partial := tools.components([]endpointInventoryComponent{parent, {id: "server-b", itemName: "notes", agentConnector: "codex"}}, false)
	if len(rows) != 0 || !partial {
		t.Fatalf("ambiguous alias produced rows: %+v partial=%v", rows, partial)
	}
	parent.id = "server-new"
	tools.refreshParents([]endpointInventoryComponent{parent})
	rows, partial = tools.components([]endpointInventoryComponent{parent}, false)
	if len(rows) != 0 || partial {
		t.Fatalf("old tool evidence followed new server ID: %+v partial=%v", rows, partial)
	}
	tools.recordAdvertised("codex", "notes", []string{"search"}, time.Now())
	rows, partial = tools.components([]endpointInventoryComponent{parent}, false)
	if len(rows) != 1 || partial || rows[0].mcpToolParentID != parent.id {
		t.Fatalf("new server evidence=%+v partial=%v", rows, partial)
	}
}

func TestMCPToolInventorySerializesReadReconcileAndDelete(t *testing.T) {
	store := &testMCPObservedToolStore{deleteStarted: make(chan struct{}), releaseDelete: make(chan struct{})}
	tools := mcpToolInventory{store: store}
	tools.refreshParents([]endpointInventoryComponent{{id: "old", itemName: "notes", agentConnector: "codex"}})
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		tools.readAndReconcileParents(t.Context(), func() ([]endpointInventoryComponent, perConnectorMCPReadStatus) {
			return []endpointInventoryComponent{{id: "new", itemName: "notes", agentConnector: "codex"}}, perConnectorMCPReadStatus{}
		})
	}()
	select {
	case <-store.deleteStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("durable delete did not start")
	}
	secondReadStarted := make(chan struct{})
	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		tools.readAndReconcileParents(t.Context(), func() ([]endpointInventoryComponent, perConnectorMCPReadStatus) {
			close(secondReadStarted)
			return []endpointInventoryComponent{{id: "newer", itemName: "notes", agentConnector: "codex"}}, perConnectorMCPReadStatus{}
		})
	}()
	select {
	case <-secondReadStarted:
		close(store.releaseDelete)
		t.Fatal("new reconciliation started before durable retirement completed")
	case <-time.After(100 * time.Millisecond):
	}
	close(store.releaseDelete)
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first reconciliation did not finish")
	}
	select {
	case <-secondDone:
	case <-time.After(2 * time.Second):
		t.Fatal("second reconciliation did not finish")
	}
	if _, recorded := tools.recordObserved("codex", "notes", "search", time.Now()); !recorded {
		t.Fatal("serialized parent refresh blocked independent observation")
	}
}

func TestMCPToolBlockedListingsUseAcceptedMetricLabels(t *testing.T) {
	var got [][3]string
	tools := mcpToolInventory{metric: func(_ context.Context, stage, outcome, reason string) {
		got = append(got, [3]string{stage, outcome, reason})
	}}
	parents := []endpointInventoryComponent{
		{id: "parent-a", itemName: "notes", agentConnector: "codex"},
		{id: "parent-b", itemName: "notes", agentConnector: "codex"},
	}
	tools.refreshParents(parents)
	tools.recordAdvertisedContext(t.Context(), "codex", "notes", []string{"search"}, time.Now())
	tools.recordListingFailureContext(t.Context(), "codex", "notes")
	want := [3]string{"list", "partial", "incomplete"}
	if len(got) != 2 || got[0] != want || got[1] != want {
		t.Fatalf("blocked listing metrics=%v want=%v twice", got, want)
	}
}

func TestMCPToolInventoryExportsOnlyBoundedNamesAndLineage(t *testing.T) {
	withManagedEnterprise(t, true)
	var tools mcpToolInventory
	parent := endpointInventoryComponent{id: "endpoint-mcp-entry-0123456789abcdef", itemName: "notes", agentConnector: "codex", active: true}
	tools.refreshParents([]endpointInventoryComponent{parent})
	tools.recordAdvertised("codex", "notes", []string{"search"}, time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC))
	rows, partial := tools.components([]endpointInventoryComponent{parent}, false)
	capture := &endpointInventoryCapture{}
	if err := emitEndpointInventorySnapshot(t.Context(), capture, "endpoint_local_mcp_tool_inventory", rows, partial,
		config.ObservabilityV8ManagedMCPInventoryAction, endpointInventoryCycle{}); err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, record := range capture.snapshot() {
		if record.EventName() != "ai_component.observed" {
			continue
		}
		body, _ := record.Body()
		fields, err := body.Object()
		if err != nil {
			t.Fatal(err)
		}
		if fields[observability.TelemetryAttributeDefenseClawAIComponentType] != "mcp_tool" {
			continue
		}
		seen = true
		if fields[observability.TelemetryAttributeDefenseClawInventoryMcpToolParentID] != parent.id ||
			fields[observability.TelemetryAttributeDefenseClawInventoryMcpToolSource] != "advertised" ||
			fields[observability.TelemetryAttributeDefenseClawInventoryMcpToolObservedAt] != "2026-11-02T00:00:00Z" {
			t.Fatalf("tool lineage fields=%v", fields)
		}
		for key, value := range fields {
			if strings.Contains(strings.ToLower(key), "argument") || strings.Contains(strings.ToLower(key), "description") {
				t.Fatalf("unexpected tool content %s=%v", key, value)
			}
		}
	}
	if !seen {
		t.Fatal("no exported tool component")
	}
}
