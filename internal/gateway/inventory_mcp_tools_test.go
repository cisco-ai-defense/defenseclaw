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
	deleteErr         error
	deleteCalls       [][]string
	stillCurrent      func() bool
	advertisedCurrent func() bool
	advertisedWrite   audit.MCPAdvertisedToolSnapshot
}

type coordinatedAdvertisedStore struct {
	testMCPObservedToolStore
	mu           sync.Mutex
	calls        int
	firstStarted chan struct{}
	releaseFirst chan struct{}
	writes       []audit.MCPAdvertisedToolSnapshot
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

func (s *testMCPObservedToolStore) UpsertMCPObservedToolIf(_ context.Context, _ audit.MCPObservedTool, stillCurrent func() bool) error {
	s.stillCurrent = stillCurrent
	return nil
}

func (s *testMCPObservedToolStore) ListMCPObservedTools(context.Context) ([]audit.MCPObservedTool, error) {
	return s.tools, s.listErr
}

func (s *testMCPObservedToolStore) ReplaceMCPAdvertisedToolsIf(_ context.Context, snapshot audit.MCPAdvertisedToolSnapshot, stillCurrent func() bool) error {
	s.advertisedCurrent = stillCurrent
	s.advertisedWrite = snapshot
	return nil
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

func (s *testMCPObservedToolStore) ListMCPAdvertisedToolSnapshots(context.Context) ([]audit.MCPAdvertisedToolSnapshot, error) {
	return s.advertised, s.listErr
}

func (s *testMCPObservedToolStore) DeleteMCPObservedToolsForParents(_ context.Context, parentIDs []string) error {
	s.deleteCalls = append(s.deleteCalls, append([]string(nil), parentIDs...))
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
	if rows, _ := tools.components([]endpointInventoryComponent{parent}, false); len(rows) != 0 {
		t.Fatalf("untrusted hook recorded tool: %+v", rows)
	}
	ctx := withAuthenticatedToolResource(withAuthenticatedHookConnector(context.Background(), "codex"), req,
		[]byte(`{"tool_name":"mcp__notes__search"}`))
	api.recordObservedMCPTool(ctx, req, at)
	rows, partial := tools.components([]endpointInventoryComponent{parent}, false)
	if partial || len(rows) != 1 || rows[0].itemName != "search" || rows[0].mcpToolSource != "observed" {
		t.Fatalf("authenticated observation=%+v partial=%v", rows, partial)
	}
	changed := req
	changed.ToolName = "mcp__notes__other"
	api.recordObservedMCPTool(ctx, changed, at)
	rows, _ = tools.components([]endpointInventoryComponent{parent}, false)
	if len(rows) != 1 {
		t.Fatalf("modified tool name crossed pinned hook projection: %+v", rows)
	}
}

func TestObservedMCPToolReportsUnavailableParent(t *testing.T) {
	var gotStage, gotOutcome, gotReason string
	tools := &mcpToolInventory{metric: func(_ context.Context, stage, outcome, reason string) {
		gotStage, gotOutcome, gotReason = stage, outcome, reason
	}}
	api := &APIServer{mcpTools: tools}
	req := agentHookRequest{
		ConnectorName: "claudecode", ConnectorInstanceID: syntheticToolResourceConnectorID,
		ToolName: "mcp__notes__search", Payload: map[string]interface{}{"mcp_server_name": "notes"},
	}
	ctx := withAuthenticatedToolResource(withAuthenticatedHookConnector(context.Background(), "claudecode"), req,
		[]byte(`{"tool_name":"mcp__notes__search","mcp_server_name":"notes"}`))
	api.recordObservedMCPTool(ctx, req, time.Now())
	if gotStage != "observe" || gotOutcome != "partial" || gotReason != "parent_unavailable" {
		t.Fatalf("unavailable parent metric=%q/%q/%q", gotStage, gotOutcome, gotReason)
	}
}

func TestObservedMCPToolDeferredWriteRejectsRetiredParent(t *testing.T) {
	store := &testMCPObservedToolStore{}
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
	if store.stillCurrent() {
		t.Fatal("deferred durable write accepted a retired parent")
	}
}

func TestObservedMCPToolRestoreReconcilesParentAndRetriesCleanup(t *testing.T) {
	now := time.Now().UTC()
	store := &testMCPObservedToolStore{tools: []audit.MCPObservedTool{
		{ParentComponentID: "old-parent", Connector: "claudecode", ServerName: "notes", ToolName: "old", LastObservedAt: now},
		{ParentComponentID: "new-parent", Connector: "claudecode", ServerName: "notes", ToolName: "current", LastObservedAt: now},
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
	if fmt.Sprint(removed) != "[old-parent]" {
		t.Fatalf("stale parents=%v", removed)
	}
	rows, _ := tools.components([]endpointInventoryComponent{server}, false, "observed")
	if len(rows) != 1 || rows[0].itemName != "current" {
		t.Fatalf("restored rows=%+v", rows)
	}
	advertised, partial := tools.components([]endpointInventoryComponent{server}, false, "advertised")
	if partial || len(advertised) != 1 || advertised[0].itemName != "listed" {
		t.Fatalf("restored advertised rows=%+v partial=%v", advertised, partial)
	}
	store.deleteErr = fmt.Errorf("temporary cleanup failure")
	if err := store.DeleteMCPObservedToolsForParents(t.Context(), removed); err == nil {
		t.Fatal("cleanup unexpectedly succeeded")
	}
	if !tools.observedIncomplete(nil) {
		t.Fatal("failed cleanup did not keep observed inventory partial")
	}
	if retry := tools.refreshParents([]endpointInventoryComponent{server}); fmt.Sprint(retry) != "[old-parent]" {
		t.Fatalf("cleanup was not retried: %v", retry)
	}
	store.deleteErr = nil
	if err := store.DeleteMCPObservedToolsForParents(t.Context(), removed); err != nil {
		t.Fatal(err)
	}
	tools.acknowledgeRemovedParents(removed)
	if tools.observedIncomplete(nil) {
		t.Fatal("successful cleanup left observed inventory partial")
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
	if !tools.observedIncomplete(nil) {
		t.Fatal("failed restore did not keep observed inventory partial")
	}
	if rows, partial := tools.components([]endpointInventoryComponent{server}, false, "advertised"); len(rows) != 0 || !partial {
		t.Fatalf("failed restore advertised rows=%+v partial=%v", rows, partial)
	}
	store.listErr = nil
	tools.retryRestoreFromStore(t.Context())
	tools.refreshParents([]endpointInventoryComponent{server})
	if tools.observedIncomplete(nil) {
		t.Fatal("successful empty restore was not authoritative")
	}
	if rows, partial := tools.components([]endpointInventoryComponent{server}, false, "advertised"); len(rows) != 0 || partial {
		t.Fatalf("successful empty restore advertised rows=%+v partial=%v", rows, partial)
	}
}

func TestMCPToolInventoryFencesReappearingParentUntilCleanupCompletes(t *testing.T) {
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
	if _, recorded := tools.recordObserved("codex", "notes", "new", time.Now()); recorded {
		t.Fatal("reappearing parent accepted evidence before cleanup completed")
	}
	tools.acknowledgeRemovedParents(removed)
	tools.refreshParents([]endpointInventoryComponent{parent})
	if _, recorded := tools.recordObserved("codex", "notes", "new", time.Now()); !recorded {
		t.Fatal("parent was not reactivated after cleanup completed")
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
	<-store.firstStarted
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
		if fields[observability.TelemetryAttributeDefenseClawInventoryMcpToolSource] == "observed" {
			wantSource = "endpoint_remote_mcp_observed_tool_inventory"
		}
		if fields[observability.TelemetryAttributeDefenseClawAIDiscoverySource] != wantSource ||
			fields[observability.TelemetryAttributeDefenseClawInventoryMcpToolParentID] != servers[0].id {
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
	if partial || len(rows) != 1 || rows[0].mcpToolSource != "observed" {
		t.Fatalf("empty remote listing=%+v partial=%v", rows, partial)
	}
	tools.recordListingFailure("codex", "notes")
	rows, partial = tools.components(servers, true)
	if !partial || len(rows) != 1 {
		t.Fatalf("failed remote listing cleared evidence: %+v partial=%v", rows, partial)
	}
}

func TestMCPToolInventoryMetricUsesOnlyBoundedLabels(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	recordMCPToolInventoryMetric(t.Context(), runtime, "list", "success", "none")
	recordMCPToolInventoryMetric(t.Context(), runtime, "observe", "partial", "parent_unavailable")
	recordMCPToolInventoryMetric(t.Context(), runtime, "export", "partial", "incomplete")
	recordMCPToolInventoryMetric(t.Context(), runtime, "list", "error", "server-secret")
	metrics := generatedMetricByName(capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawInventoryMcpToolEvents)
	if len(metrics) != 3 {
		t.Fatalf("metric count=%d, want three bounded outcomes", len(metrics))
	}
	if got := metrics[0].Attributes()[observability.TelemetryAttributeDefenseClawInventoryMcpToolStage]; got != "list" {
		t.Fatalf("listing stage=%v", got)
	}
	if got := metrics[1].Attributes()[observability.TelemetryAttributeDefenseClawInventoryMcpToolReason]; got != "parent_unavailable" {
		t.Fatalf("observation reason=%v", got)
	}
	if got := metrics[2].Attributes()[observability.TelemetryAttributeDefenseClawInventoryMcpToolReason]; got != "incomplete" {
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
	rows, partial := tools.components([]endpointInventoryComponent{parent}, false)
	if !partial || len(rows) != 3 {
		t.Fatalf("rows=%d partial=%v", len(rows), partial)
	}
	ids := map[string]string{}
	for _, row := range rows {
		if row.componentType != "mcp_tool" || row.mcpToolParentID != parent.id || row.mcpToolObservedAt == "" {
			t.Fatalf("invalid tool row %+v", row)
		}
		ids[row.mcpToolSource+":"+row.itemName] = row.id
	}
	if ids["advertised:search"] == "" || ids["observed:search"] == "" || ids["advertised:search"] == ids["observed:search"] {
		t.Fatalf("listed and observed identity collapsed: %v", ids)
	}
	tools.recordAdvertised("codex", "notes", nil, called)
	rows, partial = tools.components([]endpointInventoryComponent{parent}, false)
	if partial || len(rows) != 1 || rows[0].mcpToolSource != "observed" {
		t.Fatalf("empty completed listing did not clear advertised tools: %+v partial=%v", rows, partial)
	}
	tools.recordListingFailure("codex", "notes")
	_, partial = tools.components([]endpointInventoryComponent{parent}, false)
	if !partial {
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
	rows, partial = tools.components([]endpointInventoryComponent{parent}, false)
	if len(rows) != 1 || partial {
		t.Fatalf("observed-only snapshot rows=%+v partial=%v", rows, partial)
	}
	tools.recordAdvertised("codex", "notes", nil, time.Now())
	rows, partial = tools.components([]endpointInventoryComponent{parent}, false)
	if len(rows) != 1 || partial {
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
		if row.mcpToolSource != "observed" || row.mcpToolParentID != parent.id {
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
	rows, partial := tools.components([]endpointInventoryComponent{replacement}, false)
	if len(rows) != 0 || !partial {
		t.Fatalf("stale parent evidence was reattributed: rows=%+v partial=%v", rows, partial)
	}
}

func TestMCPToolInventoryRestoreDoesNotMoveObservationTimeBackward(t *testing.T) {
	var tools mcpToolInventory
	parent := endpointInventoryComponent{id: "parent", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	newer := time.Date(2026, 11, 18, 2, 0, 0, 0, time.UTC)
	tools.recordObserved("codex", "notes", "search", newer)
	tools.restoreObserved([]audit.MCPObservedTool{{
		ParentComponentID: parent.id, Connector: "codex", ServerName: "notes",
		ToolName: "search", LastObservedAt: newer.Add(-time.Hour),
	}})
	tools.refreshParents([]endpointInventoryComponent{parent})
	rows, partial := tools.components([]endpointInventoryComponent{parent}, false, "observed")
	if partial || len(rows) != 1 || rows[0].mcpToolObservedAt != newer.Format(time.RFC3339Nano) {
		t.Fatalf("restored observation rows=%+v partial=%v", rows, partial)
	}
}

func TestObservedMCPToolIncompleteOwnerKeepsSnapshotPartial(t *testing.T) {
	var tools mcpToolInventory
	parent := endpointInventoryComponent{id: "server-a", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	if _, recorded := tools.recordObserved("codex", "notes", "search", time.Now()); !recorded {
		t.Fatal("fixture observation was not recorded")
	}
	if !tools.observedIncomplete(map[string]struct{}{"codex": {}}) {
		t.Fatal("incomplete owner with durable evidence was treated as a complete observed snapshot")
	}
	if tools.observedIncomplete(map[string]struct{}{"claudecode": {}}) {
		t.Fatal("unrelated incomplete connector suppressed complete observed evidence")
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

func TestMCPToolInventoryRefreshesOnlyCompleteConnectors(t *testing.T) {
	var tools mcpToolInventory
	servers := []endpointInventoryComponent{
		{id: "claude-parent", itemName: "notes", agentConnector: "claudecode"},
		{id: "codex-parent", itemName: "database", agentConnector: "codex"},
	}
	tools.refreshCompleteParents(servers, map[string]struct{}{"codex": {}})

	if parent, recorded := tools.recordObserved("claudecode", "notes", "search", time.Now()); !recorded || parent != "claude-parent" {
		t.Fatalf("complete Claude parent was unavailable: parent=%q recorded=%v", parent, recorded)
	}
	if parent, recorded := tools.recordObserved("codex", "database", "query", time.Now()); recorded || parent != "" {
		t.Fatalf("incomplete Codex parent accepted a new observation: parent=%q recorded=%v", parent, recorded)
	}
	tools.refreshParents(servers)
	if parent, recorded := tools.recordObserved("codex", "database", "query", time.Now()); !recorded || parent != "codex-parent" {
		t.Fatalf("complete Codex parent was unavailable: parent=%q recorded=%v", parent, recorded)
	}
	tools.refreshCompleteParents([]endpointInventoryComponent{
		{id: "claude-parent", itemName: "notes", agentConnector: "claudecode"},
		{id: "codex-new", itemName: "database", agentConnector: "codex"},
	}, map[string]struct{}{"codex": {}})
	if parent, recorded := tools.recordObserved("codex", "database", "write", time.Now()); !recorded || parent != "codex-parent" {
		t.Fatalf("partial Codex refresh replaced its last complete parent: parent=%q recorded=%v", parent, recorded)
	}

	tools.refreshCompleteParents([]endpointInventoryComponent{
		{id: "claude-a", itemName: "notes", agentConnector: "claudecode"},
		{id: "claude-b", itemName: "notes", agentConnector: "claudecode"},
	}, map[string]struct{}{"codex": {}})
	if parent, recorded := tools.recordObserved("claudecode", "notes", "read", time.Now()); recorded || parent != "" {
		t.Fatalf("ambiguous complete alias accepted an observation: parent=%q recorded=%v", parent, recorded)
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
