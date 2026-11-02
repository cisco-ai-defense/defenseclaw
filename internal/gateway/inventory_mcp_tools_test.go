// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

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
	if !partial || len(rows) != 1 || rows[0].itemName != "search" || rows[0].mcpToolSource != "observed" {
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

func TestMCPToolInventoryMetricUsesOnlyBoundedLabels(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	recordMCPToolInventoryMetric(t.Context(), runtime, "list", "success", "none")
	recordMCPToolInventoryMetric(t.Context(), runtime, "export", "partial", "incomplete")
	recordMCPToolInventoryMetric(t.Context(), runtime, "list", "error", "server-secret")
	metrics := generatedMetricByName(capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawInventoryMcpToolEvents)
	if len(metrics) != 2 {
		t.Fatalf("metric count=%d, want two bounded outcomes", len(metrics))
	}
	if got := metrics[0].Attributes()[observability.TelemetryAttributeDefenseClawInventoryMcpToolStage]; got != "list" {
		t.Fatalf("listing stage=%v", got)
	}
	if got := metrics[1].Attributes()[observability.TelemetryAttributeDefenseClawInventoryMcpToolReason]; got != "incomplete" {
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

func TestMCPToolInventoryWaitsForAuthoritativeFirstListing(t *testing.T) {
	withManagedEnterprise(t, true)
	var tools mcpToolInventory
	parent := endpointInventoryComponent{id: "server-a", itemName: "notes", agentConnector: "codex"}
	tools.refreshParents([]endpointInventoryComponent{parent})
	rows, partial := tools.components([]endpointInventoryComponent{parent}, false)
	if len(rows) != 0 || !partial {
		t.Fatalf("pre-watcher snapshot rows=%+v partial=%v", rows, partial)
	}
	capture := &endpointInventoryCapture{}
	if err := emitEndpointInventorySnapshot(t.Context(), capture, "endpoint_local_mcp_tool_inventory", rows, partial,
		config.ObservabilityV8ManagedMCPInventoryAction, endpointInventoryCycle{}); err != nil {
		t.Fatal(err)
	}
	for _, record := range capture.snapshot() {
		if record.Action() == string(config.ObservabilityV8ManagedMCPInventoryAction) {
			t.Fatal("pre-watcher empty tool collection reached managed inventory")
		}
	}
	tools.recordObserved("codex", "notes", "read", time.Now())
	rows, partial = tools.components([]endpointInventoryComponent{parent}, false)
	if len(rows) != 1 || !partial {
		t.Fatalf("observed-only snapshot rows=%+v partial=%v", rows, partial)
	}
	tools.recordAdvertised("codex", "notes", nil, time.Now())
	rows, partial = tools.components([]endpointInventoryComponent{parent}, false)
	if len(rows) != 1 || partial {
		t.Fatalf("completed empty listing rows=%+v partial=%v", rows, partial)
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
	if len(rows) != 0 || !partial {
		t.Fatalf("old tool evidence followed new server ID: %+v partial=%v", rows, partial)
	}
	tools.recordAdvertised("codex", "notes", []string{"search"}, time.Now())
	rows, partial = tools.components([]endpointInventoryComponent{parent}, false)
	if len(rows) != 1 || partial || rows[0].mcpToolParentID != parent.id {
		t.Fatalf("new server evidence=%+v partial=%v", rows, partial)
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
