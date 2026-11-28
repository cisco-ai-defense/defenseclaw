// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// Outside Secure Client the endpoint inventory is sent with ai_discovery on,
// so the MCP tool inventory must be kept there too: the listings of the
// watcher's MCP scans, the tools the agent calls, and their durable state.
// Before GAP-1834 only a managed machine kept them, and a per-user install
// sent its tool collections complete and empty.
func TestMCPToolInventoryIsKeptOutsideSecureClientWithAIDiscoveryOn(t *testing.T) {
	withManagedEnterprise(t, false)
	parent := endpointInventoryComponent{id: "parent", itemName: "notes", agentConnector: "claudecode"}
	for _, on := range []bool{true, false} {
		cfg := &config.Config{}
		cfg.AIDiscovery.Enabled = on

		// The listing of an MCP admission scan.
		s := &Sidecar{cfg: cfg}
		s.mcpTools.refreshParents([]endpointInventoryComponent{parent})
		s.observeMCPToolListing(context.Background(), "claudecode", "notes",
			&scanner.ScanResult{MCPAdvertisedTools: []string{"search"}, Timestamp: time.Now()}, nil)
		if rows, _ := s.mcpTools.components([]endpointInventoryComponent{parent}, false, "advertised"); (len(rows) == 1) != on {
			t.Fatalf("ai_discovery %v: advertised tool rows = %+v", on, rows)
		}

		// A tool the agent called, seen by an authenticated hook.
		var tools mcpToolInventory
		tools.refreshParents([]endpointInventoryComponent{parent})
		api := &APIServer{mcpTools: &tools, scannerCfg: cfg}
		req := agentHookRequest{
			ConnectorName: "claudecode", ConnectorInstanceID: syntheticToolResourceConnectorID,
			ToolName: "mcp__notes__search", Payload: map[string]interface{}{"mcp_server_name": "notes"},
		}
		ctx := withAuthenticatedToolResource(withAuthenticatedHookConnector(context.Background(), "claudecode"), req,
			[]byte(`{"tool_name":"mcp__notes__search","mcp_server_name":"notes"}`))
		api.recordObservedMCPToolIfInventoryOn(ctx, req)
		if rows, _ := tools.components([]endpointInventoryComponent{parent}, false, "observed"); (len(rows) == 1) != on {
			t.Fatalf("ai_discovery %v: observed tool rows = %+v", on, rows)
		}

		// The durable state: read at start with the inventory on, and left
		// for the first inventory cycle with it off.
		var durable mcpToolInventory
		readErr := errors.New("tool state read")
		err := durable.attachStore(context.Background(), cfg, &testMCPObservedToolStore{listErr: readErr})
		if durable.store == nil {
			t.Fatalf("ai_discovery %v: the tool store is not attached", on)
		}
		if on != errors.Is(err, readErr) {
			t.Fatalf("ai_discovery %v: start read error = %v", on, err)
		}
		if !durable.observedRestoreIncomplete || !durable.advertisedRestoreIncomplete {
			t.Fatalf("ai_discovery %v: unread tool state is not marked for the next inventory cycle", on)
		}
	}
}
