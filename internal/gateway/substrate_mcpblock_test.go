// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestSubstrateMCPServerBlocked (B3.3 S4b, T6 ruling 2): the MCP block
// lists apply to NAME when a bridge opens. A blocked server is refused with
// 403 mcp_server_blocked and a substrate.mcp.blocked audit row, and the
// relay is never dialed; a block of another server does not leak to it.
func TestSubstrateMCPServerBlocked(t *testing.T) {
	b := newTixgBridge(t, false)
	store, _ := testStoreAndLogger(t)
	b.fixture.api.store = store
	cfg := b.fixture.api.scannerCfg
	denyAsset(cfg, "mcp", "jira", "", "another server")
	laptop, _, resp := b.open(t)
	if laptop == nil {
		t.Fatalf("a block of jira refused notes: %+v", resp)
	}
	_ = laptop.Close()

	denyAsset(cfg, "mcp", "notes", "", "notes is not allowed here")
	b.mu.Lock()
	b.audits, b.scopes = nil, nil
	b.mu.Unlock()
	laptop, _, resp = b.open(t)
	if laptop != nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked notes: laptop %v resp %+v, want 403", laptop != nil, resp)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "mcp_server_blocked") {
		t.Fatalf("refusal body %q, want mcp_server_blocked", body)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.scopes) != 0 {
		t.Fatalf("the relay was dialed for a blocked server: %v", b.scopes)
	}
	var row map[string]any
	for _, a := range b.audits {
		if a["event"] == "substrate.mcp.blocked" {
			row = a
		}
	}
	if row == nil || row["mcp"] != "notes" || row["reason"] != "mcp_server_blocked" || row["actor"] != b.reg.Name ||
		!strings.Contains(row["detail"].(string), `"notes" is blocked`) {
		t.Fatalf("audit rows %v, want one substrate.mcp.blocked for notes", b.audits)
	}
}
