// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestGAP0034LegacyLiteralHomeActionKeepsAccountsSeparate(t *testing.T) {
	api, store := toolPolicyAPI(t, "action")
	home := filepath.Join(t.TempDir(), "alice")
	project := t.TempDir()
	failed := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home + "@claudecode#" + project}
	oldPath := failed.Name + "@" + failed.Connector + ":" + failed.Home
	identity, err := json.Marshal(map[string]string{"name": failed.Name, "connector": failed.Connector,
		"home": failed.Home, "project": ""})
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := json.Marshal(map[string]string{"mcp.servers.notes": "hash", "mcp.snapshot.identity.v1": string(identity)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTargetSnapshot("mcp", oldPath, "hash", "{}", string(hashes), "[]", "", "fingerprint|mcp-scan-failed"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionFieldForConnector("mcp", oldPath, failed.Connector, "runtime", "disable",
		"scanner failure (fail-closed): previous scan"); err != nil {
		t.Fatal(err)
	}
	call := func(home, cwd string) *ToolInspectVerdict {
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
		return api.inspectToolPolicyCtx(ctx, &ToolInspectRequest{Tool: "mcp__notes__ping", Args: json.RawMessage(`{}`),
			Direction: "tool_call", Connector: "claudecode", callerCWD: cwd})
	}
	protected := call(failed.Home, t.TempDir())
	ordinary := call(home, project)
	if !hasFinding(protected.Findings, "MCP-BLOCK") || hasFinding(ordinary.Findings, "MCP-BLOCK") {
		t.Fatalf("legacy action crossed accounts: protected=%+v ordinary=%+v", protected, ordinary)
	}
}
