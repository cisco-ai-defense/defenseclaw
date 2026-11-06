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
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

func TestGAP0034PreIdentityAccountActionWaitsForFreshAdmission(t *testing.T) {
	api, store := toolPolicyAPI(t, "action")
	api.scannerCfg.Guardrail.RulePack = "default"
	api.scannerCfg.AssetPolicy = config.DefaultAssetPolicy()
	home := filepath.Join(t.TempDir(), "alice")
	project := t.TempDir()
	failed := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home + "@claudecode#" + project}
	oldPath := failed.Name + "@" + failed.Connector + ":" + failed.Home
	if err := store.SetTargetSnapshot("mcp", oldPath, "hash", "{}", `{"mcp.servers.notes":"hash"}`, "[]", "", "fingerprint|mcp-scan-failed"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionFieldForConnector("mcp", oldPath, failed.Connector, "runtime", "disable", "previous scan"); err != nil {
		t.Fatal(err)
	}
	call := func(home, cwd string) *ToolInspectVerdict {
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
		return api.inspectToolPolicyCtx(ctx, &ToolInspectRequest{Tool: "mcp__notes__ping", Args: json.RawMessage(`{}`),
			Direction: "tool_call", Connector: "claudecode", callerCWD: cwd})
	}
	protected := call(failed.Home, t.TempDir())
	ordinary := call(home, project)
	if hasFinding(protected.Findings, "MCP-BLOCK") || hasFinding(ordinary.Findings, "MCP-BLOCK") {
		t.Fatalf("old action was assigned to an account: protected=%+v ordinary=%+v", protected, ordinary)
	}
	key := watcher.MCPEventPath(failed)
	identity, err := json.Marshal(map[string]string{"name": failed.Name, "connector": failed.Connector,
		"home": failed.Home, "project": ""})
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := json.Marshal(map[string]string{"mcp.servers.notes": "hash", "mcp.snapshot.identity.v1": string(identity)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTargetSnapshot("mcp", key, "hash", "{}", string(hashes), "[]", "", "fingerprint|mcp-scan-failed"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionFieldForConnector("mcp", key, failed.Connector, "runtime", "disable", "fresh admission failed"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSourcePathForConnector("mcp", key, failed.Connector, key); err != nil {
		t.Fatal(err)
	}
	protected = call(failed.Home, t.TempDir())
	ordinary = call(home, project)
	if !hasFinding(protected.Findings, "MCP-BLOCK") || hasFinding(ordinary.Findings, "MCP-BLOCK") {
		t.Fatalf("new action crossed accounts: protected=%+v ordinary=%+v", protected, ordinary)
	}
}

func TestGAP0034PreIdentityBareAdmissionActionIsIgnored(t *testing.T) {
	api, store := toolPolicyAPI(t, "action")
	pe := enforce.NewPolicyEngine(store).WithConfig(func() *config.Config { return api.scannerCfg })
	if err := store.SetActionFieldForConnector("mcp", "notes", "claudecode", "runtime", "disable", "previous scan"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSourcePathForConnector("mcp", "notes", "claudecode", "notes@claudecode"); err != nil {
		t.Fatal(err)
	}
	if deny, _, _ := mcpServerRuntimeBlock(pe, "mcp__notes__ping", "claudecode", ""); deny {
		t.Fatal("old automatic journal row was served")
	}
	current := watcher.MCPEventPath(config.MCPServerEntry{Name: "notes", Connector: "claudecode"})
	if err := store.SetSourcePathForConnector("mcp", "notes", "claudecode", current); err != nil {
		t.Fatal(err)
	}
	if deny, _, _ := mcpServerRuntimeBlock(pe, "mcp__notes__ping", "claudecode", ""); !deny {
		t.Fatal("current automatic journal row was lost")
	}
	if err := store.SetActionFieldForConnector("mcp", "manual", "claudecode", "runtime", "disable", "operator action"); err != nil {
		t.Fatal(err)
	}
	if deny, _, _ := mcpServerRuntimeBlock(pe, "mcp__manual__ping", "claudecode", ""); deny {
		t.Fatal("source-free old journal row was served")
	}
	denyAsset(api.scannerCfg, "mcp", "manual", "claudecode", "operator action")
	if deny, _, _ := mcpServerRuntimeBlock(pe, "mcp__manual__ping", "claudecode", ""); !deny {
		t.Fatal("explicit operator policy was lost")
	}
}

func TestGAP0034LiteralVersionedSpellingDoesNotBecomeAccountAction(t *testing.T) {
	api, store := toolPolicyAPI(t, "action")
	home := t.TempDir()
	key := watcher.MCPEventPath(config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home})
	if err := store.SetActionFieldForConnector("mcp", key, "claudecode", "runtime", "disable", "old literal server"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSourcePathForConnector("mcp", key, "claudecode", key); err != nil {
		t.Fatal(err)
	}
	// The earlier release stored the literal server's baseline under its name.
	if err := store.SetTargetSnapshot("mcp", key, "hash", "{}", `{"mcp.servers.`+key+`":"hash"}`, "[]", "", "fingerprint"); err != nil {
		t.Fatal(err)
	}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
	call := func() *ToolInspectVerdict {
		return api.inspectToolPolicyCtx(ctx, &ToolInspectRequest{Tool: "mcp__notes__ping", Args: json.RawMessage(`{}`),
			Direction: "tool_call", Connector: "claudecode"})
	}
	if got := call(); hasFinding(got.Findings, "MCP-BLOCK") {
		t.Fatalf("literal old row was assigned to a versioned account: %+v", got)
	}
	identity, err := json.Marshal(map[string]string{"name": "notes", "connector": "claudecode", "home": home, "project": ""})
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := json.Marshal(map[string]string{"mcp.servers.notes": "hash", "mcp.snapshot.identity.v1": string(identity)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTargetSnapshot("mcp", key, "hash", "{}", string(hashes), "[]", "", "fingerprint"); err != nil {
		t.Fatal(err)
	}
	if got := call(); !hasFinding(got.Findings, "MCP-BLOCK") {
		t.Fatalf("versioned account action was lost: %+v", got)
	}
}

// Admission writes install=block, the versioned source path and
// runtime=disable before it stores the scan snapshot; the decision holds in
// that interval and when the snapshot write fails.
func TestGAP0034FreshFailedAccountActionBlocksBeforeSnapshot(t *testing.T) {
	api, store := toolPolicyAPI(t, "action")
	api.scannerCfg.Guardrail.RulePack = "default"
	api.scannerCfg.AssetPolicy = config.DefaultAssetPolicy()
	home := filepath.Join(t.TempDir(), "account")
	server := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home}
	key := watcher.MCPEventPath(server)
	reason := "scanner failure (fail-closed): test"
	if err := store.SetActionFieldForConnector("mcp", key, "claudecode", "install", "block", reason); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSourcePathForConnector("mcp", key, "claudecode", key); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionFieldForConnector("mcp", key, "claudecode", "runtime", "disable", reason); err != nil {
		t.Fatal(err)
	}
	call := func(callerHome string) *ToolInspectVerdict {
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: callerHome})
		return api.inspectToolPolicyCtx(ctx, &ToolInspectRequest{Tool: "mcp__notes__ping", Args: json.RawMessage(`{}`),
			Direction: "tool_call", Connector: "claudecode"})
	}
	failed := call(home)
	ordinary := call(filepath.Join(t.TempDir(), "ordinary"))
	if !hasFinding(failed.Findings, "MCP-BLOCK") || hasFinding(ordinary.Findings, "MCP-BLOCK") {
		t.Fatalf("decision before its snapshot: failed=%s/%v ordinary=%s/%v", failed.Action, failed.Findings,
			ordinary.Action, ordinary.Findings)
	}
}
