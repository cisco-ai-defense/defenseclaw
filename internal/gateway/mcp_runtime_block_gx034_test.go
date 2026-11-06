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
	if err := store.SetRuntimeDisableForConnector(watcher.AccountMCPJournalType, key, failed.Connector, key, "fresh admission failed"); err != nil {
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
	// A new snapshot does not adopt the old row's decision; the account's own
	// admission records one, with its provenance.
	if got := call(); hasFinding(got.Findings, "MCP-BLOCK") {
		t.Fatalf("a new snapshot adopted the literal old row: %+v", got)
	}
	if err := store.SetRuntimeDisableForConnector(watcher.AccountMCPJournalType, key, "claudecode", key, "fresh admission failed"); err != nil {
		t.Fatal(err)
	}
	if got := call(); !hasFinding(got.Findings, "MCP-BLOCK") {
		t.Fatalf("versioned account action was lost: %+v", got)
	}
}

// Admission records install=block, then the runtime disable with its source
// path and provenance in one statement, before it stores the scan snapshot.
// The decision holds in that interval, when the snapshot write fails, and
// while a snapshot an earlier release stored under the same key (a server
// literally named like it) remains; the ordinary account stays allowed.
func TestGAP0034FreshFailedAccountActionBlocksBeforeSnapshot(t *testing.T) {
	for _, preIdentitySnapshot := range []bool{false, true} {
		api, store := toolPolicyAPI(t, "action")
		api.scannerCfg.Guardrail.RulePack = "default"
		api.scannerCfg.AssetPolicy = config.DefaultAssetPolicy()
		home := filepath.Join(t.TempDir(), "account")
		server := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home}
		key := watcher.MCPEventPath(server)
		if preIdentitySnapshot {
			hashes, err := json.Marshal(map[string]string{"mcp.servers." + key: "oldhash"})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.SetTargetSnapshot("mcp", key, "oldhash", "{}", string(hashes), "[]", "", "fingerprint"); err != nil {
				t.Fatal(err)
			}
		}
		reason := "scanner failure (fail-closed): test"
		if err := store.SetActionFieldForConnector(watcher.AccountMCPJournalType, key, "claudecode", "install", "block", reason); err != nil {
			t.Fatal(err)
		}
		if err := store.SetRuntimeDisableForConnector(watcher.AccountMCPJournalType, key, "claudecode", key, reason); err != nil {
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
			t.Fatalf("pre-identity snapshot %v: failed=%s/%v ordinary=%s/%v", preIdentitySnapshot, failed.Action, failed.Findings,
				ordinary.Action, ordinary.Findings)
		}
	}
}

// An earlier release's automatic runtime disable under a key an old server
// literally spells stays inert for the account that key names, with or
// without the old server's snapshot (default rule pack, action mode).
func TestGAP0034OldLiteralActionLeavesOrdinaryAccountAllowed(t *testing.T) {
	for _, oldSnapshot := range []bool{false, true} {
		api, store := toolPolicyAPI(t, "action")
		api.scannerCfg.Guardrail.RulePack = "default"
		api.scannerCfg.AssetPolicy = config.DefaultAssetPolicy()
		home := filepath.Join(t.TempDir(), "ordinary-account")
		key := watcher.MCPEventPath(config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home})
		if oldSnapshot {
			hashes, err := json.Marshal(map[string]string{"mcp.servers." + key: "oldhash"})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.SetTargetSnapshot("mcp", key, "oldhash", "{}", string(hashes), "[]", "", "fingerprint"); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.SetActionFieldForConnector("mcp", key, "claudecode", "runtime", "disable", "old literal server failed scan"); err != nil {
			t.Fatal(err)
		}
		if err := store.SetSourcePathForConnector("mcp", key, "claudecode", key); err != nil {
			t.Fatal(err)
		}
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
		got := api.inspectToolPolicyCtx(ctx, &ToolInspectRequest{Tool: "mcp__notes__ping", Args: json.RawMessage(`{}`),
			Direction: "tool_call", Connector: "claudecode"})
		if hasFinding(got.Findings, "MCP-BLOCK") || got.Action == "block" {
			t.Fatalf("old snapshot %v: old literal decision crossed to ordinary account: action=%s findings=%v",
				oldSnapshot, got.Action, got.Findings)
		}
	}
}

// An account-less server may be named exactly like an enrolled account
// server key (its versioned event path). Its failed scan is its own
// decision: the failed account keeps its block before the account snapshot
// exists, the literal server is refused for its own row, and an ordinary
// account stays allowed (default rule pack).
func TestGAP0034LiteralServerNamedLikeAccountKeyCannotUndoFailedAccount(t *testing.T) {
	api, store := toolPolicyAPI(t, "action")
	api.scannerCfg.Guardrail.RulePack = "default"
	api.scannerCfg.AssetPolicy = config.DefaultAssetPolicy()
	home := filepath.Join(t.TempDir(), "account")
	account := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home}
	key := watcher.MCPEventPath(account)
	reason := "scanner failure (fail-closed): test"
	if err := store.SetActionFieldForConnector(watcher.MCPJournalType(account), key, "claudecode", "install", "block", reason); err != nil {
		t.Fatal(err)
	}
	if err := store.SetRuntimeDisableForConnector(watcher.MCPJournalType(account), key, "claudecode", key, reason); err != nil {
		t.Fatal(err)
	}
	call := func(server, callerHome string) *ToolInspectVerdict {
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: callerHome})
		return api.inspectToolPolicyCtx(ctx, &ToolInspectRequest{Tool: "mcp__" + server + "__ping", Args: json.RawMessage(`{}`),
			Direction: "tool_call", Connector: "claudecode"})
	}
	ordinaryHome := filepath.Join(t.TempDir(), "ordinary")
	check := func(stage string, literalBlocked bool) {
		t.Helper()
		if got := call("notes", home); !hasFinding(got.Findings, "MCP-BLOCK") {
			t.Fatalf("%s: the failed account was allowed: %s/%v", stage, got.Action, got.Findings)
		}
		if got := call("notes", ordinaryHome); hasFinding(got.Findings, "MCP-BLOCK") {
			t.Fatalf("%s: an ordinary account was refused: %s/%v", stage, got.Action, got.Findings)
		}
		if got := call(key, ordinaryHome); hasFinding(got.Findings, "MCP-BLOCK") != literalBlocked {
			t.Fatalf("%s: literal server blocked=%v, want %v: %s/%v", stage, hasFinding(got.Findings, "MCP-BLOCK"), literalBlocked, got.Action, got.Findings)
		}
	}
	check("before the literal server is scanned", false)

	// The scan of the literal server failed: its own row, its own path.
	literal := config.MCPServerEntry{Name: key, Connector: "claudecode"}
	literalPath := watcher.MCPEventPath(literal)
	if err := store.SetActionFieldForConnector(watcher.MCPJournalType(literal), watcher.MCPJournalName(literal), "claudecode", "install", "block", reason); err != nil {
		t.Fatal(err)
	}
	if err := store.SetRuntimeDisableForConnector(watcher.MCPJournalType(literal), watcher.MCPJournalName(literal), "claudecode", literalPath, reason); err != nil {
		t.Fatal(err)
	}
	check("after the failed scan of the literal server", true)
}
