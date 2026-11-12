// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// GAP-0686: a managed Windows gateway reads nothing in a profile, so the
// Codex servers of an enrolled account (config.toml under ~/.codex or the
// account CODEX_HOME) are known only from the record the hook enumerator
// publishes. Without one, no Codex server of an enrolled account reached
// install admission and none of its tool calls was refused. Each account
// has its own record and its own admission target; a record that says the
// file could not be read, or a missing record, refuses the Codex tool calls
// of that account only.
func TestGAP0686EnrolledCodexMCPServersAreAdmittedPerAccount(t *testing.T) {
	restore := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() {
		validateManagedGuardianAuthorization = restore
		publishMCPStatesUnreadable(nil)
	})
	root := t.TempDir()
	users := []string{"alice", "bob", "carol", "dave"}
	homes := map[string]string{}
	sids := map[string]string{}
	var targets []map[string]any
	for index, user := range users {
		homes[user] = filepath.Join(root, user)
		sids[user] = "S-1-5-21-1-" + strconv.Itoa(1001+index)
		targets = append(targets, map[string]any{"user": user, "user_home": homes[user], "sid": sids[user], "connector": "codex", "ok": true})
	}
	dataDir := filepath.Join(root, "data")
	raw, _ := json.Marshal(map[string]any{
		"version": 1, "updated_at": time.Now().UTC().Format(time.RFC3339), "ok": true,
		"target_count": len(targets), "success_count": len(targets), "failure_count": 0, "protected_targets": targets,
	})
	path := managed.HookGuardianAuthorizationPath(dataDir)
	// The folder name is the published one, written out so the test reads
	// the same record on every build.
	spoolDir := filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), "codex-mcp")
	for _, dir := range []string{filepath.Dir(path), spoolDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(user string, data []byte, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(spoolDir, sids[user]+".json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// alice and bob each add a loopback server under the same name.
	for _, user := range []string{"alice", "bob"} {
		source := filepath.Join(homes[user], ".codex", "config.toml")
		data, err := enterprisehooks.MarshalClaudeMCPSpoolRecord(sids[user], []config.MCPServerEntry{
			{Name: "r109loop", Command: "node", Args: []string{filepath.Join(homes[user], "server.js")}, Source: source, SourceScope: "user"},
			{Name: "openaiDeveloperDocs", URL: "https://developers.openai.com/mcp", Source: source, SourceScope: "user", Bundled: true},
		})
		write(user, data, err)
	}
	carolState := filepath.Join(homes["carol"], ".codex", "config.toml")
	data, err := enterprisehooks.MarshalClaudeMCPSpoolUnreadable(sids["carol"], enterprisehooks.ClaudeStateUnreadable{
		User: "carol", Home: homes["carol"], Path: carolState, Reason: "access denied",
	})
	write("carol", data, err)
	// dave is enrolled but has no record: its publication failed.

	set := resolveEnrolledWatchSet(&config.Config{DataDir: dataDir}, connector.NewDefaultRegistry(),
		config.GatewayWatcherConfig{Enabled: true}, filepath.Join(root, "service"))
	servers, _ := set.live.list()
	got := map[string]config.MCPServerEntry{}
	for _, server := range servers {
		if server.Bundled {
			t.Fatalf("a built-in Codex server is an admission target: %+v", server)
		}
		if server.Connector == "codex" {
			got[server.Home] = server
		}
	}
	for _, user := range []string{"alice", "bob"} {
		server, ok := got[homes[user]]
		if !ok || server.Name != "r109loop" || server.RunAsSID != sids[user] {
			t.Fatalf("%s: enrolled Codex servers %+v; want r109loop admitted as %s", user, servers, sids[user])
		}
	}
	if watcher.MCPEventPath(got[homes["alice"]]) == watcher.MCPEventPath(got[homes["bob"]]) {
		t.Fatal("two accounts with the same Codex server name share one admission target")
	}

	publishMCPStatesUnreadable(set.mcpUnreadable)
	api := &APIServer{scannerCfg: &config.Config{}}
	call := codexHookRequest{HookEventName: "PreToolUse", ToolName: "mcp__r109loop__ping", ToolInput: map[string]interface{}{}}
	as := func(user string, uid int) context.Context {
		return withManagedHookPeer(context.Background(), managedHookPeer{UID: uid, Home: homes[user]})
	}
	decision, refused := api.codexMCPAssetDecision(as("carol", 1003), call)
	if !refused || decision.Action != "block" || decision.Source != "codex-mcp-unreadable" ||
		!strings.Contains(decision.Reason, "of carol are blocked") || !strings.Contains(decision.Reason, carolState) {
		t.Fatalf("carol: refused=%v decision %+v; want the call refused naming %s", refused, decision, carolState)
	}
	decision, refused = api.codexMCPAssetDecision(as("dave", 1004), call)
	if !refused || decision.Action != "block" || !strings.Contains(decision.Reason, filepath.Join(spoolDir, sids["dave"]+".json")) {
		t.Fatalf("dave: refused=%v decision %+v; want the call refused for the missing record", refused, decision)
	}
	for user, uid := range map[string]int{"alice": 1001, "bob": 1002} {
		if decision, _ := api.codexMCPAssetDecision(as(user, uid), call); decision.Action == "block" {
			t.Fatalf("%s has a readable record; the ordinary call was refused: %+v", user, decision)
		}
	}
}

// GAP-0686: the Codex hook reads the enrolled users servers again before it
// decides a call about to run, as the Claude Code hook does (GAP-0216): a
// server added or changed since the last publication waits for its scan,
// and a refresh that fails refuses the call. A current, admitted server and
// a tool result are not refused.
func TestGAP0686CodexHookDecidesOnTheRefreshedDefinition(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	// Enrolled users run the strict profile, where a server still being
	// scanned is refused; the balanced default lets the call run.
	cfg.Guardrail.RulePack = "strict"
	api := &APIServer{scannerCfg: cfg}
	refreshed, refreshErr := 0, error(nil)
	api.SetMCPRefreshBeforeCall(func(_ context.Context, connector string) error {
		if connector != "codex" {
			t.Errorf("refreshed for %q", connector)
		}
		refreshed++
		return refreshErr
	})
	api.SetMCPAdmissionPending(func(_, server, _, _ string) (string, bool) { return server, refreshed > 0 })
	call := codexHookRequest{HookEventName: "PreToolUse", ToolName: "mcp__r109loop__ping",
		ToolInput: map[string]interface{}{}, CWD: filepath.Join(t.TempDir(), "proj")}
	if resp := api.evaluateCodexHook(context.Background(), call); resp.Action != "block" || refreshed != 1 {
		t.Fatalf("added server: %+v after %d refreshes, want a block after one", resp, refreshed)
	}
	cfg.Guardrail.RulePack = ""
	refreshed = 1
	if resp := api.evaluateCodexHook(context.Background(), call); resp.Action == "block" {
		t.Fatalf("balanced default with a scan pending: %+v, want the call allowed", resp)
	}
	cfg.Guardrail.RulePack = "strict"
	api.SetMCPAdmissionPending(func(_, server, _, _ string) (string, bool) { return server, false })
	refreshErr = errors.New("the hook enumerator did not answer")
	if resp := api.evaluateCodexHook(context.Background(), call); resp.Action != "block" {
		t.Fatalf("failed refresh: %+v, want the call refused", resp)
	}
	refreshErr = nil
	if resp := api.evaluateCodexHook(context.Background(), call); resp.Action == "block" {
		t.Fatalf("current, admitted server: %+v, want it allowed", resp)
	}
	result := call
	result.HookEventName = "PostToolUse"
	before := refreshed
	api.evaluateCodexHook(context.Background(), result)
	if refreshed != before {
		t.Fatal("a tool result refreshed the servers")
	}
}
