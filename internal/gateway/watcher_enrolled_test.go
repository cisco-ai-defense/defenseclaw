// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// GAP-0132: a managed gateway watches each enrolled user's connector
// folders (the set a per-user gateway watches) and reads their MCP servers,
// never folders in its own service profile or ones that do not exist yet.
func TestResolveEnrolledWatchSetWatchesEachEnrolledUser(t *testing.T) {
	restore := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = restore })

	root := t.TempDir()
	serviceHome := filepath.Join(root, "service")
	alice := filepath.Join(root, "alice")
	bob := filepath.Join(root, "bob")
	for _, name := range []string{"HOME", "USERPROFILE"} {
		t.Setenv(name, serviceHome)
	}
	for _, name := range []string{"CLAUDE_CONFIG_DIR", "CODEX_HOME", "CLAUDE_CODE_PLUGIN_CACHE_DIR"} {
		t.Setenv(name, "")
	}
	mkdir := func(parts ...string) string {
		dir := filepath.Join(parts...)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	aliceSkills := mkdir(alice, ".claude", "skills")
	alicePlugins := mkdir(alice, ".claude", "plugins", "cache")
	bobSkills := mkdir(bob, ".agents", "skills")
	mkdir(serviceHome, ".claude", "skills")
	mkdir(bob, ".codex")
	if err := os.WriteFile(filepath.Join(bob, ".codex", "config.toml"), []byte("[mcp_servers.p0-mcp]\ncommand = \"p0-server\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// alice has another server under the same name (GAP-0276).
	if err := os.WriteFile(filepath.Join(alice, ".claude.json"), []byte(`{"mcpServers":{"p0-mcp":{"command":"other-server"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	dataDir := mkdir(root, "data")
	record := map[string]any{
		"version": 1, "updated_at": time.Now().UTC().Format(time.RFC3339), "ok": true,
		"target_count": 3, "success_count": 3, "failure_count": 0,
		"protected_targets": []map[string]any{
			{"user": "alice", "user_home": alice, "sid": "S-1-5-21-1-1001", "connector": "amp", "ok": true},
			{"user": "alice", "user_home": alice, "sid": "S-1-5-21-1-1001", "connector": "claudecode", "ok": true},
			{"user": "bob", "user_home": bob, "sid": "S-1-5-21-1-1002", "connector": "codex", "ok": true},
		},
	}
	raw, _ := json.Marshal(record)
	path := managed.HookGuardianAuthorizationPath(dataDir)
	mkdir(filepath.Dir(path))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	// GAP-0424: the gateway service cannot read ~/.claude.json on Windows;
	// the enumerator publishes its servers, local scope included.
	spoolDir := mkdir(enterprisehooks.ClaudeMCPSpoolDir(managed.HookGuardianAuthorizationDir(dataDir)))
	project := filepath.Join(alice, "proj")
	spool, err := enterprisehooks.MarshalClaudeMCPSpoolRecord("S-1-5-21-1-1001", []config.MCPServerEntry{
		{Name: "proj-notes", Command: "notes-server", Project: project, SourceScope: "local"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spoolDir, "S-1-5-21-1-1001.json"), spool, 0o600); err != nil {
		t.Fatal(err)
	}

	wcfg := config.GatewayWatcherConfig{Enabled: true}
	wcfg.Skill.Enabled = true
	wcfg.Plugin.Enabled = true
	set := resolveEnrolledWatchSet(&config.Config{DataDir: dataDir}, connector.NewDefaultRegistry(), wcfg, serviceHome)

	has := func(dirs []string, want string) bool {
		for _, dir := range dirs {
			if dir == want {
				return true
			}
		}
		return false
	}
	if !has(set.skillDirs, aliceSkills) || !has(set.skillDirs, bobSkills) || !has(set.pluginDirs, alicePlugins) {
		t.Fatalf("enrolled dirs skill=%v plugin=%v", set.skillDirs, set.pluginDirs)
	}
	for _, dir := range append(append([]string{}, set.skillDirs...), set.pluginDirs...) {
		if rel, err := filepath.Rel(serviceHome, dir); err == nil && rel != ".." && filepath.IsAbs(dir) && len(rel) > 0 && rel[0] != '.' {
			t.Fatalf("watched a folder in the service profile: %s", dir)
		}
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("watched a folder that does not exist: %s", dir)
		}
	}
	// A transient permission failure must retain the enrolled root.
	rechecked := resolveEnrolledWatchSetWithStat(&config.Config{DataDir: dataDir}, connector.NewDefaultRegistry(), wcfg, serviceHome,
		func(path string) (os.FileInfo, error) {
			if path == aliceSkills {
				return nil, errors.New("permission denied")
			}
			return os.Stat(path)
		})
	if !has(rechecked.skillDirs, aliceSkills) {
		t.Fatalf("stat error dropped enrolled watcher root: %v", rechecked.skillDirs)
	}
	// GAP-0913: once the enumerator grants access the set changes, so the
	// watcher restarts and admits the folder as new.
	if rechecked.dirsKey() == set.dirsKey() || has(rechecked.readable(rechecked.skillDirs), aliceSkills) {
		t.Fatal("a folder that turned readable left the watch set unchanged")
	}
	// Amp also lists ~/.claude/skills; Claude Code owns its layout.
	if set.roots[aliceSkills] != "claudecode" || set.roots[bobSkills] != "codex" {
		t.Fatalf("root connectors = %v", set.roots)
	}
	// Each user's server is its own watcher target, even with the same name.
	servers, _ := set.live.list()
	if len(servers) != 3 || servers[0].Connector != "claudecode" || servers[0].Home != alice ||
		servers[1].Name != "proj-notes" || servers[1].Connector != "claudecode" || servers[1].Home != alice || servers[1].Project != project ||
		servers[2].Connector != "codex" || servers[2].Home != bob ||
		watcher.MCPEventPath(servers[0]) == watcher.MCPEventPath(servers[2]) {
		t.Fatalf("enrolled MCP servers = %+v", servers)
	}
}

// GAP-0829: an enrolled user whose ~/.claude.json the hook enumerator could
// not read has no servers the gateway could admit, so the hook refuses that
// user's Claude Code MCP tool calls and names the file, instead of letting a
// server changed meanwhile run unscanned. Other users are not affected.
func TestUnreadableClaudeStateRefusesThatUsersMCPToolCalls(t *testing.T) {
	restore := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() {
		validateManagedGuardianAuthorization = restore
		publishClaudeStatesUnreadable(nil)
	})
	root := t.TempDir()
	alice, bob, dataDir := filepath.Join(root, "alice"), filepath.Join(root, "bob"), filepath.Join(root, "data")
	record := map[string]any{
		"version": 1, "updated_at": time.Now().UTC().Format(time.RFC3339), "ok": true,
		"target_count": 2, "success_count": 2, "failure_count": 0,
		"protected_targets": []map[string]any{
			{"user": "alice", "user_home": alice, "sid": "S-1-5-21-1-1001", "connector": "claudecode", "ok": true},
			{"user": "bob", "user_home": bob, "sid": "S-1-5-21-1-1002", "connector": "claudecode", "ok": true},
		},
	}
	raw, _ := json.Marshal(record)
	path := managed.HookGuardianAuthorizationPath(dataDir)
	spoolDir := enterprisehooks.ClaudeMCPSpoolDir(managed.HookGuardianAuthorizationDir(dataDir))
	for _, dir := range []string{filepath.Dir(path), spoolDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(alice, ".claude.json")
	marker, err := enterprisehooks.MarshalClaudeMCPSpoolUnreadable("S-1-5-21-1-1001", enterprisehooks.ClaudeStateUnreadable{
		User: "alice", Home: alice, Path: state, Reason: "access denied",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spoolDir, "S-1-5-21-1-1001.json"), marker, 0o600); err != nil {
		t.Fatal(err)
	}
	set := resolveEnrolledWatchSet(&config.Config{DataDir: dataDir}, connector.NewDefaultRegistry(),
		config.GatewayWatcherConfig{Enabled: true}, filepath.Join(root, "service"))
	publishClaudeStatesUnreadable(set.claudeUnreadable)

	api := &APIServer{scannerCfg: &config.Config{}}
	req := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "mcp__notes__read"}
	decision, refused := api.claudeCodeMCPAssetDecision(withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: alice}), req)
	if !refused || decision.Action != "block" || !strings.Contains(decision.Reason, "of alice are blocked") || !strings.Contains(decision.Reason, state) {
		t.Fatalf("alice: refused=%v decision %+v; want the call refused naming %s", refused, decision, state)
	}
	if _, refused := api.claudeCodeMCPAssetDecision(withManagedHookPeer(context.Background(), managedHookPeer{UID: 1002, Home: bob}), req); refused {
		t.Fatal("bob's Claude Code state is readable; his MCP tool call was refused")
	}
}
