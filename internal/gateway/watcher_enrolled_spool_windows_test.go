// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// An unreadable enrolled user's project inventory must not leave MCP calls unguarded.
func TestOversizedClaudeMCPSpoolFailsClosed(t *testing.T) {
	originalTrust := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = originalTrust })

	root := t.TempDir()
	cfg := &config.Config{DataDir: filepath.Join(root, "data")}
	dir := enterprisehooks.ClaudeMCPSpoolDir(managed.HookGuardianAuthorizationDir(cfg.DataDir))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	const sid = "S-1-5-21-1-1001"
	projectFile := filepath.Join(root, "alice", "project", ".mcp.json")
	record, err := enterprisehooks.MarshalClaudeMCPSpoolUnreadable(sid, enterprisehooks.ClaudeStateUnreadable{
		User: "alice", Home: filepath.Join(root, "alice"), Path: projectFile,
		Reason: "project MCP file exceeds the size limit",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sid+".json"), record, 0o600); err != nil {
		t.Fatal(err)
	}
	servers, unreadable := enrolledClaudeMCPServers(cfg, sid)
	if len(servers) != 0 || unreadable == nil || unreadable.Path != projectFile {
		t.Fatalf("oversized project: servers=%d unreadable=%+v", len(servers), unreadable)
	}

	// A preexisting oversized or damaged spool must also fail closed.
	if err := os.WriteFile(filepath.Join(dir, sid+".json"), []byte(strings.Repeat("x", 4<<20)), 0o600); err != nil {
		t.Fatal(err)
	}
	servers, unreadable = enrolledClaudeMCPServers(cfg, sid)
	if len(servers) != 0 || unreadable == nil || unreadable.Reason == "" {
		t.Fatalf("oversized spool: servers=%d unreadable=%+v", len(servers), unreadable)
	}
}

// GAP-1468: the hook guardian protects the .kiro folder of a user enrolled
// for Kiro, so the gateway service cannot read ~/.kiro/settings/mcp.json.
// The enumerator publishes its servers, which reach install admission; a
// user whose record is missing has unknown servers, so that user's Kiro MCP
// tool calls are refused instead of the list being taken as empty.
func TestEnrolledKiroMCPServersReachAdmissionThroughSpool(t *testing.T) {
	originalTrust := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() {
		validateManagedGuardianAuthorization = originalTrust
		publishMCPStatesUnreadable(nil)
	})
	root := t.TempDir()
	alice, bob, dataDir := filepath.Join(root, "alice"), filepath.Join(root, "bob"), filepath.Join(root, "data")
	mcpFile := filepath.Join(alice, ".kiro", "settings", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(mcpFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mcpFile, []byte(`{"mcpServers":{"kiro-notes":{"command":"notes-server"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	const aliceSID, bobSID = "S-1-5-21-1-1001", "S-1-5-21-1-1002"
	record, _ := json.Marshal(map[string]any{
		"version": 1, "updated_at": time.Now().UTC().Format(time.RFC3339), "ok": true,
		"target_count": 2, "success_count": 2, "failure_count": 0,
		"protected_targets": []map[string]any{
			{"user": "alice", "user_home": alice, "sid": aliceSID, "connector": "kiro", "ok": true},
			{"user": "bob", "user_home": bob, "sid": bobSID, "connector": "kiro", "ok": true},
		},
	})
	authorization := managed.HookGuardianAuthorizationPath(dataDir)
	if err := os.MkdirAll(filepath.Dir(authorization), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authorization, record, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := enterprisehooks.KiroMCPSpoolDir(managed.HookGuardianAuthorizationDir(dataDir))
	manifest := enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{
		{SID: aliceSID, User: "alice", UserHome: alice, Connector: "kiro"},
		{SID: bobSID, User: "bob", UserHome: bob, Connector: "kiro"},
	}}
	if err := enterprisehooks.WriteWindowsKiroMCPSpool(dir, manifest, nil, t.Logf); err != nil {
		t.Fatal(err)
	}
	// The gateway cannot read alice's file, and bob's publication failed.
	if err := os.Remove(mcpFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, bobSID+".json")); err != nil {
		t.Fatal(err)
	}

	set := resolveEnrolledWatchSet(&config.Config{DataDir: dataDir}, connector.NewDefaultRegistry(),
		config.GatewayWatcherConfig{Enabled: true}, filepath.Join(root, "service"))
	servers, _ := set.live.list()
	if len(servers) != 1 || servers[0].Name != "kiro-notes" || servers[0].Connector != "kiro" || servers[0].Home != alice {
		t.Fatalf("enrolled Kiro MCP servers = %+v; want alice's kiro-notes", servers)
	}
	if _, unknown := set.mcpUnreadable[mcpUnreadableKey("kiro", bob)]; !unknown {
		t.Fatalf("bob's missing Kiro record was not recorded: %v", set.mcpUnreadable)
	}
	publishMCPStatesUnreadable(set.mcpUnreadable)
	api := &APIServer{scannerCfg: &config.Config{}}
	req := agentHookRequest{ConnectorName: "kiro", HookEventName: "PreToolUse", ToolName: "mcp__notes__read"}
	decision, refused := api.agentHookMCPAssetDecision(withManagedHookPeer(context.Background(), managedHookPeer{UID: 1002, Home: bob}), req)
	if !refused || decision.Action != "block" || !strings.Contains(decision.Reason, "Kiro MCP servers of") {
		t.Fatalf("bob: refused=%v decision %+v; want his Kiro MCP tool call refused", refused, decision)
	}
}
