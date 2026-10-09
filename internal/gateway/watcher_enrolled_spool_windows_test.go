// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Oversized state must never leave an enrolled user's MCP calls unguarded.
func TestOversizedClaudeMCPSpoolFailsClosed(t *testing.T) {
	originalTrust := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = originalTrust })

	root := t.TempDir()
	home := filepath.Join(root, "alice")
	project := filepath.Join(home, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	state, err := json.Marshal(map[string]any{
		"projects": map[string]any{
			project: map[string]any{
				"mcpServers": map[string]any{
					"local-server": map[string]any{"command": strings.Repeat("x", 4<<20)},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), state, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{DataDir: filepath.Join(root, "data")}
	dir := enterprisehooks.ClaudeMCPSpoolDir(managed.HookGuardianAuthorizationDir(cfg.DataDir))
	const sid = "S-1-5-21-1-1001"
	manifest := enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{
		{SID: sid, User: "alice", UserHome: home, Connector: "claudecode"},
	}}
	if err := enterprisehooks.WriteWindowsClaudeMCPSpool(dir, manifest, nil, t.Logf); err != nil {
		t.Fatal(err)
	}
	servers, unreadable := enrolledClaudeMCPServers(cfg, sid)
	if len(servers) != 0 || unreadable == nil || unreadable.Path != filepath.Join(home, ".claude.json") {
		t.Fatalf("oversized state: servers=%d unreadable=%+v", len(servers), unreadable)
	}

	// A preexisting oversized or damaged spool must also fail closed.
	if err := os.WriteFile(filepath.Join(dir, sid+".json"), state, 0o600); err != nil {
		t.Fatal(err)
	}
	servers, unreadable = enrolledClaudeMCPServers(cfg, sid)
	if len(servers) != 0 || unreadable == nil || unreadable.Reason == "" {
		t.Fatalf("oversized spool: servers=%d unreadable=%+v", len(servers), unreadable)
	}
}
