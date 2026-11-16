// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// In Git Bash on Windows "/" is the Git install folder, which holds no home,
// keys or DefenseClaw state: a link to it and a write inside it is an
// ordinary write. A managed Windows gateway (the service gateway) opens the
// profile and reads these calls as the per-user gateway does. A link to the home, the SSH folder
// or a drive root followed by a write to the keys file blocks
// (rel-1-0-6:GAP-0120).
func TestGitBashRootLinkWriteBlocksOnlyWhenItReachesTheKeys(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	slashed := filepath.ToSlash(home)
	msysHome := "/" + strings.ToLower(slashed[:1]) + slashed[2:]
	for _, row := range []struct {
		name, command string
		block         bool
	}{
		{"link to the Git root then touch", `ln -s / r; bash -c "cd r && touch x"`, false},
		{"link to the Git root then append", `ln -s / r; bash -c "cd r && echo k >> home/x"`, false},
		{"link to the home then keys", `ln -s ~ r; bash -c "cd r && echo k >> .ssh/authorized_keys"`, true},
		{"link to the drive home then keys", `ln -s ` + msysHome + ` r; bash -c "cd r && echo k >> .ssh/authorized_keys"`, true},
		{"link to the SSH folder then keys", `ln -s ~/.ssh r; bash -c "cd r && echo k >> authorized_keys"`, true},
		{"link to the drive root then keys", `ln -s /c r; bash -c "cd r && echo k >> ` + strings.TrimPrefix(slashed[2:], "/") + `/.ssh/authorized_keys"`, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			if row.name == "link to the drive root then keys" && !strings.EqualFold(slashed[:1], "c") {
				t.Skip("home is not on drive C")
			}
			payload := mustJSON(t, map[string]any{"session_id": "root-link", "hook_event_name": "PreToolUse",
				"tool_name": "Bash", "cwd": project, "tool_input": map[string]string{"command": row.command}})
			{
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = "claudecode"
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
				req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
				req.Header.Set("Content-Type", "application/json")
				if header := hookpaths.ResolveConnector("claudecode", "", "PreToolUse", payload); header != "" {
					req.Header.Set(hookpaths.Header, header)
				}
				recorder := httptest.NewRecorder()
				api.handleAgentHook("claudecode").ServeHTTP(recorder, req)
				if blocked := strings.HasPrefix(recorder.Body.String(), `{"action":"block"`); blocked != row.block {
					t.Errorf("%q: block=%v, want %v: %.300s", row.command, blocked, row.block, recorder.Body.String())
				}
			}
		})
	}
}
