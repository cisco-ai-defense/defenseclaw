// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestGAP0353WindowsHookRoutes keeps the native Windows hook routes aligned
// with the shared sudoers path owner in both gateway modes.
func TestGAP0353WindowsHookRoutes(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(project, "etc"), 0o700); err != nil {
		t.Fatal(err)
	}
	patch := "*** Begin Patch\n*** Update File: /etc/sudoers\n@@\n a\n+b\n*** End Patch\n"
	rows := []struct {
		name, connector, tool string
		args                  map[string]any
		main, dropin          bool
	}{
		{"Write rooted", "claudecode", "Write", map[string]any{"file_path": "/etc/sudoers", "content": "configured\n"}, true, false},
		{"Write dot", "claudecode", "Write", map[string]any{"file_path": "/etc/./sudoers", "content": "configured\n"}, true, false},
		{"Write double slash", "claudecode", "Write", map[string]any{"file_path": "/etc//sudoers", "content": "configured\n"}, true, false},
		{"Write uppercase", "claudecode", "Write", map[string]any{"file_path": "/ETC/SUDOERS", "content": "configured\n"}, true, false},
		{"Write private", "claudecode", "Write", map[string]any{"file_path": "/private/etc/sudoers", "content": "configured\n"}, true, false},
		{"Edit rooted", "claudecode", "Edit", map[string]any{"file_path": "/etc/sudoers", "old_string": "a", "new_string": "b"}, true, false},
		{"MultiEdit rooted", "claudecode", "MultiEdit", map[string]any{"file_path": "/etc/sudoers", "edits": []any{map[string]any{"old_string": "a", "new_string": "b"}}}, true, false},
		{"Codex redirect", "codex", "Bash", map[string]any{"command": "echo configured > /etc/sudoers"}, true, false},
		{"Codex append", "codex", "Bash", map[string]any{"command": "echo configured >> /etc/sudoers"}, true, false},
		{"Codex patch", "codex", "apply_patch", map[string]any{"command": patch}, true, false},
		{"Write drop-in", "claudecode", "Write", map[string]any{"file_path": "/etc/sudoers.d/lane", "content": "configured\n"}, false, true},
		{"Write project file", "claudecode", "Write", map[string]any{"file_path": filepath.Join(project, "etc", "sudoers"), "content": "configured\n"}, false, false},
		{"Read main", "claudecode", "Read", map[string]any{"file_path": "/etc/sudoers"}, false, false},
		{"Write root neighbor", "claudecode", "Write", map[string]any{"file_path": "/etc/hosts", "content": "configured\n"}, false, false},
		{"Codex read", "codex", "Bash", map[string]any{"command": "cat /etc/sudoers"}, false, false},
	}
	for _, profile := range []string{"default", "strict"} {
		for _, managed := range []bool{false, true} {
			name := profile + "/" + map[bool]string{false: "per-user", true: "managed"}[managed]
			t.Run(name, func(t *testing.T) {
				packDir := filepath.Join(guardrailPoliciesRoot(t), profile)
				installToolCallCorpusPackDirConnector(t, "claudecode", packDir)
				installToolCallCorpusPackDirConnector(t, "codex", packDir)
				for i, row := range rows {
					t.Run(row.name, func(t *testing.T) {
						raw := mustJSON(t, map[string]any{
							"session_id": "gap0353", "hook_event_name": "PreToolUse", "cwd": project,
							"permission_mode": "default", "tool_name": row.tool,
							"tool_use_id": "toolu_gap0353_" + strconv.Itoa(i), "tool_input": row.args,
						})
						cfg := &config.Config{}
						cfg.Guardrail.Mode = "action"
						cfg.Guardrail.Connector = row.connector
						cfg.Guardrail.RulePackDir = packDir
						api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
						req := httptest.NewRequest(http.MethodPost, "/api/v1/"+row.connector+"/hook", strings.NewReader(string(raw)))
						req.Header.Set("Content-Type", "application/json")
						req.Header.Set(hookpaths.Header, hookpaths.Resolve(raw))
						if row.connector == "codex" {
							setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
						}
						if managed {
							req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
						}
						recorder := httptest.NewRecorder()
						api.handleAgentHook(row.connector).ServeHTTP(recorder, req)
						body := recorder.Body.String()
						if recorder.Code != http.StatusOK {
							t.Fatalf("status %d: %.400s", recorder.Code, body)
						}
						blocked := strings.Contains(body, `"action":"block"`) || strings.Contains(body, `"permissionDecision":"deny"`)
						named := strings.Contains(body, "PATH-ETC-SUDOERS")
						wantNamed := row.main || row.dropin && profile == "strict"
						wantBlocked := wantNamed && profile == "strict"
						if named != wantNamed || blocked != wantBlocked {
							t.Fatalf("named=%t blocked=%t, want named=%t blocked=%t: %.400s", named, blocked, wantNamed, wantBlocked, body)
						}
					})
				}
			})
		}
	}
}
