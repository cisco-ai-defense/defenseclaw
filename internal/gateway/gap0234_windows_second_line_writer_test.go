// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

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

// rel-1-0-6:GAP-0234 on a native Windows home: a writer on the second line
// of a multi-line command after echo or Write-Output reaches the keys file
// through a quoted pattern (PowerShell expands a cmdlet -Path), so it
// blocks for Claude Code and Codex, per-user and managed, as it does after
// a ; on one line. Benign multi-line commands stay allowed.
func TestWindowsSecondLineWriterAfterTextStatementBlocks(t *testing.T) {
	rows := []struct {
		command string
		block   bool
	}{
		{"echo 'x'\nAdd-Content -Path '.ssh/authorized_k*' -Value 'k'", true},
		{"Write-Output 'x'\r\nSet-Content '.ssh/authorized_k*' 'k'", true},
		{"echo 'x'\r\nRemove-Item '.ssh/authorized_k*'", true},
		{"Write-Output 'x'\ncp a.txt '.ssh/authorized_k*'", true},
		{"echo hi\ngit status", false},
		{"Write-Output 'done'\r\nGet-ChildItem", false},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, row := range rows {
				name := connector + "/" + strings.NewReplacer("\r", `\r`, "\n", `\n`).Replace(row.command)
				if managed {
					name += "/managed"
				}
				t.Run(name, func(t *testing.T) {
					home := t.TempDir()
					keys := filepath.Join(home, ".ssh", "authorized_keys")
					if err := os.MkdirAll(filepath.Dir(keys), 0o700); err != nil {
						t.Fatal(err)
					}
					for file, body := range map[string]string{keys: "k\n", filepath.Join(home, "a.txt"): "x\n"} {
						if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					t.Setenv("HOME", home)
					t.Setenv("USERPROFILE", home)
					payload := mustJSON(t, map[string]any{"session_id": "gap0234", "hook_event_name": "PreToolUse",
						"cwd": home, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_gap0234",
						"tool_input": map[string]any{"command": row.command}})
					cfg := &config.Config{}
					cfg.Guardrail.Mode = "action"
					cfg.Guardrail.Connector = connector
					store, logger := testStoreAndLogger(t)
					api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
					req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set(hookpaths.Header, hookpaths.Resolve(payload))
					if connector == "codex" {
						setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
					}
					if managed {
						req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
					}
					recorder := httptest.NewRecorder()
					api.handleAgentHook(connector).ServeHTTP(recorder, req)
					got := recorder.Body.String()
					blocked := strings.HasPrefix(got, `{"action":"block"`)
					if !blocked && !strings.HasPrefix(got, `{"action":"allow"`) {
						t.Fatalf("status %d body %.300s", recorder.Code, got)
					}
					if blocked != row.block {
						t.Fatalf("%q: block=%v, want %v: %.400s", row.command, blocked, row.block, got)
					}
				})
			}
		}
	}
}
