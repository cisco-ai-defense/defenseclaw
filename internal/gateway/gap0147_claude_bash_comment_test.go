// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0147 (with GAP-1717): Claude Code's Bash tool runs Git Bash on
// Windows, a POSIX shell, so its call is read with the POSIX grammar: a #
// comment that names ~/.ssh/authorized_keys is not a target there (the
// GAP-1982 rows Codex already allows). Writes of the key before or after a
// comment, and the Windows spellings that keep every reading (a backtick
// escaped #, a cmd variable, a drive path in the comment), still block.
func TestGAP0147ClaudeCodeBashCommentNamingTheKeys(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	windows := runtime.GOOS == "windows"
	for _, row := range []struct {
		name, command      string
		block, windowsOnly bool
	}{
		{"B1 plain", "Set-Content notes.txt x", false, false},
		{"B2 comment", "Set-Content notes.txt x # see ~/.ssh/authorized_keys", false, false},
		{"B3 comment with backslashes", `Add-Content -Path notes.md -Value done  # do not edit ~\.ssh\authorized_keys`, false, false},
		{"B4 comment line first", "# rotate ~/.ssh/authorized_keys later\nSet-Content notes.txt x", false, false},
		{"B5 echo comment", "echo benign-claude-1982 # see ~/.ssh/authorized_keys", false, false},
		{"K1 direct write", "Set-Content ~/.ssh/authorized_keys x", true, false},
		{"K2 redirect", "echo dummy-key >> ~/.ssh/authorized_keys", true, false},
		{"K3 write then comment", "Set-Content ~/.ssh/authorized_keys x # see notes", true, false},
		{"K4 comment then write", "# notes\nSet-Content ~/.ssh/authorized_keys x", true, false},
		{"W01 escaped blank hash", "Write-Output a` #; Set-Content ~\\.ssh\\authorized_keys k", true, true},
		{"W02 escaped Add-Content", "Write-Output a` #; Add-Content -Path $env:USERPROFILE\\.ssh\\authorized_keys k", true, true},
		{"W03 escaped redirect", "Write-Output a` #; echo k >> ~\\.ssh\\authorized_keys", true, true},
		{"G02 lone CR", "echo a\r#x; cp k.pub ~/.ssh/authorized_keys", true, false},
		{"G03 cmd expansion", "Set-Content notes.txt x # & echo k >> %USERPROFILE%\\.ssh\\authorized_keys", true, true},
		{"G04 drive path in a comment", `python w.py # ` + filepath.Join(home, ".ssh", "authorized_keys"), true, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			if row.windowsOnly && !windows {
				t.Skip("a Windows spelling")
			}
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			store, logger := testStoreAndLogger(t)
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
			body := string(mustJSON(t, map[string]any{"session_id": "gap0147", "hook_event_name": "PreToolUse",
				"tool_name": "Bash", "cwd": project, "tool_input": map[string]string{"command": row.command}}))
			req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			api.handleAgentHook("claudecode").ServeHTTP(recorder, req)
			got := recorder.Body.String()
			blocked := strings.Contains(got, `"action":"block"`)
			if blocked != row.block {
				t.Fatalf("%q: block=%v, want %v: %.400s", row.command, blocked, row.block, got)
			}
			if row.block && !strings.Contains(got, "persistence.ssh_authorized_keys_command") {
				t.Fatalf("%q: blocked by another rule: %.400s", row.command, got)
			}
		})
	}
}
