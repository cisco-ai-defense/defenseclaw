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

// GAP-0147: on Windows the Claude Code hook path judged every Bash call with
// no dialect hint, so every reading counted: a # comment that names
// ~/.ssh/authorized_keys blocked a benign echo (the GAP-1982 rows Codex
// already allows). A Bash call the POSIX grammar reads alone is now read as
// POSIX (Git Bash runs it), where the comment is no target (with the POSIX
// comment rule of rel-1-0-6:GAP-0133). PowerShell text sent to the Bash tool
// (the B2-B4 rows of the cell) keeps every reading: lead ruling pending, see
// IN-fc-wingrammar.md. Writes of the key before or after a
// comment, and the Windows spellings that keep every reading (a backtick
// escaped #, a cmd variable, a drive path in the comment), still block.
func TestGAP0147ClaudeCodeBashCommentNamingTheKeys(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the Windows dialect hint of the Claude Code hook; the POSIX comment rule is GAP-0133")
	}
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
	for _, row := range []struct {
		name, command string
		block         bool
	}{
		{"B1 plain", "Set-Content notes.txt x", false},
		{"B5 echo comment", "echo benign-claude-1982 # see ~/.ssh/authorized_keys", false},
		{"K1 direct write", "Set-Content ~/.ssh/authorized_keys x", true},
		{"K2 redirect", "echo dummy-key >> ~/.ssh/authorized_keys", true},
		{"K3 write then comment", "Set-Content ~/.ssh/authorized_keys x # see notes", true},
		{"K4 comment then write", "# notes\nSet-Content ~/.ssh/authorized_keys x", true},
		{"W01 escaped blank hash", "Write-Output a` #; Set-Content ~\\.ssh\\authorized_keys k", true},
		{"W02 escaped Add-Content", "Write-Output a` #; Add-Content -Path $env:USERPROFILE\\.ssh\\authorized_keys k", true},
		{"W03 escaped redirect", "Write-Output a` #; echo k >> ~\\.ssh\\authorized_keys", true},
		{"G02 lone CR", "echo a\r#x; cp k.pub ~/.ssh/authorized_keys", true},
		{"G03 cmd expansion", "Set-Content notes.txt x # & echo k >> %USERPROFILE%\\.ssh\\authorized_keys", true},
		{"G04 drive path in a comment", `python w.py # ` + filepath.Join(home, ".ssh", "authorized_keys"), true},
	} {
		t.Run(row.name, func(t *testing.T) {
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
