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
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// A copy of a project folder that holds a link to the keys file, run in the
// home with env -C, is its own copy destination on Windows as on Linux: the
// bare copy is allowed, a write through the copied link blocks
// (rel-1-0-4:GAP-2579). The managed Windows service gateway reads the call
// as the per-user gateway does. Claude Code runs it in Git Bash; Codex on
// Windows reads the command as PowerShell, where env -C is not a shell form.
func TestEnvChdirProjectCopyWithKeyLinkMatchesLinuxOnWindows(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(project, "src")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(project, "a.txt"), filepath.Join(project, "src", "a.txt")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A Limited token cannot make the keys link: the rows that copy or write
	// through it skip there (GAP-2158); the other rows run on every token.
	keylink := testenv.TrySymlink(t, filepath.FromSlash("../.ssh/authorized_keys"), filepath.Join(project, "keylink"))
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, row := range []struct {
		command  string
		block    bool
		needLink bool
	}{
		{`env -C ~ cp -r project project-bak`, false, true},
		{`env -C ~ cp -r project/src src-bak`, false, false},
		{`env -C ~ cp -r project project-bak; echo key >> ~/project-bak/keylink`, true, true},
		{`env -C ~/project ln -sf ../.ssh/authorized_keys ln3; cp a.txt ln3`, true, false},
	} {
		t.Run(row.command, func(t *testing.T) {
			if row.needLink {
				keylink.Require(t)
			}
			checkEnvChdirProjectCopyRow(t, project, row.command, row.block)
		})
	}
}

// checkEnvChdirProjectCopyRow judges one row of
// TestEnvChdirProjectCopyWithKeyLinkMatchesLinuxOnWindows on the Claude Code
// route.
func checkEnvChdirProjectCopyRow(t *testing.T, project, command string, block bool) {
	t.Helper()
	payload := mustJSON(t, map[string]any{"session_id": "env-copy", "hook_event_name": "PreToolUse",
		"tool_name": "Bash", "cwd": project, "tool_input": map[string]string{"command": command}})
	const connector = "claudecode"
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	if header := hookpaths.ResolveConnector(connector, "", "PreToolUse", payload); header != "" {
		req.Header.Set(hookpaths.Header, header)
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	if blocked := strings.HasPrefix(recorder.Body.String(), `{"action":"block"`); blocked != block {
		t.Errorf("%s %q: block=%v, want %v: %.300s", connector, command, blocked, block, recorder.Body.String())
	}
}
