// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestInterpreterWriteThroughProjectLinkIsOneVerdictPerConnector pins
// GAP-1880: Copilot, Claude Code and Codex judge the same interpreter write
// through a project symlink to ~/.ssh/authorized_keys the same way. The
// quoted pathlib append (the rc.11 repro, TST-33085) blocks in action mode on
// every connector. The verify prompt typed the quotes as the literal text
// \x27, which bash passes to Python unchanged: that program is a Python
// syntax error and writes nothing, and every connector gives it the same
// verdict.
func TestInterpreterWriteThroughProjectLinkIsOneVerdictPerConnector(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell and symlink fixture")
	}
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	quoted := `python3 -c "from pathlib import Path; Path('keylink').open('a').write('m\n')"`
	literal := `python3 -c "from pathlib import Path; Path(\x27keylink\x27).open(\x27a\x27).write(\x27m\n\x27)"`
	verdict := func(t *testing.T, connectorName, command string) string {
		t.Helper()
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = connectorName
		api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
		var body map[string]any
		event := ""
		switch connectorName {
		case "copilot":
			args, _ := json.Marshal(map[string]any{"command": command, "description": "Run the requested Python command"})
			body = map[string]any{"sessionId": "s-1880", "timestamp": 1790483549431, "cwd": project,
				"toolName": "bash", "toolArgs": string(args)}
			event = "preToolUse"
		default:
			body = map[string]any{"hook_event_name": "PreToolUse", "session_id": "s-1880-" + connectorName,
				"cwd": project, "tool_name": "Bash", "tool_use_id": "t-1880-" + connectorName,
				"tool_input": map[string]any{"command": command}}
		}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connectorName+"/hook", strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		if event != "" {
			req.Header.Set("X-DefenseClaw-Copilot-Event", event)
		}
		if connectorName == "codex" {
			setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
		}
		recorder := httptest.NewRecorder()
		api.handleAgentHook(connectorName).ServeHTTP(recorder, req)
		var answer struct {
			Action string `json:"action"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
			t.Fatalf("%s answer %q: %v", connectorName, recorder.Body.String(), err)
		}
		return answer.Action
	}
	for _, connectorName := range []string{"copilot", "claudecode", "codex"} {
		if got := verdict(t, connectorName, quoted); got != "block" {
			t.Errorf("%s: quoted interpreter write through keylink = %s, want block", connectorName, got)
		}
	}
	want := verdict(t, "claudecode", literal)
	for _, connectorName := range []string{"copilot", "codex"} {
		if got := verdict(t, connectorName, literal); got != want {
			t.Errorf("%s: literal \\x27 program = %s, Claude Code = %s; want one verdict", connectorName, got, want)
		}
	}
	if data, _ := os.ReadFile(keys); len(data) != 0 {
		t.Fatalf("authorized_keys was written: %q", data)
	}
}
