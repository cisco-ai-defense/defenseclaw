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
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// Codex and Claude Code both run this literal bash -c body as a read of
// names. The home contains .ssh/authorized_keys, which */* does not select
// in Bash. A real redirect into that file still blocks in each hook route.
func TestGAP0496BashCReadOnlyGlobFromHomeFourCell(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "user")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, dir := range []string{filepath.Dir(keys), filepath.Join(home, "project")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(keys, []byte("# fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "project", "notes.txt"), []byte("notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
	for _, row := range []struct{ name, command, want string }{
		{"listing", `bash -c "ls -d */* | head -3"`, "allow"},
		{"listing-stderr-discard", `bash -c "ls -d */* 2>/dev/null | head -3"`, "allow"},
		{"protected-write", `bash -c "echo fixture >> .ssh/authorized_keys"`, "block"},
	} {
		payload := mustJSON(t, map[string]any{
			"session_id": "gap0496", "hook_event_name": "PreToolUse",
			"cwd": home, "permission_mode": "default", "tool_name": "Bash",
			"tool_use_id": "toolu_gap0496", "tool_input": map[string]any{"command": row.command},
		})
		header := hookpaths.Resolve(payload)
		for _, connector := range []string{"codex", "claudecode"} {
			for _, managed := range []bool{false, true} {
				name := runtime.GOOS + "/" + row.name + "/" + connector
				if managed {
					name += "/managed"
				} else {
					name += "/per-user"
				}
				t.Run(name, func(t *testing.T) {
					if managed && runtime.GOOS != "windows" && os.Geteuid() != 0 {
						if err := os.Chmod(home, 0); err != nil {
							t.Fatal(err)
						}
						defer os.Chmod(home, 0o700)
					}
					cfg := &config.Config{}
					cfg.Guardrail.Mode = "action"
					cfg.Guardrail.Connector = connector
					api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
					req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
					if managed {
						if runtime.GOOS != "windows" {
							req.Header.Set(hookpaths.Header, header)
						}
						req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
					}
					if connector == "codex" {
						setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
					}
					recorder := httptest.NewRecorder()
					api.handleAgentHook(connector).ServeHTTP(recorder, req)
					body := recorder.Body.String()
					if !strings.HasPrefix(body, `{"action":"`+row.want+`"`) {
						t.Errorf("%q: status %d body %.400s, want %s", row.command, recorder.Code, body, row.want)
					}
					if row.want == "block" && !strings.Contains(body, "persistence.ssh_authorized_keys_command") {
						t.Errorf("%q: wrong block rule: %.400s", row.command, body)
					}
				})
			}
		}
	}
}
