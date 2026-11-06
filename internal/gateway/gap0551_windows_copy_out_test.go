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

func TestGAP0551WindowsConfigCopyOutProfiles(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw"), filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{
		filepath.Join(home, ".defenseclaw", "config.yaml"),
		filepath.Join(home, ".ssh", "authorized_keys"),
		filepath.Join(project, "a.txt"),
	} {
		if err := os.WriteFile(file, []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	rows := []struct{ name, command, defaultWant, strictWant string }{
		{"copy-out", `cp ~/.defenseclaw/conf*.yaml project/copy.yaml`, "allow", "block"},
		{"state destination", `cp project/a.txt ~/.defenseclaw/conf*.yaml`, "block", "block"},
		{"protected link", `cp ~/.defenseclaw/conf*.yaml project/keylink`, "block", "block"},
		{"keys destination", `cp project/a.txt ~/.ssh/authorized_keys`, "block", "block"},
	}
	for _, connector := range []string{"codex", "claudecode"} {
		for _, managed := range []bool{false, true} {
			for _, tier := range []string{"default", "strict"} {
				for _, row := range rows {
					t.Run(connector+"/"+row.name+"/"+tier+"/"+map[bool]string{false: "user", true: "managed"}[managed], func(t *testing.T) {
						payload := mustJSON(t, map[string]any{
							"session_id": "gap0551", "hook_event_name": "PreToolUse",
							"cwd": home, "permission_mode": "default", "tool_name": "Bash",
							"tool_use_id": "toolu_gap0551", "tool_input": map[string]any{"command": row.command},
						})
						cfg := &config.Config{}
						cfg.Guardrail.Mode = "action"
						cfg.Guardrail.Connector = connector
						cfg.Guardrail.RulePack = tier
						store, logger := testStoreAndLogger(t)
						api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
						req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
						if managed {
							req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector(connector, "", "", payload))
							req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
						}
						if connector == "codex" {
							setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
						}
						recorder := httptest.NewRecorder()
						api.handleAgentHook(connector).ServeHTTP(recorder, req)
						want := row.defaultWant
						if tier == "strict" {
							want = row.strictWant
						}
						if body := recorder.Body.String(); !strings.HasPrefix(body, `{"action":"`+want+`"`) {
							t.Fatalf("verdict for %s: status=%d body=%.300s, want=%s", row.name, recorder.Code, body, want)
						}
					})
				}
			}
		}
	}
}
