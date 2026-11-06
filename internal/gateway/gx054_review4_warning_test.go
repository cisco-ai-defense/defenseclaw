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

func TestGX054LargeArchiveBoundHasVisiblePossibleFinding(t *testing.T) {
	f := rv4oFixture(t)
	rv4Extra(t, f, true)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	for _, row := range []struct{ name, command string }{
		{"members", "tar xzf node.tgz && ./configure > build.log"},
		{"bytes", "tar xzf blob.tgz && ./configure > build.log"},
	} {
		t.Run(row.name, func(t *testing.T) {
			for _, connector := range []string{"claudecode", "codex"} {
				body := map[string]any{"session_id": "bound-warning", "hook_event_name": "PreToolUse", "cwd": f.project, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": "bound-warning", "tool_input": map[string]any{"command": row.command}}
				if connector == "codex" {
					body["turn_id"] = "bound-warning-turn"
				}
				payload := mustJSON(t, body)
				header := rv4Header(t, f, connector, payload)
				for _, managed := range []bool{false, true} {
					if managed {
						if err := os.Chmod(f.homes, 0); err != nil {
							t.Fatal(err)
						}
					}
					cfg := &config.Config{}
					cfg.Guardrail.Mode, cfg.Guardrail.Connector = "action", connector
					cfg.DataDir = os.Getenv("DEFENSECLAW_HOME")
					api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
					req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set(hookpaths.Header, header)
					if connector == "codex" {
						setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
					}
					if managed {
						req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: filepath.Dir(f.project)}))
					}
					rec := httptest.NewRecorder()
					api.handleAgentHook(connector).ServeHTTP(rec, req)
					if managed {
						if err := os.Chmod(f.homes, 0o700); err != nil {
							t.Fatal(err)
						}
					}
					answer := rec.Body.String()
					if !strings.HasPrefix(answer, `{"action":"alert"`) ||
						!strings.Contains(answer, "Archive extraction has an unverified link scope for a later write") ||
						!strings.Contains(answer, "persistence.ssh_authorized_keys_command") {
						t.Errorf("%s managed=%t missing visible Possible finding: %.400s", connector, managed, answer)
					}
				}
			}
		})
	}
}
