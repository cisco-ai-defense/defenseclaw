// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestManagedSudoersWriteNamesTheSudoersRule: a managed gateway blocks a
// file tool write into /etc/sudoers.d, whose target the user's hook cannot
// read, and the block names the sudoers rule of the pack, not the SSH keys
// rule (rel-1-0-6:GAP-0190). The decision is unchanged; writes that reach
// the keys file keep the keys rule.
func TestManagedSudoersWriteNamesTheSudoersRule(t *testing.T) {
	if info, err := os.Stat("/etc/sudoers.d"); err != nil || !info.IsDir() {
		t.Skip("no /etc/sudoers.d on this host")
	}
	if dir, err := os.Open("/etc/sudoers.d"); err == nil {
		_ = dir.Close()
		t.Skip("/etc/sudoers.d is readable here; the managed hook could resolve the target")
	}
	grant := "lane ALL=(ALL) NOPASSWD: ALL\n"
	rows := []struct {
		name, tool, path string
		input            map[string]any
		want, rule       string
	}{
		{"Write of a grant", "Write", "/etc/sudoers.d/lane", map[string]any{"content": grant}, "block", "PATH-ETC-SUDOERS"},
		{"Write of a Defaults line", "Write", "/etc/sudoers.d/lane", map[string]any{"content": "Defaults env_reset\n"}, "block", "PATH-ETC-SUDOERS"},
		{"oversized Write of a grant", "Write", "/etc/sudoers.d/lane", map[string]any{"content": grant + strings.Repeat("#", 70000) + "\n"}, "block", "PATH-ETC-SUDOERS"},
		{"Edit of a drop-in", "Edit", "/etc/sudoers.d/lane", map[string]any{"old_string": "a", "new_string": grant}, "block", "PATH-ETC-SUDOERS"},
		{"Write through the keys link", "Write", "{P}/keylink", map[string]any{"content": "k\n"}, "block", "persistence.ssh_authorized_keys_command"},
		{"Write of the keys file", "Write", "{K}", map[string]any{"content": "k\n"}, "block", "persistence.ssh_authorized_keys_command"},
		{"Write of a project file", "Write", "{P}/notes.txt", map[string]any{"content": "k\n"}, "allow", ""},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, row := range rows {
			f := newB36ManagedHookFixture(t)
			input := map[string]any{"file_path": strings.NewReplacer("{P}", f.project, "{K}", f.keys).Replace(row.path)}
			for key, value := range row.input {
				input[key] = value
			}
			payload := mustJSON(t, map[string]any{"session_id": "gap0190", "hook_event_name": "PreToolUse", "cwd": f.project,
				"permission_mode": "default", "tool_name": row.tool, "tool_use_id": "toolu_gap0190", "tool_input": input})
			header := f.clientHeader(t, payload)
			if err := os.Chmod(f.homes, 0); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
			req.Header.Set(hookpaths.Header, header)
			if connector == "codex" {
				setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
			}
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: f.home}))
			recorder := httptest.NewRecorder()
			api.handleAgentHook(connector).ServeHTTP(recorder, req)
			if err := os.Chmod(f.homes, 0o700); err != nil {
				t.Fatal(err)
			}
			body := recorder.Body.String()
			got := "allow"
			if strings.HasPrefix(body, `{"action":"block"`) {
				got = "block"
			}
			if got != row.want {
				t.Errorf("%s %s: managed %s, want %s: %.300s", connector, row.name, got, row.want, body)
				continue
			}
			if row.rule != "" && !strings.Contains(body, row.rule) {
				t.Errorf("%s %s: the block does not name %s: %.300s", connector, row.name, row.rule, body)
			}
			if row.rule == "PATH-ETC-SUDOERS" && strings.Contains(body, "persistence.ssh_authorized_keys_command") {
				t.Errorf("%s %s: the sudoers block names the SSH keys rule: %.300s", connector, row.name, body)
			}
			if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
				t.Fatalf("decoy keys file changed: %q %v", data, err)
			}
		}
	}
}
