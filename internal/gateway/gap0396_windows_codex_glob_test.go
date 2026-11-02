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

// GAP-0396: an unquoted source glob in a project does not make the fixed
// destination an SSH keys write in a native Windows Codex hook reading.
func TestGAP0396WindowsCodexProjectGlobCopy(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	linked := filepath.Join(home, "linked")
	caseLinked := filepath.Join(home, "case-linked")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(project, "build"), filepath.Join(project, "out"),
		filepath.Join(linked, "build"), filepath.Join(linked, "out"), filepath.Join(caseLinked, "build")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{project, linked} {
		for _, name := range []string{"a.txt", "b.txt", "README.md"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, name := range []string{"a.txt", "c.TXT"} {
		if err := os.WriteFile(filepath.Join(caseLinked, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"build", "out"} {
		if err := os.Symlink(keys, filepath.Join(linked, dir, "a.txt")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(keys, filepath.Join(caseLinked, "build", "c.TXT")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	rows := []struct{ name, cwd, command, want string }{
		{"project-build", project, `cp *.txt build/`, "allow"},
		{"project-out", project, `cp *.txt out/`, "allow"},
		{"linked-build", linked, `cp *.txt build/`, "block"},
		{"linked-out", linked, `cp *.txt out/`, "block"},
		{"case-variant-link", caseLinked, `cp *.txt build/`, "block"},
		{"unzip-list-archive", project, `unzip -v x.zip; cp a.txt build/`, "allow"},
		{"unzip-list-archive-linked", project, `unzip -v x.zip; cp a.txt keylink`, "block"},
		{"literal-control", project, `cp a.txt build/`, "allow"},
		{"quoted-control", project, `cp "*.txt" build/`, "allow"},
		{"protected-destination", project, `cp *.txt ../.ssh/authorized_keys`, "block"},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, row := range rows {
				t.Run(connector+"/"+row.name+"/managed="+map[bool]string{false: "false", true: "true"}[managed], func(t *testing.T) {
					tool := "Bash"
					payload := mustJSON(t, map[string]any{"session_id": "gap0396", "hook_event_name": "PreToolUse", "cwd": row.cwd,
						"permission_mode": "default", "tool_name": tool, "tool_use_id": "toolu_gap0396",
						"tool_input": map[string]any{"command": row.command}})
					header := hookpaths.ResolveConnector(connector, "", "", payload)
					cfg := &config.Config{}
					cfg.Guardrail.Mode = "action"
					cfg.Guardrail.Connector = connector
					store, logger := testStoreAndLogger(t)
					api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
					req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
					if managed {
						req.Header.Set(hookpaths.Header, header)
						req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
					}
					if connector == "codex" {
						setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
					}
					recorder := httptest.NewRecorder()
					api.handleAgentHook(connector).ServeHTTP(recorder, req)
					body := recorder.Body.String()
					got := "other"
					if strings.HasPrefix(body, `{"action":"allow"`) {
						got = "allow"
					} else if strings.HasPrefix(body, `{"action":"block"`) {
						got = "block"
					}
					t.Logf("GAP0396ROW %s managed=%t %s: %s", connector, managed, row.name, got)
					if got != row.want {
						t.Errorf("verdict %s, want %s: status %d body %.300s", got, row.want, recorder.Code, body)
					}
				})
			}
		}
	}
}
