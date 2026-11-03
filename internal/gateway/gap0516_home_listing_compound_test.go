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

// A user shell's */* does not select .ssh/authorized_keys at the home
// directory. Adding a second statement must not turn that listing into a
// protected write. The matching explicit writes still block in every hook
// route. The native absolute path row uses Windows paths on Windows and
// Unix paths on Unix; the slash path row also covers Git Bash spelling.
func TestGAP0516HomeListingCompoundFourCell(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(home, "project", "note.txt"), []byte("note\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Cleanup(func() { _ = os.Chmod(home, 0o700) })

	rows := []struct{ name, command, want string }{
		{"lone-read", `head -n 1 */*`, "allow"},
		{"semicolon-marker", `head -n 1 */*; echo done`, "allow"},
		{"and-marker", `head -n 1 */* && echo done`, "allow"},
		{"semicolon-pwd", `head -n 1 */*; pwd`, "allow"},
		{"and-pwd", `head -n 1 */* && pwd`, "allow"},
		{"three-semicolon", `head -n 1 */*; pwd; echo done`, "allow"},
		{"read-then-pwd", `head -n 1 */*; stat .; pwd`, "allow"},
		{"three-and", `head -n 1 */* && pwd && echo done`, "allow"},
		{"pwd-physical", `head -n 1 */*; pwd -P`, "allow"},
		{"glob-print-pwd", `echo */*; pwd`, "allow"},
		{"glob-print-three", `echo */*; pwd; echo done`, "allow"},
		{"discard-then-marker", `head -n 1 */* 2>/dev/null; echo done`, "allow"},
		{"echo-glob-then-marker", `echo */*; echo done`, "allow"},
		{"bash-c-list-then-marker", `bash -c "head -n 1 */*; echo done"`, "allow"},
		{"bash-c-echo-glob-then-marker", `bash -c "echo */*; echo done"`, "allow"},
		{"relative-write", `head -n 1 */*; echo marker >> .ssh/authorized_keys`, "block"},
		{"tilde-write", `head -n 1 */* && echo marker >> ~/.ssh/authorized_keys`, "block"},
		{"pwd-then-write", `head -n 1 */*; pwd; echo marker >> .ssh/authorized_keys`, "block"},
		{"read-then-write", `head -n 1 */*; stat .; pwd > .ssh/authorized_keys`, "block"},
		{"glob-print-then-write", `echo */*; pwd; echo marker >> .ssh/authorized_keys`, "block"},
		{"native-absolute-write", `echo */*; echo marker >> "` + keys + `"`, "block"},
		{"slash-absolute-write", `echo */* && cp project/note.txt "` + filepath.ToSlash(keys) + `"`, "block"},
		{"bash-c-list-then-write", `bash -c "head -n 1 */*; echo marker >> .ssh/authorized_keys"`, "block"},
		{"bash-c-echo-glob-then-copy", `bash -c "echo */*; cp project/note.txt .ssh/authorized_keys"`, "block"},
		{"echo-substitution-write", `echo $(echo marker >> .ssh/authorized_keys) */*; echo done`, "block"},
	}
	for _, row := range rows {
		payload := mustJSON(t, map[string]any{
			"session_id": "gap0516", "hook_event_name": "PreToolUse",
			"cwd": home, "permission_mode": "default", "tool_name": "Bash",
			"tool_use_id": "toolu_gap0516", "tool_input": map[string]any{"command": row.command},
		})
		header := hookpaths.Resolve(payload)
		for _, connector := range []string{"claudecode", "codex"} {
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
					want := row.want
					if runtime.GOOS == "windows" && connector == "codex" && row.want == "allow" &&
						strings.HasPrefix(row.command, "head -n 1 */*") {
						// Codex's Windows Bash tool runs PowerShell, whose glob can
						// include .ssh. Git Bash on Claude Code excludes dot names.
						want = "block"
					}
					if !strings.HasPrefix(body, `{"action":"`+want+`"`) {
						t.Errorf("%q: status %d body %.400s, want %s", row.command, recorder.Code, body, want)
					}
					if row.want == "block" && !strings.Contains(body, "persistence.ssh_authorized_keys_command") {
						t.Errorf("%q: wrong block rule: %.400s", row.command, body)
					}
					if want == "block" && row.want == "allow" && !strings.Contains(body, "PATH-SSH-KEY") {
						t.Errorf("%q: wrong Windows private-key block rule: %.400s", row.command, body)
					}
				})
			}
		}
	}
}
