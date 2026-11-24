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
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// homeGlobRow is one shell call made at the home folder of a per-user
// action-mode gateway. alias adds keysdir, a link at the home to ~/.ssh
// that a plain * does select.
type homeGlobRow struct {
	name, command          string
	block, alias, junction bool
}

// An unquoted * or ? in a POSIX shell (bash, Git Bash on Windows) skips a
// name that starts with a dot, so at the home folder echo * or
// head -n 1 */* names no file in ~/.ssh (rel-1-0-6:GAP-0211; the quoted
// forms of rel-1-0-4:GAP-1717 already allowed). An explicit .ssh path, a
// dot pattern (.*, .ss?), a dotglob setting and a plain link at the home
// to ~/.ssh still block. Codex runs PowerShell on Windows, whose
// wildcards match a leading dot: there only the block rows are judged.
func TestUnquotedGlobAtHomeMatchesAcrossOS(t *testing.T) {
	rows := []homeGlobRow{
		{name: "G01 echo star", command: `echo *`},
		{name: "G02 echo star then echo", command: `echo * && echo done`},
		{name: "G03 head star slash star then echo", command: `head -n 1 */*; echo done`},
		{name: "G04 head with a redirect then echo", command: `head -n 1 */* 2>/dev/null; echo done`},
		{name: "G05 ls star then ls", command: `ls *; ls`},
		{name: "G06 quoted star then echo", command: `echo "*"; echo done`},
		{name: "G07 head star slash star alone", command: `head -n 1 */*`},
		{name: "K01 append to the keys file", command: `echo x >> .ssh/authorized_keys`, block: true},
		{name: "K02 copy onto the keys file", command: `cp a.txt .ssh/authorized_keys`, block: true},
		{name: "K03 copy through a dot pattern", command: `cp a.txt .ss?/authorized_keys`, block: true},
		{name: "K04 copy through dot star", command: `cp a.txt .*/authorized_keys`, block: true},
		{name: "K05 dotglob then star", command: `shopt -s dotglob; cp a.txt */authorized_keys`, block: true},
		{name: "K06 star selects a plain link to .ssh", command: `cp a.txt */authorized_keys`, block: true, alias: true},
		{name: "K07 tilde keys file", command: `cp a.txt ~/.ssh/authorized_keys`, block: true},
	}
	if runtime.GOOS == "windows" {
		// K06 needs a symbolic link, which a Limited token cannot make; the
		// junction form of the same link runs on every token (GAP-2158).
		rows = append(rows, homeGlobRow{name: "K06J star selects a junction to .ssh", command: `cp a.txt */authorized_keys`, block: true, junction: true})
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, header := range []bool{true, false} {
			for _, row := range rows {
				name := connector + "/" + row.name
				if !header {
					name += "/no-header"
				}
				t.Run(name, func(t *testing.T) {
					if connector == "codex" && codexShellRunsPowerShell && !row.block {
						t.Skip("PowerShell wildcards match a leading dot")
					}
					home := t.TempDir()
					keys := filepath.Join(home, ".ssh", "authorized_keys")
					for _, dir := range []string{filepath.Dir(keys), filepath.Join(home, "project"), filepath.Join(home, "Documents")} {
						if err := os.MkdirAll(dir, 0o700); err != nil {
							t.Fatal(err)
						}
					}
					for file, body := range map[string]string{keys: "k\n", filepath.Join(home, "a.txt"): "x\n",
						filepath.Join(home, "project", "n.txt"): "x\n"} {
						if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					if row.alias {
						testenv.Symlink(t, filepath.Dir(keys), filepath.Join(home, "keysdir"))
					}
					if row.junction {
						testenv.Junction(t, filepath.Dir(keys), filepath.Join(home, "keysdir"))
					}
					t.Setenv("HOME", home)
					t.Setenv("USERPROFILE", home)
					payload := mustJSON(t, map[string]any{"session_id": "home-glob", "hook_event_name": "PreToolUse",
						"cwd": home, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_glob",
						"tool_input": map[string]any{"command": row.command}})
					cfg := &config.Config{}
					cfg.Guardrail.Mode = "action"
					cfg.Guardrail.Connector = connector
					store, logger := testStoreAndLogger(t)
					api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
					req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
					req.Header.Set("Content-Type", "application/json")
					if header {
						req.Header.Set(hookpaths.Header, hookpaths.Resolve(payload))
					}
					if connector == "codex" {
						setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
					}
					recorder := httptest.NewRecorder()
					api.handleAgentHook(connector).ServeHTTP(recorder, req)
					got := recorder.Body.String()
					blocked := strings.HasPrefix(got, `{"action":"block"`)
					if !blocked && !strings.HasPrefix(got, `{"action":"allow"`) {
						t.Fatalf("%q: status %d body %.300s", row.command, recorder.Code, got)
					}
					if blocked != row.block {
						t.Fatalf("%s %q at the home: block=%v, want %v: %.400s", runtime.GOOS, row.command, blocked, row.block, got)
					}
				})
			}
		}
	}
}
