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

// A recursive cp without -L copies the links of the tree as links; it
// reads and writes no file they name. So a benign backup of a project that
// holds a link to the keys file and one to the state folder is allowed
// under env -C DIR as under cd DIR && (rel-1-0-4:GAP-2579, cell
// L-ewin-J3-007 B11). A copy onto the keys file or into ~/.ssh and a write
// through a link still block. On
// Windows the managed hook peer (a service gateway) judges it as the
// per-user gateway does.
func TestRecursiveCopyOfLinkedTreeMatchesAcrossOS(t *testing.T) {
	rows := []struct {
		name, command string
		block         bool
	}{
		{name: "B11 env -C home cp -r", command: `env -C ~ cp -r proj proj-bak`},
		{name: "B11c cd home then cp -r", command: `cd ~ && cp -r proj proj-bak`},
		{name: "B11d cp -r from the home", command: `cp -r ~/proj ~/proj-bak`},
		{name: "B11f env --chdir home cp -R", command: `env --chdir=~ cp -R proj proj-bak`},
		{name: "K03 env -C home copy onto the keys file", command: `env -C ~ cp proj/README.md .ssh/authorized_keys`, block: true},
		{name: "K04 env -C proj write through the link", command: `env -C ~/proj sh -c "echo x >> keylink"`, block: true},
		{name: "K05 env -C home cp -r into .ssh", command: `env -C ~ cp -r proj .ssh/`, block: true},
	}
	modes := []bool{false}
	if runtime.GOOS == "windows" {
		modes = append(modes, true)
	}
	for _, managed := range modes {
		for _, header := range []bool{true, false} {
			for _, row := range rows {
				name := "per-user/" + row.name
				if managed {
					name = "managed/" + row.name
				}
				if !header {
					name += "/no-header"
				}
				t.Run(name, func(t *testing.T) {
					home := t.TempDir()
					project := filepath.Join(home, "proj")
					keys := filepath.Join(home, ".ssh", "authorized_keys")
					state := filepath.Join(home, ".defenseclaw")
					for _, dir := range []string{filepath.Dir(keys), state, filepath.Join(project, "src")} {
						if err := os.MkdirAll(dir, 0o700); err != nil {
							t.Fatal(err)
						}
					}
					for file, body := range map[string]string{keys: "k\n", filepath.Join(state, "config.yaml"): "x: 1\n",
						filepath.Join(project, "README.md"): "x\n", filepath.Join(project, "src", "a.go"): "x\n"} {
						if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					for link, target := range map[string]string{"keylink": keys, "statelink": state} {
						if err := os.Symlink(target, filepath.Join(project, link)); err != nil {
							t.Skipf("this account cannot make links: %v", err)
						}
					}
					t.Setenv("HOME", home)
					t.Setenv("USERPROFILE", home)
					payload := mustJSON(t, map[string]any{"session_id": "linked-tree-copy", "hook_event_name": "PreToolUse",
						"cwd": project, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_copy",
						"tool_input": map[string]any{"command": row.command}})
					cfg := &config.Config{}
					cfg.Guardrail.Mode = "action"
					cfg.Guardrail.Connector = "claudecode"
					store, logger := testStoreAndLogger(t)
					api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
					req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
					req.Header.Set("Content-Type", "application/json")
					if header {
						req.Header.Set(hookpaths.Header, hookpaths.Resolve(payload))
					}
					if managed {
						req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
					}
					recorder := httptest.NewRecorder()
					api.handleAgentHook("claudecode").ServeHTTP(recorder, req)
					got := recorder.Body.String()
					blocked := strings.HasPrefix(got, `{"action":"block"`)
					if !blocked && !strings.HasPrefix(got, `{"action":"allow"`) {
						t.Fatalf("%q: status %d body %.300s", row.command, recorder.Code, got)
					}
					if blocked != row.block {
						t.Fatalf("%s managed=%v %q: block=%v, want %v: %.400s", runtime.GOOS, managed, row.command, blocked, row.block, got)
					}
				})
			}
		}
	}
}
