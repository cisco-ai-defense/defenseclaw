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

// A link the command makes inside the project and then moves, or a move
// into the folder such a link names, writes no file the link could alias:
// ln -s build/out bin; mv bin build/ is allowed (rel-1-0-6:GAP-0219, the
// GAP-0091 benign shape W07). On Windows the managed hook peer (a service
// gateway) judges it as the per-user gateway does. A link the command makes
// to the keys file or ~/.ssh and a write through it, also after a move,
// still block.
func TestLinkThenMoveInProjectMatchesAcrossOS(t *testing.T) {
	rows := []struct {
		name, command string
		block         bool
	}{
		{name: "W07 link then move the link into its folder parent", command: `ln -s build/out bin; mv bin build/`},
		{name: "W07b link and then move", command: `ln -s build/out bin && mv bin build/`},
		{name: "W07c link then move another file", command: `ln -s build/out bin; mv notes.txt build/`},
		{name: "W07d mkdir link then move", command: `mkdir -p build/out && ln -s build/out bin; mv bin build/`},
		{name: "W07e link then rename the link", command: `ln -s build/out bin; mv bin bin2`},
		{name: "K01 link to the keys file then write", command: `ln -s ~/.ssh/authorized_keys k; echo x >> k`, block: true},
		{name: "K02 link to .ssh then move onto the keys name", command: `ln -s ~/.ssh k; mv notes.txt k/authorized_keys`, block: true},
		{name: "K03 link to the keys file moved then written", command: `ln -s ~/.ssh/authorized_keys k; mv k build/; echo x >> build/k`, block: true},
		{name: "K04 link into build then a disk link to .ssh moved onto build", command: `ln -s build/authorized_keys bin; mv sshlink build; echo x >> bin`, block: true},
	}
	modes := []bool{false}
	if runtime.GOOS == "windows" {
		modes = append(modes, true)
	}
	for _, managed := range modes {
		for _, header := range []bool{true, false} {
			for _, empty := range []bool{false, true} {
				for _, row := range rows {
					name := "per-user/" + row.name
					if managed {
						name = "managed/" + row.name
					}
					if !header {
						name += "/no-header"
					}
					if empty {
						// The project folder holds nothing yet: build/ and
						// notes.txt do not exist when the hook judges the call.
						name += "/empty-project"
					}
					t.Run(name, func(t *testing.T) {
						home := t.TempDir()
						project := filepath.Join(home, "proj")
						keys := filepath.Join(home, ".ssh", "authorized_keys")
						dirs := []string{filepath.Dir(keys), filepath.Join(project, "build", "out")}
						files := map[string]string{keys: "k\n", filepath.Join(project, "notes.txt"): "x\n"}
						if empty {
							dirs = []string{filepath.Dir(keys), project}
							files = map[string]string{keys: "k\n"}
						}
						for _, dir := range dirs {
							if err := os.MkdirAll(dir, 0o700); err != nil {
								t.Fatal(err)
							}
						}
						if err := os.MkdirAll(filepath.Join(project, "sub"), 0o700); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(filepath.Dir(keys), filepath.Join(project, "sshlink")); err != nil {
							t.Skipf("this account cannot make links: %v", err)
						}
						for file, body := range files {
							if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
								t.Fatal(err)
							}
						}
						t.Setenv("HOME", home)
						t.Setenv("USERPROFILE", home)
						payload := mustJSON(t, map[string]any{"session_id": "link-then-move", "hook_event_name": "PreToolUse",
							"cwd": project, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_lnmv",
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
}
