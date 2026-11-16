// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"golang.org/x/sys/windows"
)

// A managed Windows gateway runs as a service, not as the home user. At a
// real profile folder the legacy junctions deny listing to Everyone and
// NTUSER.DAT is held open; the user Git Bash expands */* to no protected
// file there, so the managed gateway allows the same benign calls the
// per-user gateway allows (rel-1-0-6:GAP-0211, parity). Explicit .ssh
// writes, dot patterns and a link to ~/.ssh selected by * keep blocking.
func TestManagedWindowsUnquotedGlobAtProfileMatchesPerUser(t *testing.T) {
	rows := []struct {
		name, command string
		block, alias  bool
	}{
		{name: "G01 echo star", command: `echo *`},
		{name: "G03 head star slash star then echo", command: `head -n 1 */*; echo done`},
		{name: "G04 head with a redirect then echo", command: `head -n 1 */* 2>/dev/null; echo done`},
		{name: "G07 head star slash star alone", command: `head -n 1 */*`},
		{name: "K01 append to the keys file", command: `echo x >> .ssh/authorized_keys`, block: true},
		{name: "K04 copy through dot star", command: `cp a.txt .*/authorized_keys`, block: true},
		{name: "K05 dotglob then star", command: `shopt -s dotglob; cp a.txt */authorized_keys`, block: true},
		{name: "K06 star selects a junction to .ssh", command: `cp a.txt */authorized_keys`, block: true, alias: true},
	}
	for _, managed := range []bool{true, false} {
		for _, header := range []bool{true, false} {
			for _, row := range rows {
				name := row.name
				if managed {
					name = "managed/" + name
				} else {
					name = "per-user/" + name
				}
				if !header {
					name += "/no-header"
				}
				t.Run(name, func(t *testing.T) {
					home := t.TempDir()
					keys := filepath.Join(home, ".ssh", "authorized_keys")
					for _, dir := range []string{filepath.Dir(keys), filepath.Join(home, "Documents"), filepath.Join(home, "Cookies")} {
						if err := os.MkdirAll(dir, 0o700); err != nil {
							t.Fatal(err)
						}
					}
					for file, body := range map[string]string{keys: "k\n", filepath.Join(home, "a.txt"): "x\n"} {
						if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					cookies := filepath.Join(home, "Cookies")
					if out, err := exec.Command("icacls", cookies, "/deny", "*S-1-1-0:(RD)").CombinedOutput(); err != nil {
						t.Fatalf("icacls: %v %s", err, out)
					}
					t.Cleanup(func() { _ = exec.Command("icacls", cookies, "/remove:d", "*S-1-1-0").Run() })
					locked, err := windows.CreateFile(windows.StringToUTF16Ptr(filepath.Join(home, "NTUSER.DAT")),
						windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.CREATE_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = windows.CloseHandle(locked) })
					if row.alias {
						// A junction: an account without the link privilege
						// can make one.
						if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(home, "keysdir"), filepath.Dir(keys)).CombinedOutput(); err != nil {
							t.Fatalf("junction: %v %s", err, out)
						}
					}
					if !row.block {
						if directory, err := os.Open(cookies); err == nil {
							_, readErr := directory.Readdirnames(1)
							_ = directory.Close()
							if readErr == nil || errors.Is(readErr, io.EOF) {
								t.Skip("this process lists a folder that denies listing to Everyone (backup privilege)")
							}
						}
					}
					t.Setenv("HOME", home)
					t.Setenv("USERPROFILE", home)
					payload := mustJSON(t, map[string]any{"session_id": "managed-home-glob", "hook_event_name": "PreToolUse",
						"cwd": home, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_glob",
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
						t.Fatalf("managed=%v %q at the profile: block=%v, want %v: %.400s", managed, row.command, blocked, row.block, got)
					}
				})
			}
		}
	}
}
