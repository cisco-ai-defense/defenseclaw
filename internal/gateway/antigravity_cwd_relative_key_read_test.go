// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The hook table uses POSIX homes, paths and commands.

//go:build !windows

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// antigravityKeyReadHook sends one agy run_command PreToolUse body to
// /api/v1/antigravity/hook in action mode, from a managed host's peer (the
// gateway runs as its service account) when managed is set, else per-user.
func antigravityKeyReadHook(t *testing.T, managed bool, home, workspace string, args map[string]any) map[string]any {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"conversationId": "session-agy-key-read", "stepIdx": 1, "workspacePaths": []string{workspace},
		"toolCall": map[string]any{"name": "run_command", "args": args},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "antigravity"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/antigravity/hook", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Antigravity-Event", "PreToolUse")
	if managed {
		service := filepath.Join(filepath.Dir(home), "service")
		if err := os.MkdirAll(service, 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("HOME", service)
		t.Setenv("USERPROFILE", service)
		req = req.WithContext(withManagedHookPeer(withServiceAccountGateway(req.Context()),
			managedHookPeer{UID: 1001, GID: 1001, Name: "agyfx", Home: home}))
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook("antigravity").ServeHTTP(recorder, req)
	var resp map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("hook response %q: %v", recorder.Body.String(), err)
	}
	return resp
}

// TestAntigravityCwdRelativeKeyReadBlocksOnBothRoutes pins rel-1-0-2:GAP-0694
// (managed Antigravity parity): an agy run_command that reads the SSH
// private key by a path relative to its Cwd argument, or to the workspace
// when it names no Cwd, is the same read as the absolute path, per-user and
// from a managed peer. The managed route resolved the operand against the
// service account's directory, so the read was allowed there.
func TestAntigravityCwdRelativeKeyReadBlocksOnBothRoutes(t *testing.T) {
	for _, managed := range []bool{false, true} {
		route := "per-user"
		if managed {
			route = "managed"
		}
		for _, row := range []struct {
			name, command, cwd string // cwd: "ssh", "proj" or "" (no Cwd argument)
			workspace          string // "ssh" or "proj"
			block              bool
		}{
			{"cwd-ssh/bare", "cat id_rsa", "ssh", "proj", true},
			{"cwd-ssh/dot", "cat ./id_rsa", "ssh", "proj", true},
			{"cwd-ssh/ed25519", "cat id_ed25519", "ssh", "proj", true},
			{"cwd-proj/parent", "cat ../.ssh/id_rsa", "proj", "proj", true},
			{"no-cwd/workspace-ssh", "cat id_rsa", "", "ssh", true},
			{"cwd-ssh/absolute", "cat ~/.ssh/id_rsa", "ssh", "proj", true},
			// Hard negatives: the same reads of project files allow.
			{"benign/cwd-proj", "cat README.md", "proj", "proj", false},
			{"benign/no-cwd", "cat README.md", "", "proj", false},
			{"benign/public-key", "cat id_rsa.pub", "ssh", "proj", false},
		} {
			for _, extra := range []bool{false, true} {
				name := route + "/" + row.name
				if extra {
					name += "/unknown-key"
				}
				t.Run(name, func(t *testing.T) {
					root := t.TempDir()
					home := filepath.Join(root, "home")
					dirs := map[string]string{"ssh": filepath.Join(home, ".ssh"), "proj": filepath.Join(home, "proj")}
					for _, dir := range dirs {
						if err := os.MkdirAll(dir, 0o700); err != nil {
							t.Fatal(err)
						}
					}
					for _, f := range []string{filepath.Join(dirs["ssh"], "id_rsa"), filepath.Join(dirs["ssh"], "id_ed25519"),
						filepath.Join(dirs["ssh"], "id_rsa.pub"), filepath.Join(dirs["proj"], "README.md")} {
						if err := os.WriteFile(f, []byte("inert test fixture\n"), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					t.Setenv("HOME", home)
					t.Setenv("USERPROFILE", home)
					t.Chdir(dirs["proj"])
					args := map[string]any{"CommandLine": strings.ReplaceAll(row.command, "~", home)}
					if row.command == "cat ~/.ssh/id_rsa" {
						args["CommandLine"] = row.command
					}
					if row.cwd != "" {
						args["Cwd"] = dirs[row.cwd]
					}
					if extra {
						args["zzz"] = 1
					}
					if managed {
						// The managed gateway's service account cannot enter
						// the user's home (0700 on a managed host).
						if err := os.Chmod(home, 0o000); err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
					}
					resp := antigravityKeyReadHook(t, managed, home, dirs[row.workspace], args)
					raw, _ := json.Marshal(resp)
					if blocked := resp["action"] == "block"; blocked != row.block {
						t.Fatalf("blocked = %t, want %t: %.900s", blocked, row.block, raw)
					}
				})
			}
		}
	}
}
