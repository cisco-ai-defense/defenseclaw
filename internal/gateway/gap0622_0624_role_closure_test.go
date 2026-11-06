// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestReviewG622Round2RoleClosure(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	rows := []struct {
		name, command, want string
	}{
		{"reported-diff", `diff ~/.ssh/authorized_keys a.txt | head -5`, "allow"},
		{"reported-echo", `echo reminder: check ~/.ssh/authorized_keys`, "allow"},
		{"near-md5sum", `md5sum ~/.ssh/authorized_keys`, "allow"},
		{"near-b2sum", `b2sum ~/.ssh/authorized_keys`, "allow"},
		{"near-sort", `sort ~/.ssh/authorized_keys`, "allow"},
		{"near-file", `file ~/.ssh/authorized_keys`, "allow"},
		{"near-awk", `awk '{print $1}' ~/.ssh/authorized_keys`, "allow"},
		{"near-node-module-alias", `node -e 'require("node:fs").writeFileSync("/tmp/report.txt", "~/.ssh/authorized_keys")'`, "allow"},
		{"near-node-encoding-option", `node -e 'require("fs").writeFileSync("/tmp/report.txt", "~/.ssh/authorized_keys", "utf8")'`, "allow"},
		{"near-node-bound-fs", `node -e 'const fs=require("fs"); fs.writeFileSync("/tmp/report.txt", "~/.ssh/authorized_keys")'`, "allow"},
		{"near-node-append-option", `node -e 'require("fs").appendFileSync("/tmp/log", "~/.ssh/authorized_keys", {encoding:"utf8"})'`, "allow"},
		{"near-node-ordinary-dotdot-name", `node -e 'require("fs").writeFileSync(process.env.HOME + "/report..json", "~/.ssh/authorized_keys")'`, "allow"},
		{"near-node-backtick-data", "node -e 'require(\"fs\").writeFileSync(\"/tmp/report.txt\", `~/.ssh/authorized_keys`)'", "allow"},
		{"near-printf-log", `printf '%s\n' '~/.ssh/authorized_keys' >> ~/app.log`, "allow"},
		{"near-echo-stat-log", `echo "checked $(stat ~/.ssh/authorized_keys) permissions" >> ~/app.log`, "allow"},
		{"protected-direct-source", `cp ~/.ssh/authorized_keys report.txt`, "block"},
		{"protected-link-source", `cp disklink report.txt`, "block"},
		{"protected-known-link-source", `src=disklink; cp "$src" report.txt`, "block"},
		{"protected-known-link-source-dashdash", `src=disklink; cp -- "$src" report.txt`, "block"},
		{"protected-known-source-dashdash", `src=~/.ssh/authorized_keys; cp -- "$src" report.txt`, "block"},
		{"protected-target-directory-copy", `cp -t build ~/.ssh/authorized_keys`, "block"},
		{"protected-ssh-directory-source", `cp -r ~/.ssh build`, "block"},
		{"protected-dd-source", `dd if=disklink of=report.txt`, "block"},
		{"protected-dd-known-link-source", `src=disklink; dd if="$src" of=report.txt`, "block"},
		{"protected-dd-known-source", `src=~/.ssh/authorized_keys; dd if="$src" of=report.txt`, "block"},
		{"protected-link-destination", `cp a.txt disklink`, "block"},
		{"protected-known-destination", `f=~/.ssh/authorized_keys; echo marker >> "$f"`, "block"},
		{"protected-known-link-destination", `f=disklink; cat a.txt > "$f"`, "block"},
		{"protected-dd-known-link-destination", `dst=disklink; dd if=a.txt of="$dst"`, "block"},
		{"protected-node-direct", `node -e 'require("fs").writeFileSync(process.env.HOME + "/.ssh/authorized_keys", "marker")'`, "block"},
		{"protected-node-module-alias", `node -e 'require("node:fs").writeFileSync(process.env.HOME + "/.ssh/authorized_keys", "marker")'`, "block"},
		{"protected-node-encoding-option", `node -e 'require("fs").writeFileSync(process.env.HOME + "/.ssh/authorized_keys", "marker", "utf8")'`, "block"},
		{"protected-read-combo", `sort ~/.ssh/authorized_keys; echo marker >> ~/.ssh/authorized_keys`, "block"},
		{"protected-nested-known-target", `md5sum ~/.ssh/authorized_keys; (cd ~/.ssh; echo marker >> authorized_keys)`, "block"},
		{"protected-node-combo", `node -e 'require("fs").writeFileSync("/tmp/report.txt", "~/.ssh/authorized_keys")'; echo marker >> ~/.ssh/authorized_keys`, "block"},
	}
	rows = append(rows,
		struct{ name, command, want string }{"protected-node-HOME-override", `HOME=` + home + `/.ssh node -e 'require("fs").writeFileSync(process.env.HOME + "/authorized_keys", "marker")'`, "block"},
		struct{ name, command, want string }{"protected-node-env-HOME-override", `env HOME=` + home + `/.ssh node -e 'require("fs").writeFileSync(process.env.HOME + "/authorized_keys", "marker")'`, "block"},
	)
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, row := range rows {
				t.Run(fmt.Sprintf("%s/managed=%t/%s", connector, managed, row.name), func(t *testing.T) {
					got := postDynamicWordParity(t, home, project, connector, managed, row.command, nil)
					action := "other"
					if strings.HasPrefix(got, `{"action":"allow"`) {
						action = "allow"
					}
					if strings.HasPrefix(got, `{"action":"block"`) {
						action = "block"
					}
					t.Logf("CELL %s managed=%t %s action=%s want=%s keys_rule=%t", connector, managed, row.name, action, row.want, strings.Contains(got, "persistence.ssh_authorized_keys_command"))
					if action != row.want {
						t.Errorf("%s = %.300s, want %s", row.name, got, row.want)
					}
				})
			}
		}
	}

}

func TestReviewG622ProtectedEveryProfile(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	commands := []string{
		`cp ~/.ssh/authorized_keys report.txt`,
		`cp disklink report.txt`,
		`src=disklink; cp -- "$src" report.txt`,
		`f=disklink; cat a.txt > "$f"`,
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, pack := range []string{"", "permissive", "strict"} {
				for i, command := range commands {
					t.Run(fmt.Sprintf("%s/managed=%t/pack=%s/row=%d", connector, managed, pack, i), func(t *testing.T) {
						cfg := &config.Config{}
						cfg.Guardrail.Mode, cfg.Guardrail.Connector, cfg.Guardrail.RulePack = "action", connector, pack
						api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
						body := mustJSON(t, map[string]any{"session_id": "review-g622-r2", "hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": project, "tool_input": map[string]any{"command": command, "description": "d"}})
						req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
						if connector == "codex" {
							setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
						}
						if managed {
							req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
							req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
						}
						out := httptest.NewRecorder()
						api.handleAgentHook(connector).ServeHTTP(out, req)
						got := out.Body.String()
						action := "other"
						if strings.HasPrefix(got, `{"action":"allow"`) {
							action = "allow"
						}
						if strings.HasPrefix(got, `{"action":"block"`) {
							action = "block"
						}
						t.Logf("PROFILE %s managed=%t pack=%s row=%d action=%s keys_rule=%t", connector, managed, pack, i, action, strings.Contains(got, "persistence.ssh_authorized_keys_command"))
						if action != "block" {
							t.Errorf("protected operand = %.300s, want block", got)
						}
					})
				}
			}
		}
	}
}

// A project program can have the basename of a stock reader while writing
// its argument. The hook must not treat that basename as a read-only proof.
func TestReviewG622ProjectReaderBasename(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	for _, name := range []string{"cmp", "sed", "git", "env"} {
		path := filepath.Join(project, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nfor arg in \"$@\"; do case \"$arg\" in */.ssh/authorized_keys) echo marker >> \"$arg\";; esac; done\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, row := range []struct{ name, command string }{
				{"cmp", `./cmp ~/.ssh/authorized_keys`},
				{"env-cmp", `env -i ./cmp ~/.ssh/authorized_keys`},
				{"project-env", `./env -i cmp ~/.ssh/authorized_keys`},
				{"sed", `./sed -n '1p' ~/.ssh/authorized_keys`},
				{"git", `./git diff --no-index ~/.ssh/authorized_keys a.txt`},
			} {
				t.Run(fmt.Sprintf("%s/managed=%t/%s", connector, managed, row.name), func(t *testing.T) {
					got := postDynamicWordParity(t, home, project, connector, managed, row.command, nil)
					action := "other"
					if strings.HasPrefix(got, `{"action":"allow"`) {
						action = "allow"
					}
					if strings.HasPrefix(got, `{"action":"block"`) {
						action = "block"
					}
					t.Logf("BASENAME %s managed=%t %s action=%s keys_rule=%t", connector, managed, row.name, action, strings.Contains(got, "persistence.ssh_authorized_keys_command"))
					if action != "block" {
						t.Errorf("project executable with protected operand = %.300s, want block", got)
					}
				})
			}
		}
	}
}
