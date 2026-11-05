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
)

// A copy of a project folder that holds a link to the keys file, run in the
// home with env -C, is its own copy destination on Windows as on Linux: the
// bare copy is allowed, a write through the copied link blocks
// (rel-1-0-4:GAP-2579, rel-1-0-6:GAP-0288). The managed Windows hook sends
// no PreToolUse write-target header, so these calls exercise the service
// gateway's own proof with the Codex hook contract and caller identity.
func TestGAP0288ManagedWindowsCodexProjectCopy(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	serviceHome := filepath.Join(root, "service")
	project := filepath.Join(home, "project")
	proj := filepath.Join(home, "proj")
	for _, dir := range []string{serviceHome, filepath.Join(home, ".ssh"), filepath.Join(home, ".defenseclaw"),
		filepath.Join(project, "src"), filepath.Join(proj, "src"), filepath.Join(home, "src"), filepath.Join(home, "ordinary")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(home, ".ssh", "authorized_keys"),
		filepath.Join(project, "a.txt"), filepath.Join(project, "src", "a.txt"),
		filepath.Join(proj, "a.txt"), filepath.Join(proj, "src", "a.txt"),
		filepath.Join(home, "src", "a.txt"), filepath.Join(home, "ordinary", "a.txt")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tree := range []string{project, proj} {
		if err := os.Symlink(filepath.FromSlash("../.ssh/authorized_keys"), filepath.Join(tree, "keylink")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(home, ".defenseclaw"), filepath.Join(tree, "dclink")); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	strictCopyRows := map[string]bool{"B11": true, "V1": true, "V2": true, "V5": true, "V7": true, "V10": true, "V11": true, "V12": true, "V13": true}
	for _, row := range []struct {
		name, cwd, command string
		want               string
		connectors         []string
	}{
		{"B11", project, `env -C ~ cp -r project project-bak`, "allow", nil},
		{"V1", home, `env -C ~ cp -r project project-bak`, "allow", nil},
		{"V2", home, `env -C ` + filepath.ToSlash(home) + ` cp -r project project-bak`, "allow", nil},
		{"V5", project, `env -C ~ cp -r proj proj-bak`, "allow", nil},
		{"V6", project, `env -C ~ cp -r src src-bak`, "allow", nil},
		{"V7", proj, `env -C ~ cp -r proj proj-bak`, "allow", nil},
		{"V8", project, `env -C ~/project cp -r src src-bak`, "allow", nil},
		{"V9", home, `env -C ~ cp -r ordinary ordinary-bak`, "allow", nil},
		{"V10", home, `env --chdir=~ cp -R project project-R-bak`, "allow", nil},
		{"V11", home, `env -C ~ cp -a project project-a-bak`, "allow", nil},
		{"V12", home, `env -C ~ cp -R project project-R2-bak`, "allow", nil},
		{"V13", home, `Copy-Item -Recurse project project-ps-bak`, "allow", nil},
		{"B11-cd", home, `cd ~ && cp -r project project-bak`, "allow", []string{"claudecode"}},
		{"B11-write", project, `env -C ~ cp -r project project-bak; echo key >> ~/project-bak/keylink`, "block", nil},
		{"K00", project, `echo key >> ` + filepath.ToSlash(filepath.Join(home, ".ssh", "authorized_keys")), "block", nil},
		{"K05", project, `env -C ~ cp -r project .ssh/project-bak`, "block", nil},
		{"K06", project, `env -C ~/project ln -sf ../.ssh/authorized_keys ln3; cp a.txt ln3`, "block", []string{"claudecode"}},
	} {
		connectors := row.connectors
		if connectors == nil {
			connectors = []string{"claudecode", "codex"}
		}
		for _, connector := range connectors {
			installDefaultProfileConnector(t, connector)
			tools := []string{"Bash"}
			if connector == "codex" {
				tools = append(tools, "exec_command")
			}
			for _, tool := range tools {
				for _, managed := range []bool{false, true} {
					for _, profile := range []string{"default", "strict"} {
						t.Run(row.name+"/"+connector+"/"+tool+"/"+profile, func(t *testing.T) {
							t.Setenv("HOME", home)
							t.Setenv("USERPROFILE", home)
							toolInput := map[string]string{"command": row.command}
							if tool == "exec_command" {
								toolInput = map[string]string{"cmd": row.command, "workdir": row.cwd}
							}
							event := map[string]any{"session_id": "env-copy", "hook_event_name": "PreToolUse",
								"tool_name": tool, "tool_use_id": "toolu_env_copy", "cwd": row.cwd,
								"tool_input": toolInput}
							if connector == "codex" {
								event["turn_id"] = "t1"
								event["model"] = "x"
							}
							payload := mustJSON(t, event)
							cfg := &config.Config{}
							cfg.Guardrail.Mode = "action"
							cfg.Guardrail.Connector = connector
							cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
							api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
							req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connector+"/hook", strings.NewReader(string(payload)))
							req.Header.Set("Content-Type", "application/json")
							if connector == "codex" {
								setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
							}
							if managed {
								t.Setenv("HOME", serviceHome)
								t.Setenv("USERPROFILE", serviceHome)
								req = req.WithContext(withManagedHookPeer(withServiceAccountGateway(req.Context()), managedHookPeer{Home: home}))
							}
							recorder := httptest.NewRecorder()
							api.handleAgentHook(connector).ServeHTTP(recorder, req)
							body := recorder.Body.String()
							want := row.want
							if profile == "strict" && managed && connector == "codex" && strictCopyRows[row.name] {
								want = "block"
							}
							if recorder.Code != http.StatusOK || !strings.HasPrefix(body, `{"action":"`+want+`"`) {
								t.Errorf("%s %s/%s managed=%v profile=%s %q: status=%d body=%.300s, want %s", row.name, connector, tool, managed, profile, row.command, recorder.Code, body, want)
							}
						})
					}
				}
			}
		}
	}
}
