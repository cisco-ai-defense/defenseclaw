// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestR107WindowsManagedLinkFormsCorpus: the vsweep8 managed Windows forms
// (rel-1-0-6:GAP-0284, GAP-0285, GAP-0288) in all 4 cells (Claude Code and
// Codex, per user and managed with the hook client's header).
func TestR107WindowsManagedLinkFormsCorpus(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "project")
	ext := filepath.Join(root, "fcext")
	ok := filepath.Join(ext, "ok")
	state := filepath.Join(home, ".defenseclaw")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, dir := range []string{filepath.Dir(keys), filepath.Join(project, "src"), ok, state} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{keys, filepath.Join(state, "config.yaml"), filepath.Join(ok, "a.txt"), filepath.Join(project, "a.txt")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(state, filepath.Join(ext, "y")); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", filepath.Join(project, "keylink"), keys).CombinedOutput(); err != nil {
		t.Fatalf("keylink: %v %s", err, out)
	}
	if err := os.Symlink(state, filepath.Join(project, "dclink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	okWin := strings.ReplaceAll(ok, `\`, `\\`)
	// sshBody survives both parses of a bash -lc "..." body (the outer
	// double quotes, then the unquoted word in the body): mklink gets the
	// absolute .ssh folder.
	sshBody := strings.ReplaceAll(filepath.Dir(keys), `\`, `\\\\`)
	yConfig := filepath.Join(ext, "y", "config.yaml")
	rows := []struct {
		id, cwd, command string
		block            bool
		connectors       []string
		// perUser: the state rows run per user only; the managed state
		// reading is the service's and is checked live (IN-bd-cparchive.md).
		perUser bool
	}{
		// GAP-0284: a junction made inside bash -lc. Git Bash drops the
		// unquoted backslashes of the body, so mklink gets C:dir, a
		// drive-relative target it resolves from the working directory.
		{"J4c", project, `bash -lc "cmd //c mklink /J L4 ` + okWin + ` && echo k >> L4/ok.txt"`, false, nil, false},
		{"J4a", project, `bash -lc "cmd //c mklink /J L4 ` + filepath.ToSlash(ok) + ` && echo k >> L4/ok.txt"`, false, nil, false},
		{"J4q", project, `bash -lc "cmd //c mklink /J L4 '` + ok + `' && echo k >> L4/ok.txt"`, false, nil, false},
		{"J4n", project, `bash -lc "cmd //c mklink /J L4 ` + okWin + `"`, false, nil, false},
		{"J4", project, `cmd //c "mklink /J L4 ` + okWin + `" && echo k >> L4/a.txt`, false, []string{"claudecode"}, false},
		{"J4-keys", project, `bash -lc "cmd //c mklink /J L5 ` + sshBody + ` && echo k >> L5/authorized_keys"`, true, nil, false},
		{"J4-keys-quoted", project, `bash -lc "cmd //c mklink /J L5 '` + filepath.Dir(keys) + `' && echo k >> L5/authorized_keys"`, true, nil, false},
		{"J4-other-drive", project, `bash -lc "cmd //c mklink /J L6 D:\\x && echo k >> L6/authorized_keys"`, true, nil, false},
		// Review 4: an up-level drive-relative target (forward slashes survive
		// the body) that mklink resolves from the project to the .ssh decoy
		// folder, as a junction and as a hard link of the keys decoy.
		{"R4-up-junction", project, `bash -lc "cmd //c mklink /J L7 C:../.ssh && echo k >> L7/authorized_keys"`, true, nil, false},
		{"R4-up-junction-ok", project, `bash -lc "cmd //c mklink /J L7 C:../project/src && echo k >> L7/a.txt"`, false, nil, false},
		{"R4-up-hardlink", project, `bash -lc "cmd //c mklink /H L8 C:../.ssh/authorized_keys && echo k >> L8"`, true, nil, false},
		// GAP-0285: a write through a disk link to the state folder. Codex
		// on Windows runs the command as PowerShell, where /c/Users/... is
		// \c\Users\... on the current drive, not the state file: that
		// direct form is not a state write there (by design); the Git Bash
		// spellings it can run (bash -lc) and the drive spellings block.
		{"S1", project, `echo k >> ` + filepath.ToSlash(yConfig), true, nil, true},
		{"S2", project, `echo k >> ` + r107GitBashDrive(yConfig), true, []string{"claudecode"}, true},
		{"S2-codex", project, `echo k >> ` + r107GitBashDrive(yConfig), false, []string{"codex"}, true},
		{"S2-bash", project, `bash -lc "echo k >> ` + r107GitBashDrive(yConfig) + `"`, true, nil, true},
		{"S4", project, `echo k >> ` + strings.ReplaceAll(yConfig, `\`, `\\`), true, nil, true},
		// GAP-0288: env -C ~ and a recursive copy of a project holding a
		// keys link and a state link.
		{"B11", project, `env -C ~ cp -r project project-bak`, false, nil, false},
		{"V5", project, `env -C ~ cp -r project/src src-bak`, false, nil, false},
		{"B11-cd", project, `cd ~ && cp -r project project-bak`, false, []string{"claudecode"}, false},
		{"B11-write", project, `env -C ~ cp -r project project-bak; echo key >> ~/project-bak/keylink`, true, []string{"claudecode"}, false},
	}
	for _, row := range rows {
		connectors := row.connectors
		if connectors == nil {
			connectors = []string{"claudecode", "codex"}
		}
		for _, connector := range connectors {
			installDefaultProfileConnector(t, connector)
			for _, managed := range []bool{false, true} {
				if managed && row.perUser {
					continue
				}
				event := map[string]any{"session_id": "r107-win", "hook_event_name": "PreToolUse", "cwd": row.cwd,
					"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_r107win",
					"tool_input": map[string]any{"command": row.command, "description": "d"}}
				if connector == "codex" {
					event["turn_id"] = "t1"
				}
				payload := mustJSON(t, event)
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = connector
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
				req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connector+"/hook", strings.NewReader(string(payload)))
				req.Header.Set("Content-Type", "application/json")
				if header := hookpaths.ResolveConnector(connector, "", "PreToolUse", payload); header != "" {
					req.Header.Set(hookpaths.Header, header)
				}
				if connector == "codex" {
					setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
				}
				if managed {
					req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
				}
				recorder := httptest.NewRecorder()
				api.handleAgentHook(connector).ServeHTTP(recorder, req)
				body := recorder.Body.String()
				blocked := strings.HasPrefix(body, `{"action":"block"`)
				if blocked != row.block {
					t.Errorf("%s %s managed=%v %q: block=%v, want %v: %.500s", row.id, connector, managed, row.command, blocked, row.block, body)
				}
			}
		}
	}
}

// r107GitBashDrive spells an absolute Windows path as Git Bash does.
func r107GitBashDrive(path string) string {
	path = filepath.ToSlash(path)
	if len(path) > 2 && path[1] == ':' {
		return "/" + strings.ToLower(path[:1]) + path[2:]
	}
	return path
}
