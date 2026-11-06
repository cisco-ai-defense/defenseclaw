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
)

// claudeBashParityRow is one Claude Code Bash call judged by a per-user
// action-mode gateway. {H} is the home, {P} the project (forward slashes),
// {PB} the project with backslashes and {M} the project as Git Bash spells a
// drive (/c/...). windowsOnly rows spell what only Windows reads.
type claudeBashParityRow struct {
	name, command string
	block         bool
	windowsOnly   bool
}

// judgeClaudeBashParityRows runs rows through the Claude Code hook of a
// per-user action-mode gateway in a project that holds a.txt, src/a.txt,
// ordinary/n.txt and alias, a link to the keys file. The same rows give the
// same verdict on Linux, macOS and Windows (Git Bash runs the Bash tool).
func judgeClaudeBashParityRows(t *testing.T, rows []claudeBashParityRow) {
	t.Helper()
	home := t.TempDir()
	project := filepath.Join(home, "project")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, dir := range []string{filepath.Dir(keys), filepath.Join(project, "src"), filepath.Join(project, "ordinary")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{keys: "k\n", filepath.Join(project, "a.txt"): "x\n",
		filepath.Join(project, "src", "a.txt"): "x\n", filepath.Join(project, "ordinary", "n.txt"): "x\n"} {
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(keys, filepath.Join(project, "alias")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	slashProject := filepath.ToSlash(project)
	msysProject := slashProject
	if len(slashProject) > 2 && slashProject[1:2] == ":" {
		msysProject = "/" + strings.ToLower(slashProject[:1]) + slashProject[2:]
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if row.windowsOnly && runtime.GOOS != "windows" {
				t.Skip("a Windows spelling")
			}
			command := strings.NewReplacer("{H}", filepath.ToSlash(home), "{PB}", filepath.FromSlash(project),
				"{P}", slashProject, "{M}", msysProject).Replace(row.command)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			store, logger := testStoreAndLogger(t)
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
			body := string(mustJSON(t, map[string]any{"session_id": "bash-parity", "hook_event_name": "PreToolUse",
				"tool_name": "Bash", "cwd": project, "tool_input": map[string]string{"command": command}}))
			req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			api.handleAgentHook("claudecode").ServeHTTP(recorder, req)
			got := recorder.Body.String()
			blocked := strings.Contains(got, `"action":"block"`)
			if blocked != row.block {
				t.Fatalf("%q: block=%v, want %v: %.400s", command, blocked, row.block, got)
			}
			if row.block && !strings.Contains(got, "persistence.ssh_authorized_keys_command") {
				t.Fatalf("%q: blocked by another rule: %.400s", command, got)
			}
		})
	}
}

// A GNU mv with a backup option onto a project link to the keys file
// renames the link to its backup name; a write through that name in the
// same command writes the keys file (rel-1-0-6:GAP-0144, TGT-0015). On
// Windows the write through the backup name was allowed.
func TestClaudeBashMoveWithBackupOntoKeysLinkMatchesAcrossOS(t *testing.T) {
	judgeClaudeBashParityRows(t, []claudeBashParityRow{
		{name: "plain mv onto the link", command: `mv a.txt alias`},
		{name: "backup=simple", command: `mv --backup=simple a.txt alias`},
		{name: "-b with -S", command: `mv -b -S .bak a.txt alias`},
		{name: "-b", command: `mv -b a.txt alias`},
		{name: "backup=numbered with a suffix", command: `mv --backup=numbered --suffix=.old a.txt alias`},
		{name: "write to another name after the move", command: `mv -b a.txt alias; echo x >> notes.txt`},
		{name: "write through the link", command: `echo k >> alias`, block: true},
		{name: "backup onto the keys file", command: `mv --backup=simple a.txt ~/.ssh/authorized_keys`, block: true},
		{name: "write through the default backup name", command: `mv -b a.txt alias; echo x >> alias~`, block: true},
		{name: "write through the default backup name after &&", command: `mv -b a.txt alias && echo k >> alias~`, block: true},
		{name: "write through a suffix backup name", command: `mv --backup=simple --suffix=.bak a.txt alias; echo x >> alias.bak`, block: true},
		{name: "write through a numbered backup name", command: `mv --backup=numbered a.txt alias; echo x >> alias.~1~`, block: true},
		{name: "move the link then write", command: `mv -b alias k2; echo x >> k2`, block: true},
		{name: "case form of the backup name", command: `mv -b a.txt alias; echo x >> ALIAS~`, block: true, windowsOnly: true},
		{name: "drive path of the backup name", command: `mv -b a.txt alias; echo x >> {P}/alias~`, block: true, windowsOnly: true},
		{name: "Git Bash drive of the backup name", command: `mv -b a.txt alias; echo x >> {M}/alias~`, block: true, windowsOnly: true},
		{name: "Git Bash drive of the moved link", command: `mv -b a.txt {M}/alias; echo x >> {M}/alias~`, block: true, windowsOnly: true},
	})
}

// After pushd DIR a recursive copy or rsync of a project folder spelled
// with a directory-stack word reads the word as the directory the stack
// holds (rel-1-0-4:GAP-2586); copies into or out of ~/.ssh still block. On
// Windows the rsync forms blocked.
func TestClaudeBashDirectoryStackCopyMatchesAcrossOS(t *testing.T) {
	judgeClaudeBashParityRows(t, []claudeBashParityRow{
		{name: "pushd rsync stack folder", command: `pushd src && rsync -a ~1/ordinary/ out/`},
		{name: "pushd rsync stack folder no slash", command: `pushd src && rsync -a ~1/ordinary out/`},
		{name: "pushd rsync stack src", command: `pushd src && rsync -a ~1/src out/`},
		{name: "pushd rsync plus stack word", command: `pushd src && rsync -a ~+1/ordinary/ out/`},
		{name: "pushd rsync oldpwd", command: `pushd src && rsync -a ~-/ordinary/ out/`},
		{name: "cd rsync oldpwd", command: `cd src && rsync -a ~-/ordinary/ out/`},
		{name: "pushd rsync dotdot", command: `pushd src && rsync -a ../ordinary/ out/`},
		{name: "pushd cp stack folder", command: `pushd src && cp -r ~1/ordinary ord2`},
		{name: "cd cp oldpwd", command: `cd src && cp -r ~-/ordinary x`},
		{name: "pushd rsync into .ssh", command: `pushd src && rsync -a ~1/ordinary/ ~/.ssh/`, block: true},
		{name: "pushd cp into .ssh", command: `pushd src && cp -r ~1/ordinary ~/.ssh/`, block: true},
		{name: "pushd rsync onto the keys file", command: `pushd src && rsync -a ~1/a.txt ~/.ssh/authorized_keys`, block: true},
		{name: "pushd rsync through the link", command: `pushd src && rsync -a ~1/a.txt ~1/alias`, block: true},
		{name: "rsync out of .ssh by the stack", command: `pushd ~/.ssh && pushd ~/project && rsync -a ~1/ k/`, block: true},
		{name: "cp out of .ssh by the stack", command: `pushd ~/.ssh && pushd ~/project && cp -r ~1 k`, block: true},
		{name: "rsync after a cd that may fail", command: `cd /nonexistent-zz && true; rsync -a ~-/ x/`, block: true},
	})
}

// A pwsh or powershell -Command body that only lists names reads, as an ls
// of ~/.ssh does (rel-1-0-6:GAP-0145); any writer, redirect or other syntax
// in the body keeps the check. On Windows the listing blocked.
func TestClaudeBashPowerShellListingOfSSHMatchesAcrossOS(t *testing.T) {
	judgeClaudeBashParityRows(t, []claudeBashParityRow{
		{name: "Get-ChildItem", command: `pwsh -NoProfile -Command "Get-ChildItem ~/.ssh"`},
		{name: "Get-ChildItem piped to Select-Object", command: `pwsh -Command "Get-ChildItem -Force ~/.ssh | Select-Object Name"`},
		{name: "Test-Path", command: `pwsh -Command "Test-Path ~/.ssh/authorized_keys"`},
		{name: "powershell ls", command: `powershell -Command "ls ~/.ssh"`},
		{name: "drive path with slashes", command: `pwsh -NoProfile -Command "Get-ChildItem {H}/.ssh"`, windowsOnly: true},
		{name: "drive path with backslashes", command: `pwsh -NoProfile -Command "Get-ChildItem {PB}\..\.ssh"`, windowsOnly: true},
		{name: "case form", command: `pwsh -NoProfile -Command "get-childitem ~/.SSH"`, windowsOnly: true},
		{name: "Add-Content to the keys file", command: `pwsh -NoProfile -Command "Add-Content -Path ~/.ssh/authorized_keys -Value k"`, block: true},
		{name: "listing then Set-Content", command: `pwsh -NoProfile -Command "Get-ChildItem ~/.ssh; Set-Content ~/.ssh/authorized_keys k"`, block: true},
		{name: "Copy-Item onto the keys file", command: `pwsh -NoProfile -Command "Copy-Item notes.txt ~/.ssh/authorized_keys"`, block: true},
		{name: "listing piped to Remove-Item", command: `pwsh -NoProfile -Command "Get-ChildItem ~/.ssh | Remove-Item"`, block: true},
		{name: "New-Item in .ssh", command: `pwsh -NoProfile -Command "New-Item -ItemType File ~/.ssh/authorized_keys2"`, block: true},
		{name: "listing redirected onto the keys file", command: `pwsh -NoProfile -Command "Get-ChildItem ~/.ssh > ~/.ssh/authorized_keys"`, block: true},
		{name: "listing with a subexpression", command: `pwsh -NoProfile -Command "Get-ChildItem $(Set-Content ~/.ssh/authorized_keys k)"`, block: true},
		{name: "listing with sort", command: `pwsh -NoProfile -Command "Get-ChildItem ~/.ssh | sort -o ~/.ssh/authorized_keys"`, block: true},
		{name: "backslash before a statement end", command: `pwsh -NoProfile -Command "Get-ChildItem x\; Set-Content ~/.ssh/authorized_keys k"`, block: true},
		{name: "Set-Content by a backslash drive path", command: `pwsh -NoProfile -Command "Set-Content {PB}\..\.ssh\authorized_keys k"`, block: true, windowsOnly: true},
	})
}
