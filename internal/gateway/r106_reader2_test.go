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
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// r106Reader2Row is one Bash call of the action-mode keys reader rows: run
// in the project or the home folder, with the verdict both a per-user and a
// managed gateway must give. {P} is the project, {K} the keys file; the
// project holds keylink, a link to the keys file.
type r106Reader2Row struct {
	name, where, command, want string
}

// r106Reader2Check runs each row through a per-user action-mode gateway and
// a managed one (home hidden, the real hook client header), for Claude Code
// and Codex.
func r106Reader2Check(t *testing.T, rows []r106Reader2Row) {
	t.Helper()
	for _, connector := range []string{"claudecode", "codex"} {
		for _, row := range rows {
			f := newB36ManagedHookFixture(t)
			for _, name := range []string{"a.txt", "README.md"} {
				if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cwd := f.project
			if row.where == "home" {
				cwd = f.home
			}
			command := strings.NewReplacer("{P}", f.project, "{K}", f.keys).Replace(row.command)
			payload := mustJSON(t, map[string]any{"session_id": "r106", "hook_event_name": "PreToolUse", "cwd": cwd,
				"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_r106",
				"tool_input": map[string]any{"command": command, "description": "Run test fixture command"}})
			header := f.clientHeader(t, payload)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
			req.Header.Set(hookpaths.Header, header)
			if connector == "codex" {
				setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
			}
			recorder := httptest.NewRecorder()
			api.handleAgentHook(connector).ServeHTTP(recorder, req)
			perUser := "allow"
			if body := recorder.Body.String(); strings.Contains(body, `"deny"`) || strings.Contains(body, `"block"`) {
				perUser = "block"
			}
			managed := f.post(t, connector, payload, header)
			if err := os.Chmod(f.homes, 0o700); err != nil {
				t.Fatal(err)
			}
			if perUser != row.want || managed != row.want {
				t.Errorf("%s %s: per-user %s, managed %s, want %s", connector, row.name, perUser, managed, row.want)
			}
		}
	}
}

// TestR106PythonLiteralLinkIsReadAsLn: os.link or os.symlink with two string
// literals in python -c code that imports os makes the link ln makes, so an
// append through the new name of a project file is an ordinary write and
// one through a new name of the keys file a key write (rel-1-0-6:GAP-0157).
func TestR106PythonLiteralLinkIsReadAsLn(t *testing.T) {
	r106Reader2Check(t, []r106Reader2Row{
		{"absolute hard link of a project file", "project", `python3 -c "import os; os.link('{P}/README.md','{P}/kl'); open('{P}/kl','a').write('k')"`, "allow"},
		{"relative hard link of a project file", "project", `python3 -c "import os; os.link('README.md','kl'); open('kl','a').write('k')"`, "allow"},
		{"symbolic link to a project file", "project", `python3 -c "import os; os.symlink('README.md','{P}/kl'); open('{P}/kl','a').write('k')"`, "allow"},
		{"hard link of the keys file", "project", `python3 -c "import os; os.link('{K}','{P}/kl'); open('{P}/kl','a').write('k')"`, "block"},
		{"hard link through the keys link", "project", `python3 -c "import os; os.link('{P}/keylink','{P}/kl'); open('{P}/kl','a').write('k')"`, "block"},
		{"relative symbolic link to the keys file", "project", `python3 -c "import os; os.symlink('../.ssh/authorized_keys','kl'); open('kl','a').write('k')"`, "block"},
		{"computed link source", "project", `python3 -c "import os; s='{K}'; os.link(s,'kl'); open('kl','a').write('k')"`, "block"},
	})
}

// TestR106DiscardRedirectKeepsAReadOnlyCommand: a read whose only redirect
// sends output to /dev/null or copies a descriptor writes no file, so from
// the home folder a */* read that skips dot names stays allowed, as it is
// without the redirect (rel-1-0-6:GAP-0160).
func TestR106DiscardRedirectKeepsAReadOnlyCommand(t *testing.T) {
	r106Reader2Check(t, []r106Reader2Row{
		{"head of */* with stderr discarded, piped", "home", `head -n 1 */* 2>/dev/null | wc -l`, "allow"},
		{"head of */* without the redirect", "home", `head -n 1 */* | wc -l`, "allow"},
		{"cat of */* with stderr discarded", "home", `cat */* 2>/dev/null`, "allow"},
		{"ls of */* with stderr discarded", "home", `ls */* 2>/dev/null`, "allow"},
		{"wc of */* with stdout discarded", "home", `wc -l */* > /dev/null`, "allow"},
		{"head of */* with stderr copied", "home", `head */* 2>&1`, "allow"},
		{"append to the keys file after a discard", "home", `echo x 2>/dev/null >> .ssh/authorized_keys`, "block"},
		{"read redirected onto the keys file", "home", `head -n 1 */* > .ssh/authorized_keys`, "block"},
		{"read appended onto the keys file", "home", `head */* 2>/dev/null >> .ssh/authorized_keys`, "block"},
		{"tee into */* reaches the keys link", "home", `tee -a */* < project/README.md 2>/dev/null`, "block"},
		{"copy onto the keys file", "home", `cp project/README.md .*/authorized_keys 2>/dev/null`, "block"},
	})
}

// TestR106MoveWithBackupOntoKeysLinkReplacesTheLink: a GNU mv with a backup
// option onto an existing project link to the keys file renames the link
// to its backup name and writes nothing to the keys file, as a plain mv onto
// the link does (rel-1-0-6:GAP-0144). A write through the link, or through
// its backup name, still writes the keys file.
func TestR106MoveWithBackupOntoKeysLinkReplacesTheLink(t *testing.T) {
	r106Reader2Check(t, []r106Reader2Row{
		{"plain mv onto the link", "project", `mv a.txt keylink`, "allow"},
		{"backup=simple", "project", `mv --backup=simple a.txt keylink`, "allow"},
		{"backup=numbered with a suffix", "project", `mv --backup=numbered --suffix=.old a.txt keylink`, "allow"},
		{"-b with -S", "project", `mv -b -S .bak a.txt keylink`, "allow"},
		{"-b", "project", `mv -b a.txt keylink`, "allow"},
		{"backup onto the keys file", "project", `mv --backup=simple a.txt ~/.ssh/authorized_keys`, "block"},
		{"backup into .ssh", "project", `mv -b a.txt ~/.ssh/`, "block"},
		{"backup into .ssh with -t", "project", `mv --backup=simple -t ~/.ssh a.txt`, "block"},
		{"move the link then write", "project", `mv -b keylink k2; echo x >> k2`, "block"},
		{"write through the default backup name", "project", `mv -b a.txt keylink; echo x >> keylink~`, "block"},
		{"write through a suffix backup name", "project", `mv --backup=simple --suffix=.bak a.txt keylink; echo x >> keylink.bak`, "block"},
		{"write through a numbered backup name", "project", `mv --backup=numbered a.txt keylink; echo x >> keylink.~1~`, "block"},
	})
}

// TestR106PowerShellListingOfSSHIsARead: a pwsh -Command body that only
// lists names (Get-ChildItem, ls, Test-Path, Select-Object ...) reads, as an
// ls of ~/.ssh does; a body with any writer, redirect or other syntax keeps
// the target reading (rel-1-0-6:GAP-0145).
func TestR106PowerShellListingOfSSHIsARead(t *testing.T) {
	r106Reader2Check(t, []r106Reader2Row{
		{"Get-ChildItem", "project", `pwsh -NoProfile -Command "Get-ChildItem ~/.ssh"`, "allow"},
		{"Get-ChildItem piped to Select-Object", "project", `pwsh -Command "Get-ChildItem -Force ~/.ssh | Select-Object Name"`, "allow"},
		{"ls", "project", `pwsh -NoProfile -Command "ls ~/.ssh"`, "allow"},
		{"Test-Path", "project", `pwsh -NoProfile -Command "Test-Path ~/.ssh"`, "allow"},
		{"Add-Content to the keys file", "project", `pwsh -NoProfile -Command "Add-Content -Path ~/.ssh/authorized_keys -Value k"`, "block"},
		{"listing then Set-Content", "project", `pwsh -NoProfile -Command "Get-ChildItem ~/.ssh; Set-Content ~/.ssh/authorized_keys k"`, "block"},
		{"Copy-Item onto the keys file", "project", `pwsh -NoProfile -Command "Copy-Item notes.txt ~/.ssh/authorized_keys"`, "block"},
		{"listing piped to Remove-Item", "project", `pwsh -NoProfile -Command "Get-ChildItem ~/.ssh | Remove-Item"`, "block"},
		{"New-Item in .ssh", "project", `pwsh -NoProfile -Command "New-Item -ItemType File ~/.ssh/authorized_keys2"`, "block"},
		{"listing redirected onto the keys file", "project", `pwsh -NoProfile -Command "Get-ChildItem ~/.ssh > ~/.ssh/authorized_keys"`, "block"},
		{"listing with a subexpression", "project", `pwsh -NoProfile -Command "Get-ChildItem $(Set-Content ~/.ssh/authorized_keys k)"`, "block"},
		{"listing with sort", "project", `pwsh -NoProfile -Command "Get-ChildItem ~/.ssh | sort -o ~/.ssh/authorized_keys"`, "block"},
	})
}
