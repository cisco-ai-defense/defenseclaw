// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed/mcpasuser"
)

// #1164: the enumerator starts a published server as its user only through
// the launchers a scan starts anywhere else, and never a code-running flag
// or a command cmd.exe could reinterpret.
func TestCheckMCPAsUserDefinitionAppliesTheScanLauncherRules(t *testing.T) {
	ok := map[string]config.MCPServerEntry{
		"npx":     {Name: "a", Command: "npx", Args: []string{"-y", ".", "--config", `.\srv.json`}},
		"npx.cmd": {Name: "a", Command: "NPX.cmd", Args: []string{"@scope/pkg"}},
		"uvx":     {Name: "a", Command: "uvx", Args: []string{"mcp-server-time"}},
	}
	for name, entry := range ok {
		if _, err := checkMCPAsUserDefinition(entry); err != nil {
			t.Fatalf("%s refused: %v", name, err)
		}
	}
	refused := map[string]config.MCPServerEntry{
		"url":         {Name: "a", URL: "https://example.test/mcp"},
		"path":        {Name: "a", Command: `C:\Users\u\npx.cmd`, Args: []string{"pkg"}},
		"other":       {Name: "a", Command: "node", Args: []string{"server.js"}},
		"shell":       {Name: "a", Command: "cmd.exe", Args: []string{"/c", "x"}},
		"no package":  {Name: "a", Command: "npx", Args: []string{"-y"}},
		"eval flag":   {Name: "a", Command: "npx", Args: []string{"-c", "calc", "pkg"}},
		"exec= flag":  {Name: "a", Command: "uvx", Args: []string{"--exec=x", "pkg"}},
		"metachar":    {Name: "a", Command: "npx", Args: []string{"pkg&calc"}},
		"percent var": {Name: "a", Command: "npx", Args: []string{"%COMSPEC%"}},
	}
	for name, entry := range refused {
		if _, err := checkMCPAsUserDefinition(entry); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// #1164: the request names a published server and pins its definition; a
// server the user changed after the gateway read it, or one of another
// project, is not started.
func TestFindMCPAsUserServerNeedsTheScannedDefinition(t *testing.T) {
	project := `C:\Users\dcw-std1\proj`
	server := config.MCPServerEntry{Name: "notes", Command: "npx", Args: []string{"-y", "."}, Connector: "claudecode", Project: project}
	other := server
	other.Project = `C:\Users\dcw-std1\other`
	other.Args = []string{"-y", "other"}
	request, err := mcpasuser.NewRequest("DefenseClawGateway", "S-1-5-21-1-2-3-1001", server)
	if err != nil {
		t.Fatal(err)
	}
	found, err := findMCPAsUserServer([]config.MCPServerEntry{other, server}, request)
	if err != nil || found.Project != project {
		t.Fatalf("found %+v, %v", found, err)
	}
	upper := request
	upper.Project = strings.ToUpper(project)
	if _, err := findMCPAsUserServer([]config.MCPServerEntry{server}, upper); err != nil {
		t.Fatalf("project case: %v", err)
	}
	changed := server
	changed.Args = []string{"-y", "evil"}
	if _, err := findMCPAsUserServer([]config.MCPServerEntry{changed}, request); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed definition: %v", err)
	}
	if _, err := findMCPAsUserServer([]config.MCPServerEntry{other}, request); err == nil || !strings.Contains(err.Error(), "not in the MCP servers") {
		t.Fatalf("unpublished server: %v", err)
	}
}

// #1164: the launcher an as-user scan starts is the one the agent would run
// with the server's env, and only a trusted one: a server PATH entry or a
// file in the working folder that puts another npx first, a same-name .bat
// beside it, a relative or network PATH entry before it, and a launcher in a
// user-writable folder all refuse the start.
func TestResolveMCPAsUserLauncherRefusesUntrustedAndShadowed(t *testing.T) {
	const programFiles, npm, work = `C:\Program Files\nodejs`, `C:\Users\u\AppData\Roaming\npm`, `C:\Users\u\proj`
	files := map[string]bool{
		programFiles + `\npx.cmd`: true, programFiles + `\npx`: true, programFiles + `\npx.ps1`: true,
		npm + `\npx.cmd`: true, `C:\Users\u\evil\npx.bat`: true, work + `\tools\npx.cmd`: true,
	}
	fs := mcpAsUserLauncherFS{
		exists: func(path string) bool { return files[path] },
		trusted: func(path string) error {
			if strings.HasPrefix(path, programFiles+`\`) {
				return nil
			}
			return errors.New("it is not under Program Files")
		},
	}
	npx := mcpAsUserLauncher{name: "npx", file: "npx.cmd"}
	if got, err := resolveMCPAsUserLauncher(npx, work, `;"`+programFiles+`\";`+npm, "", fs); err != nil || got != programFiles+`\npx.cmd` {
		t.Fatalf("trusted npx: %q, %v", got, err)
	}
	for _, tc := range []struct{ name, work, path, pathExt, want string }{
		{"server PATH puts a user npx first", work, npm + `;` + programFiles, "", "not trusted"},
		{"a .bat earlier on PATH", work, `C:\Users\u\evil;` + programFiles, "", "comes before npx.cmd"},
		{"npx in the working folder", work + `\tools`, programFiles, "", "not trusted"},
		{"relative PATH entry", work, `.\bin;` + programFiles, "", "not an absolute folder"},
		{"network PATH entry", work, `\\server\share;` + programFiles, "", "not an absolute folder"},
		{"not on PATH", work, `C:\Windows`, "", "not on the PATH"},
		{"PATHEXT puts .ps1 first", work, programFiles, ".PS1;.CMD", "npx.ps1 comes before"},
		{"default PATHEXT", work, programFiles, ".COM;.EXE;.BAT;.CMD;.VBS;.JS;.MSC", ""},
	} {
		got, err := resolveMCPAsUserLauncher(npx, tc.work, tc.path, tc.pathExt, fs)
		if tc.want == "" {
			if err != nil || got != programFiles+`\npx.cmd` {
				t.Errorf("%s: %q, %v", tc.name, got, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %q, %v; want a refusal containing %q", tc.name, got, err, tc.want)
		}
	}
	files[programFiles+`\npx.exe`] = true
	if _, err := resolveMCPAsUserLauncher(npx, work, programFiles, "", fs); err == nil || !strings.Contains(err.Error(), "npx.exe comes before") {
		t.Fatalf("npx.exe beside npx.cmd: %v", err)
	}
	if _, err := resolveMCPAsUserLauncher(mcpAsUserLauncher{name: "uvx", file: "uvx.exe"}, work, programFiles, "", fs); err == nil {
		t.Fatal("found a launcher that is not there")
	}
}

// #1164: a cwd the enumerator refuses refuses the start even when the
// project folder would pass, so the scan never runs a server from another
// folder than the agent does and never looks for its launcher; the relay
// then fails and the gateway blocks the server as not scanned.
func TestPlanMCPAsUserLaunchHasNoFallbackFolder(t *testing.T) {
	home := filepath.Join(t.TempDir(), "u1")
	project := filepath.Join(home, "proj")
	checks := claudeMCPWorkDirChecks{
		noLinks: func(path string) error {
			if strings.Contains(path, "junction") {
				return errors.New("a folder on the way is a link or reparse point")
			}
			return nil
		},
		final: func(path string) (string, error) { return path, nil },
	}
	lookups := 0
	fs := mcpAsUserLauncherFS{
		exists: func(path string) bool {
			lookups++
			return path == `C:\Program Files\nodejs\npx.cmd`
		},
		trusted: func(string) error { return nil },
	}
	npx := mcpAsUserLauncher{name: "npx", file: "npx.cmd"}
	env := []string{`PATH=C:\Program Files\nodejs`}
	for name, cwd := range map[string]string{
		"junction cwd": filepath.Join(project, "junction"), "relative cwd": "server", "cwd outside": filepath.Join(t.TempDir(), "x"),
	} {
		entry := config.MCPServerEntry{Name: "srv", Command: "npx", Args: []string{"-y", "."}, CWD: cwd, Project: project}
		dir, launcher, err := planMCPAsUserLaunch(entry, home, nil, npx, env, checks, fs)
		if err == nil || dir != "" || launcher != "" || !strings.Contains(err.Error(), "is not started in "+cwd) {
			t.Errorf("%s: dir %q launcher %q (%v), want the start refused", name, dir, launcher, err)
		}
	}
	if lookups != 0 {
		t.Fatalf("looked for a launcher for a refused folder (%d)", lookups)
	}
	entry := config.MCPServerEntry{Name: "srv", Command: "npx", Args: []string{"-y", "."}, Project: project}
	dir, launcher, err := planMCPAsUserLaunch(entry, home, nil, npx, env, checks, fs)
	if err != nil || dir != project || launcher != `C:\Program Files\nodejs\npx.cmd` {
		t.Fatalf("project server: dir %q launcher %q (%v)", dir, launcher, err)
	}
}

func TestMCPAsUserArgv(t *testing.T) {
	argv, err := mcpAsUserArgv(mcpAsUserLauncher{name: "npx", file: "npx.cmd"}, `C:\Program Files\nodejs\npx.cmd`, `C:\Windows\System32\cmd.exe`, []string{"-y", "pkg"})
	want := []string{`C:\Windows\System32\cmd.exe`, "/d", "/s", "/v:off", "/c", "call", `C:\Program Files\nodejs\npx.cmd`, "-y", "pkg"}
	if err != nil || strings.Join(argv, "|") != strings.Join(want, "|") {
		t.Fatalf("npx argv %q, %v", argv, err)
	}
	if _, err := mcpAsUserArgv(mcpAsUserLauncher{name: "npx"}, `C:\a&b\npx.cmd`, `C:\Windows\System32\cmd.exe`, nil); err == nil {
		t.Fatal("an npx.cmd path with a metacharacter was accepted")
	}
	argv, err = mcpAsUserArgv(mcpAsUserLauncher{name: "uvx"}, `C:\u\uvx.exe`, "unused", []string{"pkg"})
	if err != nil || strings.Join(argv, "|") != `C:\u\uvx.exe|pkg` {
		t.Fatalf("uvx argv %q, %v", argv, err)
	}
}

func TestMergeMCPAsUserEnvPutsTheServerEnvOnTop(t *testing.T) {
	user := []string{"=C:=C:\\Users\\u", "Path=C:\\Windows", "USERPROFILE=C:\\Users\\u"}
	got := mergeMCPAsUserEnv(user, map[string]string{"PATH": `C:\tools`, "NOTES_TOKEN": "x", "bad=name": "y"})
	want := []string{"=C:=C:\\Users\\u", `PATH=C:\tools`, "USERPROFILE=C:\\Users\\u", "NOTES_TOKEN=x"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("env %q", got)
	}
	if mcpAsUserEnvValue(got, "path") != `C:\tools` {
		t.Fatal("PATH lookup is case sensitive")
	}
}
