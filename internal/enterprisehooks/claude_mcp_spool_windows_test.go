// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"golang.org/x/sys/windows"
)

// Project names in .claude.json are controlled by the enrolled user. A UNC
// path must be rejected before LocalSystem touches the remote filesystem.
func TestWindowsClaudeProjectMCPRejectsUNC(t *testing.T) {
	_, err := readWindowsClaudeProjectMCP(`\\server\share\project`)
	if err == nil || !strings.Contains(err.Error(), "local drive letter") {
		t.Fatalf("UNC project path was not rejected before filesystem access: %v", err)
	}
}

// GAP-0424: the enumerator publishes the Claude Code servers of an enrolled
// user (user scope, local scope, and project .mcp.json files) for the
// gateway, which cannot read ~/.claude.json.
func TestWriteWindowsClaudeMCPSpoolPublishesEveryScope(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	inside := filepath.Join(home, "proj")
	if err := os.Mkdir(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{inside, outside} {
		if err := os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(`{"mcpServers":{"shared-`+filepath.Base(dir)+`":{"command":"x"}}}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	state := map[string]any{
		"mcpServers": map[string]any{"user-srv": map[string]any{"type": "http", "url": "https://u.example.test/mcp"}},
		"projects": map[string]any{
			inside:  map[string]any{"mcpServers": map[string]any{"local-srv": map[string]any{"command": "y"}}},
			outside: map[string]any{},
		},
	}
	raw, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), ClaudeMCPSpoolDirName)
	const sid = "S-1-5-21-1-1001"
	manifest := Manifest{Targets: []ManifestTarget{{SID: sid, UserHome: home, Connector: "claudecode"}}}
	if err := WriteWindowsClaudeMCPSpool(dir, manifest, nil, t.Logf); err != nil {
		t.Fatal(err)
	}
	servers, _, err := ReadClaudeMCPSpool(dir, sid, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, server := range servers {
		got[server.Name] = server.Project
	}
	if len(got) != 4 || got["user-srv"] != "" || got["local-srv"] != inside || got["shared-proj"] != inside || got["shared-"+filepath.Base(outside)] != outside {
		t.Fatalf("published %v, want user, local and both project servers", got)
	}
}

// GAP-0829: an unreadable or malformed state must not leave the previously
// admitted definition in the gateway's inventory; the record says the state
// is unreadable instead, so the gateway fails closed for that user.
func TestWriteWindowsClaudeMCPSpoolMarksUnreadableState(t *testing.T) {
	home := t.TempDir()
	state := filepath.Join(home, ".claude.json")
	if err := os.WriteFile(state, []byte(`{"mcpServers":{"old":{"command":"old"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), ClaudeMCPSpoolDirName)
	const sid = "S-1-5-21-1-1001"
	manifest := Manifest{Targets: []ManifestTarget{{SID: sid, User: `DCLAB\dcw-std1`, UserHome: home, Connector: "claudecode"}}}
	if err := WriteWindowsClaudeMCPSpool(dir, manifest, nil, t.Logf); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteWindowsClaudeMCPSpool(dir, manifest, nil, t.Logf); err != nil {
		t.Fatal(err)
	}
	servers, unreadable, err := ReadClaudeMCPSpool(dir, sid, nil)
	if err != nil || len(servers) != 0 || unreadable == nil || unreadable.Path != state || unreadable.Account() != `DCLAB\dcw-std1` {
		t.Fatalf("servers %v, unreadable %+v (err %v); want no servers and the state marked unreadable", servers, unreadable, err)
	}
}

// A rejected project file leaves the account unreadable instead of silently
// publishing a partial server set.
func TestWriteWindowsClaudeMCPSpoolMarksRejectedProject(t *testing.T) {
	home := t.TempDir()
	project := `\\server\share\project`
	state := map[string]any{
		"mcpServers": map[string]any{"user-srv": map[string]any{"command": "x"}},
		"projects":   map[string]any{project: map[string]any{}},
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), ClaudeMCPSpoolDirName)
	const sid = "S-1-5-21-1-1001"
	manifest := Manifest{Targets: []ManifestTarget{{SID: sid, UserHome: home, Connector: "claudecode"}}}
	if err := WriteWindowsClaudeMCPSpool(dir, manifest, nil, t.Logf); err != nil {
		t.Fatal(err)
	}
	servers, unreadable, err := ReadClaudeMCPSpool(dir, sid, nil)
	if err != nil || len(servers) != 0 || unreadable == nil || unreadable.Path != filepath.Join(project, ".mcp.json") {
		t.Fatalf("servers %v, unreadable %+v (err %v); want rejected project marked unreadable", servers, unreadable, err)
	}
}

// GAP-1317: the enumerator check runs on the real file system: a project
// folder is accepted under its long path, while a junction (as the cwd or as
// the project) and a short-name alias of the project are refused.
func TestWindowsClaudeMCPWorkDirChecksRejectJunctionAndAlias(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "home")
	project := filepath.Join(home, "long project folder")
	outside := filepath.Join(base, "outside")
	junction := filepath.Join(home, "via-junction")
	for _, dir := range []string{project, outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, outside).CombinedOutput(); err != nil {
		t.Skipf("mklink /J: %v: %s", err, out)
	}
	vet := func(cwd, project string) (string, string) {
		return vetClaudeMCPWorkDir(config.MCPServerEntry{Name: "srv", Command: "npx", CWD: cwd, Project: project},
			home, nil, windowsClaudeMCPWorkDirChecks)
	}
	if dir, refused := vet("", project); !strings.EqualFold(dir, project) || refused != "" {
		t.Fatalf("project: %q (%q)", dir, refused)
	}
	if dir, refused := vet(junction, project); !strings.EqualFold(dir, project) || !strings.Contains(refused, "link or reparse point") {
		t.Fatalf("junction cwd: %q (%q), want the project and the junction refused", dir, refused)
	}
	if dir, refused := vet("", junction); dir != "" || !strings.Contains(refused, "link or reparse point") {
		t.Fatalf("junction project: %q (%q)", dir, refused)
	}
	buf := make([]uint16, windows.MAX_PATH)
	ptr, _ := windows.UTF16PtrFromString(project)
	if n, err := windows.GetShortPathName(ptr, &buf[0], uint32(len(buf))); err == nil && n > 0 {
		// Only the last folder in its short form: the rest of the path is
		// the home as the manifest names it.
		if short := filepath.Join(home, filepath.Base(windows.UTF16ToString(buf[:n]))); !strings.EqualFold(short, project) {
			if dir, refused := vet(short, project); !strings.EqualFold(dir, project) || !strings.Contains(refused, "alias") {
				t.Fatalf("short name %s: %q (%q)", short, dir, refused)
			}
		}
	}
}
