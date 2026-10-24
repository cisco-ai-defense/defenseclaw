// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"golang.org/x/sys/windows"
)

// GAP-1405: a record that cannot be updated is withdrawn, so the gateway
// never admits the old servers as the user's current ones, and the next
// successful update publishes the new ones.
func TestWriteWindowsMCPSpoolWithdrawsARecordItCannotUpdate(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(home, ".kiro", "settings")
	if err := os.MkdirAll(settings, 0o700); err != nil {
		t.Fatal(err)
	}
	writeServers := func(name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(settings, "mcp.json"), []byte(`{"mcpServers":{"`+name+`":{"command":"x"}}}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(t.TempDir(), KiroMCPSpoolDirName)
	const sid = "S-1-5-21-1-1001"
	manifest := Manifest{Targets: []ManifestTarget{{SID: sid, UserHome: home, Connector: "kiro"}}}
	names := func() ([]string, error) {
		servers, _, err := ReadKiroMCPSpool(dir, sid, nil)
		var out []string
		for _, server := range servers {
			out = append(out, server.Name)
		}
		return out, err
	}
	writeServers("first")
	if err := WriteWindowsKiroMCPSpool(dir, manifest, nil, t.Logf); err != nil {
		t.Fatal(err)
	}
	if got, err := names(); err != nil || strings.Join(got, ",") != "first" {
		t.Fatalf("published %v (%v), want first", got, err)
	}
	writeServers("second")
	previous := windowsMCPSpoolWrite
	t.Cleanup(func() { windowsMCPSpoolWrite = previous })
	windowsMCPSpoolWrite = func(string, string, string, []byte, func(string) error) error {
		return errors.New("there is not enough space on the disk")
	}
	if err := WriteWindowsKiroMCPSpool(dir, manifest, nil, t.Logf); err == nil || !strings.Contains(err.Error(), "not enough space") {
		t.Fatalf("a failed update reported %v, want the failure", err)
	}
	if got, err := names(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("after a failed update the gateway reads %v (%v), want no record", got, err)
	}
	windowsMCPSpoolWrite = previous
	if err := WriteWindowsKiroMCPSpool(dir, manifest, nil, t.Logf); err != nil {
		t.Fatal(err)
	}
	if got, err := names(); err != nil || strings.Join(got, ",") != "second" {
		t.Fatalf("published %v (%v), want second", got, err)
	}

	// A record the gateway holds open while the update fails is not left
	// naming the old servers either.
	held, err := os.Open(filepath.Join(dir, strings.ToUpper(sid)+".json"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	writeServers("third")
	windowsMCPSpoolWrite = func(string, string, string, []byte, func(string) error) error {
		return errors.New("the process cannot access the file")
	}
	if err := WriteWindowsKiroMCPSpool(dir, manifest, nil, t.Logf); err == nil {
		t.Fatal("a failed update was reported as published")
	}
	if got, err := names(); err == nil && len(got) != 0 {
		t.Fatalf("after a failed update of a held record the gateway reads %v, want no servers", got)
	}
}

// Project names in .claude.json are controlled by the enrolled user. A UNC
// path must be rejected before LocalSystem touches the remote filesystem.
func TestWindowsClaudeProjectMCPRejectsUNC(t *testing.T) {
	_, _, err := readWindowsClaudeProjectMCP(`\\server\share\project`)
	if err == nil || !strings.Contains(err.Error(), "local drive letter") {
		t.Fatalf("UNC project path was not rejected before filesystem access: %v", err)
	}
}

// GAP-0424: the enumerator publishes the Claude Code servers of an enrolled
// user (user scope, local scope, and project .mcp.json files) for the
// gateway, which cannot read ~/.claude.json.
func TestWriteWindowsClaudeMCPSpoolPublishesEveryScope(t *testing.T) {
	original := windowsClaudeProjectWithUserToken
	windowsClaudeProjectWithUserToken = func(_ *windows.SID, _ string, fn func() error) error { return fn() }
	t.Cleanup(func() { windowsClaudeProjectWithUserToken = original })
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

	// Once the enrolled user can open a project, an oversized .mcp.json
	// makes that user's whole inventory unreadable.
	if err := os.WriteFile(filepath.Join(inside, ".mcp.json"), []byte(strings.Repeat("x", maxClaudeProjectMCPBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteWindowsClaudeMCPSpool(dir, manifest, nil, t.Logf); err != nil {
		t.Fatal(err)
	}
	servers, unreadable, err := ReadClaudeMCPSpool(dir, sid, nil)
	if err != nil || len(servers) != 0 || unreadable == nil || unreadable.Path != filepath.Join(inside, ".mcp.json") {
		t.Fatalf("oversized project: servers=%v unreadable=%+v err=%v", servers, unreadable, err)
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

// GAP-0643: a user whose projects cannot be read as them because they signed
// out gets a record that says so, which the refusals name.
func TestWriteWindowsClaudeMCPSpoolMarksASignedOutUser(t *testing.T) {
	const sid = "S-1-5-21-1-1001"
	original := windowsClaudeProjectWithUserToken
	windowsClaudeProjectWithUserToken = func(*windows.SID, string, func() error) error {
		return &WindowsTargetSessionUnavailableError{SID: sid}
	}
	t.Cleanup(func() { windowsClaudeProjectWithUserToken = original })
	home := t.TempDir()
	raw, _ := json.Marshal(map[string]any{"projects": map[string]any{filepath.Join(home, "proj"): map[string]any{}}})
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), ClaudeMCPSpoolDirName)
	manifest := Manifest{Targets: []ManifestTarget{{SID: sid, User: `DCLAB\dcw-std2`, UserHome: home, Connector: "claudecode"}}}
	if err := WriteWindowsClaudeMCPSpool(dir, manifest, nil, t.Logf); err != nil {
		t.Fatal(err)
	}
	_, unreadable, err := ReadClaudeMCPSpool(dir, sid, nil)
	if err != nil || unreadable == nil || !unreadable.SignedOut ||
		!strings.Contains(unreadable.Blocked("Claude Code"), `DCLAB\dcw-std2 is not signed in`) {
		t.Fatalf("unreadable %+v (err %v); want the user marked signed out", unreadable, err)
	}
}

// A rejected project file leaves the account unreadable instead of silently
// publishing a partial server set.
func TestWriteWindowsClaudeMCPSpoolMarksRejectedProject(t *testing.T) {
	original := windowsClaudeProjectWithUserToken
	windowsClaudeProjectWithUserToken = func(_ *windows.SID, _ string, fn func() error) error { return fn() }
	t.Cleanup(func() { windowsClaudeProjectWithUserToken = original })
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

// GAP-1317, #1164: the enumerator check runs on the real file system: a
// project folder is accepted under its long path, while a junction (as the
// cwd or as the project) and a short-name alias of the project are refused.
// A refused cwd refuses the start: the project never stands in for it.
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
		dir, err := vetClaudeMCPWorkDir(config.MCPServerEntry{Name: "srv", Command: "npx", CWD: cwd, Project: project},
			home, nil, windowsClaudeMCPWorkDirChecks)
		if err != nil {
			return dir, err.Error()
		}
		return dir, ""
	}
	if dir, refused := vet("", project); !strings.EqualFold(dir, project) || refused != "" {
		t.Fatalf("project: %q (%q)", dir, refused)
	}
	if dir, refused := vet(junction, project); dir != "" || !strings.Contains(refused, "link or reparse point") {
		t.Fatalf("junction cwd: %q (%q), want the start refused, not the project", dir, refused)
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
			if dir, refused := vet(short, project); dir != "" || !strings.Contains(refused, "alias") {
				t.Fatalf("short name %s: %q (%q)", short, dir, refused)
			}
		}
	}
}

// GAP-1504: an inaccessible project contributes neither its local servers nor
// its .mcp.json servers. Other projects and the user scope remain published.
func TestWriteWindowsClaudeMCPSpoolSkipsRefusedProject(t *testing.T) {
	home := t.TempDir()
	projects := t.TempDir()
	bob := filepath.Join(projects, "a-bob")
	alice := filepath.Join(projects, "z-alice")
	for _, dir := range []string{bob, alice} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for dir, name := range map[string]string{bob: "bob-file", alice: "alice-file"} {
		if err := os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(`{"mcpServers":{"`+name+`":{"command":"x","env":{"SECRET":"private"}}}}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	state := map[string]any{
		"mcpServers": map[string]any{"user": map[string]any{"command": "x"}},
		"projects": map[string]any{
			bob:   map[string]any{"mcpServers": map[string]any{"bob-local": map[string]any{"command": "x"}}},
			alice: map[string]any{"mcpServers": map[string]any{"alice-local": map[string]any{"command": "x"}}},
		},
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	original := windowsClaudeProjectWithUserToken
	originalRead := windowsClaudeProjectRead
	calls := 0
	windowsClaudeProjectWithUserToken = func(_ *windows.SID, _ string, fn func() error) error {
		calls++
		return fn()
	}
	windowsClaudeProjectRead = func(project string) ([]byte, error, error) {
		if project == bob {
			return nil, fmt.Errorf("%w: project directory: %w", errClaudeProjectAccessDenied, windows.ERROR_ACCESS_DENIED), nil
		}
		return originalRead(project)
	}
	t.Cleanup(func() {
		windowsClaudeProjectWithUserToken = original
		windowsClaudeProjectRead = originalRead
	})
	dir := filepath.Join(t.TempDir(), ClaudeMCPSpoolDirName)
	const sid = "S-1-5-21-1-1001"
	manifest := Manifest{Targets: []ManifestTarget{{SID: sid, UserHome: home, Connector: "claudecode"}}}
	var warnings []string
	if err := WriteWindowsClaudeMCPSpool(dir, manifest, nil, func(format string, args ...any) {
		if line := fmt.Sprintf(format, args...); strings.Contains(line, "WARN") {
			warnings = append(warnings, line)
		}
	}); err != nil {
		t.Fatal(err)
	}
	servers, unreadable, err := ReadClaudeMCPSpool(dir, sid, nil)
	if err != nil || unreadable != nil || calls != 1 {
		t.Fatalf("servers=%v unreadable=%+v calls=%d err=%v", servers, unreadable, calls, err)
	}
	got := map[string]bool{}
	for _, server := range servers {
		got[server.Name] = true
	}
	if len(got) != 3 || !got["user"] || !got["alice-local"] || !got["alice-file"] || got["bob-local"] || got["bob-file"] {
		t.Fatalf("published names = %v", got)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], bob) {
		t.Fatalf("refused project warnings = %v", warnings)
	}
}

// A missing or invalid session token must not publish a normal record that
// drops project servers. The unreadable marker makes the gateway fail closed.
func TestWriteWindowsClaudeMCPSpoolMarksUnavailableToken(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	state := map[string]any{"projects": map[string]any{
		project: map[string]any{"mcpServers": map[string]any{
			"local": map[string]any{"command": "x"},
		}},
	}}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(home, ".claude.json")
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	original := windowsClaudeProjectWithUserToken
	t.Cleanup(func() { windowsClaudeProjectWithUserToken = original })
	windowsClaudeProjectWithUserToken = func(_ *windows.SID, _ string, fn func() error) error { return fn() }
	dir := filepath.Join(t.TempDir(), ClaudeMCPSpoolDirName)
	const sid = "S-1-5-21-1-1001"
	manifest := Manifest{Targets: []ManifestTarget{{SID: sid, UserHome: home, Connector: "claudecode"}}}
	if err := WriteWindowsClaudeMCPSpool(dir, manifest, nil, t.Logf); err != nil {
		t.Fatal(err)
	}
	servers, unreadable, err := ReadClaudeMCPSpool(dir, sid, nil)
	if err != nil || unreadable != nil || len(servers) != 1 {
		t.Fatalf("initial record: servers=%v unreadable=%+v err=%v", servers, unreadable, err)
	}
	windowsClaudeProjectWithUserToken = func(_ *windows.SID, _ string, _ func() error) error {
		return fmt.Errorf("resolve target token profile: %w", windows.ERROR_FILE_NOT_FOUND)
	}
	if err := WriteWindowsClaudeMCPSpool(dir, manifest, nil, t.Logf); err != nil {
		t.Fatal(err)
	}
	servers, unreadable, err = ReadClaudeMCPSpool(dir, sid, nil)
	if err != nil || len(servers) != 0 || unreadable == nil || unreadable.Path != statePath {
		t.Fatalf("token failure: servers=%v unreadable=%+v err=%v", servers, unreadable, err)
	}
}

// The real Windows directory and file DACLs are checked under the same
// effective token used for the read. A parent denial inherited by the
// project must refuse only that project, like a denied directory or file open.
func TestWindowsClaudeProjectMCPChecksDirectoryAndFileACL(t *testing.T) {
	sid := currentWindowsTestSID(t)
	original := windowsClaudeProjectWithUserToken
	windowsClaudeProjectWithUserToken = func(_ *windows.SID, _ string, fn func() error) error { return fn() }
	t.Cleanup(func() { windowsClaudeProjectWithUserToken = original })
	for _, tc := range []struct {
		name, denyMask string
		denyDirectory  bool
		denyParent     bool
	}{
		{"parent directory", "GR", false, true},
		{"directory list", "0x00000001", true, false},
		{"file read", "GR", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			project := t.TempDir()
			parent := ""
			if tc.denyParent {
				parent = filepath.Join(project, "blocked")
				project = filepath.Join(parent, "project")
				if err := os.MkdirAll(project, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			file := filepath.Join(project, ".mcp.json")
			if err := os.WriteFile(file, []byte(`{"mcpServers":{"private":{"command":"x"}}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			path := file
			if tc.denyDirectory {
				path = project
			}
			if tc.denyParent {
				path = parent
			}
			before, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			oldACL, _, err := before.DACL()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
					windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
					nil, nil, oldACL, nil); err != nil {
					t.Errorf("restore project ACL: %v", err)
				}
			})
			inherit := ""
			if tc.denyParent {
				inherit = "OICI"
			}
			sd, err := windows.SecurityDescriptorFromString("D:P(D;" + inherit + ";" + tc.denyMask + ";;;" + sid.String() +
				")(A;;FA;;;SY)(A;;FA;;;BA)")
			if err != nil {
				t.Fatal(err)
			}
			acl, _, err := sd.DACL()
			if err != nil {
				t.Fatal(err)
			}
			if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
				windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
				nil, nil, acl, nil); err != nil {
				t.Fatal(err)
			}
			if tc.denyParent {
				if err := rejectWindowsReparseChain(project); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
					t.Fatalf("project walk with denied parent ACL: %v; want access denied", err)
				}
			}
			data, accessErr, readErr := readWindowsClaudeProjectMCP(project)
			if len(data) != 0 || !errors.Is(accessErr, errClaudeProjectAccessDenied) ||
				!errors.Is(accessErr, windows.ERROR_ACCESS_DENIED) || readErr != nil {
				t.Fatalf("data=%q accessErr=%v readErr=%v; want project refused before read", data, accessErr, readErr)
			}
		})
	}
}

// W2B-G-enum review loop 3: a record that cannot be updated is named in the
// error with its account, and the other users' records are still published.
func TestWriteWindowsMCPSpoolNamesTheRecordItCouldNotPublish(t *testing.T) {
	dir := filepath.Join(t.TempDir(), KiroMCPSpoolDirName)
	var targets []ManifestTarget
	for _, sid := range []string{"S-1-5-21-1-1001", "S-1-5-21-1-1002"} {
		home := t.TempDir()
		if err := os.MkdirAll(filepath.Join(home, ".kiro", "settings"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".kiro", "settings", "mcp.json"), []byte(`{"mcpServers":{"notes":{"command":"x"}}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		targets = append(targets, ManifestTarget{SID: sid, UserHome: home, Connector: "kiro"})
	}
	previous := windowsMCPSpoolWrite
	t.Cleanup(func() { windowsMCPSpoolWrite = previous })
	windowsMCPSpoolWrite = func(dir, name, pattern string, data []byte, setOwnership func(string) error) error {
		if strings.HasPrefix(name, "S-1-5-21-1-1001") {
			return errors.New("there is not enough space on the disk")
		}
		return previous(dir, name, pattern, data, setOwnership)
	}
	err := WriteWindowsKiroMCPSpool(dir, Manifest{Targets: targets}, nil, t.Logf)
	records, whole := MCPSpoolRecordFailures(err)
	if whole || len(records) != 1 || records[0].SID != "S-1-5-21-1-1001" || records[0].Connector != "kiro" ||
		!strings.EqualFold(records[0].Home, filepath.Clean(targets[0].UserHome)) {
		t.Fatalf("error %v: records %+v whole %v; want the first user's record only", err, records, whole)
	}
	if servers, _, readErr := ReadKiroMCPSpool(dir, "S-1-5-21-1-1002", nil); readErr != nil || len(servers) != 1 {
		t.Fatalf("the other user's record: %v (%v), want published", servers, readErr)
	}
}
