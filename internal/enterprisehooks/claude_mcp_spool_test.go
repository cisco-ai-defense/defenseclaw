// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1317, #1164: the enumerator, checking as the server's user, accepts a
// server folder only inside the project or the user's own home, on a local volume,
// with no link on the way and no alias; anything else is refused with the
// reason. A refused cwd is never replaced by the project: the scan would run
// code from another folder than the agent does.
func TestVetClaudeMCPWorkDirRefusesEscapes(t *testing.T) {
	base := t.TempDir()
	users := filepath.Join(base, "Users")
	home, other := filepath.Join(users, "u1"), filepath.Join(users, "u2")
	project := filepath.Join(home, "proj")
	shared := filepath.Join(base, "shared", "proj")
	linked := filepath.Join(project, "linked")
	unc := filepath.Join(project, "unc")
	short := filepath.Join(project, "SHORT~1")
	denied := filepath.Join(project, "denied")
	checks := claudeMCPWorkDirChecks{
		volume: func(path string) error {
			if path == unc {
				return errors.New("path must use a local drive letter")
			}
			return nil
		},
		noLinks: func(path string) error {
			if strings.HasPrefix(path, linked) {
				return errors.New("a folder on the way is a link or reparse point")
			}
			return nil
		},
		final: func(path string) (string, error) {
			switch path {
			case short:
				return filepath.Join(project, "short-name"), nil
			case denied:
				return "", os.ErrPermission
			}
			return strings.ToUpper(path[:1]) + path[1:], nil
		},
	}
	for _, tc := range []struct {
		name, cwd, project, want, refused string
	}{
		{"project", "", project, project, ""},
		{"shared project", "", shared, shared, ""},
		{"user scope", "", "", home, ""},
		{"cwd in home", filepath.Join(home, "tools"), project, filepath.Join(home, "tools"), ""},
		{"relative", "server", project, "", "not an absolute path"},
		{"dot-dot into another profile", filepath.Join(project, "..", "..", "u2"), users, "", "another user profile"},
		{"other enrolled home as project", "", other, "", "another user profile"},
		{"outside", filepath.Join(base, "elsewhere"), project, "", "outside the project"},
		{"link", filepath.Join(linked, "sub"), project, "", "link or reparse point"},
		{"unc", unc, project, "", "local drive letter"},
		{"short name", short, project, "", "alias"},
		{"unreadable", denied, project, "", "permission"},
	} {
		entry := config.MCPServerEntry{Name: "srv", Command: "npx", CWD: tc.cwd, Project: tc.project}
		dir, err := vetClaudeMCPWorkDir(entry, home, []string{other}, checks)
		refused := ""
		if err != nil {
			refused = err.Error()
		}
		if !strings.EqualFold(dir, tc.want) || (tc.refused == "") != (err == nil) || !strings.Contains(refused, tc.refused) {
			t.Errorf("%s: dir %q refused %q, want %q refused containing %q", tc.name, dir, refused, tc.want, tc.refused)
		}
	}
	if dir, err := vetClaudeMCPWorkDir(config.MCPServerEntry{Name: "remote", URL: "https://x.test", Project: project}, home, nil, checks); dir != "" || err == nil {
		t.Fatalf("remote server got folder %q (%v)", dir, err)
	}
}

// #1164: a record a 1.0.2 enumerator wrote, with the folder it checked as
// LocalSystem, still parses during an upgrade, and the folder is not used:
// the enumerator checks the folder as the user when it starts the server.
// A record that fails the trust check is not read, and no configuration
// file can name the account a server starts as.
func TestReadClaudeMCPSpoolIgnoresTheLegacyWorkDir(t *testing.T) {
	dir := t.TempDir()
	const sid = "S-1-5-21-1-1001"
	project := filepath.Join(dir, "proj")
	legacy, err := json.Marshal(ClaudeMCPSpoolRecord{Version: ClaudeMCPSpoolRecordVersion, Key: sid, Servers: []ClaudeMCPSpoolServer{{
		Server: config.MCPServerEntry{Name: "srv", Command: "npx", Args: []string{"-y", "pkg"}}, Project: project,
		WorkDir: project, WorkDirRefused: "x: refused",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(legacy), `"work_dir"`) {
		t.Fatalf("the legacy record has no work_dir: %s", legacy)
	}
	if err := os.WriteFile(filepath.Join(dir, sid+".json"), legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	servers, unreadable, err := ReadClaudeMCPSpool(dir, sid, func(string, string) error { return nil })
	if err != nil || unreadable != nil || len(servers) != 1 || servers[0].Project != project || servers[0].Connector != "claudecode" {
		t.Fatalf("legacy record: %+v %v (%v)", servers, unreadable, err)
	}
	fresh, err := MarshalClaudeMCPSpoolRecord(sid, servers)
	if err != nil || strings.Contains(string(fresh), "work_dir") {
		t.Fatalf("a new record still carries a folder: %s (%v)", fresh, err)
	}
	if _, _, err := ReadClaudeMCPSpool(dir, sid, func(string, string) error { return errors.New("not the enumerator") }); err == nil {
		t.Fatal("a record that fails the trust check was read")
	}
	var forged config.MCPServerEntry
	if err := json.Unmarshal([]byte(`{"name":"srv","command":"npx","RunAsSID":"S-1-5-18","run_as_sid":"S-1-5-18"}`), &forged); err != nil || forged.RunAsSID != "" {
		t.Fatalf("a configuration entry named the account a server starts as: %+v (%v)", forged, err)
	}
}

// emptyJoinedError is a joined error with no errors in it.
type emptyJoinedError struct{}

func (emptyJoinedError) Error() string   { return "nothing" }
func (emptyJoinedError) Unwrap() []error { return nil }

// W2B-G-enum review loop 3: the refresh tells the gateway which records it
// did not publish, so a publication's error is split into its records; any
// other failure is the whole folder's.
func TestMCPSpoolRecordFailuresNamesTheRecordsAndTheFolder(t *testing.T) {
	alice := &MCPSpoolRecordError{Connector: "claudecode", SID: "S-1-5-21-1-1001", Home: `C:\Users\alice`, Err: errors.New("disk full")}
	bob := &MCPSpoolRecordError{Connector: "claudecode", SID: "S-1-5-21-1-1002", Home: `C:\Users\bob`, Err: errors.New("held open")}
	records, whole := MCPSpoolRecordFailures(errors.Join(errors.Join(nil, alice), bob))
	if whole || len(records) != 2 || records[0] != alice || records[1] != bob {
		t.Fatalf("records %v, whole %v; want alice and bob only", records, whole)
	}
	if _, whole := MCPSpoolRecordFailures(fmt.Errorf("create claudecode mcp spool: %w", errors.New("access denied"))); !whole {
		t.Fatal("a folder failure must be the whole connector's")
	}
	if records, whole := MCPSpoolRecordFailures(errors.Join(alice, errors.New("set claudecode mcp spool protection"))); !whole || len(records) != 1 {
		t.Fatalf("records %v, whole %v; want the record and the folder failure", records, whole)
	}
	if _, whole := MCPSpoolRecordFailures(emptyJoinedError{}); !whole {
		t.Fatal("an error that names no record must be the whole connector's")
	}
	if records, whole := MCPSpoolRecordFailures(nil); whole || len(records) != 0 {
		t.Fatal("no error named a failure")
	}
	if !strings.Contains(alice.Error(), "disk full") || !errors.Is(alice, alice.Err) {
		t.Fatal("a record error must name and wrap its cause")
	}
}
