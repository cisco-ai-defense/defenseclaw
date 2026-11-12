// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-0686: the enumerator publishes, for every account it enrolls for
// Codex, the servers of the one config.toml Codex reads for it: the file
// under the account persistent CODEX_HOME when that is set, else
// ~/.codex/config.toml. Each account has its own record. A file it cannot
// read as the account makes that account record unreadable (no servers),
// never an empty list, and leaves the other accounts alone. The default file
// of an account whose Codex reads CODEX_HOME is never read: a same-named old
// definition does not displace the one that runs, and an unreadable default
// does not refuse the account calls.
func TestGAP0686WindowsCodexRecordPerAccountWithCodexHome(t *testing.T) {
	root := t.TempDir()
	alice, bob := filepath.Join(root, "alice"), filepath.Join(root, "bob")
	const aliceSID, bobSID = "S-1-5-21-1-1001", "S-1-5-21-1-1002"
	relocated := filepath.Join(root, "codex-home-alice")
	files := map[string]string{
		strings.ToLower(filepath.Join(alice, ".codex", "config.toml")): "[mcp_servers.r109loop]\ncommand = \"node\"\nargs = [\"server.js\"]\n[mcp_servers.notes]\nurl = \"http://127.0.0.1:1/old\"\n",
		strings.ToLower(filepath.Join(relocated, "config.toml")):       "[mcp_servers.r109home]\nurl = \"http://127.0.0.1:28561/mcp\"\n[mcp_servers.notes]\nurl = \"http://127.0.0.1:2/new\"\n",
		strings.ToLower(filepath.Join(bob, ".codex", "config.toml")):   "[mcp_servers.r109loop]\ncommand = \"node\"\nargs = [\"other.js\"]\n",
	}
	failing := map[string]error{}
	previousRead, previousEnvironment := windowsCodexConfigRead, windowsUserEnvironment
	t.Cleanup(func() { windowsCodexConfigRead, windowsUserEnvironment = previousRead, previousEnvironment })
	windowsCodexConfigRead = func(path string, _ *windows.SID, _ string) ([]byte, error) {
		key := strings.ToLower(filepath.Clean(path))
		if err := failing[key]; err != nil {
			return nil, err
		}
		if body, ok := files[key]; ok {
			return []byte(body), nil
		}
		return nil, os.ErrNotExist
	}
	windowsUserEnvironment = func(sid, name string) string {
		if strings.EqualFold(sid, aliceSID) && name == "CODEX_HOME" {
			return relocated
		}
		return ""
	}
	dir := filepath.Join(t.TempDir(), CodexMCPSpoolDirName)
	manifest := Manifest{Targets: []ManifestTarget{
		{SID: aliceSID, User: "alice", UserHome: alice, Connector: "codex"},
		{SID: bobSID, User: "bob", UserHome: bob, Connector: "codex"},
		{SID: "S-1-5-21-1-1003", User: "carol", UserHome: filepath.Join(root, "carol"), Connector: "claudecode"},
	}}
	if err := WriteWindowsMCPSpool(dir, "codex", manifest, nil, t.Logf); err != nil {
		t.Fatal(err)
	}
	names := func(sid string) (string, *ClaudeStateUnreadable) {
		t.Helper()
		servers, unreadable, err := ReadMCPSpool(dir, sid, "codex", nil)
		if err != nil {
			t.Fatalf("%s: %v", sid, err)
		}
		var out []string
		for _, server := range servers {
			if server.Connector != "codex" || server.Source == "" {
				t.Fatalf("%s: published %+v", sid, server)
			}
			out = append(out, server.Name)
		}
		sort.Strings(out)
		return strings.Join(out, ","), unreadable
	}
	if got, unreadable := names(aliceSID); got != "notes,r109home" || unreadable != nil {
		t.Fatalf("alice published %q (%+v), want only the CODEX_HOME servers", got, unreadable)
	}
	servers, _, err := ReadMCPSpool(dir, aliceSID, "codex", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range servers {
		if server.Name == "notes" && server.URL != "http://127.0.0.1:2/new" {
			t.Fatalf("alice notes is %q; the default file definition displaced the one Codex runs", server.URL)
		}
	}
	if got, unreadable := names(bobSID); got != "r109loop" || unreadable != nil {
		t.Fatalf("bob published %q (%+v), want his own server", got, unreadable)
	}
	if _, err := os.Stat(filepath.Join(dir, "S-1-5-21-1-1003.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an account not enrolled for Codex has a Codex record: %v", err)
	}

	// An unreadable default file Codex does not read changes nothing.
	failing[strings.ToLower(filepath.Join(alice, ".codex", "config.toml"))] = errWindowsAccountFileNotOwned
	if err := WriteWindowsMCPSpool(dir, "codex", manifest, nil, t.Logf); err != nil {
		t.Fatal(err)
	}
	if got, unreadable := names(aliceSID); got != "notes,r109home" || unreadable != nil {
		t.Fatalf("alice published %q (%+v) with an unused default file unreadable, want her CODEX_HOME servers", got, unreadable)
	}
	delete(failing, strings.ToLower(filepath.Join(alice, ".codex", "config.toml")))

	failing[strings.ToLower(filepath.Join(relocated, "config.toml"))] = errWindowsAccountFileNotOwned
	if err := WriteWindowsMCPSpool(dir, "codex", manifest, nil, t.Logf); err != nil {
		t.Fatal(err)
	}
	if got, unreadable := names(aliceSID); got != "" || unreadable == nil || !strings.EqualFold(unreadable.Path, filepath.Join(relocated, "config.toml")) {
		t.Fatalf("alice published %q (%+v), want no servers and her CODEX_HOME file named", got, unreadable)
	}
	if got, unreadable := names(bobSID); got != "r109loop" || unreadable != nil {
		t.Fatalf("bob published %q (%+v) after alice file failed", got, unreadable)
	}
	if err := WriteWindowsMCPSpool(dir, "opencode", manifest, nil, t.Logf); err == nil {
		t.Fatal("a connector with no source published")
	}
}
