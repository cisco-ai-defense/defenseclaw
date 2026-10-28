// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package ideplugins

import (
	"os"
	"path/filepath"
	"testing"
)

// A scan that does not follow links reads a Windows %APPDATA% that folder
// redirection moved out of the profile, and stays inside it there as it
// does in the home: a link below the redirected folder is not followed.
func TestRedirectedAppDataOutsideTheHomeIsReadInPlace(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home, roaming, other := filepath.Join(root, "Users", "alice"), filepath.Join(root, "Redirected", "alice", "Roaming"), filepath.Join(root, "Users", "bob")
	writeFile(t, filepath.Join(home, ".vscode", "extensions", "extensions.json"), `[{"identifier":{"id":"example.tool"},"version":"1.0.0"},{"identifier":{"id":"example.other"},"version":"1.0.0"}]`)
	writeStateDB(t, filepath.Join(roaming, "Code", "User", "globalStorage", "state.vscdb"), `[{"id":"example.tool"}]`)
	limits := Limits{RoamingAppData: roaming, LocalAppData: filepath.Join(root, "Redirected", "alice", "Local")}
	plugins := byID(Scan(home, "windows", limits), FamilyVSCode, "vscode", "")
	if p := plugins["example.tool|user"]; p.Enabled != EnabledOff || p.EnabledSource != SourceStateDB {
		t.Fatalf("plugin = %+v, want disabled by the redirected state database", p)
	}
	// The redirected Code folder becomes a link to another profile's.
	writeStateDB(t, filepath.Join(other, "Code", "User", "globalStorage", "state.vscdb"), `[{"id":"example.other"}]`)
	if err := os.RemoveAll(filepath.Join(roaming, "Code")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, "Code"), filepath.Join(roaming, "Code")); err != nil {
		t.Fatal(err)
	}
	plugins = byID(Scan(home, "windows", limits), FamilyVSCode, "vscode", "")
	if p := plugins["example.other|user"]; p.Enabled == EnabledOff {
		t.Fatalf("plugin = %+v: the link below the redirected folder was followed", p)
	}
}

// The redirected folder itself swapped for a link to another profile's
// folder after the enumerator checked it: the scan does not read through
// the link.
func TestRedirectedAppDataRootSwappedForALinkIsNotRead(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home, roaming, other := filepath.Join(root, "Users", "alice"), filepath.Join(root, "Redirected", "alice", "Roaming"), filepath.Join(root, "Users", "bob", "AppData", "Roaming")
	writeFile(t, filepath.Join(home, ".vscode", "extensions", "extensions.json"), `[{"identifier":{"id":"example.other"},"version":"1.0.0"}]`)
	writeStateDB(t, filepath.Join(other, "Code", "User", "globalStorage", "state.vscdb"), `[{"id":"example.other"}]`)
	if err := os.MkdirAll(filepath.Dir(roaming), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, roaming); err != nil {
		t.Fatal(err)
	}
	limits := Limits{RoamingAppData: roaming, LocalAppData: filepath.Join(root, "Redirected", "alice", "Local")}
	plugins := byID(Scan(home, "windows", limits), FamilyVSCode, "vscode", "")
	if p, ok := plugins["example.other|user"]; !ok || p.Enabled == EnabledOff {
		t.Fatalf("plugin = %+v (found %v): the other profile's state database was read through the swapped folder", p, ok)
	}
}
