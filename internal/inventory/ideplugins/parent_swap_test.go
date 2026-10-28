// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package ideplugins

import (
	"os"
	"path/filepath"
	"testing"
)

// A folder above the VS Code state database that is swapped for a link to
// another profile after the scan checked it, and before SQLite opens the
// database, does not apply that profile's disabled list to this home's
// plugins: the state is unknown instead (GAP-1138).
func TestParentSwappedBeforeStateDBOpenDoesNotReadAnotherProfile(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home, other := filepath.Join(root, "alice"), filepath.Join(root, "bob")
	writeFile(t, filepath.Join(home, ".vscode", "extensions", "extensions.json"), `[{"identifier":{"id":"example.tool"},"version":"1.0.0"}]`)
	storage := filepath.Join(".config", "Code", "User", "globalStorage")
	writeStateDB(t, filepath.Join(home, storage, "state.vscdb"), "[]")
	writeStateDB(t, filepath.Join(other, storage, "state.vscdb"), `[{"id":"example.tool"}]`)
	target := filepath.Join(home, storage, "state.vscdb")
	swapped := false
	beforeOpen = func(path string) {
		if path != target || swapped {
			return
		}
		swapped = true
		user := filepath.Join(home, ".config", "Code", "User")
		if err := os.Rename(filepath.Join(user, "globalStorage"), filepath.Join(user, "globalStorage-moved")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(other, storage), filepath.Join(user, "globalStorage")); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { beforeOpen = nil })
	p := byID(Scan(home, "linux", Limits{}), FamilyVSCode, "vscode", "")["example.tool|user"]
	if !swapped {
		t.Fatal("the scan never opened the state database")
	}
	if p.Enabled == EnabledOff {
		t.Fatalf("the other profile's disabled list was applied: %+v", p)
	}
}

// A folder above a plugin file that is swapped for a link to another
// profile after the scan checked it, and before the file is opened, does
// not put that profile's metadata in this home's inventory (GAP-1138).
func TestParentSwappedBeforeOpenDoesNotReadAnotherProfile(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home, other := filepath.Join(root, "alice"), filepath.Join(root, "bob")
	rel := filepath.Join(".vscode", "extensions", "example.tool-1.0.0", "package.json")
	writeFile(t, filepath.Join(home, rel), `{"name":"tool","publisher":"example","version":"1.0.0"}`)
	writeFile(t, filepath.Join(other, rel), `{"name":"tool","publisher":"example","version":"9.9.9"}`)
	target := filepath.Join(home, rel)
	swapped := false
	beforeOpen = func(path string) {
		if path != target || swapped {
			return
		}
		swapped = true
		if err := os.Rename(filepath.Join(home, ".vscode"), filepath.Join(home, ".vscode-moved")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(other, ".vscode"), filepath.Join(home, ".vscode")); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { beforeOpen = nil })
	installs := Scan(home, "linux", Limits{})
	if !swapped {
		t.Fatal("the scan never opened the plugin manifest")
	}
	for _, inst := range installs {
		for _, p := range inst.Plugins {
			if p.Version == "9.9.9" {
				t.Fatalf("plugin %s read from the other profile: %+v", p.ID, p)
			}
		}
	}
}
