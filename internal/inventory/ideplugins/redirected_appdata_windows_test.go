// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ideplugins

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// redirectedProfiles lays out alice's profile, an empty folder her %APPDATA%
// is redirected to, and bob's %APPDATA% with a JetBrains plugin and a VS
// Code state database that disables alice's extension.
func redirectedProfiles(t *testing.T) (home string, limits Limits, bob string) {
	t.Helper()
	// The long path: the scan compares it with the path Windows gives an
	// opened handle.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home = filepath.Join(root, "Users", "alice")
	bob = filepath.Join(root, "Users", "bob", "AppData", "Roaming")
	limits = Limits{
		RoamingAppData: filepath.Join(root, "Redirected", "alice", "Roaming"),
		LocalAppData:   filepath.Join(root, "Redirected", "alice", "Local"),
	}
	writeFile(t, filepath.Join(home, ".vscode", "extensions", "extensions.json"), `[{"identifier":{"id":"example.tool"},"version":"1.0.0"}]`)
	writeJar(t, filepath.Join(bob, "JetBrains", "PyCharm2024.1", "plugins", "bob-tool", "lib", "bob-tool.jar"),
		`<idea-plugin><id>com.example.bob</id><name>Bob</name><version>1.0</version></idea-plugin>`)
	writeStateDB(t, filepath.Join(bob, "Code", "User", "globalStorage", "state.vscdb"), `[{"id":"example.tool"}]`)
	return home, limits, bob
}

// junction makes link a directory junction to target, which an unprivileged
// account can create.
func junction(t *testing.T, link, target string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J %s %s: %v: %s", link, target, err, out)
	}
}

// assertNotBobs fails when the scan put bob's plugin or bob's disabled list
// in alice's inventory.
func assertNotBobs(t *testing.T, installs []Install, what string) {
	t.Helper()
	for _, inst := range installs {
		for _, p := range inst.Plugins {
			if p.ID == "com.example.bob" {
				t.Errorf("%s: bob's plugin is in alice's inventory: %+v", what, p)
			}
		}
	}
	if p := byID(installs, FamilyVSCode, "vscode", "")["example.tool|user"]; p.Enabled == EnabledOff {
		t.Errorf("%s: bob's state database disabled alice's extension: %+v", what, p)
	}
}

// A redirected %APPDATA% on a local folder is read in place.
func TestRedirectedAppDataIsReadOnWindows(t *testing.T) {
	home, limits, _ := redirectedProfiles(t)
	writeJar(t, filepath.Join(limits.RoamingAppData, "JetBrains", "PyCharm2024.1", "plugins", "alice-tool", "lib", "alice-tool.jar"),
		`<idea-plugin><id>com.example.alice</id><name>Alice</name><version>1.0</version></idea-plugin>`)
	writeStateDB(t, filepath.Join(limits.RoamingAppData, "Code", "User", "globalStorage", "state.vscdb"), `[{"id":"example.tool"}]`)
	installs := Scan(home, "windows", limits)
	if _, ok := byID(installs, FamilyJetBrains, "pycharm", "")["com.example.alice|user"]; !ok {
		t.Errorf("the plugin in the redirected folder was not found: %+v", installs)
	}
	if p := byID(installs, FamilyVSCode, "vscode", "")["example.tool|user"]; p.Enabled != EnabledOff || p.EnabledSource != SourceStateDB {
		t.Errorf("extension = %+v, want disabled by the redirected state database", p)
	}
}

// The redirected %APPDATA% replaced by a junction to another account's
// %APPDATA%: none of that account's plugins or settings are read.
func TestRedirectedAppDataJunctionToAnotherProfileIsNotRead(t *testing.T) {
	home, limits, bob := redirectedProfiles(t)
	junction(t, limits.RoamingAppData, bob)
	assertNotBobs(t, Scan(home, "windows", limits), "junction as the redirected folder")
}

// A junction below the redirected %APPDATA% is not followed.
func TestJunctionBelowRedirectedAppDataIsNotFollowed(t *testing.T) {
	home, limits, bob := redirectedProfiles(t)
	junction(t, filepath.Join(limits.RoamingAppData, "JetBrains"), filepath.Join(bob, "JetBrains"))
	junction(t, filepath.Join(limits.RoamingAppData, "Code"), filepath.Join(bob, "Code"))
	assertNotBobs(t, Scan(home, "windows", limits), "junctions below the redirected folder")
}

// A hard link in the redirected %APPDATA% to another account's file is not
// read: the file has more than one name.
func TestHardLinkInRedirectedAppDataIsNotRead(t *testing.T) {
	home, limits, bob := redirectedProfiles(t)
	for _, rel := range []string{
		filepath.Join("JetBrains", "PyCharm2024.1", "plugins", "bob-tool", "lib", "bob-tool.jar"),
		filepath.Join("Code", "User", "globalStorage", "state.vscdb"),
	} {
		dst := filepath.Join(limits.RoamingAppData, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(bob, rel), dst); err != nil {
			t.Fatal(err)
		}
	}
	assertNotBobs(t, Scan(home, "windows", limits), "hard links in the redirected folder")
}
