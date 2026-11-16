// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// mklinkJunction makes a directory junction (no privilege needed).
func mklinkJunction(t *testing.T, link, target string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
}

// A junction (a reparse point that is not a symbolic link) on any folder level
// must not lead into another account's data. This test has only been
// compiled and vetted for windows so far (live check on a Windows host).
func TestClaudeDesktopJunctionsAreNotFollowed(t *testing.T) {
	claudeDesktopTestOS(t, "windows")
	for _, tc := range []struct{ name, link string }{
		{"claude-code", "claude-code"},
		{"vm_bundles", "vm_bundles"},
		{"the bundle itself", `vm_bundles\claudevm.bundle`},
		{"local-agent-mode-sessions", "local-agent-mode-sessions"},
		{"the account folder", `local-agent-mode-sessions\acct-1`},
		{"the organization folder", `local-agent-mode-sessions\acct-1\org-1`},
		{"the plugin folder", `local-agent-mode-sessions\acct-1\org-1\rpm`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			victim := filepath.Join(t.TempDir(), "victim")
			seedClaudeDesktopData(t, victim)
			home := t.TempDir()
			t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
			t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
			data := filepath.Join(home, "AppData", "Roaming", "Claude")
			if err := os.MkdirAll(data, 0o700); err != nil {
				t.Fatal(err)
			}
			mklinkJunction(t, filepath.Join(data, tc.link), filepath.Join(victim, tc.link))
			info := claudeDesktopOne(t, claudeDesktopTestService(home)).ClaudeDesktop
			if info.EngineVersion != "" || info.CoworkEnabled != nil || len(info.CoworkPlugins) != 0 || info.VMBundlePresent || info.VMBundleBytes != 0 {
				t.Fatalf("a junction was followed: %+v", info)
			}
		})
	}
	t.Run("a junction as the data folder", func(t *testing.T) {
		victim := filepath.Join(t.TempDir(), "victim")
		seedClaudeDesktopData(t, victim)
		home := t.TempDir()
		t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
		t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
		mklinkJunction(t, filepath.Join(home, "AppData", "Roaming", "Claude"), victim)
		if got := claudeDesktopTestService(home).detectClaudeDesktop(); len(got) != 0 {
			t.Fatalf("a junction data folder produced %+v", got)
		}
	})
}

// Attributes that cannot be read count as a reparse point (refused), and a
// folder os.Open reached through a junction is not the folder that was
// checked, whatever its own attributes say.
func TestClaudeDesktopWindowsReparseChecksFailClosed(t *testing.T) {
	root := t.TempDir()
	if !claudeDesktopReparsePoint(filepath.Join(root, "absent")) {
		t.Fatal("unreadable attributes were taken for a real folder")
	}
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(real)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if claudeDesktopReparsePoint(real) || !claudeDesktopOpenedIsChecked(real, f) {
		t.Fatal("a real folder was refused")
	}
	link := filepath.Join(root, "link")
	mklinkJunction(t, link, real)
	followed, err := os.Open(link)
	if err != nil {
		t.Fatal(err)
	}
	defer followed.Close()
	if claudeDesktopOpenedIsChecked(link, followed) {
		t.Fatal("a folder opened through a junction passed the handle check")
	}
	if _, _, err := claudeDesktopReadDir(link, 8); err == nil {
		t.Fatal("claudeDesktopReadDir listed a junction")
	}
}
