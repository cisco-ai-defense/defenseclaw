//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// agentConfigHome is a home with the usual agent config files, each written by
// the account. rootOwns then makes named paths read as root-owned.
func agentConfigHome(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("a root caller never sees root-owned agent config")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	for _, rel := range []string{".claude/settings.json", ".codex/config.toml", ".copilot/hooks/defenseclaw.json", ".cursor/hooks.json"} {
		writeAgentConfig(t, filepath.Join(home, rel))
	}
	return home
}

func writeAgentConfig(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// rootOwns makes the paths read as owned by root: the same inode is root-owned
// under any name that reaches it.
func rootOwns(t *testing.T, paths ...string) {
	t.Helper()
	var known []os.FileInfo
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		known = append(known, info)
	}
	real := agentConfigOwner
	t.Cleanup(func() { agentConfigOwner = real })
	agentConfigOwner = func(info os.FileInfo) (uint32, uint64, bool) {
		uid, links, ok := real(info)
		for _, owned := range known {
			if os.SameFile(info, owned) {
				return 0, links, true
			}
		}
		return uid, links, ok
	}
}

func TestRootOwnedAgentConfigPathsNamesTheVendorFilesRootWrote(t *testing.T) {
	home := agentConfigHome(t)
	// The cursor file stays with the account: the benign twin.
	rootOwns(t,
		filepath.Join(home, ".claude/settings.json"),
		filepath.Join(home, ".codex/config.toml"),
		filepath.Join(home, ".copilot/hooks/defenseclaw.json"),
	)
	got := RootOwnedAgentConfigPaths(filepath.Join(home, ".defenseclaw"))
	want := []string{
		filepath.Join(home, ".claude/settings.json"),
		filepath.Join(home, ".codex/config.toml"),
		filepath.Join(home, ".copilot/hooks/defenseclaw.json"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("root-owned agent config = %v, want %v", got, want)
	}
}

func TestRootOwnedAgentConfigPathsLeavesAnAccountOwnedHomeAlone(t *testing.T) {
	home := agentConfigHome(t)
	if got := RootOwnedAgentConfigPaths(filepath.Join(home, ".defenseclaw")); len(got) != 0 {
		t.Fatalf("account-owned agent config listed: %v", got)
	}
}

// A root-owned folder is returned whole: the account cannot create the atomic
// temp file in it, and a 0700 one hides its files from this scan.
func TestRootOwnedAgentConfigPathsNamesTheRootOwnedVendorFolderNotItsFiles(t *testing.T) {
	home := agentConfigHome(t)
	folder := filepath.Join(home, ".copilot", "hooks")
	rootOwns(t, folder, filepath.Join(folder, "defenseclaw.json"))
	got := RootOwnedAgentConfigPaths(filepath.Join(home, ".defenseclaw"))
	if want := []string{folder}; !reflect.DeepEqual(got, want) {
		t.Fatalf("root-owned vendor folder = %v, want %v", got, want)
	}
}

func TestRootOwnedAgentConfigPathsNamesAFolderTheAccountCannotEnter(t *testing.T) {
	home := agentConfigHome(t)
	folder := filepath.Join(home, ".claude")
	rootOwns(t, folder)
	if err := os.Chmod(folder, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(folder, 0o700) })
	got := RootOwnedAgentConfigPaths(filepath.Join(home, ".defenseclaw"))
	if want := []string{folder}; !reflect.DeepEqual(got, want) {
		t.Fatalf("root-owned folder the account cannot enter = %v, want %v", got, want)
	}
}

// A root-owned file outside the home must never reach the chown, however the
// vendor path links to it.
func TestRootOwnedAgentConfigPathsSkipsLinkedTargets(t *testing.T) {
	home := agentConfigHome(t)
	outside := t.TempDir()
	target := filepath.Join(outside, "settings.json")
	writeAgentConfig(t, target)
	rootOwns(t, target)

	// A folder link on the way: ~/.claude -> outside.
	if err := os.RemoveAll(filepath.Join(home, ".claude")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, ".claude")); err != nil {
		t.Fatal(err)
	}
	// A file link: ~/.codex/config.toml -> outside file.
	if err := os.Remove(filepath.Join(home, ".codex/config.toml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, ".codex/config.toml")); err != nil {
		t.Fatal(err)
	}
	// A hard link: the vendor path is a second name of the outside inode.
	if err := os.Remove(filepath.Join(home, ".copilot/hooks/defenseclaw.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, filepath.Join(home, ".copilot/hooks/defenseclaw.json")); err != nil {
		t.Fatal(err)
	}
	if got := RootOwnedAgentConfigPaths(filepath.Join(home, ".defenseclaw")); len(got) != 0 {
		t.Fatalf("a path that links outside the home was listed: %v", got)
	}
}

// A home reached through a link is still scanned: the walk starts from the
// physical home and names its paths from there.
func TestRootOwnedAgentConfigPathsNamesPhysicalPathsOfALinkedHome(t *testing.T) {
	home := agentConfigHome(t)
	linked := filepath.Join(t.TempDir(), "home-link")
	if err := os.Symlink(home, linked); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", linked)
	path := filepath.Join(home, ".claude/settings.json")
	rootOwns(t, path)
	got := RootOwnedAgentConfigPaths(filepath.Join(linked, ".defenseclaw"))
	if want := []string{path}; !reflect.DeepEqual(got, want) {
		t.Fatalf("linked home = %v, want %v", got, want)
	}
}
