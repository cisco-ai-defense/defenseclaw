//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// trustChainTestDir is trustedTestDir for the path-trust tests, which need
// every ancestor to refuse group and other writes: a checkout made with a
// group-writable umask (002, the default for Ubuntu users) cannot model the
// owner-only chain they check.
func trustChainTestDir(t *testing.T) string {
	t.Helper()
	dir := trustedTestDir(t)
	for ancestor := filepath.Dir(dir); ; ancestor = filepath.Dir(ancestor) {
		if info, err := os.Stat(ancestor); err == nil && info.Mode().Perm()&0o022 != 0 {
			t.Skipf("%s is group- or world-writable; the path-trust tests need an owner-only chain", ancestor)
		}
		if ancestor == filepath.Dir(ancestor) {
			return dir
		}
	}
}

// sharedAgentPrefix lays out a machine prefix outside home with a devin CLI
// that leaves a marker when it runs and a codex package.json, and makes it
// the only machine prefix discovery searches.
func sharedAgentPrefix(t *testing.T, home string) (prefix, marker string) {
	t.Helper()
	prefix = trustChainTestDir(t)
	previous := machinePrefixes
	machinePrefixes = func() []string { return []string{prefix} }
	t.Cleanup(func() { machinePrefixes = previous })
	bin := filepath.Join(prefix, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	marker = filepath.Join(home, "ran")
	script := "#!/bin/sh\ntouch '" + marker + "'\necho 'devin 2026.2.3'\n"
	if err := os.WriteFile(filepath.Join(bin, "devin"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestPackage(t, filepath.Join(prefix, "lib", "node_modules", "@openai", "codex"), "@openai/codex", "0.170.0")
	return prefix, marker
}

// A shared prefix directory that other accounts can write (a group-writable
// Linuxbrew or Homebrew bin directory) lets any of them replace the CLI, so
// discovery neither runs it nor reads package metadata below it for the
// target user; the CLI is still reported as installed.
func TestDiscoverUnixAgentVersionSkipsSharedPrefixesOthersCanWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("ownership checks need a non-root test account")
	}
	home := trustChainTestDir(t)
	prefix, marker := sharedAgentPrefix(t, home)

	if version, reason := DiscoverUnixAgentVersion(context.Background(), home, "devin", true); version != "2026.2.3" {
		t.Fatalf("devin from a prefix only the user and root can change = %q (%s)", version, reason)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the trusted CLI did not run: %v", err)
	}
	if version, reason := DiscoverUnixAgentVersion(context.Background(), home, "codex", false); version != "0.170.0" {
		t.Fatalf("codex metadata from a trusted prefix = %q (%s)", version, reason)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}

	bin := filepath.Join(prefix, "bin")
	if err := os.Chmod(bin, 0o775); err != nil {
		t.Fatal(err)
	}
	version, reason := DiscoverUnixAgentVersion(context.Background(), home, "devin", true)
	if version != "" || !UnixAgentInstalledWithoutVersion(reason) || !strings.Contains(reason, filepath.Join(bin, "devin")+" (not run") {
		t.Fatalf("devin in a group-writable prefix = %q (%s), want it reported installed and not run", version, reason)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("discovery ran a CLI from a group-writable directory: %v", err)
	}
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	modules := filepath.Join(prefix, "lib", "node_modules")
	if err := os.Chmod(modules, 0o777); err != nil {
		t.Fatal(err)
	}
	if version, reason := DiscoverUnixAgentVersion(context.Background(), home, "codex", false); version != "" {
		t.Fatalf("codex metadata below a world-writable directory was read: %q (%s)", version, reason)
	}

	// The standalone per-user worker's PATH leaves out a machine bin directory
	// another account could change, as discovery does, so connector setup never
	// finds an agent there; the Secure Client guardian's PATH is unchanged.
	t.Run("search dirs", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("ownership checks need a non-root test account")
		}
		uid := os.Geteuid()
		prefix := trustChainTestDir(t)
		bin := filepath.Join(prefix, "bin")
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		previous := machinePrefixes
		machinePrefixes = func() []string { return []string{prefix} }
		t.Cleanup(func() { machinePrefixes = previous; SetStandaloneUnix(false) })
		home := filepath.Join(t.TempDir(), "alice")

		SetStandaloneUnix(true)
		if dirs := UnixAgentSearchDirsFor(home, uid); !containsString(dirs, bin) {
			t.Fatalf("a machine dir only root and the user can change was left out: %v", dirs)
		}
		if dirs := UnixAgentSearchDirsFor(home, uid+1); containsString(dirs, bin) {
			t.Fatalf("a machine dir another account owns stayed on the worker PATH: %v", dirs)
		}
		if dirs := UnixAgentSearchDirsFor(home, uid+1); !containsString(dirs, filepath.Join(home, ".local", "bin")) {
			t.Fatalf("the user's own bin dir was left out: %v", dirs)
		}
		SetStandaloneUnix(false)
		if dirs := UnixAgentSearchDirsFor(home, uid+1); !containsString(dirs, bin) {
			t.Fatalf("outside the standalone profile the machine dirs changed: %v", dirs)
		}
	})
}

// The worker runs discovery as each enrolled user. A CLI outside the home
// that another account owns (the account that installed Linuxbrew under
// /home/linuxbrew, for example) is not run as the target user, and its
// package metadata is not read; neither is a CLI the user's home links to
// in such a tree.
func TestDiscoverUnixAgentVersionRunsNoCandidateOwnedByAnotherAccount(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("ownership checks need a non-root test account")
	}
	home := trustChainTestDir(t)
	prefix, marker := sharedAgentPrefix(t, home)
	previous := unixDiscoveryUID
	// The prefix belongs to the test account; discover as another account.
	unixDiscoveryUID = func() int { return os.Geteuid() + 1 }
	t.Cleanup(func() { unixDiscoveryUID = previous })

	cli := filepath.Join(prefix, "bin", "devin")
	version, reason := DiscoverUnixAgentVersion(context.Background(), home, "devin", true)
	if version != "" || !UnixAgentInstalledWithoutVersion(reason) || !strings.Contains(reason, cli+" (not run") {
		t.Fatalf("devin owned by another account = %q (%s), want it reported installed and not run", version, reason)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("discovery ran another account's CLI as the target user: %v", err)
	}
	if version, reason := DiscoverUnixAgentVersion(context.Background(), home, "codex", false); version != "" {
		t.Fatalf("codex metadata owned by another account was read: %q (%s)", version, reason)
	}

	// A link in the user's own bin directory to that CLI is not followed.
	link := filepath.Join(home, ".local", "bin", "devin")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(cli, link); err != nil {
		t.Fatal(err)
	}
	if version, reason := DiscoverUnixAgentVersion(context.Background(), home, "devin", true); version != "" {
		t.Fatalf("a home link to another account's CLI ran it: %q (%s)", version, reason)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("discovery followed a home link to another account's CLI: %v", err)
	}

	// The user's own CLI in the home still runs.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	own := "#!/bin/sh\necho 'devin 2026.3.1'\n"
	if err := os.WriteFile(link, []byte(own), 0o755); err != nil {
		t.Fatal(err)
	}
	if version, reason := DiscoverUnixAgentVersion(context.Background(), home, "devin", true); version != "2026.3.1" {
		t.Fatalf("the user's own CLI = %q (%s)", version, reason)
	}
}

func TestUnixPathTrustedForFollowsLinksAndChecksEveryElement(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("ownership checks need a non-root test account")
	}
	uid := os.Geteuid()
	dir := trustChainTestDir(t)
	file := filepath.Join(dir, "real", "tool")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("real", "tool"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "real", "tool"), filepath.Join(dir, "real", "up")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{file, filepath.Join(dir, "link"), filepath.Join(dir, "real", "up"), filepath.Join(dir, "real", ".", "tool")} {
		if !unixPathTrustedFor(path, uid) {
			t.Fatalf("%s not trusted for its owner", path)
		}
		if unixPathTrustedFor(path, uid+1) {
			t.Fatalf("%s trusted for another account", path)
		}
	}
	if unixPathTrustedFor("relative/tool", uid) {
		t.Fatal("a relative path was trusted")
	}
	// A link into a directory others can write is not trusted.
	open := filepath.Join(dir, "open")
	if err := os.MkdirAll(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(open, "tool"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(open, "tool"), filepath.Join(dir, "real", "via-open")); err != nil {
		t.Fatal(err)
	}
	if unixPathTrustedFor(filepath.Join(dir, "real", "via-open"), uid) {
		t.Fatal("a link into a world-writable directory was trusted")
	}
	// A loop of links is refused.
	if err := os.Symlink("loop-b", filepath.Join(dir, "loop-a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("loop-a", filepath.Join(dir, "loop-b")); err != nil {
		t.Fatal(err)
	}
	if unixPathTrustedFor(filepath.Join(dir, "loop-a"), uid) {
		t.Fatal("a link loop was trusted")
	}
}

// On macOS /Applications is root:admin 0775 and a Homebrew prefix belongs to
// the administrator who installed it (admin group, group-writable). The
// admin group can already act as root through sudo, so an element of that
// group that others cannot write is admitted when root, the target or an
// admin member owns it; a world-writable element or a non-member owner is
// still refused, and Linux stays strict.
func TestUnixPathTrustedForAdmitsTheMacOSAdminGroup(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("ownership checks need a non-root test account")
	}
	uid, gid := os.Geteuid(), uint32(os.Getegid())
	dir := trustedTestDir(t)
	app := filepath.Join(dir, "Applications", "Agent.app", "Contents", "MacOS")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "Applications"), 0o775); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(app, "agent")
	if err := os.WriteFile(tool, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if unixPathTrustedFor(tool, uid+1) {
		t.Fatal("premise: a group-writable folder another account owns is refused without the admin rule")
	}

	previousGroup, previousMember := unixPathTrustAdminGroup, unixAdminGroupMember
	t.Cleanup(func() { unixPathTrustAdminGroup, unixAdminGroupMember = previousGroup, previousMember })
	// The test account's own group stands in for macOS admin, and the test
	// account for an administrator who installed the app.
	unixPathTrustAdminGroup = func() (uint32, bool) { return gid, true }
	member := true
	unixAdminGroupMember = func(owner, group uint32) bool { return member && int(owner) == uid && group == gid }
	if !unixPathTrustedFor(tool, uid+1) {
		t.Fatal("an admin-group install another admin owns was refused")
	}
	member = false
	if unixPathTrustedFor(tool, uid+1) {
		t.Fatal("a group-writable folder owned by a non-member was trusted")
	}
	member = true
	if err := os.Chmod(filepath.Join(dir, "Applications"), 0o777); err != nil {
		t.Fatal(err)
	}
	if unixPathTrustedFor(tool, uid+1) {
		t.Fatal("a world-writable folder was trusted")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
