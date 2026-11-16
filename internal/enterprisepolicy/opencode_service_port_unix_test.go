//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// requireOpenCodeServiceFilePrivate is the private-file contract of the
// platform: the owner alone reads and writes the file (mode 0600).
func requireOpenCodeServiceFilePrivate(t *testing.T, path string) {
	t.Helper()
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", info, err)
	}
}

// A port that already matches is checked like a port that does not
// (GAP-0053 REVIEW-1 MF1). The stow layout (a link to the account's own
// private dotfiles) stays a no-op; a link that leads to a file or folder
// another account can write is not accepted as it stands.
func TestSetOpenCodeServicePortChecksWhereAMatchingFileLives(t *testing.T) {
	const port = 25001
	type layout struct {
		name     string
		linkAt   string // "config" links ~/.config, "opencode" links ~/.config/opencode
		fileMode os.FileMode
		dirMode  os.FileMode
		wantNoOp bool
	}
	for _, c := range []layout{
		{"linked config folder, private target", "config", 0o600, 0o700, true},
		{"linked opencode folder, private target", "opencode", 0o600, 0o700, true},
		{"linked config folder, shared file", "config", 0o666, 0o700, false},
		{"linked opencode folder, shared file", "opencode", 0o666, 0o700, false},
		{"linked config folder, shared target folder", "config", 0o600, 0o777, false},
		{"linked opencode folder, shared target folder", "opencode", 0o600, 0o777, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "dotfiles")
			real := filepath.Join(target, "opencode")
			if c.linkAt == "opencode" {
				real = target
			}
			if err := os.MkdirAll(real, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(real, c.dirMode); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(real, "service.json")
			if err := os.WriteFile(file, []byte(`{"port":25001}`), c.fileMode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(file, c.fileMode); err != nil {
				t.Fatal(err)
			}
			if c.linkAt == "config" {
				if err := os.Symlink(target, filepath.Join(home, ".config")); err != nil {
					t.Skip(err)
				}
			} else {
				if err := os.MkdirAll(filepath.Join(home, ".config"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(home, ".config", "opencode")); err != nil {
					t.Skip(err)
				}
			}
			result, err := SetOpenCodeServicePort(home, port)
			if c.wantNoOp {
				if err != nil || result.Changed || result.Port != port {
					t.Fatalf("a private linked file was not accepted: %+v %v", result, err)
				}
				return
			}
			if err == nil && !result.Changed {
				t.Fatalf("a matching file another account can write was accepted as it stands: %+v", result)
			}
			if c.linkAt == "opencode" && err == nil {
				t.Fatalf("a link in place of the opencode folder was written through: %+v", result)
			}
		})
	}
}

func TestSetOpenCodeServicePortReplacesASharedWritableMatchingFile(t *testing.T) {
	const port = 25001
	for _, mode := range []os.FileMode{0o666, 0o664, 0o622} {
		home := t.TempDir()
		path := OpenCodeServiceConfigPath(home)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"port":25001,"password":"p"}`), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		result, err := SetOpenCodeServicePort(home, port)
		if err != nil || !result.Changed || result.Port != port {
			t.Fatalf("mode %o: %+v %v", mode, result, err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("mode %o: file mode after the call %v %v", mode, info, err)
		}
		if data, _ := os.ReadFile(path); !strings.Contains(string(data), `"password": "p"`) || !strings.Contains(string(data), `"port": 25001`) {
			t.Fatalf("mode %o: keys lost: %s", mode, data)
		}
	}
}

// Benign twin: an ordinary private matching file (0600 and 0644, the modes
// OpenCode creates) stays untouched.
func TestSetOpenCodeServicePortLeavesAnOrdinaryMatchingFile(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o644} {
		home := t.TempDir()
		path := OpenCodeServiceConfigPath(home)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"port":25001}`), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		before, _ := os.Stat(path)
		result, err := SetOpenCodeServicePort(home, 25001)
		after, _ := os.Stat(path)
		if err != nil || result.Changed || result.Port != 25001 || !os.SameFile(before, after) || after.Mode().Perm() != mode {
			t.Fatalf("mode %o: %+v %v", mode, result, err)
		}
	}
}

// The whole path to service.json is checked before a matching port is
// accepted and before a write (GAP-0053 REVIEW-2 MF1b): a folder another
// account can write, anywhere on the resolved path or on the path of a link
// the walk passes through, makes the file replaceable.
func TestSetOpenCodeServicePortChecksEveryFolderOnThePath(t *testing.T) {
	const port = 25001
	type layout struct {
		name  string
		build func(t *testing.T, home string) // makes the layout and opens one folder
	}
	writeFile := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "service.json"), []byte(`{"port":25001}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []layout{
		{"opencode folder world writable", func(t *testing.T, home string) {
			dir := filepath.Dir(OpenCodeServiceConfigPath(home))
			writeFile(t, dir)
			if err := os.Chmod(dir, 0o777); err != nil {
				t.Fatal(err)
			}
		}},
		{"config folder world writable", func(t *testing.T, home string) {
			writeFile(t, filepath.Dir(OpenCodeServiceConfigPath(home)))
			if err := os.Chmod(filepath.Join(home, ".config"), 0o777); err != nil {
				t.Fatal(err)
			}
		}},
		{"home world writable", func(t *testing.T, home string) {
			writeFile(t, filepath.Dir(OpenCodeServiceConfigPath(home)))
			if err := os.Chmod(home, 0o777); err != nil {
				t.Fatal(err)
			}
		}},
		{"link target parent world writable", func(t *testing.T, home string) {
			parent := filepath.Join(home, "dotfiles")
			writeFile(t, filepath.Join(parent, "opencode"))
			if err := os.MkdirAll(filepath.Join(home, ".config"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(parent, "opencode"), filepath.Join(home, ".config", "opencode")); err != nil {
				t.Skip(err)
			}
			if err := os.Chmod(parent, 0o777); err != nil {
				t.Fatal(err)
			}
		}},
		{"folder holding the link world writable", func(t *testing.T, home string) {
			writeFile(t, filepath.Join(home, "dotfiles", "opencode"))
			if err := os.MkdirAll(filepath.Join(home, ".config"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(home, "dotfiles", "opencode"), filepath.Join(home, ".config", "opencode")); err != nil {
				t.Skip(err)
			}
			if err := os.Chmod(filepath.Join(home, ".config"), 0o777); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			home := reachableHome(t)
			c.build(t, home)
			path := OpenCodeServiceConfigPath(home)
			before, _ := os.ReadFile(path)
			if result, err := SetOpenCodeServicePort(home, port); err == nil {
				t.Fatalf("a matching port was accepted through a folder another account can write: %+v", result)
			}
			if result, err := SetOpenCodeServicePort(home, port+1); err == nil {
				t.Fatalf("a port was written through a folder another account can write: %+v", result)
			}
			if after, _ := os.ReadFile(path); string(after) != string(before) {
				t.Fatalf("the file changed: %s", after)
			}
		})
	}
}

// Benign twin: a sticky folder everyone can write (the shared scratch root)
// above a private home, and the private-group layout of Debian and Ubuntu,
// keep a matching port a no-op.
func TestSetOpenCodeServicePortAcceptsStickyAndPrivateGroupFolders(t *testing.T) {
	const port = 25001
	t.Run("sticky world writable folder above the home", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chmod(root, os.ModeSticky|0o777); err != nil {
			t.Fatal(err)
		}
		home := filepath.Join(root, "home")
		path := OpenCodeServiceConfigPath(home)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"port":25001}`), 0o600); err != nil {
			t.Fatal(err)
		}
		result, err := SetOpenCodeServicePort(home, port)
		if err != nil || result.Changed || result.Port != port {
			t.Fatalf("%+v %v", result, err)
		}
	})
	t.Run("stow target in the private group of the account", func(t *testing.T) {
		home := t.TempDir()
		target := filepath.Join(home, "dotfiles", "opencode")
		if err := os.MkdirAll(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(target, 0o775); err != nil {
			t.Fatal(err)
		}
		info, _ := os.Lstat(target)
		if !connector.OwnerPrivateGroup(target, info) {
			t.Skip("the primary group of this account is not private to it")
		}
		if err := os.WriteFile(filepath.Join(target, "service.json"), []byte(`{"port":25001}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(home, ".config"), 0o775); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(home, ".config", "opencode")); err != nil {
			t.Skip(err)
		}
		result, err := SetOpenCodeServicePort(home, port)
		if err != nil || result.Changed || result.Port != port {
			t.Fatalf("a stow target in the private group was refused: %+v %v", result, err)
		}
	})
}

// A group-write folder is refused when its group is not the private group of
// the account (a supplementary group stands in for a shared one).
func TestSetOpenCodeServicePortRefusesASharedGroupFolder(t *testing.T) {
	gid := -1
	groups, _ := os.Getgroups()
	for _, g := range groups {
		if g != os.Getegid() {
			gid = g
			break
		}
	}
	if gid < 0 {
		t.Skip("this account has no supplementary group")
	}
	home := t.TempDir()
	dir := filepath.Dir(OpenCodeServiceConfigPath(home))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "service.json"), []byte(`{"port":25001}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, -1, gid); err != nil {
		t.Skip(err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Lstat(dir); info.Sys().(*syscall.Stat_t).Gid != uint32(gid) {
		t.Skip("the group was not applied")
	}
	if result, err := SetOpenCodeServicePort(home, 25001); err == nil {
		t.Fatalf("a folder a shared group can write was accepted: %+v", result)
	}
}

// reachableHome returns a new home directly beneath /tmp, so every folder
// above it is searchable by another account (a t.TempDir parent is mode 0700,
// and so is the per-user TMPDIR of macOS, and would hide the folders the test
// opens). The home gets the group of the test account: a new entry takes the
// group of the folder it is made in on macOS and BSD (and in a setgid folder on
// Linux), which would be the group of /tmp, not one the second account holds,
// and the group-write cases would then be refused for the wrong reason.
func reachableHome(t *testing.T) string {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "opencode-port-home-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(home, -1, os.Getegid()); err != nil {
		_ = os.RemoveAll(home)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o700); _ = os.RemoveAll(home) })
	if err := os.Chmod(home, 0o755); err != nil {
		t.Fatal(err)
	}
	return home
}

// REVIEW-3 MF1: a 0775 target whose group the local files call private, but
// the name service gives a second member (the proof says no), is refused even
// when service.json already names the recorded port: the member can rename a
// new file over it. The setter must not report the port as reconciled; the
// guardian warns instead. The proof itself is TestOwnerPrivateGroupStrictAsksTheNameService.
func TestSetOpenCodeServicePortRefusesALinkedTargetWhoseGroupIsNotProvablyPrivate(t *testing.T) {
	const port = 25001
	for _, private := range []bool{true, false} {
		name := "group proven private"
		if !private {
			name = "group has a member the name service lists"
		}
		t.Run(name, func(t *testing.T) {
			old := openCodeOwnerPrivateGroup
			openCodeOwnerPrivateGroup = func(string, os.FileInfo) bool { return private }
			t.Cleanup(func() { openCodeOwnerPrivateGroup = old })
			home := t.TempDir()
			target := filepath.Join(home, "dotfiles", "opencode")
			if err := os.MkdirAll(target, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(target, 0o775); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(target, "service.json")
			if err := os.WriteFile(file, []byte(`{"port":25001}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(home, ".config"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(home, ".config", "opencode")); err != nil {
				t.Skip(err)
			}
			result, err := SetOpenCodeServicePort(home, port)
			if private {
				if err != nil || result.Changed || result.Port != port {
					t.Fatalf("a private-group stow target was refused: %+v %v", result, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("a target another account can write was reported as reconciled: %+v", result)
			}
			if after, _ := os.ReadFile(file); string(after) != `{"port":25001}` {
				t.Fatalf("the file changed: %s", after)
			}
		})
	}
}
