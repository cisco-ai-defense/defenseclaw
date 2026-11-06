// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// GAP-0657: Ubuntu's umask 002 with user private groups leaves
// ~/.config and ~/.config/opencode at 0775. The gateway refused to install
// the OpenCode plugin under them. A folder of the owner's own private group
// passes; a shared group, a group member, another account with that primary
// group, or write for everyone is still refused.
func TestPluginDestinationAcceptsOnlyTheOwnersPrivateGroup(t *testing.T) {
	me := &user.User{Username: "me", Uid: fmt.Sprint(os.Geteuid())}
	for _, tc := range []struct {
		name, passwdExtra, group string
		mode                     os.FileMode
		want                     string // "" = accepted
	}{
		{name: "private group", mode: 0o775},
		{name: "shared group", group: "devs:x:%[2]s:%[1]s,bob\n", mode: 0o775, want: "group/other writable"},
		{name: "member in private group", group: "%[1]s:x:%[2]s:%[1]s,bob\n", mode: 0o775, want: "group/other writable"},
		{name: "other account with that primary group", passwdExtra: "bob:x:%[3]d:%[2]s::/home/bob:/bin/sh\n", mode: 0o775, want: "group/other writable"},
		{name: "same login name with another uid", passwdExtra: "%[1]s:x:%[3]d:%[2]s::/home/other:/bin/sh\n", mode: 0o775, want: "group/other writable"},
		{name: "everyone writable", mode: 0o777, want: "group/other writable"},
		{name: "group file unreadable", group: "-", mode: 0o775, want: "group/other writable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			pluginDir := filepath.Join(root, ".config", "opencode", "plugins")
			if err := os.MkdirAll(pluginDir, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, dir := range []string{filepath.Join(root, ".config"), filepath.Join(root, ".config", "opencode")} {
				if err := os.Chmod(dir, tc.mode); err != nil {
					t.Fatal(err)
				}
			}
			dropInheritedACLs(t, root)
			info, err := os.Lstat(filepath.Join(root, ".config"))
			if err != nil {
				t.Fatal(err)
			}
			gid := fmt.Sprint(info.Sys().(*syscall.Stat_t).Gid)
			oldUser, oldLookupGroup := privateGroupLookupUser, privateGroupLookupGroup
			privateGroupLookupUser = func(string) (*user.User, error) {
				return &user.User{Username: me.Username, Uid: me.Uid, Gid: gid}, nil
			}
			privateGroupLookupGroup = func(string) (*user.Group, error) { return &user.Group{Gid: gid, Name: me.Username}, nil }
			t.Cleanup(func() { privateGroupLookupUser, privateGroupLookupGroup = oldUser, oldLookupGroup })
			files := t.TempDir()
			passwd := filepath.Join(files, "passwd")
			groupFile := filepath.Join(files, "group")
			line := fmt.Sprintf("%s:x:%s:%s::%s:/bin/sh\n", me.Username, me.Uid, gid, root)
			if tc.passwdExtra != "" {
				line += fmt.Sprintf(tc.passwdExtra, me.Username, gid, os.Geteuid()+1)
			}
			if err := os.WriteFile(passwd, []byte(line), 0o600); err != nil {
				t.Fatal(err)
			}
			groupLine := fmt.Sprintf("%s:x:%s:\n", me.Username, gid)
			if tc.group != "" && tc.group != "-" {
				groupLine = fmt.Sprintf(tc.group, me.Username, gid)
			}
			if tc.group != "-" {
				if err := os.WriteFile(groupFile, []byte(groupLine), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			oldPasswd, oldGroup := privateGroupPasswdFile, privateGroupGroupFile
			privateGroupPasswdFile, privateGroupGroupFile = passwd, groupFile
			t.Cleanup(func() { privateGroupPasswdFile, privateGroupGroupFile = oldPasswd, oldGroup })

			err = validatePluginArtifactDestination(filepath.Join(pluginDir, "defenseclaw.js"))
			if tc.want == "" && err != nil {
				t.Fatalf("private-group folder refused: %v", err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("err=%v, want %q", err, tc.want)
			}
			if tc.name == "private group" {
				plugin := filepath.Join(pluginDir, "defenseclaw.js")
				if err := os.WriteFile(plugin, []byte("// managed plugin\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(plugin, 0o664); err != nil {
					t.Fatal(err)
				}
				if err := validatePluginArtifactDestination(plugin); err != nil {
					t.Fatalf("private-group file refused: %v", err)
				}
				// A named user with effective write access changes the file's
				// group mode bits to the ACL mask. It must not inherit the
				// parent directory's private-group exception.
				acl := make([]byte, 4+5*8)
				binary.LittleEndian.PutUint32(acl[:4], 2)
				for i, entry := range []struct {
					tag, perm uint16
					id        uint32
				}{
					{1, 6, ^uint32(0)},
					{2, 6, 65534},
					{4, 0, ^uint32(0)},
					{16, 6, ^uint32(0)},
					{32, 0, ^uint32(0)},
				} {
					offset := 4 + i*8
					binary.LittleEndian.PutUint16(acl[offset:offset+2], entry.tag)
					binary.LittleEndian.PutUint16(acl[offset+2:offset+4], entry.perm)
					binary.LittleEndian.PutUint32(acl[offset+4:offset+8], entry.id)
				}
				if err := unix.Setxattr(plugin, "system.posix_acl_access", acl, 0); err != nil {
					t.Fatal(err)
				}
				if err := validatePluginArtifactDestination(plugin); err == nil {
					t.Fatal("foreign-writable plugin file accepted")
				}
			}
			// Agent executable folders (Codex policy, Hermes admission) ask the same rule.
			if err := hookAPIValidateAgentDirectory(pluginDir); (err == nil) != (tc.want == "") {
				t.Fatalf("agent directory check err=%v, want accepted=%v", err, tc.want == "")
			}
			// Hook token and data folders keep the strict rule.
			if err := hookAPIValidateDirectory(pluginDir); err == nil || !strings.Contains(err.Error(), "group/other writable") {
				t.Fatalf("hook API directory check accepted a group-writable ancestor: %v", err)
			}
		})
	}
}

// The same on this host's real account files, when the test account has a
// user private group (Ubuntu and Debian runners do); skipped elsewhere.
func TestPluginDestinationAcceptsARealPrivateGroupFolder(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	if group, err := user.LookupGroupId(me.Gid); err != nil || group.Name != me.Username {
		t.Skipf("the test account has no private group (%v)", err)
	}
	root := t.TempDir()
	pluginDir := filepath.Join(root, ".config", "opencode", "plugins")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dropInheritedACLs(t, root)
	for _, dir := range []string{filepath.Join(root, ".config"), filepath.Join(root, ".config", "opencode")} {
		if err := os.Chmod(dir, 0o775); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(info.Sys().(*syscall.Stat_t).Gid) != me.Gid {
			t.Skip("the temp folder does not carry the primary group")
		}
	}
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		t.Skip(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Split(line, ":"); len(f) >= 4 && f[2] == me.Gid && strings.TrimSpace(f[3]) != "" && f[3] != me.Username {
			t.Skip("the private group lists other members")
		}
	}
	if err := validatePluginArtifactDestination(filepath.Join(pluginDir, "defenseclaw.js")); err != nil {
		t.Fatalf("a 0775 folder of the account's own private group was refused: %v", err)
	}
}

// dropInheritedACLs removes the access and default ACLs a temp folder may
// inherit (some hosts set a default ACL on their temp root): with one the
// group bits are the ACL mask and the rule rightly refuses.
func dropInheritedACLs(t *testing.T, root string) {
	t.Helper()
	for _, dir := range []string{root, filepath.Join(root, ".config"), filepath.Join(root, ".config", "opencode"), filepath.Join(root, ".config", "opencode", "plugins")} {
		for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
			if err := unix.Removexattr(dir, name); err != nil && err != unix.ENODATA && err != unix.ENOTSUP {
				t.Fatalf("remove %s on %s: %v", name, dir, err)
			}
		}
	}
}
