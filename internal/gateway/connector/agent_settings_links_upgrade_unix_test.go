// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The 1.0.2 and 1.0.3 releases wrote the same Claude Code registration
// snapshot. Exercise the upgrade with a link actually owned by root, while
// the target and Setup process remain owned by the user. An unprivileged CI
// host without passwordless sudo still runs the owner-check unit test.
func TestClaudeCodeUpgradeThroughAdministratorOwnedSettingsLink(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("this upgrade must run as the non-root owner of the settings target")
	}
	for _, predecessor := range []string{"1.0.2", "1.0.3"} {
		for _, linkKind := range []string{"file", "directory"} {
			t.Run(predecessor+"/"+linkKind, func(t *testing.T) {
				root := t.TempDir()
				home := filepath.Join(root, "home")
				outside := filepath.Join(root, "dotfiles")
				for _, dir := range []string{home, outside} {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv("HOME", home)
				t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, ".claude"))
				dataDir := filepath.Join(home, ".defenseclaw")
				body, err := os.ReadFile(filepath.Join("testdata", "predecessor_1_0_2_1_0_3", "claudecode.json"))
				if err != nil {
					t.Fatal(err)
				}
				body = []byte(strings.ReplaceAll(strings.ReplaceAll(string(body), "{home}", home), "{data_dir}", dataDir))
				target := filepath.Join(outside, "settings.json")
				if err := os.WriteFile(target, body, 0o600); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(home, ".claude")
				linkTarget := outside
				if linkKind == "file" {
					if err := os.MkdirAll(link, 0o700); err != nil {
						t.Fatal(err)
					}
					link = filepath.Join(link, "settings.json")
					linkTarget = target
				}
				if err := os.Symlink(linkTarget, link); err != nil {
					t.Fatal(err)
				}
				// Changing the owner of the link inode requires privilege; -h
				// deliberately leaves the target owned by this account.
				if output, err := exec.Command("sudo", "-n", "chown", "-h", "0", link).CombinedOutput(); err != nil {
					t.Skipf("cannot prepare administrator-owned link: %v (%s)", err, strings.TrimSpace(string(output)))
				}
				info, err := os.Lstat(link)
				if err != nil {
					t.Fatal(err)
				}
				if owner, ok := pluginOwnerUID(info); !ok || owner != 0 {
					t.Fatalf("settings link owner = %d (known=%t), want root", owner, ok)
				}
				conn := NewClaudeCodeConnector()
				opts := SetupOpts{
					DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token", HookFailMode: "closed",
				}
				if err := CheckAgentSettings(conn, opts); err != nil {
					t.Fatalf("upgrade precheck refused administrator-owned link: %v", err)
				}
				if err := conn.Setup(context.Background(), opts); err != nil {
					t.Fatalf("upgrade setup through administrator-owned link: %v", err)
				}
				if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
					t.Fatalf("hooks after upgrade: present=%t, err=%v", present, err)
				}
				if got, err := os.Readlink(link); err != nil || got != linkTarget {
					t.Fatalf("settings link after upgrade = %q, %v; want %s", got, err, linkTarget)
				}
				if info, err := os.Stat(target); err != nil {
					t.Fatal(err)
				} else if owner, ok := pluginOwnerUID(info); !ok || owner != uint32(os.Getuid()) {
					t.Fatalf("settings target owner = %d (known=%t), want this account", owner, ok)
				}
			})
		}
	}
}
