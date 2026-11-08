// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows create POSIX symlinks and name /etc/sudoers.

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sudoersLinkRow is a Claude Code Write of text through a project symlink named
// grant-link that points at target.
func sudoersLinkRow(t *testing.T, target, text string) sudoersHookRow {
	return sudoersHookRow{"claudecode", "Write through a link to " + target, func(project string) map[string]any {
		link := filepath.Join(project, "grant-link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		return sudoersClaudeCall("Write", sudoersFixed(map[string]any{"file_path": link, "content": text}))(project)
	}}
}

// TestFileToolWriteOfAGrantThroughALinkToSudoersIsBlockedInEveryProfile: a
// symlink of any name to the main sudoers file is that file, which the hook
// client resolves as the user, so the grant is refused like the direct write.
func TestFileToolWriteOfAGrantThroughALinkToSudoersIsBlockedInEveryProfile(t *testing.T) {
	if _, err := os.Stat("/etc/sudoers"); err != nil {
		t.Skip("main sudoers file absent on this host")
	}
	hostLinksEtc(t, false)
	for _, profile := range []string{"default", "permissive", "strict"} {
		for _, managed := range []bool{false, true} {
			t.Run(profile+"/"+map[bool]string{false: "per-user", true: "managed"}[managed], func(t *testing.T) {
				blocked, _, body := postSudoersHook(t, sudoersLinkRow(t, "/etc/sudoers", "r109yem5 ALL=(ALL) NOPASSWD: ALL\n"), profile, managed)
				if !blocked || !strings.Contains(body, sudoersGrantRuleID) {
					t.Fatalf("blocked = %t, want a block naming %s: %.600s", blocked, sudoersGrantRuleID, body)
				}
			})
		}
	}
}

// TestFileToolWriteThroughALinkToAnOrdinaryFileIsNotAGrantTarget is the benign
// twin: the same grant text through a link to an ordinary file never names the
// grant rule, and the balanced profiles allow it.
func TestFileToolWriteThroughALinkToAnOrdinaryFileIsNotAGrantTarget(t *testing.T) {
	hostLinksEtc(t, false)
	other := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(other, []byte("notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"default", "permissive"} {
		t.Run(profile+"/ordinary file", func(t *testing.T) {
			blocked, _, body := postSudoersHook(t, sudoersLinkRow(t, other, "r109yem5 ALL=(ALL) NOPASSWD: ALL\n"), profile, false)
			if blocked || strings.Contains(body, sudoersGrantRuleID) {
				t.Fatalf("blocked = %t, names the grant rule = %t, want neither: %.600s", blocked, strings.Contains(body, sudoersGrantRuleID), body)
			}
		})
	}
}
