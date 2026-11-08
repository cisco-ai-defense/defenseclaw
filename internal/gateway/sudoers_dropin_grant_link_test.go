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

// sudoersLinkSpelledRow is a Claude Code Write of text through a project
// symlink named grant-link that points at target, named as spell writes its
// absolute path: a ./ or doubled-slash spelling, or a relative one from the
// call directory.
func sudoersLinkSpelledRow(t *testing.T, target, text string, spell func(link string) string) sudoersHookRow {
	return sudoersHookRow{"claudecode", "Write through a link to " + target, func(project string) map[string]any {
		link := filepath.Join(project, "grant-link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		return sudoersClaudeCall("Write", sudoersFixed(map[string]any{"file_path": spell(link), "content": text}))(project)
	}}
}

// sudoersLinkSpellings are the ordinary ways to write the same project link;
// the hook client keys its answer by the cleaned path (dot-dot kept raw).
var sudoersLinkSpellings = map[string]func(link string) string{
	"direct":           func(link string) string { return link },
	"dot-slash":        func(link string) string { return "./" + filepath.Base(link) },
	"absolute dot":     func(link string) string { return filepath.Dir(link) + "/./" + filepath.Base(link) },
	"doubled slash":    func(link string) string { return filepath.Dir(link) + "//" + filepath.Base(link) },
	"relative dot-dot": func(link string) string { return "../" + filepath.Base(filepath.Dir(link)) + "/" + filepath.Base(link) },
	"absolute dot-dot": func(link string) string {
		return filepath.Dir(link) + "/../" + filepath.Base(filepath.Dir(link)) + "/" + filepath.Base(link)
	},
	"repeated dot-slash": func(link string) string { return "././" + filepath.Base(link) },
}

// TestFileToolWriteOfAGrantThroughALinkToSudoersIsBlockedInEveryProfile: a
// symlink of any name to the main sudoers file is that file, which the hook
// client resolves as the user, so the grant is refused like the direct write.
func TestFileToolWriteOfAGrantThroughALinkToSudoersIsBlockedInEveryProfile(t *testing.T) {
	if _, err := os.Stat("/etc/sudoers"); err != nil {
		t.Skip("main sudoers file absent on this host")
	}
	hostLinksEtc(t, false)
	for spelling, spell := range sudoersLinkSpellings {
		for _, profile := range []string{"default", "permissive", "strict"} {
			for _, managed := range []bool{false, true} {
				t.Run(spelling+"/"+profile+"/"+map[bool]string{false: "per-user", true: "managed"}[managed], func(t *testing.T) {
					row := sudoersLinkSpelledRow(t, "/etc/sudoers", "r109yem5 ALL=(ALL) NOPASSWD: ALL\n", spell)
					blocked, _, body := postSudoersHook(t, row, profile, managed)
					if !blocked || !strings.Contains(body, sudoersGrantRuleID) {
						t.Fatalf("blocked = %t, want a block naming %s: %.600s", blocked, sudoersGrantRuleID, body)
					}
				})
			}
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
	for spelling, spell := range sudoersLinkSpellings {
		for _, profile := range []string{"default", "permissive"} {
			t.Run(spelling+"/"+profile+"/ordinary file", func(t *testing.T) {
				row := sudoersLinkSpelledRow(t, other, "r109yem5 ALL=(ALL) NOPASSWD: ALL\n", spell)
				blocked, _, body := postSudoersHook(t, row, profile, false)
				if blocked || strings.Contains(body, sudoersGrantRuleID) {
					t.Fatalf("blocked = %t, names the grant rule = %t, want neither: %.600s", blocked, strings.Contains(body, sudoersGrantRuleID), body)
				}
			})
		}
	}
}
