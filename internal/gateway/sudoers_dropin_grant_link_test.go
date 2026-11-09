// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows create POSIX symlinks and name /etc/sudoers. They leave
// actionfacts.HostLinksEtcToPrivate at the host value: the hook client here
// resolves the real link, so on macOS it answers /private/etc/sudoers, the
// spelling the macOS gateway folds back to /etc.

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
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

// sudoersLinkFromAliasedProjectRow is sudoersLinkSpelledRow for a call whose
// reported working directory is a symlink to the project: the hook client keys
// its answer by the name it was given, the gateway resolves the project.
func sudoersLinkFromAliasedProjectRow(t *testing.T, target, text, operand string) sudoersHookRow {
	return sudoersHookRow{"claudecode", "Write through a link from an aliased project", func(project string) map[string]any {
		alias := filepath.Join(filepath.Dir(project), "project-alias")
		if err := os.Symlink(project, alias); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(project, "grant-link")); err != nil {
			t.Fatal(err)
		}
		payload := sudoersClaudeCall("Write", sudoersFixed(map[string]any{"file_path": operand, "content": text}))(project)
		payload["cwd"] = alias
		resolved, ok := hookpaths.Decode(hookpaths.Resolve(mustJSON(t, payload)))
		// The client answers the physical file: on macOS /etc/sudoers is
		// /private/etc/sudoers and a temporary directory is under /private.
		want, err := filepath.EvalSymlinks(target)
		if err != nil {
			t.Fatal(err)
		}
		if key := hookpaths.OperandPath(operand, alias); !ok || actionfacts.EtcSpelling(resolved[key]) != actionfacts.EtcSpelling(want) {
			t.Fatalf("the hook client did not place %q on %q: valid=%t got %q", key, target, ok, resolved[key])
		}
		return payload
	}}
}

// TestFileToolWriteOfAGrantThroughALinkFromAnAliasedProjectIsBlockedInEveryProfile:
// a relative link name written from a project the client reports through a
// symlink is still the file the client proved, so the grant is refused with
// the grant rule like the absolute write.
func TestFileToolWriteOfAGrantThroughALinkFromAnAliasedProjectIsBlockedInEveryProfile(t *testing.T) {
	if _, err := os.Stat("/etc/sudoers"); err != nil {
		t.Skip("main sudoers file absent on this host")
	}
	for _, operand := range []string{"grant-link", "./grant-link"} {
		for _, profile := range []string{"default", "permissive", "strict"} {
			for _, managed := range []bool{false, true} {
				t.Run(operand+"/"+profile+"/"+map[bool]string{false: "per-user", true: "managed"}[managed], func(t *testing.T) {
					row := sudoersLinkFromAliasedProjectRow(t, "/etc/sudoers", "r109yem5 ALL=(ALL) NOPASSWD: ALL\n", operand)
					blocked, _, body := postSudoersHook(t, row, profile, managed)
					if !blocked || !strings.Contains(body, sudoersGrantRuleID) {
						t.Fatalf("blocked = %t, want a block naming %s: %.600s", blocked, sudoersGrantRuleID, body)
					}
				})
			}
		}
	}
}

// TestFileToolWriteThroughALinkFromAnAliasedProjectToAnOrdinaryFileIsAllowed is
// the benign twin: the same call to an ordinary file never names the grant
// rule, and the balanced profiles allow it.
func TestFileToolWriteThroughALinkFromAnAliasedProjectToAnOrdinaryFileIsAllowed(t *testing.T) {
	other := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(other, []byte("notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, operand := range []string{"grant-link", "./grant-link"} {
		for _, profile := range []string{"default", "permissive"} {
			t.Run(operand+"/"+profile, func(t *testing.T) {
				row := sudoersLinkFromAliasedProjectRow(t, other, "r109yem5 ALL=(ALL) NOPASSWD: ALL\n", operand)
				blocked, _, body := postSudoersHook(t, row, profile, false)
				if blocked || strings.Contains(body, sudoersGrantRuleID) {
					t.Fatalf("blocked = %t, names the grant rule = %t, want neither: %.600s", blocked, strings.Contains(body, sudoersGrantRuleID), body)
				}
			})
		}
	}
}
