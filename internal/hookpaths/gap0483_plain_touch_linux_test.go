// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestGAP0483PlainTouchMissingLeavesSkipPathWalk(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	key := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 2000)
	for i := range names {
		names[i] = fmt.Sprintf("lo%d.txt", i)
	}
	command := "touch " + strings.Join(names, " ")
	memo := NewTargetMemo()
	if got := memo.ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, actionfacts.DialectPOSIX, nil); got != "" {
		t.Fatalf("ordinary leaves = %q, want allow", got)
	}
	if walked, _ := memo.WorkParts(); walked > 64 {
		t.Fatalf("ordinary leaves walked %d path parts, want at most 64", walked)
	}
	for _, prefix := range []string{"touch -- ", "touch -c ", "touch -amc ", "touch --no-create --time=atime -- "} {
		for _, operands := range [][]string{names, func() []string {
			withDot := make([]string, len(names))
			for i, name := range names {
				withDot[i] = "./" + name
			}
			return withDot
		}()} {
			command := prefix + strings.Join(operands, " ")
			memo := NewTargetMemo()
			if got := memo.ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, actionfacts.DialectPOSIX, nil); got != "" {
				t.Fatalf("ordinary variant %q = %q, want allow", prefix, got)
			}
			if walked, _ := memo.WorkParts(); walked > 64 {
				t.Fatalf("ordinary variant %q walked %d path parts, want at most 64", prefix, walked)
			}
			if !OrdinaryLongTouchMissingLeaves(command, cwd, home) {
				t.Fatalf("ordinary variant %q has no late proof", prefix)
			}
		}
	}
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = fmt.Sprintf("%q", name)
	}
	for _, command := range []string{
		"touch " + strings.Join(quoted, " "),
		"touch -t 202611060101 " + strings.Join(names, " "),
		"touch -c -- " + strings.Join(quoted, " "),
	} {
		memo := NewTargetMemo()
		if decision := memo.ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, actionfacts.DialectPOSIX, nil); decision != "" {
			t.Fatalf("ordinary literal touch = %q", decision)
		}
		if walked, _ := memo.WorkParts(); walked > 64 {
			t.Fatalf("ordinary literal touch walked %d path parts", walked)
		}
		if !OrdinaryLongTouchMissingLeaves(command, cwd, home) {
			t.Fatal("ordinary literal touch has no late proof")
		}
	}
	for _, index := range []int{0, len(names) / 2, len(names) - 1} {
		withKey := append([]string(nil), quoted...)
		withKey[index] = `"../.ssh/authorized_keys"`
		command := "touch -t 202611060101 -- " + strings.Join(withKey, " ")
		if OrdinaryLongTouchMissingLeaves(command, cwd, home) || ActionCommandDecision(command, cwd, home) != "protected-target" {
			t.Fatalf("protected literal touch at %d did not close", index)
		}
	}
	if OrdinaryLongTouchMissingLeaves("touch "+strings.Join(names[:128], " ")+"\necho hello", cwd, home) {
		t.Fatal("a second shell statement received a touch-only proof")
	}
	for _, index := range []int{0, len(names) / 2, len(names) - 1} {
		withKey := append([]string(nil), names...)
		withKey[index] = "../.ssh/authorized_keys"
		if got := ActionCommandDecision("touch "+strings.Join(withKey, " "), cwd, home); got != "protected-target" {
			t.Fatalf("key path at %d = %q, want protected-target", index, got)
		}
	}
	link := filepath.Join(cwd, names[len(names)/2])
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
		t.Fatalf("existing link = %q, want protected-target", got)
	}
}

func TestGAP0483LiteralLeafSpellingsStayBounded(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	key := filepath.Join(home, ".ssh", "authorized_keys")
	for _, dir := range []string{cwd, filepath.Dir(key)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(key, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	bare, spaced, absolute, absoluteDot := make([]string, 2000), make([]string, 2000), make([]string, 2000), make([]string, 2000)
	for i := range bare {
		bare[i] = fmt.Sprintf("leaf%d.txt", i)
		spaced[i] = fmt.Sprintf("%q", fmt.Sprintf("leaf %d.txt", i))
		absolute[i] = filepath.Join(cwd, bare[i])
		absoluteDot[i] = cwd + string(filepath.Separator) + "." + string(filepath.Separator) + bare[i]
	}
	for _, tc := range []struct{ name, command string }{
		{"quoted spaced leaves", "touch " + strings.Join(spaced, " ")},
		{"attached timestamp", "touch -t202611060101 " + strings.Join(bare, " ")},
		{"absolute same-directory leaves", "touch " + strings.Join(absolute, " ")},
		{"absolute dot leaves", "touch " + strings.Join(absoluteDot, " ")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memo := NewTargetMemo()
			if decision := memo.ActionCommandDecisionWithDialectAndGlobFacts(tc.command, cwd, home, actionfacts.DialectPOSIX, nil); decision != "" {
				t.Fatalf("ordinary touch decision = %q", decision)
			}
			if walked, _ := memo.WorkParts(); walked > 64 {
				t.Fatalf("ordinary touch walked %d path parts", walked)
			}
			if !OrdinaryLongTouchMissingLeaves(tc.command, cwd, home) {
				t.Fatal("ordinary touch has no late proof")
			}
		})
	}
	alias := filepath.Join(cwd, "alias with space.txt")
	if err := os.Link(key, alias); err != nil {
		t.Fatal(err)
	}
	withAlias := append([]string(nil), spaced...)
	withAlias[len(withAlias)/2] = fmt.Sprintf("%q", filepath.Base(alias))
	command := "touch -t202611060101 " + strings.Join(withAlias, " ")
	if OrdinaryLongTouchMissingLeaves(command, cwd, home) || ActionCommandDecision(command, cwd, home) != "protected-target" {
		t.Fatal("linked protected leaf received an ordinary proof")
	}
}

func TestGAP0483DateAndKnownDirectoryLeavesStayBounded(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	key := filepath.Join(home, ".ssh", "authorized_keys")
	for _, dir := range []string{cwd, filepath.Dir(key)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(key, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 2000)
	known := make([]string, 2000)
	for i := range names {
		names[i] = fmt.Sprintf("leaf%d.txt", i)
		known[i] = `"$PWD"/` + names[i]
	}
	for _, tc := range []struct{ name, command string }{
		{"separate date", "touch -d 2026-11-06 " + strings.Join(names, " ")},
		{"attached date", "touch --date=2026-11-06 " + strings.Join(names, " ")},
		{"known directory", "touch " + strings.Join(known, " ")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memo := NewTargetMemo()
			if got := memo.ActionCommandDecisionWithDialectAndGlobFacts(tc.command, cwd, home, actionfacts.DialectPOSIX, nil); got != "" {
				t.Fatalf("ordinary leaves = %q", got)
			}
			if walked, _ := memo.WorkParts(); walked > 64 {
				t.Fatalf("ordinary leaves walked %d path parts", walked)
			}
			if !OrdinaryLongTouchMissingLeaves(tc.command, cwd, home) {
				t.Fatal("ordinary leaves have no late proof")
			}
		})
	}
	alias := filepath.Join(cwd, "linked-leaf")
	if err := os.Link(key, alias); err != nil {
		t.Fatal(err)
	}
	withAlias := append([]string(nil), names...)
	withAlias[len(withAlias)/2] = filepath.Base(alias)
	command := "touch -d 2026-11-06 " + strings.Join(withAlias, " ")
	if OrdinaryLongTouchMissingLeaves(command, cwd, home) || ActionCommandDecision(command, cwd, home) != "protected-target" {
		t.Fatal("linked protected leaf received an ordinary proof")
	}
	projectAlias := filepath.Join(home, "project-link")
	if err := os.Symlink(cwd, projectAlias); err != nil {
		t.Fatal(err)
	}
	command = "touch -d 2026-11-06 " + strings.Join(known, " ")
	if !OrdinaryLongTouchMissingLeaves(command, projectAlias, home) ||
		ActionCommandDecision(command, projectAlias, home) != "" {
		t.Fatal("ordinary leaves in a linked project directory lost the bounded proof")
	}
}
