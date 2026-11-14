// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// gap0270ReadShapes are the call shapes of the rel-1-0-10:GAP-0270 false
// blocks (agent-transcripts-sample): listings, sizes and loops over a glob
// in a temp folder, none of which names a file under the home.
func gap0270ReadShapes(dir string) []string {
	return []string{
		"ls " + dir + "/x-*.log 2>/dev/null",
		"ls -la " + dir + "/x-*.log",
		"du -sh " + dir + "/x-* 2>/dev/null",
		"df -h " + dir + "/x-* 2>/dev/null | tail -1",
		"for f in " + dir + "/x-*.log; do echo \"$f\"; done",
		"for f in " + dir + "/x-*/out.json; do wc -l \"$f\"; done 2>/dev/null",
		"cat " + dir + "/x-*.log > out.txt",
		"head -n 5 " + dir + "/x-*/*.txt",
	}
}

// fillDir adds plain files to dir until it holds n entries.
func fillDir(t *testing.T, dir string, n int) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(entries); i < n; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("fill-%05d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

type gap0270Verdict struct {
	decision, unproven, glob string
	keyRead                  bool
}

// gap0270Dialect reads the rows as a POSIX shell runs them; on Windows that
// shell is Git Bash under the native home (posixShellDecision).
func gap0270Dialect() actionfacts.Dialect {
	if runtime.GOOS == "windows" {
		return actionfacts.DialectPOSIX
	}
	return ""
}

func gap0270Read(command, cwd, home string) gap0270Verdict {
	memo := NewTargetMemo()
	return gap0270Verdict{
		decision: memo.ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, gap0270Dialect(), nil),
		unproven: UnprovenProtectedWrite(command, cwd, home),
		glob:     memo.GlobUnproven(),
		keyRead:  posixShellPrivateKeyRead(command, cwd, home),
	}
}

// rel-1-0-10:GAP-0270 (a, c): a pattern whose literal folder is away from
// the home is decided from its text, so a busy folder (more names than the
// walk reads) gives the verdict a small one gives. Before the fix the
// for-loop and redirect shapes were protected-target and the listings an
// unproven dynamic-argument once the folder passed actionGlobMaxNames.
func TestGAP0270GlobOutsideHomeSameOnEveryBox(t *testing.T) {
	home, cwd := globAliasFixture(t)
	busy := t.TempDir()
	rows := gap0270ReadShapes(busy)
	small := make([]gap0270Verdict, len(rows))
	for i, command := range rows {
		small[i] = gap0270Read(command, cwd, home)
	}
	fillDir(t, busy, actionGlobMaxNames+1)
	for i, command := range rows {
		t.Run(strings.ReplaceAll(command, busy, "BUSY"), func(t *testing.T) {
			got := gap0270Read(command, cwd, home)
			if got != small[i] {
				t.Fatalf("busy folder verdict %+v, small folder %+v", got, small[i])
			}
			if got.decision != "" || got.unproven != "" || got.glob != "" || got.keyRead {
				t.Fatalf("verdict %+v, want no protected, unproven or unknown target", got)
			}
		})
	}
	// The GAP-1445 rows under the home keep their verdicts beside the busy
	// folder.
	for _, command := range globAliasProtectedCommands(cwd) {
		if got := posixShellDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("%s: decision = %q, want protected-target", command, got)
		}
	}
	for _, command := range globAliasAllowCommands {
		if got := posixShellDecision(command, cwd, home); got != "" {
			t.Errorf("%s: decision = %q, want allow", command, got)
		}
	}
}

// rel-1-0-10:GAP-0270 (b): under the home the pattern is still expanded,
// through links. A walk past its bound keeps every match it read, so an
// alias it found is still a protected target; a walk that found none is an
// unknown target (TargetMemo.GlobUnproven), not a protected one.
func TestGAP0270GlobInHomeBoundIsUnknown(t *testing.T) {
	home, cwd := globAliasFixture(t)
	fillDir(t, cwd, actionGlobMaxNames+1)
	for _, command := range globAliasProtectedCommands(cwd) {
		t.Run(command, func(t *testing.T) {
			if got := gap0270Read(command, cwd, home); got.decision != "protected-target" {
				t.Fatalf("verdict %+v, want protected-target", got)
			}
		})
	}
	for _, command := range []string{`cp payload b*/`, `cp payload buil*/notes.txt`, `cp payload s*/notes.txt`} {
		t.Run("unknown/"+command, func(t *testing.T) {
			got := gap0270Read(command, cwd, home)
			if got.decision != "" || got.glob != cwd {
				t.Fatalf("verdict %+v, want no decision and the unknown folder %s", got, cwd)
			}
		})
	}
}

func TestGAP0270GlobLiteralDir(t *testing.T) {
	for _, row := range []struct{ pattern, dir string }{
		{"/tmp/x-*.log", "/tmp"},
		{"/var/tmp/run/x-*/out.json", "/var/tmp/run"},
		{"/*/x", "/"},
		{"/home/u/proj/[ab]/c", "/home/u/proj"},
		{"/home/u/proj/a?", "/home/u/proj"},
		// A shell may still rewrite these components (bash brace lists,
		// extglob groups, escapes): the literal folder stops before them.
		{"/{tmp,home}/u/.ssh/x*", "/"},
		{"/@(home)/u/.ssh/a*", "/"},
		{"/tmp/+(x)/y*", "/tmp"},
		{"/tmp/!(x)/y*", "/tmp"},
		// ".." stays as written (rel-1-0-10:GAP-0400); a relative pattern
		// has no literal folder (it is never away).
		{"/tmp/l/../x/y*", "/tmp/l/../x"},
		{"rel/x*", ""},
	} {
		pattern, dir := filepath.FromSlash(row.pattern), filepath.FromSlash(row.dir)
		if got := actionGlobLiteralDir(pattern); got != filepath.VolumeName(pattern)+dir && got != dir {
			t.Errorf("actionGlobLiteralDir(%s) = %s, want %s", pattern, got, dir)
		}
	}
	home := filepath.FromSlash("/home/u")
	for _, row := range []struct {
		path string
		near bool
	}{
		{"/home/u", true}, {"/home/u/proj", true}, {"/home", true}, {"/", true},
		{"/tmp", false}, {"/home/u2", false}, {"/var/tmp/home/u", false},
	} {
		if got := NearProtected(filepath.FromSlash(row.path), home); got != row.near {
			t.Errorf("NearProtected(%s) = %t, want %t", row.path, got, row.near)
		}
	}
}

// globHeld is globHeldDecision's answer for a pattern held as an unknown
// target (TargetMemo.GlobUnproven) with no protected target proved.
const globHeld = "held-unknown"

// globHeldDecision is the action decision of command with facts, or
// globHeld when the decision found no protected target but held an
// unfinished pattern expansion.
func globHeldDecision(command, cwd, home string, facts map[string]string) string {
	memo := NewTargetMemo()
	decision := memo.ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, gap0270Dialect(), facts)
	if decision == "" && memo.GlobUnproven() != "" {
		return globHeld
	}
	return decision
}
