// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/testenv/hlinkmatrix"
	"mvdan.cc/sh/v3/syntax"
)

// shellWordFixture is the GAP-0431 fixture tree: a keys decoy with link
// names around it, built from the shared corpus names.
type shellWordFixture struct {
	home, project, keys string
	names               hlinkmatrix.Names
	values              actionValues
}

func newShellWordFixture(t *testing.T) shellWordFixture {
	t.Helper()
	clearShellStartupEnv(t)
	root := t.TempDir()
	f := shellWordFixture{names: hlinkmatrix.DefaultNames()}
	f.home = filepath.Join(root, "home")
	f.project = filepath.Join(f.home, "project")
	f.keys = filepath.Join(f.home, ".ssh", "authorized_keys")
	for _, dir := range []string{filepath.Dir(f.keys), f.project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(f.keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hlinkmatrix.Setup(t, f.project, f.keys, f.names)
	t.Setenv("HOME", f.home)
	f.values = actionValues{"HOME": f.home, "PWD": f.project}
	return f
}

// word parses one command and returns the word after the program.
func shellWordOf(t *testing.T, command string, index int) *syntax.Word {
	t.Helper()
	file, ok := parseShell(command)
	if !ok || len(file.Stmts) == 0 {
		t.Fatalf("no parse for %q", command)
	}
	call, ok := file.Stmts[len(file.Stmts)-1].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) <= index {
		t.Fatalf("no word %d in %q", index, command)
	}
	return call.Args[index]
}

// Every quoting form of a name resolves to that one entry: quote removal is
// done once, ANSI-C escapes (hex, octal, unicode) included, and the entry is
// the hard link whatever the spelling.
func TestResolveShellWordEveryQuotingNamesTheEntry(t *testing.T) {
	f := newShellWordFixture(t)
	for _, name := range []string{f.names.HardBracket, f.names.PlainBracket, f.names.NoMatchHard, f.names.NoMatchSym} {
		want := filepath.Join(f.project, name)
		for _, q := range hlinkmatrix.Quotings() {
			t.Run(q.ID+"/"+name, func(t *testing.T) {
				got := resolveShellWord(shellWordOf(t, "touch "+q.Spell(name), 1), f.values, f.project, shellGlobOptions{}, nil)
				if got.uncertain != "" {
					t.Fatalf("uncertain %q", got.uncertain)
				}
				if !slices.Contains(got.candidates, want) {
					t.Errorf("candidates %q miss %q", got.candidates, want)
				}
			})
		}
	}
}

// An unmatched pattern is the literal word (nullglob off), and with nullglob
// set it is nothing; dotglob and nocaseglob widen the candidates.
func TestResolveShellWordGlobRules(t *testing.T) {
	f := newShellWordFixture(t)
	for _, name := range []string{".hid1", "zz1"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		id, word string
		opts     shellGlobOptions
		want     []string
		absent   []string
	}{
		{"nomatch-is-literal", f.names.NoMatchHard, shellGlobOptions{}, []string{f.names.NoMatchHard}, nil},
		{"nomatch-nullglob", f.names.NoMatchHard, shellGlobOptions{nullGlob: true}, nil, []string{f.names.NoMatchHard}},
		{"match-replaces-literal", "zz[1]*", shellGlobOptions{}, []string{"zz1"}, []string{"zz[1]*"}},
		{"star-skips-dot", ".hid*", shellGlobOptions{}, []string{".hid1"}, nil},
		{"dotglob-star", "*1", shellGlobOptions{dotGlob: true}, []string{".hid1"}, nil},
		{"nodot-star", "*1", shellGlobOptions{}, nil, []string{".hid1"}},
		{"nocaseglob", "ALIAS?1?", shellGlobOptions{noCaseGlob: true}, []string{f.names.HardBracket}, nil},
		{"case-sensitive", "ALIAS?1?", shellGlobOptions{}, nil, []string{f.names.HardBracket}},
		{"noglob-literal", "alias[[]1]", shellGlobOptions{noGlob: true}, []string{"alias[[]1]"}, nil},
	} {
		t.Run(tc.id, func(t *testing.T) {
			got := resolveShellWord(shellWordOf(t, "touch "+tc.word, 1), f.values, f.project, tc.opts, nil)
			if got.uncertain != "" {
				t.Fatalf("uncertain %q", got.uncertain)
			}
			for _, name := range tc.want {
				if !slices.Contains(got.candidates, filepath.Join(f.project, name)) {
					t.Errorf("candidates %q miss %q", got.candidates, name)
				}
			}
			for _, name := range tc.absent {
				if slices.Contains(got.candidates, filepath.Join(f.project, name)) {
					t.Errorf("candidates %q hold %q", got.candidates, name)
				}
			}
		})
	}
}

// What the resolver cannot settle is uncertain, never an empty answer.
func TestResolveShellWordUncertainClasses(t *testing.T) {
	f := newShellWordFixture(t)
	for _, row := range hlinkmatrix.UncertainRows() {
		if row.ID[len(row.ID)-len("touch"):] != "touch" || row.Effect != hlinkmatrix.Content {
			continue
		}
		t.Run(row.ID, func(t *testing.T) {
			got := resolveShellWord(shellWordOf(t, row.Command, 1), f.values, f.project, shellGlobOptions{}, nil)
			if got.uncertain == "" {
				t.Errorf("settled to %q", got.candidates)
			}
		})
	}
	t.Run("unreadable-directory-as-the-user", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a mode 0 directory")
		}
		closed := filepath.Join(f.project, "closed")
		if err := os.Mkdir(closed, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })
		// The user's own shell cannot list it either: it expands nothing and
		// passes the word as written. A gateway that cannot see the home
		// (hidden view) is uncertain instead; TestResolveShellWordHiddenHome.
		got := resolveShellWord(shellWordOf(t, "touch closed/*", 1), f.values, f.project, shellGlobOptions{}, nil)
		if got.uncertain != "" || len(got.candidates) != 1 {
			t.Errorf("uncertain %q, candidates %q", got.uncertain, got.candidates)
		}
	})
	t.Run("past-the-bound", func(t *testing.T) {
		many := filepath.Join(f.project, "many")
		if err := os.Mkdir(many, 0o700); err != nil {
			t.Fatal(err)
		}
		for i := 0; i <= maxResolvedCandidates; i++ {
			if err := os.WriteFile(filepath.Join(many, "f"+string(rune('a'+i%26))+string(rune('a'+i/26%26))+string(rune('a'+i/676))), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		got := resolveShellWord(shellWordOf(t, "touch many/*", 1), f.values, f.project, shellGlobOptions{}, nil)
		if got.uncertain != wordUncertainTruncated || !got.caps.Has(bounded.Paths) {
			t.Errorf("uncertain %q, caps %q, candidates %d", got.uncertain, got.caps.Reason(), len(got.candidates))
		}
	})
}

// The options come from the call's own environment (BASHOPTS, SHELLOPTS).
func TestShellGlobOptionsFromEnv(t *testing.T) {
	env := map[string]string{"BASHOPTS": "cmdhist:dotglob:nocaseglob", "SHELLOPTS": "braceexpand:noglob"}
	got := shellGlobOptionsFromEnv(func(k string) string { return env[k] })
	if !got.dotGlob || !got.noCaseGlob || !got.noGlob || got.nullGlob || got.extGlob {
		t.Errorf("options %+v", got)
	}
	if shellGlobOptionsFromEnv(func(string) string { return "" }) != (shellGlobOptions{}) {
		t.Error("an empty environment sets an option")
	}
}
