// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Variants of the GAP-0293 corpus (round 2 review, s7-hlrev2): every row
// composed with a file layout, a bash option or a respelled name. Truth is
// never a hand label: the real-bash oracle test runs each composed row on
// the synthetic fixture and asks whether the decoy keys inode changed.
// The generator is data only; it types no command of its own beyond the
// transforms of the corpus rows.

package hlinkmatrix

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Variant is one composed case: base row x layout x transform.
type Variant struct {
	ID, Layout, Transform, Command string
	Base                           Row
	Env                            map[string]string
}

func rev2ClassMatch(n Names) string {
	return strings.NewReplacer("[", "", "]", "").Replace(n.HardBracket)
}
func rev2Deep(n Names) string    { return n.KeyHard + "2" }
func rev2DeepDir(n Names) string { return filepath.Join(n.SubDir, "lvl2") }

// Rev2Setup is Setup; layout L1 adds an ordinary file that the hard-link
// bracket name, read as a pattern, matches, and a hard link two levels down.
func Rev2Setup(t testing.TB, project, keys string, n Names, layout string) {
	t.Helper()
	Setup(t, project, keys, n)
	if layout == "L3" {
		stem := rev2Stem(n)
		if err := os.WriteFile(filepath.Join(project, stem+"x"), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(keys, filepath.Join(project, stem+"q")); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(project, rev2DeepDir(n))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(keys, filepath.Join(dir, stem+"d")); err != nil {
			t.Fatal(err)
		}
		return
	}
	if layout == "L2" {
		for i := 0; i < 300; i++ {
			if err := os.WriteFile(filepath.Join(project, fmt.Sprintf("%s-%03d", n.KeyHard, i)), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	if layout != "L1" {
		return
	}
	if err := os.WriteFile(filepath.Join(project, rev2ClassMatch(n)), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(project, rev2DeepDir(n))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(keys, filepath.Join(dir, rev2Deep(n))); err != nil {
		t.Fatal(err)
	}
}

func rev2Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

type rev2Opt struct {
	id  string
	pre string
	env map[string]string
}

func rev2Options(only ...string) []rev2Opt {
	out := []rev2Opt{{id: "none"}}
	for _, o := range []string{"nocaseglob", "globstar", "extglob", "dotglob", "nullglob", "failglob"} {
		if len(only) > 0 && !containsStr(only, o) {
			continue
		}
		out = append(out, rev2Opt{id: "shopt-" + o, pre: "shopt -s " + o + "; "},
			rev2Opt{id: "env-" + o, env: map[string]string{"BASHOPTS": o}})
	}
	if len(only) == 0 {
		out = append(out, rev2Opt{id: "set-f", pre: "set -f; "},
			rev2Opt{id: "globignore-all", pre: "GLOBIGNORE=" + rev2Quote("*") + "; "},
			rev2Opt{id: "env-globignore-all", env: map[string]string{"GLOBIGNORE": "*"}},
			rev2Opt{id: "env-shellopts-noglob", env: map[string]string{"SHELLOPTS": "braceexpand:hashall:interactive-comments:noglob"}})
	}
	return out
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Rev2Variants composes every row (Rows and UncertainRows) with the layouts,
// option transforms, two name transforms and two wrappers.
func Rev2Variants(n Names) []Variant {
	var out []Variant
	base := append(Rows(n), UncertainRows()...)
	upperQ := strings.ToUpper(n.KeyHard[:len(n.KeyHard)-1]) + "?"
	deep := "**/" + rev2Deep(n)
	type nameT struct {
		id   string
		f    func(string) (string, bool)
		opts []rev2Opt
	}
	names := []nameT{
		{"plain", func(c string) (string, bool) { return c, true }, rev2Options()},
		{"caseq", func(c string) (string, bool) {
			return strings.ReplaceAll(c, n.KeyHard, upperQ), strings.Contains(c, n.KeyHard)
		}, rev2Options("nocaseglob")},
		{"star2", func(c string) (string, bool) {
			return strings.ReplaceAll(c, n.KeyHard, deep), strings.Contains(c, n.KeyHard)
		}, rev2Options("globstar")},
	}
	stem := n.KeyHard[:len(n.KeyHard)-1]
	for _, cls := range []struct{ id, text string }{
		{"cls-bang", "[!z]"}, {"cls-caret", "[^z]"}, {"cls-posix", "[[:alpha:]]"},
		{"cls-rbracket-first", "[]" + n.KeyHard[len(n.KeyHard)-1:] + "]"}, {"cls-dash-last", "[" + n.KeyHard[len(n.KeyHard)-1:] + "-]"},
	} {
		cls := cls
		names = append(names, nameT{cls.id, func(c string) (string, bool) {
			return strings.ReplaceAll(c, n.KeyHard, stem+cls.text), strings.Contains(c, n.KeyHard)
		}, []rev2Opt{{id: "none"}}})
	}
	for _, layout := range []string{"L0", "L1"} {
		for _, row := range base {
			for _, nt := range names {
				cmd, ok := nt.f(row.Command)
				if !ok {
					continue
				}
				for _, o := range nt.opts {
					tid := nt.id + "+" + o.id
					out = append(out, Variant{ID: row.ID + "/" + layout + "/" + tid, Layout: layout, Transform: tid,
						Command: o.pre + cmd, Base: row, Env: o.env})
				}
			}
			for _, w := range []string{"sh", "bash"} {
				tid := "wrap-" + w
				out = append(out, Variant{ID: row.ID + "/" + layout + "/" + tid, Layout: layout, Transform: tid,
					Command: w + " -c " + rev2Quote(row.Command), Base: row})
			}
		}
	}
	return out
}

// Rev2ExtraVariants: layout L2 (300 ordinary names beside the plain hard
// link) with the hard-link name widened to a prefix pattern, past the
// resolver's candidate bound; L0 is the control.
func Rev2ExtraVariants(n Names) []Variant {
	var out []Variant
	for _, row := range append(Rows(n), UncertainRows()...) {
		if !strings.Contains(row.Command, n.KeyHard) {
			continue
		}
		for _, layout := range []string{"L0", "L2"} {
			out = append(out, Variant{ID: row.ID + "/" + layout + "/star", Layout: layout, Transform: "star",
				Command: strings.ReplaceAll(row.Command, n.KeyHard, n.KeyHard+"*"), Base: row})
		}
	}
	return out
}

func rev2Stem(n Names) string { return n.NoMatchHard[:strings.Index(n.NoMatchHard, "[")] }

// Rev2ClassVariants: layout L3 (an ordinary file the no-match class now
// matches, a plain-named hard link and a deep hard link) with the unquoted
// no-match rows of every verb respelled by bracket, case, globstar and
// extglob forms, each with and without the bash option that gives it effect
// (in the command on its own line, or in BASHOPTS / GLOBIGNORE).
func Rev2ClassVariants(n Names) []Variant {
	stem := rev2Stem(n)
	type form struct {
		id, word string
		opts     []rev2Opt
	}
	none := rev2Opt{id: "none"}
	opt := func(o string) []rev2Opt {
		return []rev2Opt{none, {id: "shopt-" + o, pre: "shopt -s " + o + "\n"}, {id: "env-" + o, env: map[string]string{"BASHOPTS": o}}}
	}
	forms := []form{
		{"cls-bang", stem + "[!z]", []rev2Opt{none}},
		{"cls-range-bang", stem + "[!a-p]", []rev2Opt{none}},
		{"cls-posix", stem + "[[:alpha:]]", []rev2Opt{none}},
		{"cls-caret", stem + "[^z]", []rev2Opt{none}},
		{"q", stem + "?", []rev2Opt{none}},
		{"same", n.NoMatchHard, []rev2Opt{none,
			{id: "globignore-all", pre: "GLOBIGNORE=" + rev2Quote("*") + "\n"},
			{id: "globignore-match", pre: "GLOBIGNORE=" + stem + "x\n"},
			{id: "env-globignore-all", env: map[string]string{"GLOBIGNORE": "*"}},
			{id: "env-globignore-match", env: map[string]string{"GLOBIGNORE": stem + "x"}}}},
		{"upper-q", strings.ToUpper(stem) + "?", opt("nocaseglob")},
		{"star2", "**/" + stem + "d", opt("globstar")},
		{"ext", stem + "@(q)", opt("extglob")},
	}
	var out []Variant
	for _, row := range Rows(n) {
		if !strings.HasPrefix(row.ID, "HL-nomatch-hard-unquoted-") || !strings.Contains(row.Command, n.NoMatchHard) {
			continue
		}
		for _, f := range forms {
			cmd := strings.ReplaceAll(row.Command, n.NoMatchHard, f.word)
			for _, o := range f.opts {
				tid := f.id + "+" + o.id
				out = append(out, Variant{ID: row.ID + "/L3/" + tid, Layout: "L3", Transform: tid,
					Command: o.pre + cmd, Base: row, Env: o.env})
			}
		}
	}
	return out
}

// Writer is a metadata or content writer (case id HLR3-W-<id>-<row>) whose
// prefix replaces the verb of a corpus row, for the managed-parity tests
// (round 3 review, GAP-0415).
type Writer struct{ ID, Prefix string }

// Writers are the writers the reviewer swapped into the chmod rows.
func Writers() []Writer {
	return []Writer{
		{"setfacl", "setfacl -m u:0:r "}, {"chattr", "chattr +A "}, {"setfattr", "setfattr -n user.k -v 1 "},
		{"cp-attr", "cp --attributes-only a.txt "}, {"touch-r", "touch -r a.txt "},
		{"chmod-ref", "chmod --reference=a.txt "}, {"chown-ref", "chown --reference=a.txt "}, {"chgrp", "chgrp 0 "},
		{"sort-o", "sort a.txt -o "}, {"shred", "shred -n 1 "}, {"rsync", "rsync a.txt "}, {"ln-f", "ln -f a.txt "},
		{"chmod", "chmod 600 "}, {"truncate", "truncate -s 0 "},
	}
}
