// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
	"unicode"
)

// The reader follows the shell only where the shell does what it assumes: a
// break or continue with no loop to leave does not stop the command, a
// function can take the place of a builtin whose result the reader reads, and
// a command past the reading bound is read by the words it expands.
func TestOpenClawOutageKnownValuesKeepShellFlowHonest(t *testing.T) {
	root, protected, ordinary := outageR10Fixture(t, "home")
	cases := []struct{ name, command, want string }{
		{"break outside loop", `{ break; rm "$OUT"; }`, "protected"},
		{"continue outside loop", `{ continue; rm "$OUT"; }`, "protected"},
		{"break in if outside loop", `if true; then break; rm "$OUT"; fi`, "protected"},
		{"continue in case outside loop", `case yes in yes) continue; rm "$OUT";; esac`, "protected"},
		{"break count past loop depth", `{ for x in a; do break 2; done; rm "$OUT"; }`, "protected"},
		{"continue count past loop depth", `{ for x in a; do continue 3; done; rm "$OUT"; }`, "protected"},
		{"break in subshell loop then remove", `for x in a; do ( break ); rm "$OUT"; done`, "protected"},
		{"loop break then later remove", `for x in a; do break; done; rm "$OUT"`, "protected"},
		{"shadowed true else", `true() { false; }; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"shadowed false then", `false() { true; }; if false; then rm "$OUT"; fi`, "protected"},
		{"shadowed true or", `true() { false; }; true || rm "$OUT"`, "protected"},
		{"shadowed false and", `false() { true; }; false && rm "$OUT"`, "protected"},
		{"shadowed colon", `:() { false; }; if :; then :; else rm "$OUT"; fi`, "protected"},
		{"shadowed exit", `exit() { :; }; { exit; rm "$OUT"; }`, "protected"},
		{"shadowed break", `break() { :; }; for x in a; do break; rm "$OUT"; done`, "protected"},
		{"shadowed continue", `continue() { :; }; for x in a; do continue; rm "$OUT"; done`, "protected"},
		{"shadowed false while", `false() { true; }; while false; do rm "$OUT"; break; done`, "protected"},
		{"shadowed true with loop", `true() { false; }; if true; then :; else for x in "$PROT"; do rm "$x"; done; fi`, "protected"},
		{"shadowed true value tracking", `true() { false; }; if true; then :; else T="$PROT"; fi; rm "$T"`, "protected"},
		{"eval defined true", `eval 'true() { false; }'; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"function call keeps known value", `f() { :; }; f; rm "$OUT"`, "protected"},
		{"function defined in block", `{ f() { rm "$PROT"; }; f; }`, "protected"},
		{"function defined in block ordinary", `{ f() { rm notes.txt; }; f; }`, "open"},
		{"ordinary break outside loop", `{ break; rm notes.txt; }`, "open"},
		{"ordinary loop break before remove", `for x in a; do break; rm "$OUT"; done`, "open"},
		{"ordinary loop continue before remove", `for x in a b; do continue; rm "$OUT"; done`, "open"},
		{"ordinary counted break inside two loops", `for x in a; do for y in b; do break 2; rm "$OUT"; done; rm "$OUT"; done`, "open"},
		{"ordinary exit before remove", `exit 0; rm "$OUT"`, "open"},
		{"ordinary unrelated function", `f() { :; }; if false; then rm "$OUT"; fi`, "open"},
		{"ordinary shadowed true other file", `true() { false; }; if true; then :; else rm notes.txt; fi`, "open"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := outageR10Decision(t, root, ordinary, tc.command, map[string]interface{}{"OUT": protected, "PROT": protected})
			if got != tc.want {
				t.Errorf("decision=%q want=%q command=%q", got, tc.want, tc.command)
			}
		})
	}
}

// outageFieldSeparator returns a one-character IFS that is a plain word
// character to the shell and is absent from path, so the path is one field
// under that IFS whatever directory the tests run in. It prefers the ASCII
// characters below, and when a directory name holds all of them it takes the
// first printable character past U+00A0 the path lacks, so a separator always
// exists and no case is skipped.
func outageFieldSeparator(t *testing.T, path string) string {
	t.Helper()
	for _, candidate := range []string{":", ",", "@", "+", "^"} {
		if !strings.Contains(path, candidate) {
			return candidate
		}
	}
	for r := rune(0xa1); ; r++ {
		if unicode.IsPrint(r) && !unicode.IsSpace(r) && !strings.ContainsRune(path, r) {
			return string(r)
		}
	}
}

// An unquoted known value splits at the field separators the shell has: the
// default ones, not every Unicode space, or the IFS the command or the
// environment set. The separator the cases set is one that the generated
// protected path does not hold (a colon, or the next candidate when the
// temporary directory has one): a Windows path holds a colon after its drive
// letter, and any of these can be legal in a directory name.
func TestOpenClawOutageKnownValuesSplitAtShellSeparators(t *testing.T) {
	root, protected, ordinary := outageR10Fixture(t, "home\u00a0with\u00a0nbsp")
	sep := outageFieldSeparator(t, protected)
	cases := []struct {
		name, command, ifs, value, want string
	}{
		{"nonbreaking space path", `for x in $PROT; do rm "$x"; done`, "", protected, "protected"},
		{"quoted nonbreaking space path", `for x in "$PROT"; do rm "$x"; done`, "", protected, "protected"},
		{"default split ordinary", `for x in $PROT; do rm "$x"; done`, "", "notes.txt other.txt", "open"},
		{"default split reaches protected", `for x in $PROT; do rm "$x"; done`, "", "notes.txt " + protected, "protected"},
		{"local IFS whole value", `IFS=` + sep + `; for x in $PROT; do rm "$x"; done`, "", protected, "protected"},
		{"environment IFS whole value", `for x in $PROT; do rm "$x"; done`, sep, protected, "protected"},
		{"local IFS splits to protected", `IFS=` + sep + `; for x in $PROT; do rm "$x"; done`, "", "notes.txt" + sep + protected, "protected"},
		{"local IFS splits ordinary", `IFS=` + sep + `; for x in $PROT; do rm "$x"; done`, "", "notes.txt" + sep + "other.txt", "open"},
		{"environment IFS splits ordinary", `for x in $PROT; do rm "$x"; done`, sep, "notes.txt" + sep + "other.txt", "open"},
		{"unknown IFS keeps whole value", `IFS=$(printf ` + sep + `); for x in $PROT; do rm "$x"; done`, "", protected, "protected"},
		{"empty IFS keeps whole value", `IFS=; for x in $PROT; do rm "$x"; done`, "", protected, "protected"},
		{"empty IFS ordinary", `IFS=; for x in $PROT; do rm "$x"; done`, "", "notes.txt other.txt", "open"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			environment := map[string]interface{}{"PROT": tc.value}
			if tc.ifs != "" {
				environment["IFS"] = tc.ifs
			}
			if got := outageR10Decision(t, root, ordinary, tc.command, environment); got != tc.want {
				t.Errorf("decision=%q want=%q command=%q", got, tc.want, tc.command)
			}
		})
	}
}

// A command long enough to pass the reading bound still blocks a protected
// target a known value reaches, whether the value comes from before the
// padding, is set after it, or is built in pieces; padding with ordinary
// statements does not change an ordinary command's answer.
func TestOpenClawOutageKnownValuesPastReadingBound(t *testing.T) {
	root, protected, ordinary := outageR10Fixture(t, "home")
	for _, count := range []int{200, 250, 260, 600} {
		for _, pad := range []string{":; ", "rm notes.txt; ", "echo x; "} {
			block := func(body string) string { return "{ " + strings.Repeat(pad, count) + body + " }" }
			cases := []struct {
				name, command, want string
				held                bool
			}{
				{"set after padding", block(`OUT="$PROT"; rm "$OUT";`), "protected", true},
				{"set before padding", `{ OUT="$PROT"; ` + strings.Repeat(pad, count) + `rm "$OUT"; }`, "protected", true},
				{"built in pieces", block(`D="$HOME/.defenseclaw"; F="$D/config.yaml"; rm "$F";`), "protected", false},
				{"loop after padding", block(`for x in "$PROT"; do rm "$x"; done;`), "protected", true},
				{"function after padding", `{ f() { rm "$PROT"; }; ` + strings.Repeat(pad, count) + `f; }`, "protected", true},
				{"ordinary after padding", block(`rm notes.txt;`), "open", false},
				{"ordinary value after padding", block(`OUT=notes.txt; rm "$OUT";`), "open", false},
			}
			for _, tc := range cases {
				t.Run(strings.TrimSpace(pad)+"/"+tc.name+"/"+strings.Repeat("x", count%7+1), func(t *testing.T) {
					environment := map[string]interface{}{}
					if tc.held {
						environment["PROT"] = protected
					}
					got := outageR10Decision(t, root, ordinary, tc.command, environment)
					if got != tc.want {
						t.Errorf("padding=%q x%d decision=%q want=%q", pad, count, got, tc.want)
					}
				})
			}
		}
	}
}
