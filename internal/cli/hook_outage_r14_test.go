// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// A call of a function scans the definition the shell has made when it runs,
// and the statements of that body the shell reaches: a definition in a branch
// the shell skips, one made after the call, one the shell has replaced, and
// an eval in a branch the body skips change nothing for the ordinary command.
// A definition or statement the shell can reach still counts.
func TestOpenClawOutageCalledFunctionScansWhatTheShellReaches(t *testing.T) {
	outageR12Run(t, []outageR12Case{
		{"definition in a skipped branch", `f() { :; }; if false; then f() { eval 'true() { false; }'; }; fi; f; if true; then :; else rm "$OUT"; fi`, "open"},
		{"function called before the replacement", `f() { :; }; f; f() { eval 'true() { false; }'; }; if true; then :; else rm "$OUT"; fi`, "open"},
		{"replacement made before the call", `f() { eval 'true() { false; }'; }; f() { :; }; f; if true; then :; else rm "$OUT"; fi`, "open"},
		{"eval in a skipped branch of the body", `f() { if false; then eval 'true() { false; }'; fi; }; f; if true; then :; else rm "$OUT"; fi`, "open"},
		{"eval after a failed and-list in the body", `f() { false && eval 'true() { false; }'; }; f; if true; then :; else rm "$OUT"; fi`, "open"},
		{"eval in a loop the body does not enter", `f() { while false; do eval 'true() { false; }'; done; }; f; if true; then :; else rm "$OUT"; fi`, "open"},
		{"command skips the function of that name", `false() { eval 'true() { false; }'; }; command false; if true; then :; else rm "$OUT"; fi`, "open"},
		{"builtin skips the function of that name", `f() { eval 'true() { false; }'; }; builtin f; if true; then :; else rm "$OUT"; fi`, "open"},
		{"body returns before the eval", `f() { return; eval 'true() { false; }'; }; f; if true; then :; else rm "$OUT"; fi`, "open"},
		{"body returns after a taken and-list", `f() { true && return; eval 'true() { false; }'; }; f; if true; then :; else rm "$OUT"; fi`, "open"},
		{"body returns in both branches", `f() { if [ -n "$X" ]; then return; else return; fi; eval 'true() { false; }'; }; f; if true; then :; else rm "$OUT"; fi`, "open"},
		{"body returns in one branch", `f() { if [ -n "$X" ]; then return; fi; eval 'true() { false; }'; }; f; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"body returns after a failed and-list", `f() { false && return; eval 'true() { false; }'; }; f; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"return is a function", `return() { :; }; f() { return; eval 'true() { false; }'; }; f; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"return runs in a subshell", `f() { (return); eval 'true() { false; }'; }; f; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"call before any definition", `f; f() { eval 'true() { false; }'; }; if true; then :; else rm "$OUT"; fi`, "open"},
		{"loop in the body keeps the guard", `f() { for x in a b; do if true; then :; else eval 'false() { command true; }'; fi; done; }; f; if false; then rm "$OUT"; fi`, "open"},
		{"loop in the body redefines the guard for a later pass", `f() { for x in a b; do if true; then :; else eval 'false() { command true; }'; fi; true() { false; }; done; }; f; if false; then rm "$OUT"; fi`, "protected"},
		{"uncalled function of true", `true() { eval 'false() { true; }'; }; if false; then rm "$OUT"; fi`, "open"},
		{"definition in a taken branch", `f() { :; }; if true; then f() { eval 'true() { false; }'; }; fi; f; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"second definition holds the eval", `f() { :; }; f() { eval 'true() { false; }'; }; f; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"definition in a branch the shell may take", `if [ -n "$X" ]; then f() { eval 'true() { false; }'; }; else f() { :; }; fi; f; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"eval in a taken branch of the body", `f() { if true; then eval 'true() { false; }'; fi; }; f; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"eval in the else branch of the body", `f() { if false; then :; else eval 'true() { false; }'; fi; }; f; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"eval after a failed or-list in the body", `f() { false || eval 'true() { false; }'; }; f; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"eval in a loop the body enters", `f() { while true; do eval 'true() { false; }'; break; done; }; f; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"function defined after a first call of its caller", `g() { f; }; g; f() { eval 'true() { false; }'; }; g; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"function that defines the function it calls", `g() { f() { eval 'true() { false; }'; }; f; }; g; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"command does not skip eval", `f() { command eval 'true() { false; }'; }; f; if true; then :; else rm "$OUT"; fi`, "protected"},
	}, func(protected string) map[string]interface{} { return map[string]interface{}{"OUT": protected} })
}

// A function that takes the name of a builtin the reader relies on runs its
// body where the command calls it by that name.
func TestOpenClawOutageFunctionOfABuiltinNameRunsItsBody(t *testing.T) {
	outageR12Run(t, []outageR12Case{
		{"true defines false", `true() { eval 'false() { true; }'; }; true; if false; then rm "$OUT"; fi`, "protected"},
		{"false defines true", `false() { eval 'true() { command false; }'; }; false; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"colon defines true", `:() { eval 'true() { false; }'; }; :; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"exit defines true", `exit() { eval 'true() { false; }'; }; exit; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"true defines false and is called through f", `true() { eval 'false() { true; }'; }; f() { true; }; f; if false; then rm "$OUT"; fi`, "protected"},
		{"true defines false and is not called", `true() { eval 'false() { true; }'; }; if false; then rm "$OUT"; fi`, "open"},
		{"true defines false in a branch the body skips", `true() { if false; then eval 'false() { true; }'; fi; }; true; if false; then rm "$OUT"; fi`, "open"},
	}, func(protected string) map[string]interface{} { return map[string]interface{}{"OUT": protected} })
}

// A word of mixed quoted and unquoted parts is split only where its unquoted
// expansion has blanks: the quoted part, and the literal text, stay in the
// field they touch.
func TestOpenClawOutageMixedQuotingKeepsTheQuotedPartWhole(t *testing.T) {
	root, protected, ordinary := outageR10Fixture(t, "home")
	spaced := filepath.Join(ordinary, "config link")
	if err := os.Symlink(protected, spaced); err != nil {
		t.Fatal(err)
	}
	spacedOrdinary := filepath.Join(ordinary, "notes link")
	if err := os.Symlink(filepath.Join(ordinary, "notes.txt"), spacedOrdinary); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, command, want string
		environment         map[string]interface{}
	}{
		{"empty expansion before a quoted protected link", `f() { OUT="$1"; }; f $E"$PROT"; rm "$OUT"`, "protected", map[string]interface{}{"E": "", "PROT": spaced}},
		{"empty expansion after a quoted protected link", `f() { OUT="$1"; }; f "$PROT"$E; rm "$OUT"`, "protected", map[string]interface{}{"E": "", "PROT": spaced}},
		{"empty expansion before a quoted protected file", `f() { OUT="$1"; }; f $E"$PROT"; rm "$OUT"`, "protected", map[string]interface{}{"E": "", "PROT": protected}},
		{"empty expansion after a quoted protected file", `f() { OUT="$1"; }; f "$PROT"$E; rm "$OUT"`, "protected", map[string]interface{}{"E": "", "PROT": protected}},
		{"empty expansions around a quoted protected link", `f() { OUT="$1"; }; f $E"$PROT"$E; rm "$OUT"`, "protected", map[string]interface{}{"E": "", "PROT": spaced}},
		{"second parameter after a mixed word", `f() { OUT="$2"; }; f x $E"$PROT"; rm "$OUT"`, "protected", map[string]interface{}{"E": "", "PROT": spaced}},
		{"empty expansion before an ordinary link", `f() { OUT="$1"; }; f $E"$ORD"; rm "$OUT"`, "open", map[string]interface{}{"E": "", "ORD": spacedOrdinary}},
		{"empty expansion after an ordinary link", `f() { OUT="$1"; }; f "$ORD"$E; rm "$OUT"`, "open", map[string]interface{}{"E": "", "ORD": spacedOrdinary}},
		{"blanks in the unquoted part split before the quoted part", `f() { OUT="$2"; }; f $LIST"$PROT"; rm "$OUT"`, "open", map[string]interface{}{"LIST": "a b", "PROT": spaced}},
		{"blanks in the unquoted part leave the first field", `f() { OUT="$1"; }; f $LIST"$PROT"; rm "$OUT"`, "open", map[string]interface{}{"LIST": "a b", "PROT": spaced}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := outageR10Decision(t, root, ordinary, tc.command, tc.environment)
			if got != tc.want {
				t.Errorf("decision=%q want=%q command=%q", got, tc.want, tc.command)
			}
		})
	}
}
