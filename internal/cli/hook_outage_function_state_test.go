// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const outageBad = "eval ^true() { false; }^"

func outageQuoted(commands []outageR12Case) []outageR12Case {
	for i := range commands {
		commands[i].command = strings.ReplaceAll(commands[i].command, "^", "\x27")
	}
	return commands
}

// A definition the shell certainly runs replaces the earlier ones, wherever it
// stands in straight-line order: in a block, in a branch a static condition
// takes, in eval text, in a function the command calls. A definition in a
// branch an unknown condition decides, a loop, a subshell, a background list,
// a pipeline or a function that may return first does not replace the old one,
// so the old definition still counts.
func TestOpenClawOutageReplacementInStraightLineOrderReplaces(t *testing.T) {
	old := "f() { " + outageBad + "; }; "
	guard := `; f; if true; then :; else rm "$OUT"; fi`
	outageR12Run(t, outageQuoted([]outageR12Case{
		{"replacement at the top", old + `f() { :; }` + guard, "open"},
		{"replacement in a block", old + `{ f() { :; }; }` + guard, "open"},
		{"replacement in a block of a block", old + `{ { f() { :; }; }; }` + guard, "open"},
		{"replacement in a taken branch", old + `if true; then f() { :; }; fi` + guard, "open"},
		{"replacement in the else of a failed condition", old + `if false; then :; else f() { :; }; fi` + guard, "open"},
		{"replacement after a taken and-list", old + `true && f() { :; }` + guard, "open"},
		{"replacement after a failed or-list", old + `false || f() { :; }` + guard, "open"},
		{"replacement in eval text", old + `eval ^f() { :; }^` + guard, "open"},
		{"replacement in eval text of a block", old + `eval ^{ f() { :; }; }^` + guard, "open"},
		{"replacement in command eval text", old + `command eval ^f() { :; }^` + guard, "open"},
		{"replacement by a function the command calls", old + `g() { f() { :; }; }; g` + guard, "open"},
		{"replacement by a function in a block", old + `g() { { f() { :; }; }; }; g` + guard, "open"},
		{"replacement by a function through eval", old + `g() { eval ^f() { :; }^; }; g` + guard, "open"},
		{"replacement in a taken branch of a function", old + `g() { if true; then f() { :; }; fi; }; g` + guard, "open"},
		{"replacement by a case branch the word selects", old + `case a in a) f() { :; };; esac` + guard, "open"},
		{"replacement in a branch an unknown condition decides", old + `if [ -n "$X" ]; then f() { :; }; fi` + guard, "protected"},
		{"replacement in the else of an unknown condition", old + `if [ -n "$X" ]; then :; else f() { :; }; fi` + guard, "protected"},
		{"replacement after an unknown and-list", old + `[ -n "$X" ] && f() { :; }` + guard, "protected"},
		{"replacement after an unknown or-list", old + `[ -n "$X" ] || f() { :; }` + guard, "protected"},
		{"replacement in a loop over a fixed list", old + `for x in a b; do f() { :; }; done` + guard, "open"},
		{"replacement in a loop over a fixed list with a nested block", old + `for x in a b; do { f() { :; }; }; done` + guard, "open"},
		{"replacement in a loop over an unknown list", old + `for x in $LIST; do f() { :; }; done` + guard, "protected"},
		{"replacement in a loop that may continue first", old + `for x in a b; do if [ -n "$X" ]; then continue; fi; f() { :; }; done` + guard, "protected"},
		{"replacement in a loop whose function breaks", old + `g() { break; }; for x in a b; do g; f() { :; }; done` + guard, "protected"},
		{"replacement in a loop that may break first", old + `for x in a b; do if [ -n "$X" ]; then break; fi; f() { :; }; done` + guard, "protected"},
		{"replacement in a while loop", old + `while true; do f() { :; }; break; done` + guard, "protected"},
		{"replacement in a subshell", old + `( f() { :; } )` + guard, "protected"},
		{"replacement in a background list", old + `f() { :; } & true` + guard, "protected"},
		{"replacement in a pipeline", old + `{ f() { :; }; } | cat` + guard, "protected"},
		{"replacement in eval text that may return first", old + `eval ^[ -n "$X" ] && return; f() { :; }^` + guard, "protected"},
		{"replacement in a function that may return first", old + `g() { [ -n "$X" ] && return; f() { :; }; }; g` + guard, "protected"},
		{"replacement in a function that may be another one", old + `if [ -n "$X" ]; then g() { f() { :; }; }; else g() { :; }; fi; g` + guard, "protected"},
		{"replacement in unknown eval text", old + `eval "$X"; f() { :; }` + guard, "protected"},
		{"replacement made after the call", old + `f; f() { :; }` + guard, "protected"},
		{"replacement in a function never called", old + `g() { f() { :; }; }` + guard, "protected"},
	}), func(protected string) map[string]interface{} { return map[string]interface{}{"OUT": protected} })
}

// A function named eval takes the place of the builtin: its arguments are
// parameters, not text. A call that skips functions, a function the shell may
// not have, one it removed, and a body that evals its own text are read.
func TestOpenClawOutageFunctionNamedEvalIsNotEvalText(t *testing.T) {
	guard := `; if true; then :; else rm "$OUT"; fi`
	outageR12Run(t, outageQuoted([]outageR12Case{
		{"function of eval ignores its text", `eval() { :; }; ` + outageBad + guard, "open"},
		{"function of eval in a block", `{ eval() { :; }; }; ` + outageBad + guard, "open"},
		{"function of eval in a taken branch", `if true; then eval() { :; }; fi; ` + outageBad + guard, "open"},
		{"function of eval called twice", `eval() { :; }; eval x; ` + outageBad + guard, "open"},
		{"function of eval with another text", `eval() { :; }; eval ^g() { :; }^` + guard, "open"},
		{"builtin eval skips the function", `eval() { :; }; builtin ` + outageBad + guard, "protected"},
		{"command eval skips the function", `eval() { :; }; command ` + outageBad + guard, "protected"},
		{"function of eval that forwards its text", `eval() { builtin eval "$@"; }; ` + outageBad + guard, "protected"},
		{"function of eval that evals its own text", `eval() { builtin ` + outageBad + `; }; eval x` + guard, "protected"},
		{"function of eval defined in a branch an unknown condition decides", `if [ -n "$X" ]; then eval() { :; }; fi; ` + outageBad + guard, "protected"},
		{"function of eval removed", `eval() { :; }; unset -f eval; ` + outageBad + guard, "protected"},
		{"function of eval removed by a computed name", `eval() { :; }; unset -f "$X"; ` + outageBad + guard, "protected"},
		{"function of eval defined in a subshell", `( eval() { :; } ); ` + outageBad + guard, "protected"},
		{"eval text without a function of eval", outageBad + guard, "protected"},
	}), func(protected string) map[string]interface{} { return map[string]interface{}{"OUT": protected} })
}

// A word of mixed quoted and unquoted parts keeps a protected name whole when
// the name has a brace character: quoted text and the value of an expansion
// are not brace-expanded, so the name reaches the function as it is.
func TestOpenClawOutageMixedQuotingKeepsABraceNamedTargetWhole(t *testing.T) {
	root, protected, ordinary := outageR10Fixture(t, "home{one}")
	braceLink := filepath.Join(ordinary, "config{link}")
	if err := os.Symlink(protected, braceLink); err != nil {
		t.Fatal(err)
	}
	braceOrdinary := filepath.Join(ordinary, "notes{link}")
	if err := os.Symlink(filepath.Join(ordinary, "notes.txt"), braceOrdinary); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, command, want string
		environment         map[string]interface{}
	}{
		{"direct file", `rm "$PROT"`, "protected", map[string]interface{}{"PROT": protected}},
		{"direct link", `rm "$PROT"`, "protected", map[string]interface{}{"PROT": braceLink}},
		{"empty expansion before a quoted file", `f() { OUT="$1"; }; f $E"$PROT"; rm "$OUT"`, "protected", map[string]interface{}{"E": "", "PROT": protected}},
		{"empty expansion after a quoted file", `f() { OUT="$1"; }; f "$PROT"$E; rm "$OUT"`, "protected", map[string]interface{}{"E": "", "PROT": protected}},
		{"empty expansion before a quoted link", `f() { OUT="$1"; }; f $E"$PROT"; rm "$OUT"`, "protected", map[string]interface{}{"E": "", "PROT": braceLink}},
		{"empty expansion after a quoted link", `f() { OUT="$1"; }; f "$PROT"$E; rm "$OUT"`, "protected", map[string]interface{}{"E": "", "PROT": braceLink}},
		{"empty expansions around a quoted link", `f() { OUT="$1"; }; f $E"$PROT"$E; rm "$OUT"`, "protected", map[string]interface{}{"E": "", "PROT": braceLink}},
		{"second parameter after a mixed word", `f() { OUT="$2"; }; f x $E"$PROT"; rm "$OUT"`, "protected", map[string]interface{}{"E": "", "PROT": braceLink}},
		{"unquoted file", `f() { OUT="$1"; }; f $PROT; rm "$OUT"`, "protected", map[string]interface{}{"PROT": protected}},
		{"unquoted link", `f() { OUT="$1"; }; f $PROT; rm "$OUT"`, "protected", map[string]interface{}{"PROT": braceLink}},
		{"quoted file", `f() { OUT="$1"; }; f "$PROT"; rm "$OUT"`, "protected", map[string]interface{}{"PROT": protected}},
		{"empty expansion before an ordinary link", `f() { OUT="$1"; }; f $E"$ORD"; rm "$OUT"`, "open", map[string]interface{}{"E": "", "ORD": braceOrdinary}},
		{"empty expansion after an ordinary link", `f() { OUT="$1"; }; f "$ORD"$E; rm "$OUT"`, "open", map[string]interface{}{"E": "", "ORD": braceOrdinary}},
		{"unquoted ordinary link", `f() { OUT="$1"; }; f $ORD; rm "$OUT"`, "open", map[string]interface{}{"ORD": braceOrdinary}},
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
