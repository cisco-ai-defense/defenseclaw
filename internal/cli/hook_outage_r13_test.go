// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// A redefinition counts from the statement the shell reaches it in, in a
// function only where the command calls the function, and in a loop in the
// pass that reaches it. command -v only describes a name.
func TestOpenClawOutageShadowedBuiltinsFollowCallsAndLoopPasses(t *testing.T) {
	outageR12Run(t, []outageR12Case{
		{"unused function holds eval", `f() { eval 'true() { false; }'; }; if true; then :; else rm "$OUT"; fi`, "open"},
		{"unused function holds alias", `f() { alias true=false; }; if true; then :; else rm "$OUT"; fi`, "open"},
		{"unused function holds a computed command", `f() { "$X"; }; if true; then :; else rm "$OUT"; fi`, "open"},
		{"single pass loop defines true after the guard", `for x in a; do if true; then :; else rm "$OUT"; fi; true() { false; }; done`, "open"},
		{"single pass loop evals after the guard", `for x in a; do if true; then :; else rm "$OUT"; fi; eval 'true() { false; }'; done`, "open"},
		{"command -v does not run eval", `command -v eval 'true() { false; }'; if true; then :; else rm "$OUT"; fi`, "open"},
		{"command -V does not run eval", `command -V eval 'true() { false; }'; if true; then :; else rm "$OUT"; fi`, "open"},
		{"called function evals true", `f() { eval 'true() { false; }'; }; f; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"function called through another", `f() { eval 'true() { false; }'; }; g() { f; }; g; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"function defined by eval and called", `eval 'f() { eval "true() { false; }"; }'; f; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"two pass loop defines true after the guard", `for x in a b; do if true; then :; else rm "$OUT"; fi; true() { false; }; done`, "protected"},
		{"unknown pass loop defines true after the guard", `for x in $LIST; do if true; then :; else rm "$OUT"; fi; true() { false; }; done`, "protected"},
		{"while loop defines true after the guard", `while read x; do if true; then :; else rm "$OUT"; fi; true() { false; }; done`, "protected"},
		{"function of true that returns success", `true() { :; }; if true; then :; else rm "$OUT"; fi`, "open"},
		{"function of false that returns failure", `false() { false; }; if false; then rm "$OUT"; fi`, "open"},
		{"function of true that returns failure", `true() { false; }; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"function of false that returns success", `false() { true; }; if false; then rm "$OUT"; fi`, "protected"},
		{"function of true that changes a target", `true() { OUT="$PROT"; }; true; rm "$OUT"`, "protected"},
		{"function of colon that removes a target", `:() { rm "$PROT"; }; :`, "protected"},
		{"command -p still runs eval", `command -p eval 'true() { false; }'; if true; then :; else rm "$OUT"; fi`, "protected"},
	}, func(protected string) map[string]interface{} {
		return map[string]interface{}{"OUT": protected, "PROT": protected, "X": "echo", "LIST": "a b"}
	})
}

// A call of a function leaves what the body assigns, from the words the call
// gives: a quoted word is one parameter whatever its value, an unquoted word
// the fields of its value, and a prefix assignment holds for the body only.
func TestOpenClawOutageFunctionEffectsKeepQuotedValuesAndPrefixCalls(t *testing.T) {
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
		{"quoted protected file through parameter", `f() { OUT="$1"; }; f "$PROT"; rm "$OUT"`, "protected", map[string]interface{}{"PROT": protected}},
		{"quoted protected link with space through parameter", `f() { OUT="$1"; }; f "$PROT"; rm "$OUT"`, "protected", map[string]interface{}{"PROT": spaced}},
		{"quoted protected link over an ordinary value", `f() { OUT="$1"; }; f "$PROT"; rm "$OUT"`, "protected", map[string]interface{}{"PROT": spaced, "OUT": "notes.txt"}},
		{"unquoted assignment keeps the whole value", `f() { OUT=$1; }; f "$PROT"; rm "$OUT"`, "protected", map[string]interface{}{"PROT": spaced}},
		{"ordinary link with space through parameter", `f() { OUT="$1"; }; f "$ORD"; rm "$OUT"`, "open", map[string]interface{}{"ORD": spacedOrdinary}},
		{"second quoted parameter", `f() { OUT="$2"; }; f "$ORD" "$PROT"; rm "$OUT"`, "protected", map[string]interface{}{"ORD": spacedOrdinary, "PROT": protected}},
		{"empty unquoted word shifts the parameters", `f() { OUT="$1"; }; f $E "$PROT"; rm "$OUT"`, "protected", map[string]interface{}{"E": "", "PROT": protected}},
		{"split unquoted word shifts the parameters", `f() { OUT="$2"; }; f $LIST "$PROT"; rm "$OUT"`, "open", map[string]interface{}{"LIST": "a b", "PROT": protected}},
		{"prefixed call sets protected target", `f() { OUT="$PROT"; }; X=1 f; rm "$OUT"`, "protected", map[string]interface{}{"PROT": protected, "OUT": "notes.txt"}},
		{"prefixed call sets protected link", `f() { OUT="$PROT"; }; X=1 f; rm "$OUT"`, "protected", map[string]interface{}{"PROT": spaced, "OUT": "notes.txt"}},
		{"prefixed call overwrites protected target", `f() { OUT=notes.txt; }; X=1 f; rm "$OUT"`, "open", map[string]interface{}{"OUT": protected}},
		{"prefixed value read by the body", `f() { OUT="$X"; }; X="$PROT" f; rm "$OUT"`, "protected", map[string]interface{}{"PROT": protected}},
		{"prefixed value is not kept", `f() { :; }; OUT="$PROT" f; rm "$OUT"`, "open", map[string]interface{}{"PROT": protected, "OUT": "notes.txt"}},
		{"later definition overwrites target", `f() { OUT="$PROT"; }; f() { OUT=notes.txt; }; f; rm "$OUT"`, "open", map[string]interface{}{"PROT": protected, "OUT": protected}},
		{"colon function makes protected target", `:() { OUT="$PROT"; }; f() { OUT=notes.txt; :; }; f; rm "$OUT"`, "protected", map[string]interface{}{"PROT": protected}},
		{"colon builtin changes nothing", `f() { OUT=notes.txt; :; }; f; rm "$OUT"`, "open", map[string]interface{}{"OUT": protected}},
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

// A protected file under a home with a space, reached through a quoted
// parameter, is protected; an ordinary file there stays open.
func TestOpenClawOutageQuotedParameterUnderHomeWithSpace(t *testing.T) {
	root, protected, ordinary := outageR10Fixture(t, "home space")
	for _, tc := range []struct{ name, command, target, want string }{
		{"direct protected file", `rm "$PROT"`, protected, "protected"},
		{"protected file through a quoted parameter", `f() { OUT="$1"; }; f "$PROT"; rm "$OUT"`, protected, "protected"},
		{"ordinary file through a quoted parameter", `f() { OUT="$1"; }; f "$PROT"; rm "$OUT"`, filepath.Join(ordinary, "notes.txt"), "open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := outageR10Decision(t, root, ordinary, tc.command, map[string]interface{}{"PROT": tc.target})
			if got != tc.want {
				t.Errorf("decision=%q want=%q command=%q", got, tc.want, tc.command)
			}
		})
	}
}
