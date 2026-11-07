// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

type outageR12Case struct{ name, command, want string }

func outageR12Run(t *testing.T, cases []outageR12Case, environment func(protected string) map[string]interface{}) {
	t.Helper()
	root, protected, ordinary := outageR10Fixture(t, "home")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := outageR10Decision(t, root, ordinary, tc.command, environment(protected))
			if got != tc.want {
				t.Errorf("decision=%q want=%q command=%q", got, tc.want, tc.command)
			}
		})
	}
}

// What a command redefines counts from the statement that redefines it, and
// only the names it redefines: an eval of text that defines none of the
// builtins the reader relies on, a function of another name, a definition
// the shell makes after the condition or in a branch it skips, change
// nothing for the ordinary command, and a definition the shell has made,
// through command or builtin as well, is read.
func TestOpenClawOutageShadowedBuiltinsFollowTheShellOrder(t *testing.T) {
	outageR12Run(t, []outageR12Case{
		{"harmless eval before static true", `eval ':'; if true; then :; else rm "$OUT"; fi`, "open"},
		{"harmless eval of a function before static true", `eval 'g() { :; }'; if true; then :; else rm "$OUT"; fi`, "open"},
		{"definition after the condition", `{ if true; then :; else rm "$OUT"; fi; true() { false; }; }`, "open"},
		{"definition of another builtin", `false() { true; }; if true; then :; else rm "$OUT"; fi`, "open"},
		{"definition of another builtin in a loop", `false() { true; }; for x in a b; do if true; then :; else rm "$OUT"; fi; done`, "open"},
		{"definition in a skipped branch", `{ if false; then true() { false; }; fi; if true; then :; else rm "$OUT"; fi; }`, "open"},
		{"eval in a skipped branch", `{ if false; then eval 'true() { false; }'; fi; if true; then :; else rm "$OUT"; fi; }`, "open"},
		{"command eval of a harmless text", `command eval ':'; if true; then :; else rm "$OUT"; fi`, "open"},
		{"definition then use", `true() { false; }; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"eval defined true", `eval 'true() { false; }'; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"eval with double quotes", `eval "true() { false; }"; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"command eval shadows true", `command eval 'true() { false; }'; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"command option eval shadows true", `command -- eval 'true() { false; }'; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"builtin eval shadows true", `builtin eval 'true() { false; }'; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"command eval shadows exit", `command eval 'exit() { :; }'; { exit; rm "$OUT"; }`, "protected"},
		{"command eval shadows false", `command eval 'false() { true; }'; if false; then rm "$OUT"; fi`, "protected"},
		{"eval of a nested eval", `eval "eval 'true() { false; }'"; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"eval of a computed text", `T="true() { false; }"; eval "$T"; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"computed command word", `X=eval; $X 'true() { false; }'; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"substituted command word", `$(echo eval) 'true() { false; }'; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"alias", `alias true=false; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"definition in a loop reaches the first statement", `for x in a b; do if true; then :; else rm "$OUT"; fi; true() { false; }; done`, "protected"},
		{"eval in a loop reaches the first statement", `while :; do if true; then :; else rm "$OUT"; fi; eval 'true() { false; }'; break; done`, "protected"},
		{"definition in a taken branch", `{ if true; then true() { false; }; fi; if true; then :; else rm "$OUT"; fi; }`, "protected"},
	}, func(protected string) map[string]interface{} { return map[string]interface{}{"OUT": protected} })
}

// A call runs the definition the shell has made by then: a body only a
// skipped branch defines, or defined after the call, is not run, and one the
// shell may have defined is.
func TestOpenClawOutageFunctionBodiesNeedTheirDefinition(t *testing.T) {
	outageR12Run(t, []outageR12Case{
		{"definition in a skipped branch", `{ if false; then f() { rm "$OUT"; }; fi; f; }`, "open"},
		{"definition after the call", `{ f; f() { rm "$OUT"; }; }`, "open"},
		{"definition in a taken branch", `{ if true; then f() { rm "$OUT"; }; fi; f; }`, "protected"},
		{"definition in the else branch", `{ if false; then :; else f() { rm "$OUT"; }; fi; f; }`, "protected"},
		{"definition in an unknown branch", `{ if test -e x; then f() { rm "$OUT"; }; fi; f; }`, "protected"},
		{"definition in a function", `g() { f() { rm "$OUT"; }; }; { g; f; }`, "protected"},
		{"definition then call", `{ f() { rm "$OUT"; }; f; }`, "protected"},
		{"definition in an earlier statement", `f() { rm "$OUT"; }; { f; }`, "protected"},
		{"definition in an earlier pass", `for x in a b; do f; f() { rm "$OUT"; }; done`, "protected"},
		{"definition in a case", `{ case x in x) f() { rm "$OUT"; };; esac; f; }`, "protected"},
	}, func(protected string) map[string]interface{} { return map[string]interface{}{"OUT": protected} })
}

// A call of a function leaves the values its body establishes: a value it
// assigns from a known parameter is the target afterwards, a value it
// overwrites is not kept, and a body the reader does not read keeps both.
func TestOpenClawOutageFunctionCallsKeepWhatTheyEstablish(t *testing.T) {
	root, protected, ordinary := outageR10Fixture(t, "home")
	link := filepath.Join(ordinary, "config-link")
	if err := os.Symlink(protected, link); err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct{ name, value string }{{"file", protected}, {"link", link}} {
		for _, tc := range []struct {
			name, command, want string
			environment         map[string]interface{}
		}{
			{"direct", `rm "$PROT"`, "protected", map[string]interface{}{"PROT": target.value}},
			{"function assigns the value", `f() { OUT="$PROT"; }; f; rm "$OUT"`, "protected", map[string]interface{}{"PROT": target.value}},
			{"function assigns the value after another", `f() { :; OUT="$PROT"; X=1; }; f; rm "$OUT"`, "protected", map[string]interface{}{"PROT": target.value}},
			{"function assigns the value in a block", `f() { OUT="$PROT"; }; { f; rm "$OUT"; }`, "protected", map[string]interface{}{"PROT": target.value}},
			{"function assigns the value in a loop", `f() { OUT="$PROT"; }; for x in a b; do f; rm "$OUT"; done`, "protected", map[string]interface{}{"PROT": target.value}},
			{"function assigns the value from a name", `f() { OUT="$PROT"; }; g() { T="$OUT"; }; f; g; rm "$T"`, "protected", map[string]interface{}{"PROT": target.value}},
			{"function overwrites the value", `f() { OUT=notes.txt; }; f; rm "$OUT"`, "open", map[string]interface{}{"OUT": target.value}},
			{"function overwrites the value from a name", `f() { OUT="$ORD"; }; f; rm "$OUT"`, "open", map[string]interface{}{"OUT": target.value, "ORD": "notes.txt"}},
			{"function overwrites the value in a block", `f() { OUT=notes.txt; }; { f; rm "$OUT"; }`, "open", map[string]interface{}{"OUT": target.value}},
			{"function keeps the value", `f() { :; }; f; rm "$OUT"`, "protected", map[string]interface{}{"OUT": target.value}},
			{"function in the background keeps the value", `f() { OUT=notes.txt; }; f & rm "$OUT"`, "protected", map[string]interface{}{"OUT": target.value}},
			{"function with an unread body keeps both", `f() { read OUT; }; f; rm "$OUT"`, "protected", map[string]interface{}{"OUT": target.value}},
			{"function with a local keeps the value", `f() { local OUT=notes.txt; }; f; rm "$OUT"`, "protected", map[string]interface{}{"OUT": target.value}},
			{"function takes a known parameter", `f() { OUT="$1"; }; f notes.txt; rm "$OUT"`, "open", map[string]interface{}{"OUT": target.value}},
			{"function takes an unknown parameter", `f() { OUT="$1"; }; f "$UNKNOWN"; rm "$OUT"`, "protected", map[string]interface{}{"OUT": target.value}},
			{"function reads a parameter the call does not give", `f() { OUT="$2"; }; f notes.txt; rm "$OUT"`, "protected", map[string]interface{}{"OUT": target.value}},
			{"function passes the value on", `f() { OUT="$1"; }; f "$PROT"; rm "$OUT"`, "protected", map[string]interface{}{"PROT": target.value}},
			{"function of a readonly name keeps the value", `readonly OUT; f() { OUT=notes.txt; }; f; rm "$OUT"`, "protected", map[string]interface{}{"OUT": target.value}},
			{"ordinary value stays ordinary", `f() { OUT="$ORD"; }; f; rm "$OUT"`, "open", map[string]interface{}{"ORD": "notes.txt"}},
		} {
			t.Run(target.name+"/"+tc.name, func(t *testing.T) {
				got := outageR10Decision(t, root, ordinary, tc.command, tc.environment)
				if got != tc.want {
					t.Errorf("decision=%q want=%q command=%q", got, tc.want, tc.command)
				}
			})
		}
	}
}
