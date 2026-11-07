// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A protected name with literal braces (a pair without a comma or a sequence
// is not brace-expanded) reaches a function as it is typed: unquoted, with
// the braces escaped, or next to a quoted known value. The ordinary twin
// stays allowed.
func TestOpenClawOutageLiteralBraceNameReachesAFunctionWhole(t *testing.T) {
	root, protected, ordinary := outageR10Fixture(t, "home{one}")
	braceLink := filepath.Join(ordinary, "config{link}")
	if err := os.Symlink(protected, braceLink); err != nil {
		t.Fatal(err)
	}
	braceOrdinary := filepath.Join(ordinary, "notes{link}")
	if err := os.Symlink(filepath.Join(ordinary, "notes.txt"), braceOrdinary); err != nil {
		t.Fatal(err)
	}
	escape := func(name string) string { return strings.NewReplacer("{", `\{`, "}", `\}`).Replace(name) }
	base := filepath.Dir(filepath.Dir(root))
	tail := strings.TrimPrefix(protected, base)
	take := `f() { OUT="$1"; }; `
	cases := []struct {
		name, command, want string
		environment         map[string]interface{}
	}{
		{"literal file", take + `f ` + protected + `; rm "$OUT"`, "protected", nil},
		{"literal link", take + `f ` + braceLink + `; rm "$OUT"`, "protected", nil},
		{"escaped braces in a file", take + `f ` + escape(protected) + `; rm "$OUT"`, "protected", nil},
		{"escaped braces in a link", take + `f ` + escape(braceLink) + `; rm "$OUT"`, "protected", nil},
		{"quoted known value then literal braces", take + `f "$BASE"` + tail + `; rm "$OUT"`, "protected", map[string]interface{}{"BASE": base}},
		{"second parameter", `f() { OUT="$2"; }; f x ` + protected + `; rm "$OUT"`, "protected", nil},
		{"quoted file", take + `f "` + protected + `"; rm "$OUT"`, "protected", nil},
		{"direct literal file", `rm ` + protected, "protected", nil},
		{"literal ordinary link", take + `f ` + braceOrdinary + `; rm "$OUT"`, "open", nil},
		{"escaped ordinary link", take + `f ` + escape(braceOrdinary) + `; rm "$OUT"`, "open", nil},
		{"quoted known value then literal braces, ordinary", take + `f "$BASE"/notes{link}; rm "$OUT"`, "open", map[string]interface{}{"BASE": ordinary}},
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

// unset removes a function only without -v or -n (or with -f), and a function
// named unset runs in its place. An ordinary unset of a variable leaves the
// function named eval in the builtin place; a removed function gives the name
// back.
func TestOpenClawOutageUnsetRemovesAFunctionOnlyWhenItDoes(t *testing.T) {
	guard := `; if true; then :; else rm "$OUT"; fi`
	run := ` ` + outageBad + guard
	outageR12Run(t, outageQuoted([]outageR12Case{
		{"unset of a variable", `eval() { :; }; unset -v eval;` + run, "open"},
		{"unset of a variable by builtin", `eval() { :; }; builtin unset -v eval;` + run, "open"},
		{"unset of a variable by command", `eval() { :; }; command unset -v eval;` + run, "open"},
		{"unset of a nameref", `eval() { :; }; unset -n eval;` + run, "open"},
		{"unset of a variable after the end of options", `eval() { :; }; unset -v -- eval;` + run, "open"},
		{"unset of another function", `eval() { :; }; unset -f other;` + run, "open"},
		{"function named unset", `unset() { :; }; eval() { :; }; unset -f eval;` + run, "open"},
		{"function named unset in a block", `{ unset() { :; }; }; eval() { :; }; unset -f eval;` + run, "open"},
		{"unset of the function", `eval() { :; }; unset -f eval;` + run, "protected"},
		{"unset without an option", `eval() { :; }; unset eval;` + run, "protected"},
		{"unset of the function after the end of options", `eval() { :; }; unset -f -- eval;` + run, "protected"},
		{"unset of the function by builtin", `eval() { :; }; builtin unset -f eval;` + run, "protected"},
		{"unset of the function by command", `eval() { :; }; command unset -f eval;` + run, "protected"},
		{"unset of a computed name", `eval() { :; }; unset -f "$X";` + run, "protected"},
		{"unset of a computed name without an option", `eval() { :; }; unset "$X";` + run, "protected"},
		{"function named unset that removes the function", `unset() { builtin unset -f eval; }; eval() { :; }; unset;` + run, "protected"},
		{"function named unset that may not exist", `if [ -n "$X" ]; then unset() { :; }; fi; eval() { :; }; unset -f eval;` + run, "protected"},
	}), func(protected string) map[string]interface{} { return map[string]interface{}{"OUT": protected} })
}

// A loop over a fixed list that redefines a function in straight-line order
// replaces it, whatever other functions the command has: a loop control or a
// command the reader cannot name ends a pass early only in a function the
// loop can call, and a return only leaves its own function.
func TestOpenClawOutageFixedLoopReplacementIgnoresFunctionsItCannotCall(t *testing.T) {
	old := "f() { " + outageBad + "; }; "
	loop := `for x in a; do f() { :; }; done; f; if true; then :; else rm "$OUT"; fi`
	called := `for x in a; do g; f() { :; }; done; f; if true; then :; else rm "$OUT"; fi`
	outageR12Run(t, outageQuoted([]outageR12Case{
		{"loop alone", old + loop, "open"},
		{"unused function that returns", old + `unused() { return; }; ` + loop, "open"},
		{"unused function that breaks", old + `unused() { break; }; ` + loop, "open"},
		{"unused function that continues", old + `unused() { continue; }; ` + loop, "open"},
		{"unused function with a computed command", old + `unused() { $X; }; ` + loop, "open"},
		{"unused function with a loop of its own", old + `unused() { for y in a; do break; done; }; ` + loop, "open"},
		{"called function that returns", old + `g() { return; }; ` + called, "open"},
		{"called function that returns a status", old + `g() { return 1; }; ` + called, "open"},
		{"called function of a plain command", old + `g() { :; }; ` + called, "open"},
		{"called function that breaks", old + `g() { break; }; ` + called, "protected"},
		{"called function that continues", old + `g() { continue; }; ` + called, "protected"},
		{"called function with a computed command", old + `g() { $X; }; ` + called, "protected"},
		{"function that calls a function that breaks", old + `h() { break; }; g() { h; }; ` + called, "protected"},
		{"function that calls a function that returns", old + `h() { return; }; g() { h; }; ` + called, "open"},
		{"function called through eval that breaks", old + `g() { break; }; for x in a; do eval g; f() { :; }; done; f; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"loop with a computed command and a function that breaks", old + `unused() { break; }; for x in a; do $X; f() { :; }; done; f; if true; then :; else rm "$OUT"; fi`, "protected"},
		{"loop that breaks itself", old + `for x in a; do if [ -n "$X" ]; then break; fi; f() { :; }; done; f; if true; then :; else rm "$OUT"; fi`, "protected"},
	}), func(protected string) map[string]interface{} { return map[string]interface{}{"OUT": protected} })
}
