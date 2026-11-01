// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// GAP-2089 (review RV4-1, regression of the GAP-1535 uncalled-function
// rule): bash evaluates strings in arithmetic contexts, subscripts, prompt
// expansion and the builtins that take a variable name or a callback, and a
// subscript such as a[$(f""oo)] runs a command substitution that calls the
// function under a name the command never spells. Such a command keeps every
// function body checked; plain $name expansions still leave an uncalled body
// unscanned (GAP-1535).
func TestActionRuntimeEvaluatedNameKeepsFunctionBodyChecked(t *testing.T) {
	home := t.TempDir()
	cwd := home
	body := "foo() { dd of=~/.ssh/authorized_keys if=k.pub; }; "
	for _, call := range []string{
		`a=f; b=oo; mapfile -t -c 1 -C "$a$b" arr <<< x`,
		`x='a[$(f""oo)]'; : $((x))`,
		`x='$(f""oo)'; echo "${x@P}"`,
		`PS4='$(f""oo)'; set -x; true`,
		`let 'a[$(f""oo)]'`,
		`[[ 'a[$(f""oo)]' -eq 0 ]]`,
		`declare -i n; n='a[$(f""oo)]'`,
		`printf -v 'a[$(f""oo)]' x`,
		`test -v 'a[$(f""oo)]'`,
		`read -r n < name.txt; mapfile -t -c 1 -C "$n" arr <<< x`,
		`x='a[$(f""oo)]'; echo "${b[x]}"`,
		`n='a[$(f""oo)]'; echo "${!n}"`,
		`x='a[$(f""oo)]'; b[x]=1`,
		`builtin mapfile -C f""oo -c 1 arr <<< x`,
		`for ((i='a[$(f""oo)]'; i < 1; i++)); do :; done`,
		// zsh (the macOS agent shell) calls the function from a glob
		// qualifier, prompt expansion or a zstyle -e value (RV5-1).
		`print -l *(e:f""oo:)`,
		`print -l *(+f""oo)`,
		`setopt promptsubst; print -P '$(f""oo)'`,
		`print -rP -- 'x'`,
		`zstyle -e ':x:*' y 'reply=(f""oo)'`,
		`PROMPT='$(f""oo)'`,
		// A zsh glob-subst expansion runs the qualifier held in a
		// string (RV6-1).
		`p='*(e:f""oo:)'; print -l $~p`,
		`p='*(e:f""oo:)'; ls $~p`,
		`p='*(+f""oo)'; ls $~p`,
		`p='*(e:f""oo:)'; ls ${~p}`,
		`p='*(.e:f""oo:)'; print -l ${(~)p}`,
	} {
		command := body + call
		if got := posixShellDecision(command, cwd, home); got == "" {
			t.Errorf("posixShellDecision(%q) = allow, want a protected decision", command)
		}
	}
	for _, call := range []string{
		"echo ok",
		`n=3; echo "$n" "${n:-0}" "$@"`,
		`printf '%s\n' done; echo "${PWD}"`,
		`for f in a b; do echo "$f"; done`,
		`print -l -- a b`,
		`print -r -- done`,
		`p='notes (draft).md'; echo "$p"`,
		`ls *.go; echo "see (e.g. README)"`,
	} {
		if got := posixShellDecision(body+call, cwd, home); got != "" {
			t.Errorf("posixShellDecision(%q) = %q, want allow", body+call, got)
		}
	}
}
