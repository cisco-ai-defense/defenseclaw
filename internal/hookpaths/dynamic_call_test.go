// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// Classifier refix round 1 (RV3-2, regression of GAP-1535): a function body
// is skipped as uncalled only when every program word of the command is
// static and nothing (eval, source, a quoted trap handler) can call it under
// another spelling. A call through a built, escaped, indirect or run-time
// name keeps the protected write in the body a target.
func TestActionDynamicCallKeepsFunctionBodyChecked(t *testing.T) {
	home := t.TempDir()
	cwd := home
	// Writers whose operand roles only the mention scan reads.
	for _, writer := range []string{
		"dd of=~/.ssh/authorized_keys if=k.pub",
		"rsync k.pub ~/.ssh/authorized_keys",
		"mytool --out ~/.ssh/authorized_keys",
	} {
		body := "foo() { " + writer + "; }; "
		for _, call := range []string{
			`a=f; b=oo; "$a$b"`,
			`p=fo; "${p}o"`,
			`f\oo`,
			`fo""o`,
			`fo''o x`,
			`a=f; b=oo; x=$a$b; n=x; "${!n}"`,
			`$(printf 'f%s' oo)`,
			"`printf 'f%s' oo`",
			`read -r n < name.txt; "$n"`,
			`eval "$(printf 'f%s' oo)"`,
			`. ./run.sh`,
			`source ./run.sh`,
			`trap 'f""oo' EXIT`,
			`trap "f\oo" EXIT`,
			`n=foo; export -f "$n"; bash -c "$n"`,
			`echo ok; for n in fo; do "${n}o"; done`,
		} {
			command := body + call
			if got := posixShellDecision(command, cwd, home); got == "" {
				t.Errorf("posixShellDecision(%q) = allow, want a protected decision", command)
			}
		}
		// Benign: every program word static, the body never called (GAP-1535).
		for _, call := range []string{
			"echo ok",
			`main() { echo hi; }; main "$@"`,
			`echo "$HOME"; printf '%s\n' done`,
			`trap 'rm -f tmp.txt' EXIT; echo ok`,
		} {
			if got := posixShellDecision(body+call, cwd, home); got != "" {
				t.Errorf("posixShellDecision(%q) = %q, want allow", body+call, got)
			}
		}
	}
}
