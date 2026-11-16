// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// reviewHP3Rows are the independent review rows of fix/r107-bd-hookparse3
// (IN-bd-hookparse3-REVIEW.md) for the 4-cell harness. want "" is a logged
// probe with no assertion.
var reviewHP3Rows = []struct{ name, command, want string }{
	// rel-1-0-6:GAP-0298: a loosening mode, a recursive chmod, a keys-file
	// operand, a redirect and a later writer keep blocking.
	{"0298-mkdir-m777", "mkdir -m 777 -p ~/.ssh", "block"},
	{"0298-mkdir-mode777", "mkdir --mode=777 ~/.ssh", "block"},
	{"0298-mkdir-m777-attached", "mkdir -m777 ~/.ssh", "block"},
	{"0298-mkdir-pm777", "mkdir -pm 777 ~/.ssh", "block"},
	{"0298-chmod-755", "chmod 755 ~/.ssh", "block"},
	{"0298-chmod-gow", "chmod go+w ~/.ssh", "block"},
	{"0298-chmod-two-operands", "chmod 700 ~/.ssh ~/.ssh/authorized_keys", "block"},
	{"0298-chmod-keylink", "chmod 700 ~/.ssh keylink", "block"},
	{"0298-chmod-R-after", "chmod 700 ~/.ssh -R", "block"},
	{"0298-chmod-R-before", "chmod -R 700 ~/.ssh", "block"},
	{"0298-chmod-recursive", "chmod --recursive 700 ~/.ssh", "block"},
	{"0298-chmod-vR", "chmod -vR 700 ~/.ssh", "block"},
	{"0298-chmod-keys-600", "chmod 600 ~/.ssh/authorized_keys", "block"},
	{"0298-chmod-keys-after-setup", "chmod 700 ~/.ssh && chmod 666 ~/.ssh/authorized_keys", "block"},
	{"0298-mkdir-two-operands", "mkdir -p ~/.ssh ~/.ssh/authorized_keys", "block"},
	{"0298-mkdir-redirect-keys", "mkdir -p ~/.ssh > ~/.ssh/authorized_keys", "block"},
	{"0298-chmod-stderr-keys", "chmod 700 ~/.ssh 2>> ~/.ssh/authorized_keys", "block"},
	{"0298-setup-then-link-append", "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat a.txt >> keylink", "block"},
	{"0298-setup-then-tee", "mkdir -p ~/.ssh && cat a.txt | tee -a keylink", "block"},
	{"0298-setup-then-ln", "mkdir -p ~/.ssh && ln -sf ~/project/a.txt ~/.ssh/authorized_keys", "block"},
	{"0298-setup-subshell-write", "mkdir -p ~/.ssh && (cat a.txt >> keylink)", "block"},
	{"0298-chmod-sshlink-keys", "chmod 700 sshlink/authorized_keys", "block"},
	{"0298-mkdir-dotdot", "mkdir -p ~/.ssh/authorized_keys/..", "block"},
	{"0298-mkdir-dot", "mkdir -p ~/.ssh/.", "block"},
	{"0298-allow-var", "d=~/.ssh; mkdir -p $d && chmod 700 $d", ""},
	{"0298-allow-setup", "mkdir -p ~/.ssh && chmod 700 ~/.ssh", "allow"},
	// rel-1-0-4:GAP-2590: a removal that reaches the keys file, or a link
	// re-created and then written, keeps blocking.
	{"2590-recreate-append", "rm keylink && ln -s ../.ssh/authorized_keys keylink && cat a.txt >> keylink", "block"},
	{"2590-recreate-home", "rm keylink; ln -s \"$HOME/.ssh/authorized_keys\" keylink; ls keylink", "block"},
	{"2590-sort-o-after", "ls keylink && rm keylink && sort -o keylink a.txt", "block"},
	{"2590-tee-after", "rm keylink && tee -a keylink < a.txt", "block"},
	{"2590-rm-keys-through-dirlink", "ls keylink && rm sshlink/authorized_keys", "block"},
	{"2590-cp-after", "cat keylink && rm keylink && cp a.txt sshlink/authorized_keys", "block"},
	{"2590-mv-after", "rm keylink; mv a.txt sshlink/authorized_keys", "block"},
	{"2590-uniq-before", "uniq a.txt keylink && rm keylink", "block"},
	{"2590-group-append", "{ ls keylink; rm keylink; } && cat a.txt >> keylink", "block"},
	{"2590-rm-f-keys", "rm -f keylink sshlink/authorized_keys", "block"},
	{"2590-find-delete", "ls keylink && rm keylink && find sshlink/ -name authorized_keys -delete", "block"},
	{"2590-allow-live-form", "ls -l keylink && rm keylink && ls keylink; echo done", "allow"},
	// rel-1-0-2:GAP-0409 and rel-1-0-6:GAP-0255: values the client tracker
	// now reads, and the names it drops.
	{"0409-echo-brace", "f=$(echo {keylink,}); echo m >> \"$f\"", "block"},
	{"0409-echo-brace-bare", "echo m >> $(echo {keylink,})", "block"},
	{"0409-echo-quoted-glob", "f=$(echo \x27keyl*\x27); echo m >> $f", "block"},
	{"0409-assign-quoted-glob", "f=\x27keyl*\x27; echo m >> $f", "block"},
	{"0409-eval-true", "f=keylink; eval true; echo m >> \"$f\"", "block"},
	{"0409-subshell", "f=keylink; (f=x); echo m >> \"$f\"", "block"},
	{"0409-and-false", "f=keylink; false && f=x; echo m >> \"$f\"", "block"},
	{"0409-if-false", "f=keylink; if false; then f=x; fi; echo m >> \"$f\"", "block"},
	{"0409-echo-e", "f=$(echo -e keylink); echo m >> \"$f\"", "block"},
	{"0409-echo-n", "f=$(echo -n keylink); echo m >> \"$f\"", "block"},
	{"0409-eval-concat", "eval \"f=key\"\"link\"; echo m >> \"$f\"", "block"},
	{"0409-eval-two", "eval f=x f=keylink; echo m >> \"$f\"", "block"},
	{"0409-test-and", "f=keylink; [ -n \"$X\" ] && f=x; echo m >> \"$f\"", "block"},
	{"0409-case", "f=keylink; case $X in y) f=x;; esac; echo m >> \"$f\"", "block"},
	{"0409-while-false", "f=keylink; while false; do f=x; done; echo m >> \"$f\"", "block"},
	{"0409-if-unset-plain", "f=keylink; if false; then unset f; fi; echo m >> \"$f\"", "block"},
	{"0298-mkdir-pm777-attached", "mkdir -pm777 ~/.ssh", "block"},
	{"0233-brace-cap-touch", "touch ../.ssh/authorized_key{s,{1..300}}", "block"},
	{"0233-brace-cap-touch-home", "touch ~/.ssh/authorized_key{s,{1..300}}", "block"},
	{"0233-brace-cap-tee", "tee ../.ssh/authorized_key{s,{1..300}} < a.txt", "block"},
	{"0233-brace-cap-tee-home", "echo k | tee -a ~/.ssh/authorized_key{s,{1..300}}", "block"},
	{"0233-brace-cap-tee-link", "cat a.txt | tee -a key{link,{1..300}}", "block"},
	{"0233-brace-redirect-one", "echo m >> {keylink,}", "block"},
	{"0409-eval-tilde", "eval f=~/.ssh/authorized_keys; echo m >> \"$f\"", "block"},
	{"0409-eval-tilde-link", "eval f=~/project/keylink; echo m >> \"$f\"", "block"},
	{"0310-escaped-semicolon", "pwsh -Command Get-ChildItem ~/.ssh \\; Add-Content ~/.ssh/authorized_keys k", "block"},
	{"0310-quoted-semicolon-set", "pwsh -Command Get-ChildItem ~/.ssh \";\" Set-Content ~/.ssh/authorized_keys k", "block"},
	{"0310-quoted-pipe-remove", "pwsh -Command Get-ChildItem ~/.ssh/authorized_keys \"|\" Remove-Item", "block"},
	{"0310-quoted-pipe-clear", "pwsh -Command Get-Item ~/.ssh/authorized_keys \"|\" Clear-Content", "block"},
	{"0310-split-out-file", "pwsh -c Get-ChildItem ~/.ssh \"|\" Out-File ~/.ssh/authorized_keys", "block"},
	{"0310-split-andand", "pwsh -Command ls ~/.ssh \"&&\" Add-Content ~/.ssh/authorized_keys k", "block"},
	{"0310-split-paren", "pwsh -Command Test-Path \"(Set-Content ~/.ssh/authorized_keys k)\"", "block"},
	{"0310-split-subexpr", "pwsh -Command Get-ChildItem ~/.ssh -Filter \x27$(Set-Content ~/.ssh/authorized_keys k)\x27", "block"},
	{"0310-split-iex", "pwsh -Command Get-ChildItem ~/.ssh \";\" iex k", "block"},
	{"0310-split-link-writer", "pwsh -Command Get-ChildItem keylink \";\" Add-Content keylink k", "block"},
	{"0310-glob-word", "pwsh -Command Get-ChildItem ~/.ssh/*", "block"},
	{"0310-var-word", "pwsh -Command Get-ChildItem $D/.ssh", ""},
	{"0310-subst-word", "pwsh -Command Get-ChildItem $(echo ~/.ssh)", "block"},
	{"0310-brace-word", "pwsh -Command Get-ChildItem ~/.ssh/{a,b}", "block"},
	{"0310-backtick-word", "pwsh -Command Get-ChildItem `echo ~/.ssh`", "block"},
	{"0310-unknown-var-last", "pwsh -Command Get-ChildItem ~/.ssh $X", "block"},
	{"0310-quoted-glob", "pwsh -Command Get-ChildItem \x27~/.ssh/*\x27", "allow"},
	{"0310-allow-split", "pwsh -Command Get-ChildItem ~/.ssh", "allow"},
	// Round 2 rows (kept candidate through a compound statement or eval).
	{"r2-0298-mkdir-dotdot-var", "d=$HOME/.ssh/authorized_keys/..; mkdir -p \"$d\"", "block"},
	{"r2-0409-cp-operand-if-false", "f=keylink; if false; then f=x; fi; cp a.txt \"$f\"", "block"},
	{"r2-0409-tee-operand-if-false", "f=keylink; if false; then f=x; fi; cat a.txt | tee -a \"$f\"", "block"},
	{"r2-0409-if-true-inner-value", "f=x; if true; then f=keylink; fi; echo m >> \"$f\"", "block"},
	{"r2-0409-group-inner-value", "f=x; { f=keylink; }; echo m >> \"$f\"", "block"},
	{"r2-0409-if-unknown-inner-value", "f=x; if [ -n \"$X\" ]; then f=keylink; fi; echo m >> \"$f\"", "block"},
	{"r2-0409-eval-prefix-static", "eval f=keylink $X; echo m >> \"$f\"", "block"},
	{"r2-0409-unset-default", "f=a.txt; if true; then unset f; fi; echo m >> \"${f:-keylink}\"", "block"},
	{"r2-0409-allow-if-false-other", "f=a.txt; if false; then f=x; fi; echo m >> \"$f\"", "allow"},
	// Logged: claudecode managed blocks it on base b3547e66a9 too (a benign
	// false block, not a hole); the other three cells allow.
	{"r2-0409-allow-eval-true-other", "f=a.txt; eval true; echo m >> \"$f\"", ""},
	{"0409-echo-two-words", "f=$(echo keylink x); echo m >> \"$f\"", ""},
}

// reviewHP3PreExisting are review rows red on base b3547e66a9 too, filed as
// their own gaps for r107-bd-hookparse4; each cell they name is logged, not
// asserted, until that gap is fixed (managed only where the per-user cell
// already blocks).
var reviewHP3PreExisting = map[string]struct {
	gap         string
	managedOnly bool
}{
	"0409-assign-quoted-glob":      {"rel-1-0-6:GAP-0311", false},
	"0409-echo-quoted-glob":        {"rel-1-0-6:GAP-0311", false},
	"0409-echo-e":                  {"rel-1-0-6:GAP-0312", true},
	"0409-echo-brace":              {"rel-1-0-6:GAP-0312", true},
	"0409-echo-brace-bare":         {"rel-1-0-6:GAP-0312", true},
	"0233-brace-redirect-one":      {"rel-1-0-6:GAP-0312", true},
	"0310-split-link-writer":       {"rel-1-0-6:GAP-0313", true},
	"2590-rm-keys-through-dirlink": {"rel-1-0-6:GAP-0314", true},
	"2590-rm-f-keys":               {"rel-1-0-6:GAP-0314", true},
	"2590-find-delete":             {"rel-1-0-6:GAP-0314", true},
	"0298-chmod-sshlink-keys":      {"rel-1-0-6:GAP-0314", true},
	"0233-brace-cap-touch":         {"rel-1-0-6:GAP-0315", false},
	"0233-brace-cap-touch-home":    {"rel-1-0-6:GAP-0315", false},
}

// TestReviewHP3FourCell runs reviewHP3Rows on claudecode and codex,
// managed and per-user, with the fixture decoy keys file, the project
// keylink and an sshlink to the .ssh folder; the decoy must not change.
func TestReviewHP3FourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.Symlink("../.ssh", filepath.Join(f.project, "sshlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "a.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, row := range reviewHP3Rows {
		payload := f.payload(t, row.command)
		header := f.clientHeader(t, payload)
		for _, call := range everyMode(row.name, payload, header) {
			mode := os.FileMode(0o700)
			if call.managed {
				mode = 0
			}
			if err := os.Chmod(f.homes, mode); err != nil {
				t.Fatal(err)
			}
			call.verdict, call.body = f.serve(call)
			t.Logf("HP3ROW %s | %s | want %s", call.name, call.verdict, row.want)
			if pre, ok := reviewHP3PreExisting[row.name]; ok && (call.managed || !pre.managedOnly) {
				if call.verdict != row.want {
					t.Logf("HP3ROW %s: pre-existing %s, logged", call.name, pre.gap)
				}
				continue
			}
			if row.want != "" && call.verdict != row.want {
				t.Errorf("%s: verdict %s, want %s; body %.160s", call.name, call.verdict, row.want, call.body)
			}
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}
