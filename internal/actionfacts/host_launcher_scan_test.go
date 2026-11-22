// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

// launcherCall is the launcher call every row below runs or carries.
const launcherCall = "powershell -EncodedCommand QQBBQQBB"

// TestHostLauncherScreenReadsTheShellGrammar (rel-1-0-10:GAP-0740): the screen of a
// call past the input bound finds a launcher by the shell's own reading of the
// text, by the id of the review variant that left it a clean allow.
func TestHostLauncherScreenReadsTheShellGrammar(t *testing.T) {
	pad := strings.Repeat("a", 100000)
	for _, test := range []struct{ id, text string }{
		{"space-path-dq", `"C:\Program Files\PowerShell\7\pwsh.exe" -enc QQBB`},
		{"space-path-sq", `'C:\Program Files\PowerShell\7\pwsh.exe' -enc QQBB`},
		{"space-path-unix", `"/mnt/c/Program Files/PowerShell/7/pwsh.exe" -enc QQBB`},
		{"path-unquoted", `C:\Windows\System32\WindowsPowerShell\v1.0\` + launcherCall},
		{"env-flag", "env -i " + launcherCall},
		{"env-assign", "env X=1 " + launcherCall},
		{"env-split-string", `env -S "` + launcherCall + `"`},
		{"sudo-flag", "sudo -u root " + launcherCall},
		{"timeout", "timeout 60 " + launcherCall},
		{"timeout-flag", "timeout -k 5 60 " + launcherCall},
		{"nice", "nice -n 10 " + launcherCall},
		{"nohup-chain", "nohup sudo env X=1 " + launcherCall},
		{"redirect-lead", ">/dev/null 2>&1 " + launcherCall},
		{"redirect-lead-spaced", "2>&1 > out.txt " + launcherCall},
		{"xargs", "echo x | xargs " + launcherCall},
		{"start-title", `start "" ` + launcherCall},
		{"start-titled", `start "Title" /wait ` + launcherCall},
		{"wsl", "wsl.exe " + launcherCall},
		{"wsl-e", "wsl -e " + launcherCall},
		{"wsl-d-e", "wsl -d Ubuntu -e " + launcherCall},
		{"split-quote", `pow""ershell -EncodedCommand QQBB`},
		{"cr-lead", "echo a\r" + launcherCall},
		{"lead-dollarsq", `echo $'a\'b'; ` + launcherCall},
		{"lead-aposdq", `echo "it's"; ` + launcherCall},
		{"lead-dqinsq", `echo 'say "hi"'; ` + launcherCall},
		{"lead-escapos", `echo it\'s; ` + launcherCall},
		{"lead-comment", "echo a # it's\n" + launcherCall},
		{"if-then", "if true; then " + launcherCall + "; fi"},
		{"braces", "{ " + launcherCall + "; }"},
		{"subshell", "(" + launcherCall + ")"},
		{"substitution", "echo $(" + launcherCall + ")"},
		{"backtick", "echo `" + launcherCall + "`"},
		{"bash-c-sq", "bash -c '" + launcherCall + "'"},
		{"bash-lc-dq", `bash -lc "` + launcherCall + `"`},
		{"sh-o-c", "sh -o pipefail -c '" + launcherCall + "'"},
		{"sudo-bash-c", "sudo -E bash -c '" + launcherCall + "'"},
		{"eval-dq", `eval "` + launcherCall + `"`},
		{"bash-c-nested", `bash -c 'sh -c "` + launcherCall + `"'`},
		{"big-bash-bashc", "bash -c '" + pad + "; " + launcherCall + "'"},
		{"big-bash-bashc-lead", "echo " + pad + "; bash -c '" + launcherCall + "'"},
		{"cmd-c", "cmd /c echo hi"},
	} {
		if !hostLauncherMention(test.text) {
			t.Errorf("%s: the screen does not name the launcher", test.id)
		}
	}
}

// TestHostLauncherScreenKeepsDataQuotesOut: the launcher word in the data of
// another command stays out (the benign alerts of rel-1-0-10:GAP-0608), twins of
// the rows above that a careful developer runs.
func TestHostLauncherScreenKeepsDataQuotesOut(t *testing.T) {
	for _, test := range []struct{ id, text string }{
		{"ssh-dq", `ssh host "` + launcherCall + `"`},
		{"ssh-sq", `ssh -o BatchMode=yes host '` + launcherCall + `'`},
		{"ssh-after-flags", `ssh -t -p 22 host "powershell -Command Get-Date"`},
		{"sudo-ssh", `sudo -u deploy ssh host "` + launcherCall + `"`},
		{"commit-message", `git commit -m "fix; pwsh tests"`},
		{"echo-message", `echo "run cmd /c dir" | tee log.txt`},
		{"echo-launcher-arg", "echo powershell is installed"},
		{"go-cmd-dir", "go build ./cmd/... && ls cmd"},
		{"sudo-ls-cmd", "sudo ls cmd"},
		{"cd-cmd", "cd cmd; ls"},
		{"which", "which powershell pwsh cmd"},
		{"command-v", "command -v pwsh"},
		{"comment", "ls # then run powershell here\nls"},
		{"bash-c-ssh", `bash -c 'ssh host "` + launcherCall + `"'`},
		{"bash-c-echo", "bash -c 'echo cmd'"},
		{"bash-script-arg", "bash run.sh powershell"},
		{"grep-pattern", `grep -r "cmd" .`},
		{"cmdkey", "cmdkey /list"},
		{"user-named", "sudo -u cmdr ls"},
	} {
		if hostLauncherMention(test.text) {
			t.Errorf("%s: the screen names a launcher in data", test.id)
		}
	}
}

// TestTruncatedHostCallReadsArgvShellScripts (rel-1-0-10:GAP-0741): an argv, and a
// JSON array command, that carries a launcher in the script of a local shell
// -c (or behind a wrapper) is a host call past the bound, as one whose word is
// the launcher is.
func TestTruncatedHostCallReadsArgvShellScripts(t *testing.T) {
	words := strings.Fields(launcherCall)
	for _, test := range []struct {
		id   string
		argv []string
		want bool
	}{
		{"argv-bash-lc", []string{"bash", "-lc", launcherCall}, true},
		{"argv-sh-c", []string{"sh", "-c", launcherCall}, true},
		{"argv-env-sh-c", []string{"env", "X=1", "sh", "-c", launcherCall}, true},
		{"argv-sudo-bash-c-lead", []string{"sudo", "-E", "bash", "-c", "echo a; " + launcherCall}, true},
		{"argv-direct", words, true},
		{"argv-cmd-c", append([]string{"cmd", "/c"}, words...), true},
		{"argv-bash-lc-ssh", []string{"bash", "-lc", `ssh host "` + launcherCall + `"`}, false},
		{"argv-bash-lc-echo", []string{"bash", "-lc", "echo hello"}, false},
		{"argv-git", []string{"git", "status"}, false},
		{"argv-bash-script", []string{"bash", "run.sh", "--flag"}, false},
	} {
		if got := TruncatedHostCall(Input{Tool: "Bash", Argv: test.argv}); got != test.want {
			t.Errorf("%s as argv: TruncatedHostCall = %v, want %v", test.id, got, test.want)
		}
		args, err := json.Marshal(map[string]any{"command": test.argv})
		if err != nil {
			t.Fatal(err)
		}
		if got := TruncatedHostCall(Input{Tool: "Bash", Args: args}); got != test.want {
			t.Errorf("%s as an array command: TruncatedHostCall = %v, want %v", test.id, got, test.want)
		}
	}
}

// TestHostLauncherScreenBoundsItsReading: scripts nested deeper than the screen
// follows count as naming a launcher (the one bound rule), the reading stays
// linear on a text of unbalanced quotes, and an unreadable text still gets the
// pattern screen.
func TestHostLauncherScreenBoundsItsReading(t *testing.T) {
	deep := "echo hi"
	for range maxLauncherScriptDepth + 2 {
		deep = "bash -c '" + strings.ReplaceAll(deep, "'", `'\''`) + "'"
	}
	if !hostLauncherMention(deep) {
		t.Error("a script nested past the depth is read as naming no launcher")
	}
	if hostLauncherMention("bash -c 'echo hi'") {
		t.Error("one script level names a launcher")
	}
	for _, text := range []string{
		strings.Repeat(`'"`, 200000),
		strings.Repeat("echo it's ", 50000),
		strings.Repeat("`", 100001),
		strings.Repeat("$(", 50000),
	} {
		hostLauncherMention(text)
	}
	// A text the reading cannot follow names a launcher at any command
	// position, quoted or not; one with none names nothing.
	for id, text := range map[string]string{
		"unterminated-quote":   "echo 'unterminated; " + launcherCall,
		"process-substitution": "cat <(ls); " + launcherCall,
		"arithmetic":           "echo $((1+2)); " + launcherCall,
	} {
		if !hostLauncherMention(text) {
			t.Errorf("%s: an unreadable text with a launcher names none", id)
		}
	}
	for id, text := range map[string]string{
		"arithmetic-benign":   "echo $((1+2)); ls cmd",
		"unterminated-benign": "echo 'unterminated; ls",
		"unread-ssh-quote":    `echo $((1+2)); ssh host "` + launcherCall + `"`,
	} {
		if hostLauncherMention(text) {
			t.Errorf("%s: an unreadable text with no launcher names one", id)
		}
	}
}
