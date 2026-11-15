// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// TestWorkingFolderResolvesRelativeOperandsAfterACD pins the shape of the
// tracking (working_folder.go): which commands run in the folder a cd moved the
// call to, which run in the hook's folder, and which leave the folder unknown
// (then the operand keeps its resolution against the hook's folder, never a
// guess). Substrate-1:GAP-0327.
func TestWorkingFolderResolvesRelativeOperandsAfterACD(t *testing.T) {
	const cwd, home = "/work/proj", "/home/alice"
	for _, tc := range []struct {
		name, command string
		// want is the resolved write target of the last redirect or "" when
		// the call has no path fact for it.
		want string
	}{
		{"and", "cd .git/hooks && echo x > pre-push", "/work/proj/.git/hooks/pre-push"},
		{"semicolon", "cd .git/hooks; echo x > pre-push", "/work/proj/.git/hooks/pre-push"},
		{"newline", "cd .git/hooks\necho x > pre-push", "/work/proj/.git/hooks/pre-push"},
		{"two steps", "cd .git && cd hooks && echo x > pre-push", "/work/proj/.git/hooks/pre-push"},
		{"parent", "cd .. && echo x > f", "/work/f"},
		{"absolute", "cd /etc/cron.d && echo x > job", "/etc/cron.d/job"},
		{"absolute then relative", "cd /etc && cd cron.d && echo x > job", "/etc/cron.d/job"},
		{"home tilde", "cd ~ && echo x > .bashrc", "/home/alice/.bashrc"},
		{"home tilde folder", "cd ~/.ssh && echo x > authorized_keys", "/home/alice/.ssh/authorized_keys"},
		{"bare cd is home", "cd && echo x > .bashrc", "/home/alice/.bashrc"},
		{"home variable", "cd $HOME/.aws && echo x > credentials", "/home/alice/.aws/credentials"},
		{"pushd", "pushd .git/hooks && echo x > pre-push", "/work/proj/.git/hooks/pre-push"},
		{"option then folder", "cd -P .git/hooks && echo x > pre-push", "/work/proj/.git/hooks/pre-push"},
		{"subshell sees its cd", "(cd .git/hooks && echo x > pre-push)", "/work/proj/.git/hooks/pre-push"},
		{"subshell does not leak", "(cd .git/hooks); echo x > pre-push", "/work/proj/pre-push"},
		{"group leaks", "{ cd .git/hooks; }; echo x > pre-push", "/work/proj/.git/hooks/pre-push"},
		{"pipe does not leak", "cd .git/hooks | cat; echo x > pre-push", "/work/proj/pre-push"},
		{"background does not leak", "cd .git/hooks & echo x > pre-push", "/work/proj/pre-push"},
		{"or: unknown", "cd .git/hooks || true; echo x > pre-push", "/work/proj/pre-push"},
		{"if body: unknown", "if true; then cd .git/hooks; fi; echo x > pre-push", "/work/proj/pre-push"},
		{"variable target: unknown", "cd $X && echo x > pre-push", "/work/proj/pre-push"},
		{"glob target: unknown", "cd .git/h* && echo x > pre-push", "/work/proj/pre-push"},
		{"dash target: unknown", "cd - && echo x > pre-push", "/work/proj/pre-push"},
		{"popd: unknown", "popd && echo x > pre-push", "/work/proj/pre-push"},
		{"other user home: unknown", "cd ~bob && echo x > f", "/work/proj/f"},
		{"before the cd", "echo x > before && cd .git", "/work/proj/before"},
		{"absolute operand is untouched", "cd .git/hooks && echo x > /tmp/f", "/tmp/f"},
		{"no cd", "echo x > pre-push", "/work/proj/pre-push"},
		{"shell body inherits the cd", "cd .git/hooks && sh -c 'echo x > pre-push'", "/work/proj/.git/hooks/pre-push"},
		{"shell body then its own cd", "cd .git && bash -c 'cd hooks && echo x > pre-push'", "/work/proj/.git/hooks/pre-push"},
		{"shell body of an unknown folder", "cd $X && sh -c 'echo x > pre-push'", "/work/proj/pre-push"},
		{"shell body without a cd", "sh -c 'echo x > pre-push'", "/work/proj/pre-push"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "Bash", Command: tc.command, CWD: cwd, ActiveHome: home, DialectHint: DialectPOSIX})
			got := ""
			for _, path := range facts.Paths {
				if path.Access == PathAccessWrite || path.Access == PathAccessAppend {
					got = path.Resolved
				}
			}
			if got != tc.want {
				t.Errorf("%q: resolved write %q, want %q (%+v)", tc.command, got, tc.want, facts.Paths)
			}
		})
	}
}

// TestWorkingFolderStepBound: a chain past the bound leaves the folder unknown.
func TestWorkingFolderStepBound(t *testing.T) {
	command := ""
	for i := 0; i < maxWorkFolderSteps+2; i++ {
		command += "cd a && "
	}
	command += "echo x > f"
	facts := Analyze(Input{Tool: "Bash", Command: command, CWD: "/work", ActiveHome: "/home/alice", DialectHint: DialectPOSIX})
	for _, path := range facts.Paths {
		if path.Access == PathAccessWrite && path.Resolved != "/work/f" {
			t.Errorf("a chain past the bound resolved to %q, want the hook folder's /work/f", path.Resolved)
		}
	}
}

// TestWindowsWorkingFolderParity: the PowerShell and CMD dialects keep the same
// reading of a cd-first call as the POSIX one (windows_simple_commands.go
// tracks the folder for them): the operand after the folder change resolves in
// that folder, a move the reader cannot read leaves the hook's folder.
func TestWindowsWorkingFolderParity(t *testing.T) {
	const cwd, home = `C:\work\proj`, `C:\Users\alice`
	for _, tc := range []struct {
		name    string
		dialect Dialect
		command string
		want    string
	}{
		{"powershell set-location", DialectPowerShell, `Set-Location C:\Users\alice\.ssh; Add-Content authorized_keys 'k'`, `C:\Users\alice\.ssh\authorized_keys`},
		{"powershell cd alias", DialectPowerShell, `cd C:\Users\alice\.ssh; Add-Content authorized_keys 'k'`, `C:\Users\alice\.ssh\authorized_keys`},
		{"powershell push-location", DialectPowerShell, `Push-Location C:\Users\alice\.ssh; Add-Content authorized_keys 'k'`, `C:\Users\alice\.ssh\authorized_keys`},
		{"powershell relative step", DialectPowerShell, `Set-Location .git\hooks; Add-Content pre-push 'x'`, `C:\work\proj\.git\hooks\pre-push`},
		{"powershell no cd", DialectPowerShell, `Add-Content pre-push 'x'`, `C:\work\proj\pre-push`},
		{"cmd cd", DialectCMD, `cd /d C:\Users\alice\.ssh && echo k>> authorized_keys`, `C:\Users\alice\.ssh\authorized_keys`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "PowerShell", Command: tc.command, CWD: cwd, ActiveHome: home, DialectHint: tc.dialect})
			got := ""
			for _, path := range facts.Paths {
				if path.Access == PathAccessWrite || path.Access == PathAccessAppend {
					got = path.Resolved
				}
			}
			if !strings.EqualFold(strings.ReplaceAll(got, "/", `\`), tc.want) {
				t.Errorf("%q: resolved write %q, want %q (%+v)", tc.command, got, tc.want, facts.Paths)
			}
		})
	}
}

// TestWorkingFolderNeverPanics: every shape of statement the grammar allows,
// including the ones with no command of their own (a bare redirect), gets a
// reading: a panic in the tracking would be the call's internal parser
// failure, a block of every call that has such a statement.
func TestWorkingFolderNeverPanics(t *testing.T) {
	for _, command := range []string{
		"> out.txt", ">> out.txt; cd /x; echo y", "2>&1", "cd /x && > f", "{ > f; }", "( > f )", "if true; then > f; fi", "while false; do > f; done",
		"for i in 1; do > f; done", "case x in x) > f;; esac", "f() { > g; }; f", "time > f", "coproc { cd /x; }", "echo $(> f)", "cat <(> f)",
		"declare -a x=(1); > f", "let x=1; > f", "[[ -n x ]] && > f", "(( 1 )) || > f", "! > f", "> f &", "cd /x & > f", "cd /x | > f",
		"cd /x\n\n> f\n#c", "echo a > f <<EOF\nx\nEOF", "cd /x && > /dev/null 2>&1; echo ok",
	} {
		facts := Analyze(Input{Tool: "Bash", Command: command, CWD: "/work", ActiveHome: "/home/alice", DialectHint: DialectPOSIX})
		for _, issue := range facts.Parse.Issues {
			if issue == IssueInternalParserFailure {
				t.Errorf("%q: internal parser failure (a panic in the analysis)", command)
			}
		}
	}
}
