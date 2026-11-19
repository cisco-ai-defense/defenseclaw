// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// TestWorkingFolderResolvesRelativeOperandsAfterACD pins the shape of the
// tracking (working_folder.go): the folders each command may run in. A move
// counts alone only where it is proven to have run and worked (the right side
// of `cd X &&`, the then-branch of `if cd X`); after a cd that may fail or not
// run (`;`, a newline, `false && cd X;`, `|| cd X`, a branch) the operand is
// read in the folder before the move AND in the moved one, so the strongest
// reading decides (substrate-1:GAP-0327, rel-1-0-10:GAP-0869). A folder the
// call does not give keeps the hook folder's reading and is marked unresolved
// (rel-1-0-10:GAP-0871).
func TestWorkingFolderResolvesRelativeOperandsAfterACD(t *testing.T) {
	const cwd, home = "/work/proj", "/home/alice"
	const hooks, top = "/work/proj/.git/hooks/pre-push", "/work/proj/pre-push"
	for _, tc := range []struct {
		name, command string
		// want are the resolved write targets of the call, in any order.
		want []string
		// unresolved: a write target sits in a folder the call does not give.
		unresolved bool
	}{
		{"and", "cd .git/hooks && echo x > pre-push", []string{hooks}, false},
		{"semicolon: the cd may fail", "cd .git/hooks; echo x > pre-push", []string{top, hooks}, false},
		{"newline: the cd may fail", "cd .git/hooks\necho x > pre-push", []string{top, hooks}, false},
		{"two steps", "cd .git && cd hooks && echo x > pre-push", []string{hooks}, false},
		{"parent", "cd .. && echo x > f", []string{"/work/f"}, false},
		{"absolute", "cd /etc/cron.d && echo x > job", []string{"/etc/cron.d/job"}, false},
		{"absolute then relative", "cd /etc && cd cron.d && echo x > job", []string{"/etc/cron.d/job"}, false},
		{"missing folder then ;", "cd /nonexistent; echo x > f", []string{"/work/proj/f", "/nonexistent/f"}, false},
		{"home tilde", "cd ~ && echo x > .bashrc", []string{"/home/alice/.bashrc"}, false},
		{"home tilde folder", "cd ~/.ssh && echo x > authorized_keys", []string{"/home/alice/.ssh/authorized_keys"}, false},
		{"bare cd is home", "cd && echo x > .bashrc", []string{"/home/alice/.bashrc"}, false},
		{"home variable", "cd $HOME/.aws && echo x > credentials", []string{"/home/alice/.aws/credentials"}, false},
		{"pushd", "pushd .git/hooks && echo x > pre-push", []string{hooks}, false},
		{"builtin cd", "builtin cd .git/hooks && echo x > pre-push", []string{hooks}, false},
		{"option then folder", "cd -P .git/hooks && echo x > pre-push", []string{hooks}, false},
		{"cdpath on the call", "CDPATH=/srv cd app && echo x > f", []string{"/work/proj/app/f", "/srv/app/f"}, false},
		{"if cd: the then-branch is proven", "if cd .git/hooks; then echo x > pre-push; fi", []string{hooks}, false},
		{"if cd: the else-branch may run anywhere", "if cd .git/hooks; then :; else echo x > pre-push; fi", []string{top, hooks}, false},
		{"subshell sees its cd", "(cd .git/hooks && echo x > pre-push)", []string{hooks}, false},
		{"subshell does not leak", "(cd .git/hooks); echo x > pre-push", []string{top}, false},
		{"group: the cd may fail", "{ cd .git/hooks; }; echo x > pre-push", []string{top, hooks}, false},
		{"pipe does not leak", "cd .git/hooks | cat; echo x > pre-push", []string{top}, false},
		{"background does not leak", "cd .git/hooks & echo x > pre-push", []string{top}, false},
		{"false and cd", "false && cd .git/hooks; echo x > pre-push", []string{top, hooks}, false},
		{"test and cd", "test -d .git/hooks && cd .git/hooks; echo x > pre-push", []string{top, hooks}, false},
		{"group false and cd", "{ false && cd .git/hooks; }; echo x > pre-push", []string{top, hooks}, false},
		{"or cd", "true || cd .git/hooks; echo x > pre-push", []string{top, hooks}, false},
		{"cd or true", "cd .git/hooks || true; echo x > pre-push", []string{top, hooks}, false},
		{"cd or exit", "cd .git/hooks || exit 1; echo x > pre-push", []string{top, hooks}, false},
		{"if body", "if true; then cd .git/hooks; fi; echo x > pre-push", []string{top, hooks}, false},
		{"while body moving each pass", "while true; do cd sub; done; echo x > f", []string{"/work/proj/f", "/work/proj/sub/f", "/work/proj/sub/sub/f"}, true},
		// A call of a function whose body moves leaves the shell where the
		// body may (rel-1-0-10:GAP-1144).
		{"function that moves", "f() { cd /srv; }; f; echo x > g", []string{"/srv/g", "/work/proj/g"}, false},
		{"function that moves, && after it", "f() { cd /srv || cd /opt; }; f && echo x > g", []string{"/srv/g", "/opt/g"}, false},
		{"function moving to a variable: unresolved", "f() { cd $X; }; f; echo x > g", []string{"/work/proj/g"}, true},
		{"function defined twice: unresolved", "f() { cd /srv; }; f() { cd /opt; }; f; echo x > g", []string{"/work/proj/g"}, true},
		{"function called before its definition: unresolved", "f; f() { cd /srv; }; echo x > g", []string{"/work/proj/g"}, true},
		{"function defined in another body: unresolved", "h() { g() { cd /srv; }; }; g; echo x > g", []string{"/work/proj/g"}, true},
		{"mover called in a body defined before it", "h() { f; }; f() { cd /srv; }; h; echo x > g", []string{"/srv/g", "/work/proj/g"}, false},
		// A definition anywhere the text reaches it defines the mover; one
		// that may not have run leaves the shell where it was too
		// (rel-1-0-10:GAP-1229).
		{"function defined in an && tail", "cd /srv && f() { cd /opt || return; }; f; echo x > g", []string{"/opt/g", "/srv/g", "/work/proj/g"}, false},
		{"function defined in a branch", "if true; then f() { cd /srv; }; fi; f; echo x > g", []string{"/srv/g", "/work/proj/g"}, false},
		{"function defined in a body called first", "h() { f() { cd /srv; }; }; h; f; echo x > g", []string{"/srv/g", "/work/proj/g"}, false},
		{"function defined in a subshell: unresolved", "(f() { cd /srv; }); f; echo x > g", []string{"/work/proj/g"}, true},
		// A function named cd may run instead of the builtin, at the top
		// level and in a mover body the tracking reads (substrate-1:GAP-0684
		// on the GAP-1144 body reading).
		{"function named cd: a top-level cd is unresolved", "cd() { :; }; cd /srv && echo x > g", []string{"/work/proj/g"}, true},
		{"function named cd: a cd in a mover body is unresolved", "cd() { :; }; f() { cd /srv; }; f; echo x > g", []string{"/work/proj/g"}, true},
		{"function never called", "f() { cd /srv; }; echo x > g", []string{"/work/proj/g"}, false},
		{"variable target: unresolved", "cd $X && echo x > pre-push", []string{top}, true},
		{"command substitution target: unresolved", "cd \"$(cat d)\" && echo x > pre-push", []string{top}, true},
		{"glob target: unresolved", "cd .git/h* && echo x > pre-push", []string{top}, true},
		{"dash target: unresolved", "cd - && echo x > pre-push", []string{top}, true},
		{"popd: unresolved", "popd && echo x > pre-push", []string{top}, true},
		{"other user home: unresolved", "cd ~bob && echo x > f", []string{"/work/proj/f"}, true},
		{"before the cd", "echo x > before && cd .git", []string{"/work/proj/before"}, false},
		{"absolute operand is untouched", "cd .git/hooks; echo x > /tmp/f", []string{"/tmp/f"}, false},
		{"no cd", "echo x > pre-push", []string{top}, false},
		{"shell body inherits the cd", "cd .git/hooks && sh -c 'echo x > pre-push'", []string{hooks}, false},
		{"shell body then its own cd", "cd .git && bash -c 'cd hooks && echo x > pre-push'", []string{hooks}, false},
		{"shell body after a cd that may fail", "cd .git/hooks; sh -c 'echo x > pre-push'", []string{top, hooks}, false},
		{"shell body of an unknown folder", "cd $X && sh -c 'echo x > pre-push'", []string{top}, true},
		{"shell body without a cd", "sh -c 'echo x > pre-push'", []string{top}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "Bash", Command: tc.command, CWD: cwd, ActiveHome: home, DialectHint: DialectPOSIX})
			var got []string
			unresolved := false
			for _, path := range facts.Paths {
				if path.Access == PathAccessWrite || path.Access == PathAccessAppend {
					if !slices.Contains(got, path.Resolved) {
						got = append(got, path.Resolved)
					}
					unresolved = unresolved || path.UnresolvedFolder()
				}
			}
			want := slices.Clone(tc.want)
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) || unresolved != tc.unresolved {
				t.Errorf("%q: resolved writes %q unresolved=%v, want %q unresolved=%v (%+v)", tc.command, got, unresolved, want, tc.unresolved, facts.Paths)
			}
			// The reading in the hook's folder (when there is one) is the
			// operand; the others are readings, not further operands.
			if operands := facts.OperandPaths(); len(operands) > len(facts.Paths) {
				t.Errorf("%q: more operands than path facts", tc.command)
			}
		})
	}
}

// TestWorkingFolderOtherReadingsAreNotOperands: the other-folder readings
// are path facts every rule sees, but OperandPaths and AtHookFolder leave
// them out, so a proof that counts operands or places links by the hook's
// folder reads the call as before (rel-1-0-10:GAP-0869).
func TestWorkingFolderOtherReadingsAreNotOperands(t *testing.T) {
	facts := Analyze(Input{Tool: "Bash", Command: "cd .git/hooks; echo x > pre-push", CWD: "/work/proj", ActiveHome: "/home/alice", DialectHint: DialectPOSIX})
	writes := func(paths []PathFact) (n int) {
		for _, path := range paths {
			if path.Access == PathAccessWrite {
				n++
			}
		}
		return n
	}
	if got := writes(facts.Paths); got != 2 {
		t.Fatalf("path facts: %d writes, want 2 (hook folder and moved folder): %+v", got, facts.Paths)
	}
	if got := writes(facts.OperandPaths()); got != 1 {
		t.Errorf("OperandPaths: %d writes, want 1", got)
	}
	hook := facts.AtHookFolder()
	if got := writes(hook.Paths); got != 1 {
		t.Errorf("AtHookFolder: %d writes, want 1", got)
	}
	for _, path := range hook.Paths {
		if path.Access == PathAccessWrite && path.Resolved != "/work/proj/pre-push" {
			t.Errorf("AtHookFolder write %q, want the hook folder's /work/proj/pre-push", path.Resolved)
		}
	}
}

// TestWorkingFolderSetBound: a call whose commands may run in more folders
// than the bound reads the first ones and marks the rest unresolved.
func TestWorkingFolderSetBound(t *testing.T) {
	command := ""
	for i := 0; i < maxWorkFolders+3; i++ {
		command += fmt.Sprintf("cd /d%d; ", i)
	}
	command += "echo x > f"
	facts := Analyze(Input{Tool: "Bash", Command: command, CWD: "/work", ActiveHome: "/home/alice", DialectHint: DialectPOSIX})
	writes, unresolved := 0, false
	for _, path := range facts.Paths {
		if path.Access == PathAccessWrite {
			writes++
			unresolved = unresolved || path.UnresolvedFolder()
		}
	}
	if writes > maxWorkFolders || !unresolved {
		t.Errorf("%d write readings unresolved=%v, want at most %d and unresolved", writes, unresolved, maxWorkFolders)
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
// tracks the folder for them): the operand after the folder change is read in
// that folder (and, as the move may fail, in the hook's), a move the reader
// cannot read leaves the hook's folder.
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
			found := false
			for _, path := range facts.Paths {
				if (path.Access == PathAccessWrite || path.Access == PathAccessAppend) &&
					strings.EqualFold(strings.ReplaceAll(path.Resolved, "/", `\`), tc.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("%q: no write reading %q (%+v)", tc.command, tc.want, facts.Paths)
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
