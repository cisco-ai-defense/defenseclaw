// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestChainStatementFindingsAreTheUnion (rel-1-0-10:GAP-0951): a list's
// findings are the union of its statements' findings, so its verdict is at
// least the verdict of each statement sent alone. On int/r110-b11d4 a copy of
// a developer-token file of the home alerted (CRITICAL) alone and was allowed
// as soon as any other statement came before or after it, chmod or not: the
// facts of the whole list leave its "~/" operand dynamic (an earlier statement
// may change HOME), and the shell lane read only those facts.
//
// The statements come from the credentials-file table (one probe per row),
// each copied out of the home, in all five packs. A statement whose lone
// verdict is allow decides nothing, so only the others are wrapped.
func TestChainStatementFindingsAreTheUnion(t *testing.T) {
	const home = "/home/alice"
	t.Setenv("HOME", home)
	cwd := home + "/proj"
	rank := map[any]int{"allow": 0, "alert": 1, "block": 2}
	severity := map[any]int{"NONE": 0, "": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	forms := []struct{ name, format string }{
		{"and", "%s && true"},
		{"seq", "%s; true"},
		{"or", "%s || true"},
		{"second", "true && %s"},
		{"chmod", "%s && chmod 644 /tmp/n"},
	}
	judged := 0
	for _, pack := range gap0437Packs {
		server := gap0437Server(t, pack, "claudecode", "action")
		call := 0
		hook := func(command string) map[string]any {
			call++
			return gap0437Hook(t, server, cwd, fmt.Sprintf("union-%s-%d", pack.name, call), command)
		}
		for _, probe := range actionfacts.CredentialFileShapeProbePaths() {
			statement := "cp ~/" + probe + " /tmp/n"
			alone := hook(statement)
			if rank[alone["action"]] == 0 {
				continue
			}
			judged++
			aloneIDs, _ := alone["rule_ids"].([]any)
			for _, form := range forms {
				list := fmt.Sprintf(form.format, statement)
				got := hook(list)
				if rank[got["action"]] < rank[alone["action"]] ||
					severity[got["severity"]] < severity[alone["severity"]] {
					t.Errorf("%s: %s (%s): %v %v %v, weaker than the statement alone: %v %v %v",
						pack.name, probe, form.name, got["action"], got["severity"], got["rule_ids"],
						alone["action"], alone["severity"], aloneIDs)
					continue
				}
				gotIDs, _ := got["rule_ids"].([]any)
				if len(gotIDs) >= 8 {
					// The answer names at most eight rules.
					continue
				}
				for _, id := range aloneIDs {
					if !slices.Contains(gotIDs, id) {
						t.Errorf("%s: %s (%s): rule %v of the statement alone is gone: %v",
							pack.name, probe, form.name, id, gotIDs)
					}
				}
			}
		}
	}
	if judged == 0 {
		t.Fatal("no credentials-file copy was judged alone; the table or the packs changed")
	}
}

// TestChainStatementFindingsKeepTheStrictest (rel-1-0-10:GAP-0995,
// GAP-0996) takes the statements of TestChainStatementFindingsAreTheUnion
// into forms the union first got wrong, in all five packs.
//
// GAP-0995: in a called function, after a function that assigns HOME, and
// (for a developer-token file, PATH-GIT-CREDS) as the copy of a find -exec,
// the dispatch already carried the statement's rule
// as detection-only evidence, and the shell lane skipped every rule id it saw,
// so its enforcing finding was dropped. Such a form is never weaker than the
// statement alone.
//
// GAP-0996: a HOME assignment on the right side of && or || may not run, so
// a later ~ is the home it had (as alone) or the one assigned, and the form is
// never weaker than the statement alone. A HOME set at run time (a command
// substitution, a variable, read) names a home the walk cannot know, so a
// later ~ read of a credentials-table file, or of one past the home (~/..),
// is at least the unknown tier: an alert, a block in strict.
//
// A benign statement in the same forms keeps its verdict.
func TestChainStatementFindingsKeepTheStrictest(t *testing.T) {
	const home = "/home/alice"
	t.Setenv("HOME", home)
	cwd := home + "/proj"
	decoy := cwd + "/h"
	rank := map[any]int{"allow": 0, "alert": 1, "block": 2}
	severity := map[any]int{"NONE": 0, "": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	copyOut := func(path string) string { return "cp " + path + " /tmp/n" }
	type form struct {
		name string
		make func(probe string) string
	}
	wrap := func(name, format string) form {
		return form{name, func(probe string) string { return fmt.Sprintf(format, copyOut("~/"+probe)) }}
	}
	strict := []form{
		wrap("function", "f(){ %s; }; f"),
		wrap("function-second", "f() { true; %s; }; f"),
		wrap("function-assigns-home", "f(){ HOME="+decoy+"; }; %s"),
		wrap("false-and-home", "false && HOME="+decoy+"; %s"),
		wrap("true-or-home", "true || HOME="+decoy+"; %s"),
		wrap("false-and-export-home", "false && export HOME="+decoy+"; %s"),
		wrap("skipped-function-home", "f(){ HOME="+decoy+"; }; false && f; %s"),
	}
	// The statement reads the account's file through the home set at run
	// time: $(pwd) and the hook directory, $D and read name another home
	// the walk cannot follow.
	findExec := func(probe string) string { return "true; find ~/" + probe + " -exec cp {} /tmp/n \\;" }
	unknown := []form{
		{"home-from-pwd", func(probe string) string { return "HOME=$(pwd); " + copyOut("~/../"+probe) }},
		{"home-from-variable", func(probe string) string { return "HOME=$D; " + copyOut("~/"+probe) }},
		{"home-from-read", func(probe string) string { return "read HOME </dev/null; " + copyOut("~/"+probe) }},
		{"export-home-from-pwd", func(probe string) string { return "export HOME=$(pwd); " + copyOut("~/../"+probe) }},
	}
	benign := []string{"proj/README.md", "notes.txt"}
	judged := 0
	for _, pack := range gap0437Packs {
		server := gap0437Server(t, pack, "claudecode", "action")
		call := 0
		hook := func(command string) map[string]any {
			call++
			return gap0437Hook(t, server, cwd, fmt.Sprintf("strictest-%s-%d", pack.name, call), command)
		}
		strictPack := pack.pack == "strict"
		for _, probe := range actionfacts.CredentialFileShapeProbePaths() {
			alone := hook(copyOut("~/" + probe))
			if rank[alone["action"]] == 0 {
				continue
			}
			judged++
			for _, f := range strict {
				got := hook(f.make(probe))
				if rank[got["action"]] < rank[alone["action"]] || severity[got["severity"]] < severity[alone["severity"]] {
					t.Errorf("%s: %s (%s): %v %v %v, weaker than the statement alone: %v %v %v",
						pack.name, probe, f.name, got["action"], got["severity"], got["rule_ids"],
						alone["action"], alone["severity"], alone["rule_ids"])
				}
			}
			if aloneIDs, _ := alone["rule_ids"].([]any); slices.Contains(aloneIDs, any("PATH-GIT-CREDS")) {
				got := hook(findExec(probe))
				if rank[got["action"]] < rank[alone["action"]] || severity[got["severity"]] < severity[alone["severity"]] {
					t.Errorf("%s: %s (find-exec): %v %v %v, weaker than the statement alone: %v %v %v",
						pack.name, probe, got["action"], got["severity"], got["rule_ids"],
						alone["action"], alone["severity"], alone["rule_ids"])
				}
			}
			for _, f := range unknown {
				got := hook(f.make(probe))
				want := 1
				if strictPack {
					want = 2
				}
				if rank[got["action"]] < want {
					t.Errorf("%s: %s (%s): %v %v %v, below the unknown tier",
						pack.name, probe, f.name, got["action"], got["severity"], got["rule_ids"])
				}
			}
		}
		for _, name := range benign {
			alone := hook(copyOut("~/" + name))
			for _, f := range strict {
				if got := hook(f.make(name)); got["action"] != alone["action"] {
					t.Errorf("%s: benign %s (%s): %v %v, the statement alone is %v",
						pack.name, name, f.name, got["action"], got["rule_ids"], alone["action"])
				}
			}
		}
		// A HOME set at run time that no later statement reads an account's
		// file through changes nothing: a test script that points HOME at its
		// own folder and reads its own log there is ordinary work.
		for _, command := range []string{"HOME=$(pwd); ls -la", "read HOME </dev/null; git status",
			"T=$(mktemp -d); export HOME=\"$T\"; tail -n 5 \"$HOME/init.log\"",
			"export HOME=$(cat /tmp/n); cat ~/notes.txt"} {
			if got := hook(command); got["action"] != "allow" {
				t.Errorf("%s: %q: %v %v, want allow", pack.name, command, got["action"], got["rule_ids"])
			}
		}
	}
	if judged == 0 {
		t.Fatal("no credentials-file copy was judged alone; the table or the packs changed")
	}
}

// TestChainStatementFindingsAfterABackgroundStatement (rel-1-0-10:GAP-1021)
// takes the statements of TestChainStatementFindingsAreTheUnion behind a
// background statement that changes HOME or the directory, in all five packs.
// The shell runs a background statement (cmd &) in a child shell, so the
// statements after it read the HOME and directory from before it, as the
// statement alone does. The walk kept a background statement in the
// caller's scope: ~ resolved to the decoy, and a copy of the account's file
// was allowed in every pack.
//
// A benign statement in the same forms keeps its verdict.
func TestChainStatementFindingsAfterABackgroundStatement(t *testing.T) {
	const home = "/home/alice"
	t.Setenv("HOME", home)
	cwd := home + "/proj"
	decoy := cwd + "/h"
	rank := map[any]int{"allow": 0, "alert": 1, "block": 2}
	severity := map[any]int{"NONE": 0, "": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	copyOut := func(path string) string { return "cp " + path + " /tmp/n" }
	type form struct{ name, format string }
	// %s is the statement; each form changes HOME only in a child shell.
	homeForms := []form{
		{"background", "HOME=" + decoy + " & %s"},
		{"background-wait", "HOME=" + decoy + " & wait; %s"},
		{"background-newline", "HOME=" + decoy + " &\n%s"},
		{"background-export", "export HOME=" + decoy + " & %s"},
		{"background-group", "{ HOME=" + decoy + "; } & %s"},
		{"background-list", "true && HOME=" + decoy + " & %s"},
		{"background-function", "f(){ HOME=" + decoy + "; }; f & %s"},
		{"background-in-function", "f(){ HOME=" + decoy + " & }; f; %s"},
		{"background-in-if", "if true; then HOME=" + decoy + " & fi; %s"},
	}
	// %s is the statement read relative to the directory; each form changes
	// the directory only in a child shell.
	cwdForms := []form{
		{"background-cd", "cd /tmp & %s"},
		{"background-cd-wait", "cd /tmp & wait; %s"},
		{"background-pushd", "pushd /tmp & %s"},
	}
	benign := []string{"proj/README.md", "notes.txt"}
	judged := 0
	for _, pack := range gap0437Packs {
		server := gap0437Server(t, pack, "claudecode", "action")
		call := 0
		hook := func(command string) map[string]any {
			call++
			return gap0437Hook(t, server, cwd, fmt.Sprintf("background-%s-%d", pack.name, call), command)
		}
		check := func(probe string, statement string, forms []form) {
			alone := hook(statement)
			if rank[alone["action"]] == 0 {
				return
			}
			judged++
			for _, f := range forms {
				got := hook(fmt.Sprintf(f.format, statement))
				if rank[got["action"]] < rank[alone["action"]] || severity[got["severity"]] < severity[alone["severity"]] {
					t.Errorf("%s: %s (%s): %v %v %v, weaker than the statement alone: %v %v %v",
						pack.name, probe, f.name, got["action"], got["severity"], got["rule_ids"],
						alone["action"], alone["severity"], alone["rule_ids"])
				}
			}
		}
		for _, probe := range actionfacts.CredentialFileShapeProbePaths() {
			check(probe, copyOut("~/"+probe), homeForms)
			check(probe, copyOut("../"+probe), cwdForms)
		}
		for _, name := range benign {
			for _, statement := range []string{copyOut("~/" + name), copyOut("../" + name)} {
				alone := hook(statement)
				for _, f := range append(slices.Clone(homeForms), cwdForms...) {
					if got := hook(fmt.Sprintf(f.format, statement)); got["action"] != alone["action"] {
						t.Errorf("%s: benign %s (%s): %v %v, the statement alone is %v",
							pack.name, name, f.name, got["action"], got["rule_ids"], alone["action"])
					}
				}
			}
		}
	}
	if judged == 0 {
		t.Fatal("no credentials-file copy was judged alone; the table or the packs changed")
	}
}
