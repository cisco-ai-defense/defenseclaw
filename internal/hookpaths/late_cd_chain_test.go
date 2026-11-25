// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGAP1188LateChainCallGradeReadsALeadingCD: the late-ordinary reading of
// the shared reader grades a call that starts with "cd DIR &&" or "cd DIR;"
// against the folder the cd enters (and, after ";" or with a "||", the folder
// the call started in too), so an ordinary cd chain is no longer Possible only
// because a cd came first. A cd the reader cannot prove (a variable, -, ~, a
// glob, a substitution, an option, a redirect, a link, a missing folder, the
// home, a protected or state folder, CDPATH), and a later word that reaches a
// protected file from either folder, keep the call not ordinary. LateCallGrade
// itself is unchanged: it keeps every one of these calls Possible.
// GAP-1303: a cd at a later step ("ls && cd sub && ls", "cd sub && make && cd
// ..") is read the same way, each step against the folder current at it; the
// same protected cds stay not ordinary at a later step, and so does a step
// before the cd that changes the shell context.
func TestGAP1188LateChainCallGradeReadsALeadingCD(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "h")
	project := filepath.Join(home, "proj")
	sub := filepath.Join(project, "sub")
	other := filepath.Join(root, "other")
	backend, frontend := filepath.Join(project, "backend"), filepath.Join(project, "frontend")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".defenseclaw"), sub, other, backend, frontend} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, file := range []string{keys, filepath.Join(project, "plain.txt"), filepath.Join(sub, "plain.txt"), filepath.Join(home, ".env")} {
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		filepath.Join(sub, "childlink"):     keys,
		filepath.Join(project, "sshlink"):   filepath.Join(home, ".ssh"),
		filepath.Join(project, "linkdir"):   sub,
		filepath.Join(root, "proj-link"):    project,
		filepath.Join(sub, "deep-keyslink"): keys,
	} {
		testSymlink(t, target, link)
	}
	for _, tc := range []struct {
		name, command string
		ordinary      bool
	}{
		{"cd then a plain file", "cd sub && cat plain.txt", true},
		{"cd then ls", "cd sub && ls", true},
		{"cd to an absolute project then go test", "cd " + project + " && go test ./...", true},
		{"cd then a semicolon", "cd sub; ls", true},
		{"cd and back", "cd sub && cd .. && cat plain.txt", true},
		{"quoted cd folder", "cd 'sub' && ls -la", true},
		{"dot-slash cd folder", "cd ./sub && ls", true},
		{"cd outside the home", "cd " + other + " && ls", true},
		{"cd then a pipe into a filter", "cd sub && cat plain.txt | head -1", true},
		{"cd then a link of that folder", "cd sub && cat childlink", false},
		{"cd then a link after a semicolon", "cd sub; cat childlink", false},
		{"cd then an or into a link", "cd sub && ls || cat childlink", false},
		{"cd or", "cd sub || cat plain.txt", false},
		{"cd into the SSH folder", "cd ../.ssh && cat authorized_keys", false},
		{"cd up to the home", "cd .. && cat .env", false},
		{"cd up twice to the home", "cd sub/../.. && ls", false},
		{"cd home by tilde", "cd ~/.ssh && cat authorized_keys", false},
		{"cd by a variable", "cd $HOME/.defenseclaw && ls", false},
		{"cd by a quoted variable", `cd "$HOME/.defenseclaw" && ls`, false},
		{"cd to a missing folder, then tilde", "cd /x; cd ~/.aws && cat credentials", false},
		{"cd to a folder, then tilde", "cd " + other + "; cd ~/.aws && cat credentials", false},
		{"cd to the state folder", "cd " + filepath.Join(home, ".defenseclaw") + " && ls", false},
		{"cd to the state folder by a parent step", "cd ../.defenseclaw && ls", false},
		{"cd into a link to the SSH folder", "cd sshlink && cat authorized_keys", false},
		{"cd into a link to an ordinary folder", "cd linkdir && ls", false},
		{"cd dash", "cd - && ls", false},
		{"cd glob", "cd s* && ls", false},
		{"cd substitution", "cd $(echo sub) && ls", false},
		{"cd option", "cd -P sub && ls", false},
		{"cd with a redirect", "cd sub 2>/dev/null && ls", false},
		{"cd with an assignment", "X=1 cd sub && ls", false},
		{"cd to a missing folder", "cd missing && ls", false},
		{"cd to the root", "cd / && ls", false},
		{"cd then a parent step into the SSH folder", "cd sub && cd ../../.ssh && cat authorized_keys", false},
		{"cd in the background", "cd sub & ls", false},
		{"negated cd", "! cd sub && ls", false},
		{"five leading cds", "cd sub && cd .. && cd sub && cd .. && cd sub && ls", false},
		{"cd then a link to the keys file", "cd sub && cat deep-keyslink", false},
		// GAP-1303: a cd at a later step.
		{"later cd: ls, cd, ls", "ls && cd sub && ls", true},
		{"later cd: cd, make, cd back", "cd sub && make && cd ..", true},
		{"later cd: two projects", "cd backend && go test ./... && cd ../frontend && npm test", true},
		{"later cd: after a semicolon", "ls; cd sub; cat plain.txt", true},
		{"later cd: cd and back, then a plain file", "ls && cd sub && cd .. && cat plain.txt", true},
		{"later cd: after an or, then a plain file", "ls || cd sub && cat plain.txt", true},
		{"later cd into the SSH folder", "ls && cd ../.ssh && cat authorized_keys", false},
		{"later cd up to the home", "ls && cd .. && cat .env", false},
		{"later cd, make, cd up to the home", "cd sub && make && cd ../.. && cat .env", false},
		{"later cd up twice to the home", "ls && cd sub/../.. && ls", false},
		{"later cd home by tilde", "ls && cd ~/.ssh && cat authorized_keys", false},
		{"later cd by a variable", "ls && cd $HOME/.defenseclaw && ls", false},
		{"later cd to the state folder", "ls && cd " + filepath.Join(home, ".defenseclaw") + " && ls", false},
		{"later cd to the state folder by a parent step", "ls && cd ../.defenseclaw && ls", false},
		{"later cd into a link to the SSH folder", "ls && cd sshlink && cat authorized_keys", false},
		{"later cd into a link to an ordinary folder", "ls && cd linkdir && ls", false},
		{"later cd dash", "ls && cd - && ls", false},
		{"later cd plus", "ls && cd +1 && ls", false},
		{"later cd glob", "ls && cd s* && ls", false},
		{"later cd substitution", "ls && cd $(echo sub) && ls", false},
		{"later cd option", "ls && cd -P sub && ls", false},
		{"later cd with a redirect", "ls && cd sub 2>/dev/null && ls", false},
		{"later cd with an assignment", "ls && X=1 cd sub && ls", false},
		{"later cd to a missing folder", "ls && cd missing && ls", false},
		{"later cd to the root", "ls && cd / && ls", false},
		{"later cd then a link of that folder", "ls && cd sub && cat childlink", false},
		{"later cd then an or", "ls && cd sub || cat plain.txt", false},
		{"later cd after an or, then a word protected from the call folder", "ls || cd sub && cat sshlink/authorized_keys", false},
		{"later cd after a semicolon, then a word protected from the call folder", "ls; cd sub; cat sshlink/authorized_keys", false},
		{"later cd as the last step, into the SSH folder", "ls && cd ../.ssh", false},
		{"later cd as the last step, up to the home", "cd sub && make && cd ../..", false},
		{"later cd in the background", "ls && cd sub & cat childlink", false},
		{"later cd in a pipeline", "ls && cd sub | cat childlink", false},
		{"later cd in a subshell", "ls && (cd ../.ssh && cat authorized_keys)", false},
		{"later cd in a group", "ls && { cd sub && cat childlink; }", false},
		{"pushd before a later cd", "pushd sub && cd . && cat childlink", false},
		{"zsh chdir before a later cd", "chdir sub && cd . && cat childlink", false},
		{"source before a later cd", "source x.sh && cd sub && ls", false},
		{"a subshell with a cd before a later cd", "(cd ../.ssh) && cd sub && ls", false},
		{"CDPATH set before a later cd", "CDPATH=" + home + "; cd sub && ls", false},
		{"CDPATH read before a later cd", "echo " + home + " | read CDPATH; cd sub && ls", false},
		{"printf -v before a later cd", "printf -v CDPATH x; cd sub && ls", false},
		{"shopt before a later cd", "shopt -s cdable_vars; cd sub && ls", false},
		{"printf before a later cd", "printf x && cd sub && ls", true},
		{"later cd, five cds", "ls && cd sub && cd .. && cd sub && cd .. && cd sub && ls", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := LateChainCallGrade(tc.command, project, home) == GradeNone; got != tc.ordinary {
				t.Fatalf("LateChainCallGrade(%q) ordinary=%v, want %v", tc.command, got, tc.ordinary)
			}
			if strings.Contains(tc.command, "cd ") || strings.HasPrefix(tc.command, "pushd ") || strings.HasPrefix(tc.command, "chdir ") || strings.HasPrefix(tc.command, "source ") {
				// LateCallGrade keeps every compound call with a cd Possible.
				if grade := LateCallGrade(tc.command, project, home); grade == GradeNone {
					t.Fatalf("LateCallGrade(%q) = None, want it unchanged (not ordinary)", tc.command)
				}
			}
		})
	}
	t.Run("from a call folder reached through a link, a parent step is refused", func(t *testing.T) {
		linked := filepath.Join(root, "proj-link")
		if LateChainCallGrade("cd sub && ls", linked, home) != GradeNone {
			t.Fatal("cd sub from a linked call folder is not ordinary, want ordinary (no parent step)")
		}
		if LateChainCallGrade("cd sub/.. && ls", linked, home) == GradeNone {
			t.Fatal("cd sub/.. from a linked call folder is ordinary, want refused (the shell and the file system disagree)")
		}
	})
	t.Run("CDPATH", func(t *testing.T) {
		t.Setenv("CDPATH", home)
		if LateChainCallGrade("cd sub && ls", project, home) == GradeNone {
			t.Fatal("cd sub with CDPATH set is ordinary, want refused")
		}
		if LateChainCallGrade("cd ./sub && ls", project, home) != GradeNone {
			t.Fatal("cd ./sub with CDPATH set is not ordinary, want ordinary (CDPATH is not read)")
		}
		if LateChainCallGrade("ls && cd sub && ls", project, home) == GradeNone {
			t.Fatal("a later cd sub with CDPATH set is ordinary, want refused")
		}
		if LateChainCallGrade("ls && cd ./sub && ls", project, home) != GradeNone {
			t.Fatal("a later cd ./sub with CDPATH set is not ordinary, want ordinary (CDPATH is not read)")
		}
	})
}

// TestGAP1188LateEnteredDirectory: a relative Codex workdir is placed as a
// cd from the call folder; a link, a parent step to the home and a protected
// folder are refused.
func TestGAP1188LateEnteredDirectory(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "h")
	project := filepath.Join(home, "proj")
	sub := filepath.Join(project, "sub")
	for _, dir := range []string{filepath.Join(home, ".ssh"), sub} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	testSymlink(t, sub, filepath.Join(project, "linkdir"))
	for _, tc := range []struct {
		dir, want string
	}{
		{"sub", sub},
		{"sub/", sub},
		{"./sub/.", sub},
		{"sub/..", project},
		{sub, sub},
		{"..", ""},
		{"../.ssh", ""},
		{"linkdir", ""},
		{"missing", ""},
		{"~", ""},
		{"-", ""},
		{"+1", ""},
		{"", ""},
	} {
		got, ok := LateEnteredDirectory(project, tc.dir, home)
		if ok != (tc.want != "") || got != tc.want {
			t.Errorf("LateEnteredDirectory(%q) = %q, %v; want %q", tc.dir, got, ok, tc.want)
		}
	}
}
