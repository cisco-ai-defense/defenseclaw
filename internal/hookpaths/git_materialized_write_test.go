// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestGAP0626GitMaterializedWriteScope(t *testing.T) {
	home := t.TempDir()
	repo := filepath.Join(home, "project")
	for _, dir := range []string{repo, filepath.Join(repo, ".git"), filepath.Join(repo, "sub")} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, command string
		cwd           string
		want          bool
	}{
		{"subdirectory pull", `git -C sub pull && echo marker >> future`, repo, true},
		{"directory change", `cd project && git -C sub pull && echo marker >> future`, home, true},
		{"checkout", `git -C sub checkout -- future && echo marker >> future`, repo, true},
		{"switch", `git -C sub switch topic && echo marker >> future`, repo, true},
		{"merge", `git -C sub merge topic && echo marker >> future`, repo, true},
		{"reset", `git -C sub reset --hard HEAD && echo marker >> future`, repo, true},
		{"apply", `git -C sub apply change.patch && echo marker >> future`, repo, true},
		{"am", `git -C sub am change.patch && echo marker >> future`, repo, true},
		{"submodule update", `git -C sub submodule update --init && echo marker >> future`, repo, true},
		{"clone", `git clone source cloned && echo marker >> cloned/future`, repo, true},
		{"copy target", `git -C sub pull && cp source future`, repo, true},
		{"nested shell", `bash -lc 'git -C sub pull && echo marker >> future'`, repo, true},
		{"brace group", `{ git -C sub pull; echo marker >> future; }`, repo, true},
		{"conditional body", `if true; then git -C sub pull; echo marker >> future; fi`, repo, true},
		{"plain wrapper", `nohup git -C sub pull && echo marker >> future`, repo, true},
		{"environment directory", `env -C project git -C sub pull && echo marker >> project/future`, home, true},
		{"environment worktree", `env GIT_WORK_TREE=.. git -C sub pull && echo marker >> ../outside.txt`, repo, true},
		{"exported worktree", `export GIT_WORK_TREE="$HOME"; git -C sub pull && echo marker >> ../future`, repo, true},
		{"exported checkout worktree", `export GIT_WORK_TREE="$HOME"; git -C sub checkout -- future && echo marker >> ../future`, repo, true},
		{"declared exported worktree", `declare -x GIT_WORK_TREE="$HOME"; git -C sub pull && echo marker >> ../future`, repo, true},
		{"exported git directory", `export GIT_DIR="$HOME/project/.git"; git -C sub pull && echo marker >> ../future`, repo, true},
		{"unexported worktree", `GIT_WORK_TREE="$HOME"; git -C sub pull && echo marker >> ../future`, repo, false},
		{"removed worktree export", `export GIT_WORK_TREE="$HOME"; unset GIT_WORK_TREE; git -C sub pull && echo marker >> ../future`, repo, false},
		{"removed worktree export flag", `export GIT_WORK_TREE="$HOME"; export -n GIT_WORK_TREE; git -C sub pull && echo marker >> ../future`, repo, false},
		{"export after materialization", `git -C sub pull; export GIT_WORK_TREE="$HOME"; echo marker >> ../future`, repo, false},
		{"exported read only git", `export GIT_WORK_TREE="$HOME"; git -C sub show HEAD && echo marker >> ../future`, repo, false},
		{"ordinary environment data", `printf '%s' 'GIT_WORK_TREE=..' && echo marker >> ../outside.txt`, repo, false},
		{"ordinary text", `printf '%s' 'git pull' > future`, repo, false},
		{"outside worktree", `git -C sub pull && echo marker >> ../outside.txt`, repo, false},
		{"write before pull", `echo marker >> future && git -C sub pull`, repo, false},
		{"read only Git", `git -C sub show HEAD && echo marker >> future`, repo, false},
		{"read only submodule", `git -C sub submodule status && echo marker >> future`, repo, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "Bash", Command: tc.command, CWD: tc.cwd,
				ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
			facts := actionfacts.Analyze(input)
			if got := GitMaterializedWrite(input, facts); (got == GradePossible) != tc.want {
				t.Fatalf("possible=%v want=%v simples=%+v", got, tc.want, actionfacts.SimpleCommands(input, facts))
			}
		})
	}
}
