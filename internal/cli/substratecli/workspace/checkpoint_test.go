// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package workspace

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// scriptExec answers every command with one canned result and keeps the
// last request.
type scriptExec struct {
	res  osw.ExecResult
	last osw.ExecRequest
}

func (s *scriptExec) Exec(_ context.Context, _ string, req osw.ExecRequest) (*osw.ExecResult, error) {
	s.last = req
	r := s.res
	return &r, nil
}

func TestCheckpointAnswersFromTheScript(t *testing.T) {
	ex := &scriptExec{res: osw.ExecResult{Stdout: []byte("checkpoint=4\ncommit=abc123\nfiles=17\n")}}
	info, err := Checkpoint(context.Background(), CheckpointOptions{Exec: ex, Dir: "/work/proj", Label: "  before the  refactor "})
	if err != nil || info.ID != "4" || info.Tag != "dc-checkpoint-4" || info.Commit != "abc123" || info.Files != 17 {
		t.Fatalf("%+v %v", info, err)
	}
	// The values travel as arguments of the script, never inside it.
	argv := ex.last.Argv
	if argv[0] != "sh" || argv[1] != "-c" || argv[len(argv)-3] != "/work/proj" || argv[len(argv)-2] != "/work/.dc-checkpoint" || argv[len(argv)-1] != "before the refactor" {
		t.Fatalf("argv tail %q", argv[len(argv)-3:])
	}
	if strings.Contains(argv[2], "refactor") || strings.Contains(argv[2], "/work/proj") {
		t.Fatal("an argument was put into the script text")
	}
}

func TestCheckpointAndUndoRefusalsAndFailures(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		res    osw.ExecResult
		undo   bool
		id     string
		want   error
		wantIn string
	}{
		{"no git, checkpoint", osw.ExecResult{ExitCode: 90, Stderr: []byte("no git in this image")}, false, "", ErrNoGit, "has no git"},
		{"no git, undo", osw.ExecResult{ExitCode: 90}, true, "", ErrNoGit, "has no git"},
		{"nothing to go back to", osw.ExecResult{ExitCode: 92}, true, "", ErrNoCheckpoint, "no checkpoint"},
		{"unknown id", osw.ExecResult{ExitCode: 93, Stdout: []byte("known=1 2 3\n")}, true, "9", nil, "there is no checkpoint 9; the checkpoints are 1, 2, 3"},
		{"folder missing", osw.ExecResult{ExitCode: 91, Stderr: []byte("/work/proj does not exist in the actor")}, false, "", nil, "does not exist in the actor"},
		{"garbage answer", osw.ExecResult{Stdout: []byte("done\n")}, false, "", nil, "answered the checkpoint with"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ex := &scriptExec{res: tc.res}
			var err error
			if tc.undo {
				_, err = Undo(ctx, UndoOptions{Exec: ex, Dir: "/work/proj", ID: tc.id})
			} else {
				_, err = Checkpoint(ctx, CheckpointOptions{Exec: ex, Dir: "/work/proj"})
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantIn) || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	for name, o := range map[string]CheckpointOptions{
		"relative dir":     {Exec: &scriptExec{}, Dir: "proj"},
		"root":             {Exec: &scriptExec{}, Dir: "/"},
		"state inside dir": {Exec: &scriptExec{}, Dir: "/work/proj", StateDir: "/work/proj/.cp"},
		"state is dir":     {Exec: &scriptExec{}, Dir: "/work/proj", StateDir: "/work/proj"},
		"relative state":   {Exec: &scriptExec{}, Dir: "/work/proj", StateDir: "cp"},
		"no transport":     {Dir: "/work/proj"},
	} {
		if _, err := Checkpoint(ctx, o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, id := range []string{"x", "1; rm -rf /", "../1", "dc-checkpoint-", "-1"} {
		if _, err := Undo(ctx, UndoOptions{Exec: &scriptExec{}, Dir: "/work/proj", ID: id}); err == nil {
			t.Errorf("id %q accepted", id)
		}
	}
	// A project directly below / keeps its checkpoints in /tmp.
	ex := &scriptExec{res: osw.ExecResult{Stdout: []byte("checkpoint=1\ncommit=c\nfiles=0\n")}}
	if _, err := Checkpoint(ctx, CheckpointOptions{Exec: ex, Dir: "/proj"}); err != nil || ex.last.Argv[len(ex.last.Argv)-2] != "/tmp/.dc-checkpoint" {
		t.Fatalf("%v %q", err, ex.last.Argv)
	}
}

// noGit runs the actor's commands with a PATH that has no git.
type noGit struct{ Client *Client }

func (n noGit) Exec(ctx context.Context, sb string, req osw.ExecRequest) (*osw.ExecResult, error) {
	req.Argv = append([]string{"/usr/bin/env", "PATH=/nonexistent"}, req.Argv...)
	req.Argv[2] = "/bin/sh"
	return n.Client.Exec(ctx, sb, req)
}

func TestCheckpointAndUndoInARealActor(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	a := newActor(t)
	c := a.client()
	ctx := context.Background()
	proj := filepath.Join(a.workdir, "proj")
	write(t, proj, "f.txt", "one", 0o644)
	write(t, proj, "bin/run.sh", "#!/bin/sh\n", 0o755)
	write(t, proj, ".gitignore", "*.log\n", 0o644)
	write(t, proj, "build.log", "ignored", 0o644)

	// The project is a repository of its own; checkpoints leave it alone.
	o := &operator{t: t, home: a.workdir}
	o.git(proj, "init", "-q", "-b", "main")
	o.git(proj, "add", "-A")
	o.git(proj, "commit", "-q", "-m", "init")
	head := o.git(proj, "rev-parse", "HEAD")

	cp1, err := Checkpoint(ctx, CheckpointOptions{Exec: c, Dir: proj, Label: "first"})
	if err != nil || cp1.ID != "1" || cp1.Files == 0 {
		t.Fatalf("%+v %v", cp1, err)
	}
	write(t, proj, "f.txt", "two", 0o644)
	write(t, proj, "added.txt", "new", 0o644)
	cp2, err := Checkpoint(ctx, CheckpointOptions{Exec: c, Dir: proj})
	if err != nil || cp2.ID != "2" {
		t.Fatalf("%+v %v", cp2, err)
	}
	write(t, proj, "f.txt", "three", 0o644)
	write(t, proj, "later.txt", "later", 0o644)
	if err := os.Remove(filepath.Join(proj, "bin/run.sh")); err != nil {
		t.Fatal(err)
	}

	// The last one.
	u, err := Undo(ctx, UndoOptions{Exec: c, Dir: proj})
	if err != nil || u.ID != "2" {
		t.Fatalf("%+v %v", u, err)
	}
	if read(t, proj, "f.txt") != "two" || read(t, proj, "added.txt") != "new" || read(t, proj, "bin/run.sh") != "#!/bin/sh\n" {
		t.Fatal("the folder is not as checkpoint 2 left it")
	}
	if _, err := os.Stat(filepath.Join(proj, "later.txt")); err == nil {
		t.Fatal("a file added since the checkpoint is still there")
	}
	if fi, _ := os.Stat(filepath.Join(proj, "bin/run.sh")); fi == nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode lost: %v", fi)
	}
	if read(t, proj, "build.log") != "ignored" {
		t.Fatal("an ignored file was touched")
	}

	// A named one, and the numbering goes on.
	if u, err = Undo(ctx, UndoOptions{Exec: c, Dir: proj, ID: "dc-checkpoint-1"}); err != nil || u.ID != "1" {
		t.Fatalf("%+v %v", u, err)
	}
	if read(t, proj, "f.txt") != "one" {
		t.Fatal("not back at checkpoint 1")
	}
	if _, err := os.Stat(filepath.Join(proj, "added.txt")); err == nil {
		t.Fatal("added.txt survived going back to checkpoint 1")
	}
	cp3, err := Checkpoint(ctx, CheckpointOptions{Exec: c, Dir: proj})
	if err != nil || cp3.ID != "3" {
		t.Fatalf("%+v %v", cp3, err)
	}

	_, err = Undo(ctx, UndoOptions{Exec: c, Dir: proj, ID: "9"})
	if err == nil || !strings.Contains(err.Error(), "there is no checkpoint 9; the checkpoints are 1, 2, 3") {
		t.Fatalf("err = %v", err)
	}
	if got := o.git(proj, "rev-parse", "HEAD"); got != head {
		t.Fatalf("the project's own history moved: %s -> %s", head, got)
	}
	if st := o.git(proj, "status", "--porcelain"); st != "" {
		t.Fatalf("the project's git sees changes: %q", st)
	}

	// No checkpoint yet in another folder; no git at all.
	other := filepath.Join(a.workdir, "other")
	write(t, other, "x", "x", 0o644)
	if _, err := Undo(ctx, UndoOptions{Exec: c, Dir: other}); !errors.Is(err, ErrNoCheckpoint) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Checkpoint(ctx, CheckpointOptions{Exec: noGit{c}, Dir: other}); !errors.Is(err, ErrNoGit) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Undo(ctx, UndoOptions{Exec: noGit{c}, Dir: other}); !errors.Is(err, ErrNoGit) {
		t.Fatalf("err = %v", err)
	}
}
