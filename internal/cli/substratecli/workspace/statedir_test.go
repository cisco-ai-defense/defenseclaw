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
	"os"
	"path"
	"regexp"
	"strings"
	"testing"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

var stateDirName = regexp.MustCompile(`^\.dc-state-[a-z0-9-]+-[0-9a-f]{8}$`)

func TestNewStateDirIsASiblingOfTheProjectAndDiffersEveryTime(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		d, err := NewStateDir("/work", "copy-1")
		if err != nil {
			t.Fatal(err)
		}
		if path.Dir(d) != "/work" || !strings.HasPrefix(path.Base(d), StateDirPrefix+"copy-1-") || !stateDirName.MatchString(path.Base(d)) {
			t.Fatalf("state dir %q", d)
		}
		seen[d] = true
	}
	if len(seen) != 20 {
		t.Fatalf("only %d different directories in 20 tries", len(seen))
	}
	for _, root := range []string{"", "work", "/", "/work/.."} {
		if d, err := NewStateDir(root, "x"); err == nil {
			t.Errorf("root %q gave %q", root, d)
		}
	}
}

func TestStartMakesAPrivateStateDirOutsideTheProject(t *testing.T) {
	_, sb, res := copyInActor(t)
	d := res.StateDir
	if path.Dir(d) != "/sandbox/work" || !stateDirName.MatchString(path.Base(d)) || strings.HasPrefix(d, res.RemoteDir+"/") {
		t.Fatalf("state dir %q (project %q)", d, res.RemoteDir)
	}
	if fi, err := os.Stat(sb.local(d)); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("state dir: %v %v", fi, err)
	}
	// Nothing of the pipeline is in the shared directory.
	if _, err := os.Stat(sb.local("/sandbox/.dc")); err == nil {
		t.Fatal("the shared /sandbox/.dc was used")
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("warnings %q", res.Warnings)
	}
}

func TestEveryStartHasItsOwnStateDirAndTheOldOneGoes(t *testing.T) {
	o := newOperator(t)
	o.initRepo()
	a := newActor(t)
	sb := sandboxFS{Client: a.client(), dir: t.TempDir()}
	ctx := context.Background()
	start := func(name string, replace bool) *StartResult {
		t.Helper()
		res, err := Start(ctx, StartOptions{Transport: sb, Project: o.project, Name: name, DataDir: o.data, Home: o.home, Replace: replace})
		if err != nil {
			t.Fatalf("Start %s: %v", name, err)
		}
		return res
	}
	first := start("same", false)
	other := start("other", false)
	again := start("same", true)
	if first.StateDir == again.StateDir || first.StateDir == other.StateDir || other.StateDir == again.StateDir {
		t.Fatalf("directories repeat: %q %q %q", first.StateDir, other.StateDir, again.StateDir)
	}
	if _, err := os.Stat(sb.local(first.StateDir)); err == nil {
		t.Fatal("the replaced copy's state directory is still there")
	}
	for _, d := range []string{other.StateDir, again.StateDir} {
		if fi, err := os.Stat(sb.local(d)); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v", d, fi, err)
		}
	}
	// A directory the caller names is used as it is.
	named, err := Start(ctx, StartOptions{Transport: sb, Project: o.project, Name: "named", DataDir: o.data, Home: o.home, StateDir: "/sandbox/mine/state"})
	if err != nil || named.StateDir != "/sandbox/mine/state" {
		t.Fatalf("%+v %v", named, err)
	}
	if fi, err := os.Stat(sb.local("/sandbox/mine/state")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("named state dir: %v %v", fi, err)
	}
	// ... and one inside the project is refused.
	if _, err := Start(ctx, StartOptions{Transport: sb, Project: o.project, Name: "inside", DataDir: o.data, Home: o.home, StateDir: remoteProject + "/.state"}); err == nil {
		t.Fatal("a state directory inside the project was accepted")
	}
}

func TestPullAndCheckpointUseTheRecordedStateDir(t *testing.T) {
	o, sb, res := copyInActor(t)
	ctx := context.Background()
	write(t, sb.local(remoteProject), "src/new.go", "package main\n\nfunc New() {}\n", 0o644)
	if _, err := Pull(ctx, PullOptions{Exec: sb, DataDir: o.data, Name: "c1"}); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if _, err := os.Stat(sb.local(res.StateDir + "/result.bundle")); err != nil {
		t.Fatalf("the bundle is not in the recorded state directory: %v", err)
	}

	cp, err := Checkpoint(ctx, CheckpointOptions{Exec: sb, Dir: remoteProject, DataDir: o.data, Name: "c1"})
	if err != nil || cp.ID != "1" {
		t.Fatalf("Checkpoint: %+v %v", cp, err)
	}
	repo := sb.local(res.StateDir + "/checkpoint")
	if fi, err := os.Stat(repo); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("checkpoint folder: %v %v", fi, err)
	}
	if _, err := os.Stat(repo + "/myapp.git/HEAD"); err != nil {
		t.Fatalf("the checkpoint repository is not under the state directory: %v", err)
	}
	if _, err := os.Stat(sb.local("/sandbox/work/.dc-checkpoint")); err == nil {
		t.Fatal("a checkpoint folder was made next to the project")
	}
	write(t, sb.local(remoteProject), "src/new.go", "changed\n", 0o644)
	u, err := Undo(ctx, UndoOptions{Exec: sb, Dir: remoteProject, DataDir: o.data, Name: "c1"})
	if err != nil || u.ID != "1" || read(t, sb.local(remoteProject), "src/new.go") != "package main\n\nfunc New() {}\n" {
		t.Fatalf("Undo: %+v %v", u, err)
	}
}

// A copy made before state directories had a field of their own keeps its
// checkpoints where they were, next to the project.
func TestCheckpointOfACopyWithoutAStateDirKeepsTheOldPlace(t *testing.T) {
	o := newOperator(t)
	o.initRepo()
	if runtimeUnsupported() {
		t.Skip("copy mode is Linux and macOS only")
	}
	ctx := context.Background()
	rec, err := osw.Stage(ctx, osw.StageOptions{Project: o.project, Name: "old1", DataDir: o.data, Home: o.home})
	if err != nil || rec.StateDir != "" {
		t.Fatalf("%+v %v", rec, err)
	}
	for name, o2 := range map[string]CheckpointOptions{
		"record without the field": {DataDir: o.data, Name: "old1"},
		"no record":                {DataDir: o.data, Name: "nope"},
		"no copy named":            {},
	} {
		ex := &scriptExec{res: osw.ExecResult{Stdout: []byte("checkpoint=1\ncommit=c\nfiles=0\n")}}
		o2.Exec, o2.Dir = ex, remoteProject
		if _, err := Checkpoint(ctx, o2); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := ex.last.Argv[len(ex.last.Argv)-2]; got != "/sandbox/work/.dc-checkpoint" {
			t.Fatalf("%s: checkpoint folder %q", name, got)
		}
	}
}

func TestCheckpointFolderIsTheRecordedStateDirs(t *testing.T) {
	o := newOperator(t)
	o.initRepo()
	if runtimeUnsupported() {
		t.Skip("copy mode is Linux and macOS only")
	}
	ctx := context.Background()
	if _, err := osw.Stage(ctx, osw.StageOptions{Project: o.project, Name: "new1", DataDir: o.data, Home: o.home, StateDir: "/sandbox/x/.dc-state-new1-0a1b2c3d"}); err != nil {
		t.Fatal(err)
	}
	ex := &scriptExec{res: osw.ExecResult{Stdout: []byte("checkpoint=1\ncommit=c\nfiles=0\n")}}
	if _, err := Checkpoint(ctx, CheckpointOptions{Exec: ex, Dir: remoteProject, DataDir: o.data, Name: "new1"}); err != nil {
		t.Fatal(err)
	}
	if got := ex.last.Argv[len(ex.last.Argv)-2]; got != "/sandbox/x/.dc-state-new1-0a1b2c3d/checkpoint" {
		t.Fatalf("checkpoint folder %q", got)
	}
	// An explicit folder wins.
	if _, err := Checkpoint(ctx, CheckpointOptions{Exec: ex, Dir: remoteProject, DataDir: o.data, Name: "new1", StateDir: "/sandbox/elsewhere"}); err != nil {
		t.Fatal(err)
	}
	if got := ex.last.Argv[len(ex.last.Argv)-2]; got != "/sandbox/elsewhere" {
		t.Fatalf("checkpoint folder %q", got)
	}
}
