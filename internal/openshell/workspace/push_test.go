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

//go:build !windows

package workspace

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// pushLaunch sends e.project into a fake sandbox, as run does.
func pushLaunch(t *testing.T, e *env, name string) (*CopyRecord, *fakeSandbox) {
	t.Helper()
	fs := newFakeSandbox(t, e)
	if _, err := Stage(bg, e.stageOpts(name)); err != nil {
		t.Fatal(err)
	}
	if _, err := Upload(bg, e.data, name, fs, fs); err != nil {
		t.Fatal(err)
	}
	rec, err := EstablishBaseline(bg, e.data, name, fs)
	if err != nil {
		t.Fatal(err)
	}
	return rec, fs
}

// planPush stages e.project again and plans a push of it.
func planPush(t *testing.T, e *env, name string, fs *fakeSandbox, paths ...string) *PushPlan {
	t.Helper()
	st, err := PrepareCopy(bg, e.stageOpts(name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	p, err := PlanPush(bg, PushPlanOptions{DataDir: e.data, Name: name, Stage: st, Exec: fs, Paths: paths})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func changeList(p *PushPlan) []string {
	var out []string
	for _, c := range p.Changes {
		s := c.Status + " " + c.Path
		if c.Conflict {
			s += " conflict"
		}
		if c.Same {
			s += " same"
		}
		out = append(out, s)
	}
	return out
}

func TestPushRefusesConflictListsFiles(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	rec, fs := pushLaunch(t, e, "p1")
	writeFile(t, e.project, "README.md", "laptop\n")
	writeFile(t, e.project, "src/new.go", "package main // new\n")
	fs.write(rec.RemoteDir+"/README.md", "agent\n")
	p := planPush(t, e, "p1", fs)
	want := []string{"modified README.md conflict", "added src/new.go"}
	if got := changeList(p); !reflect.DeepEqual(got, want) {
		t.Fatalf("plan = %q, want %q", got, want)
	}
	_, err := p.Send(bg, fs, PushRefuse, "")
	var ce *PushConflictError
	if !errors.As(err, &ce) || !reflect.DeepEqual(ce.Paths, []string{"README.md"}) {
		t.Fatalf("send = %v, want a conflict on README.md", err)
	}
	wantFiles(t, fs.local(rec.RemoteDir), "README.md", "agent\n", "src/new.go", absent)
	if after, _ := LoadCopy(e.data, "p1"); after.Baseline != rec.Baseline {
		t.Fatal("a refused push moved the baseline")
	}
}

func TestPushSameEditNotConflict(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	rec, fs := pushLaunch(t, e, "p2")
	writeFile(t, e.project, "README.md", "both\n")
	fs.write(rec.RemoteDir+"/README.md", "both\n")
	p := planPush(t, e, "p2", fs)
	if got := changeList(p); !reflect.DeepEqual(got, []string{"modified README.md same"}) {
		t.Fatalf("plan = %q", got)
	}
	res, err := p.Send(bg, fs, PushRefuse, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sent) != 0 || res.Baseline == rec.Baseline {
		t.Fatalf("result %+v: want nothing written and the baseline advanced", res)
	}
}

func TestPushMineTheirsPatchOut(t *testing.T) {
	for _, mode := range []PushMode{PushMine, PushTheirs} {
		t.Run(string(mode), func(t *testing.T) {
			e := newEnv(t)
			e.initRepo()
			rec, fs := pushLaunch(t, e, "p3")
			writeFile(t, e.project, "README.md", "laptop\n")
			writeFile(t, e.project, "src/app.go", "package main // laptop\n")
			fs.write(rec.RemoteDir+"/README.md", "agent\n")
			p := planPush(t, e, "p3", fs)
			patch := filepath.Join(e.root, "conflict.patch")
			if mode == PushTheirs {
				if err := p.PatchOut(bg, patch); err != nil {
					t.Fatal(err)
				}
				b, _ := os.ReadFile(patch)
				if !strings.Contains(string(b), "+laptop") || strings.Contains(string(b), "src/app.go") {
					t.Fatalf("patch:\n%s", b)
				}
			}
			res, err := p.Send(bg, fs, mode, "4")
			if err != nil {
				t.Fatal(err)
			}
			readme := "laptop\n"
			if mode == PushTheirs {
				readme = "agent\n"
				if !reflect.DeepEqual(res.Kept, []string{"README.md"}) {
					t.Fatalf("kept %q", res.Kept)
				}
			}
			wantFiles(t, fs.local(rec.RemoteDir), "README.md", readme, "src/app.go", "package main // laptop\n")
			log, _ := LoadPushLog(e.data, "p3")
			if len(log) != 1 || log[0].Checkpoint != "4" || log[0].Old != rec.Baseline || log[0].New != res.Baseline {
				t.Fatalf("push log %+v", log)
			}
		})
	}
}

func TestPushAdvancesBaselineSoPullOmitsPushed(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	rec, fs := pushLaunch(t, e, "p4")
	writeFile(t, e.project, "src/app.go", "package main // laptop\n")
	mustRemove(t, e.project, "README.md")
	writeFile(t, e.project, ".env.local", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
	p := planPush(t, e, "p4", fs)
	if got := changeList(p); !reflect.DeepEqual(got, []string{"deleted README.md", "modified src/app.go"}) {
		t.Fatalf("plan = %q (held back %q)", got, p.HeldBack)
	}
	if !reflect.DeepEqual(p.HeldBack, []string{".env.local"}) {
		t.Fatalf("held back %q", p.HeldBack)
	}
	if _, err := p.Send(bg, fs, PushRefuse, "1"); err != nil {
		t.Fatal(err)
	}
	remote := fs.local(rec.RemoteDir)
	wantFiles(t, remote, "README.md", absent, "src/app.go", "package main // laptop\n", ".env.local", absent)
	fs.write(rec.RemoteDir+"/src/agent.go", "package main // agent\n")
	res, err := Pull(bg, PullOptions{DataDir: e.data, Name: "p4", Exec: fs})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range res.Changes {
		got = append(got, c.Status+" "+c.Path)
	}
	if !reflect.DeepEqual(got, []string{"A src/agent.go"}) {
		t.Fatalf("pull after push = %q, want only the agent's file", got)
	}
}

func TestPushPathsLimit(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	_, fs := pushLaunch(t, e, "p5")
	writeFile(t, e.project, "README.md", "laptop\n")
	writeFile(t, e.project, "src/app.go", "package main // laptop\n")
	p := planPush(t, e, "p5", fs, filepath.Join(e.project, "src"))
	if got := changeList(p); !reflect.DeepEqual(got, []string{"modified src/app.go"}) {
		t.Fatalf("plan = %q", got)
	}
	if _, err := PlanPush(bg, PushPlanOptions{DataDir: e.data, Name: "p5", Stage: p.opts.Stage, Exec: fs, Paths: []string{e.root}}); err == nil {
		t.Fatal("a path outside the project was accepted")
	}
}

func TestPushPlainFolder(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.project, "notes.md", "a\n")
	rec, fs := pushLaunch(t, e, "p6")
	writeFile(t, e.project, "notes.md", "b\n")
	writeFile(t, e.project, "more/x.txt", "x\n")
	p := planPush(t, e, "p6", fs)
	if _, err := p.Send(bg, fs, PushRefuse, ""); err != nil {
		t.Fatal(err)
	}
	wantFiles(t, fs.local(rec.RemoteDir), "notes.md", "b\n", "more/x.txt", "x\n")
}

func TestUndoAfterPushRestoresBaseline(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	rec, fs := pushLaunch(t, e, "p7")
	writeFile(t, e.project, "README.md", "one\n")
	if _, err := planPush(t, e, "p7", fs).Send(bg, fs, PushRefuse, "2"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.project, "README.md", "two\n")
	if _, err := planPush(t, e, "p7", fs).Send(bg, fs, PushRefuse, "3"); err != nil {
		t.Fatal(err)
	}
	// Undo to restore point 3 (taken before push 2) rewinds push 2 only.
	n, err := RewindPushes(bg, e.data, "p7", fs, "3")
	if err != nil || n != 1 {
		t.Fatalf("rewind = %d, %v", n, err)
	}
	log, _ := LoadPushLog(e.data, "p7")
	after, _ := LoadCopy(e.data, "p7")
	if len(log) != 1 || after.Baseline != log[0].New {
		t.Fatalf("after rewind: log %+v baseline %s", log, after.Baseline)
	}
	if got := strings.TrimSpace(fs.agent(rec.RemoteDir, "rev-parse", baselineRef)); got != log[0].New {
		t.Fatalf("sandbox baseline %s, want %s", got, log[0].New)
	}
	// A restore point before every push puts the run's baseline back.
	if n, err := RewindPushes(bg, e.data, "p7", fs, "dc-checkpoint-1"); err != nil || n != 1 {
		t.Fatalf("rewind = %d, %v", n, err)
	}
	if after, _ := LoadCopy(e.data, "p7"); after.Baseline != rec.Baseline {
		t.Fatal("baseline not back at the run's")
	}
}
