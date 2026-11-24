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
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0489: pull from a second computer (same person, a checkout of the
// project at the same commit, no record of the copy) gives the agent's
// changes with the same flags as on the first computer. The baseline is the
// checkout's last commit, never the agent's copy of it: a secret file is
// neither measured nor brought back, local work that is not committed is not
// part of the baseline, and push and checkpoint still have no record here.
// Before the fix pull on such a computer failed with "this computer has no
// record of the folder you sent".
func TestPullOnAnotherComputerUsesTheCheckoutGAP0489(t *testing.T) {
	old := hostCopy
	hostCopy = true // the first computer's upload, on any OS
	t.Cleanup(func() { hostCopy = old })
	o := newHCEnv(t)
	o.git(o.project, "init", "-q", "-b", "main")
	hcWrite(t, o.project, "README.md", "line one\n")
	hcWrite(t, o.project, "src/main.go", "package main\n")
	hcWrite(t, o.project, "gone.txt", "to be deleted\n")
	o.git(o.project, "add", ".")
	o.git(o.project, "-c", "user.name=t", "-c", "user.email=t@example.test", "commit", "-qm", "init")
	hcWrite(t, o.project, ".env", "API_KEY=do-not-copy-this-value\n")

	workdir, c := hcActor(t)
	ctx := context.Background()
	if _, err := Start(ctx, StartOptions{Transport: c, Project: o.project, Name: "w1", DataDir: o.data, Home: o.home}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	remote := filepath.Join(workdir, "myapp")
	hcWrite(t, remote, "README.md", "line one\nline two by the agent\n")
	hcWrite(t, remote, "docs/new.md", "new file\n")
	if err := os.Remove(filepath.Join(remote, "gone.txt")); err != nil {
		t.Fatal(err)
	}
	hcWrite(t, remote, ".env", "API_KEY=agent-made\n")

	// The second computer: its own data directory and a clone of the
	// project at the same commit, in a folder of the same name.
	hostCopy = old
	second := filepath.Join(t.TempDir(), "laptop2")
	data2 := filepath.Join(second, "data")
	o.git(filepath.Dir(o.project), "clone", "-q", o.project, filepath.Join(second, "myapp"))
	clone := filepath.Join(second, "myapp")
	hcWrite(t, clone, "notes.txt", "local, not committed\n")
	if HasCopy(data2, "w1") {
		t.Fatal("the second computer has a copy record before pull")
	}

	rv, err := Pull(ctx, PullOptions{Exec: c, DataDir: data2, Name: "w1", Label: "agent-1", Project: clone, ExcludesStated: true}) // run had no --exclude (RV-T6A)
	if err != nil {
		t.Fatalf("pull on the second computer: %v", err)
	}
	got := map[string]string{}
	for _, f := range rv.Changed {
		got[f.Path] = f.Status
	}
	want := map[string]string{"README.md": "modified", "docs/new.md": "added", "gone.txt": "deleted"}
	if len(got) != len(want) {
		t.Errorf("changed %v, want %v (review %q)", got, want, rv.Text)
	}
	for p, st := range want {
		if got[p] != st {
			t.Errorf("%s: %q, want %q (review %q)", p, got[p], st, rv.Text)
		}
	}
	if !strings.Contains(rv.Text, "measured against this folder's last commit") {
		t.Errorf("the review does not say what it is measured against: %q", rv.Text)
	}
	if strings.Contains(string(rv.Diff), "agent-made") {
		t.Errorf("the agent's .env reached the diff:\n%s", rv.Diff)
	}
	if _, err := Apply(ctx, ApplyOptions{DataDir: data2, Name: "w1", Mode: ModeBranch, Branch: "agent/w1"}); err != nil {
		t.Fatalf("pull --branch on the second computer: %v", err)
	}
	if out := o.git(clone, "show", "agent/w1:README.md"); out != "line one\nline two by the agent\n" {
		t.Errorf("branch README %q", out)
	}
	if b, err := os.ReadFile(filepath.Join(clone, "notes.txt")); err != nil || string(b) != "local, not committed\n" {
		t.Errorf("local work changed: %q %v", b, err)
	}
	// Push, sync, checkpoint and undo still have no record here.
	if HasCopy(data2, "w1") || RemoteDirOf(data2, "w1") != "" {
		t.Errorf("the pull baseline counts as a copy record: HasCopy %v, RemoteDirOf %q", HasCopy(data2, "w1"), RemoteDirOf(data2, "w1"))
	}
	// A second pull goes on from the same record: nothing new since.
	if rv, err := Pull(ctx, PullOptions{Exec: c, DataDir: data2, Name: "w1", Project: clone, ExcludesStated: true}); err != nil || len(rv.Changed) != 3 {
		t.Fatalf("second pull: %v %v", err, rv)
	}

	// A folder that is not a checkout, and one the agent has no folder
	// for, still refuse and say why.
	plain := filepath.Join(t.TempDir(), "myapp")
	hcWrite(t, plain, "README.md", "x\n")
	if _, err := Pull(ctx, PullOptions{Exec: c, DataDir: filepath.Join(t.TempDir(), "d3"), Name: "w1", Project: plain}); err == nil || !strings.Contains(err.Error(), "not a git checkout") {
		t.Errorf("pull in a folder that is not a checkout: %v", err)
	}
	other := filepath.Join(t.TempDir(), "otherapp")
	o.git(filepath.Dir(o.project), "clone", "-q", o.project, other)
	if _, err := Pull(ctx, PullOptions{Exec: c, DataDir: filepath.Join(t.TempDir(), "d4"), Name: "w1", Project: other}); err == nil || !strings.Contains(err.Error(), "no folder named otherapp") {
		t.Errorf("pull in a checkout the agent has no folder for: %v", err)
	}
}
