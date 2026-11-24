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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// RV1 P2-1: an agent file in the way of a laptop folder is a conflict;
// neither refuse nor theirs unlinks it.
func TestPushAgentFileInTheWayOfLaptopFolder(t *testing.T) {
	for _, mode := range []PushMode{PushRefuse, PushTheirs} {
		t.Run(string(mode), func(t *testing.T) {
			e := newEnv(t)
			e.initRepo()
			rec, fs := pushLaunch(t, e, "f1")
			fs.write(rec.RemoteDir+"/out", "agent\n")
			writeFile(t, e.project, "out/report.txt", "laptop\n")
			p := planPush(t, e, "f1", fs)
			if got := changeList(p); !reflect.DeepEqual(got, []string{"added out/report.txt conflict"}) {
				t.Fatalf("plan = %q", got)
			}
			_, _ = p.Send(bg, fs, mode, "")
			wantFiles(t, fs.local(rec.RemoteDir), "out", "agent\n")
		})
	}
}

// RV1 P2-1: a laptop file that became a folder is no conflict when the
// agent left the file alone, and a conflict (kept) when it edited it.
func TestPushLaptopFileBecameFolder(t *testing.T) {
	for _, agentEdit := range []bool{false, true} {
		t.Run(map[bool]string{false: "untouched", true: "edited"}[agentEdit], func(t *testing.T) { laptopFileBecameFolder(t, agentEdit) })
	}
}

func laptopFileBecameFolder(t *testing.T, agentEdit bool) {
	{
		e := newEnv(t)
		e.initRepo()
		rec, fs := pushLaunch(t, e, "f2")
		if agentEdit {
			fs.write(rec.RemoteDir+"/README.md", "agent\n")
		}
		if err := os.Remove(filepath.Join(e.project, "README.md")); err != nil {
			t.Fatal(err)
		}
		writeFile(t, e.project, "README.md/x.txt", "laptop\n")
		p := planPush(t, e, "f2", fs)
		want := []string{"deleted README.md", "added README.md/x.txt"}
		if agentEdit {
			want = []string{"deleted README.md conflict", "added README.md/x.txt conflict"}
		}
		if got := changeList(p); !reflect.DeepEqual(got, want) {
			t.Fatalf("agent edit %v: plan = %q, want %q", agentEdit, got, want)
		}
		if _, err := p.Send(bg, fs, PushTheirs, ""); err != nil {
			t.Fatal(err)
		}
		if agentEdit {
			wantFiles(t, fs.local(rec.RemoteDir), "README.md", "agent\n")
		} else {
			wantFiles(t, fs.local(rec.RemoteDir), "README.md/x.txt", "laptop\n")
		}
	}
}

// RV1 P3-2: a delete never follows a symlinked parent out of the project,
// even with --mine.
func TestPushDeleteDoesNotFollowSymlinkedParent(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	rec, fs := pushLaunch(t, e, "f3")
	outside := t.TempDir()
	writeFile(t, outside, "app.go", "package main\n")
	agentSrc := filepath.Join(fs.local(rec.RemoteDir), "src")
	if err := os.RemoveAll(agentSrc); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, agentSrc); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(e.project, "src", "app.go")); err != nil {
		t.Fatal(err)
	}
	p := planPush(t, e, "f3", fs)
	if got := changeList(p); !reflect.DeepEqual(got, []string{"deleted src/app.go conflict"}) {
		t.Fatalf("plan = %q", got)
	}
	_, _ = p.Send(bg, fs, PushMine, "")
	wantFiles(t, outside, "app.go", "package main\n")
}

// RV1 P3-3: an agent edit between the check and the write stops the push
// with nothing written, and a second writer waits its turn.
func TestPushRechecksBeforeWriteAndLocks(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	rec, fs := pushLaunch(t, e, "f4")
	writeFile(t, e.project, "src/app.go", "package main // laptop\n")
	writeFile(t, e.project, "notes.md", "n\n")
	p := planPush(t, e, "f4", fs)
	fs.write(rec.RemoteDir+"/src/app.go", "package main // agent, after the check\n")
	_, err := p.Send(bg, fs, PushTheirs, "")
	if err == nil || !strings.Contains(err.Error(), "src/app.go") {
		t.Fatalf("send = %v, want a stop naming src/app.go", err)
	}
	wantFiles(t, fs.local(rec.RemoteDir), "src/app.go", "package main // agent, after the check\n", "notes.md", absent)
	if after, _ := LoadCopy(e.data, "f4"); after.Baseline != rec.Baseline {
		t.Fatal("a stopped push moved the baseline")
	}

	fs.write(rec.RemoteDir+"/src/app.go", "package main\n")
	lock := filepath.Join(fs.local(rec.stateDir()), "push.lock")
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	p = planPush(t, e, "f4", fs)
	if _, err := p.Send(bg, fs, PushTheirs, ""); err == nil || !strings.Contains(err.Error(), "another push or sync") {
		t.Fatalf("send under a held lock = %v", err)
	}
	wantFiles(t, fs.local(rec.RemoteDir), "notes.md", absent)
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	p = planPush(t, e, "f4", fs)
	if _, err := p.Send(bg, fs, PushTheirs, ""); err != nil {
		t.Fatalf("send past a stale lock: %v", err)
	}
	wantFiles(t, fs.local(rec.RemoteDir), "notes.md", "n\n", "src/app.go", "package main // laptop\n")
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatalf("the write left its lock: %v", err)
	}
}
