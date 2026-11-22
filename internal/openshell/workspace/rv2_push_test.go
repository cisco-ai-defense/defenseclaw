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
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// RV2 N1: a parent folder name with a space no longer makes the write's
// re-check fail (every push and sync batch stopped with "the agent
// changed ...").
func TestPushUnderParentWithSpace(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, "my dir", "old\n")
	e.commit("spaced file")
	rec, fs := pushLaunch(t, e, "s1")
	if err := os.Remove(filepath.Join(e.project, "my dir")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.project, "my dir/x.txt", "laptop\n")
	p := planPush(t, e, "s1", fs)
	if got := changeList(p); !reflect.DeepEqual(got, []string{"deleted my dir", "added my dir/x.txt"}) {
		t.Fatalf("plan = %q", got)
	}
	if _, err := p.Send(bg, fs, PushTheirs, ""); err != nil {
		t.Fatalf("send under a spaced parent: %v", err)
	}
	wantFiles(t, fs.local(rec.RemoteDir), "my dir/x.txt", "laptop\n")
}

// RV2 N2: --mine never silently removes an agent file in the way of a
// laptop folder, nor an agent folder where the laptop made a file.
func TestPushMineKeepsAgentFilesInTheWay(t *testing.T) {
	t.Run("agent file, laptop folder", func(t *testing.T) {
		e := newEnv(t)
		e.initRepo()
		rec, fs := pushLaunch(t, e, "m1")
		fs.write(rec.RemoteDir+"/out", "agent\n")
		writeFile(t, e.project, "out/report.txt", "laptop\n")
		p := planPush(t, e, "m1", fs)
		_, err := p.Send(bg, fs, PushMine, "")
		if err == nil || !strings.Contains(err.Error(), "out") {
			t.Fatalf("send --mine = %v, want a refusal naming out", err)
		}
		wantFiles(t, fs.local(rec.RemoteDir), "out", "agent\n")
	})
	t.Run("agent folder, laptop file", func(t *testing.T) {
		e := newEnv(t)
		e.initRepo()
		rec, fs := pushLaunch(t, e, "m2")
		fs.write(rec.RemoteDir+"/notes/a.md", "agent\n")
		writeFile(t, e.project, "notes", "laptop\n")
		p := planPush(t, e, "m2", fs)
		if got := changeList(p); !reflect.DeepEqual(got, []string{"added notes conflict"}) {
			t.Fatalf("plan = %q", got)
		}
		if _, err := p.Send(bg, fs, PushMine, ""); err == nil {
			t.Fatal("send --mine replaced the agent's folder notes")
		}
		wantFiles(t, fs.local(rec.RemoteDir), "notes/a.md", "agent\n")
	})
}

// termExec ends the write script with TERM once it holds the lock, as the
// relay does on a timeout or Ctrl-C.
type termExec struct{ *fakeSandbox }

func (x termExec) Exec(ctx context.Context, sb string, req ExecRequest) (*ExecResult, error) {
	if len(req.Argv) == 3 && strings.Contains(req.Argv[2], "push.lock") {
		req.Argv = append([]string(nil), req.Argv...)
		req.Argv[2] = strings.Replace(req.Argv[2], "\ncur=$(", "\nkill -TERM $$\ncur=$(", 1)
	}
	return x.fakeSandbox.Exec(ctx, sb, req)
}

// RV2 N3: a write ended by a signal removes its lock, so the next push is
// not refused for 15 minutes.
func TestPushInterruptedWriteLeavesNoLock(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	rec, fs := pushLaunch(t, e, "k1")
	writeFile(t, e.project, "notes.md", "n\n")
	p := planPush(t, e, "k1", fs)
	p.opts.Exec = termExec{fs}
	if _, err := p.Send(bg, fs, PushTheirs, ""); err == nil {
		t.Fatal("the killed write reported success")
	}
	lock := filepath.Join(fs.local(rec.stateDir()), "push.lock")
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatalf("a write ended by TERM left its lock: %v", err)
	}
	p = planPush(t, e, "k1", fs)
	if _, err := p.Send(bg, fs, PushTheirs, ""); err != nil {
		t.Fatalf("push after the interrupted one: %v", err)
	}
	wantFiles(t, fs.local(rec.RemoteDir), "notes.md", "n\n")
}

// RV2 N4: a stale lock is taken over only under the takeover guard: while
// another writer holds the guard, this one waits its turn; a guard left
// by a killed takeover goes after a minute.
func TestPushStaleLockTakeoverIsGuarded(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	rec, fs := pushLaunch(t, e, "g1")
	writeFile(t, e.project, "notes.md", "n\n")
	state := fs.local(rec.stateDir())
	lock, guard := filepath.Join(state, "push.lock"), filepath.Join(state, "push.lock.take")
	for _, d := range []string{lock, guard} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	p := planPush(t, e, "g1", fs)
	if _, err := p.Send(bg, fs, PushTheirs, ""); err == nil || !strings.Contains(err.Error(), "another push or sync") {
		t.Fatalf("send while another writer takes the stale lock over = %v", err)
	}
	wantFiles(t, fs.local(rec.RemoteDir), "notes.md", absent)
	if err := os.Chtimes(guard, old, old); err != nil {
		t.Fatal(err)
	}
	p = planPush(t, e, "g1", fs)
	if _, err := p.Send(bg, fs, PushTheirs, ""); err != nil {
		t.Fatalf("send past a stale lock and a stale guard: %v", err)
	}
	wantFiles(t, fs.local(rec.RemoteDir), "notes.md", "n\n")
	for _, d := range []string{lock, guard} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Fatalf("%s left behind: %v", filepath.Base(d), err)
		}
	}
}
