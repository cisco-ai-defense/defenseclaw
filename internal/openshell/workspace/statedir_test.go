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
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// eventLog records, in order, what the pipeline asks of the sandbox.
type eventLog struct {
	*fakeSandbox
	events []string
}

func (l *eventLog) Exec(ctx context.Context, sandbox string, req ExecRequest) (*ExecResult, error) {
	l.events = append(l.events, "exec: "+strings.Join(req.Argv, " "))
	return l.fakeSandbox.Exec(ctx, sandbox, req)
}

func (l *eventLog) Upload(ctx context.Context, sandbox, localPath, remoteDir string) error {
	l.events = append(l.events, "upload: "+remoteDir)
	return l.fakeSandbox.Upload(ctx, sandbox, localPath, remoteDir)
}

func (l *eventLog) all(substr string) int {
	n := 0
	for _, ev := range l.events {
		if strings.Contains(ev, substr) {
			n++
		}
	}
	return n
}

func (l *eventLog) first(substr string) int {
	for i, ev := range l.events {
		if strings.Contains(ev, substr) {
			return i
		}
	}
	return -1
}

func launchLogged(t *testing.T, e *env, name string, mutate func(*StageOptions)) (*CopyRecord, *eventLog) {
	t.Helper()
	log := &eventLog{fakeSandbox: newFakeSandbox(t, e)}
	opts := e.stageOpts(name)
	if mutate != nil {
		mutate(&opts)
	}
	if _, err := Stage(bg, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := Upload(bg, e.data, name, log, log); err != nil {
		t.Fatal(err)
	}
	rec, err := EstablishBaseline(bg, e.data, name, log)
	if err != nil {
		t.Fatal(err)
	}
	return rec, log
}

// Without a StateDir nothing changes: the shared /sandbox/.dc, no
// directory-creating step, and no new field in the record.
func TestStateDirDefaultUnchanged(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.project, "notes.md", "a\n")
	rec, log := launchLogged(t, e, "d1", nil)
	if rec.StateDir != "" || rec.stateDir() != "/sandbox/.dc" || rec.privateState() {
		t.Fatalf("record: %+v", rec)
	}
	if rec.RemoteGitDir != "/sandbox/.dc/git" || !pathExists(log.local("/sandbox/.dc/git/HEAD")) {
		t.Fatalf("plain copy git dir: %+v", rec)
	}
	if n := log.all("chmod 700"); n != 0 {
		t.Fatalf("the default directory was made private %d times", n)
	}
	raw, err := os.ReadFile(e.data + "/sandboxes/d1/copy/copy.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "remote_state_dir") {
		t.Fatalf("the record carries the new field: %s", raw)
	}
	fs := log.fakeSandbox
	fs.write(remoteRepo+"/new.txt", "n\n")
	if got := changePaths(pull(t, e, fs, "d1").Changes); got != "A:new.txt" {
		t.Fatalf("changes = %s", got)
	}
	if !pathExists(fs.local("/sandbox/.dc/result.bundle")) {
		t.Fatal("the bundle is not in /sandbox/.dc")
	}
}

// A record written before the field existed means /sandbox/.dc.
func TestStateDirOldRecordResolvesToDefault(t *testing.T) {
	var rec CopyRecord
	if err := json.Unmarshal([]byte(`{"version":1,"name":"o1","remote_dir":"/sandbox/work/x","remote_git_dir":"/sandbox/.dc/git"}`), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.stateDir() != remoteStateDir || rec.privateState() {
		t.Fatalf("old record resolves to %q", rec.stateDir())
	}
	if line := rec.mkStateDirLine(); line != `mkdir -p "$D"` {
		t.Fatalf("old record's mkdir line: %s", line)
	}
	out, err := json.Marshal(&rec)
	if err != nil || strings.Contains(string(out), "remote_state_dir") {
		t.Fatalf("marshal: %s %v", out, err)
	}
}

// A custom directory is created 0700 in the sandbox before anything is
// written there, holds the plain folder's git dir, the upload receipts and
// the bundle, and leaves /sandbox/.dc alone.
func TestStateDirCustomIsPrivateAndUsed(t *testing.T) {
	const dir = "/sandbox/state/s1"
	for _, kind := range []string{"git", "plain"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t)
			if kind == "git" {
				e.initRepo()
			} else {
				writeFile(t, e.project, "notes.md", "a\n")
			}
			rec, log := launchLogged(t, e, "s1", func(o *StageOptions) { o.StateDir = dir })
			if rec.StateDir != dir || rec.stateDir() != dir || !rec.privateState() {
				t.Fatalf("record: %+v", rec)
			}
			mk, up := log.first("chmod 700"), log.first("upload:")
			if mk != 0 || up < 0 || mk > up {
				t.Fatalf("the directory must be made before the first upload: %q", log.events)
			}
			if !strings.Contains(log.events[mk], "umask 077") || !strings.Contains(log.events[mk], dir) {
				t.Fatalf("the mkdir step: %s", log.events[mk])
			}
			if fi, err := os.Stat(log.local(dir)); err != nil || fi.Mode().Perm() != 0o700 {
				t.Fatalf("state dir: %v %v", fi, err)
			}
			if kind == "plain" && (rec.RemoteGitDir != dir+"/git" || !pathExists(log.local(dir+"/git/HEAD"))) {
				t.Fatalf("plain git dir: %+v", rec)
			}
			if len(uploadMarkers(t, log.local(dir))) == 0 || !strings.HasPrefix(uploadMarkers(t, log.local(dir))[0], "uploads/") {
				t.Fatalf("receipts are not under %s: %v", dir, uploadMarkers(t, log.local(dir)))
			}
			log.fakeSandbox.write(remoteRepo+"/new.txt", "n\n")
			if got := changePaths(pull(t, e, log.fakeSandbox, "s1").Changes); got != "A:new.txt" {
				t.Fatalf("changes = %s", got)
			}
			if !pathExists(log.local(dir + "/result.bundle")) {
				t.Fatal("the bundle is not in the state directory")
			}
			if pathExists(log.local("/sandbox/.dc")) {
				t.Fatal("the shared /sandbox/.dc was used")
			}
			if fi, err := os.Stat(log.local(dir)); err != nil || fi.Mode().Perm() != 0o700 {
				t.Fatalf("state dir after the pull: %v %v", fi, err)
			}
			// The record on disk carries it, so a later pull finds it.
			back, err := LoadCopy(e.data, "s1")
			if err != nil || back.StateDir != dir {
				t.Fatalf("loaded: %+v %v", back, err)
			}
		})
	}
}

// A state directory must be a clean absolute path outside the project copy.
func TestStateDirRefusals(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.project, "notes.md", "a\n")
	for name, dir := range map[string]string{
		"relative":       "state",
		"root":           "/",
		"not clean":      "/sandbox/state/../x",
		"is the project": remoteRepo,
		"in the project": remoteRepo + "/.state",
		"holds project":  "/sandbox/work",
	} {
		t.Run(name, func(t *testing.T) {
			opts := e.stageOpts("r1")
			opts.StateDir = dir
			if _, err := Stage(bg, opts); err == nil || !strings.Contains(err.Error(), "state directory") {
				t.Fatalf("Stage accepted %q: %v", dir, err)
			}
		})
	}
	// The shared default spelled out is the default.
	opts := e.stageOpts("r2")
	opts.StateDir = remoteStateDir
	rec, err := Stage(bg, opts)
	if err != nil || rec.StateDir != "" {
		t.Fatalf("explicit default: %+v %v", rec, err)
	}
}

// A refresh takes out the old copy's private state directory with the copy.
func TestStateDirRefreshRemovesTheOldOne(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.project, "notes.md", "a\n")
	rec, fs := launchCopy(t, e, "f1", func(o *StageOptions) { o.StateDir = "/sandbox/state/old" })
	if rec.StateDir != "/sandbox/state/old" || !pathExists(fs.local("/sandbox/state/old")) {
		t.Fatalf("first copy: %+v", rec)
	}
	opts := e.refreshOpts("f1", fs)
	opts.Stage.StateDir = "/sandbox/state/new"
	opts.Force = true
	got, err := Refresh(bg, opts)
	if err != nil || got.StateDir != "/sandbox/state/new" {
		t.Fatalf("refresh: %+v %v", got, err)
	}
	if pathExists(fs.local("/sandbox/state/old")) {
		t.Fatal("the old state directory is still there")
	}
	if fi, err := os.Stat(fs.local("/sandbox/state/new")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("new state dir: %v %v", fi, err)
	}
}
