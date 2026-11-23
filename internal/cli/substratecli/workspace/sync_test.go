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
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

func pushOpts(o *operator, sb sandboxFS) PushOptions {
	return PushOptions{Start: StartOptions{DataDir: o.data, Home: o.home}, Name: "c1", Transport: sb, Label: "before push"}
}

// Through the real relay: the bundle lands in the state directory, the
// write uses the actor's git, and a conflict sends nothing.
func TestPushThroughRelay(t *testing.T) {
	o, sb, res := copyInActor(t)
	write(t, o.project, "src/app.go", "package main // laptop\n", 0o644)
	write(t, o.project, "README.md", "laptop\n", 0o644)
	write(t, sb.local(remoteProject), "README.md", "agent\n", 0o644)
	_, err := Push(context.Background(), pushOpts(o, sb))
	var ce *osw.PushConflictError
	if !errors.As(err, &ce) || len(ce.Paths) != 1 || ce.Paths[0] != "README.md" {
		t.Fatalf("push = %v, want a conflict on README.md", err)
	}
	if got := read(t, sb.local(remoteProject), "src/app.go"); got != "package main\n" {
		t.Fatalf("a refused push wrote app.go: %q", got)
	}
	opts := pushOpts(o, sb)
	opts.Mode = osw.PushTheirs
	out, err := Push(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if out.Checkpoint == "" || out.Result == nil || len(out.Result.Kept) != 1 {
		t.Fatalf("outcome %+v", out)
	}
	if got := read(t, sb.local(remoteProject), "src/app.go"); got != "package main // laptop\n" {
		t.Fatalf("app.go = %q", got)
	}
	if got := read(t, sb.local(remoteProject), "README.md"); got != "agent\n" {
		t.Fatalf("README.md = %q, want the agent's", got)
	}
	if !strings.Contains(out.SendLine("Sent"), "src/app.go (modified)") || strings.Contains(out.SendLine("Sent"), "README") {
		t.Fatalf("send line %q", out.SendLine("Sent"))
	}
	rec, _ := osw.LoadCopy(o.data, "c1")
	if rec.Baseline == res.Baseline {
		t.Fatal("baseline did not move")
	}
	// Undo to the restore point the push took puts the baseline back.
	info, err := Undo(context.Background(), UndoOptions{Exec: sb, Dir: remoteProject, DataDir: o.data, Name: "c1", ID: out.Checkpoint})
	if err != nil || info.Pushes != 1 {
		t.Fatalf("undo = %+v, %v", info, err)
	}
	if rec, _ := osw.LoadCopy(o.data, "c1"); rec.Baseline != res.Baseline {
		t.Fatal("undo left the push in the baseline")
	}
}

type syncRun struct {
	out  bytes.Buffer
	mu   sync.Mutex
	done chan error
}

func (r *syncRun) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.out.Write(p)
}

func (r *syncRun) text() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.out.String()
}

func startSync(ctx context.Context, opts SyncOptions) *syncRun {
	r := &syncRun{done: make(chan error, 1)}
	opts.Out = r
	opts.Debounce, opts.MaxWait, opts.StateEvery = 50*time.Millisecond, 300*time.Millisecond, 50*time.Millisecond
	go func() { r.done <- Sync(ctx, opts) }()
	return r
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func pushes(t *testing.T, o *operator) int {
	log, err := osw.LoadPushLog(o.data, "c1")
	if err != nil {
		t.Fatal(err)
	}
	return len(log)
}

func TestSyncDebounceOneBatch(t *testing.T) {
	o, sb, _ := copyInActor(t)
	ev := make(chan string, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := startSync(ctx, SyncOptions{Push: pushOpts(o, sb), Events: ev, Label: "agent-1"})
	waitFor(t, "the start restore point", func() bool { return strings.Contains(r.text(), "Saved restore point") })
	for i := 0; i < 5; i++ {
		write(t, o.project, "src/app.go", "package main // "+strings.Repeat("x", i)+"\n", 0o644)
	}
	// A burst of saves (events 5 ms apart) is one batch.
	for i := 0; i < 5; i++ {
		ev <- filepath.Join(o.project, "src", "app.go")
		time.Sleep(5 * time.Millisecond)
	}
	waitFor(t, "one batch", func() bool { return pushes(t, o) == 1 })
	time.Sleep(200 * time.Millisecond)
	if n := pushes(t, o); n != 1 {
		t.Fatalf("%d batches for one burst, want 1", n)
	}
	if got := read(t, sb.local(remoteProject), "src/app.go"); got != "package main // xxxx\n" {
		t.Fatalf("app.go = %q", got)
	}
	cancel()
	if err := <-r.done; err != nil {
		t.Fatal(err)
	}
}

func TestSyncSkipsIgnoredAndSecrets(t *testing.T) {
	o, sb, _ := copyInActor(t)
	ev := make(chan string, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := startSync(ctx, SyncOptions{Push: pushOpts(o, sb), Events: ev, Label: "agent-1"})
	waitFor(t, "the start", func() bool { return strings.Contains(r.text(), "Saved restore point") })
	for i := 0; i < 2; i++ {
		ev <- filepath.Join(o.project, ".git", "index")
		ev <- filepath.Join(o.project, "web", "node_modules", "x.js")
	}
	write(t, o.project, "debug.log", "noise\n", 0o644)
	write(t, o.project, "notes.md", "n\n", 0o644)
	ev <- filepath.Join(o.project, "debug.log")
	ev <- filepath.Join(o.project, "notes.md")
	waitFor(t, "the batch", func() bool { return pushes(t, o) == 1 })
	ev <- filepath.Join(o.project, ".git", "HEAD")
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-r.done
	txt := r.text()
	for _, want := range []string{"Not synced: .git (git internals).", "Not synced: web/node_modules (package cache).", "Held back: .env", "Synced 1 change"} {
		if strings.Count(txt, want) != 1 {
			t.Fatalf("want %q once in:\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "debug.log") || pushes(t, o) != 1 {
		t.Fatalf("ignored file synced or extra batch:\n%s", txt)
	}
	if got := read(t, sb.local(remoteProject), "notes.md"); got != "n\n" {
		t.Fatalf("notes.md = %q", got)
	}
}

func TestSyncSuspendedWaitsAndGoneStops(t *testing.T) {
	o, sb, _ := copyInActor(t)
	var state atomic.Value
	state.Store(SyncActorSuspended)
	var calls atomic.Int32
	ev := make(chan string, 4)
	r := startSync(context.Background(), SyncOptions{Push: pushOpts(o, sb), Events: ev, State: func(context.Context) (string, error) {
		calls.Add(1)
		return state.Load().(string), nil
	}})
	waitFor(t, "the start", func() bool { return strings.Contains(r.text(), "Saved restore point") })
	write(t, o.project, "notes.md", "n\n", 0o644)
	ev <- filepath.Join(o.project, "notes.md")
	waitFor(t, "the wait line", func() bool { return strings.Contains(r.text(), "suspended; changes wait") })
	waitFor(t, "a state check", func() bool { return calls.Load() >= 3 })
	if pushes(t, o) != 0 {
		t.Fatal("pushed into a suspended agent")
	}
	state.Store(SyncActorRunning)
	waitFor(t, "the batch after the wake", func() bool { return pushes(t, o) == 1 })
	state.Store(SyncActorGone)
	write(t, o.project, "notes.md", "m\n", 0o644)
	ev <- filepath.Join(o.project, "notes.md")
	if err := <-r.done; !errors.Is(err, ErrSyncActorGone) {
		t.Fatalf("sync ended with %v, want gone", err)
	}
}

func TestSyncStopsCleanNoGoroutines(t *testing.T) {
	o, sb, _ := copyInActor(t)
	sb.HTTP.CloseIdleConnections()
	time.Sleep(100 * time.Millisecond)
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	r := startSync(ctx, SyncOptions{Push: pushOpts(o, sb)})
	waitFor(t, "the start", func() bool { return strings.Contains(r.text(), "Saved restore point") })
	write(t, o.project, "src/new.go", "package main // new\n", 0o644)
	waitFor(t, "the watcher's batch", func() bool { return pushes(t, o) == 1 })
	cancel()
	if err := <-r.done; err != nil {
		t.Fatal(err)
	}
	waitFor(t, "goroutines to end", func() bool {
		sb.HTTP.CloseIdleConnections()
		return runtime.NumGoroutine() <= before
	})
}
