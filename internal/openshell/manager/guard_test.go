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

package manager

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/nestguard"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// fakeGuard records guard runs; a running guard can be made to detect.
type fakeGuard struct {
	mu      sync.Mutex
	running map[string]nestguard.Options
	runs    []nestguard.Options
}

func newFakeGuard() *fakeGuard { return &fakeGuard{running: map[string]nestguard.Options{}} }

func (g *fakeGuard) run(ctx context.Context, opts nestguard.Options) error {
	g.mu.Lock()
	g.running[opts.Root] = opts
	g.runs = append(g.runs, opts)
	g.mu.Unlock()
	<-ctx.Done()
	g.mu.Lock()
	delete(g.running, opts.Root)
	g.mu.Unlock()
	return nil
}

func (g *fakeGuard) active(root string) (nestguard.Options, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	o, ok := g.running[root]
	return o, ok
}

func (g *fakeGuard) waitActive(t *testing.T, root string, want bool) nestguard.Options {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		o, ok := g.active(root)
		if ok == want {
			return o
		}
		if time.Now().After(deadline) {
			t.Fatalf("guard active for %s = %t, want %t", root, ok, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestGuardRunsWhileMountedSandboxIsReady(t *testing.T) {
	e := newEnv(t, nil)
	// A repository that exists before the session is in the baseline.
	if err := os.MkdirAll(filepath.Join(e.project, "vendor", "lib", ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "guarded"})
	opts := e.guard.waitActive(t, e.project, true)
	if !slices.Equal(opts.Baseline.Repos, []string{"vendor/lib"}) {
		t.Fatalf("guard baseline = %+v", opts.Baseline)
	}

	at := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	opts.OnDetect(nestguard.Detection{Kind: nestguard.KindRepository, Dir: "src/evil", Quarantined: "src/evil/.git.defenseclaw-quarantine-x", At: at})
	opts.OnDetect(nestguard.Detection{Kind: nestguard.KindGitlink, Dir: "third_party/sub", At: at})

	got, err := e.m.Get(context.Background(), sb.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.NestedRepos) != 2 || got.NestedRepos[0].Path != "src/evil/.git" || got.NestedRepos[0].Quarantined == "" ||
		got.NestedRepos[1].Kind != "gitlink" {
		t.Fatalf("nested repos = %+v", got.NestedRepos)
	}
	e.tel.mu.Lock()
	var quarantines, findings int
	for _, w := range e.tel.workspace {
		if w.Operation == audit.SandboxWorkspaceQuarantine {
			quarantines++
			if !slices.Equal(w.Paths, []string{"src/evil/.git"}) || w.Sandbox.Name != sb.Name {
				t.Errorf("quarantine telemetry = %+v", w)
			}
		}
	}
	for _, f := range e.tel.findings {
		if f.Kind == audit.SandboxFindingNestedRepo {
			findings++
		}
	}
	e.tel.mu.Unlock()
	if quarantines != 1 || findings != 2 {
		t.Fatalf("telemetry: %d quarantines, %d nested-repo findings; want 1 and 2", quarantines, findings)
	}
	var feed []sandboxapi.ActivityEvent
	for _, ev := range e.m.ActivitySince(0, sb.Name) {
		if ev.Kind == sandboxapi.ActivityFinding && ev.Reason == sandboxapi.ReasonNestedRepo {
			feed = append(feed, ev)
		}
	}
	if len(feed) != 2 || !strings.Contains(feed[0].Message, "quarantined") {
		t.Fatalf("feed = %+v", feed)
	}

	// Stopping ends the guard; a start takes a fresh baseline for the new
	// session, which drops the previous session's detections.
	if _, err := e.m.Stop(context.Background(), sb.Name); err != nil {
		t.Fatal(err)
	}
	e.guard.waitActive(t, e.project, false)
	if err := os.MkdirAll(filepath.Join(e.project, "kept", ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Start(context.Background(), sb.Name, sandboxapi.StartRequest{}); err != nil {
		t.Fatal(err)
	}
	opts = e.guard.waitActive(t, e.project, true)
	if !slices.Equal(opts.Baseline.Repos, []string{"kept", "vendor/lib"}) {
		t.Fatalf("second session baseline = %+v", opts.Baseline)
	}
	if got, _ := e.m.Get(context.Background(), sb.Name); len(got.NestedRepos) != 0 {
		t.Fatalf("detections carried into the new session: %+v", got.NestedRepos)
	}

	if _, err := e.m.Delete(context.Background(), sb.Name, sandboxapi.DeleteRequest{}); err != nil {
		t.Fatal(err)
	}
	e.guard.waitActive(t, e.project, false)
}

func TestGuardSurvivesDaemonRestartWithItsBaseline(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "restart"})
	e.guard.waitActive(t, e.project, true)
	e.stop()
	e.guard.waitActive(t, e.project, false)

	// The agent planted a repository while the daemon was down: it is not
	// in the persisted baseline, so the restarted guard quarantines it.
	if err := os.MkdirAll(filepath.Join(e.project, "planted", ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.m = e.newManager()
	e.run()
	opts := e.guard.waitActive(t, e.project, true)
	if slices.Contains(opts.Baseline.Repos, "planted") {
		t.Fatalf("the restarted guard re-took its baseline: %+v", opts.Baseline)
	}
	_ = sb
}

func TestGuardSkipsCopyMode(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Workdir.Mode = config.OpenShellWorkdirCopy })
	e.run()
	e.create(sandboxapi.CreateRequest{Name: "copied", Copy: true})
	time.Sleep(50 * time.Millisecond)
	if _, ok := e.guard.active(e.project); ok {
		t.Fatal("the guard runs for a copy-mode sandbox")
	}
}

// TestGuardDetectionLeavesRecordCopiesAlone: the guard reports on its own
// goroutine while other paths (the watch cursor, lifecycle, unblocks) copy
// the record under the lock and save the copy after releasing it. A
// detection must not write through state those copies share; with -race the
// concurrent loop below also catches it.
func TestGuardDetectionLeavesRecordCopiesAlone(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "copies"})
	opts := e.guard.waitActive(t, e.project, true)
	b, err := e.m.box(sb.Name)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	detect := func(i int) {
		dir := "nested/" + strconv.Itoa(i)
		opts.OnDetect(nestguard.Detection{Kind: nestguard.KindRepository, Dir: dir, Quarantined: dir + "/.git.q", At: at})
	}

	e.m.mu.Lock()
	before := b.rec
	e.m.mu.Unlock()
	detect(0)
	if before.Guard == nil || len(before.Guard.Detections) != 0 {
		t.Fatalf("a detection changed a record copy taken before it: %+v", before.Guard)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 32 {
			if err := e.m.saveCursor(b, "cursor-"+strconv.Itoa(i)); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for i := 1; i <= 32; i++ {
		detect(i)
	}
	wg.Wait()

	got, err := e.m.Get(context.Background(), sb.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.NestedRepos) != 33 || got.NestedRepos[32].Path != "nested/32/.git" {
		t.Fatalf("nested repos = %+v", got.NestedRepos)
	}
}
