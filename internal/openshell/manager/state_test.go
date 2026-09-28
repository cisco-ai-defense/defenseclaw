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
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/nestguard"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// loadRecord reads one sandbox's record from disk.
func loadRecord(t *testing.T, e *harnessEnv, name string) *record {
	t.Helper()
	recs, errs := e.m.records.loadAll()
	if len(errs) > 0 {
		t.Fatalf("load records: %v", errs)
	}
	for _, r := range recs {
		if r.Name == name {
			return r
		}
	}
	return nil
}

// TestRecordSavesNeverGoBack pins that concurrent writers of a sandbox
// record leave the newest state on disk. The first write stalls right
// before it reaches the file while a second writer changes the record and
// saves it; a write that took its copy before the change must not land
// last.
func TestRecordSavesNeverGoBack(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "savebox"})
	e.m.mu.Lock()
	b := e.m.boxes["savebox"]
	e.m.mu.Unlock()
	stalled, second := make(chan struct{}), make(chan struct{})
	var writes atomic.Int32
	e.m.records.beforeWrite = func(string) {
		if writes.Add(1) == 1 {
			close(stalled)
			select {
			case <-second:
			case <-time.After(300 * time.Millisecond):
			}
		}
	}
	first := make(chan error, 1)
	go func() { first <- e.m.saveCursor(b, "v1:old") }()
	<-stalled
	go func() {
		if err := e.m.saveCursor(b, "v1:new"); err != nil {
			t.Error(err)
		}
		close(second)
	}()
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	<-second
	got := loadRecord(t, e, "savebox")
	if got == nil {
		t.Fatal("the record is gone")
	}
	if got.Cursor != "v1:new" {
		t.Fatalf("record on disk has cursor %q, want the newest, v1:new", got.Cursor)
	}
}

// TestRecordTooLargeToReadBackIsNotWritten pins that the daemon never
// writes a record a restart would skip: the last one that fits stays.
func TestRecordTooLargeToReadBackIsNotWritten(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "bigbox"})
	e.m.mu.Lock()
	b := e.m.boxes["bigbox"]
	b.rec.Warnings = append(slices.Clip(b.rec.Warnings), strings.Repeat("w", recordMaxBytes))
	e.m.mu.Unlock()
	if err := e.m.saveRecord(b); err == nil {
		t.Fatal("a record over the read limit was written")
	}
	got := loadRecord(t, e, "bigbox")
	if got == nil || slices.ContainsFunc(got.Warnings, func(w string) bool { return len(w) == recordMaxBytes }) {
		t.Fatal("the record on disk is not the last one that fits")
	}
}

// TestSandboxWithoutRecordFailsClosed pins that a live sandbox the daemon
// has no readable record of is not rebuilt under the default policy: its
// egress credential stays unregistered and it cannot be started, and its
// labels are never written as its record.
func TestSandboxWithoutRecordFailsClosed(t *testing.T) {
	e := newEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{Name: "lostbox", Profile: "balanced"})
	live, _ := e.client.GetSandbox(context.Background(), sb.Name)
	proxy, _ := url.Parse(live.Spec.Environment["HTTPS_PROXY"])
	pass, _ := proxy.User.Password()
	p, _ := e.m.records.path("lostbox")
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A new daemon process over the same data dir and gateway.
	e.m = e.newManager()
	e.run()
	eventually(t, "startup reconcile", func() bool {
		st, _ := e.m.Status(context.Background())
		return !st.LastReconcile.IsZero()
	})
	if pr, ok := e.m.creds.Authenticate(proxy.User.Username(), pass); ok {
		t.Fatalf("the sandbox without a record got egress under the default policy: %+v", pr)
	}
	got, err := e.m.Get(context.Background(), "lostbox")
	if err != nil || !slices.ContainsFunc(got.Warnings, func(w string) bool { return strings.Contains(w, "no readable record") }) {
		t.Fatalf("sandbox = %+v, %v", got, err)
	}
	if _, err := e.m.Stop(context.Background(), "lostbox"); err != nil {
		t.Fatal(err)
	}
	_, err = e.m.Start(context.Background(), "lostbox", sandboxapi.StartRequest{})
	wantCode(t, err, sandboxapi.CodeConflict)
	if data, _ := os.ReadFile(p); string(data) != "{not json" {
		t.Fatalf("the unreadable record was replaced by the labels: %q", data)
	}
	// Delete still releases it.
	if _, err := e.m.Delete(context.Background(), "lostbox", sandboxapi.DeleteRequest{}); err != nil {
		t.Fatal(err)
	}
}

// TestUnrecordedSandboxDeletedElsewhereKeepsItsSnapshot pins that a
// sandbox adopted without a record and then deleted outside DefenseClaw
// keeps its snapshot reachable, across restarts too: a retained record
// needs no run flags.
func TestUnrecordedSandboxDeletedElsewhereKeepsItsSnapshot(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "lostsnap"})
	p, _ := e.m.records.path("lostsnap")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	e.m = e.newManager()
	if err := e.m.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.DeleteSandbox(ctx, "lostsnap"); err != nil {
		t.Fatal(err)
	}
	if err := e.m.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if rec := loadRecord(t, e, "lostsnap"); rec == nil || !rec.Retained {
		t.Fatalf("retained record = %+v", rec)
	}
	e.m = e.newManager()
	if _, err := e.m.Undo(ctx, "lostsnap", sandboxapi.UndoRequest{}); err != nil {
		t.Fatalf("undo after a restart: %v", err)
	}
}

// TestGuardBaselineIsBounded pins that a project listing a huge number of
// gitlinks cannot push its sandbox's record past what a restart reads
// back: the baseline is cut (and marked truncated), the project's own
// repository kept.
func TestGuardBaselineIsBounded(t *testing.T) {
	e := newEnv(t, nil)
	if err := os.MkdirAll(filepath.Join(e.project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	links := make([]string, 0, 200_000)
	for i := range 200_000 {
		links = append(links, fmt.Sprintf("third_party/%s/module-%06d", strings.Repeat("x", 40), i))
	}
	e.m.opts.GuardGitlinks = func(context.Context, string) ([]string, error) { return links, nil }
	e.create(sandboxapi.CreateRequest{Name: "linkbox"})
	got := loadRecord(t, e, "linkbox")
	if got == nil || got.Guard == nil {
		t.Fatalf("record = %v", got)
	}
	if !got.Guard.Baseline.Truncated || len(got.Guard.Baseline.Gitlinks) >= len(links) || !slices.Contains(got.Guard.Baseline.Repos, ".") {
		t.Fatalf("baseline kept %d gitlinks, truncated %t, repos %v", len(got.Guard.Baseline.Gitlinks),
			got.Guard.Baseline.Truncated, got.Guard.Baseline.Repos)
	}
}

func TestBoundBaseline(t *testing.T) {
	small := nestguard.Baseline{Repos: []string{"vendor/a", "."}, Gitlinks: []string{"sub"}}
	if got := boundBaseline(small, 1<<10); !slices.Equal(got.Repos, small.Repos) || got.Truncated {
		t.Fatalf("a baseline within the limit changed: %+v", got)
	}
	big := nestguard.Baseline{Repos: []string{"a/" + strings.Repeat("r", 100), ".", "b/" + strings.Repeat("r", 100)},
		Gitlinks: []string{strings.Repeat("g", 100)}}
	got := boundBaseline(big, 150)
	if !got.Truncated || !slices.Equal(got.Repos, []string{".", big.Repos[0]}) || len(got.Gitlinks) != 0 {
		t.Fatalf("bounded baseline = %+v", got)
	}
}

// TestSaveAfterRemoveKeepsTheRecordGone pins that a write racing the
// removal of a deleted sandbox's record cannot bring the record back.
func TestSaveAfterRemoveKeepsTheRecordGone(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "gonebox"})
	e.m.mu.Lock()
	b := e.m.boxes["gonebox"]
	e.m.mu.Unlock()
	if err := e.m.removeRecord(b); err != nil {
		t.Fatal(err)
	}
	if err := e.m.saveCursor(b, "v1:late"); err != nil {
		t.Fatal(err)
	}
	p, _ := e.m.records.path("gonebox")
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("the removed record is back: %v", err)
	}
}

// TestRemoveSandboxState pins the local half of a delete teardown runs for
// a sandbox it deleted on the gateway while no daemon runs: the binding,
// the run files, the record and the directory go; a malformed record stays
// where it is, with everything it would name.
func TestRemoveSandboxState(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "offbox"})
	e.stop()
	e.m.mu.Lock()
	bindingID := e.m.boxes[sb.Name].rec.BindingID
	e.m.mu.Unlock()
	if _, err := e.store.Get(bindingID); err != nil {
		t.Fatalf("binding before: %v", err)
	}
	if err := RemoveSandboxState(context.Background(), e.dataDir, sb.Name); err != nil {
		t.Fatal(err)
	}
	if got := RecordedSandboxes(e.dataDir); len(got) != 0 {
		t.Fatalf("records after = %+v", got)
	}
	if _, err := e.store.Get(bindingID); err == nil {
		t.Fatal("the binding survived")
	}
	if _, err := os.Stat(filepath.Join(e.dataDir, "sandboxes", sb.Name)); !os.IsNotExist(err) {
		t.Fatalf("the sandbox directory is still there: %v", err)
	}

	bad := filepath.Join(e.dataDir, "sandboxes", recordDirName, "badbox.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSandboxState(context.Background(), e.dataDir, "badbox"); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("malformed record: %v", err)
	}
	if _, err := os.Stat(bad); err != nil {
		t.Fatalf("the malformed record was removed: %v", err)
	}
	if err := RemoveSandboxState(context.Background(), e.dataDir, "../escape"); err == nil {
		t.Fatal("an invalid name was accepted")
	}
}

// TestOrphanedSnapshotIsFoundAndRemoved pins that a pre-session snapshot
// an interrupted create or delete left without a record (and without any
// sandbox directory) is listed as orphaned data and removed with it.
func TestOrphanedSnapshotIsFoundAndRemoved(t *testing.T) {
	dataDir := t.TempDir()
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "README.md"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := workspace.Snapshot(ctx, workspace.SnapshotOptions{Project: project, Name: "lostsnap", DataDir: dataDir}); err != nil {
		t.Fatal(err)
	}
	if got := OrphanedSandboxData(dataDir); !slices.Equal(got, []string{"lostsnap"}) {
		t.Fatalf("orphans = %v, want the snapshot's sandbox", got)
	}
	if err := RemoveOrphanedSandboxData(dataDir, "lostsnap"); err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.LoadSnapshot(dataDir, "lostsnap"); !errors.Is(err, workspace.ErrSnapshotNotFound) {
		t.Fatalf("the orphaned snapshot is left: %v", err)
	}
	if got := OrphanedSandboxData(dataDir); len(got) != 0 {
		t.Fatalf("orphans after removal = %v", got)
	}
}
