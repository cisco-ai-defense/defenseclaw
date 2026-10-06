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

package manager

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/nestguard"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
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

// Concurrent writers of a sandbox record leave the newest state on disk: a
// write that took its copy before a change must not land last.
func TestRecordSavesNeverGoBack(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "savebox"})
	b := e.boxOf("savebox")
	stalled, second := make(chan struct{}), make(chan struct{})
	var writes atomic.Int32
	e.m.records.beforeWrite = func(string) {
		if writes.Add(1) == 1 { // the first write stalls right before it reaches the file
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
	must(t, <-first)
	<-second
	if got := loadRecord(t, e, "savebox"); got == nil || got.Cursor != "v1:new" {
		t.Fatalf("record on disk = %+v, want the newest cursor, v1:new", got)
	}
}

// The daemon never writes a record a restart would skip: the last one that
// fits stays. A write racing the removal of a deleted sandbox's record
// cannot bring it back.
func TestRecordWritesStayReadable(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "bigbox"})
	b := e.boxOf("bigbox")
	e.m.mu.Lock()
	b.rec.Warnings = append(slices.Clip(b.rec.Warnings), strings.Repeat("w", recordMaxBytes))
	e.m.mu.Unlock()
	if err := e.m.saveRecord(b); err == nil {
		t.Fatal("a record over the read limit was written")
	}
	if got := loadRecord(t, e, "bigbox"); got == nil || slices.ContainsFunc(got.Warnings, func(w string) bool { return len(w) == recordMaxBytes }) {
		t.Fatal("the record on disk is not the last one that fits")
	}
	must(t, e.m.removeRecord(b))
	must(t, e.m.saveCursor(b, "v1:late"))
	if p, _ := e.m.records.path("bigbox"); fileExists(p) {
		t.Fatal("the removed record is back")
	}
}

// A live sandbox without a readable record gets no egress and no start
// under the default policy, and its labels never become its record.
func TestSandboxWithoutRecordFailsClosed(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "lostbox", Profile: "balanced"})
	live, _ := e.client.GetSandbox(t.Context(), "lostbox")
	proxy, _ := url.Parse(live.Spec.Environment["HTTPS_PROXY"])
	pass, _ := proxy.User.Password()
	p, _ := e.m.records.path("lostbox")
	must(t, os.WriteFile(p, []byte("{not json"), 0o600))
	e.restartDaemon()
	if pr, ok := e.m.creds.Authenticate(proxy.User.Username(), pass); ok {
		t.Fatalf("the sandbox without a record got egress under the default policy: %+v", pr)
	}
	if got := e.get("lostbox"); !slices.ContainsFunc(got.Warnings, func(w string) bool { return strings.Contains(w, "no readable record") }) {
		t.Fatalf("sandbox = %+v", got)
	}
	e.stopBox("lostbox")
	_, err := e.m.Start(t.Context(), "lostbox", sandboxapi.StartRequest{})
	wantCode(t, err, sandboxapi.CodeConflict)
	if data, _ := os.ReadFile(p); string(data) != "{not json" {
		t.Fatalf("the unreadable record was replaced by the labels: %q", data)
	}
	e.deleteBox("lostbox", sandboxapi.DeleteRequest{})
}

// A sandbox adopted without a record and then deleted outside DefenseClaw
// keeps its snapshot reachable, across restarts too: a retained record needs
// no run flags.
func TestUnrecordedSandboxDeletedElsewhereKeepsItsSnapshot(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "lostsnap"})
	p, _ := e.m.records.path("lostsnap")
	must(t, os.Remove(p))
	e.m = e.newManager()
	must(t, e.m.Reconcile(t.Context()))
	_, err := e.client.DeleteSandbox(t.Context(), "lostsnap")
	must(t, err)
	must(t, e.m.Reconcile(t.Context()))
	if rec := loadRecord(t, e, "lostsnap"); rec == nil || !rec.Retained {
		t.Fatalf("retained record = %+v", rec)
	}
	e.m = e.newManager()
	if _, err := e.m.Undo(t.Context(), "lostsnap", sandboxapi.UndoRequest{}); err != nil {
		t.Fatalf("undo after a restart: %v", err)
	}
}

// A project listing a huge number of gitlinks cannot push its sandbox's
// record past what a restart reads back: the baseline is cut (and marked
// truncated), the project's own repository kept.
func TestGuardBaselineIsBounded(t *testing.T) {
	e := newEnv(t, nil)
	must(t, os.MkdirAll(filepath.Join(e.project, ".git"), 0o755))
	links := make([]string, 0, 200_000)
	for i := range 200_000 {
		links = append(links, fmt.Sprintf("third_party/%s/module-%06d", strings.Repeat("x", 40), i))
	}
	e.m.opts.GuardGitlinks = func(context.Context, string) ([]string, error) { return links, nil }
	e.create(sandboxapi.CreateRequest{Name: "linkbox"})
	got := loadRecord(t, e, "linkbox")
	if got == nil || got.Guard == nil || !got.Guard.Baseline.Truncated || len(got.Guard.Baseline.Gitlinks) >= len(links) ||
		!slices.Contains(got.Guard.Baseline.Repos, ".") {
		t.Fatalf("record = %+v", got)
	}
	small := nestguard.Baseline{Repos: []string{"vendor/a", "."}, Gitlinks: []string{"sub"}}
	if got := boundBaseline(small, 1<<10); !slices.Equal(got.Repos, small.Repos) || got.Truncated {
		t.Fatalf("a baseline within the limit changed: %+v", got)
	}
	big := nestguard.Baseline{Repos: []string{"a/" + strings.Repeat("r", 100), ".", "b/" + strings.Repeat("r", 100)}, Gitlinks: []string{strings.Repeat("g", 100)}}
	if got := boundBaseline(big, 150); !got.Truncated || !slices.Equal(got.Repos, []string{".", big.Repos[0]}) || len(got.Gitlinks) != 0 {
		t.Fatalf("bounded baseline = %+v", got)
	}
}

// The local half of a delete teardown runs for a sandbox deleted on the
// gateway while no daemon runs: the binding, the run files, the record and
// the directory go; a malformed record stays, with everything it would name.
func TestRemoveSandboxState(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	e.create(sandboxapi.CreateRequest{Name: "offbox"})
	e.stop()
	id := e.boxOf("offbox").rec.BindingID
	_, err := e.store.Get(id)
	must(t, err)
	must(t, RemoveSandboxState(t.Context(), e.dataDir, "offbox"))
	if _, err := e.store.Get(id); err == nil || len(RecordedSandboxes(e.dataDir)) != 0 || fileExists(filepath.Join(e.dataDir, "sandboxes", "offbox")) {
		t.Fatalf("left after the teardown: binding %v, records %v, directory %v", err == nil, RecordedSandboxes(e.dataDir),
			fileExists(filepath.Join(e.dataDir, "sandboxes", "offbox")))
	}
	bad := filepath.Join(e.dataDir, "sandboxes", recordDirName, "badbox.json")
	must(t, os.WriteFile(bad, []byte("{not json"), 0o600))
	if err := RemoveSandboxState(t.Context(), e.dataDir, "badbox"); err == nil || !strings.Contains(err.Error(), "malformed") || !fileExists(bad) {
		t.Fatalf("malformed record: %v", err)
	}
	if err := RemoveSandboxState(t.Context(), e.dataDir, "../escape"); err == nil {
		t.Fatal("an invalid name was accepted")
	}
}

// A sandbox deleted outside DefenseClaw is garbage-collected (binding,
// providers, mount), while its snapshot stays reachable for undo, review and
// delete.
func TestReconcileGarbageCollectsDeletedSandboxes(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "gonebox"})
	token := e.ingressToken("gonebox")
	_, err := e.client.DeleteSandbox(t.Context(), "gonebox")
	must(t, err)
	must(t, e.m.Reconcile(t.Context()))
	if _, err := e.store.Match(token); !errors.Is(err, sandboxauth.ErrUnauthenticated) || len(e.providers()) != 0 || !slices.Contains(e.ws.released, "gonebox") {
		t.Fatalf("left: binding %v, providers %v, released %v", err, e.providers(), e.ws.released)
	}
	if slices.Contains(e.ws.deleted, "gonebox") {
		t.Fatal("reconcile deleted the snapshot of a sandbox the user deleted elsewhere")
	}
	must(t, e.m.Reconcile(t.Context())) // a second pass leaves the retained box alone
	if got := e.get("gonebox"); got.Phase != "deleted" || got.Snapshot == nil {
		t.Fatalf("retained box = %+v", got)
	}
	if _, err := e.m.Undo(t.Context(), "gonebox", sandboxapi.UndoRequest{}); err != nil {
		t.Fatalf("undo of the retained box: %v", err)
	}
	e.deleteBox("gonebox", sandboxapi.DeleteRequest{})
	if _, err := e.m.Get(t.Context(), "gonebox"); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) || !slices.Contains(e.ws.deleted, "gonebox") {
		t.Fatalf("box survived its delete: %v", err)
	}
	if len(where(&e.tel.mu, &e.tel.lifecycle, func(ev audit.SandboxLifecycleEvent) bool {
		return ev.Sandbox.Name == "gonebox" && ev.Trigger == audit.SandboxTriggerReconcile && ev.Sandbox.Phase == audit.SandboxPhaseDeleted
	})) == 0 {
		t.Fatal("no reconcile deleted lifecycle")
	}
}

// A reconcile revokes this data dir's bindings and providers of sandboxes
// that are gone, and adopts a labelled sandbox without a record as an orphan,
// which cannot start but can be deleted; another data dir's are left alone.
func TestReconcileRevokesStaleStateAndAdoptsOrphans(t *testing.T) {
	e := newEnv(t, nil)
	stale, _, err := e.store.Mint(sandboxauth.Spec{SandboxName: "stale", Connector: "claudecode", Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy}})
	must(t, err)
	for _, p := range []*openshell.Provider{
		{Name: "stale-ingress", Type: "defenseclaw-ingress", Labels: map[string]string{LabelManaged: "true", LabelOwner: testOwner, LabelSandbox: "stale"}},
		{Name: "someone-else", Type: "generic", Labels: map[string]string{LabelManaged: "true", LabelOwner: "ffffffffffffffff", LabelSandbox: "x"}},
	} {
		_, err := e.client.CreateProvider(t.Context(), p)
		must(t, err)
	}
	for name, labels := range map[string]map[string]string{
		"orphanbox": {LabelManaged: "true", LabelOwner: testOwner, LabelHarness: "claudecode", LabelProfile: "open"},
		"otherdata": {LabelManaged: "true", LabelOwner: "ffffffffffffffff"},
	} {
		_, err := e.client.CreateSandbox(t.Context(), name, &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{Labels: labels})
		must(t, err)
	}
	must(t, e.m.Reconcile(t.Context()))
	if _, err := e.store.Get(stale.ID); !errors.Is(err, sandboxauth.ErrNotFound) || !slices.Equal(e.providers(), []string{"someone-else"}) {
		t.Fatalf("stale binding: %v, providers %v", err, e.providers())
	}
	if list, _ := e.m.List(t.Context()); len(list) != 1 || list[0].Name != "orphanbox" || !list[0].Orphaned {
		t.Fatalf("list = %+v", list)
	}
	if _, err := e.m.Start(t.Context(), "orphanbox", sandboxapi.StartRequest{}); !sandboxapi.IsCode(err, sandboxapi.CodeConflict) {
		t.Fatalf("start orphan: %v", err)
	}
	e.deleteBox("orphanbox", sandboxapi.DeleteRequest{})
	if _, err := e.client.GetSandbox(t.Context(), "otherdata"); err != nil {
		t.Fatalf("foreign sandbox touched: %v", err)
	}
}

// A new daemon process over the same data dir and gateway recovers the
// proxy credential, republishes the lifecycle, keeps sandbox-scoped unblocks
// and watches again.
func TestRestartRecoversState(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "survivor"})
	_, err := e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "webhook.site", Sandbox: "survivor"})
	must(t, err)
	got, _ := e.client.GetSandbox(t.Context(), "survivor")
	proxy, _ := url.Parse(got.Spec.Environment["HTTPS_PROXY"])
	pass, _ := proxy.User.Password()
	e.tel.lifecycle = nil
	e.m = e.newManager()
	if _, ok := e.m.creds.Authenticate(proxy.User.Username(), pass); ok {
		t.Fatal("credential known before reconcile")
	}
	e.restartDaemon()
	if p, ok := e.m.creds.Authenticate(proxy.User.Username(), pass); !ok || p.SandboxName != "survivor" {
		t.Fatalf("credential not recovered: %+v %v", p, ok)
	}
	if len(where(&e.tel.mu, &e.tel.lifecycle, func(ev audit.SandboxLifecycleEvent) bool {
		return ev.Sandbox.Name == "survivor" && ev.Trigger == audit.SandboxTriggerReconcile && ev.Sandbox.Phase == audit.SandboxPhaseReady && ev.PreviousPhase == ""
	})) == 0 {
		t.Fatalf("lifecycle = %+v", e.tel.lifecycle)
	}
	if len(e.m.unblocks.List()) != 1 {
		t.Fatalf("unblocks = %v", e.m.unblocks.List())
	}
	e.watch.waitStarted(t, "survivor")
}

func TestWatcherEventsAndGC(t *testing.T) {
	e := liveEnv(t, "watchbox", nil)
	e.watch.push(t, "watchbox", stream.Event{Kind: stream.KindStatus, Status: &stream.Status{Phase: openshell.PhaseStopped}})
	eventually(t, "stopped lifecycle", func() bool {
		phases := e.tel.phases("watchbox")
		return phases[len(phases)-1] == audit.SandboxPhaseStopped
	})
	// The sandbox disappears; the watcher reports it and the manager releases everything.
	_, err := e.client.DeleteSandbox(t.Context(), "watchbox")
	must(t, err)
	e.watch.end("watchbox", stream.ErrSandboxNotFound)
	eventually(t, "garbage collection", func() bool {
		got, err := e.m.Get(t.Context(), "watchbox")
		// The record is written last; a read racing the write is retried.
		recs, errs := e.m.records.loadAll()
		return err == nil && got.Phase == "deleted" && len(errs) == 0 && slices.ContainsFunc(recs, func(r *record) bool { return r.Name == "watchbox" && r.Retained })
	})
	if names := e.providers(); len(names) != 0 {
		t.Fatalf("providers left: %v", names)
	}
}

// Sandboxes created before the data dir's owner id changed (images.json was
// lost) stay DefenseClaw's: loaded, kept by a reconcile, deletable.
func TestSandboxesOfAnEarlierOwnerStayManaged(t *testing.T) {
	e := newEnv(t, nil)
	must(t, newRecordStore(e.dataDir).save(&record{Name: "earlier", Owner: "ffffffffffffffff"}))
	must(t, os.WriteFile(filepath.Join(e.dataDir, "sandboxes", "manager", "broken.json"), []byte("{"), 0o600))
	m := e.newManager()
	m.mu.Lock()
	b := m.boxes["earlier"]
	if len(m.boxes) != 1 || b == nil || m.ownerOf(b.rec) != "ffffffffffffffff" {
		t.Errorf("boxes = %v", m.boxes)
	}
	m.mu.Unlock()

	e = newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "oldowner"})
	e.owner = "fedcba9876543210"
	e.m = e.newManager()
	must(t, e.m.Reconcile(t.Context()))
	if _, err := e.store.Lookup("oldowner"); err != nil {
		t.Fatalf("reconcile revoked the binding of the running sandbox: %v", err)
	}
	if list, err := e.m.List(t.Context()); err != nil || len(list) != 1 || list[0].Name != "oldowner" || list[0].Phase != "ready" {
		t.Fatalf("list = %+v, %v", list, err)
	}
	e.deleteBox("oldowner", sandboxapi.DeleteRequest{})
	assertNothingLeft(t, e)
}

// A reconcile pass that listed a sandbox before it was deleted and recreated
// under the same name leaves the new sandbox's state alone.
func TestGarbageCollectionSkipsReplacedBoxes(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "samename"})
	stale := e.boxOf("samename")
	if !e.m.current(stale) {
		t.Fatal("live box not current")
	}
	e.deleteBox("samename", sandboxapi.DeleteRequest{})
	e.create(sandboxapi.CreateRequest{Name: "samename"})
	if e.m.current(stale) {
		t.Fatal("a deleted box is still current")
	}
	released := len(e.ws.released)
	e.m.reconcileOne(t.Context(), "samename")
	if len(e.ws.released) != released {
		t.Fatal("reconciling a live sandbox released its mount")
	}
	if _, err := e.store.Lookup("samename"); err != nil {
		t.Fatalf("the new binding was revoked: %v", err)
	}
}

// staleList serves a ListSandboxes snapshot taken earlier, as a slow
// reconcile pass sees it.
type staleList struct {
	openshell.Client
	list []*openshell.Sandbox
}

func (s staleList) ListSandboxes(context.Context, map[string]string) ([]*openshell.Sandbox, error) {
	return s.list, nil
}

// A sandbox whose create finished after the pass listed OpenShell is not
// garbage-collected (binding revoked, providers deleted, record removed).
func TestReconcileKeepsSandboxesCreatedDuringThePass(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "early"})
	snapshot, err := e.client.ListSandboxes(t.Context(), e.m.managedSelector())
	if err != nil || len(snapshot) != 1 {
		t.Fatalf("list = %v, %v", snapshot, err)
	}
	e.create(sandboxapi.CreateRequest{Name: "late", Project: e.otherProject("late")})
	token := e.ingressToken("late")
	e.gw.Client = staleList{Client: e.client, list: snapshot}
	must(t, e.m.Reconcile(t.Context()))
	if _, err := e.store.Match(token); err != nil || !slices.Contains(e.providers(), "late-ingress") || slices.Contains(e.ws.released, "late") {
		t.Fatalf("the new sandbox was collected: binding %v, providers %v, released %v", err, e.providers(), e.ws.released)
	}
	if _, err := e.m.Get(t.Context(), "late"); err != nil {
		t.Fatalf("the new sandbox was forgotten: %v", err)
	}
}

// switchGateway makes the manager's next connection gw.
func switchGateway(t *testing.T, e *harnessEnv, gw *Gateway) {
	t.Helper()
	cur, err := e.m.gateway(t.Context())
	must(t, err)
	e.gw = gw
	e.m.dropGateway(cur, &types.StatusError{Code: types.ErrorUnavailable, Message: "reconnecting"})
}

// On another gateway or workspace the daemon keeps the sandboxes it created
// elsewhere (reported missing) and adopts them again once back.
func TestReconcileKeepsSandboxesOfAnotherGateway(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "homebox"})
	home := e.gw
	moved := *e.gw
	moved.Client = e.fake.Client(openshell.ClientOptions{PollInterval: time.Millisecond, Workspace: "team"})
	for _, gw := range []*Gateway{&moved, {Client: openshelltest.New().Client(openshell.ClientOptions{PollInterval: time.Millisecond}),
		Name: "other", Endpoint: "https://127.0.0.1:27670", Port: 27670, Version: "0.1.1"}} {
		switchGateway(t, e, gw)
		must(t, e.m.Reconcile(t.Context()))
		if _, err := e.store.Lookup("homebox"); err != nil || slices.Contains(e.ws.released, "homebox") || slices.Contains(e.ws.deleted, "homebox") {
			t.Fatalf("on %s: binding %v, released %v, deleted %v", gw.Name, err, e.ws.released, e.ws.deleted)
		}
	}
	if got := e.get("homebox"); got.Phase != "missing" || !slices.ContainsFunc(got.Warnings, func(w string) bool { return strings.Contains(w, "created on gateway openshell") }) {
		t.Fatalf("get = %+v; want it missing with the gateway it lives on", got)
	}
	switchGateway(t, e, home)
	must(t, e.m.Reconcile(t.Context()))
	if got := e.get("homebox"); got.Phase != "ready" || len(got.Warnings) != 0 {
		t.Fatalf("back on its gateway: %+v", got)
	}
}

// A sandbox's watcher ends when the connection its stream runs on is dropped
// and follows the next connection, instead of staying on the dead one.
func TestWatcherFollowsTheNextGatewayConnection(t *testing.T) {
	e := liveEnv(t, "rewatch", nil)
	first, err := e.m.gateway(t.Context())
	must(t, err)
	next := *e.gw
	e.gw = &next
	e.m.dropGateway(first, &types.StatusError{Code: types.ErrorUnavailable, Message: "the gateway restarted"})
	e.watch.waitStarted(t, "rewatch")
	e.watch.mu.Lock()
	last := e.watch.gateways[len(e.watch.gateways)-1]
	e.watch.mu.Unlock()
	if last != &next {
		t.Fatal("the restarted watch does not run on the new connection")
	}
}

// A draft notification hands the draft poll off: a poll whose lookups hang
// must not hold the stream's receive loop, which OpenShell drops events for
// when it lags.
func TestDraftEventsDoNotHoldTheStream(t *testing.T) {
	savedBudget := triagePassBudget
	triagePassBudget = 2 * time.Second
	t.Cleanup(func() { triagePassBudget = savedBudget })
	e := liveEnv(t, "lagbox", nil)
	e.dns.setHang("slow.example.org", true)
	e.propose("lagbox", "slow.example.org")
	h := e.watch.handler(t, "lagbox")
	for _, kind := range []stream.Kind{stream.KindDraft, stream.KindConnected} {
		done := make(chan struct{})
		go func() { h(stream.Event{Kind: kind, Sandbox: "lagbox"}); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("a %s event held the receive loop for the draft poll", kind)
		}
	}
	e.dns.setHang("slow.example.org", false)
	e.waitTriage("lagbox")
}

// OpenShell's warnings on a sandbox's stream (dropped messages) are recorded
// as degraded health, the watcher's own only logged.
func TestServerStreamWarningsAreReported(t *testing.T) {
	e := liveEnv(t, "warnbox", nil)
	degraded := func() int {
		return len(where(&e.tel.mu, &e.tel.health, func(h audit.SandboxHealthEvent) bool {
			return h.Sandbox.Name == "warnbox" && h.State == audit.SandboxHealthDegraded && strings.Contains(h.ErrorSummary, "lagging")
		}))
	}
	e.watch.push(t, "warnbox", stream.Event{Kind: stream.KindWarning, Warning: &stream.Warning{Message: "lagging receiver: 12 messages dropped", Local: true}})
	if n := degraded(); n != 0 {
		t.Fatalf("a local warning was recorded as health: %d", n)
	}
	e.watch.push(t, "warnbox", stream.Event{Kind: stream.KindWarning, Warning: &stream.Warning{Message: "lagging receiver: 12 messages dropped"}})
	if n := degraded(); n != 1 {
		t.Fatalf("%d degraded health records for OpenShell's warning, want 1", n)
	}
}

// The nested-repository guard runs while a mounted sandbox is ready, from
// the session's baseline; detections reach status, telemetry and the feed.
// A new session starts over; a stop and a delete end it with a final pass.
func TestGuardRunsWhileMountedSandboxIsReady(t *testing.T) {
	e := newEnv(t, nil)
	must(t, os.MkdirAll(filepath.Join(e.project, "vendor", "lib", ".git"), 0o755))
	e.run()
	e.create(sandboxapi.CreateRequest{Name: "guarded"})
	opts := e.guard.waitActive(t, e.project, true)
	if !slices.Equal(opts.Baseline.Repos, []string{"vendor/lib"}) {
		t.Fatalf("guard baseline = %+v", opts.Baseline)
	}
	at := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	opts.OnDetect(nestguard.Detection{Kind: nestguard.KindRepository, Dir: "src/evil", Quarantined: "src/evil/.git.defenseclaw-quarantine-x", At: at})
	opts.OnDetect(nestguard.Detection{Kind: nestguard.KindGitlink, Dir: "third_party/sub", At: at})
	if got := e.get("guarded").NestedRepos; len(got) != 2 || got[0].Path != "src/evil/.git" || got[0].Quarantined == "" || got[1].Kind != "gitlink" {
		t.Fatalf("nested repos = %+v", got)
	}
	quarantines := where(&e.tel.mu, &e.tel.workspace, func(w audit.SandboxWorkspaceEvent) bool { return w.Operation == audit.SandboxWorkspaceQuarantine })
	if len(quarantines) != 1 || !slices.Equal(quarantines[0].Paths, []string{"src/evil/.git"}) || quarantines[0].Sandbox.Name != "guarded" ||
		len(e.tel.findingsOf(audit.SandboxFindingNestedRepo)) != 2 {
		t.Fatalf("quarantine telemetry = %+v, %d nested-repo findings", quarantines, len(e.tel.findingsOf(audit.SandboxFindingNestedRepo)))
	}
	if feed := e.events("guarded", sandboxapi.ActivityFinding, sandboxapi.ReasonNestedRepo); len(feed) != 2 || !strings.Contains(feed[0].Message, "quarantined") {
		t.Fatalf("feed = %+v", feed)
	}
	e.stopBox("guarded")
	e.guard.waitActive(t, e.project, false)
	must(t, os.MkdirAll(filepath.Join(e.project, "kept", ".git"), 0o755))
	e.startBox("guarded", sandboxapi.StartRequest{})
	opts = e.guard.waitActive(t, e.project, true)
	if !slices.Equal(opts.Baseline.Repos, []string{"kept", "vendor/lib"}) {
		t.Fatalf("second session baseline = %+v", opts.Baseline)
	}
	if got := e.get("guarded"); len(got.NestedRepos) != 0 {
		t.Fatalf("detections carried into the new session: %+v", got.NestedRepos)
	}
	e.deleteBox("guarded", sandboxapi.DeleteRequest{})
	e.guard.waitActive(t, e.project, false)
	if n := len(e.guard.finals(e.project)); n != 2 {
		t.Fatalf("%d final passes, want one for the stop and one for the delete", n)
	}
	// A copy-mode sandbox of the project has no guard.
	e.create(sandboxapi.CreateRequest{Name: "copied", Copy: true})
	time.Sleep(50 * time.Millisecond)
	if _, ok := e.guard.active(e.project); ok {
		t.Fatal("the guard runs for a copy-mode sandbox")
	}
}

// A repository the agent planted while the daemon was down is not in the
// persisted baseline, so the restarted guard quarantines it.
func TestGuardSurvivesDaemonRestartWithItsBaseline(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	e.create(sandboxapi.CreateRequest{Name: "restart"})
	e.guard.waitActive(t, e.project, true)
	e.stop()
	e.guard.waitActive(t, e.project, false)
	must(t, os.MkdirAll(filepath.Join(e.project, "planted", ".git"), 0o755))
	e.m = e.newManager()
	e.run()
	if opts := e.guard.waitActive(t, e.project, true); slices.Contains(opts.Baseline.Repos, "planted") {
		t.Fatalf("the restarted guard re-took its baseline: %+v", opts.Baseline)
	}
}

// A detection (on the guard's goroutine) must not write through state the
// record copies other paths save share; -race checks the concurrent loop.
func TestGuardDetectionLeavesRecordCopiesAlone(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	e.create(sandboxapi.CreateRequest{Name: "copies"})
	opts := e.guard.waitActive(t, e.project, true)
	b, err := e.m.box("copies")
	must(t, err)
	detect := func(i int) {
		dir := "nested/" + strconv.Itoa(i)
		opts.OnDetect(nestguard.Detection{Kind: nestguard.KindRepository, Dir: dir, Quarantined: dir + "/.git.q", At: time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)})
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
	if got := e.get("copies").NestedRepos; len(got) != 33 || got[32].Path != "nested/32/.git" {
		t.Fatalf("nested repos = %+v", got)
	}
}

// The guard keeps watching while OpenShell stops the sandbox (its workload
// runs through the grace period) and makes one final pass with the session's
// baseline once it stopped; the next start does not sweep again.
func TestGuardWatchesTheStopAndSweepsAfterIt(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	e.create(sandboxapi.CreateRequest{Name: "graceful"})
	e.guard.waitActive(t, e.project, true)
	var during *bool
	e.fake.Intercept(func(method string) error {
		if method == openshelltest.MethodStopSandbox && during == nil {
			_, ok := e.guard.active(e.project)
			during = &ok
		}
		return nil
	})
	e.stopBox("graceful")
	if during == nil || !*during {
		t.Fatal("the guard was off while OpenShell stopped the sandbox")
	}
	e.guard.waitActive(t, e.project, false)
	eventually(t, "the final pass", func() bool { return len(e.guard.finals(e.project)) == 1 })
	b := e.boxOf("graceful")
	e.m.waitGuard(b)
	e.m.mu.Lock()
	unswept := b.rec.Guard.Unswept
	e.m.mu.Unlock()
	if unswept {
		t.Fatal("the session is still marked without its final pass")
	}
	e.startBox("graceful", sandboxapi.StartRequest{})
	if len(e.guard.finals(e.project)) != 1 {
		t.Fatalf("%d final passes, want 1", len(e.guard.finals(e.project)))
	}
}

// A session whose sandbox stopped while the daemon was down gets its final
// pass, with its own baseline, before the next session's baseline is taken.
func TestGuardSweepsASessionThatEndedWhileTheDaemonWasDown(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	e.create(sandboxapi.CreateRequest{Name: "downstop"})
	e.guard.waitActive(t, e.project, true)
	e.stop()
	_, err := e.client.StopSandbox(t.Context(), "downstop")
	must(t, err)
	_, err = e.client.WaitStopped(t.Context(), "downstop")
	must(t, err)
	must(t, os.MkdirAll(filepath.Join(e.project, "planted", ".git"), 0o755)) // planted before it stopped
	e.m = e.newManager()
	e.startBox("downstop", sandboxapi.StartRequest{})
	if finals := e.guard.finals(e.project); len(finals) != 1 || slices.Contains(finals[0].Baseline.Repos, "planted") {
		t.Fatalf("final passes = %+v, want one with the old session's baseline", finals)
	}
}

// One `git init` is one quarantine on status, the feed and the summary: the
// guard's merge of the recreated .git goes on the record's detection without
// a second finding or feed line, and undo is told every quarantined name.
func TestMergedQuarantineIsOneDetection(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	e.create(sandboxapi.CreateRequest{Name: "gitinit"})
	opts := e.guard.waitActive(t, e.project, true)
	first := nestguard.Detection{Kind: nestguard.KindRepository, Dir: "vendor/tool", Quarantined: "vendor/tool/.git.defenseclaw-quarantine-20260928T054445Z", At: time.Now()}
	opts.OnDetect(first)
	merged := first
	merged.Also = []string{first.Quarantined + "-1"}
	opts.OnMerge(merged)
	if got := e.get("gitinit").NestedRepos; len(got) != 1 || !slices.Equal(got[0].Also, merged.Also) || len(e.events("gitinit", "", sandboxapi.ReasonNestedRepo)) != 1 {
		t.Fatalf("nested repos = %+v, feed %+v", got, e.events("gitinit", "", sandboxapi.ReasonNestedRepo))
	}
	_, err := e.m.Undo(t.Context(), "gitinit", sandboxapi.UndoRequest{Stop: true})
	must(t, err)
	e.ws.mu.Lock()
	quarantined := e.ws.lastUndo.Quarantined
	e.ws.mu.Unlock()
	if !slices.Equal(quarantined, []string{first.Quarantined, first.Quarantined + "-1"}) {
		t.Fatalf("undo was told %v", quarantined)
	}
}

// recordingQuiescer notes which bindings a caller waited on, and how many
// profiles were imported by then.
type recordingQuiescer struct {
	mu       sync.Mutex
	waited   map[string]int
	importer *fakeImporter
}

func (q *recordingQuiescer) WaitQuiescent(_ context.Context, bindingID string, _ time.Duration) error {
	imported, updated := q.importer.counts()
	q.mu.Lock()
	defer q.mu.Unlock()
	q.waited[bindingID] = imported + updated
	return nil
}

// A create that has to import a global provider profile (a new --credential),
// which resets every running sandbox's connections, first tells the running
// sandboxes and waits until their hooks are quiet.
func TestGlobalProfileImportWaitsForRunningSandboxes(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "busybox"})
	q := &recordingQuiescer{waited: map[string]int{}, importer: e.importer}
	e.m.opts.Quiesce = q
	before, _ := e.importer.counts()
	e.create(sandboxapi.CreateRequest{Name: "credbox", Project: e.otherProject("cred"), Credentials: stripeCred})
	after, _ := e.importer.counts()
	q.mu.Lock()
	at, ok := q.waited[e.binding("busybox").ID]
	q.mu.Unlock()
	if after == before || !ok || at != before {
		t.Fatalf("the import did not wait for the running sandbox's hooks first (waited %t, after %d of %d imports)", ok, at, after)
	}
	if len(e.events("busybox", "", "profile_import")) == 0 {
		t.Fatal("the running sandbox was not told about the import")
	}
}

// activityProxy is a proxy that reports per-binding tunnel activity.
type activityProxy struct{ fakeProxy }

func (p *activityProxy) BindingActivity(bindingID string) (int, int64) {
	if bindingID == "sb_busy" {
		return 2, 4096
	}
	return 0, 0
}

// The approval batcher sees the attached proxy's per-binding traffic, and
// nothing before a proxy that reports it is attached.
func TestApprovalBatchesWatchProxyTunnels(t *testing.T) {
	e := newEnv(t, nil)
	tunnels := proxyTunnels{m: e.m}
	if open, moved := tunnels.BindingActivity("sb_busy"); open != 0 || moved != 0 {
		t.Fatalf("activity without a proxy = %d, %d", open, moved)
	}
	e.m.AttachProxy(&fakeProxy{counter: egress.NewCounter(egress.CounterOptions{})})
	if open, _ := tunnels.BindingActivity("sb_busy"); open != 0 {
		t.Fatalf("activity from a proxy that reports none = %d", open)
	}
	e.m.AttachProxy(&activityProxy{fakeProxy{counter: egress.NewCounter(egress.CounterOptions{})}})
	if open, moved := tunnels.BindingActivity("sb_busy"); open != 2 || moved != 4096 {
		t.Fatalf("activity = %d, %d", open, moved)
	}
}

// The feed is a ring buffer read since a sequence number, for a sandbox or all.
// A subscriber gets its backlog and its sandbox's new events; a slow one gets
// a marker counting what it dropped; subscribers are capped, and a cancel
// releases the slot.
func TestFeed(t *testing.T) {
	f := NewFeed(4, nil)
	for i := 1; i <= 6; i++ {
		f.Publish(sandboxapi.ActivityEvent{Kind: "k", Sandbox: fmt.Sprintf("s%d", i%2), Message: fmt.Sprint(i)})
	}
	if all := f.Since(0, ""); len(all) != 4 || all[0].Seq != 3 || all[3].Seq != 6 || f.Seq() != 6 || all[0].Time.IsZero() {
		t.Fatalf("buffer = %+v, seq %d", all, f.Seq())
	}
	if got := f.Since(4, ""); len(got) != 2 || got[0].Seq != 5 {
		t.Fatalf("since 4 = %+v", got)
	}
	if got := f.Since(0, "s1"); len(got) != 2 || got[0].Seq != 3 || got[1].Seq != 5 {
		t.Fatalf("filtered = %+v", got)
	}
	// Every event carries the feed's epoch, and a new feed (a restarted
	// daemon's) has another one.
	if all := f.Since(0, ""); len(f.Epoch()) != 16 || all[0].Epoch != f.Epoch() || all[3].Epoch != f.Epoch() || NewFeed(4, nil).Epoch() == f.Epoch() {
		t.Fatalf("epochs = %q, %+v", f.Epoch(), all)
	}

	f = NewFeed(16, nil)
	f.Publish(sandboxapi.ActivityEvent{Kind: "old", Sandbox: "a"})
	backlog, ch, cancel, ok := f.Subscribe(0, "a")
	if !ok || len(backlog) != 1 || backlog[0].Kind != "old" {
		t.Fatalf("backlog = %+v", backlog)
	}
	f.Publish(sandboxapi.ActivityEvent{Kind: "other", Sandbox: "b"})
	f.Publish(sandboxapi.ActivityEvent{Kind: "new", Sandbox: "a"})
	select {
	case ev := <-ch:
		if ev.Kind != "new" {
			t.Fatalf("event = %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no event")
	}
	cancel()
	cancel()
	if _, open := <-ch; open {
		t.Fatal("channel open after cancel")
	}

	f = NewFeed(1024, nil)
	_, ch, cancel, _ = f.Subscribe(0, "")
	defer cancel()
	for range defaultSubscriberBuf + 10 {
		f.Publish(sandboxapi.ActivityEvent{Kind: "k"})
	}
	for range defaultSubscriberBuf {
		<-ch
	}
	f.Publish(sandboxapi.ActivityEvent{Kind: "after"})
	if marker, ev := <-ch, <-ch; marker.Kind != sandboxapi.ActivityDropped || marker.BytesUp != 10 || ev.Kind != "after" || marker.Epoch != f.Epoch() {
		t.Fatalf("marker = %+v, then %+v", marker, ev)
	}

	f = NewFeed(4, nil)
	var cancels []func()
	for i := range maxSubscribers {
		_, _, c, ok := f.Subscribe(0, "")
		if !ok {
			t.Fatalf("subscriber %d refused", i)
		}
		cancels = append(cancels, c)
	}
	if _, _, _, ok := f.Subscribe(0, ""); ok {
		t.Fatal("subscriber over the limit accepted")
	}
	cancels[0]()
	if _, _, _, ok := f.Subscribe(0, ""); !ok {
		t.Fatal("slot not released")
	}
}
