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
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

func TestReconcileGarbageCollectsDeletedSandboxes(t *testing.T) {
	e := newEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{Name: "gonebox"})
	ingress, _ := e.client.GetProvider(context.Background(), "gonebox-ingress")
	token := ingress.Spec.Credentials[openshell.EnvSandboxToken]

	// Deleted outside DefenseClaw.
	if _, err := e.client.DeleteSandbox(context.Background(), sb.Name); err != nil {
		t.Fatal(err)
	}
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Match(token); !errors.Is(err, sandboxauth.ErrUnauthenticated) {
		t.Fatalf("binding survived: %v", err)
	}
	if names := e.providers(); len(names) != 0 {
		t.Fatalf("providers left: %v", names)
	}
	if !slices.Contains(e.ws.released, "gonebox") {
		t.Fatal("mount not released")
	}
	if slices.Contains(e.ws.deleted, "gonebox") {
		t.Fatal("reconcile deleted the snapshot of a sandbox the user deleted elsewhere")
	}
	// The kept snapshot stays reachable: the box is retained for undo,
	// review and delete, and a second pass leaves it alone.
	got, err := e.m.Get(context.Background(), "gonebox")
	if err != nil || got.Phase != "deleted" || got.Snapshot == nil {
		t.Fatalf("retained box = %+v, %v", got, err)
	}
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Undo(context.Background(), "gonebox", sandboxapi.UndoRequest{}); err != nil {
		t.Fatalf("undo of the retained box: %v", err)
	}
	if _, err := e.m.Delete(context.Background(), "gonebox", sandboxapi.DeleteRequest{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(e.ws.deleted, "gonebox") {
		t.Fatal("delete of the retained box kept its snapshot")
	}
	if _, err := e.m.Get(context.Background(), "gonebox"); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		t.Fatalf("box survived its delete: %v", err)
	}
	var reconciled bool
	for _, ev := range e.tel.lifecycle {
		reconciled = reconciled || (ev.Sandbox.Name == "gonebox" && ev.Trigger == audit.SandboxTriggerReconcile && ev.Sandbox.Phase == audit.SandboxPhaseDeleted)
	}
	if !reconciled {
		t.Fatal("no reconcile deleted lifecycle")
	}
}

func TestReconcileRevokesStaleBindingsAndProviders(t *testing.T) {
	e := newEnv(t, nil)
	stale, _, err := e.store.Mint(sandboxauth.Spec{SandboxName: "stale", Connector: "claudecode", Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy}})
	if err != nil {
		t.Fatal(err)
	}
	orphan := &openshell.Provider{Name: "stale-ingress", Type: "defenseclaw-ingress",
		Labels: map[string]string{LabelManaged: "true", LabelOwner: testOwner, LabelSandbox: "stale"}}
	foreign := &openshell.Provider{Name: "someone-else", Type: "generic",
		Labels: map[string]string{LabelManaged: "true", LabelOwner: "ffffffffffffffff", LabelSandbox: "x"}}
	for _, p := range []*openshell.Provider{orphan, foreign} {
		if _, err := e.client.CreateProvider(context.Background(), p); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Get(stale.ID); !errors.Is(err, sandboxauth.ErrNotFound) {
		t.Fatalf("stale binding: %v", err)
	}
	if names := e.providers(); !slices.Equal(names, []string{"someone-else"}) {
		t.Fatalf("providers = %v", names)
	}
}

func TestReconcileAdoptsAndFlagsOrphans(t *testing.T) {
	e := newEnv(t, nil)
	labels := map[string]string{LabelManaged: "true", LabelOwner: testOwner, LabelHarness: "claudecode", LabelProfile: "open"}
	if _, err := e.client.CreateSandbox(context.Background(), "orphanbox", &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{Labels: labels}); err != nil {
		t.Fatal(err)
	}
	other := map[string]string{LabelManaged: "true", LabelOwner: "ffffffffffffffff"}
	if _, err := e.client.CreateSandbox(context.Background(), "otherdata", &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{Labels: other}); err != nil {
		t.Fatal(err)
	}
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	list, _ := e.m.List(context.Background())
	if len(list) != 1 || list[0].Name != "orphanbox" || !list[0].Orphaned {
		t.Fatalf("list = %+v", list)
	}
	if _, err := e.m.Start(context.Background(), "orphanbox", sandboxapi.StartRequest{}); !sandboxapi.IsCode(err, sandboxapi.CodeConflict) {
		t.Fatalf("start orphan: %v", err)
	}
	// Deleting the orphan works and leaves the other data dir's sandbox.
	if _, err := e.m.Delete(context.Background(), "orphanbox", sandboxapi.DeleteRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.GetSandbox(context.Background(), "otherdata"); err != nil {
		t.Fatalf("foreign sandbox touched: %v", err)
	}
}

func TestRestartRecoversState(t *testing.T) {
	e := newEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{Name: "survivor"})
	if _, err := e.m.Unblock(context.Background(), sandboxapi.UnblockRequest{Host: "webhook.site", Sandbox: "survivor"}); err != nil {
		t.Fatal(err)
	}
	got, _ := e.client.GetSandbox(context.Background(), sb.Name)
	proxy, _ := url.Parse(got.Spec.Environment["HTTPS_PROXY"])
	pass, _ := proxy.User.Password()

	// A new daemon process over the same data dir and gateway.
	e.tel.lifecycle = nil
	e.m = e.newManager()
	if _, ok := e.m.creds.Authenticate(proxy.User.Username(), pass); ok {
		t.Fatal("credential known before reconcile")
	}
	e.run()
	eventually(t, "startup reconcile", func() bool {
		st, _ := e.m.Status(context.Background())
		return !st.LastReconcile.IsZero()
	})
	p, ok := e.m.creds.Authenticate(proxy.User.Username(), pass)
	if !ok || p.SandboxName != "survivor" {
		t.Fatalf("credential not recovered: %+v %v", p, ok)
	}
	// Startup republishes the lifecycle with the recorded previous phase.
	var republished bool
	e.tel.mu.Lock()
	for _, ev := range e.tel.lifecycle {
		if ev.Sandbox.Name == "survivor" && ev.Trigger == audit.SandboxTriggerReconcile && ev.Sandbox.Phase == audit.SandboxPhaseReady &&
			ev.PreviousPhase == "" {
			republished = true
		}
	}
	e.tel.mu.Unlock()
	if !republished {
		t.Fatalf("lifecycle = %+v", e.tel.lifecycle)
	}
	// The sandbox-scoped unblock survived.
	if len(e.m.unblocks.List()) != 1 {
		t.Fatalf("unblocks = %v", e.m.unblocks.List())
	}
	e.watch.waitStarted(t, "survivor")
}

func TestWatcherEventsAndGC(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "watchbox"})
	e.watch.waitStarted(t, sb.Name)

	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindStatus, Status: &stream.Status{Phase: openshell.PhaseStopped}})
	eventually(t, "stopped lifecycle", func() bool {
		phases := e.tel.phases(sb.Name)
		return phases[len(phases)-1] == audit.SandboxPhaseStopped
	})

	// The sandbox disappears; the watcher reports it and the manager
	// releases everything.
	if _, err := e.client.DeleteSandbox(context.Background(), sb.Name); err != nil {
		t.Fatal(err)
	}
	e.watch.end(sb.Name, stream.ErrSandboxNotFound)
	eventually(t, "garbage collection", func() bool {
		got, err := e.m.Get(context.Background(), sb.Name)
		return err == nil && got.Phase == "deleted"
	})
	if names := e.providers(); len(names) != 0 {
		t.Fatalf("providers left: %v", names)
	}
}

func TestRecordsSkipOtherOwners(t *testing.T) {
	e := newEnv(t, nil)
	rs := newRecordStore(e.dataDir)
	if err := rs.save(&record{Name: "foreign", Owner: "ffffffffffffffff"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dataDir, "sandboxes", "manager", "broken.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := e.newManager()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.boxes) != 0 {
		t.Fatalf("boxes = %v", m.boxes)
	}
}

// TestGarbageCollectionSkipsReplacedBoxes pins that a reconcile pass that
// listed a sandbox before it was deleted and recreated under the same name
// leaves the new sandbox's state alone.
func TestGarbageCollectionSkipsReplacedBoxes(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "samename"})
	e.m.mu.Lock()
	stale := e.m.boxes["samename"]
	e.m.mu.Unlock()
	if !e.m.current(stale) {
		t.Fatal("live box not current")
	}
	if _, err := e.m.Delete(context.Background(), "samename", sandboxapi.DeleteRequest{}); err != nil {
		t.Fatal(err)
	}
	e.create(sandboxapi.CreateRequest{Name: "samename"})
	if e.m.current(stale) {
		t.Fatal("a deleted box is still current")
	}
	released := len(e.ws.released)
	e.m.reconcileOne(context.Background(), "samename")
	if len(e.ws.released) != released {
		t.Fatal("reconciling a live sandbox released its mount")
	}
	if _, err := e.store.Lookup("samename"); err != nil {
		t.Fatalf("the new binding was revoked: %v", err)
	}
}
