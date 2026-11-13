// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// deletedSet is the leader's registration store as Options.Deleted sees it.
type deletedSet struct {
	mu sync.Mutex
	m  map[string]bool
}

func (d *deletedSet) mark(a Actor) { d.mu.Lock(); d.m[a.key()] = true; d.mu.Unlock() }
func (d *deletedSet) fn(_ context.Context, atespace, uid string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.m[Actor{Atespace: atespace, UID: uid}.key()], nil
}

func exists(t *testing.T, p string) bool {
	t.Helper()
	_, err := os.Stat(p)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// GAP-0142: a deleted event purges only a registration marked deleted, so a
// peer that cannot write registrations cannot wipe a live actor's chains.
func TestDeleteNeedsADeletedRegistration(t *testing.T) {
	del := &deletedSet{m: map[string]bool{}}
	var warn bytes.Buffer
	h := newHarness(t, t.TempDir(), Options{Deleted: del.fn, Warn: &warn})
	h.hook(actorA, "s1", projection(t, reverseShell, 1))
	if r := h.life(LifecycleEvent{Actor: actorA, Event: LifecycleDeleted}); !r.Ignored {
		t.Fatalf("delete of a live registration %+v, want ignored", r)
	}
	if !exists(t, h.svc.dbPath(actorA)) || !strings.Contains(warn.String(), "not marked deleted") {
		t.Fatalf("the live actor's chains were purged (warn %q)", warn.String())
	}
	del.mark(actorA)
	if r := h.life(LifecycleEvent{Actor: actorA, Event: LifecycleDeleted}); r.Ignored {
		t.Fatal("delete of a deleted registration ignored")
	}
	if exists(t, h.svc.dbPath(actorA)) || exists(t, h.svc.statePath(actorA)) {
		t.Fatal("deleted actor's state left")
	}
}

// GAP-0142: a delete while a call holds the actor's store waits for it,
// and no new call gets the actor meanwhile.
func TestDeleteWaitsForCallsInUse(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	h.hook(actorA, "s1", projection(t, reverseShell, 1))
	e, release, err := h.svc.acquire(actorA)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.svc.storeOf(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	h.life(LifecycleEvent{Actor: actorA, Event: LifecycleDeleted})
	if !exists(t, h.svc.dbPath(actorA)) {
		t.Fatal("the store was purged under a call that holds it")
	}
	if _, _, err := h.svc.acquire(actorA); !errors.Is(err, errEvicted) {
		t.Fatalf("a new call got an actor waiting for its purge: %v", err)
	}
	release()
	if exists(t, h.svc.dbPath(actorA)) {
		t.Fatal("not purged when the last call returned")
	}
}

// GAP-0142: the fork parent is the registration's; an event naming another
// parent copies nothing.
func TestForkParentComesFromTheRegistration(t *testing.T) {
	actorC := Actor{Atespace: "eng-web", UID: "3c0e2a1b-5d4f-4e6a-9b8c-7d6e5f4a3b2c"}
	parentOf := func(_ context.Context, _, uid string) (string, error) {
		if uid == actorB.UID {
			return actorA.UID, nil
		}
		return "", nil
	}
	h := newHarness(t, t.TempDir(), Options{ParentOf: parentOf, Warn: &bytes.Buffer{}})
	h.hook(actorC, "s1", projection(t, reverseShell, 1))
	h.hook(actorA, "s1", projection(t, reverseShell, 1))
	h.hook(actorB, "s1", projection(t, reverseShell, 2)) // B's first call copies A (its registered parent)
	if r := h.life(LifecycleEvent{Actor: actorB, Event: LifecycleForked, Parent: &actorC}); !r.Ignored || r.CopiedEvents != 0 {
		t.Fatalf("fork event with a parent the registration does not name: %+v", r)
	}
	if r := h.life(LifecycleEvent{Actor: actorC, Event: LifecycleForked, Parent: &actorA}); !r.Ignored {
		t.Fatalf("fork event for an actor that is no fork: %+v", r)
	}
}

// GAP-0142: a repeated or late fork event never resets the child's clock.
func TestForkEventNeverResetsTheChildClock(t *testing.T) {
	// The parent has no store, so no copy marks the fork as started: only
	// the clock rule keeps a repeated event from resetting the child.
	h := newHarness(t, t.TempDir(), Options{})
	h.life(LifecycleEvent{Actor: actorB, Event: LifecycleForked, Parent: &actorA})
	h.life(LifecycleEvent{Actor: actorB, Event: LifecycleSuspended, AtUnixNano: h.clock().UnixNano()})
	h.advance(time.Hour)
	h.life(LifecycleEvent{Actor: actorB, Event: LifecycleResumed, AtUnixNano: h.clock().UnixNano()})
	before := h.svc.stateOf(h.svc.actors[actorB.key()])
	if before.SuspendedNanos < int64(time.Hour) || !before.Forked {
		t.Fatalf("child clock %+v", before)
	}
	h.life(LifecycleEvent{Actor: actorB, Event: LifecycleForked, Parent: &actorA})
	if after := h.svc.stateOf(h.svc.actors[actorB.key()]); after.SuspendedNanos != before.SuspendedNanos {
		t.Fatalf("a repeated fork event reset the child's clock: %d -> %d", before.SuspendedNanos, after.SuspendedNanos)
	}
}

// GAP-0142: past the open-store cap, idle stores close down to 7/8 of it,
// so the next calls do not close and reopen a store each.
func TestOpenStoresHaveHysteresis(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{MaxOpenStores: 8})
	actor := func(i int) Actor {
		return Actor{Atespace: "eng-web", UID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i)}
	}
	open := func() int { h.svc.mu.Lock(); defer h.svc.mu.Unlock(); return h.svc.open }
	for i := 1; i <= 9; i++ {
		h.advance(time.Second) // a real clock orders the least recently used
		h.hook(actor(i), "s1", projection(t, reverseShell, 1))
	}
	if got := open(); got != 7 {
		t.Fatalf("open after crossing the cap = %d, want 7", got)
	}
	h.advance(time.Second)
	h.hook(actor(10), "s1", projection(t, reverseShell, 1))
	if got := open(); got != 8 {
		t.Fatalf("open after one more = %d, want 8 (no close below the cap)", got)
	}
}

// GAP-0142: the fork copy opens the parent read-only; a missing parent file
// is an error and is never created.
func TestForkCopyNeverCreatesTheParentFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "with space")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := audit.NewStore(filepath.Join(dir, "child.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Init(); err != nil {
		t.Fatal(err)
	}
	pi, _ := audit.ToolChainSubstrateInstanceID(actorA.Atespace, actorA.UID)
	ci, _ := audit.ToolChainSubstrateInstanceID(actorB.Atespace, actorB.UID)
	pd, _ := audit.ToolChainActorScopeDigest(actorA.Atespace, actorA.UID)
	cd, _ := audit.ToolChainActorScopeDigest(actorB.Atespace, actorB.UID)
	missing := filepath.Join(dir, "parent.db")
	_, err = st.CopyToolChainFork(context.Background(), missing, audit.ToolChainForkCopy{ParentInstance: pi, ChildInstance: ci,
		ParentActorDigest: pd, ChildActorDigest: cd, At: time.Now()})
	if err == nil {
		t.Fatal("a fork copy from a missing parent store succeeded")
	}
	if exists(t, missing) {
		t.Fatal("the fork copy created an empty parent store")
	}
}
