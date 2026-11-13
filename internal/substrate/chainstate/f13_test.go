// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// names is the leader's registrations as Options.Current and
// Options.Deleted see them: each name's newest UID, and the tombstones.
type names struct {
	mu      sync.Mutex
	newest  map[string]string // atespace/name -> uid
	deleted map[string]bool   // atespace/uid
}

func newNames() *names { return &names{newest: map[string]string{}, deleted: map[string]bool{}} }

func (n *names) register(name string, a Actor) {
	n.mu.Lock()
	n.newest[a.Atespace+"/"+name] = a.UID
	n.mu.Unlock()
}

func (n *names) tombstone(a Actor) { n.mu.Lock(); n.deleted[a.key()] = true; n.mu.Unlock() }

func (n *names) current(_ context.Context, atespace, name, uid string) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.newest[atespace+"/"+name] == uid && !n.deleted[Actor{Atespace: atespace, UID: uid}.key()], nil
}

func (n *names) isDeleted(_ context.Context, atespace, uid string) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.deleted[Actor{Atespace: atespace, UID: uid}.key()], nil
}

func (h *harness) egressAs(name string, a Actor) (EgressVerdict, error) {
	return h.client.CheckEgress(context.Background(), EgressRequest{Actor: a, Name: name, Host: "example.com", Method: "POST"})
}

// GAP-0234 (R7's TestR7EgressOfADeletedUIDIsNotAllowed, failed at
// 18ad6a2dc2): a same-name actor deleted and created again. The callout may
// still ask under the predecessor's UID; the leader answers that stale, not
// allow, and makes no fresh entry for the purged UID. The new incarnation is
// checked against its own window, which holds the secret read.
func TestEgressOfADeletedUIDIsNotAllowed(t *testing.T) {
	n := newNames()
	h := newHarness(t, t.TempDir(), Options{Current: n.current, Deleted: n.isDeleted, Warn: &bytes.Buffer{}})
	old, recreated := actorA, actorB // same atespace and name, two incarnations
	n.register("w1", old)
	h.hook(old, "s1", projection(t, reverseShell, 1))
	n.tombstone(old)
	if r := h.life(LifecycleEvent{Actor: old, Event: LifecycleDeleted}); r.Ignored {
		t.Fatal("delete ignored")
	}
	n.register("w1", recreated)
	h.hook(recreated, "s1", secretRead(t))
	if v, err := h.egressAs("w1", recreated); err != nil || !v.Deny || v.Stale {
		t.Fatalf("new incarnation after a secret read: %+v %v, want deny", v, err)
	}
	v, err := h.egressAs("w1", old)
	if err != nil || !v.Stale || !v.Deny {
		t.Fatalf("egress check under the deleted predecessor UID: %+v %v, want stale (and deny)", v, err)
	}
	h.svc.mu.Lock()
	_, made := h.svc.actors[old.key()]
	h.svc.mu.Unlock()
	if made || exists(t, h.svc.dbPath(old)) || exists(t, h.svc.statePath(old)) {
		t.Fatal("the stale check made state for the purged UID")
	}
}

// GAP-0234 class: the new incarnation is registered before the controller
// tombstones the old one (its delete event is still on the way). The old
// UID is not the name's newest, so it is stale already.
func TestEgressOfAReplacedUIDBeforeItsTombstoneIsStale(t *testing.T) {
	n := newNames()
	h := newHarness(t, t.TempDir(), Options{Current: n.current, Deleted: n.isDeleted, Warn: &bytes.Buffer{}})
	n.register("w1", actorA)
	h.hook(actorA, "s1", projection(t, reverseShell, 1))
	if v, err := h.egressAs("w1", actorA); err != nil || v.Stale || v.Deny {
		t.Fatalf("live incarnation: %+v %v", v, err)
	}
	n.register("w1", actorB)
	if v, err := h.egressAs("w1", actorA); err != nil || !v.Stale {
		t.Fatalf("replaced, not yet tombstoned: %+v %v, want stale", v, err)
	}
	// A deleted actor with no successor is stale too.
	n.register("w2", actorB)
	n.tombstone(actorB)
	if v, err := h.egressAs("w2", actorB); err != nil || !v.Stale {
		t.Fatalf("deleted, not recreated: %+v %v, want stale", v, err)
	}
	// A UID that names another actor's incarnation, or none, is stale.
	if v, err := h.egressAs("other", actorA); err != nil || !v.Stale {
		t.Fatalf("UID under another name: %+v %v, want stale", v, err)
	}
}

// A brand-new actor is answered as soon as its registration exists, which
// is before the callout can know its UID (the callout learns the UID from
// that registration), even before its first hook.
func TestEgressOfANewActorIsAnswered(t *testing.T) {
	n := newNames()
	h := newHarness(t, t.TempDir(), Options{Current: n.current, Deleted: n.isDeleted, Warn: &bytes.Buffer{}})
	n.register("w1", actorA)
	if v, err := h.egressAs("w1", actorA); err != nil || v.Stale || v.Deny {
		t.Fatalf("new actor, no hook yet: %+v %v", v, err)
	}
	h.hook(actorA, "s1", secretRead(t))
	if v, err := h.egressAs("w1", actorA); err != nil || !v.Deny || v.Stale {
		t.Fatalf("new actor after a secret read: %+v %v, want deny", v, err)
	}
}

// With registrations wired, an egress check names the actor.
func TestEgressCheckNamesTheActor(t *testing.T) {
	n := newNames()
	h := newHarness(t, t.TempDir(), Options{Current: n.current, Deleted: n.isDeleted, Warn: &bytes.Buffer{}})
	n.register("w1", actorA)
	_, err := h.egressAs("", actorA)
	var we *leader.WireError
	if !errors.As(err, &we) || we.Code != leader.CodeBadRequest {
		t.Fatalf("check without a name: %v, want bad_request", err)
	}
}
