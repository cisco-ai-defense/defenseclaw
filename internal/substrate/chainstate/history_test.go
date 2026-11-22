// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/historystore"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// substrate-1 GAP-0266: the proxy's inspect-once record on the leader. Two
// gateway replicas (two HistoryStore clients) share an actor's record; actors
// never see each other's; a call that is not an actor's stays local.
func TestHistoryStoreOnTheLeader(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	type ctxKey struct{}
	actorOf := func(ctx context.Context) (Actor, bool) { a, ok := ctx.Value(ctxKey{}).(Actor); return a, ok }
	replicaA := &HistoryStore{Client: h.client, ActorOf: actorOf, Fallback: &historystore.Process{}}
	replicaB := &HistoryStore{Client: h.client, ActorOf: actorOf, Fallback: &historystore.Process{}}
	a := context.WithValue(context.Background(), ctxKey{}, actorA)
	b := context.WithValue(context.Background(), ctxKey{}, actorB)
	var refusedHash, allowedHash historystore.Hash
	copy(refusedHash[:], "refused-segment!")
	copy(allowedHash[:], "allowed-segment!")
	if err := replicaA.Record(a, "actor", "scope-1", []historystore.Hash{refusedHash}, historystore.Entry{Verdict: historystore.Refused, Rule: "TRUST-IGNORE-PREVIOUS"}, 2048); err != nil {
		t.Fatal(err)
	}
	if err := replicaA.Record(a, "actor", "scope-1", []historystore.Hash{allowedHash}, historystore.Entry{}, 2048); err != nil {
		t.Fatal(err)
	}
	got, err := replicaB.Seen(a, "scope-1", []historystore.Hash{refusedHash, allowedHash})
	if err != nil || len(got) != 2 || got[refusedHash] != (historystore.Entry{Verdict: historystore.Refused, Rule: "TRUST-IGNORE-PREVIOUS"}) || got[allowedHash] != (historystore.Entry{}) {
		t.Fatalf("the other replica sees %v (%v), want the refusal and the allow", got, err)
	}
	if got, err := replicaB.Seen(b, "scope-1", []historystore.Hash{refusedHash}); err != nil || len(got) != 0 {
		t.Errorf("another actor sees %v (%v)", got, err)
	}
	if got, err := replicaB.Seen(a, "scope-2", []historystore.Hash{refusedHash}); err != nil || len(got) != 0 {
		t.Errorf("another scope sees %v (%v)", got, err)
	}
	// Not an actor's call: the replica's own store.
	local := context.Background()
	_ = replicaA.Record(local, "host", "scope-1", []historystore.Hash{refusedHash}, historystore.Entry{Verdict: historystore.Refused}, 2048)
	if got, _ := replicaB.Seen(local, "scope-1", []historystore.Hash{refusedHash}); len(got) != 0 {
		t.Errorf("a host call's record left the replica: %v", got)
	}
	// Malformed requests are refused, not stored.
	for _, in := range []HistoryRequest{
		{Actor: actorA, Scope: "", Hashes: []string{"00112233445566778899aabbccddeeff"}, Max: 8},
		{Actor: actorA, Scope: "s", Hashes: []string{"zz"}, Max: 8},
		{Actor: actorA, Scope: "s", Hashes: []string{"00112233445566778899aabbccddeeff"}, Max: 0},
		{Actor: actorA, Scope: "s", Hashes: []string{"00112233445566778899aabbccddeeff"}, Verdict: 9, Max: 8},
	} {
		if err := h.client.call(context.Background(), MethodHistoryRecord, in, nil); err == nil {
			t.Errorf("a malformed record %+v was accepted", in)
		}
	}
	// The per-actor scope bound.
	for i := 0; i < 2*historystore.MaxScopesPerCaller; i++ {
		_ = replicaA.Record(a, "actor", "rot-"+string(rune('a'+i%26))+string(rune('a'+i/26)), []historystore.Hash{allowedHash}, historystore.Entry{}, 8)
	}
	e, release, err := h.svc.acquire(actorA)
	if err != nil {
		t.Fatal(err)
	}
	n, _, perActor := h.svc.history(e).Stats("", "actor")
	release()
	if n != historystore.MaxScopesPerCaller || perActor != historystore.MaxScopesPerCaller {
		t.Errorf("an actor holds %d scopes (%d counted), want %d", n, perActor, historystore.MaxScopesPerCaller)
	}
}

// A leader that does not answer is an error the proxy reads as an empty
// record; it never answers "seen".
func TestHistoryStoreLeaderDown(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	h.srv.Close()
	type ctxKey struct{}
	store := &HistoryStore{Client: &Client{Leader: &leader.Client{BaseURL: h.srv.URL, HTTP: h.srv.Client(), Retry: 50 * time.Millisecond}},
		ActorOf: func(ctx context.Context) (Actor, bool) { a, ok := ctx.Value(ctxKey{}).(Actor); return a, ok }}
	ctx := context.WithValue(context.Background(), ctxKey{}, actorA)
	var x historystore.Hash
	if got, err := store.Seen(ctx, "s", []historystore.Hash{x}); err == nil || got != nil {
		t.Errorf("a leader that is down answered %v (%v)", got, err)
	}
	if err := store.Record(ctx, "actor", "s", []historystore.Hash{x}, historystore.Entry{}, 8); err == nil {
		t.Error("a record on a leader that is down did not fail")
	}
}
