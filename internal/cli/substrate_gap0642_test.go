// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// GAP-0642: after a rollout restart, the first `run --clone` failed with
// the network guard's 503. The new leader answered the clone's egress check
// unavailable for its whole start grace, also for an actor created after
// the restart. The leader as it is wired here (its registrations) answers
// that actor at once. An actor registered before the term, and a fork,
// still wait out the grace (GAP-0601).
func TestGAP0642LeaderAnswersAnActorRegisteredInItsTerm(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	person := registry.Person{Kind: "oidc", Issuer: "https://idp.example", Subject: "s-1", Principal: "eng1"}
	reg := func(name, uid, parent string) registry.Registration {
		return registry.Registration{Atespace: "dc-eng", UID: uid, Name: name, Connector: "claudecode", Person: person, ParentUID: parent}
	}
	request := func(name, uid string) chainstate.EgressRequest {
		return chainstate.EgressRequest{Actor: chainstate.Actor{Atespace: "dc-eng", UID: uid}, Name: name, Host: "github.com", Method: "GET"}
	}
	// "older" is on disk when the leader process starts: not registered in its term.
	before, err := registry.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Its CreatedAt was written by another node whose clock is an hour ahead
	// of this one: compared with the term's start it would look born in the
	// term (GAP-1148). The leader's own set does not read it.
	skewed := reg("old-1", "7a2b3c4d-5e6f-4a70-8b9c-0d1e2f3a4b5c", "")
	skewed.CreatedAt = time.Now().Add(time.Hour)
	if err := before.Put(ctx, skewed); err != nil {
		t.Fatal(err)
	}
	store, err := registry.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	opts, _ := leaderChainOptions(&config.Config{}, store, t.TempDir(), time.Hour)
	svc, err := chainstate.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	svc.Leading()
	put := func(name, uid, parent string) chainstate.EgressRequest {
		t.Helper()
		if err := store.Put(ctx, reg(name, uid, parent)); err != nil {
			t.Fatalf("put %s: %v", name, err)
		}
		return request(name, uid)
	}
	fresh := put("sv17-c1", "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b", "")
	older := request("old-1", "7a2b3c4d-5e6f-4a70-8b9c-0d1e2f3a4b5c")
	fork := put("fork-1", "8b3c4d5e-6f7a-4b80-9c0d-1e2f3a4b5c6d", older.Actor.UID)
	if v, err := svc.Egress(ctx, fresh); err != nil || v.Deny {
		t.Fatalf("the first clone of an actor registered after the restart: %+v %v, want a clear answer", v, err)
	}
	for name, req := range map[string]chainstate.EgressRequest{"an actor registered before the term": older, "a fork": fork} {
		if v, err := svc.Egress(ctx, req); err == nil && !v.Deny {
			t.Errorf("%s was answered inside the start grace: %+v", name, v)
		}
	}
}
