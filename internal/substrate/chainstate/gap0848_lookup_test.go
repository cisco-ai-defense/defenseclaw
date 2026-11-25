// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/intentstore"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// rel-1-0-10:GAP-0848 on Substrate: the leader's intent store is an
// intentstore.Reader, so the tool-result judges get the turn's request. A
// lookup records nothing, finds only the verified actor's own context (never
// another actor's under the same key, nor another judge role's), finds a
// --task actor's task, and a call that is not an actor's reads the fallback.
func TestIntentStoreLookupOnTheLeader(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	type ctxKey struct{}
	actorOf := func(ctx context.Context) (Actor, bool) { a, ok := ctx.Value(ctxKey{}).(Actor); return a, ok }
	limits := intentstore.Limits{MaxSessions: 4, MaxPrior: 4, TTL: time.Minute}
	store := &IntentStore{Client: h.client, Namespace: "judge", ActorOf: actorOf, Fallback: intentstore.NewProcess(limits)}
	reader := asReader(t, store)
	ctxA := context.WithValue(context.Background(), ctxKey{}, actorA)
	if _, found, err := reader.Lookup(ctxA, "k1"); err != nil || found {
		t.Fatalf("empty store: found=%v err=%v", found, err)
	}
	if err := store.ObservePrompt(ctxA, "k1", "deploy the web app"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendToolCall(ctxA, "k1", intentstore.ToolCall{Tool: "Read", Args: "README"}); err != nil {
		t.Fatal(err)
	}
	snap, found, err := reader.Lookup(ctxA, "k1")
	if err != nil || !found || snap.UserIntent != "deploy the web app" || len(snap.Prior) != 1 {
		t.Fatalf("lookup %+v found=%v err=%v", snap, found, err)
	}
	// Recording nothing: the next call finds only the one earlier call.
	if snap, _ := store.AppendToolCall(ctxA, "k1", intentstore.ToolCall{Tool: "Bash", Args: "make"}); len(snap.Prior) != 1 {
		t.Fatalf("Lookup recorded a call: %+v", snap)
	}
	// Another actor with the same session key, and another judge role of
	// the same actor, see nothing of actor A's request.
	ctxB := context.WithValue(context.Background(), ctxKey{}, actorB)
	if snap, found, err := reader.Lookup(ctxB, "k1"); err != nil || found || snap.UserIntent != "" {
		t.Fatalf("actor B read actor A's context: %+v found=%v err=%v", snap, found, err)
	}
	decision := asReader(t, &IntentStore{Client: h.client, Namespace: "decision", ActorOf: actorOf, Fallback: intentstore.NewProcess(limits)})
	if snap, found, _ := decision.Lookup(ctxA, "k1"); found || snap.UserIntent != "" {
		t.Fatalf("another judge role read the context: %+v", snap)
	}
	// A --task actor's task is its request before any prompt.
	if err := h.client.PutTask(context.Background(), actorB, "fix the flaky test in pkg/foo"); err != nil {
		t.Fatal(err)
	}
	if snap, found, err := reader.Lookup(ctxB, "k2"); err != nil || !found || snap.UserIntent != "fix the flaky test in pkg/foo" {
		t.Fatalf("task lookup %+v found=%v err=%v", snap, found, err)
	}
	// A host call reads the fallback.
	if err := store.ObservePrompt(context.Background(), "host", "local"); err != nil {
		t.Fatal(err)
	}
	if snap, found, err := reader.Lookup(context.Background(), "host"); err != nil || !found || snap.UserIntent != "local" {
		t.Fatalf("fallback lookup %+v found=%v err=%v", snap, found, err)
	}
	// A fallback without Reader finds nothing; no fallback is an error.
	noRead := asReader(t, &IntentStore{Client: h.client, ActorOf: actorOf, Fallback: storeOnly{intentstore.NewProcess(limits)}})
	if _, found, err := noRead.Lookup(context.Background(), "host"); err != nil || found {
		t.Fatalf("fallback without Reader: found=%v err=%v", found, err)
	}
	if _, _, err := asReader(t, &IntentStore{Client: h.client, ActorOf: actorOf}).Lookup(context.Background(), "host"); err == nil {
		t.Fatal("a host lookup without a fallback did not fail")
	}
}

// With the leader down, a judge's lookup gives up in about a second
// (intentLookupTimeout), not after the gateway leader client's 45 s retry
// window (Retry zero), and finds nothing.
func TestIntentStoreLookupLeaderDownGivesUpPromptly(t *testing.T) {
	srv := httptest.NewServer(nil)
	url, hc := srv.URL, srv.Client()
	srv.Close() // the leader refuses connections from now on
	type ctxKey struct{}
	actorOf := func(ctx context.Context) (Actor, bool) { a, ok := ctx.Value(ctxKey{}).(Actor); return a, ok }
	store := &IntentStore{Client: &Client{Leader: &leader.Client{BaseURL: url, HTTP: hc}}, Namespace: "judge", ActorOf: actorOf}
	start := time.Now()
	snap, found, err := store.Lookup(context.WithValue(context.Background(), ctxKey{}, actorA), "k1")
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("lookup with the leader down took %s, want about %s", elapsed, intentLookupTimeout)
	}
	if err == nil || found || snap.UserIntent != "" {
		t.Fatalf("lookup with the leader down: %+v found=%v err=%v", snap, found, err)
	}
}

// asReader is s as an intentstore.Reader, the interface the tool-result
// judges assert (LLMJudge.sessionUserIntent).
func asReader(t *testing.T, s intentstore.Store) intentstore.Reader {
	t.Helper()
	reader, ok := s.(intentstore.Reader)
	if !ok {
		t.Fatalf("%T is not an intentstore.Reader: the tool-result judges get no user request", s)
	}
	return reader
}

// storeOnly hides the Reader of a store.
type storeOnly struct{ s intentstore.Store }

func (o storeOnly) ObservePrompt(ctx context.Context, key, intent string) error {
	return o.s.ObservePrompt(ctx, key, intent)
}
func (o storeOnly) AppendToolCall(ctx context.Context, key string, call intentstore.ToolCall) (intentstore.Snapshot, error) {
	return o.s.AppendToolCall(ctx, key, call)
}
func (o storeOnly) Reset(ctx context.Context, key string) error { return o.s.Reset(ctx, key) }
