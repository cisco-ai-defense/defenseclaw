// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/intentstore"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

var (
	actorA = Actor{Atespace: "eng-web", UID: "25a1da0f-1c9b-4ef7-8248-c276138c7f77"}
	actorB = Actor{Atespace: "eng-web", UID: "2e8d6260-7d31-4e56-b416-1222430fa637"}
)

const ruleset = "1111111111111111111111111111111111111111111111111111111111111111"

// harness is a leader (Service behind the real transport) and a client.
type harness struct {
	t      *testing.T
	dir    string
	svc    *Service
	client *Client
	mu     sync.Mutex
	now    time.Time
	srv    *httptest.Server
}

func newHarness(t *testing.T, dir string, opts Options) *harness {
	t.Helper()
	h := &harness{t: t, dir: dir, now: time.Date(2026, 11, 12, 20, 0, 0, 0, time.UTC)}
	opts.Dir, opts.Now = dir, h.clock
	svc, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ls := &leader.Server{IsLeader: func() bool { return true }}
	svc.Register(ls)
	h.svc, h.srv = svc, httptest.NewServer(ls)
	h.client = &Client{Leader: &leader.Client{BaseURL: h.srv.URL, HTTP: h.srv.Client(), Retry: time.Second}}
	t.Cleanup(func() { h.srv.Close(); _ = svc.Close() })
	return h
}

func (h *harness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

func projection(t *testing.T, id string, step int) guardrail.ToolChainProjection {
	t.Helper()
	bit, ok := guardrail.ToolChainStepMask(id, step)
	if !ok {
		t.Fatalf("unknown chain %s", id)
	}
	p := guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete, DetectionStepMask: bit, EnforcementStepMask: bit}
	if def, _ := guardrail.ToolChainDefinitionByID(id); def.RequiresEnforcementJoin || def.RequiresExactJoin {
		index, _ := guardrail.ToolChainIndexByID(id)
		p.EnforcementJoinDigests[index] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	}
	return p
}

// hook observes one tool event of actor in session, in both windows, as the
// gateway's chain stage does through two bindings, and returns both results.
func (h *harness) hook(actor Actor, session string, p guardrail.ToolChainProjection) (sessionResult, actorResult audit.ToolChainObserveResult) {
	h.t.Helper()
	id, err := audit.NewSemanticEventID()
	if err != nil {
		h.t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(id))
	in := audit.ToolChainObserveInput{SemanticEventID: id, InputFingerprint: hex.EncodeToString(sum[:]),
		RulesetFingerprint: ruleset, Projection: p, DenyEligible: true}
	for _, scope := range []Scope{ScopeSession, ScopeActor} {
		b, err := h.client.Bind(actor, scope, "claudecode", session, "PreToolUse")
		if err != nil {
			h.t.Fatal(err)
		}
		r, err := b.Observe(context.Background(), in)
		if err != nil {
			h.t.Fatalf("%s observe: %v", scope, err)
		}
		if scope == ScopeSession {
			sessionResult = r
		} else {
			actorResult = r
		}
	}
	return sessionResult, actorResult
}

func (h *harness) life(ev LifecycleEvent) LifecycleResult {
	h.t.Helper()
	r, err := h.client.Lifecycle(context.Background(), ev)
	if err != nil {
		h.t.Fatalf("%s: %v", ev.Event, err)
	}
	return r
}

const reverseShell = guardrail.ToolChainStagedReverseShellPersistence

// J44 a: two agent sessions in one actor; the actor window still matches.
func TestSessionRotationStillMatchesInTheActorWindow(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	h.hook(actorA, "claude-session-1", projection(t, reverseShell, 1))
	h.advance(time.Second)
	s, a := h.hook(actorA, "claude-session-2", projection(t, reverseShell, 2))
	if s.DetectedMask != 0 || !slices.Contains(a.DetectedChainIDs, reverseShell) || a.DeniedMask == 0 {
		t.Fatalf("session %+v actor %+v", s, a)
	}
	// Another actor never sees it.
	if _, b := h.hook(actorB, "claude-session-1", projection(t, reverseShell, 2)); b.DetectedMask != 0 {
		t.Fatalf("other actor %+v", b)
	}
}

// J44 b: step one, suspend 40 min, resume, step two: still matched; the
// same 40 min while running is past the 30 min window.
func TestSuspendPausesTheChainClock(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	h.hook(actorA, "s1", projection(t, reverseShell, 1))
	h.advance(time.Minute)
	h.life(LifecycleEvent{Actor: actorA, Event: LifecycleSuspended})
	h.advance(40 * time.Minute)
	h.life(LifecycleEvent{Actor: actorA, Event: LifecycleResumed})
	h.advance(time.Minute)
	if s, a := h.hook(actorA, "s1", projection(t, reverseShell, 2)); !slices.Contains(s.DetectedChainIDs, reverseShell) ||
		!slices.Contains(a.DetectedChainIDs, reverseShell) {
		t.Fatalf("after a suspend: session %+v actor %+v", s, a)
	}
	h.hook(actorB, "s1", projection(t, reverseShell, 1))
	h.advance(41 * time.Minute)
	if _, a := h.hook(actorB, "s1", projection(t, reverseShell, 2)); a.DetectedMask != 0 {
		t.Fatalf("41 running minutes still matched: %+v", a)
	}
}

// J44 c: fork, then step two in the child: matched in its session and actor
// windows; the parent's later steps stay its own.
func TestForkInheritsWindows(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	h.hook(actorA, "s1", projection(t, reverseShell, 1))
	r := h.life(LifecycleEvent{Actor: actorB, Event: LifecycleForked, Parent: &actorA})
	if r.CopiedEvents != 2 {
		t.Fatalf("copied %+v", r)
	}
	if again := h.life(LifecycleEvent{Actor: actorB, Event: LifecycleForked, Parent: &actorA}); again.CopiedEvents != 0 {
		t.Fatalf("second fork event copied again: %+v", again)
	}
	h.advance(time.Second)
	if s, a := h.hook(actorB, "s1", projection(t, reverseShell, 2)); !slices.Contains(s.DetectedChainIDs, reverseShell) ||
		!slices.Contains(a.DetectedChainIDs, reverseShell) {
		t.Fatalf("child: session %+v actor %+v", s, a)
	}
	other := Actor{Atespace: "eng-pay", UID: actorB.UID}
	if _, err := h.client.Lifecycle(context.Background(), LifecycleEvent{Actor: other, Event: LifecycleForked, Parent: &actorA}); err == nil {
		t.Fatal("a fork across atespaces inherited windows")
	}
}

// J44 d: download, revert, execute: no same-artifact match.
func TestRevertBarrierStopsSameArtifactChains(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	const chain = guardrail.ToolChainDownloadThenExecuteSameArtifact
	h.hook(actorA, "s1", projection(t, chain, 1))
	h.advance(time.Second)
	if r := h.life(LifecycleEvent{Actor: actorA, Event: LifecycleReverted}); r.Barriers != 2 {
		t.Fatalf("barriers %+v", r)
	}
	h.advance(time.Second)
	if s, a := h.hook(actorA, "s1", projection(t, chain, 2)); s.DetectedMask != 0 || a.DetectedMask != 0 {
		t.Fatalf("matched across a revert: session %+v actor %+v", s, a)
	}
	// Control: without a revert the same pair matches.
	h.hook(actorB, "s1", projection(t, chain, 1))
	h.advance(time.Second)
	if _, a := h.hook(actorB, "s1", projection(t, chain, 2)); !slices.Contains(a.DetectedChainIDs, chain) {
		t.Fatalf("control: %+v", a)
	}
}

// J44 e: a secret read in the actor window, then egress at the callout:
// refused (alert mode only reports it); no window, nothing to match.
func TestCalloutEgressAfterSecretRead(t *testing.T) {
	for _, mode := range []string{EgressBlock, EgressAlert} {
		h := newHarness(t, t.TempDir(), Options{EgressAction: mode})
		v, err := h.client.CheckEgress(context.Background(), EgressRequest{Actor: actorA, Host: "example.com", Method: "POST"})
		if err != nil || v.Deny || len(v.Detected) != 0 {
			t.Fatalf("%s: no window: %+v err=%v", mode, v, err)
		}
		h.hook(actorA, "s1", projection(t, guardrail.ToolChainSecretReadThenEgress, 1))
		h.advance(time.Second)
		v, err = h.client.CheckEgress(context.Background(), EgressRequest{Actor: actorA, Host: "example.com", Method: "POST"})
		if err != nil || !slices.Contains(v.Detected, guardrail.ToolChainSecretReadThenEgress) ||
			v.Deny != (mode == EgressBlock) || v.Rule != guardrail.ToolChainSecretReadThenEgress {
			t.Fatalf("%s: after a secret read: %+v err=%v", mode, v, err)
		}
	}
	if _, err := New(Options{Dir: t.TempDir(), EgressAction: "deny"}); err == nil {
		t.Fatal("bad egress action accepted")
	}
}

// Intent: prompt then calls through the leader; a --task actor's task text
// is its intent until a prompt; a call that is not an actor's uses the
// fallback.
func TestIntentStoreOnTheLeader(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	type ctxKey struct{}
	store := &IntentStore{Client: h.client, Fallback: intentstore.NewProcess(intentstore.Limits{MaxSessions: 4, MaxPrior: 4, TTL: time.Minute}),
		ActorOf: func(ctx context.Context) (Actor, bool) { a, ok := ctx.Value(ctxKey{}).(Actor); return a, ok }}
	ctx := context.WithValue(context.Background(), ctxKey{}, actorA)
	if err := store.ObservePrompt(ctx, "k1", "deploy the web app"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendToolCall(ctx, "k1", intentstore.ToolCall{Tool: "Read", Args: "README"}); err != nil {
		t.Fatal(err)
	}
	snap, err := store.AppendToolCall(ctx, "k1", intentstore.ToolCall{Tool: "Bash", Args: "make"})
	if err != nil || snap.UserIntent != "deploy the web app" || len(snap.Prior) != 1 || snap.Prior[0].Tool != "Read" {
		t.Fatalf("snapshot %+v err=%v", snap, err)
	}
	if err := h.client.PutTask(context.Background(), actorB, "fix the flaky test in pkg/foo"); err != nil {
		t.Fatal(err)
	}
	ctxB := context.WithValue(context.Background(), ctxKey{}, actorB)
	if snap, err := store.AppendToolCall(ctxB, "k1", intentstore.ToolCall{Tool: "Bash", Args: "go test"}); err != nil ||
		snap.UserIntent != "fix the flaky test in pkg/foo" {
		t.Fatalf("task intent %+v err=%v", snap, err)
	}
	if err := store.Reset(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	if snap, _ := store.AppendToolCall(ctx, "k1", intentstore.ToolCall{Tool: "x"}); snap.UserIntent != "" || len(snap.Prior) != 0 {
		t.Fatalf("after reset %+v", snap)
	}
	if err := store.ObservePrompt(context.Background(), "host", "local"); err != nil {
		t.Fatal(err)
	}
	if snap, _ := store.Fallback.AppendToolCall(context.Background(), "host", intentstore.ToolCall{}); snap.UserIntent != "local" {
		t.Fatalf("fallback %+v", snap)
	}
}

// Failover: a new leader on the same volume keeps the chain windows, the
// running-time clocks and task intents.
func TestNewLeaderKeepsChainsClocksAndTasks(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, dir, Options{})
	h.hook(actorA, "s1", projection(t, reverseShell, 1))
	h.life(LifecycleEvent{Actor: actorA, Event: LifecycleSuspended})
	if err := h.client.PutTask(context.Background(), actorA, "the task"); err != nil {
		t.Fatal(err)
	}
	h.srv.Close()
	_ = h.svc.Close()

	n := newHarness(t, dir, Options{})
	n.now = h.clock().Add(40 * time.Minute)
	n.life(LifecycleEvent{Actor: actorA, Event: LifecycleResumed})
	if s, a := n.hook(actorA, "s1", projection(t, reverseShell, 2)); !slices.Contains(s.DetectedChainIDs, reverseShell) ||
		!slices.Contains(a.DetectedChainIDs, reverseShell) {
		t.Fatalf("after failover: session %+v actor %+v", s, a)
	}
	got, err := n.svc.IntentGet(context.Background(), IntentRequest{Actor: actorA, Key: "k"})
	if err != nil || got.UserIntent != "the task" || !got.Task {
		t.Fatalf("task after failover %+v err=%v", got, err)
	}
}

// Parallel calls of one actor are ordered: every event gets its own sequence.
func TestParallelCallsOfOneActorAreOrdered(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.hook(actorA, "s1", projection(t, reverseShell, 1))
		}()
	}
	wg.Wait()
	h.advance(time.Second)
	if _, a := h.hook(actorA, "s9", projection(t, reverseShell, 2)); !slices.Contains(a.DetectedChainIDs, reverseShell) {
		t.Fatalf("after parallel calls: %+v", a)
	}
}

// The wire carries the fields JSON leaves out (keyed digests, SQL sources).
func TestGobKeepsJSONExcludedFields(t *testing.T) {
	in := audit.ToolChainResolvePendingInput{SuccessfulReadPathDigest: ruleset,
		SuccessfulSQLValueSource: audit.ToolChainPendingSQLValueSource{DatabaseIdentityDigest: ruleset}}
	raw, err := encodeGob(in)
	if err != nil {
		t.Fatal(err)
	}
	var out audit.ToolChainResolvePendingInput
	if err := decodeGob(raw, &out); err != nil || out.SuccessfulReadPathDigest != ruleset ||
		out.SuccessfulSQLValueSource.DatabaseIdentityDigest != ruleset {
		t.Fatalf("round trip %+v err=%v", out, err)
	}
	for _, bad := range []Actor{{Atespace: "../x", UID: actorA.UID}, {Atespace: "eng", UID: "../../etc"}, {}} {
		if bad.Validate() == nil {
			t.Fatalf("%+v accepted", bad)
		}
	}
}
