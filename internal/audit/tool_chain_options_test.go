// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

const (
	testActorUIDA = "25a1da0f-1c9b-4ef7-8248-c276138c7f77"
	testActorUIDB = "2e8d6260-7d31-4e56-b416-1222430fa637"
)

func actorRepositoryForTest(t *testing.T, fixture *toolChainFixture, uid string, opts ...ToolChainOption) *ToolChainRepository {
	t.Helper()
	repo, err := fixture.store.ToolChainRepositoryWith(t.Context(), append([]ToolChainOption{WithToolChainActorScope("eng-web", uid)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	repo.now = func() time.Time { return fixture.now }
	return repo
}

// fixedHorizon keeps extra more than the wall-clock window (an actor that
// was suspended for extra).
type fixedHorizon struct{ extra time.Duration }

func (h fixedHorizon) Cutoff(at time.Time, horizon time.Duration) time.Time {
	return at.Add(-horizon - h.extra)
}

func TestToolChainRepositoryWithoutOptionsIsTheSessionRepository(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	repo, err := fixture.store.ToolChainRepositoryWith(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if repo.Scope() != ToolChainScopeSession || repo.horizon != nil || repo.forkParent != nil {
		t.Fatalf("plain repository %+v", repo)
	}
	if _, err := fixture.store.ToolChainRepositoryWith(nil); err == nil { //nolint:staticcheck // a nil context is refused
		t.Fatal("nil context accepted")
	}
}

func TestToolChainActorScopeDigestIsUnambiguousAndScoped(t *testing.T) {
	a, err := ToolChainActorScopeDigest("eng-web", testActorUIDA)
	if err != nil {
		t.Fatal(err)
	}
	for name, parts := range map[string][2]string{
		"other uid":      {"eng-web", testActorUIDB},
		"other atespace": {"eng-pay", testActorUIDA},
		"shifted bytes":  {"eng-web" + testActorUIDA[:1], testActorUIDA[1:]},
	} {
		other, err := ToolChainActorScopeDigest(parts[0], parts[1])
		if err != nil || other == a {
			t.Fatalf("%s: %q err=%v", name, other, err)
		}
	}
	instance := ConnectorInstanceID("01890a5d-ac96-774b-bcce-b302099a8057")
	if root, err := ToolChainRootScopeDigest(instance, "eng-web", testActorUIDA, ""); err == nil && root == a {
		t.Fatal("actor digest collides with a root digest")
	}
	for _, parts := range [][2]string{{"", testActorUIDA}, {"eng-web", ""}} {
		if _, err := ToolChainActorScopeDigest(parts[0], parts[1]); err == nil {
			t.Fatalf("%q accepted", parts)
		}
	}
}

// Every call of one actor lands in its window, whatever session it names;
// another actor (a fork has a new UID) has its own window.
func TestToolChainActorScopeFollowsTheActorAcrossSessions(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	actor := actorRepositoryForTest(t, fixture, testActorUIDA)
	other := actorRepositoryForTest(t, fixture, testActorUIDB)
	if actor.Scope() != ToolChainScopeRoot {
		t.Fatalf("actor scope %s", actor.Scope())
	}
	chainID := guardrail.ToolChainStagedReverseShellPersistence
	first := fixture.seed(t, "session-1", correlationDigest("actor-first"))
	first.Projection = toolChainProjection(t, []string{chainID}, 1, true)
	if _, err := actor.Observe(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	// One event belongs to one actor's window: the root events table keys on
	// the event, so another actor never takes it.
	if _, err := other.Observe(t.Context(), first); !errors.Is(err, ErrToolChainIntegrity) {
		t.Fatalf("another actor took the same event: %v", err)
	}
	fixture.now = fixture.now.Add(time.Second)
	final := fixture.seed(t, "session-2-rotated", correlationDigest("actor-final"))
	final.Projection = toolChainProjection(t, []string{chainID}, 2, true)
	final.DenyEligible = true
	if result, err := fixture.chain.Observe(t.Context(), final); err != nil || result.DetectedMask != 0 {
		t.Fatalf("the session window completed a chain split across sessions: %+v err=%v", result, err)
	}
	result, err := actor.Observe(t.Context(), final)
	if err != nil || !slices.Contains(result.DetectedChainIDs, chainID) {
		t.Fatalf("actor window result=%+v err=%v", result, err)
	}

	// Another actor (a fork's new UID) that never saw step one completes
	// nothing.
	fixture.now = fixture.now.Add(time.Second)
	again := fixture.seed(t, "session-1", correlationDigest("actor-other"))
	again.Projection = toolChainProjection(t, []string{chainID}, 2, true)
	if result, err := other.Observe(t.Context(), again); err != nil || result.DetectedMask != 0 {
		t.Fatalf("another actor's window completed the chain: %+v err=%v", result, err)
	}
}

// A running-time horizon keeps a predecessor the wall-clock window has
// dropped; a horizon that would shrink the window is ignored.
func TestToolChainHorizonKeepsRunningTime(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	wall := actorRepositoryForTest(t, fixture, testActorUIDA)
	running := actorRepositoryForTest(t, fixture, testActorUIDB, WithToolChainHorizon(fixedHorizon{extra: 10 * time.Minute}))
	for _, repo := range []*ToolChainRepository{wall, running} {
		repo.maxHorizon, repo.pendingTTL = time.Minute, time.Minute
	}
	chainID := guardrail.ToolChainStagedReverseShellPersistence
	step := func(repo *ToolChainRepository, name string, n int) ToolChainObserveResult {
		t.Helper()
		input := fixture.seed(t, "s", correlationDigest(name))
		input.Projection = toolChainProjection(t, []string{chainID}, n, true)
		result, err := repo.Observe(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	step(wall, "wall-first", 1)
	step(running, "running-first", 1)
	fixture.now = fixture.now.Add(2 * time.Minute)
	if result := step(wall, "wall-final", 2); result.DetectedMask != 0 {
		t.Fatalf("wall-clock window kept a step past its horizon: %+v", result)
	}
	if result := step(running, "running-final", 2); !slices.Contains(result.DetectedChainIDs, chainID) {
		t.Fatalf("running-time window lost the step: %+v", result)
	}

	at := fixture.now
	shrink := &ToolChainRepository{maxHorizon: time.Minute, horizon: fixedHorizon{extra: -30 * time.Second}}
	if got := shrink.horizonCutoff(at); !got.Equal(at.Add(-time.Minute)) {
		t.Fatalf("a shrinking horizon moved the cutoff to %v", got)
	}
	zero := &ToolChainRepository{maxHorizon: time.Minute, horizon: zeroHorizon{}}
	if got := zero.horizonCutoff(at); !got.Equal(at.Add(-time.Minute)) {
		t.Fatalf("a zero cutoff moved the cutoff to %v", got)
	}
	if _, err := fixture.store.ToolChainRepositoryWith(t.Context(), WithToolChainHorizon(nil)); err == nil {
		t.Fatal("nil horizon accepted")
	}
}

type zeroHorizon struct{}

func (zeroHorizon) Cutoff(time.Time, time.Duration) time.Time { return time.Time{} }

// A fork's repository copies its parent's window when it first opens its
// own, inside the same transaction, and refuses to start without the copy.
func TestToolChainForkParentCopiesOnFirstActivation(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	parentDigest, err := ToolChainActorScopeDigest("eng-web", testActorUIDA)
	if err != nil {
		t.Fatal(err)
	}
	parent := ToolChainPartition{ConnectorInstanceID: fixture.instance.ConnectorInstanceID, ScopeDigest: parentDigest}
	child := actorRepositoryForTest(t, fixture, testActorUIDB, WithToolChainForkParent(parent))
	input := fixture.seed(t, "s", correlationDigest("fork-first"))
	input.Projection = toolChainProjection(t, []string{guardrail.ToolChainStagedReverseShellPersistence}, 1, true)
	if _, err := child.Observe(t.Context(), input); !errors.Is(err, ErrToolChainForkCopyUnsupported) {
		t.Fatalf("fork without copy support: %v", err)
	}

	var copies []ToolChainPartition
	saved := toolChainCopyForkWindow
	t.Cleanup(func() { toolChainCopyForkWindow = saved })
	toolChainCopyForkWindow = func(_ context.Context, tx *sql.Tx, _ *ToolChainRepository, from, to ToolChainPartition, _ time.Time) error {
		if tx == nil {
			t.Error("copy outside the transaction")
		}
		copies = append(copies, from, to)
		return nil
	}
	if _, err := child.Observe(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(time.Second)
	next := fixture.seed(t, "s", correlationDigest("fork-next"))
	next.Projection = toolChainProjection(t, []string{guardrail.ToolChainStagedReverseShellPersistence}, 1, true)
	if _, err := child.Observe(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	childDigest, _ := ToolChainActorScopeDigest("eng-web", testActorUIDB)
	want := []ToolChainPartition{parent, {ConnectorInstanceID: fixture.instance.ConnectorInstanceID, ScopeDigest: childDigest}}
	if !slices.Equal(copies, want) {
		t.Fatalf("copies %+v, want one copy %+v", copies, want)
	}

	for name, opts := range map[string][]ToolChainOption{
		"no actor scope":  {WithToolChainForkParent(parent)},
		"own parent":      {WithToolChainActorScope("eng-web", testActorUIDA), WithToolChainForkParent(parent)},
		"bad digest":      {WithToolChainActorScope("eng-web", testActorUIDB), WithToolChainForkParent(ToolChainPartition{ConnectorInstanceID: parent.ConnectorInstanceID, ScopeDigest: "x"})},
		"bad instance":    {WithToolChainActorScope("eng-web", testActorUIDB), WithToolChainForkParent(ToolChainPartition{ConnectorInstanceID: "x", ScopeDigest: parentDigest})},
		"bad actor scope": {WithToolChainActorScope("", testActorUIDB)},
	} {
		if _, err := fixture.store.ToolChainRepositoryWith(t.Context(), opts...); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
