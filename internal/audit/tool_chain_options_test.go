// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

const (
	testActorUIDA = "25a1da0f-1c9b-4ef7-8248-c276138c7f77"
	testActorUIDB = "2e8d6260-7d31-4e56-b416-1222430fa637"
)

func TestToolChainRepositoryWithoutOptionsIsTheSessionRepository(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	repo, err := fixture.store.ToolChainRepositoryWith(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if repo.Scope() != ToolChainScopeSession || repo.tables != toolChainSessionTables || repo.rootDigest != "" {
		t.Fatalf("plain repository %+v", repo)
	}
	if _, err := fixture.store.ToolChainRepositoryWith(nil); err == nil { //nolint:staticcheck // a nil context is refused
		t.Fatal("nil context accepted")
	}
	if _, err := fixture.store.ToolChainRepositoryWith(t.Context(), WithToolChainClock(nil)); err == nil {
		t.Fatal("nil clock accepted")
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

// The actor's connector instance is a canonical UUIDv7 the same everywhere,
// one per actor; session digests separate connectors and sessions.
func TestToolChainSubstrateKeys(t *testing.T) {
	a, err := ToolChainSubstrateInstanceID("eng-web", testActorUIDA)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateUUIDv7("instance", string(a)); err != nil {
		t.Fatalf("%s: %v", a, err)
	}
	if parsed := uuid.MustParse(string(a)); parsed.Variant() != uuid.RFC4122 {
		t.Fatalf("variant %v", parsed.Variant())
	}
	again, _ := ToolChainSubstrateInstanceID("eng-web", testActorUIDA)
	other, _ := ToolChainSubstrateInstanceID("eng-web", testActorUIDB)
	if again != a || other == a {
		t.Fatalf("instance ids %s %s %s", a, again, other)
	}
	s1, _ := ToolChainSubstrateSessionDigest("claudecode", "s1")
	s2, _ := ToolChainSubstrateSessionDigest("claudecode", "s2")
	c1, _ := ToolChainSubstrateSessionDigest("codex", "s1")
	if s1 == s2 || s1 == c1 || validateSHA256("d", s1, true) != nil {
		t.Fatalf("session digests %s %s %s", s1, s2, c1)
	}
	if _, err := ToolChainSubstrateSessionDigest("claudecode", ""); err == nil {
		t.Fatal("empty session accepted")
	}
}

// substrateChain drives the leader's path: a join recorded at the actor's
// running time, then the repository operation.
type substrateChain struct {
	store    *Store
	instance ConnectorInstanceID
	running  time.Time
	ruleset  string
}

func newSubstrateChain(t *testing.T, store *Store, uid string) *substrateChain {
	t.Helper()
	instance, err := ToolChainSubstrateInstanceID("eng-web", uid)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureToolChainSubstrateInstance(t.Context(), instance); err != nil {
		t.Fatal(err)
	}
	return &substrateChain{store: store, instance: instance,
		running: time.Date(2026, 11, 12, 20, 0, 0, 0, time.UTC), ruleset: correlationDigest("ruleset-a")}
}

func (c *substrateChain) repo(t *testing.T, uid string, actor bool) *ToolChainRepository {
	t.Helper()
	opts := []ToolChainOption{WithToolChainClock(func() time.Time { return c.running })}
	if actor {
		opts = append(opts, WithToolChainActorScope("eng-web", uid))
	}
	repo, err := c.store.ToolChainRepositoryWith(t.Context(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func (c *substrateChain) observe(t *testing.T, repo *ToolChainRepository, session string, projection guardrail.ToolChainProjection) ToolChainObserveResult {
	t.Helper()
	semantic, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := ToolChainSubstrateSessionDigest("claudecode", session)
	fp := correlationDigest(string(semantic))
	if err := c.store.RecordToolChainJoin(t.Context(), ToolChainJoin{ConnectorInstanceID: c.instance,
		SemanticEventID: semantic, InputFingerprint: fp, ReceivedAt: c.running, SessionDigest: digest}); err != nil {
		t.Fatal(err)
	}
	result, err := repo.Observe(t.Context(), ToolChainObserveInput{SemanticEventID: semantic,
		ConnectorInstanceID: c.instance, InputFingerprint: fp, RulesetFingerprint: c.ruleset,
		Projection: projection, DenyEligible: true})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// Every call of one actor lands in its window, whatever session it names;
// another actor (a fork has a new UID) has its own window.
func TestToolChainActorScopeFollowsTheActorAcrossSessions(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	a := newSubstrateChain(t, fixture.store, testActorUIDA)
	b := newSubstrateChain(t, fixture.store, testActorUIDB)
	chainID := guardrail.ToolChainStagedReverseShellPersistence
	sessionA, actorA := a.repo(t, testActorUIDA, false), a.repo(t, testActorUIDA, true)
	for _, repo := range []*ToolChainRepository{sessionA, actorA} {
		a.observe(t, repo, "session-1", toolChainProjection(t, []string{chainID}, 1, true))
	}
	a.running = a.running.Add(time.Second)
	step2 := toolChainProjection(t, []string{chainID}, 2, true)
	if result := a.observe(t, sessionA, "session-2-rotated", step2); result.DetectedMask != 0 {
		t.Fatalf("the session window completed a chain split across sessions: %+v", result)
	}
	if result := a.observe(t, actorA, "session-2-rotated", step2); !slices.Contains(result.DetectedChainIDs, chainID) {
		t.Fatalf("actor window after a session rotation: %+v", result)
	}
	if result := b.observe(t, b.repo(t, testActorUIDB, true), "session-1", step2); result.DetectedMask != 0 {
		t.Fatalf("another actor's window completed the chain: %+v", result)
	}
}

// The window is in running time: a predecessor 40 minutes of wall time
// back, of which 39 suspended, still joins; the same gap in running time
// does not (the chain's 30 minute window).
func TestToolChainRunningClockKeepsTheWindowAcrossASuspend(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	c := newSubstrateChain(t, fixture.store, testActorUIDA)
	chainID := guardrail.ToolChainStagedReverseShellPersistence
	repo := c.repo(t, testActorUIDA, true)
	c.observe(t, repo, "s1", toolChainProjection(t, []string{chainID}, 1, true))
	c.running = c.running.Add(time.Minute) // 40 min of wall time, 39 suspended
	if result := c.observe(t, repo, "s1", toolChainProjection(t, []string{chainID}, 2, true)); !slices.Contains(result.DetectedChainIDs, chainID) {
		t.Fatalf("running-time window lost the predecessor: %+v", result)
	}
	c.running = c.running.Add(40 * time.Minute) // 40 min running
	c.observe(t, repo, "s2", toolChainProjection(t, []string{chainID}, 1, true))
	c.running = c.running.Add(40 * time.Minute)
	if result := c.observe(t, repo, "s2", toolChainProjection(t, []string{chainID}, 2, true)); slices.Contains(result.DetectedChainIDs, chainID) {
		t.Fatalf("a 40 minute running gap still matched: %+v", result)
	}
}

func TestRecordToolChainJoinIsOnceAndChecked(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	c := newSubstrateChain(t, fixture.store, testActorUIDA)
	semantic, _ := NewSemanticEventID()
	s1, _ := ToolChainSubstrateSessionDigest("claudecode", "s1")
	s2, _ := ToolChainSubstrateSessionDigest("claudecode", "s2")
	join := ToolChainJoin{ConnectorInstanceID: c.instance, SemanticEventID: semantic,
		InputFingerprint: correlationDigest("in"), ReceivedAt: c.running, SessionDigest: s1}
	for range 2 {
		if err := fixture.store.RecordToolChainJoin(t.Context(), join); err != nil {
			t.Fatal(err)
		}
	}
	for name, mutate := range map[string]func(*ToolChainJoin){
		"fingerprint": func(j *ToolChainJoin) { j.InputFingerprint = correlationDigest("other") },
		"session":     func(j *ToolChainJoin) { j.SessionDigest = s2 },
	} {
		bad := join
		mutate(&bad)
		if err := fixture.store.RecordToolChainJoin(t.Context(), bad); !errors.Is(err, ErrToolChainIntegrity) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	bad := join
	bad.ReceivedAt = time.Time{}
	if err := fixture.store.RecordToolChainJoin(t.Context(), bad); err == nil {
		t.Fatal("zero time accepted")
	}
}

// A fork starts, in its own store, from its parent's session and actor
// windows read from the parent's store; the copy runs once, leaves the
// parent as it was, and keeps a window the child already made (GAP-0091).
func TestCopyToolChainForkCopiesBothScopesOnce(t *testing.T) {
	dir := t.TempDir()
	parentPath := filepath.Join(dir, "parent.db")
	parentFixture := newToolChainFixture(t, parentPath)
	childFixture := newToolChainFixture(t, filepath.Join(dir, "child.db"))
	parent := newSubstrateChain(t, parentFixture.store, testActorUIDA)
	child := newSubstrateChain(t, childFixture.store, testActorUIDB)
	chainID := guardrail.ToolChainStagedReverseShellPersistence
	step1, step2 := toolChainProjection(t, []string{chainID}, 1, true), toolChainProjection(t, []string{chainID}, 2, true)
	parent.observe(t, parent.repo(t, testActorUIDA, false), "s1", step1)
	parent.observe(t, parent.repo(t, testActorUIDA, false), "s2", step1)
	parent.observe(t, parent.repo(t, testActorUIDA, true), "s1", step1)
	// The child posts a benign call in s2 before the copy.
	child.observe(t, child.repo(t, testActorUIDB, false), "s2", guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusNotApplicable})
	parentDigest, _ := ToolChainActorScopeDigest("eng-web", testActorUIDA)
	childDigest, _ := ToolChainActorScopeDigest("eng-web", testActorUIDB)
	fork := ToolChainForkCopy{ParentInstance: parent.instance, ChildInstance: child.instance,
		ParentActorDigest: parentDigest, ChildActorDigest: childDigest, At: parent.running}
	result, err := childFixture.store.CopyToolChainFork(t.Context(), parentPath, fork)
	if err != nil || result.Copied != 2 || result.Skipped != 1 {
		t.Fatalf("copy %+v err=%v", result, err)
	}
	if _, err := childFixture.store.CopyToolChainFork(t.Context(), parentPath, fork); !errors.Is(err, ErrToolChainForkAlreadyStarted) {
		t.Fatalf("second copy: %v", err)
	}
	child.running = parent.running.Add(time.Second)
	if result := child.observe(t, child.repo(t, testActorUIDB, false), "s1", step2); !slices.Contains(result.DetectedChainIDs, chainID) {
		t.Fatalf("child session window: %+v", result)
	}
	if result := child.observe(t, child.repo(t, testActorUIDB, true), "s9", step2); !slices.Contains(result.DetectedChainIDs, chainID) {
		t.Fatalf("child actor window: %+v", result)
	}
	windows, err := parentFixture.store.ToolChainInstanceWindows(t.Context(), parent.instance)
	if err != nil || len(windows) != 3 {
		t.Fatalf("parent windows %+v err=%v", windows, err)
	}
	for _, bad := range []ToolChainForkCopy{
		{ParentInstance: parent.instance, ChildInstance: parent.instance, ParentActorDigest: parentDigest, ChildActorDigest: childDigest, At: parent.running},
		{ParentInstance: parent.instance, ChildInstance: child.instance, ParentActorDigest: parentDigest, ChildActorDigest: parentDigest, At: parent.running},
		{ParentInstance: parent.instance, ChildInstance: child.instance, ParentActorDigest: parentDigest, ChildActorDigest: childDigest},
	} {
		if _, err := childFixture.store.CopyToolChainFork(t.Context(), parentPath, bad); err == nil || errors.Is(err, ErrToolChainForkAlreadyStarted) {
			t.Fatalf("bad fork %+v: %v", bad, err)
		}
	}
	if _, err := childFixture.store.CopyToolChainFork(t.Context(), "", fork); err == nil {
		t.Fatal("a copy without the parent's store ran")
	}
}

// A revert's mutation barrier stops a same-artifact chain across it.
func TestToolChainMutationBarrier(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	c := newSubstrateChain(t, fixture.store, testActorUIDA)
	chainID := guardrail.ToolChainDownloadThenExecuteSameArtifact
	repo := c.repo(t, testActorUIDA, true)
	step1, step2 := toolChainProjection(t, []string{chainID}, 1, true), toolChainProjection(t, []string{chainID}, 2, true)
	c.observe(t, repo, "s1", step1)
	c.running = c.running.Add(time.Second)
	if result := c.observe(t, repo, "s1", step2); !slices.Contains(result.DetectedChainIDs, chainID) {
		t.Fatalf("control: no match without a barrier: %+v", result)
	}
	c.running = c.running.Add(time.Second)
	c.observe(t, repo, "s1", step1)
	c.running = c.running.Add(time.Second)
	c.observe(t, repo, "s1", guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusNotApplicable,
		DetectionStepMask: guardrail.ToolChainArtifactMutationBarrier})
	c.running = c.running.Add(time.Second)
	if result := c.observe(t, repo, "s1", step2); slices.Contains(result.DetectedChainIDs, chainID) {
		t.Fatalf("matched across a revert barrier: %+v", result)
	}
}
