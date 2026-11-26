// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

const (
	gap0476Commit  = "0123456789abcdef0123456789abcdef01234567"
	gap0476Commit2 = "89abcdef0123456789abcdef0123456789abcdef"
)

func gap0476Path(t *testing.T, p string) string {
	t.Helper()
	d, ok := guardrail.ToolChainPOSIXPathDigest(p)
	if !ok {
		t.Fatalf("no digest for %s", p)
	}
	return d
}

// gap0476Step is step of chain about the file with digest in (and out, the
// output of a decode or the file a derived chain runs).
func gap0476Step(t *testing.T, chain string, step int, in, out string) guardrail.ToolChainProjection {
	t.Helper()
	bit, ok := guardrail.ToolChainStepMask(chain, step)
	if !ok {
		t.Fatalf("unknown chain %s", chain)
	}
	index, _ := guardrail.ToolChainIndexByID(chain)
	p := guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete, DetectionStepMask: bit}
	p.EnforcementJoinDigests[index] = in
	p.EnforcementOutputJoinDigests[index] = out
	if err := guardrail.ValidateToolChainProjection(p); err != nil {
		t.Fatalf("%s step %d: %v", chain, step, err)
	}
	return p
}

// gap0476Flagged runs the last step in both windows and reports whether
// each flagged chain.
func gap0476Flagged(h *harness, actor Actor, chain string, p guardrail.ToolChainProjection) (session, root bool) {
	h.advance(time.Second)
	s, a := h.hook(actor, "s1", p)
	return slices.Contains(s.DetectedChainIDs, chain), slices.Contains(a.DetectedChainIDs, chain)
}

// GAP-0476: substrate undo reports itself; a download after the checkpoint
// into a file the undo removed no longer joins a later run of that path. A
// download outside the folder, and one before the checkpoint, still do.
func TestGAP0476UndoForgetsOnlyRevertedFilesAfterTheCheckpoint(t *testing.T) {
	const chain = guardrail.ToolChainDownloadThenExecuteSameArtifact
	inTree, outside := gap0476Path(t, "/work/app/dl.sh"), gap0476Path(t, "/tmp/dl.sh")
	early := gap0476Path(t, "/work/app/early.sh")

	h := newHarness(t, t.TempDir(), Options{})
	h.hook(actorA, "s1", gap0476Step(t, chain, 1, early, ""))
	h.advance(time.Second)
	h.life(LifecycleEvent{Actor: actorA, Event: LifecycleCheckpointed, Checkpoint: gap0476Commit})
	h.advance(time.Second)
	h.hook(actorA, "s1", gap0476Step(t, chain, 1, inTree, ""))
	h.advance(time.Second)
	h.hook(actorA, "s1", gap0476Step(t, chain, 1, outside, ""))
	h.advance(time.Second)
	r := h.life(LifecycleEvent{Actor: actorA, Event: LifecycleUndone, Checkpoint: gap0476Commit,
		Removed: []string{inTree}, Restored: []string{early}})
	if r.CheckpointUnknown || r.Forgotten != 2 {
		t.Fatalf("undo result %+v, want the in-folder download forgotten in both windows", r)
	}
	if s, a := gap0476Flagged(h, actorA, chain, gap0476Step(t, chain, 2, inTree, "")); s || a {
		t.Fatalf("a run of the file the undo removed still flagged: session %v actor %v", s, a)
	}
	if s, a := gap0476Flagged(h, actorA, chain, gap0476Step(t, chain, 2, outside, "")); !s || !a {
		t.Fatalf("a download outside the folder no longer flagged: session %v actor %v", s, a)
	}
	if s, a := gap0476Flagged(h, actorA, chain, gap0476Step(t, chain, 2, early, "")); !s || !a {
		t.Fatalf("a download before the checkpoint no longer flagged: session %v actor %v", s, a)
	}

	// Control, the base's behaviour: the same steps without the undo
	// report flag the run of the reverted path.
	h.life(LifecycleEvent{Actor: actorB, Event: LifecycleCheckpointed, Checkpoint: gap0476Commit})
	h.advance(time.Second)
	h.hook(actorB, "s1", gap0476Step(t, chain, 1, inTree, ""))
	if s, a := gap0476Flagged(h, actorB, chain, gap0476Step(t, chain, 2, inTree, "")); !s || !a {
		t.Fatalf("control: session %v actor %v", s, a)
	}
}

// A file the undo put back: the facts from after the checkpoint go when
// the leader has the checkpoint's mark, and all stay without it. A removed
// file without a mark: every fact about it goes (it did not exist at the
// checkpoint and is gone).
func TestGAP0476UndoRestoredFilesNeedTheCheckpointMark(t *testing.T) {
	const chain = guardrail.ToolChainDownloadThenExecuteSameArtifact
	tracked, added := gap0476Path(t, "/work/app/run.sh"), gap0476Path(t, "/work/app/new.sh")

	h := newHarness(t, t.TempDir(), Options{})
	h.life(LifecycleEvent{Actor: actorA, Event: LifecycleCheckpointed, Checkpoint: gap0476Commit})
	h.advance(time.Second)
	h.hook(actorA, "s1", gap0476Step(t, chain, 1, tracked, ""))
	h.advance(time.Second)
	if r := h.life(LifecycleEvent{Actor: actorA, Event: LifecycleUndone, Checkpoint: gap0476Commit, Restored: []string{tracked}}); r.CheckpointUnknown || r.Forgotten != 2 {
		t.Fatalf("known mark: %+v", r)
	}
	if s, a := gap0476Flagged(h, actorA, chain, gap0476Step(t, chain, 2, tracked, "")); s || a {
		t.Fatalf("a run of the file the undo put back still flagged: session %v actor %v", s, a)
	}

	// Unknown checkpoint (taken before this version).
	h.hook(actorB, "s1", gap0476Step(t, chain, 1, tracked, ""))
	h.advance(time.Second)
	h.hook(actorB, "s1", gap0476Step(t, chain, 1, added, ""))
	h.advance(time.Second)
	r := h.life(LifecycleEvent{Actor: actorB, Event: LifecycleUndone, Checkpoint: gap0476Commit2,
		Removed: []string{added}, Restored: []string{tracked}})
	if !r.CheckpointUnknown || r.Forgotten != 2 {
		t.Fatalf("unknown mark: %+v", r)
	}
	if s, a := gap0476Flagged(h, actorB, chain, gap0476Step(t, chain, 2, tracked, "")); !s || !a {
		t.Fatalf("without the mark a put-back file's download was forgotten: session %v actor %v", s, a)
	}
	if s, a := gap0476Flagged(h, actorB, chain, gap0476Step(t, chain, 2, added, "")); s || a {
		t.Fatalf("a removed file's download still flagged: session %v actor %v", s, a)
	}
}

// The other artifact chains: a sensitive-egress artifact the undo removed
// is forgotten; a download the agent decoded into a file outside the folder
// still joins the run of the decoded file; a decode whose output the undo
// removed no longer joins.
func TestGAP0476UndoOtherArtifactChains(t *testing.T) {
	inTree, outside := gap0476Path(t, "/work/app/payload.b64"), gap0476Path(t, "/tmp/payload.sh")
	decoded := gap0476Path(t, "/work/app/payload.sh")

	const egress = guardrail.ToolChainSensitiveEgressArtifactThenExec
	h := newHarness(t, t.TempDir(), Options{})
	h.life(LifecycleEvent{Actor: actorA, Event: LifecycleCheckpointed, Checkpoint: gap0476Commit})
	h.advance(time.Second)
	h.hook(actorA, "s1", gap0476Step(t, egress, 1, inTree, ""))
	h.advance(time.Second)
	h.life(LifecycleEvent{Actor: actorA, Event: LifecycleUndone, Checkpoint: gap0476Commit, Removed: []string{inTree}})
	if s, a := gap0476Flagged(h, actorA, egress, gap0476Step(t, egress, 2, inTree, "")); s || a {
		t.Fatalf("sensitive-egress artifact the undo removed still flagged: session %v actor %v", s, a)
	}

	const derived = guardrail.ToolChainDownloadDecodeExecuteSameArtifact
	for _, tc := range []struct {
		name    string
		output  string
		removed []string
		flagged bool
	}{
		{"decoded outside the folder", outside, []string{inTree}, true},
		{"decoded into the folder", decoded, []string{inTree, decoded}, false},
	} {
		h := newHarness(t, t.TempDir(), Options{})
		h.life(LifecycleEvent{Actor: actorA, Event: LifecycleCheckpointed, Checkpoint: gap0476Commit})
		h.advance(time.Second)
		h.hook(actorA, "s1", gap0476Step(t, derived, 1, inTree, ""))
		h.advance(time.Second)
		h.hook(actorA, "s1", gap0476Step(t, derived, 2, inTree, tc.output))
		h.advance(time.Second)
		h.life(LifecycleEvent{Actor: actorA, Event: LifecycleUndone, Checkpoint: gap0476Commit, Removed: tc.removed})
		if s, a := gap0476Flagged(h, actorA, derived, gap0476Step(t, derived, 3, "", tc.output)); s != tc.flagged || a != tc.flagged {
			t.Fatalf("%s: session %v actor %v, want %v", tc.name, s, a, tc.flagged)
		}
	}
}

// A repeat of an observation whose stored event an undo changed is the
// same event, not an integrity failure.
func TestGAP0476ReplayOfAForgottenEvent(t *testing.T) {
	const chain = guardrail.ToolChainDownloadThenExecuteSameArtifact
	inTree := gap0476Path(t, "/work/app/dl.sh")
	h := newHarness(t, t.TempDir(), Options{})
	id, err := audit.NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(id))
	in := audit.ToolChainObserveInput{SemanticEventID: id, InputFingerprint: hex.EncodeToString(sum[:]),
		RulesetFingerprint: ruleset, Projection: gap0476Step(t, chain, 1, inTree, ""), DenyEligible: true}
	observe := func() []audit.ToolChainObserveResult {
		var out []audit.ToolChainObserveResult
		for _, scope := range []Scope{ScopeSession, ScopeActor} {
			b, err := h.client.Bind(actorA, scope, "claudecode", "s1", "PreToolUse")
			if err != nil {
				t.Fatal(err)
			}
			r, err := b.Observe(context.Background(), in)
			if err != nil {
				t.Fatalf("%s observe: %v", scope, err)
			}
			out = append(out, r)
		}
		return out
	}
	observe()
	h.advance(time.Second)
	if r := h.life(LifecycleEvent{Actor: actorA, Event: LifecycleUndone, Removed: []string{inTree}}); r.Forgotten != 2 {
		t.Fatalf("undo %+v", r)
	}
	for _, r := range observe() {
		if r.Status != audit.ToolChainObserveReplay {
			t.Fatalf("repeat after the undo: %+v", r)
		}
	}
	if s, a := gap0476Flagged(h, actorA, chain, gap0476Step(t, chain, 2, inTree, "")); s || a {
		t.Fatalf("the repeat brought the forgotten download back: session %v actor %v", s, a)
	}
}

func TestGAP0476WorkspaceEventsAreChecked(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	many := make([]string, MaxUndoFiles+1)
	for i := range many {
		many[i] = strings.Repeat("a", 64)
	}
	for name, ev := range map[string]LifecycleEvent{
		"checkpoint without commit": {Actor: actorA, Event: LifecycleCheckpointed},
		"checkpoint bad commit":     {Actor: actorA, Event: LifecycleCheckpointed, Checkpoint: "HEAD"},
		"undo bad commit":           {Actor: actorA, Event: LifecycleUndone, Checkpoint: "dc-checkpoint-1"},
		"undo bad digest":           {Actor: actorA, Event: LifecycleUndone, Removed: []string{"/work/app/dl.sh"}},
		"undo upper-case digest":    {Actor: actorA, Event: LifecycleUndone, Restored: []string{strings.Repeat("A", 64)}},
		"undo too many":             {Actor: actorA, Event: LifecycleUndone, Removed: many},
	} {
		if _, err := h.client.Lifecycle(context.Background(), ev); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A caller's time never sets a checkpoint's mark: a mark moved back
	// would forget a download from before the checkpoint.
	const chain = guardrail.ToolChainDownloadThenExecuteSameArtifact
	p := gap0476Path(t, "/work/app/early.sh")
	h.hook(actorA, "s1", gap0476Step(t, chain, 1, p, ""))
	h.advance(time.Second)
	h.life(LifecycleEvent{Actor: actorA, Event: LifecycleCheckpointed, Checkpoint: gap0476Commit, AtUnixNano: 1})
	h.advance(time.Second)
	if r := h.life(LifecycleEvent{Actor: actorA, Event: LifecycleUndone, Checkpoint: gap0476Commit, Restored: []string{p}}); r.Forgotten != 0 {
		t.Fatalf("a download before the checkpoint was forgotten: %+v", r)
	}
}
