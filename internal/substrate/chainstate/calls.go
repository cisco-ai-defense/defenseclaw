// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"container/list"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// A tool call can have more than one result: Claude Code and Cursor post a
// failure result and then a PostToolUse for one failed call, and the kit
// retries a post that timed out. The window resolves a call's proposal once
// and drops it, so a further result found nothing (Missing), and the gateway
// marked the actor unrecorded as if the call had reached no leader (review
// rch3 R1): every benign failed read of a missing credentials file refused
// the actor's next upload (substrate-1 GAP-0348, GAP-0345).
//
// The leader remembers the calls it prepared and resolved, by actor, session
// and call identity (the invocation digest, the same on every replica), with
// what each scope knows of the call. A further result of a resolved call is
// a replay, never missing:
//   - one whose content proves the call read nothing changes nothing;
//   - one that may have read starts the secret-read chain from the call's
//     proposal (its secret-read step 1, as an unsuccessful result that may
//     have read does, GAP-0337), so a second result never clears a read;
//   - with the proposal unknown (prepared before this leader started) or the
//     ruleset changed since, it stays missing: the gateway marks it (R1).
// A result of a call nobody prepared or resolved here stays missing.
//
// The memory is small and bounded (GAP-0350): a call keeps its two scopes'
// flags and, only when its proposal read a credentials file, that one step
// (callStart), never the proposal. Calls leave in the order they were last
// touched: past the chain window (ToolChainMaxHorizon, dropped on every
// update and lookup), past callsPerActorMax for their actor, or past
// callsLeaderMax for the leader. Each drop is O(1). A dropped call, like one
// a restarted leader never saw (the memory is not saved), answers missing,
// so its further result is marked: availability, never a silent replay.

const (
	// callsPerActorMax bounds one actor's remembered calls: below the
	// leader's bound a busy actor ages out its own calls, not other actors'.
	// At the leader's bound (32 actors at this one) the oldest calls go,
	// whoever's: their further results are marked (fail closed).
	callsPerActorMax = 4096
	// callsLeaderMax bounds the leader's remembered calls (about 1 KiB each
	// through noteCall and furtherResult, TestCallTableBytesPerCall: under
	// 192 MiB of the 2 GiB leader).
	callsLeaderMax = 131072
)

type callKey struct {
	actor, session, invocation string
}

// callStart is a proposal's secret-read step 1, as
// guardrail.ToolChainProjectionStep keeps it, and the ruleset it was
// prepared under.
type callStart struct {
	parse                 actionfacts.ParseStatus
	enforce               bool
	join, output, ruleset string
}

func newCallStart(p guardrail.ToolChainProjection, ruleset string) *callStart {
	step, ok := guardrail.ToolChainProjectionStep(p, guardrail.ToolChainSecretReadThenEgress, 1)
	index, indexed := guardrail.ToolChainIndexByID(guardrail.ToolChainSecretReadThenEgress)
	if !ok || !indexed {
		return nil
	}
	return &callStart{parse: step.ParseStatus, enforce: step.EnforcementStepMask != 0,
		join: step.EnforcementJoinDigests[index], output: step.EnforcementOutputJoinDigests[index], ruleset: ruleset}
}

// projection is the step as ToolChainProjectionStep returned it.
func (c *callStart) projection() guardrail.ToolChainProjection {
	bit, _ := guardrail.ToolChainStepMask(guardrail.ToolChainSecretReadThenEgress, 1)
	index, _ := guardrail.ToolChainIndexByID(guardrail.ToolChainSecretReadThenEgress)
	p := guardrail.ToolChainProjection{ParseStatus: c.parse, DetectionStepMask: bit}
	if c.enforce {
		p.EnforcementStepMask = bit
	}
	p.EnforcementJoinDigests[index], p.EnforcementOutputJoinDigests[index] = c.join, c.output
	return p
}

// scopeCall is what one scope (session or actor window) knows of a call:
// known, this leader took its proposal (start is its secret-read step, nil
// when it read no credentials file); resolved, it took a result of it.
//
// cleared: the result that resolved the call proved its read failed (an
// unsuccessful result whose content proves nothing was read, or a denied
// call): a further result then starts the chain only if its own content
// shows a read (GAP-0352).
type scopeCall struct {
	known, resolved, cleared bool
	start                    *callStart
}

func scopeIndex(s Scope) int {
	if s == ScopeActor {
		return 1
	}
	return 0
}

// callNode is one call. Its scopes leave together, so an eviction can't
// leave a session replay over an actor-window miss (review rk347 P3-1).
type callNode struct {
	key       callKey
	scopes    [2]scopeCall
	at        time.Time
	all, mine *list.Element
}

// callTable is the leader's call memory; its own lock guards it.
type callTable struct {
	mu       sync.Mutex
	byKey    map[callKey]*callNode
	all      *list.List            // every call, least recently touched first
	byActor  map[string]*list.List // each actor's calls, the same order
	perActor int
	max      int
	ttl      time.Duration
}

func newCallTable() *callTable {
	return &callTable{byKey: map[callKey]*callNode{}, all: list.New(), byActor: map[string]*list.List{},
		perActor: callsPerActorMax, max: callsLeaderMax, ttl: guardrail.ToolChainMaxHorizon}
}

// lookup is what scope knows of the call; remembered is false for a call it
// knows nothing of, or one past the window.
func (t *callTable) lookup(key callKey, scope Scope, now time.Time) (c scopeCall, remembered bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked(now)
	n, ok := t.byKey[key]
	if !ok {
		return scopeCall{}, false
	}
	c = n.scopes[scopeIndex(scope)]
	return c, c.known || c.resolved
}

// update applies f to what scope knows of the call and marks it touched now.
func (t *callTable) update(key callKey, scope Scope, now time.Time, f func(*scopeCall)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked(now)
	n, ok := t.byKey[key]
	if ok {
		t.all.MoveToBack(n.all)
		t.byActor[key.actor].MoveToBack(n.mine)
	} else {
		n = &callNode{key: key}
		t.byKey[key] = n
		n.all = t.all.PushBack(n)
		mine := t.byActor[key.actor]
		if mine == nil {
			mine = list.New()
			t.byActor[key.actor] = mine
		}
		n.mine = mine.PushBack(n)
		for mine.Len() > t.perActor {
			t.removeLocked(mine.Front().Value.(*callNode))
		}
		for t.all.Len() > t.max {
			t.removeLocked(t.all.Front().Value.(*callNode))
		}
	}
	n.at = now
	f(&n.scopes[scopeIndex(scope)])
}

// forget drops what scope knows of the call (a reused call id).
func (t *callTable) forget(key callKey, scope Scope) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n, ok := t.byKey[key]
	if !ok {
		return
	}
	n.scopes[scopeIndex(scope)] = scopeCall{}
	if n.scopes == [2]scopeCall{} {
		t.removeLocked(n)
	}
}

// dropActor forgets every call of an actor whose windows were purged.
func (t *callTable) dropActor(actor string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	mine := t.byActor[actor]
	for mine != nil && mine.Len() > 0 {
		t.removeLocked(mine.Front().Value.(*callNode))
		mine = t.byActor[actor]
	}
}

// pruneLocked drops the calls past the window, oldest first: each call is
// dropped once, so the cost is amortized over the updates.
func (t *callTable) pruneLocked(now time.Time) {
	for f := t.all.Front(); f != nil && now.Sub(f.Value.(*callNode).at) > t.ttl; f = t.all.Front() {
		t.removeLocked(f.Value.(*callNode))
	}
}

func (t *callTable) removeLocked(n *callNode) {
	delete(t.byKey, n.key)
	t.all.Remove(n.all)
	if mine := t.byActor[n.key.actor]; mine != nil {
		mine.Remove(n.mine)
		if mine.Len() == 0 {
			delete(t.byActor, n.key.actor)
		}
	}
}

type furtherVerdict int

const (
	// furtherMissing: the window's answer stands (the gateway marks it, R1).
	furtherMissing furtherVerdict = iota
	// furtherReplay: a further result of a resolved call that read nothing.
	furtherReplay
	// furtherChain: a further result that may have read: observe the start.
	furtherChain
)

// furtherResultVerdict decides a result whose ResolvePending found no
// proposal, from what the scope remembers of its call.
func furtherResultVerdict(c scopeCall, remembered, mayHaveRead, showsRead bool, ruleset string) furtherVerdict {
	switch {
	case !remembered || !c.resolved:
		return furtherMissing
	case c.cleared && !showsRead:
		// An earlier result proved the read failed and this one shows no
		// read: the same failure, or no output (GAP-0352).
		return furtherReplay
	case !mayHaveRead:
		return furtherReplay
	case c.start == nil && c.known:
		// The proposal read no credentials file.
		return furtherReplay
	case c.start == nil || c.start.ruleset != ruleset:
		// The proposal is unknown here, or the ruleset changed since.
		return furtherMissing
	}
	return furtherChain
}

func callKeyOf(e *actorEntry, in ObserveRequest, invocation string) (callKey, bool) {
	if in.Join == nil || in.Join.SessionDigest == "" || invocation == "" {
		return callKey{}, false
	}
	return callKey{actor: e.actor.key(), session: in.Join.SessionDigest, invocation: invocation}, true
}

// noteCall remembers a call whose proposal the window took.
func (s *Service) noteCall(e *actorEntry, in ObserveRequest, x audit.ToolChainPreparePendingInput, status audit.ToolChainPendingStatus, err error) {
	key, ok := callKeyOf(e, in, x.ToolInvocationDigest)
	if !ok {
		return
	}
	switch {
	case errors.Is(err, audit.ErrToolChainPendingConflict):
		// A reused call id makes both proposals unauthoritative.
		s.calls.forget(key, in.Scope)
	case err != nil || status != audit.ToolChainPendingPrepared:
	default:
		start := newCallStart(x.Projection, x.RulesetFingerprint)
		s.calls.update(key, in.Scope, s.opts.Now(), func(c *scopeCall) { *c = scopeCall{known: true, start: start} })
	}
}

// furtherResult is the leader's answer to a call's result after the window's
// own ResolvePending (the actor lock is held).
func (s *Service) furtherResult(ctx context.Context, repo *audit.ToolChainRepository, e *actorEntry, in ObserveRequest,
	x audit.ToolChainResolvePendingInput, r audit.ToolChainResolvePendingResult) (audit.ToolChainResolvePendingResult, error) {
	key, ok := callKeyOf(e, in, x.ToolInvocationDigest)
	if !ok {
		return r, nil
	}
	now := s.opts.Now()
	switch r.Status {
	case audit.ToolChainPendingResolved:
		cleared := x.Outcome != audit.ToolChainPendingOutcomeSuccess && !x.ResultMayHaveRead
		s.calls.update(key, in.Scope, now, func(c *scopeCall) { c.resolved, c.cleared = true, cleared })
		return r, nil
	case audit.ToolChainPendingMissing:
	default:
		return r, nil
	}
	c, remembered := s.calls.lookup(key, in.Scope, now)
	switch furtherResultVerdict(c, remembered, x.ResultMayHaveRead, x.ResultShowsRead, x.RulesetFingerprint) {
	case furtherMissing:
		return r, nil
	case furtherReplay:
		return audit.ToolChainResolvePendingResult{Status: audit.ToolChainPendingReplay}, nil
	}
	start := c.start.projection()
	if err := s.notePending(e, in.Scope, start); err != nil {
		return audit.ToolChainResolvePendingResult{}, err
	}
	observation, err := repo.Observe(ctx, audit.ToolChainObserveInput{
		SemanticEventID: x.TerminalSemanticEventID, ConnectorInstanceID: x.ConnectorInstanceID,
		InputFingerprint: x.TerminalInputFingerprint, RulesetFingerprint: x.RulesetFingerprint,
		Projection: start,
	})
	if err != nil {
		return audit.ToolChainResolvePendingResult{}, err
	}
	if observation.Status == audit.ToolChainObserveNoJoin {
		return r, nil
	}
	// Resolved, as the window answers an unsuccessful result that may have
	// read: the gateway then records nothing more for this result.
	return audit.ToolChainResolvePendingResult{Status: audit.ToolChainPendingResolved, Observation: observation}, nil
}
