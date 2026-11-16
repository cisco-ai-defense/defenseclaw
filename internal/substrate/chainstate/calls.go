// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"errors"
	"time"

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
// The leader remembers, per actor, scope, session and call identity (the
// invocation digest, the same on every replica), the calls it prepared and
// resolved. A further result of a resolved call is a replay, never missing:
//   - one whose content proves the call read nothing changes nothing;
//   - one that may have read starts the secret-read chain from the call's
//     proposal (its secret-read step 1, as an unsuccessful result that may
//     have read does, GAP-0337), so a second result never clears a read;
//   - with the proposal unknown (prepared before this leader started) or the
//     ruleset changed since, it stays missing: the gateway marks it (R1).
// A result of a call nobody prepared or resolved here stays missing. The
// memory lasts the chain window (ToolChainMaxHorizon) and is not saved: a
// leader that restarts forgets it and marks such a result, the safe side.

// callMemoMax bounds one actor's remembered calls.
const callMemoMax = 4096

type callKey struct {
	scope               Scope
	session, invocation string
}

type callMemo struct {
	// known: this leader took the call's proposal (start holds its
	// secret-read step 1 when it had one).
	known, hasStart, resolved bool
	start                     guardrail.ToolChainProjection
	ruleset                   string
	at                        time.Time
}

func callKeyOf(in ObserveRequest, invocation string) (callKey, bool) {
	if in.Join == nil || in.Join.SessionDigest == "" || invocation == "" {
		return callKey{}, false
	}
	return callKey{scope: in.Scope, session: in.Join.SessionDigest, invocation: invocation}, true
}

// noteCall remembers a call whose proposal the window took (the actor lock
// is held).
func (s *Service) noteCall(e *actorEntry, in ObserveRequest, x audit.ToolChainPreparePendingInput, status audit.ToolChainPendingStatus, err error) {
	key, ok := callKeyOf(in, x.ToolInvocationDigest)
	if !ok {
		return
	}
	switch {
	case errors.Is(err, audit.ErrToolChainPendingConflict):
		// A reused call id makes both proposals unauthoritative.
		delete(e.calls, key)
	case err != nil || status != audit.ToolChainPendingPrepared:
	default:
		c := callMemo{known: true, ruleset: x.RulesetFingerprint, at: s.opts.Now()}
		c.start, c.hasStart = guardrail.ToolChainProjectionStep(x.Projection, guardrail.ToolChainSecretReadThenEgress, 1)
		s.putCall(e, key, c)
	}
}

// furtherResult is the leader's answer to a call's result after the window's
// own ResolvePending (the actor lock is held).
func (s *Service) furtherResult(ctx context.Context, repo *audit.ToolChainRepository, e *actorEntry, in ObserveRequest,
	x audit.ToolChainResolvePendingInput, r audit.ToolChainResolvePendingResult) (audit.ToolChainResolvePendingResult, error) {
	key, ok := callKeyOf(in, x.ToolInvocationDigest)
	if !ok {
		return r, nil
	}
	now := s.opts.Now()
	switch r.Status {
	case audit.ToolChainPendingResolved:
		c := e.calls[key]
		c.resolved, c.at = true, now
		s.putCall(e, key, c)
		return r, nil
	case audit.ToolChainPendingMissing:
	default:
		return r, nil
	}
	c, ok := e.calls[key]
	if !ok || !c.resolved || now.Sub(c.at) > guardrail.ToolChainMaxHorizon {
		return r, nil
	}
	replay := audit.ToolChainResolvePendingResult{Status: audit.ToolChainPendingReplay}
	if !x.ResultMayHaveRead || c.known && !c.hasStart {
		return replay, nil
	}
	if !c.hasStart || c.ruleset != x.RulesetFingerprint {
		return r, nil
	}
	if err := s.notePending(e, in.Scope, c.start); err != nil {
		return audit.ToolChainResolvePendingResult{}, err
	}
	observation, err := repo.Observe(ctx, audit.ToolChainObserveInput{
		SemanticEventID: x.TerminalSemanticEventID, ConnectorInstanceID: x.ConnectorInstanceID,
		InputFingerprint: x.TerminalInputFingerprint, RulesetFingerprint: x.RulesetFingerprint,
		Projection: c.start,
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

// putCall stores c, dropping expired calls, then the oldest, at the bound.
func (s *Service) putCall(e *actorEntry, key callKey, c callMemo) {
	if e.calls == nil {
		e.calls = make(map[callKey]callMemo)
	}
	if _, ok := e.calls[key]; !ok && len(e.calls) >= callMemoMax {
		now := s.opts.Now()
		var oldest callKey
		var oldestAt time.Time
		for k, v := range e.calls {
			if now.Sub(v.at) > guardrail.ToolChainMaxHorizon {
				delete(e.calls, k)
				continue
			}
			if oldestAt.IsZero() || v.at.Before(oldestAt) {
				oldest, oldestAt = k, v.at
			}
		}
		if len(e.calls) >= callMemoMax {
			delete(e.calls, oldest)
		}
	}
	e.calls[key] = c
}
