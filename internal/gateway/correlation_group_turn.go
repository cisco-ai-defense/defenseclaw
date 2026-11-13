// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// hookCorrelationGroupLimits bounds the hook occurrences that share one
// correlation transaction (audit.Store.JoinCorrelationGroup): at most the
// occurrences of one hook-call write group, and none joins a transaction
// that has held the store's one writer for 20 ms, so the audit rows of the
// calls already answered, which wait for that writer, get it back within a
// few milliseconds of work. Code constants, not configuration; tests change
// them.
var hookCorrelationGroupLimits = audit.CorrelationGroupLimits{Occurrences: 64, Hold: 20 * time.Millisecond}

// correlateHookOccurrenceInTurn runs one correlation attempt of a hook in the
// store's correlation turn (S8 design section 13). It waits for the turn
// with the caller's context, so a caller that leaves while queued takes
// nothing. The attempt runs on audit.CorrelationTurnContext: the caller's
// context, except that while the attempt holds the store write turn it has
// no cancellation or deadline, because its statements then share a
// transaction with the occurrences of other hooks and an interrupted
// statement would make SQLite roll back all of them. The context the attempt
// returns is put back on the caller's context.
//
// The turn replaces the per-session turn of rel-1-0-6 GAP-0490: the hooks of
// one session still correlate one at a time and in arrival order, and the
// occurrences of every session that queue behind each other now share one
// baton turn, one BEGIN and one COMMIT instead of one each (issue #1384).
func (a *APIServer) correlateHookOccurrenceInTurn(
	ctx context.Context,
	profile connector.HookProfile,
	req agentHookRequest,
	rawBody []byte,
) (context.Context, agentHookRequest, error) {
	if a == nil || a.store == nil {
		return a.correlateHookOccurrenceOnce(ctx, nil, nil, profile, req, rawBody)
	}
	limits := hookCorrelationGroupLimits
	// A session start commits on its own: the session start gate holds the
	// session's first prompt and tool calls until the start's verdict, which
	// comes after its correlation commits, so it must not wait for the
	// occurrences queued behind it (they were refused as start pending).
	limits.Boundary = canonicalHookLifecycleEvent(req.HookEventName) == "session_start"
	repo, release, err := a.store.JoinCorrelationGroup(ctx, req.ConnectorName+"\x00"+req.SessionID, limits)
	if err != nil {
		return ctx, req, err
	}
	defer release()
	attemptCtx := audit.CorrelationTurnContext(ctx, repo)
	outCtx, out, err := a.correlateHookOccurrenceOnce(attemptCtx, repo, release, profile, req, rawBody)
	if outCtx == attemptCtx {
		return ctx, out, err
	}
	return hookCallContextWithValuesOf(ctx, outCtx), out, err
}
