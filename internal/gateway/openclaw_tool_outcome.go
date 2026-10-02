// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// An OpenClaw tool call is decided at the inspect endpoint, which the
// OpenClaw plugin calls from before_tool_call, while its tool span comes
// from the event router, which follows the OpenClaw gateway's stream. The
// decision sat only on a separate apply_guardrail root trace, so the turn's
// tool span ("exec") in Galileo had no action, rule, severity or user, and a
// blocked call could not be found there (GAP-1930). The inspect endpoint
// leaves each block, ask or alert here; the router puts it on the span of
// the same call, as the hook connectors' tool spans carry theirs.

const (
	openClawToolOutcomeTTL = 2 * time.Minute
	openClawToolOutcomeCap = 256
)

type openClawToolOutcome struct {
	sessionID, runID, tool       string
	outcome                      hookGuardrailOutcome
	userID, userIDKind, userName string
	at                           time.Time
}

var openClawToolOutcomes struct {
	mu      sync.Mutex
	entries []openClawToolOutcome
	now     func() time.Time
}

func openClawToolOutcomeNow() time.Time {
	if openClawToolOutcomes.now != nil {
		return openClawToolOutcomes.now()
	}
	return time.Now()
}

// rememberOpenClawToolOutcome records the decision of one OpenClaw tool
// call. The user is the caller's identity, or the gateway's own OS user on
// an unmanaged install (the OpenClaw plugin sends no identity headers).
func rememberOpenClawToolOutcome(sessionID, runID, tool string, outcome hookGuardrailOutcome, identity AgentIdentity) {
	tool = strings.TrimSpace(tool)
	if tool == "" || outcome.Action == "" {
		return
	}
	entry := openClawToolOutcome{
		sessionID: strings.TrimSpace(sessionID), runID: strings.TrimSpace(runID), tool: tool, outcome: outcome,
		userID: identity.UserID, userIDKind: identity.UserIDKind, userName: identity.UserName,
	}
	if entry.userID == "" && entry.userName == "" {
		entry.userID, entry.userName = localProcessUser()
		entry.userIDKind = useridentity.KindForID(entry.userID)
	}
	openClawToolOutcomes.mu.Lock()
	defer openClawToolOutcomes.mu.Unlock()
	entry.at = openClawToolOutcomeNow()
	entries := openClawToolOutcomes.entries[:0]
	for _, e := range openClawToolOutcomes.entries {
		if entry.at.Sub(e.at) < openClawToolOutcomeTTL {
			entries = append(entries, e)
		}
	}
	entries = append(entries, entry)
	if len(entries) > openClawToolOutcomeCap {
		entries = entries[len(entries)-openClawToolOutcomeCap:]
	}
	openClawToolOutcomes.entries = entries
}

// takeOpenClawToolOutcome removes and returns the newest live decision for
// a call of tool: one of the same run, else of the same session, else any.
// A decision of another run is never taken. The plugin may name the session
// by its id and the stream by its key, so a session mismatch alone does not
// rule a decision out.
func takeOpenClawToolOutcome(sessionID, runID, tool string) (openClawToolOutcome, bool) {
	tool, sessionID, runID = strings.TrimSpace(tool), strings.TrimSpace(sessionID), strings.TrimSpace(runID)
	openClawToolOutcomes.mu.Lock()
	defer openClawToolOutcomes.mu.Unlock()
	now := openClawToolOutcomeNow()
	best, bestScore := -1, 0
	for i := len(openClawToolOutcomes.entries) - 1; i >= 0; i-- {
		e := openClawToolOutcomes.entries[i]
		if e.tool != tool || now.Sub(e.at) >= openClawToolOutcomeTTL || (runID != "" && e.runID != "" && e.runID != runID) {
			continue
		}
		score := 1
		switch {
		case runID != "" && e.runID == runID:
			score = 3
		case sessionID != "" && e.sessionID == sessionID:
			score = 2
		}
		if score > bestScore {
			best, bestScore = i, score
		}
	}
	if best < 0 {
		return openClawToolOutcome{}, false
	}
	entry := openClawToolOutcomes.entries[best]
	openClawToolOutcomes.entries = append(openClawToolOutcomes.entries[:best], openClawToolOutcomes.entries[best+1:]...)
	return entry, true
}

// applyOpenClawToolOutcome puts a remembered decision on the tool span of
// the call: the guardrail outcome, a blocked status for a block, and the
// user when the stream did not name one.
func applyOpenClawToolOutcome(observation *generatedToolV8Observation) {
	if observation == nil || observation.meta.Guardrail.Action != "" {
		return
	}
	entry, ok := takeOpenClawToolOutcome(observation.meta.SessionID, observation.meta.RunID, observation.tool)
	if !ok {
		return
	}
	observation.meta.Guardrail = entry.outcome
	if entry.outcome.Action == "block" {
		observation.outcome = observability.OutcomeBlocked
		observation.toolStatus = "blocked"
		observation.technicalFailure = false
		observation.errorType = ""
	}
	if observation.meta.UserID == "" && observation.meta.UserName == "" {
		observation.meta.UserID, observation.meta.UserIDKind, observation.meta.UserName =
			entry.userID, entry.userIDKind, entry.userName
	}
}
