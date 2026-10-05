// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
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
	args                         map[string]string
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
func rememberOpenClawToolOutcome(sessionID, runID, tool string, args []byte, outcome hookGuardrailOutcome, identity AgentIdentity) {
	tool = strings.TrimSpace(tool)
	if tool == "" || outcome.Action == "" {
		return
	}
	entry := openClawToolOutcome{
		sessionID: strings.TrimSpace(sessionID), runID: strings.TrimSpace(runID), tool: tool, outcome: outcome,
		args:   openClawToolArgs(args),
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

// openClawToolArgs keys a call's top-level arguments by name, each value in
// canonical JSON, so the plugin's params and the stream's args compare
// regardless of formatting. Arguments that are not a JSON object give nil.
func openClawToolArgs(raw []byte) map[string]string {
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil || len(fields) == 0 {
		return nil
	}
	args := make(map[string]string, len(fields))
	for key, value := range fields {
		if encoded, err := json.Marshal(value); err == nil {
			args[key] = string(encoded)
		}
	}
	return args
}

// openClawToolArgsAgree reports whether two calls' arguments name a common
// field (shared) and whether any common field differs (conflict).
func openClawToolArgsAgree(a, b map[string]string) (shared, conflict bool) {
	for key, value := range a {
		if other, ok := b[key]; ok {
			shared = true
			if other != value {
				return shared, true
			}
		}
	}
	return shared, false
}

// takeOpenClawToolOutcome removes and returns the live decision that best
// fits a call of tool: the same run, the same session and the same
// arguments each count, and among equals the newest wins. The plugin's run
// and session ids come from the plugin hook context while the stream names
// its own (a different run id, the session key instead of the session id),
// so an id mismatch does not rule a decision out (GAP-1930 r4). A decision
// whose arguments differ from the call's in a common field (another
// command) is never taken.
func takeOpenClawToolOutcome(sessionID, runID, tool, arguments string) (openClawToolOutcome, bool) {
	tool, sessionID, runID = strings.TrimSpace(tool), strings.TrimSpace(sessionID), strings.TrimSpace(runID)
	args := openClawToolArgs([]byte(arguments))
	openClawToolOutcomes.mu.Lock()
	defer openClawToolOutcomes.mu.Unlock()
	now := openClawToolOutcomeNow()
	best, bestScore := -1, 0
	for i := len(openClawToolOutcomes.entries) - 1; i >= 0; i-- {
		e := openClawToolOutcomes.entries[i]
		if e.tool != tool || now.Sub(e.at) >= openClawToolOutcomeTTL {
			continue
		}
		shared, conflict := openClawToolArgsAgree(args, e.args)
		if conflict {
			continue
		}
		score := 1
		if runID != "" && e.runID == runID {
			score += 8
		}
		if sessionID != "" && e.sessionID == sessionID {
			score += 4
		}
		if shared {
			score += 2
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
// user when the stream did not name one. A call without a remembered
// decision (an allowed call) names the gateway's own OS user on an unmanaged
// install, as the turn's agent and chat spans do (GAP-2358).
func applyOpenClawToolOutcome(observation *generatedToolV8Observation) {
	if observation == nil {
		return
	}
	if observation.meta.Guardrail.Action == "" {
		applyOpenClawToolDecision(observation)
	}
	if observation.meta.UserID == "" && observation.meta.UserName == "" {
		userID, userName := localProcessUser()
		observation.meta.UserID, observation.meta.UserName = userID, userName
		observation.meta.UserIDKind = useridentity.KindForID(userID)
	}
}

func applyOpenClawToolDecision(observation *generatedToolV8Observation) {
	arguments := observation.arguments
	if observation.argumentsTruncated {
		arguments = ""
	}
	entry, ok := takeOpenClawToolOutcome(observation.meta.SessionID, observation.meta.RunID, observation.tool, arguments)
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
