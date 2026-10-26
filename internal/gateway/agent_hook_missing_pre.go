// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
)

const missingPreToolRuleID = "HOOK-PRE-TOOL-MISSING"

// A post-tool hook can observe a call whose pre-tool hook never reached the
// gateway. This bounded ring holds only decisions whose audit row persisted;
// it does not claim to prevent a tool that the agent already ran.
const maxPendingPreToolDecisions = 4096

// preToolDecisionKey names one tool call of one caller. The caller is the
// verified hook caller (copilotDedupeScope), never the correlation-minted
// connector instance: concurrent hooks of one session can leave one of a
// call's two deliveries without its correlation, and a key that differed
// between them reported the audited PreToolUse as missing (GAP-1228).
type preToolDecisionKey struct {
	caller    string
	connector string
	session   string
	toolUse   string
}

type preToolDecisionSlot struct {
	key      preToolDecisionKey
	sequence uint64
}

type preToolDecisionTracker struct {
	mu       sync.Mutex
	seen     map[preToolDecisionKey]uint64
	slots    [maxPendingPreToolDecisions]preToolDecisionSlot
	sequence uint64
}

func (tracker *preToolDecisionTracker) record(key preToolDecisionKey) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if tracker.seen == nil {
		tracker.seen = make(map[preToolDecisionKey]uint64)
	}
	if tracker.seen[key] != 0 {
		return
	}
	tracker.sequence++
	index := tracker.sequence % maxPendingPreToolDecisions
	previous := tracker.slots[index]
	if tracker.seen[previous.key] == previous.sequence {
		delete(tracker.seen, previous.key)
	}
	tracker.slots[index] = preToolDecisionSlot{key: key, sequence: tracker.sequence}
	tracker.seen[key] = tracker.sequence
}

func (tracker *preToolDecisionTracker) forget(key preToolDecisionKey) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	delete(tracker.seen, key)
}

func (tracker *preToolDecisionTracker) contains(key preToolDecisionKey) bool {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.seen[key] != 0
}

// preToolDecisionKeyFor is the key of a tracked hook call and its event, or
// false for a call the tracker does not follow.
func (a *APIServer) preToolDecisionKeyFor(ctx context.Context, req agentHookRequest) (preToolDecisionKey, string, bool) {
	if a == nil || a.logger == nil || (a.scannerCfg != nil && a.scannerCfg.SecureClientIntegration()) {
		return preToolDecisionKey{}, "", false
	}
	connector := connName(req.ConnectorName)
	if connector != "claudecode" && connector != "codex" {
		return preToolDecisionKey{}, "", false
	}
	event := strings.TrimSpace(req.HookEventName)
	if event != "PreToolUse" && event != "PostToolUse" && event != "PostToolUseFailure" {
		return preToolDecisionKey{}, "", false
	}
	return preToolDecisionKey{
		caller:    copilotDedupeScope(ctx),
		connector: connector,
		session:   strings.TrimSpace(req.SessionID),
		toolUse:   strings.TrimSpace(req.ToolInvocationID),
	}, event, true
}

// notePreToolDecision records a PreToolUse whose verdict is final before its
// answer is offered: the agent can run the tool and its PostToolUse can be
// finalized before this call's audit commit, which reported the audited
// PreToolUse as missing (GAP-1228). The caller forgets the key when the
// answer is unconfirmed or its audit row is not written.
func (a *APIServer) notePreToolDecision(ctx context.Context, req agentHookRequest, resp agentHookResponse) (preToolDecisionKey, bool) {
	key, event, ok := a.preToolDecisionKeyFor(ctx, req)
	if !ok || event != "PreToolUse" || key.session == "" || key.toolUse == "" ||
		resp.Action == hookActionUnconfirmed || a.preToolDecisions.contains(key) {
		return preToolDecisionKey{}, false
	}
	a.preToolDecisions.record(key)
	return key, true
}

func (a *APIServer) auditMissingPreToolDecision(ctx context.Context, req agentHookRequest, resp agentHookResponse) {
	key, event, ok := a.preToolDecisionKeyFor(ctx, req)
	if !ok {
		return
	}
	connector := key.connector
	if event == "PreToolUse" {
		if key.session != "" && key.toolUse != "" && resp.Action != hookActionUnconfirmed {
			a.preToolDecisions.record(key)
		}
		return
	}
	if key.session != "" && key.toolUse != "" && a.preToolDecisions.contains(key) {
		return
	}
	// A missing exact ID cannot establish a safe match. Keep the post-tool
	// verdict observational and persist the gap under the same caller scope.
	alertCtx := contextWithHookCorrelation(ctx, req, "")
	if err := a.logger.LogAlertCtx(alertCtx, missingPreToolRuleID, "HIGH",
		"Tool result arrived without an audited PreToolUse decision", map[string]any{
			"connector": connector, "event": event,
			"session_id": key.session, "tool_use_id": key.toolUse,
			"rule_id": missingPreToolRuleID,
		}); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] missing pre-tool decision alert failed connector=%s: %v\n", connector, err)
	}
}
