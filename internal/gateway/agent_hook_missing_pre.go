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

type preToolDecisionKey struct {
	connectorInstance string
	connector         string
	session           string
	toolUse           string
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
	tracker.sequence++
	index := tracker.sequence % maxPendingPreToolDecisions
	previous := tracker.slots[index]
	if tracker.seen[previous.key] == previous.sequence {
		delete(tracker.seen, previous.key)
	}
	tracker.slots[index] = preToolDecisionSlot{key: key, sequence: tracker.sequence}
	tracker.seen[key] = tracker.sequence
}

func (tracker *preToolDecisionTracker) contains(key preToolDecisionKey) bool {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.seen[key] != 0
}

func (a *APIServer) auditMissingPreToolDecision(ctx context.Context, req agentHookRequest, resp agentHookResponse) {
	if a == nil || a.logger == nil || (a.scannerCfg != nil && a.scannerCfg.SecureClientIntegration()) {
		return
	}
	connector := connName(req.ConnectorName)
	if connector != "claudecode" && connector != "codex" {
		return
	}
	event := strings.TrimSpace(req.HookEventName)
	if event != "PreToolUse" && event != "PostToolUse" && event != "PostToolUseFailure" {
		return
	}
	key := preToolDecisionKey{
		connectorInstance: strings.TrimSpace(req.ConnectorInstanceID),
		connector:         connector,
		session:           strings.TrimSpace(req.SessionID),
		toolUse:           strings.TrimSpace(req.ToolInvocationID),
	}
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
