// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/google/uuid"
)

const (
	hiltStatusApproved    = "approval_approved"
	hiltStatusDenied      = "approval_denied"
	hiltStatusTimeout     = "approval_timeout"
	hiltStatusUnsupported = "hilt_unsupported"
)

type pendingHILTApproval struct {
	id        string
	sessionID string
	result    chan bool
}

// HILTApprovalManager owns DefenseClaw-delivered OpenClaw approval prompts.
// Connector-native approval surfaces such as Claude Code PreToolUse do not use
// this manager; they emit the connector's native "ask" decision instead.
type HILTApprovalManager struct {
	client   *Client
	notifier *notifier.Dispatcher

	observabilityMu              sync.RWMutex
	observabilityV8              hiltObservabilityV8Runtime
	observabilityV8Authoritative bool

	mu             sync.Mutex
	pending        map[string]*pendingHILTApproval
	activeMu       sync.Mutex
	activeSessions map[string]time.Time
}

func NewHILTApprovalManager(client *Client) *HILTApprovalManager {
	return &HILTApprovalManager{
		client:         client,
		pending:        make(map[string]*pendingHILTApproval),
		activeSessions: make(map[string]time.Time),
	}
}

// SetNotifier wires the user-session OS notifier dispatcher used to
// surface "approval needed" toasts when a HILT prompt is dispatched.
// Safe to call with nil.
func (m *HILTApprovalManager) SetNotifier(n *notifier.Dispatcher) {
	if m == nil {
		return
	}
	m.notifier = n
}

// HILTApprovalContext carries the optional correlation IDs that
// surfaces upstream of HILT (proxy guardrail verdict, inspect
// endpoint, hook handler) attach to a confirm decision so the
// resulting approval audit row + OS notification carry the same
// evaluation_id + top rule_ids as the verdict that triggered the
// prompt. Pass the zero value when no structured findings exist
// for this approval (legacy callers, blocklist confirms).
type HILTApprovalContext struct {
	EvaluationID      string
	RuleIDs           []string
	RunID             string
	RequestID         string
	TurnID            string
	OperationID       string
	SessionID         string
	AgentID           string
	AgentName         string
	AgentType         string
	AgentInstanceID   string
	RootAgentID       string
	ParentAgentID     string
	RootSessionID     string
	ParentSessionID   string
	LineageProvenance string
	LifecycleID       string
	ExecutionID       string
	Depth             *int64
	Phase             string
	Sequence          *int64
	UserID            string
	UserName          string
	PolicyID          string
	PolicyVersion     string
	ToolID            string
	ToolName          string
	ToolType          string
	ToolCallID        string
	ToolProvider      string
	ToolSkillKey      string
	DestinationApp    string
}

// Request blocks until the user replies, the timeout fires, or the
// caller's context cancels. The optional evalCtx (last variadic
// slot) lets callers stamp the same evaluation_id + rule_ids on
// the approval audit row + OS toast that surfaced on the verdict
// upstream — pure-additive, so existing callers pass nothing and
// get the prior behavior.
func (m *HILTApprovalManager) Request(ctx context.Context, sessionID, subject, severity, reason string, timeout time.Duration, evalCtx ...HILTApprovalContext) (bool, string, error) {
	var ec HILTApprovalContext
	if len(evalCtx) > 0 {
		ec = evalCtx[0]
	}
	if m == nil {
		return false, hiltStatusUnsupported, fmt.Errorf("hilt approval unavailable")
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	sessionIDs := m.sessionCandidates(sessionID)
	correlationSessionID := sessionID
	if correlationSessionID == "" && len(sessionIDs) == 1 {
		correlationSessionID = sessionIDs[0]
	}
	id := "hilt-" + strings.Split(uuid.NewString(), "-")[0]
	startedAt := time.Now().UTC()
	operation, observabilityErr := m.startHILTApprovalV8(
		ctx, id, correlationSessionID, subject, severity, reason, ec, startedAt,
	)
	if observabilityErr != nil {
		return false, hiltStatusUnsupported, fmt.Errorf("hilt approval observability unavailable")
	}
	finish := func(result string, outcome observability.Outcome, technicalFailure bool, errorType string) error {
		if operation == nil {
			return nil
		}
		return operation.finish(ctx, result, outcome, technicalFailure, errorType, time.Now().UTC())
	}
	if m.client == nil || len(sessionIDs) == 0 {
		finishErr := finish("cancelled", observability.OutcomeCancelled, true, "approval_unavailable")
		return false, hiltStatusUnsupported, errors.Join(fmt.Errorf("hilt approval unavailable"), finishErr)
	}

	safeReason := string(redaction.ForSinkReason(reason))
	msg := fmt.Sprintf("DefenseClaw needs your approval before this agent action proceeds.\n\nAction: %s\nSeverity: %s\nReason: %s\n\nReply exactly `approve %s` to allow once, or `deny %s` to block.",
		subject, severity, reasonOrFallback(safeReason, "matched guardrail policy"), id, id)

	var pending *pendingHILTApproval
	var lastErr error
	for _, candidate := range sessionIDs {
		pending = &pendingHILTApproval{
			id:        id,
			sessionID: candidate,
			result:    make(chan bool, 1),
		}

		m.mu.Lock()
		m.pending[strings.ToLower(id)] = pending
		m.mu.Unlock()

		sendCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := m.client.SessionsSend(sendCtx, candidate, msg)
		cancel()
		if err == nil {
			lastErr = nil
			break
		}
		m.remove(id)
		lastErr = err
		pending = nil
	}
	if lastErr != nil || pending == nil {
		details := "session send failed"
		if lastErr != nil {
			details = lastErr.Error()
		}
		finishErr := finish("cancelled", observability.OutcomeCancelled, true, "approval_delivery_failed")
		return false, hiltStatusUnsupported, errors.Join(
			fmt.Errorf("hilt approval unavailable: %s", details), finishErr,
		)
	}
	if operation != nil {
		operation.recordMetric(ctx, operation.input, time.Now().UTC(), "pending")
	}
	// Fire a user-session toast as soon as the chat-side prompt has
	// been delivered. This is the single chokepoint covering every
	// HILT path — guardrail confirm verdicts, OpenClaw inspect
	// confirm, and exec approval prompts all funnel through here —
	// so a per-call dispatcher injection at each surface is not
	// needed. The notification is purely informational ("reply in
	// chat"); approve/deny still happens via the chat session.
	if m.notifier != nil {
		m.notifier.OnApprovalPending(notifier.ApprovalEvent{
			Subject:  subject,
			Reason:   safeReason,
			Severity: severity,
			// Source is left empty because HILT does not know which
			// upstream surface emitted the confirm verdict — the
			// dispatcher's allowSource lets unspecified sources
			// through under the master Enabled gate, which keeps
			// approval coverage independent of the per-source
			// filter that operators use to silence chatty blocks.
			EvaluationID: ec.EvaluationID,
			RuleIDs:      ec.RuleIDs,
		})
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case approved := <-pending.result:
		if approved {
			if err := finish("approved", observability.OutcomeApproved, false, ""); err != nil {
				return false, hiltStatusApproved, fmt.Errorf("hilt approval audit failed")
			}
			return true, hiltStatusApproved, nil
		}
		if err := finish("denied", observability.OutcomeDenied, false, ""); err != nil {
			return false, hiltStatusDenied, fmt.Errorf("hilt denial audit failed")
		}
		return false, hiltStatusDenied, nil
	case <-timer.C:
		m.remove(id)
		if err := finish("expired", observability.OutcomeTimedOut, false, ""); err != nil {
			return false, hiltStatusTimeout, fmt.Errorf("hilt timeout audit failed")
		}
		return false, hiltStatusTimeout, nil
	case <-ctx.Done():
		m.remove(id)
		finishErr := finish("cancelled", observability.OutcomeCancelled, true, "approval_cancelled")
		return false, hiltStatusTimeout, errors.Join(ctx.Err(), finishErr)
	}
}

func (m *HILTApprovalManager) sessionCandidates(sessionID string) []string {
	if m == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(candidate string) {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || seen[candidate] {
			return
		}
		seen[candidate] = true
		out = append(out, candidate)
	}
	add(sessionID)
	add(m.defaultSessionID())
	return out
}

func (m *HILTApprovalManager) TrackSession(sessionID string) {
	if m == nil {
		return
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}
	m.activeMu.Lock()
	defer m.activeMu.Unlock()
	m.activeSessions[sessionID] = time.Now()
	m.pruneActiveSessionsLocked()
}

func (m *HILTApprovalManager) defaultSessionID() string {
	if m == nil {
		return ""
	}
	m.activeMu.Lock()
	defer m.activeMu.Unlock()
	m.pruneActiveSessionsLocked()
	if len(m.activeSessions) != 1 {
		return ""
	}
	for sessionID := range m.activeSessions {
		return sessionID
	}
	return ""
}

func (m *HILTApprovalManager) pruneActiveSessionsLocked() {
	cutoff := time.Now().Add(-1 * time.Hour)
	for sessionID, seen := range m.activeSessions {
		if seen.Before(cutoff) {
			delete(m.activeSessions, sessionID)
		}
	}
}

func (m *HILTApprovalManager) ResolveFromMessage(sessionID, role, content string) bool {
	if m == nil || !strings.EqualFold(strings.TrimSpace(role), "user") {
		return false
	}
	fields := strings.Fields(strings.TrimSpace(content))
	if len(fields) != 2 {
		return false
	}
	verb := strings.ToLower(fields[0])
	if verb != "approve" && verb != "deny" {
		return false
	}
	id := strings.ToLower(fields[1])

	m.mu.Lock()
	pending, ok := m.pending[id]
	if ok && pending.sessionID == sessionID {
		delete(m.pending, id)
	}
	m.mu.Unlock()
	if !ok || pending.sessionID != sessionID {
		return false
	}
	pending.result <- verb == "approve"
	return true
}

func (m *HILTApprovalManager) remove(id string) {
	m.mu.Lock()
	delete(m.pending, strings.ToLower(id))
	m.mu.Unlock()
}

func reasonOrFallback(reason, fallback string) string {
	if strings.TrimSpace(reason) == "" {
		return fallback
	}
	return reason
}
