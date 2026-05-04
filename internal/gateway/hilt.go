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
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/google/uuid"
)

const (
	hiltStatusRequested   = "approval_requested"
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
	client *Client
	logger *audit.Logger
	otel   *telemetry.Provider

	mu             sync.Mutex
	pending        map[string]*pendingHILTApproval
	activeMu       sync.Mutex
	activeSessions map[string]time.Time
}

func NewHILTApprovalManager(client *Client, logger *audit.Logger, otel *telemetry.Provider) *HILTApprovalManager {
	return &HILTApprovalManager{
		client:         client,
		logger:         logger,
		otel:           otel,
		pending:        make(map[string]*pendingHILTApproval),
		activeSessions: make(map[string]time.Time),
	}
}

func (m *HILTApprovalManager) Request(ctx context.Context, sessionID, subject, severity, reason string, timeout time.Duration) (bool, string, error) {
	if m == nil {
		return false, hiltStatusUnsupported, fmt.Errorf("hilt approval unavailable")
	}
	sessionIDs := m.sessionCandidates(sessionID)
	if m.client == nil || len(sessionIDs) == 0 {
		m.record(ctx, hiltStatusUnsupported, subject, severity, "session/client unavailable")
		return false, hiltStatusUnsupported, fmt.Errorf("hilt approval unavailable")
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	id := "hilt-" + strings.Split(uuid.NewString(), "-")[0]
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
		m.record(ctx, hiltStatusUnsupported, subject, severity, details)
		return false, hiltStatusUnsupported, fmt.Errorf("hilt approval unavailable: %s", details)
	}
	m.record(ctx, hiltStatusRequested, subject, severity, safeReason)

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case approved := <-pending.result:
		if approved {
			m.record(ctx, hiltStatusApproved, subject, severity, safeReason)
			return true, hiltStatusApproved, nil
		}
		m.record(ctx, hiltStatusDenied, subject, severity, safeReason)
		return false, hiltStatusDenied, nil
	case <-timer.C:
		m.remove(id)
		m.record(ctx, hiltStatusTimeout, subject, severity, safeReason)
		return false, hiltStatusTimeout, nil
	case <-ctx.Done():
		m.remove(id)
		m.record(ctx, hiltStatusTimeout, subject, severity, ctx.Err().Error())
		return false, hiltStatusTimeout, ctx.Err()
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

func (m *HILTApprovalManager) record(ctx context.Context, action, subject, severity, details string) {
	if m == nil {
		return
	}
	if m.logger != nil {
		_ = m.logger.LogActionCtx(ctx, action, subject,
			fmt.Sprintf("severity=%s details=%s", severity, redaction.ForSinkReason(details)))
	}
	if m.otel != nil {
		m.otel.RecordGuardrailEvaluation(ctx, "openclaw:hilt", action)
	}
}

func reasonOrFallback(reason, fallback string) string {
	if strings.TrimSpace(reason) == "" {
		return fallback
	}
	return reason
}
