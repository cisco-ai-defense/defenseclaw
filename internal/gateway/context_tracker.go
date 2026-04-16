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
	"sync"
	"time"
)

const (
	defaultMaxTurns    = 10
	defaultMaxSessions = 200
)

// contextMessage represents a single turn stored in the context tracker.
type contextMessage struct {
	Role      string
	Content   string
	Timestamp time.Time
}

// SessionContext holds the bounded conversation buffer for a single session.
type SessionContext struct {
	Messages []contextMessage
	LastSeen time.Time
}

// ContextTracker maintains per-session conversation buffers for multi-turn
// analysis. The buffer is bounded: only the most recent maxTurns messages
// are retained per session, and sessions are pruned when the total count
// exceeds maxSessions.
type ContextTracker struct {
	mu          sync.RWMutex
	sessions    map[string]*SessionContext
	maxTurns    int
	maxSessions int
}

// NewContextTracker creates a tracker with the given limits.
// Zero values use defaults: 10 turns per session, 200 sessions max.
func NewContextTracker(maxTurns, maxSessions int) *ContextTracker {
	if maxTurns <= 0 {
		maxTurns = defaultMaxTurns
	}
	if maxSessions <= 0 {
		maxSessions = defaultMaxSessions
	}
	return &ContextTracker{
		sessions:    make(map[string]*SessionContext),
		maxTurns:    maxTurns,
		maxSessions: maxSessions,
	}
}

// Record adds a message to the session's conversation buffer.
func (ct *ContextTracker) Record(sessionKey, role, content string) {
	if sessionKey == "" || content == "" {
		return
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	sc, ok := ct.sessions[sessionKey]
	if !ok {
		sc = &SessionContext{}
		ct.sessions[sessionKey] = sc
	}

	sc.Messages = append(sc.Messages, contextMessage{
		Role:      role,
		Content:   content,
		Timestamp: time.Now(),
	})
	sc.LastSeen = time.Now()

	if len(sc.Messages) > ct.maxTurns {
		sc.Messages = sc.Messages[len(sc.Messages)-ct.maxTurns:]
	}

	if len(ct.sessions) > ct.maxSessions {
		ct.pruneOldestLocked()
	}
}

// RecentMessages returns the last N messages for a session as ChatMessages
// suitable for passing to the inspector.
func (ct *ContextTracker) RecentMessages(sessionKey string, n int) []ChatMessage {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	sc, ok := ct.sessions[sessionKey]
	if !ok || len(sc.Messages) == 0 {
		return nil
	}

	start := 0
	if n > 0 && len(sc.Messages) > n {
		start = len(sc.Messages) - n
	}

	msgs := make([]ChatMessage, 0, len(sc.Messages)-start)
	for _, m := range sc.Messages[start:] {
		msgs = append(msgs, ChatMessage{Role: m.Role, Content: m.Content})
	}
	return msgs
}

// HasRepeatedInjection checks whether injection-like patterns appear in
// multiple recent user turns, indicating a multi-turn attack.
// Uses the globally active pattern set (populated via ApplyRulePackOverrides
// at startup), so rule pack customizations are honored automatically.
func (ct *ContextTracker) HasRepeatedInjection(sessionKey string, threshold int) bool {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	sc, ok := ct.sessions[sessionKey]
	if !ok {
		return false
	}

	count := 0
	for _, m := range sc.Messages {
		if m.Role != "user" {
			continue
		}
		if scanLocalPatterns("prompt", m.Content).Severity != "NONE" {
			count++
		}
	}
	return count >= threshold
}

// SessionCount returns the number of tracked sessions.
func (ct *ContextTracker) SessionCount() int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return len(ct.sessions)
}

// pruneOldestLocked removes the oldest quarter of sessions by LastSeen.
// Caller must hold ct.mu write lock.
func (ct *ContextTracker) pruneOldestLocked() {
	target := ct.maxSessions * 3 / 4
	if target < 1 {
		target = 1
	}

	for len(ct.sessions) > target {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, sc := range ct.sessions {
			if first || sc.LastSeen.Before(oldestTime) {
				oldestKey = k
				oldestTime = sc.LastSeen
				first = false
			}
		}
		if oldestKey != "" {
			delete(ct.sessions, oldestKey)
		}
	}
}
