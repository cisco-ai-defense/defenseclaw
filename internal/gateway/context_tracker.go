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
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	defaultMaxTurns     = 10
	defaultMaxSessions  = 200
	defaultSessionTTL   = 30 * time.Minute
	staleSweepFrequency = 50 // run a stale sweep roughly every N Record calls
)

// contextMessage represents a single turn stored in the context tracker.
type contextMessage struct {
	Role          string
	Content       string
	Timestamp     time.Time
	OccurrenceKey string
}

// SessionContext holds the bounded conversation buffer for a single session.
type SessionContext struct {
	Messages                 []contextMessage
	LastSeen                 time.Time
	RepeatedInjectionAlerted bool
}

// ContextTracker maintains per-session conversation buffers for multi-turn
// analysis. The buffer is bounded on three axes:
//   - maxTurns: messages retained per session (FIFO).
//   - maxSessions: total sessions retained (LRU-evict when exceeded).
//   - ttl: sessions untouched for longer than ttl are eligible for
//     eviction on the next sweep. TTL-based eviction prevents the
//     tracker from retaining conversation buffers for sessions the
//     user has long-abandoned.
type ContextTracker struct {
	mu          sync.RWMutex
	sessions    map[string]*SessionContext
	maxTurns    int
	maxSessions int
	ttl         time.Duration
	// writesSinceSweep counts Record calls since the last stale sweep.
	// We amortize the sweep cost across many writes rather than running
	// a separate goroutine.
	writesSinceSweep int
	// now is injected for tests; production uses time.Now.
	now func() time.Time
}

// NewContextTracker creates a tracker with the given limits.
// Zero values use defaults: 10 turns per session, 200 sessions max,
// 30 minute TTL.
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
		ttl:         defaultSessionTTL,
		now:         time.Now,
	}
}

// SetTTL overrides the default session TTL. A non-positive value disables
// TTL-based eviction (sessions are only evicted by LRU when maxSessions
// is exceeded). Primarily used in tests.
func (ct *ContextTracker) SetTTL(ttl time.Duration) {
	ct.mu.Lock()
	ct.ttl = ttl
	ct.mu.Unlock()
}

// Record adds a message to the session's conversation buffer.
func (ct *ContextTracker) Record(sessionKey, role, content string) {
	ct.record(sessionKey, role, content, "")
}

// RecordOccurrence adds one observed stream message to the session buffer and
// reports whether it was new. Message IDs are authoritative occurrence keys;
// sequence numbers provide a stable fallback for older envelopes without an
// ID. Envelopes with neither identity remain recordable because content-based
// deduplication would collapse legitimate repeated user turns.
func (ct *ContextTracker) RecordOccurrence(
	sessionKey, role, content, messageID string,
	messageSeq int,
) bool {
	key := ""
	if messageID != "" {
		key = "id:" + messageID
	} else if messageSeq > 0 {
		key = "seq:" + strconv.Itoa(messageSeq)
	}
	return ct.record(sessionKey, role, content, key)
}

func (ct *ContextTracker) record(sessionKey, role, content, occurrenceKey string) bool {
	if sessionKey == "" || content == "" {
		return false
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	now := ct.now()

	sc, ok := ct.sessions[sessionKey]
	if !ok {
		sc = &SessionContext{}
		ct.sessions[sessionKey] = sc
	}
	if occurrenceKey != "" {
		for _, existing := range sc.Messages {
			if existing.OccurrenceKey == occurrenceKey {
				return false
			}
		}
	}

	sc.Messages = append(sc.Messages, contextMessage{
		Role:          role,
		Content:       content,
		Timestamp:     now,
		OccurrenceKey: occurrenceKey,
	})
	sc.LastSeen = now

	if len(sc.Messages) > ct.maxTurns {
		sc.Messages = sc.Messages[len(sc.Messages)-ct.maxTurns:]
	}

	ct.writesSinceSweep++
	if ct.writesSinceSweep >= staleSweepFrequency {
		ct.evictStaleLocked(now)
		ct.writesSinceSweep = 0
	}

	if len(ct.sessions) > ct.maxSessions {
		ct.pruneOldestLocked()
	}
	return true
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

// HasRepeatedInjection reports the transition into a repeated-injection state.
// It returns true at most once for a retained session so later benign turns do
// not replay the same HIGH alert indefinitely. Session eviction naturally
// resets the latch.
//
// The contextual trust-exploit rules are authoritative here. The legacy local
// substring floor was intentionally removed because phrases such as "pretend
// you are a compiler" and "ignore prior test output" caused alert fatigue.
func (ct *ContextTracker) HasRepeatedInjection(sessionKey string, threshold int) bool {
	if threshold <= 0 {
		return false
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	sc, ok := ct.sessions[sessionKey]
	if !ok || sc.RepeatedInjectionAlerted {
		return false
	}

	count := 0
	for _, m := range sc.Messages {
		if m.Role != "user" {
			continue
		}
		if contextMessageHasTrustExploit(m.Content) {
			count++
			if count >= threshold {
				sc.RepeatedInjectionAlerted = true
				return true
			}
		}
	}
	return false
}

func contextMessageHasTrustExploit(content string) bool {
	return len(scanContentRuleCategoryForConnector(
		"", content, "", ruleContentScopeUntrusted, "trust-exploit",
	)) > 0
}

// SessionCount returns the number of tracked sessions.
func (ct *ContextTracker) SessionCount() int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return len(ct.sessions)
}

// pruneOldestLocked removes the oldest quarter of sessions by LastSeen.
// Caller must hold ct.mu write lock.
//
// The previous implementation repeatedly scanned the whole map to find
// the single oldest entry, giving O(n²) total work when shrinking from
// N to 3N/4. We now snapshot all (key, LastSeen) pairs once, sort them,
// and delete the oldest in a single pass: O(n log n).
func (ct *ContextTracker) pruneOldestLocked() {
	target := ct.maxSessions * 3 / 4
	if target < 1 {
		target = 1
	}
	if len(ct.sessions) <= target {
		return
	}

	type keyAge struct {
		key  string
		seen time.Time
	}
	ages := make([]keyAge, 0, len(ct.sessions))
	for k, sc := range ct.sessions {
		ages = append(ages, keyAge{key: k, seen: sc.LastSeen})
	}
	sort.Slice(ages, func(i, j int) bool {
		return ages[i].seen.Before(ages[j].seen)
	})

	toDelete := len(ct.sessions) - target
	for i := 0; i < toDelete && i < len(ages); i++ {
		delete(ct.sessions, ages[i].key)
	}
}

// evictStaleLocked removes any session whose LastSeen is older than
// now-ttl. No-op when ttl is non-positive. Caller must hold ct.mu write
// lock.
func (ct *ContextTracker) evictStaleLocked(now time.Time) {
	if ct.ttl <= 0 {
		return
	}
	cutoff := now.Add(-ct.ttl)
	for k, sc := range ct.sessions {
		if sc.LastSeen.Before(cutoff) {
			delete(ct.sessions, k)
		}
	}
}
