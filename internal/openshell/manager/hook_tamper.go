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

package manager

import (
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
)

const (
	// maxTrackedToolCalls bounds memory per binding. PreToolUse events older
	// than this count are evicted when a new one arrives.
	maxTrackedToolCalls = 1000
	// toolCallTTL is how long a PreToolUse stays in memory without a matching
	// PostToolUse before being evicted (during periodic cleanup).
	toolCallTTL = 10 * time.Minute
)

// toolCallRecord tracks one PreToolUse event.
type toolCallRecord struct {
	toolUseID  string
	tool       string
	event      string
	denied     bool
	insertedAt time.Time
}

// hookTamperTracker correlates PreToolUse and PostToolUse events by tool_use_id
// per binding to detect hook tampering.
type hookTamperTracker struct {
	mu       sync.Mutex
	bindings map[string]*bindingToolCalls
}

// bindingToolCalls tracks tool calls for one binding.
type bindingToolCalls struct {
	// pending maps tool_use_id → PreToolUse record.
	pending map[string]toolCallRecord
	// insertOrder tracks insertion order for FIFO eviction when capacity is reached.
	insertOrder []string
}

// newHookTamperTracker creates a new hook tamper tracker.
func newHookTamperTracker() *hookTamperTracker {
	return &hookTamperTracker{
		bindings: make(map[string]*bindingToolCalls),
	}
}

// ObservePreToolUse records a PreToolUse event.
func (t *hookTamperTracker) ObservePreToolUse(bindingID, toolUseID, tool, event string, denied bool) {
	if toolUseID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	btc := t.bindings[bindingID]
	if btc == nil {
		btc = &bindingToolCalls{
			pending:     make(map[string]toolCallRecord),
			insertOrder: make([]string, 0, maxTrackedToolCalls),
		}
		t.bindings[bindingID] = btc
	}

	// Evict oldest if at capacity.
	if len(btc.pending) >= maxTrackedToolCalls && btc.pending[toolUseID].toolUseID == "" {
		if len(btc.insertOrder) > 0 {
			oldest := btc.insertOrder[0]
			delete(btc.pending, oldest)
			btc.insertOrder = btc.insertOrder[1:]
		}
	}

	// Record or update the PreToolUse.
	if _, exists := btc.pending[toolUseID]; !exists {
		btc.insertOrder = append(btc.insertOrder, toolUseID)
	}
	btc.pending[toolUseID] = toolCallRecord{
		toolUseID:  toolUseID,
		tool:       tool,
		event:      event,
		denied:     denied,
		insertedAt: time.Now(),
	}
}

// CheckPostToolUse checks a PostToolUse event for tamper. Returns true if
// tamper was detected, along with a description.
func (t *hookTamperTracker) CheckPostToolUse(bindingID, toolUseID, event string) (tampered bool, reason string) {
	if toolUseID == "" {
		return false, ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	btc := t.bindings[bindingID]
	if btc == nil {
		return true, "PostToolUse for a tool whose PreToolUse was never seen (binding has no tracked calls)"
	}

	rec, found := btc.pending[toolUseID]
	if !found {
		return true, "PostToolUse for a tool whose PreToolUse was never seen"
	}

	// Remove from tracking now that we've seen the PostToolUse.
	delete(btc.pending, toolUseID)
	for i, id := range btc.insertOrder {
		if id == toolUseID {
			btc.insertOrder = append(btc.insertOrder[:i], btc.insertOrder[i+1:]...)
			break
		}
	}

	if rec.denied {
		return true, "PostToolUse for a tool whose PreToolUse was denied by DefenseClaw"
	}

	return false, ""
}

// ForgetBinding drops tracking state for a binding.
func (t *hookTamperTracker) ForgetBinding(bindingID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.bindings, bindingID)
}

// Cleanup removes stale PreToolUse records that never received a PostToolUse.
func (t *hookTamperTracker) Cleanup(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, btc := range t.bindings {
		var toRemove []string
		for toolUseID, rec := range btc.pending {
			if now.Sub(rec.insertedAt) > toolCallTTL {
				toRemove = append(toRemove, toolUseID)
			}
		}
		for _, toolUseID := range toRemove {
			delete(btc.pending, toolUseID)
			for i, id := range btc.insertOrder {
				if id == toolUseID {
					btc.insertOrder = append(btc.insertOrder[:i], btc.insertOrder[i+1:]...)
					break
				}
			}
		}
	}
}

// isPreToolUseEvent reports whether an event is a PreToolUse-like event.
func isPreToolUseEvent(event string) bool {
	// Normalize: remove separators and lowercase.
	e := ""
	for _, r := range event {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			if r >= 'A' && r <= 'Z' {
				e += string(r + 32)
			} else {
				e += string(r)
			}
		}
	}
	return e == "pretooluse" || e == "beforetooluse" || e == "pretoolcall" || e == "toolcall"
}

// isPostToolUseEvent reports whether an event is a PostToolUse-like event.
func isPostToolUseEvent(event string) bool {
	// Normalize: remove separators and lowercase.
	e := ""
	for _, r := range event {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			if r >= 'A' && r <= 'Z' {
				e += string(r + 32)
			} else {
				e += string(r)
			}
		}
	}
	return e == "posttooluse" || e == "aftertooluse" || e == "posttoolcall" || e == "toolresult"
}

// onTamperShouldStop reports whether the hooks.on_tamper setting means
// we should stop the sandbox.
func onTamperShouldStop(onTamper string) bool {
	return onTamper == packs.OnTamperStop
}
