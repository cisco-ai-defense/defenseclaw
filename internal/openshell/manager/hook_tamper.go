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
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
)

// Hook tamper detection.
//
// A sandbox hook is judgment inside the sandbox boundary: it runs as the
// workload's uid in the workload's PID namespace, and Claude Code treats a
// hook that dies with anything but exit 2 as a non-blocking error. A
// workload that kills the PreToolUse hook therefore gets its tool call run
// without a DefenseClaw verdict. The files and egress boundaries are
// enforced outside the sandbox and do not depend on the hooks. What the
// gateway can see is the lifecycle of each tool call: the harness reports
// the call's PreToolUse and, once the tool ran, its PostToolUse, both
// carrying the harness's per-call ID. A PostToolUse whose PreToolUse was
// denied, or never arrived, is a tool that ran without DefenseClaw's
// approval.

const (
	// maxOpenToolCalls bounds, per binding, the allowed tool calls whose
	// result has not arrived. A harness runs a handful at a time; the rest
	// are calls whose result never comes (an interrupted turn).
	maxOpenToolCalls = 1024
	// maxPastToolCalls bounds, per binding, the denied and finished tool
	// calls kept so a late or repeated result is judged right.
	maxPastToolCalls = 1024
	// maxToolUseIDBytes is the longest tool-use ID kept verbatim; a longer
	// one is kept as its digest, so an entry never exceeds ~80 bytes of key.
	maxToolUseIDBytes = 128
)

// toolCallState is what the tracker knows about one tool call.
type toolCallState uint8

const (
	// toolCallAllowed: the PreToolUse was allowed and no result arrived yet.
	toolCallAllowed toolCallState = iota + 1
	// toolCallDenied: DefenseClaw denied the PreToolUse.
	toolCallDenied
	// toolCallDone: a result arrived, or an allowed call left the open set
	// unanswered. Either way a result for it is not tamper.
	toolCallDone
)

// toolResult classifies the post-tool hook events.
type toolResult uint8

const (
	toolResultNone toolResult = iota
	// toolResultRan is PostToolUse: the tool ran.
	toolResultRan
	// toolResultFailed is Claude Code's PostToolUseFailure. Claude can
	// report a call that failed before its PreToolUse (invalid input), so
	// it closes a call but never proves tamper.
	toolResultFailed
	// toolResultRefused is Claude Code's PermissionDenied: the harness
	// itself refused the call.
	toolResultRefused
)

// tamperKind is the verdict for one tool result.
type tamperKind uint8

const (
	tamperNone tamperKind = iota
	// tamperDenied: the tool ran although DefenseClaw denied its PreToolUse.
	tamperDenied
	// tamperUnseen: the tool ran and its PreToolUse never reached
	// DefenseClaw.
	tamperUnseen
)

// toolHookEvent classifies a hook event for the tracker. Event names are
// exact: Claude Code and Codex both use these spellings, and case folding
// would widen what a vendor contract promises (see
// connector.ToolCallLifecycleContract).
func toolHookEvent(event string) (pre bool, result toolResult) {
	switch event {
	case "PreToolUse":
		return true, toolResultNone
	case "PostToolUse":
		return false, toolResultRan
	case "PostToolUseFailure":
		return false, toolResultFailed
	case "PermissionDenied":
		return false, toolResultRefused
	}
	return false, toolResultNone
}

// toolCallKey is the tracker key of a tool-use ID: the ID itself, or the
// digest of an oversized one. Empty IDs are not tracked.
func toolCallKey(id string) string {
	id = strings.TrimSpace(id)
	if len(id) <= maxToolUseIDBytes {
		return id
	}
	sum := sha256.Sum256([]byte(id))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type toolCall struct {
	key   string
	state toolCallState
}

// toolCallLedger is one binding's tool calls: allowed calls in open, the
// others in past, each oldest first.
type toolCallLedger struct {
	// complete is set when this process has seen every hook request of the
	// binding since the harness started: the binding was minted, or its
	// sandbox started, here. Only then does a result for an unknown call
	// prove that its PreToolUse never arrived. After a daemon restart the
	// ledger of a running sandbox is partial until its next start.
	complete bool
	calls    map[string]*list.Element
	open     *list.List
	past     *list.List
}

func newToolCallLedger(complete bool) *toolCallLedger {
	return &toolCallLedger{complete: complete, calls: map[string]*list.Element{}, open: list.New(), past: list.New()}
}

func (l *toolCallLedger) queue(state toolCallState) (*list.List, int) {
	if state == toolCallAllowed {
		return l.open, maxOpenToolCalls
	}
	return l.past, maxPastToolCalls
}

func (l *toolCallLedger) remove(el *list.Element) {
	call := el.Value.(*toolCall)
	q, _ := l.queue(call.state)
	q.Remove(el)
	delete(l.calls, call.key)
}

// put records key in state, as the newest entry of its queue. An allowed
// call pushed out of the open set is remembered as done; a call pushed out
// of the past set is forgotten.
func (l *toolCallLedger) put(key string, state toolCallState) {
	if el, ok := l.calls[key]; ok {
		l.remove(el)
	}
	q, limit := l.queue(state)
	l.calls[key] = q.PushBack(&toolCall{key: key, state: state})
	for q.Len() > limit {
		oldest := q.Front()
		evicted := oldest.Value.(*toolCall).key
		l.remove(oldest)
		if state == toolCallAllowed {
			l.put(evicted, toolCallDone)
		}
	}
}

func (l *toolCallLedger) pre(key string, denied bool) {
	if el, ok := l.calls[key]; ok && el.Value.(*toolCall).state == toolCallDenied {
		// A denial stands: a second PreToolUse for the same call cannot
		// clear it.
		return
	}
	state := toolCallAllowed
	if denied {
		state = toolCallDenied
	}
	l.put(key, state)
}

func (l *toolCallLedger) result(key string, kind toolResult) tamperKind {
	el, ok := l.calls[key]
	if !ok {
		l.put(key, toolCallDone)
		if kind == toolResultRan && l.complete {
			return tamperUnseen
		}
		return tamperNone
	}
	switch el.Value.(*toolCall).state {
	case toolCallAllowed:
		l.put(key, toolCallDone)
	case toolCallDenied:
		if kind == toolResultRan {
			l.put(key, toolCallDone)
			return tamperDenied
		}
		// The harness reporting the denial it honoured.
	}
	return tamperNone
}

func (l *toolCallLedger) size() int { return len(l.calls) }

// hookTamperTracker correlates the PreToolUse and PostToolUse decisions of
// each binding by tool-use ID. Memory is bounded per binding
// (maxOpenToolCalls + maxPastToolCalls entries); ledgers are dropped on
// revoke and when their binding no longer belongs to a sandbox.
type hookTamperTracker struct {
	mu       sync.Mutex
	bindings map[string]*toolCallLedger
}

func newHookTamperTracker() *hookTamperTracker {
	return &hookTamperTracker{bindings: map[string]*toolCallLedger{}}
}

// Begin starts a complete ledger for a binding whose harness has not run
// yet: at mint, and at every sandbox start.
func (t *hookTamperTracker) Begin(bindingID string) {
	if bindingID == "" {
		return
	}
	t.mu.Lock()
	t.bindings[bindingID] = newToolCallLedger(true)
	t.mu.Unlock()
}

// Forget drops a binding's ledger.
func (t *hookTamperTracker) Forget(bindingID string) {
	t.mu.Lock()
	delete(t.bindings, bindingID)
	t.mu.Unlock()
}

// Retain drops the ledgers of bindings live does not report.
func (t *hookTamperTracker) Retain(live func(bindingID string) bool) {
	t.mu.Lock()
	for id := range t.bindings {
		if !live(id) {
			delete(t.bindings, id)
		}
	}
	t.mu.Unlock()
}

// ledger returns the binding's ledger, starting a partial one for a
// binding this process did not begin. Callers hold t.mu.
func (t *hookTamperTracker) ledger(bindingID string) *toolCallLedger {
	l := t.bindings[bindingID]
	if l == nil {
		l = newToolCallLedger(false)
		t.bindings[bindingID] = l
	}
	return l
}

// ObservePre records a PreToolUse decision.
func (t *hookTamperTracker) ObservePre(bindingID, toolUseID string, denied bool) {
	key := toolCallKey(toolUseID)
	if bindingID == "" || key == "" {
		return
	}
	t.mu.Lock()
	t.ledger(bindingID).pre(key, denied)
	t.mu.Unlock()
}

// ObserveResult records a post-tool event and reports whether it proves
// the tool ran without DefenseClaw's approval.
func (t *hookTamperTracker) ObserveResult(bindingID, toolUseID string, kind toolResult) tamperKind {
	key := toolCallKey(toolUseID)
	if bindingID == "" || key == "" || kind == toolResultNone {
		return tamperNone
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ledger(bindingID).result(key, kind)
}

// tracked reports the entries kept for a binding (tests).
func (t *hookTamperTracker) tracked(bindingID string) (int, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	l := t.bindings[bindingID]
	if l == nil {
		return 0, false
	}
	return l.size(), true
}
