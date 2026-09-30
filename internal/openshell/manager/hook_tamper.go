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
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
)

// Hook tamper detection.
//
// A sandbox hook is judgment inside the sandbox boundary: it runs as the
// workload's uid in the workload's PID namespace, and a harness treats a
// hook that dies with anything but its veto exit code (2) as a non-blocking
// error. A workload that kills the pre-tool hook therefore gets its tool
// call run without a DefenseClaw verdict. The files and egress boundaries
// are enforced outside the sandbox and do not depend on the hooks. What the
// gateway can see is the lifecycle of each tool call: the harness reports
// the call's pre-tool event and, once the tool ran, its post-tool event,
// both naming the same call. A post-tool event whose pre-tool event was
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
	// toolCallAllowed: the pre-tool event was allowed and no result arrived
	// yet.
	toolCallAllowed toolCallState = iota + 1
	// toolCallDenied: DefenseClaw denied the pre-tool event.
	toolCallDenied
	// toolCallDone: a result arrived, or an allowed call left the open set
	// unanswered. Either way a result for it is not tamper.
	toolCallDone
)

// toolResult classifies the post-tool hook events.
type toolResult uint8

const (
	toolResultNone toolResult = iota
	// toolResultRan is an event that proves the tool ran (PostToolUse).
	toolResultRan
	// toolResultFailed is a failed call (Claude Code's PostToolUseFailure,
	// Cursor's postToolUseFailure, an Amp tool.result that is not done).
	// Claude can report a call that failed before its PreToolUse (invalid
	// input), so it closes a call but never proves tamper.
	toolResultFailed
	// toolResultRefused is Claude Code's PermissionDenied: the harness
	// itself refused the call.
	toolResultRefused
)

// tamperKind is the verdict for one tool result.
type tamperKind uint8

const (
	tamperNone tamperKind = iota
	// tamperDenied: the tool ran although DefenseClaw denied its pre-tool
	// event.
	tamperDenied
	// tamperUnseen: the tool ran and its pre-tool event never reached
	// DefenseClaw.
	tamperUnseen
)

// toolCallKeying is how a harness's hooks name one tool call.
type toolCallKeying uint8

const (
	// keyNone: the hooks name no call, so its events are not paired.
	keyNone toolCallKeying = iota
	// keyByID: the harness sends one per-call ID with the call's pre-tool
	// and post-tool events.
	keyByID
	// keyByContent: the hooks carry no per-call ID, but the harness sends
	// the call's session, tool name and tool input unchanged with both
	// events and sends the post-tool event only for a tool that ran. A call
	// is keyed by a digest of the three; identical calls share the key, so
	// the ledger counts them.
	keyByContent
)

// toolCallHooks are one harness's tool-call hook events. Event names are
// exact, as the harness sends them: case folding would widen what a vendor
// contract promises (see connector.ToolCallLifecycleContract).
type toolCallHooks struct {
	keying toolCallKeying
	// pre opens a call.
	pre string
	// ran proves the tool ran; failed and refused close a call without
	// proving it ran (toolResultFailed, toolResultRefused).
	ran, failed, refused string
	// statusResult reports the outcome in the event's status field: only
	// ranStatus proves the tool ran, any other status closes the call as
	// failed.
	statusResult, ranStatus string
}

// toolCallHooksByConnector are the tool-call hook events of each sandboxed
// harness, as the gateway receives them.
var toolCallHooksByConnector = map[string]toolCallHooks{
	"claudecode": {keying: keyByID, pre: "PreToolUse", ran: "PostToolUse", failed: "PostToolUseFailure", refused: "PermissionDenied"},
	"codex":      {keying: keyByID, pre: "PreToolUse", ran: "PostToolUse"},
	// Cursor Agent sends tool_use_id with preToolUse and postToolUse (its
	// specialised shell, MCP and file events carry none).
	"cursor": {keying: keyByID, pre: "preToolUse", ran: "postToolUse", failed: "postToolUseFailure"},
	// The OpenCode plugin forwards the call's callID. OpenCode runs
	// tool.execute.after only once the tool returned; a throw from
	// tool.execute.before (DefenseClaw's block) skips the tool and the
	// after hook.
	"opencode": {keying: keyByID, pre: "tool.execute.before", ran: "tool.execute.after"},
	// The Amp plugin forwards the call's toolUseID. A tool.result reports
	// done, error or cancelled; only done proves the tool ran (a call the
	// plugin rejected is not reported as done).
	"amp": {keying: keyByID, pre: "tool.call", statusResult: "tool.result", ranStatus: "done"},
	// Kiro CLI 2.24.1 sends no per-call ID: preToolUse carries session_id,
	// tool_name and tool_input, and postToolUse the same three plus
	// tool_response. Measured: postToolUse fires only for a tool that ran,
	// never for one a preToolUse exit 2 blocked or Kiro's own permission
	// check denied, and preToolUse fires before that check.
	"kiro": {keying: keyByContent, pre: "preToolUse", ran: "postToolUse"},
	// Copilot CLI and Devin CLI hooks carry no per-call ID either, and
	// whether their post-tool events fire for a call a hook denied is not
	// measured, so their calls are not paired: hook silence is their
	// backstop.
	"copilot": {pre: "preToolUse", ran: "postToolUse", failed: "postToolUseFailure"},
	"devin":   {pre: "PreToolUse", ran: "PostToolUse"},
	// Hermes, OpenHands, Antigravity and OmniGent: whether their hooks carry
	// a per-call ID the gateway sees, and whether a post-tool event fires for
	// a denied call, is not measured, so they are not paired either.
	"hermes":      {pre: "pre_tool_call", ran: "post_tool_call"},
	"openhands":   {pre: "PreToolUse", ran: "PostToolUse"},
	"antigravity": {pre: "PreToolUse", ran: "PostToolUse"},
	"omnigent":    {pre: "PreToolUse", ran: "PostToolUse"},
}

// toolCallHooksFor returns the connector's tool-call hook events. A
// decision that names no connector uses Claude Code's; an unknown connector
// has none.
func toolCallHooksFor(connector string) toolCallHooks {
	if connector == "" {
		connector = "claudecode"
	}
	return toolCallHooksByConnector[connector]
}

// classify reports whether event opens a tool call, or which result it is.
// status is the event's reported status (statusResult events only).
func (h toolCallHooks) classify(event, status string) (pre bool, result toolResult) {
	if event == "" {
		return false, toolResultNone
	}
	switch event {
	case h.pre:
		return true, toolResultNone
	case h.ran:
		return false, toolResultRan
	case h.failed:
		return false, toolResultFailed
	case h.refused:
		return false, toolResultRefused
	case h.statusResult:
		if strings.TrimSpace(status) == h.ranStatus {
			return false, toolResultRan
		}
		return false, toolResultFailed
	}
	return false, toolResultNone
}

// preHookName names the pre-tool hook in a tamper report.
func (h toolCallHooks) preHookName() string {
	if h.pre == "" {
		return "pre-tool"
	}
	return h.pre
}

// toolCallRef names one tool call in a binding's ledger. The zero value
// names none.
type toolCallRef struct {
	key string
	// byContent: key is the call's content digest, shared by identical
	// calls.
	byContent bool
}

// idRef names the call a harness's per-call ID identifies: the ID itself,
// or the digest of an oversized one. Empty IDs name no call.
func idRef(id string) toolCallRef {
	id = strings.TrimSpace(id)
	if id == "" {
		return toolCallRef{}
	}
	if len(id) <= maxToolUseIDBytes {
		return toolCallRef{key: id}
	}
	sum := sha256.Sum256([]byte(id))
	return toolCallRef{key: "sha256:" + hex.EncodeToString(sum[:])}
}

// contentRef names a call by the digest of its session, tool name and
// canonical tool input (object keys sorted, numbers verbatim). A call
// without a tool name or input names none.
func contentRef(session, tool string, input json.RawMessage) toolCallRef {
	tool = strings.TrimSpace(tool)
	if tool == "" || len(bytes.TrimSpace(input)) == 0 {
		return toolCallRef{}
	}
	canonical := []byte(input)
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err == nil {
		if out, err := json.Marshal(v); err == nil {
			canonical = out
		}
	}
	h := sha256.New()
	for _, part := range [][]byte{[]byte(strings.TrimSpace(session)), []byte(tool), canonical} {
		_, _ = h.Write(part)
		_, _ = h.Write([]byte{0})
	}
	return toolCallRef{key: "call:" + hex.EncodeToString(h.Sum(nil)), byContent: true}
}

// ref names the call a decision concerns, as the connector's hooks do.
func (h toolCallHooks) ref(d HookDecision) toolCallRef {
	switch h.keying {
	case keyByID:
		return idRef(d.ToolUseID)
	case keyByContent:
		return contentRef(d.SessionID, d.Tool, d.ToolInput)
	}
	return toolCallRef{}
}

type toolCall struct {
	key   string
	state toolCallState
	// open counts the allowed calls of a content key whose result has not
	// arrived; it is 1 for an allowed ID key and 0 otherwise.
	open int
}

// toolCallLedger is one binding's tool calls: allowed calls in open, the
// others in past, each oldest first.
type toolCallLedger struct {
	// complete is set when this process has seen every hook request of the
	// binding since the harness started: the binding was minted, or its
	// sandbox started, here. Only then does a result for an unknown call
	// prove that its pre-tool event never arrived. After a daemon restart
	// the ledger of a running sandbox is partial until its next start.
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

// put records key in state with open allowed calls, as the newest entry of
// its queue. An allowed call pushed out of the open set is remembered as
// done; a call pushed out of the past set is forgotten.
func (l *toolCallLedger) put(key string, state toolCallState, open int) {
	if el, ok := l.calls[key]; ok {
		l.remove(el)
	}
	q, limit := l.queue(state)
	l.calls[key] = q.PushBack(&toolCall{key: key, state: state, open: open})
	for q.Len() > limit {
		oldest := q.Front()
		evicted := oldest.Value.(*toolCall).key
		l.remove(oldest)
		if state == toolCallAllowed {
			l.put(evicted, toolCallDone, 0)
		}
	}
}

func (l *toolCallLedger) pre(ref toolCallRef, denied bool) {
	if el, ok := l.calls[ref.key]; ok {
		call := el.Value.(*toolCall)
		switch {
		case !ref.byContent && call.state == toolCallDenied:
			// A denial stands: a second PreToolUse for the same call
			// cannot clear it.
			return
		case ref.byContent && call.state == toolCallAllowed:
			// An identical call is already open. Another allowed one
			// joins it; a denied one leaves it, since the next result
			// is the open call's.
			if !denied {
				l.put(ref.key, toolCallAllowed, call.open+1)
			}
			return
		}
	}
	// A new call, or for a content key a repeat of a finished or denied
	// one: its own verdict decides.
	if denied {
		l.put(ref.key, toolCallDenied, 0)
		return
	}
	l.put(ref.key, toolCallAllowed, 1)
}

func (l *toolCallLedger) result(ref toolCallRef, kind toolResult) tamperKind {
	el, ok := l.calls[ref.key]
	if !ok {
		l.put(ref.key, toolCallDone, 0)
		if kind == toolResultRan && l.complete {
			return tamperUnseen
		}
		return tamperNone
	}
	call := el.Value.(*toolCall)
	switch call.state {
	case toolCallAllowed:
		if call.open > 1 {
			call.open--
			return tamperNone
		}
		l.put(ref.key, toolCallDone, 0)
	case toolCallDenied:
		if kind == toolResultRan {
			l.put(ref.key, toolCallDone, 0)
			return tamperDenied
		}
		// The harness reporting the denial it honoured.
	}
	// toolCallDone: a repeated result, or for a content key a repeat of a
	// call DefenseClaw allowed with the same input.
	return tamperNone
}

func (l *toolCallLedger) size() int { return len(l.calls) }

// hookTamperTracker correlates the pre-tool and post-tool decisions of
// each binding's tool calls. Memory is bounded per binding
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

// ObservePre records a pre-tool decision.
func (t *hookTamperTracker) ObservePre(bindingID string, ref toolCallRef, denied bool) {
	if bindingID == "" || ref.key == "" {
		return
	}
	t.mu.Lock()
	t.ledger(bindingID).pre(ref, denied)
	t.mu.Unlock()
}

// ObserveResult records a post-tool event and reports whether it proves
// the tool ran without DefenseClaw's approval.
func (t *hookTamperTracker) ObserveResult(bindingID string, ref toolCallRef, kind toolResult) tamperKind {
	if bindingID == "" || ref.key == "" || kind == toolResultNone {
		return tamperNone
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ledger(bindingID).result(ref, kind)
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
