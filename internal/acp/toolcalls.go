// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"bytes"
	"encoding/json"
	"unicode/utf8"
)

// What the guard keeps of the tool calls an agent reports, and the bounds on
// it (rel-1-0-10:GAP-0330, GAP-0374). The editor applies a ToolCallUpdate onto
// the tool_call it names, so a permission or an update that leaves out the
// kind is the call that report gave; the gateway cannot know that without the
// guard, which sees the whole conversation. The gateway judges the frame
// merged onto the state before it.
const (
	// MaxTrackedToolCalls is how many tool calls one guard keeps (the least
	// recently used goes first). A frame naming a call that was dropped is
	// sent with {"dropped":true}.
	MaxTrackedToolCalls = 256
	// MaxToolCallStateBytes bounds the state kept and sent for one call. A
	// rawInput over it is cut to a prefix of its text values (so a command
	// that was seen is still judged) and the state says {"truncated":true};
	// when nothing useful fits, rawInput is left out.
	MaxToolCallStateBytes = 64 << 10

	maxToolCallInputText = 8 << 10
	maxDroppedKeysKept   = 1024
)

// ToolCallTracker keeps the state of the tool calls of one guard. The zero
// value is ready to use. It is not safe for concurrent use: the proxy holds
// its own lock around it.
type ToolCallTracker struct {
	calls   *lruMap[json.RawMessage]
	dropped *lruMap[struct{}]
}

// toolCallFields are the fields of a tool call the guard keeps and sends.
type toolCallFields struct {
	Kind      json.RawMessage `json:"kind,omitempty"`
	Title     json.RawMessage `json:"title,omitempty"`
	RawInput  json.RawMessage `json:"rawInput,omitempty"`
	Locations json.RawMessage `json:"locations,omitempty"`
	// Truncated says a field was cut or left out for size; Dropped says the
	// state of the call was dropped to make room for others.
	Truncated bool `json:"truncated,omitempty"`
	Dropped   bool `json:"dropped,omitempty"`
}

// toolCallOf reads the tool call a session/update (tool_call and
// tool_call_update) or a session/request_permission frame names: its
// session, its toolCallId, whether the frame is the first report of the call
// (tool_call), and the object that holds its fields.
func toolCallOf(msg Message) (session, id string, first bool, fields map[string]json.RawMessage, ok bool) {
	if msg.Method != "session/update" && msg.Method != "session/request_permission" {
		return "", "", false, nil, false
	}
	var params map[string]json.RawMessage
	if json.Unmarshal(msg.Params, &params) != nil {
		return "", "", false, nil, false
	}
	_ = json.Unmarshal(params["sessionId"], &session)
	key := "toolCall"
	if msg.Method == "session/update" {
		key = "update"
	}
	if json.Unmarshal(params[key], &fields) != nil || fields == nil {
		return "", "", false, nil, false
	}
	if msg.Method == "session/update" {
		var kind string
		_ = json.Unmarshal(fields["sessionUpdate"], &kind)
		if kind != "tool_call" && kind != "tool_call_update" {
			return "", "", false, nil, false
		}
		first = kind == "tool_call"
	}
	if json.Unmarshal(fields["toolCallId"], &id) != nil || id == "" || session == "" {
		return "", "", false, nil, false
	}
	return session, id, first, fields, true
}

func toolCallKey(session, id string) string { return session + "\x00" + id }

// Peek is the state of the call a frame names as it was before the frame, for
// Evaluation.ToolCallState: nil for a frame that names no call, for the first
// report of one (the editor takes it as the call, it does not merge it) and
// for a call the guard has not seen; {"dropped":true} for a call whose state
// was dropped. It changes nothing but the order of use.
func (t *ToolCallTracker) Peek(msg Message) json.RawMessage {
	session, id, first, _, ok := toolCallOf(msg)
	if !ok || first {
		return nil
	}
	key := toolCallKey(session, id)
	if t.calls != nil {
		if state, found := t.calls.get(key); found {
			return state
		}
	}
	if t.dropped != nil && t.dropped.has(key) {
		return json.RawMessage(`{"dropped":true}`)
	}
	return nil
}

// Commit applies a frame the guard forwarded to the state: the first report
// of a call replaces what was kept, an update replaces the fields it holds
// (null does not). A frame the guard refused is never committed: the editor
// did not see it.
func (t *ToolCallTracker) Commit(msg Message) {
	session, id, first, fields, ok := toolCallOf(msg)
	if !ok {
		return
	}
	key := toolCallKey(session, id)
	if t.calls == nil {
		t.calls = newLRUMap[json.RawMessage](MaxTrackedToolCalls)
	}
	var state toolCallFields
	if !first {
		if before, found := t.calls.get(key); found {
			_ = json.Unmarshal(before, &state)
		}
	}
	set := func(dst *json.RawMessage, name string) {
		if raw, present := fields[name]; present && string(bytes.TrimSpace(raw)) != "null" {
			*dst = raw
		}
	}
	set(&state.Kind, "kind")
	set(&state.Title, "title")
	set(&state.RawInput, "rawInput")
	set(&state.Locations, "locations")
	merged, err := json.Marshal(state)
	if err == nil && len(merged) > MaxToolCallStateBytes {
		state.RawInput, state.Truncated = shrinkToolCallInput(state.RawInput), true
		merged, err = json.Marshal(state)
	}
	if err == nil && len(merged) > MaxToolCallStateBytes {
		state.RawInput, state.Locations = nil, nil
		merged, err = json.Marshal(state)
	}
	if err != nil || len(merged) > MaxToolCallStateBytes {
		return
	}
	if evicted, ok := t.calls.put(key, merged); ok {
		if t.dropped == nil {
			t.dropped = newLRUMap[struct{}](maxDroppedKeysKept)
		}
		t.dropped.put(evicted, struct{}{})
	}
	if t.dropped != nil {
		t.dropped.remove(key)
	}
}

// shrinkToolCallInput keeps of a rawInput that is too large the prefix of each
// of its text values (a command that was seen is still judged) and its small
// values; nothing when it is not an object.
func shrinkToolCallInput(raw json.RawMessage) json.RawMessage {
	var input map[string]json.RawMessage
	if json.Unmarshal(raw, &input) != nil || input == nil {
		return nil
	}
	kept := make(map[string]json.RawMessage, len(input))
	for name, value := range input {
		var text string
		if json.Unmarshal(value, &text) == nil {
			if len(text) > maxToolCallInputText {
				cut := maxToolCallInputText
				for cut > 0 && !utf8.RuneStart(text[cut]) {
					cut--
				}
				text = text[:cut]
			}
			if encoded, err := json.Marshal(text); err == nil {
				kept[name] = encoded
			}
		} else if len(value) <= 1<<10 {
			kept[name] = value
		}
	}
	out, err := json.Marshal(kept)
	if err != nil {
		return nil
	}
	return out
}
