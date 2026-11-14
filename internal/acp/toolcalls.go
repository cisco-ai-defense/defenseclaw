// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"bytes"
	"encoding/json"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
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
	// state over it has its title and the text values of its rawInput cut to
	// a prefix (so a command that was seen is still judged) and says
	// {"truncated":true}; locations past the bound are cut to the first ones
	// that fit (at most MaxToolCallLocations); when nothing useful fits,
	// rawInput is left out, and then all but the kind and the marks.
	MaxToolCallStateBytes = 64 << 10
	// MaxToolCallLocations is how many locations of one call the gateway
	// judges one by one: a frame that names more has the first ones judged
	// and is raised to the unknown tier of the pack. A kept state cut for
	// size keeps at most this many of its first locations.
	MaxToolCallLocations = 64

	maxToolCallInputText  = 8 << 10
	maxToolCallSmallValue = 1 << 10
	maxDroppedKeysKept    = 1024
)

// ToolCallTracker keeps the state of the tool calls of one guard. The zero
// value is ready to use. It is not safe for concurrent use: the proxy holds
// its own lock around it.
type ToolCallTracker struct {
	calls *lruMap[json.RawMessage]
	// dropped are the calls whose state was dropped to make room, true for
	// one with a report the gateway judged a block (toolCallFields.Flagged).
	dropped *lruMap[bool]
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
	// Flagged says the gateway judged a report of the call that the guard
	// forwarded a block, or one that would have blocked. The gateway never
	// judges a permission for the call below a block: what the guard kept of
	// it may have been cut or dropped since (ACP review round 4, P3-1).
	Flagged bool `json:"flagged,omitempty"`
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
// was dropped (with "flagged":true when a report of it was judged a block).
// It changes nothing but the order of use.
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
	if t.dropped != nil {
		if flagged, found := t.dropped.peek(key); found {
			if flagged {
				return json.RawMessage(`{"dropped":true,"flagged":true}`)
			}
			return json.RawMessage(`{"dropped":true}`)
		}
	}
	return nil
}

// Commit applies a frame the guard forwarded to the state: the first report
// of a call replaces what was kept, an update replaces the fields it holds
// (null does not). A frame the guard refused is never committed: the editor
// did not see it. blocked says the gateway judged the frame a block or one
// that would have blocked (Verdict.JudgedBlock); it stays with the call for
// as long as the guard knows the call, its state dropped or not.
func (t *ToolCallTracker) Commit(msg Message, blocked bool) {
	session, id, first, fields, ok := toolCallOf(msg)
	if !ok {
		return
	}
	key := toolCallKey(session, id)
	if t.calls == nil {
		t.calls = newLRUMap[json.RawMessage](MaxTrackedToolCalls)
	}
	var state toolCallFields
	before, found := t.calls.get(key)
	if found && !first {
		_ = json.Unmarshal(before, &state)
	}
	state.Flagged = blocked || t.flagged(before, found, key)
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
		// The title is cut as the input's text is: claude-code-acp titles a
		// shell call with its command (ACP review round 5, GAP-0462).
		state.Title = shrinkToolCallTitle(state.Title)
		state.RawInput, state.Truncated = shrinkToolCallInput(state.RawInput), true
		merged, err = json.Marshal(state)
	}
	// The locations past the bound are cut to the first ones that fit, as
	// an input keeps the start of its text: what was seen first is still
	// judged. Then the input goes, and the first locations that fit without
	// it stay.
	locations := state.Locations
	if err == nil && len(merged) > MaxToolCallStateBytes {
		state.Locations = firstToolCallLocations(locations, toolCallLocationRoom(state))
		merged, err = json.Marshal(state)
	}
	if err == nil && len(merged) > MaxToolCallStateBytes {
		state.RawInput = nil
		state.Locations = firstToolCallLocations(locations, toolCallLocationRoom(state))
		merged, err = json.Marshal(state)
	}
	if err != nil || len(merged) > MaxToolCallStateBytes {
		// Nothing useful fits. The call is still kept, cut: never the state
		// before this frame, which the editor no longer shows, and never
		// without the report's block mark (ACP review round 5, GAP-0462).
		merged = minimalToolCallState(state.Kind, state.Flagged)
	}
	if evicted, evictedState, ok := t.calls.put(key, merged); ok {
		if t.dropped == nil {
			t.dropped = newLRUMap[bool](maxDroppedKeysKept)
		}
		var gone toolCallFields
		_ = json.Unmarshal(evictedState, &gone)
		t.dropped.put(evicted, gone.Flagged)
	}
	if t.dropped != nil {
		t.dropped.remove(key)
	}
}

// flagged reports that a report of the call under key was judged a block: in
// its kept state (before, when found), or in the record of its drop.
func (t *ToolCallTracker) flagged(before json.RawMessage, found bool, key string) bool {
	if found {
		var state toolCallFields
		return json.Unmarshal(before, &state) == nil && state.Flagged
	}
	if t.dropped == nil {
		return false
	}
	flagged, _ := t.dropped.peek(key)
	return flagged
}

// toolCallLocationRoom is how many bytes of locations fit in the bound beside
// the other fields of state.
func toolCallLocationRoom(state toolCallFields) int {
	state.Locations = nil
	others, err := json.Marshal(state)
	if err != nil {
		return 0
	}
	return MaxToolCallStateBytes - len(others) - len(`,"locations":`)
}

// firstToolCallLocations keeps the first locations of raw that fit in room
// bytes, at most MaxToolCallLocations: the ones the gateway judges first.
// Nothing when raw is not a list or none fits. The caller marks the state
// truncated, which the gateway reads as the bound rule's cap hit.
func firstToolCallLocations(raw json.RawMessage, room int) json.RawMessage {
	var all []json.RawMessage
	if json.Unmarshal(raw, &all) != nil {
		return nil
	}
	var trunc bounded.Truncated
	count := bounded.NewCounter(&trunc, bounded.Locations, MaxToolCallLocations)
	size := bounded.NewCounter(&trunc, bounded.Bytes, room-len(`[]`))
	kept := make([]json.RawMessage, 0, min(len(all), MaxToolCallLocations))
	for _, location := range all {
		if !count.Take() || !size.TakeN(len(location)+len(`,`)) {
			break
		}
		kept = append(kept, location)
	}
	if len(kept) == 0 {
		return nil
	}
	out, err := json.Marshal(kept)
	if err != nil {
		return nil
	}
	return out
}

// minimalToolCallState is the state kept for a call when nothing useful fits
// in the bound: its kind (when that is small), the truncated mark the gateway
// reads as the bound rule's cap hit, and the report's block mark.
func minimalToolCallState(kind json.RawMessage, flagged bool) json.RawMessage {
	state := toolCallFields{Truncated: true, Flagged: flagged}
	if len(kind) <= maxToolCallSmallValue {
		state.Kind = kind
	}
	if out, err := json.Marshal(state); err == nil {
		return out
	}
	state.Kind = nil
	out, _ := json.Marshal(state) // only bools: it cannot fail
	return out
}

// cutToolCallText keeps the prefix of text that fits in maxToolCallInputText
// bytes, cut at the start of a rune (a command that was seen is still
// judged). The cut is recorded in trunc.
func cutToolCallText(trunc *bounded.Truncated, text string) string {
	size := bounded.NewCounter(trunc, bounded.Bytes, maxToolCallInputText)
	if size.TakeN(len(text)) {
		return text
	}
	cut := maxToolCallInputText
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut]
}

// shrinkToolCallTitle cuts a title that is too large: a text title to its
// prefix, any other value that is not small goes. The caller marks the state
// truncated.
func shrinkToolCallTitle(raw json.RawMessage) json.RawMessage {
	var title string
	if json.Unmarshal(raw, &title) != nil {
		if len(raw) <= maxToolCallSmallValue {
			return raw
		}
		return nil
	}
	var trunc bounded.Truncated
	out, err := json.Marshal(cutToolCallText(&trunc, title))
	if err != nil {
		return nil
	}
	return out
}

// shrinkToolCallInput keeps of a rawInput that is too large the prefix of each
// of its text values (a command that was seen is still judged) and its small
// values; nothing when it is not an object.
func shrinkToolCallInput(raw json.RawMessage) json.RawMessage {
	var input map[string]json.RawMessage
	if json.Unmarshal(raw, &input) != nil || input == nil {
		return nil
	}
	var trunc bounded.Truncated
	kept := make(map[string]json.RawMessage, len(input))
	for name, value := range input {
		var text string
		if json.Unmarshal(value, &text) == nil {
			if encoded, err := json.Marshal(cutToolCallText(&trunc, text)); err == nil {
				kept[name] = encoded
			}
		} else if len(value) <= maxToolCallSmallValue {
			kept[name] = value
		}
	}
	out, err := json.Marshal(kept)
	if err != nil {
		return nil
	}
	return out
}
