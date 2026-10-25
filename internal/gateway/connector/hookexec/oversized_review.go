// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"encoding/json"
	"strings"
)

const (
	// oversizedReviewHead bounds a string the review keeps as context only
	// (content, prompts, tool results).
	oversizedReviewHead = 8 << 10
	// oversizedReviewKeep bounds the command and target text kept verbatim,
	// summed over every such field. A call whose command and target values do
	// not all fit is reviewed as uninspected (OversizeUninspectedField).
	// oversizedReviewHeads bounds the context heads; only they shrink when
	// the encoded review is too large.
	oversizedReviewKeep  = 896 << 10
	oversizedReviewHeads = 192 << 10
	// oversizedReviewMaxBytes is the encoded review size the reducer aims
	// for, under the gateway's 1 MiB request cap.
	oversizedReviewMaxBytes = 960 << 10
	oversizedReviewMaxDepth = 128
)

// OversizeUninspectedField marks a bounded review that lacks part of a
// command or target value of the call: one too long to keep whole, cut by
// the cap, nested too deep, or hidden past the cap in the call's arguments.
// The gateway never allows such a review silently: it warns and audits
// "oversize, command not inspected" in observe mode and blocks in action
// mode. The field can only tighten a verdict, never loosen one.
const OversizeUninspectedField = "oversize_command_not_inspected"

// oversizedReviewKeys are the fields, at any depth and in any connector's
// payload, that carry what a call runs or touches: shell commands and their
// arguments (Amp and Codex exec_command "cmd", Claude/Cursor "command",
// Codex shell "command" arrays, Copilot "toolArgs"), patches (Codex
// apply_patch "input"/"patch"), scripts and every path or target form. The
// review keeps their values, and everything nested in them, verbatim, or
// sends no review at all. Keys are compared lower-case without '_' and '-'.
var oversizedReviewKeys = map[string]bool{
	"cmd": true, "command": true, "commands": true, "commandline": true,
	"args": true, "arguments": true, "argv": true, "toolargs": true,
	"script": true, "code": true, "input": true, "patch": true, "patchtext": true, "diff": true,
	"filepath": true, "path": true, "paths": true, "file": true, "files": true, "filename": true,
	"target": true, "targetfile": true, "targetpath": true, "targets": true,
	"destination": true, "dest": true, "source": true, "sourcepath": true,
	"oldpath": true, "newpath": true, "absolutepath": true, "relativepath": true,
	"url": true, "uri": true, "cwd": true, "workdir": true, "workingdirectory": true,
	"directory": true, "dir": true,
}

func oversizedReviewKey(key string) bool {
	key = strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(key))
	return oversizedReviewKeys[key]
}

// oversizedReviewPayload turns the bounded prefix of an oversized payload
// into an ordinary, valid hook request for the gateway's usual verdict. It
// keeps the prefix's whole structure: every key at every depth, before or
// after a long value, arrays included. Command and target values are kept
// verbatim (oversizedReviewKeys); other strings keep an 8 KiB head; a context
// value the cap cut keeps the part the prefix holds. Fields past the cap were
// never read and are not in the review. A review that could not keep every
// command and target value of the call whole carries OversizeUninspectedField
// (and a head of each such value). It returns nil, so the caller keeps its
// closed oversize answer, only for a duplicated key (the gateway refuses that
// payload at full size) or a structure too large for the gateway cap.
func oversizedReviewPayload(prefix []byte, boundEvent string) []byte {
	review, _ := oversizedReview(prefix, boundEvent)
	return review
}

// oversizedReview is oversizedReviewPayload; uninspected reports that the
// review carries OversizeUninspectedField.
func oversizedReview(prefix []byte, boundEvent string) (body []byte, uninspected bool) {
	// The last pass keeps no command or target value whole: the review is
	// then uninspected but still under the cap.
	for pass := 0; pass <= 4; pass++ {
		r := &oversizedReducer{src: prefix, keep: oversizedReviewKeep, heads: oversizedReviewHeads >> min(pass, 3)}
		if pass == 4 {
			r.keep = 0
		}
		review := map[string]any{}
		decoder := json.NewDecoder(bytes.NewReader(prefix))
		decoder.UseNumber()
		if token, err := decoder.Token(); err == nil && token == json.Delim('{') {
			if object, _, _ := r.object(decoder, false, 1); object != nil {
				review = object.(map[string]any)
			}
		}
		if r.duplicate {
			return nil, false
		}
		if r.incomplete {
			review[OversizeUninspectedField] = true
		}
		review["content_truncated"] = true
		review["bounded_prefix_review"] = true
		review["original_body_bytes"] = len(prefix) // lower bound: the reader stopped at cap+1
		if boundEvent != "" {
			review["hook_event_name"] = boundEvent
		}
		if _, ok := review["tool_input"]; !ok {
			if path, ok := review["file_path"].(string); ok {
				review["tool_input"] = map[string]any{"file_path": path}
			}
		}
		if body := encodeOversizedReview(review); len(body) <= oversizedReviewMaxBytes {
			return body, r.incomplete
		}
	}
	return nil, false
}

// OversizedReviewPayload is the shell transport's bounded review encoder.
// The native hook uses the same encoder directly before its gateway call.
func OversizedReviewPayload(prefix []byte, boundEvent string) []byte {
	return oversizedReviewPayload(prefix, boundEvent)
}

func encodeOversizedReview(value any) []byte {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(value) != nil {
		return nil
	}
	return bytes.TrimRight(out.Bytes(), "\n")
}

type oversizedReducer struct {
	src         []byte
	keep, heads int
	duplicate   bool
	// incomplete is set when a command or target value is not kept whole.
	incomplete bool
	// argsDepth is the depth of the call's arguments object (tool_input, an
	// embedded toolArgs document) while the reducer is inside it, else 0.
	argsDepth int
	// cutSettled is set once settleCut has judged where the prefix ends.
	cutSettled bool
}

// value reads the next value. present reports whether the review keeps
// it; complete is false once the prefix ends inside it.
func (r *oversizedReducer) value(decoder *json.Decoder, keep bool, depth int) (value any, present, complete bool) {
	if depth > oversizedReviewMaxDepth {
		r.incomplete = r.incomplete || keep
		var skipped json.RawMessage
		return nil, false, decoder.Decode(&skipped) == nil
	}
	start := decoder.InputOffset()
	token, err := decoder.Token()
	if err != nil {
		text, ok := r.cutString(start, keep, depth)
		return text, ok, false
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			return r.object(decoder, keep, depth+1)
		case '[':
			return r.array(decoder, keep, depth+1)
		}
		return nil, false, false
	case string:
		text, ok := r.text(token, keep, depth)
		return text, ok, true
	case json.Number:
		return token, r.charge(keep, len(token)), true
	default: // bool or null
		return token, r.charge(keep, 4), true
	}
}

func (r *oversizedReducer) object(decoder *json.Decoder, keep bool, depth int) (any, bool, bool) {
	out := map[string]any{}
	sawKey := false // a command or target key of this object was read whole
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			r.settleCut(keep, sawKey, depth)
			return out, true, false
		}
		key, ok := token.(string)
		if !ok {
			r.settleCut(keep, sawKey, depth)
			return out, true, false
		}
		if _, seen := out[key]; seen {
			r.duplicate = true
		}
		childKeep := keep || oversizedReviewKey(key)
		args := depth == 1 && r.argsDepth == 0 && strings.EqualFold(strings.ReplaceAll(key, "_", ""), "toolinput")
		if args {
			r.argsDepth = depth + 1
		}
		value, present, complete := r.value(decoder, childKeep, depth)
		if present && (r.charge(childKeep, len(key)) || childKeep || value != nil) {
			out[key] = value
		}
		if !complete {
			r.settleCut(childKeep, sawKey, depth)
			return out, true, false
		}
		if args {
			r.argsDepth = 0
		}
		sawKey = sawKey || childKeep
	}
	_, err := decoder.Token()
	if err != nil {
		r.settleCut(keep, sawKey, depth)
	}
	return out, len(out) > 0 || r.charge(keep, 2), err == nil
}

// settleCut judges, from the innermost object the prefix ends in outward,
// whether the cap may have hidden a command or target value: the prefix ends
// inside one, or inside the call's arguments before any of their command or
// target keys was read (an agent writes the arguments in any order, so a long
// description can come before the command). A cut in context outside the
// arguments, or after the arguments named their command or target, hides none.
func (r *oversizedReducer) settleCut(keep, sawKey bool, depth int) {
	if r.cutSettled {
		return
	}
	switch {
	case keep:
		r.incomplete = true
	case r.argsDepth == 0 || depth < r.argsDepth || sawKey:
	case depth > r.argsDepth:
		return // an enclosing object of the arguments decides
	default:
		r.incomplete = true
	}
	r.cutSettled = true
}

func (r *oversizedReducer) array(decoder *json.Decoder, keep bool, depth int) (any, bool, bool) {
	out := []any{}
	for decoder.More() {
		value, present, complete := r.value(decoder, keep, depth)
		if present {
			out = append(out, value)
		}
		if !complete {
			return out, true, false
		}
	}
	_, err := decoder.Token()
	return out, len(out) > 0 || r.charge(keep, 2), err == nil
}

// charge takes n bytes from the budget of the value's class.
func (r *oversizedReducer) charge(keep bool, n int) bool {
	if keep {
		if r.keep >= n {
			r.keep -= n
			return true
		}
		r.incomplete = true
		return false
	}
	if r.heads >= n {
		r.heads -= n
		return true
	}
	r.heads = 0
	return false
}

// text keeps a command or target value verbatim while the keep budget
// lasts, and a bounded head of anything else. An embedded JSON document
// (Copilot toolArgs) too long to keep is reduced like the payload, so its
// command and target keys survive whole. A command or target value that
// fits neither way marks the review incomplete and keeps a bounded head.
func (r *oversizedReducer) text(value string, keep bool, depth int) (string, bool) {
	if keep && len(value) <= r.keep {
		r.keep -= len(value)
		return value, true
	}
	if keep {
		if reduced, ok := r.embedded(value, depth); ok {
			return reduced, true
		}
		// Only a head of it is sent, and the review is marked uninspected.
		r.incomplete = true
	}
	n := min(len(value), oversizedReviewHead, r.heads)
	if n <= 0 {
		return "", value == ""
	}
	r.heads -= n
	return validUTF8Head(value, n), true
}

func (r *oversizedReducer) embedded(value string, depth int) (string, bool) {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') || depth >= oversizedReviewMaxDepth {
		return "", false
	}
	// The document is the call's arguments: settleCut judges a cut in it.
	sub := &oversizedReducer{src: []byte(trimmed), keep: r.keep, heads: r.heads, argsDepth: depth + 1}
	decoder := json.NewDecoder(bytes.NewReader(sub.src))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return "", false
	}
	// Its keys are classified like the payload's: a long file text in it
	// keeps a head, its command and target keys stay whole.
	var reduced any
	complete := false
	if token == json.Delim('{') {
		reduced, _, complete = sub.object(decoder, false, depth+1)
	} else {
		reduced, _, complete = sub.array(decoder, false, depth+1)
	}
	r.keep, r.heads = sub.keep, sub.heads
	r.duplicate = r.duplicate || sub.duplicate
	r.incomplete = r.incomplete || sub.incomplete || (!complete && !sub.cutSettled)
	return string(encodeOversizedReview(reduced)), true
}

// cutString recovers the head of the string value the prefix ends in.
func (r *oversizedReducer) cutString(start int64, keep bool, depth int) (string, bool) {
	if start < 0 || start >= int64(len(r.src)) {
		return "", false
	}
	raw := bytes.TrimLeft(r.src[start:], " \t\r\n:,")
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	limit := min(oversizedReviewHead, r.heads)
	if keep {
		limit = max(limit, r.keep)
	}
	if limit <= 0 {
		r.incomplete = r.incomplete || keep
		return "", false
	}
	if len(raw) > limit+1 {
		raw = raw[:limit+1]
	}
	// The cut may split a UTF-8 rune or an escape. Drop only its tail.
	for trim := 0; trim < 8 && len(raw) > 1; trim++ {
		var text string
		if json.Unmarshal(append(append([]byte(nil), raw...), '"'), &text) == nil {
			text = strings.ToValidUTF8(text, "")
			if keep {
				// The cap cut this command or target value: only an embedded
				// document's whole keys can still be judged. Else send a head
				// of it and mark the review uninspected.
				if reduced, ok := r.embedded(text, depth); ok {
					r.cutSettled = true // the document judged its own cut
					return reduced, true
				}
				r.incomplete = true
			}
			return r.text(text, false, depth)
		}
		raw = raw[:len(raw)-1]
	}
	r.incomplete = r.incomplete || keep
	return "", false
}

func validUTF8Head(value string, n int) string {
	if n >= len(value) {
		return value
	}
	return strings.ToValidUTF8(value[:n], "")
}
