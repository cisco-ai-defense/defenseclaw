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
	// not all fit gets no review: it keeps the closed oversize answer.
	// oversizedReviewHeads bounds the context heads; only they shrink when
	// the encoded review is too large.
	oversizedReviewKeep  = 896 << 10
	oversizedReviewHeads = 192 << 10
	// oversizedReviewMaxBytes is the encoded review size the reducer aims
	// for, under the gateway's 1 MiB request cap.
	oversizedReviewMaxBytes = 960 << 10
	oversizedReviewMaxDepth = 128
)

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
// never read and are not in the review. It returns nil, so the caller keeps
// its closed oversize answer, when the review could not judge the call as
// sent: a command or target value that does not fit whole (too long, cut by
// the cap, nested too deep), a review still over the gateway cap, or a
// duplicated key (the gateway refuses that payload at full size).
func oversizedReviewPayload(prefix []byte, boundEvent string) []byte {
	for scale := 1; scale <= 8; scale *= 2 {
		r := &oversizedReducer{src: prefix, keep: oversizedReviewKeep, heads: oversizedReviewHeads / scale}
		review := map[string]any{}
		decoder := json.NewDecoder(bytes.NewReader(prefix))
		decoder.UseNumber()
		if token, err := decoder.Token(); err == nil && token == json.Delim('{') {
			if object, _, _ := r.object(decoder, false, 1); object != nil {
				review = object.(map[string]any)
			}
		}
		if r.duplicate || r.incomplete {
			return nil
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
			return body
		}
	}
	return nil
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
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return out, true, false
		}
		key, ok := token.(string)
		if !ok {
			return out, true, false
		}
		if _, seen := out[key]; seen {
			r.duplicate = true
		}
		childKeep := keep || oversizedReviewKey(key)
		value, present, complete := r.value(decoder, childKeep, depth)
		if present && (r.charge(childKeep, len(key)) || childKeep || value != nil) {
			out[key] = value
		}
		if !complete {
			return out, true, false
		}
	}
	_, err := decoder.Token()
	return out, len(out) > 0 || r.charge(keep, 2), err == nil
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
// fits neither way marks the review incomplete: no head of it is sent.
func (r *oversizedReducer) text(value string, keep bool, depth int) (string, bool) {
	if keep && len(value) <= r.keep {
		r.keep -= len(value)
		return value, true
	}
	if keep {
		if reduced, ok := r.embedded(value, depth); ok {
			return reduced, true
		}
		r.incomplete = true
		return "", false
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
	sub := &oversizedReducer{src: []byte(trimmed), keep: r.keep, heads: r.heads}
	decoder := json.NewDecoder(bytes.NewReader(sub.src))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return "", false
	}
	// Its keys are classified like the payload's: a long file text in it
	// keeps a head, its command and target keys stay whole.
	var reduced any
	if token == json.Delim('{') {
		reduced, _, _ = sub.object(decoder, false, depth+1)
	} else {
		reduced, _, _ = sub.array(decoder, false, depth+1)
	}
	r.keep, r.heads = sub.keep, sub.heads
	r.duplicate = r.duplicate || sub.duplicate
	r.incomplete = r.incomplete || sub.incomplete
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
				// document's whole keys can still be judged.
				if reduced, ok := r.embedded(text, depth); ok {
					return reduced, true
				}
				r.incomplete = true
				return "", false
			}
			return r.text(text, keep, depth)
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
