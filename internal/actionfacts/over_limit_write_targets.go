// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// A native file-write tool call whose arguments go over maxArgsJSONBytes, or
// whose written text goes over maxCommandBytes, is limit-exceeded: its write
// target never becomes a path fact, so no file-write rule judges it
// (GAP-0674). The target keys of these schemas are small; only the text is
// large. OverLimitWriteTargetReduction reads such arguments once more with a
// bounded token scan that keeps every key and every small value, replaces
// only a large value of a reviewed text key with a one-byte stand-in (a
// patch envelope keeps its file headers), and analyzes that reduced call.
// Its facts name the same tool and the same targets. The text they leave out
// is never in Facts anyway: Facts keep only whether a payload is empty.

// maxOverLimitWriteArgsBytes bounds the second scan: the gateway's API
// request ceiling, so every hook body the gateway accepts can be read.
const maxOverLimitWriteArgsBytes = 1 << 20

// overLimitTextStandIn replaces a large text value. It is not empty, as the
// value it stands for is not.
const overLimitTextStandIn = "x"

// overLimitTextKeys are the reviewed write-tool argument keys whose value is
// only the text written or replaced (Claude Code, OpenCode, Copilot CLI and
// the Hermes projections). A large value of any other key is kept as it is,
// so a large target or an unknown key leaves the reduced call
// limit-exceeded or partial and the call has no reduction.
var overLimitTextKeys = map[string]struct{}{
	"content":    {},
	"old_string": {},
	"new_string": {},
	"oldString":  {},
	"newString":  {},
	"old_str":    {},
	"new_str":    {},
	"file_text":  {},
	"new_source": {},
}

// StructuredWriteTool reports whether tool names a reviewed native file
// mutation schema: a write, edit, append, create, patch, copy, move or delete
// tool.
func StructuredWriteTool(tool string) bool {
	semantics, known := lookupToolArgumentSemantics(tool)
	if !known {
		return false
	}
	switch semantics.pathShape {
	case toolPathOutput, toolPathPatch, toolPathCopy, toolPathMove:
		return true
	case toolPathTarget:
		return semantics.pathAccess == PathAccessDelete
	default:
		return false
	}
}

// ApplyPatchTool reports whether tool names the apply_patch envelope tool.
func ApplyPatchTool(tool string) bool { return isApplyPatchTool(tool) }

// LimitExceededWriteTool reports whether facts are the limit-exceeded
// analysis of a structured write tool call: one whose write targets the
// ordinary analysis could not read.
func LimitExceededWriteTool(input Input, facts Facts) bool {
	return facts.Parse.Status == StatusLimitExceeded &&
		StructuredWriteTool(input.Tool) &&
		input.Command == "" && len(input.Argv) == 0 &&
		len(bytes.TrimSpace(input.Args)) != 0
}

// OverLimitWriteTargetReduction returns the complete analysis of a
// limit-exceeded structured write tool call with its large text values
// replaced, and those reduced arguments. It reports false when the call is
// not one, when the arguments are malformed or over
// maxOverLimitWriteArgsBytes, or when the reduced call does not analyze
// complete with a write, append or delete target. The view proves only
// what the call writes: callers count a rule match on it and never a
// non-match.
func OverLimitWriteTargetReduction(input Input, facts Facts) (Facts, json.RawMessage, bool) {
	if !LimitExceededWriteTool(input, facts) ||
		len(input.Args) > maxOverLimitWriteArgsBytes || !utf8.Valid(input.Args) {
		return Facts{}, nil, false
	}
	reduced, ok := reduceOverLimitWriteArgs(input.Args, isApplyPatchTool(input.Tool))
	if !ok || len(reduced) > maxArgsJSONBytes {
		return Facts{}, nil, false
	}
	reducedInput := input
	reducedInput.Args = reduced
	view := Analyze(reducedInput)
	if !view.Authoritative() || !factsMutateAPath(view) {
		return Facts{}, nil, false
	}
	return view, reduced, true
}

func factsMutateAPath(facts Facts) bool {
	for _, path := range facts.Paths {
		switch path.Access {
		case PathAccessWrite, PathAccessAppend, PathAccessDelete:
			return true
		}
	}
	return false
}

// overLimitArgsReducer copies one JSON object token by token. It holds the
// limits of validateJSONWithStringLimit (depth, members, key size, unique
// keys) and keeps no value it replaces.
type overLimitArgsReducer struct {
	decoder   *json.Decoder
	out       bytes.Buffer
	members   int
	patchTool bool
}

func reduceOverLimitWriteArgs(raw json.RawMessage, patchTool bool) (json.RawMessage, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	reducer := &overLimitArgsReducer{decoder: json.NewDecoder(bytes.NewReader(trimmed)), patchTool: patchTool}
	reducer.decoder.UseNumber()
	if !reducer.value(0, "") {
		return nil, false
	}
	if _, err := reducer.decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, false
	}
	return json.RawMessage(reducer.out.Bytes()), true
}

// value copies the next JSON value; key is the object key it belongs to
// ("" for an array element).
func (r *overLimitArgsReducer) value(depth int, key string) bool {
	if depth > maxJSONDepth {
		return false
	}
	token, err := r.decoder.Token()
	if err != nil {
		return false
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			return r.object(depth)
		case '[':
			return r.array(depth)
		default:
			return false
		}
	case string:
		text, ok := r.reduceString(key, token)
		return ok && r.writeString(text)
	case json.Number:
		r.out.WriteString(token.String())
	case bool:
		if token {
			r.out.WriteString("true")
		} else {
			r.out.WriteString("false")
		}
	case nil:
		r.out.WriteString("null")
	default:
		return false
	}
	return true
}

func (r *overLimitArgsReducer) object(depth int) bool {
	r.out.WriteByte('{')
	seen := make(map[string]struct{})
	for r.decoder.More() {
		token, err := r.decoder.Token()
		if err != nil {
			return false
		}
		key, ok := token.(string)
		if !ok || len(key) > maxScalarBytes {
			return false
		}
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
		r.members++
		if r.members > maxJSONMembers {
			return false
		}
		if len(seen) > 1 {
			r.out.WriteByte(',')
		}
		if !r.writeString(key) {
			return false
		}
		r.out.WriteByte(':')
		if !r.value(depth+1, key) {
			return false
		}
	}
	end, err := r.decoder.Token()
	if err != nil || end != json.Delim('}') {
		return false
	}
	r.out.WriteByte('}')
	return true
}

func (r *overLimitArgsReducer) array(depth int) bool {
	r.out.WriteByte('[')
	for index := 0; r.decoder.More(); index++ {
		r.members++
		if r.members > maxJSONMembers {
			return false
		}
		if index > 0 {
			r.out.WriteByte(',')
		}
		if !r.value(depth+1, "") {
			return false
		}
	}
	end, err := r.decoder.Token()
	if err != nil || end != json.Delim(']') {
		return false
	}
	r.out.WriteByte(']')
	return true
}

func (r *overLimitArgsReducer) writeString(text string) bool {
	encoded, err := json.Marshal(text)
	if err != nil {
		return false
	}
	r.out.Write(encoded)
	return true
}

// reduceString keeps a small value, compacts the envelope of a patch tool's
// patch key and stands in for the large value of a text key. Any other
// large value is kept, so the reduced call stays limit-exceeded.
func (r *overLimitArgsReducer) reduceString(key, text string) (string, bool) {
	if len(text) <= maxScalarBytes {
		return text, true
	}
	if r.patchTool && (isPatchInputField(key) || isPatchEnvelopeField(key, text)) {
		return compactPatchEnvelope(text)
	}
	if _, ok := overLimitTextKeys[key]; ok {
		return overLimitTextStandIn, true
	}
	return text, true
}

// compactPatchEnvelope keeps every line of a patch envelope except the
// repeats of a hunk line class: of consecutive "+", "-", " " or "@@" lines it
// keeps one marker. parsePatchEnvelope reads each line only by that class,
// and a repeat of a class leaves its state as the first line left it, so
// the compact envelope parses to the same directives, paths and accesses
// (or fails the same way).
func compactPatchEnvelope(text string) (string, bool) {
	normalized := strings.ReplaceAll(text, "\r\n", "\n")
	if strings.ContainsRune(normalized, '\r') {
		return "", false
	}
	lines := strings.Split(normalized, "\n")
	kept := make([]string, 0, 16)
	previous := ""
	for _, line := range lines {
		marker := ""
		switch {
		case strings.HasPrefix(line, "@@"):
			marker = "@@"
		case strings.HasPrefix(line, "+"), strings.HasPrefix(line, "-"), strings.HasPrefix(line, " "):
			marker = line[:1]
		}
		if marker == "" {
			kept = append(kept, line)
			previous = ""
			continue
		}
		if marker == previous {
			continue
		}
		kept = append(kept, marker)
		previous = marker
	}
	return strings.Join(kept, "\n"), true
}
