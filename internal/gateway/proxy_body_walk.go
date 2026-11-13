// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
)

// Inspect by default (substrate-1 GAP-0189, GAP-0196). The guardrail proxy
// does not know every field every provider adds to a request or a reply, so
// it does not look for the fields that carry text: it hands the guardrail
// every string of the body, except the values of an explicit list of fields
// that are known not to be text (ids, model names, roles, types, enums, opaque
// media) and the echo of the request inside a reply. A field a provider adds
// tomorrow is inspected until someone proves it is not text.
//
// The body is read into a tree that keeps repeated keys, so every value of a
// repeated or case-folded key is read whichever one the provider keeps.

const (
	walkMaxNodes = 400000
	walkMaxDepth = 64
)

var (
	errWalkTooBig  = errors.New("the body has too many values to inspect")
	errWalkTooDeep = errors.New("the body is nested too deeply to inspect")
)

// jnode is a JSON value. Object keys keep their order and repeats.
type jnode struct {
	kind byte // 'o' object, 'a' array, 's' string, 'v' number, boolean or null
	s    string
	keys []string
	kids []*jnode
}

type treeParser struct {
	dec   *json.Decoder
	nodes int
}

// parseJSONTree parses exactly one JSON value.
func parseJSONTree(b []byte) (*jnode, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	p := &treeParser{dec: dec}
	n, err := p.value(0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("the body has data after the JSON value")
	}
	return n, nil
}

func (p *treeParser) value(depth int) (*jnode, error) {
	if depth > walkMaxDepth {
		return nil, errWalkTooDeep
	}
	p.nodes++
	if p.nodes > walkMaxNodes {
		return nil, errWalkTooBig
	}
	t, err := p.dec.Token()
	if err != nil {
		return nil, err
	}
	switch v := t.(type) {
	case json.Delim:
		n := &jnode{kind: 'a'}
		if v == '{' {
			n.kind = 'o'
		}
		for p.dec.More() {
			if n.kind == 'o' {
				kt, err := p.dec.Token()
				if err != nil {
					return nil, err
				}
				k, _ := kt.(string)
				n.keys = append(n.keys, k)
			}
			c, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			n.kids = append(n.kids, c)
		}
		if _, err := p.dec.Token(); err != nil {
			return nil, err
		}
		return n, nil
	case string:
		return &jnode{kind: 's', s: v}, nil
	case json.Number:
		return &jnode{kind: 'v', s: v.String()}, nil
	case bool:
		if v {
			return &jnode{kind: 'v', s: "true"}, nil
		}
		return &jnode{kind: 'v', s: "false"}, nil
	}
	return &jnode{kind: 'v', s: "null"}, nil
}

// get is the value of key as encoding/json reads it: keys match with simple
// case folding and the last of several wins.
func (n *jnode) get(key string) *jnode {
	if n == nil || n.kind != 'o' {
		return nil
	}
	var out *jnode
	for i, k := range n.keys {
		if strings.EqualFold(k, key) {
			out = n.kids[i]
		}
	}
	return out
}

func (n *jnode) str(key string) string {
	if c := n.get(key); c != nil && c.kind == 's' {
		return c.s
	}
	return ""
}

func walkJSONString(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

func (n *jnode) marshal(b *strings.Builder) {
	switch n.kind {
	case 'o':
		b.WriteByte('{')
		for i, k := range n.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(walkJSONString(k))
			b.WriteByte(':')
			n.kids[i].marshal(b)
		}
		b.WriteByte('}')
	case 'a':
		b.WriteByte('[')
		for i, c := range n.kids {
			if i > 0 {
				b.WriteByte(',')
			}
			c.marshal(b)
		}
		b.WriteByte(']')
	case 's':
		b.WriteString(walkJSONString(n.s))
	default:
		b.WriteString(n.s)
	}
}

func (n *jnode) json() string {
	var b strings.Builder
	n.marshal(&b)
	return b.String()
}

// ---- what is not text -------------------------------------------------------

// normKey lowers a key and drops the separators, so stop_reason, stopReason
// and stop-reason are one key.
func normKey(k string) string {
	var b strings.Builder
	for _, r := range k {
		if r == '_' || r == '-' {
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

func keySet(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[normKey(k)] = true
	}
	return m
}

// walkSkipScalar are the fields whose string value is an identifier, an enum
// or a version, never text a model reads.
var walkSkipScalar = keySet("id", "call_id", "tool_call_id", "tool_use_id", "item_id", "response_id", "previous_response_id",
	"conversation_id", "session_id", "request_id", "approval_request_id", "model", "model_version", "role", "type", "status",
	"object", "finish_reason", "stop_reason", "index", "output_index", "content_index", "summary_index", "sequence_number",
	"created", "created_at", "completed_at", "system_fingerprint", "service_tier", "encrypted_content", "signature",
	"thought_signature", "media_type", "mime_type", "detail", "voice", "size", "quality", "stream", "version",
	"anthropic_version", "anthropic_beta", "obfuscation", "done_reason", "user")

// walkSkipSubtree are the fields whose whole value is configuration, counts
// or bookkeeping.
var walkSkipSubtree = keySet("usage", "usage_metadata", "logprobs", "metadata", "request_metadata", "stream_options",
	"generation_config", "inference_config", "safety_settings", "safety_ratings", "performance_config", "guardrail_config",
	"stop", "stop_sequences", "include", "modalities", "response_modalities", "tool_choice", "options", "timings",
	"total_duration", "load_duration", "prompt_eval_count", "eval_count", "eval_duration")

// replyEchoKeys are the request fields a reply may repeat.
var replyEchoKeys = keySet("instructions", "tools", "tool_choice", "input", "parallel_tool_calls")

// opaqueString reports a value that is binary media, not text: a data URL of
// a non-text type, or a long base64 string in a field that carries bytes.
func opaqueString(key, s string) bool {
	if strings.HasPrefix(s, "data:") {
		if i := strings.IndexByte(s, ','); i > 0 {
			mt := s[5:i]
			return !strings.HasPrefix(mt, "text/") && !strings.HasPrefix(mt, "application/json")
		}
	}
	switch normKey(key) {
	case "data", "bytes", "b64json", "filedata", "blob", "audio", "image":
		if len(s) >= 64 {
			for i := 0; i < len(s); i++ {
				c := s[i]
				if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '+' && c != '/' && c != '=' && c != '-' && c != '_' {
					return false
				}
			}
			return true
		}
	}
	return false
}

// foldCanon is the smallest rune of every rune's simple-folding orbit, so
// keys that encoding/json treats as one are one.
func foldCanon(s string) string {
	var b strings.Builder
	for _, r := range s {
		m := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < m {
				m = f
			}
		}
		b.WriteRune(m)
	}
	return b.String()
}

func canonSet(keys ...string) map[string]string {
	m := make(map[string]string, len(keys))
	for _, k := range keys {
		m[foldCanon(k)] = k
	}
	return m
}

// walkStructuralKeys are the keys that decide how a body is read; a repeated
// or differently spelled one makes the body ambiguous.
var walkStructuralKeys = canonSet("role", "type", "content", "text", "messages", "input", "output", "parts", "instructions",
	"system", "contents", "model", "tools", "name", "arguments", "prompt", "systemInstruction", "system_instruction", "toolUse",
	"toolResult", "functionCall", "functionResponse", "tool_calls", "function", "delta", "choices", "candidates")

// ---- the walker ---------------------------------------------------------------

// replyCallKeys are the fields that hold a tool call in a reply.
var replyCallKeys = keySet("tool_calls", "function_call", "tool_use", "toolUse", "function_calls", "functionCall")

func isCallType(t string) bool {
	switch t {
	case "tool_use", "server_tool_use", "mcp_tool_use":
		return true
	}
	return strings.HasSuffix(t, "_call")
}

// textWalker collects the inspectable strings of a body.
type textWalker struct {
	segs      []string
	ambiguous string // why the body can be read two ways, if it can
	reply     bool
	stream    bool // reply event of a stream: calls under delta, item and content_block belong to sseToolCalls
	skipCalls bool
	calls     []sseToolCall
}

func (w *textWalker) add(s string) {
	if strings.TrimSpace(s) != "" {
		w.segs = append(w.segs, s)
	}
}

func (w *textWalker) flag(why string) {
	if w.ambiguous == "" {
		w.ambiguous = why
	}
}

// checkKeys flags a repeated structural key in an object, and a role or type
// spelled another way.
func (w *textWalker) checkKeys(n *jnode) {
	seen := map[string]string{}
	for _, k := range n.keys {
		if len(k) > 32 {
			continue
		}
		c := foldCanon(k)
		name, ok := walkStructuralKeys[c]
		if !ok {
			continue
		}
		if prev, dup := seen[c]; dup {
			if prev == k {
				w.flag("the body repeats the key " + name)
			} else {
				w.flag("the body spells the key " + name + " two ways")
			}
		}
		seen[c] = k
		if (name == "role" || name == "type") && k != name {
			w.flag("the body spells the key " + name + " another way")
		}
	}
}

func (w *textWalker) walk(n *jnode, key string, depth int) {
	switch n.kind {
	case 's':
		nk := normKey(key)
		if walkSkipScalar[nk] || opaqueString(key, n.s) {
			return
		}
		w.add(n.s)
	case 'a':
		if w.reply && replyCallKeys[normKey(key)] {
			for _, c := range n.kids {
				if c.kind == 'o' {
					w.callObject(c, key)
				} else {
					w.walk(c, key, depth+1)
				}
			}
			return
		}
		for _, c := range n.kids {
			w.walk(c, key, depth+1)
		}
	case 'o':
		if w.reply {
			if replyCallKeys[normKey(key)] || isCallType(n.str("type")) {
				w.callObject(n, key)
				return
			}
		} else {
			w.checkKeys(n)
		}
		for i, k := range n.keys {
			nk := normKey(k)
			if walkSkipSubtree[nk] {
				continue
			}
			if w.reply && (depth == 0 || (depth == 1 && normKey(key) == "response")) && replyEchoKeys[nk] {
				continue
			}
			if w.stream && (nk == "delta" || nk == "item" || nk == "contentblock") && !w.skipCalls {
				w.skipCalls = true
				w.walk(n.kids[i], k, depth+1)
				w.skipCalls = false
				continue
			}
			w.walk(n.kids[i], k, depth+1)
		}
	}
}

// callObjectOwn are the fields of a tool call that the tool-call rules read
// (or that identify it); every other string of a call (an mcp_call output, an
// error, a result) is reply text.
var callObjectOwn = keySet("name", "tool_name", "function", "arguments", "input", "args", "parameters", "action", "code", "id", "call_id", "type", "index")

// callObject records the tool call n (unless the stream state machine does)
// and reads the rest of its strings as text.
func (w *textWalker) callObject(n *jnode, key string) {
	if n.kind == 'o' {
		for i, k := range n.keys {
			if nk := normKey(k); !callObjectOwn[nk] && !walkSkipSubtree[nk] {
				w.walk(n.kids[i], k, 2)
			}
		}
	}
	if w.skipCalls {
		return
	}
	fn := n.get("function")
	typ := n.str("type")
	name := firstNonEmpty(n.str("name"), fn.str("name"), n.str("tool_name"), n.str("toolName"))
	var args *jnode
	for _, c := range []*jnode{n.get("arguments"), n.get("input"), n.get("args"), fn.get("arguments"), n.get("parameters"), n.get("action"), n.get("code")} {
		if c != nil {
			args = c
			break
		}
	}
	if name == "" {
		name = firstNonEmpty(typ, key)
		if typ == "local_shell_call" {
			name = "local_shell"
		}
	}
	a := ""
	switch {
	case args == nil:
		a = n.json()
	case args.kind == 's':
		a = args.s
	default:
		a = args.json()
	}
	c := sseToolCall{ID: firstNonEmpty(n.str("call_id"), n.str("id")), Type: "function"}
	c.Function.Name, c.Function.Arguments = name, a
	w.calls = append(w.calls, c)
}

// ---- requests -------------------------------------------------------------------

// walkTurns reads a list of turns (chat messages, Responses input items,
// Anthropic or Converse messages, Gemini contents). System and developer
// turns are always read. The turns before the model's last turn are history
// an earlier request already carried and the proxy decided then; reading
// them again would make one blocked prompt block every later request of the
// session. The model's own last turn is skipped too, unless it is the final
// item (a prefill the client wrote).
func (w *textWalker) walkTurns(list *jnode) {
	last := -1
	for i, it := range list.kids {
		if it.kind != 'o' {
			continue
		}
		w.checkKeys(it)
		role := strings.ToLower(it.str("role"))
		typ := it.str("type")
		if role == "assistant" || role == "model" || typ == "reasoning" || isCallType(typ) {
			last = i
		}
	}
	for i, it := range list.kids {
		if it.kind == 'o' {
			role := strings.ToLower(it.str("role"))
			if role != "system" && role != "developer" && (i < last || (i == last && i != len(list.kids)-1)) {
				continue
			}
		}
		w.walk(it, "", 1)
	}
}

// passthroughPromptKeys are the top-level request fields that carry
// prompt-side text or decide the call.
var passthroughPromptKeys = map[string]bool{"model": true, "input": true, "messages": true, "instructions": true,
	"system": true, "prompt": true, "contents": true, "systemInstruction": true, "system_instruction": true, "tools": true}

// passthroughSidePrompt is every inspectable text of a request body, and why
// the body cannot be read with confidence, if it cannot.
type passthroughSidePrompt struct {
	// Text is Segments joined by a line feed.
	Text     string
	Segments []string
	// Unreadable is why the body takes the fail mode ("" when it is read).
	Unreadable string
}

// passthroughPrompt reads body; see passthroughPromptFor.
func passthroughPrompt(body []byte) passthroughSidePrompt {
	return passthroughPromptFor(body, false)
}

// passthroughPromptFor reads every inspectable text of a request body once,
// for every wire shape the passthrough serves. A body that is JSON on its
// face (it starts with { or [, or jsonHint says so) but not valid JSON, a
// body that carries no text, and a body whose keys can be read two ways take
// the fail mode; the text it does carry is still returned, every value of a
// repeated key included. A body that is not JSON is not a model request.
func passthroughPromptFor(body []byte, jsonHint bool) passthroughSidePrompt {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return passthroughSidePrompt{}
	}
	if trimmed[0] != '{' && trimmed[0] != '[' && !jsonHint {
		return passthroughSidePrompt{}
	}
	root, err := parseJSONTree(trimmed)
	if err != nil {
		return passthroughSidePrompt{Unreadable: "the body is not valid JSON: " + err.Error()}
	}
	if root.kind != 'o' {
		return passthroughSidePrompt{}
	}
	w := &textWalker{}
	seen := map[string]bool{}
	prompt := false
	for _, k := range root.keys {
		f := foldPromptKey(k)
		if f == "" {
			continue
		}
		prompt = prompt || (f != "model" && f != "tools")
		if f != k {
			// Another spelling of a field (Model, meſſages): some decoders
			// take it for the field and others do not.
			w.flag("the body spells the key " + f + " another way")
		}
		if seen[f] {
			// Parsers disagree on which value wins (Go keeps the last and
			// matches keys case-insensitively); both are read here.
			w.flag("the body repeats the key " + f)
		}
		seen[f] = true
	}
	w.checkKeys(root)
	for i, k := range root.keys {
		c := root.kids[i]
		switch f := foldPromptKey(k); {
		case c.kind == 'a' && (f == "messages" || f == "input" || f == "contents"):
			w.walkTurns(c)
		default:
			if nk := normKey(k); walkSkipSubtree[nk] {
				continue
			}
			w.walk(c, k, 1)
		}
	}
	side := passthroughSidePrompt{Segments: w.segs, Text: strings.Join(w.segs, "\n"), Unreadable: w.ambiguous}
	if len(w.segs) == 0 && prompt && side.Unreadable == "" {
		side.Unreadable = "the body carries no prompt text"
	}
	return side
}

// ---- replies ---------------------------------------------------------------------

// replyScan is the inspectable content of one reply (or one stream event).
type replyScan struct {
	// Type is the "type" of a stream event.
	Type     string
	Segments []string
	Calls    []sseToolCall
}

// scanReplyJSON reads one JSON reply or stream event. With stream set, the
// tool calls under delta, item and content_block are left to the stream
// state machine (sseToolCalls), which assembles them across events.
func scanReplyJSON(data []byte, stream bool) (replyScan, error) {
	root, err := parseJSONTree(bytes.TrimSpace(data))
	if err != nil {
		return replyScan{}, err
	}
	w := &textWalker{reply: true, stream: stream}
	w.walk(root, "", 0)
	return replyScan{Type: root.str("type"), Segments: w.segs, Calls: w.calls}, nil
}

// scanReplyBody reads a buffered reply: one JSON value, or newline-delimited
// JSON (Ollama streams). ok is false for a body that is neither.
func scanReplyBody(data []byte) (replyScan, bool) {
	if sc, err := scanReplyJSON(data, false); err == nil {
		return sc, true
	}
	var out replyScan
	lines := bytes.Split(data, []byte("\n"))
	n := 0
	for _, ln := range lines {
		ln = bytes.TrimSpace(ln)
		if len(ln) == 0 {
			continue
		}
		sc, err := scanReplyJSON(ln, false)
		if err != nil {
			return replyScan{}, false
		}
		n++
		out.Segments = append(out.Segments, sc.Segments...)
		out.Calls = append(out.Calls, sc.Calls...)
	}
	return out, n > 0
}

// joinPromptSegments adds the segments of a body to the text the proxy
// already inspects (the user turn), once: a segment the text contains, or
// that is part of skip (the heartbeat text), is left out.
func joinPromptSegments(inspect string, segs []string, skip string) string {
	budget := 64 << 20
	seen := map[string]bool{}
	var b strings.Builder
	b.WriteString(inspect)
	for _, s := range segs {
		if seen[s] || (skip != "" && strings.Contains(skip, s)) {
			continue
		}
		seen[s] = true
		if budget > len(inspect) {
			budget -= len(inspect) + 1
			if strings.Contains(inspect, s) {
				continue
			}
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(s)
	}
	return b.String()
}
