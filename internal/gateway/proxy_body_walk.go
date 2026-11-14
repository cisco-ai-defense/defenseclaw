// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
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

const walkMaxDepth = 64

var errWalkTooDeep = errors.New("the body is nested too deeply to inspect")

// walkLimit is the value cap of a body: guardrail.max_body_values, or its
// default when that is unset.
func walkLimit(max int) int {
	if max <= 0 {
		return config.DefaultMaxBodyValues
	}
	return max
}

// errTooManyValues is a body with more values than the cap; its message
// names the cap and the key that raises it.
type errTooManyValues struct{ max int }

func (e *errTooManyValues) Error() string {
	return fmt.Sprintf("the body has more than %d values to inspect (the limit is guardrail.max_body_values)", e.max)
}

func errWalkTooBig(max int) error { return &errTooManyValues{max} }

// replyRefusalReason is the reason a refused reply shows the agent: the
// generic one, plus the cap and the key that raises it when the reply was
// refused for having more values than guardrail.max_body_values.
func replyRefusalReason(why string) string {
	if strings.Contains(why, "guardrail.max_body_values") {
		return "the provider reply could not be inspected: " + why
	}
	return "the provider reply could not be inspected"
}

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
	max   int
}

// parseJSONTree parses exactly one JSON value of at most max values (0: the
// default of guardrail.max_body_values).
func parseJSONTree(b []byte, max int) (*jnode, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	p := &treeParser{dec: dec, max: walkLimit(max)}
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
	if p.nodes > p.max {
		return nil, errWalkTooBig(p.max)
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

// Binary media is skipped by where it sits, never by what the value looks
// like (GAP-0238). A string is skipped only when it is in a position where
// the wire format puts encoded bytes (an image, audio or document field) and
// it is encoded bytes: a base64 data URL of a non-text type, or a long
// base64 string. The same shape anywhere else (system text, a tool result, a
// reply, a tool call's input) is text and is inspected. Inside a tool call's
// or tool result's free-form payload nothing is skipped at all.

// mediaURLKeys are the fields that hold a URL or data URL of a media file.
var mediaURLKeys = keySet("image_url", "video_url", "audio_url", "file_url")

// mediaURLParents are the objects whose "url" is a media URL.
var mediaURLParents = keySet("image_url", "video_url", "audio_url", "file_url", "image", "video", "audio")

// mediaDataParents are the objects whose "data" holds encoded bytes: the
// OpenAI input_audio and reply audio, Gemini inlineData.
var mediaDataParents = keySet("input_audio", "inline_data", "audio")

// mediaBytesParents are the objects whose "bytes" holds encoded bytes: the
// source of a Converse image, document or video.
var mediaBytesParents = keySet("source")

// textMediaType reports a media type that is text a model reads.
func textMediaType(mt string) bool {
	mt = strings.ToLower(strings.TrimSpace(mt))
	return mt == "" || !strings.Contains(mt, "/") || strings.HasPrefix(mt, "text/") ||
		mt == "application/json" || mt == "application/xml" || mt == "application/javascript" ||
		mt == "application/x-www-form-urlencoded" || strings.HasSuffix(mt, "+json") || strings.HasSuffix(mt, "+xml")
}

// encodedBytes reports a value that is encoded binary: a base64 data URL of
// a non-text media type, or a base64 string of at least 64 characters.
func encodedBytes(s string) bool {
	if strings.HasPrefix(s, "data:") {
		i := strings.IndexByte(s, ',')
		if i < 0 {
			return false
		}
		head := strings.ToLower(s[5:i])
		mt, params, _ := strings.Cut(head, ";")
		return !textMediaType(mt) && strings.Contains(";"+params+";", ";base64;")
	}
	if len(s) < 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '+' && c != '/' && c != '=' && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// mediaValue reports a string that is binary media at its position: key is
// the field, w.cur the object that holds it and w.curKey the field that
// object sits under.
func (w *textWalker) mediaValue(key, s string) bool {
	if w.payload > 0 {
		return false
	}
	nk, ck := normKey(key), normKey(w.curKey)
	typ := ""
	if w.cur != nil {
		typ = w.cur.str("type")
	}
	var pos bool
	switch nk {
	case "imageurl", "videourl", "audiourl", "fileurl":
		pos = mediaURLKeys[nk]
	case "url":
		pos = mediaURLParents[ck]
	case "filedata", "b64json", "partialimageb64", "images":
		pos = true
	case "data":
		pos = (ck == "source" && typ == "base64") || mediaDataParents[ck]
	case "bytes":
		pos = mediaBytesParents[ck]
	case "result":
		pos = typ == "image_generation_call"
	case "delta":
		pos = typ == "response.audio.delta" || typ == "response.output_audio.delta"
	}
	return pos && encodedBytes(s)
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
	"toolResult", "functionCall", "functionResponse", "tool_calls", "function", "delta", "choices", "candidates",
	"content_block", "item", "function_call", "tool_use", "partial_json", "finish_reason", "stop_reason", "index", "output_index", "id", "call_id", "item_id", "response", "message")

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
	segs []string
	// hist collects the strings of the history turns (walkTurns) while
	// history > 0: inspected once per actor or session (proxy_history_seen.go).
	hist    []string
	history int
	// user counts the user turns the walker is inside and result the tool
	// calls and results: the canonical OpenClaw probes are left out of user
	// text only (GAP-0251), the one place OpenClaw sends them; probe is set
	// when a user text held one.
	user   int
	result int
	probe  bool
	// redact, when set, names the refused history segments to remove
	// (redactRefusedHistory): a turn string whose segment it holds is
	// replaced in the tree; turn is the index of the turn being read
	// (-1 outside the turn lists).
	redact     map[historyHash]historyRefusal
	redactions []historyRedaction
	turn       int
	// curTurn is set while the walker reads a current-scope turn that is
	// not system or developer text; its strings also go into turnSegs, the
	// candidates a refusal is attributed to (GAP-0257).
	curTurn   bool
	turnSegs  []string
	ambiguous string // why the body can be read two ways, if it can
	reply     bool
	stream    bool // reply event of a stream: calls under delta, item and content_block belong to sseToolCalls
	skipCalls bool
	calls     []sseToolCall
	// cur is the object whose value is being read and curKey the field it
	// sits under (media positions); payload counts the free-form payloads
	// (tool input and results) the walker is inside.
	cur     *jnode
	curKey  string
	payload int
}

// callHolderKeys are the fields whose object is a tool call or a tool
// result, and payloadKeys the fields of such an object that hold free-form
// data: no field name inside them is a protocol field. A "json" field
// (Converse toolResult content) is free-form wherever it is.
var callHolderKeys = keySet("toolUse", "toolResult", "functionCall", "functionResponse", "function", "function_call", "tool_use")
var payloadKeys = keySet("input", "arguments", "args", "response", "output", "result")

func isResultType(t string) bool {
	switch t {
	case "tool_result", "function_call_output", "computer_call_output", "mcp_tool_result":
		return true
	}
	return strings.HasSuffix(t, "_call_output")
}

// add collects the text s and returns the segment it read ("" for none).
func (w *textWalker) add(s string) string {
	if w.user > 0 && w.result == 0 && w.payload == 0 {
		// The heartbeat and session-startup prompts are left out as the exact
		// canonical sentences only (guardrail_probe.go); the rest of the text
		// is inspected. A tool result, a system, developer or instructions
		// text keeps them: OpenClaw never sends them there (GAP-0251).
		if rest, ok := stripCanonicalProbes(s); ok {
			w.probe, s = true, rest
		}
	}
	if strings.TrimSpace(s) == "" {
		return ""
	}
	if w.history > 0 {
		w.hist = append(w.hist, s)
		return s
	}
	w.segs = append(w.segs, s)
	if w.curTurn {
		w.turnSegs = append(w.turnSegs, s)
	}
	return s
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
		if w.payload == 0 && (walkSkipScalar[normKey(key)] || w.mediaValue(key, n.s)) {
			return
		}
		if seg := w.add(n.s); seg != "" && w.redact != nil && w.turn >= 0 {
			if rf, ok := w.redact[historyHashOf(seg)]; ok {
				n.s = historyRedactedText
				w.redactions = append(w.redactions, historyRedaction{Turn: w.turn, Rule: rf.rule})
			}
		}
	case 'a':
		if w.reply && replyCallKeys[normKey(key)] {
			for _, c := range n.kids {
				if c.kind == 'o' {
					if w.payload == 0 {
						w.checkKeys(c)
					}
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
		if w.payload == 0 {
			// Replies too: a repeated or differently spelled structural key
			// is read one way here and another by the agent (GAP-0240).
			w.checkKeys(n)
		}
		if w.reply {
			if replyCallKeys[normKey(key)] || isCallType(n.str("type")) {
				w.callObject(n, key)
				return
			}
		}
		prevCur, prevKey := w.cur, w.curKey
		w.cur, w.curKey = n, key
		defer func() { w.cur, w.curKey = prevCur, prevKey }()
		typ := n.str("type")
		holder := isCallType(typ) || isResultType(typ) || callHolderKeys[normKey(key)]
		if holder {
			w.result++
			defer func() { w.result-- }()
		}
		for i, k := range n.keys {
			nk := normKey(k)
			if w.payload == 0 && walkSkipSubtree[nk] {
				continue
			}
			if w.reply && (depth == 0 || (depth == 1 && normKey(key) == "response")) && replyEchoKeys[nk] {
				continue
			}
			enter := w.payload == 0 && ((holder && payloadKeys[nk]) || nk == "json")
			if enter {
				w.payload++
			}
			if w.stream && (nk == "delta" || nk == "item" || nk == "contentblock") && !w.skipCalls {
				w.skipCalls = true
				w.walk(n.kids[i], k, depth+1)
				w.skipCalls = false
			} else {
				w.walk(n.kids[i], k, depth+1)
			}
			if enter {
				w.payload--
			}
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
// turns, the turns after the model's last turn and a final model turn (a
// prefill the client wrote) are the current scope: read into segs and
// inspected on every request. The other turns, the model's last one
// included, are history: the client can write any of them, so they are read
// too, into hist, and the proxy inspects each history segment once per actor
// or session (substrate-1 GAP-0244, proxy_history_seen.go).
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
		hist, user, sys := false, false, false
		if it.kind == 'o' {
			role := strings.ToLower(it.str("role"))
			sys = role == "system" || role == "developer"
			hist = !sys && (i < last || (i == last && i != len(list.kids)-1))
			user = role == "user"
		}
		if hist {
			w.history++
		}
		if user {
			w.user++
		}
		prevTurn, prevCur := w.turn, w.curTurn
		w.turn, w.curTurn = i, !hist && !sys
		w.walk(it, "", 1)
		w.turn, w.curTurn = prevTurn, prevCur
		if user {
			w.user--
		}
		if hist {
			w.history--
		}
	}
}

// passthroughPromptKeys are the top-level request fields that carry
// prompt-side text or decide the call.
var passthroughPromptKeys = map[string]bool{"model": true, "input": true, "messages": true, "instructions": true,
	"system": true, "prompt": true, "contents": true, "systemInstruction": true, "system_instruction": true, "tools": true}

// passthroughSidePrompt is every inspectable text of a request body, and why
// the body cannot be read with confidence, if it cannot.
type passthroughSidePrompt struct {
	Segments []string
	// History is the text of the history turns (walkTurns), apart from
	// Segments: the proxy inspects what this actor or session has not sent
	// before (historySeen).
	History []string
	// Turn is the strings of Segments that sit in the current turns (not
	// system or developer text, not instructions or tool definitions): the
	// candidates a refusal is attributed to (refusedSegments, GAP-0257).
	Turn []string
	// Unreadable is why the body takes the fail mode ("" when it is read).
	Unreadable string
}

// passthroughPromptFor reads every inspectable text of a request body once,
// for every wire shape the passthrough serves. A body that is JSON on its
// face (it starts with { or [, or jsonHint says so) but not valid JSON, a
// body that carries no text, and a body whose keys can be read two ways take
// the fail mode; the text it does carry is still returned, every value of a
// repeated key included. A body that is not JSON is not a model request.
func passthroughPromptFor(body []byte, jsonHint bool, max int) passthroughSidePrompt {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return passthroughSidePrompt{}
	}
	if trimmed[0] != '{' && trimmed[0] != '[' && !jsonHint {
		return plainBodyPrompt(body)
	}
	root, err := parseJSONTree(trimmed, max)
	if err != nil {
		var big *errTooManyValues
		if errors.As(err, &big) {
			return passthroughSidePrompt{Unreadable: err.Error()}
		}
		return passthroughSidePrompt{Unreadable: "the body is not valid JSON: " + err.Error()}
	}
	if root.kind != 'o' {
		// A JSON array or scalar at the root is no model request the proxy
		// knows, but its strings are still read: they are text a provider
		// may take for a prompt. No text at all takes the fail mode.
		w := &textWalker{}
		w.walk(root, "", 1)
		side := passthroughSidePrompt{Segments: w.segs, Unreadable: w.ambiguous}
		if len(w.segs) == 0 && side.Unreadable == "" {
			side.Unreadable = "the JSON body is not an object and carries no text"
		}
		return side
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
	w.walkRequest(root)
	side := passthroughSidePrompt{Segments: w.segs, History: w.hist, Turn: w.turnSegs, Unreadable: w.ambiguous}
	// A body whose only text is a probe carries a prompt: the probe.
	if len(w.segs) == 0 && !w.probe && prompt && side.Unreadable == "" {
		side.Unreadable = "the body carries no prompt text"
	}
	return side
}

// walkRequest reads the fields of a request object: the turn lists by turn
// (walkTurns), every other field but the bookkeeping ones as text.
func (w *textWalker) walkRequest(root *jnode) {
	w.turn = -1
	for i, k := range root.keys {
		c := root.kids[i]
		switch f := foldPromptKey(k); {
		case c.kind == 'a' && (f == "messages" || f == "input" || f == "contents"):
			w.walkTurns(c)
		default:
			if nk := normKey(k); walkSkipSubtree[nk] {
				continue
			}
			// A Responses input string and a completion prompt (a string or a
			// list of strings) are the user turn.
			user := (f == "input" && c.kind == 's') || (f == "prompt" && (c.kind == 's' || c.kind == 'a'))
			if user {
				w.user++
				w.curTurn = true
			}
			w.walk(c, k, 1)
			if user {
				w.user--
				w.curTurn = false
			}
		}
	}
}

// historyRedaction is one refused turn string the proxy removed from a
// request: the index of its turn and the rule that refused it.
type historyRedaction struct {
	Turn int
	Rule string
}

// redactRefusedHistory rewrites a JSON request body: every turn string whose
// segment is in refused (the history segments of requests the proxy
// refused, GAP-0254) is replaced by historyRedactedText. The turns, their
// roles and order, and every other field stay. ok is false when nothing was
// replaced (the body is not a JSON object, or holds none of them): the
// caller then refuses the request.
func redactRefusedHistory(body []byte, max int, refused map[historyHash]historyRefusal) (out []byte, reds []historyRedaction, ok bool) {
	trimmed := bytes.TrimSpace(body)
	if len(refused) == 0 || len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, nil, false
	}
	root, err := parseJSONTree(trimmed, max)
	if err != nil || root.kind != 'o' {
		return nil, nil, false
	}
	w := &textWalker{redact: refused}
	w.walkRequest(root)
	if len(w.redactions) == 0 {
		return nil, nil, false
	}
	return []byte(root.json()), w.redactions, true
}

// passthroughPromptForRequest reads a request body by its content type: a
// multipart or a form body by its text fields (GAP-0196), anything else as
// passthroughPromptFor does.
func passthroughPromptForRequest(body []byte, contentType string, jsonHint bool, max int) passthroughSidePrompt {
	if mt, params, err := mime.ParseMediaType(contentType); err == nil {
		switch {
		case strings.HasPrefix(mt, "multipart/"):
			return multipartPrompt(body, params["boundary"])
		case mt == "application/x-www-form-urlencoded":
			return formPrompt(body)
		}
	}
	return passthroughPromptFor(body, jsonHint, max)
}

// plainBodyPrompt reads a body that is not JSON and not a form: text is
// inspected as it is; binary bytes cannot be, and take the fail mode.
func plainBodyPrompt(body []byte) passthroughSidePrompt {
	if utf8.Valid(body) && !bytes.Contains(body, []byte{0}) {
		t := string(body)
		return passthroughSidePrompt{Segments: []string{t}}
	}
	return passthroughSidePrompt{Unreadable: "the body is binary and neither JSON nor a form"}
}

// formPrompt reads an application/x-www-form-urlencoded body: every value
// is text, except the fields known not to be (model, user, size ...).
func formPrompt(body []byte) passthroughSidePrompt {
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return passthroughSidePrompt{Unreadable: "the form body cannot be parsed: " + err.Error()}
	}
	w := &textWalker{}
	for k, vs := range vals {
		if walkSkipScalar[normKey(k)] {
			continue
		}
		for _, v := range vs {
			w.add(v)
		}
	}
	return passthroughSidePrompt{Segments: w.segs}
}

// multipartPrompt reads a multipart/form-data body: every text field, and
// every part whose own type is text, is inspected; a file of a binary type
// (an image or an audio file to edit or transcribe) is media and is not.
// A body that cannot be parsed takes the fail mode.
func multipartPrompt(body []byte, boundary string) passthroughSidePrompt {
	if boundary == "" {
		return passthroughSidePrompt{Unreadable: "the multipart body has no boundary"}
	}
	w := &textWalker{}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	parts := 0
	for {
		part, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return passthroughSidePrompt{Unreadable: "the multipart body cannot be parsed: " + err.Error()}
		}
		parts++
		data, err := io.ReadAll(part)
		if err != nil {
			return passthroughSidePrompt{Unreadable: "the multipart body cannot be parsed: " + err.Error()}
		}
		ct := strings.ToLower(part.Header.Get("Content-Type"))
		mt, _, _ := mime.ParseMediaType(ct)
		file := part.FileName() != ""
		isText := textMediaType(mt) && (!file || mt != "")
		if !isText || (!file && walkSkipScalar[normKey(part.FormName())]) {
			continue // binary media (an image or an audio file), or a field that is no text
		}
		if !utf8.Valid(data) {
			return passthroughSidePrompt{Unreadable: "a multipart text field is not valid UTF-8"}
		}
		w.add(string(data))
	}
	if parts == 0 {
		return passthroughSidePrompt{Unreadable: "the multipart body has no parts"}
	}
	return passthroughSidePrompt{Segments: w.segs}
}

// ---- replies ---------------------------------------------------------------------

// replyScan is the inspectable content of one reply (or one stream event).
type replyScan struct {
	// Type is the "type" of a stream event.
	Type     string
	Segments []string
	Calls    []sseToolCall
	// Ambiguous is why the reply can be read two ways ("" when it cannot):
	// the reply takes the fail mode, as an ambiguous request does.
	Ambiguous string
}

// scanReplyJSON reads one JSON reply or stream event. With stream set, the
// tool calls under delta, item and content_block are left to the stream
// state machine (sseToolCalls), which assembles them across events.
func scanReplyJSON(data []byte, stream bool, max int) (replyScan, error) {
	root, err := parseJSONTree(bytes.TrimSpace(data), max)
	if err != nil {
		var big *errTooManyValues
		if errors.As(err, &big) {
			// Valid JSON the proxy will not read: the fail mode, naming the key.
			return replyScan{Ambiguous: err.Error()}, nil
		}
		return replyScan{}, err
	}
	w := &textWalker{reply: true, stream: stream}
	w.walk(root, "", 0)
	return replyScan{Type: root.str("type"), Segments: w.segs, Calls: w.calls, Ambiguous: w.ambiguous}, nil
}

// scanReplyBody reads a buffered reply: one JSON value, or newline-delimited
// JSON (Ollama streams). ok is false for a body that is neither.
func scanReplyBody(data []byte, max int) (replyScan, bool) {
	if sc, err := scanReplyJSON(data, false, max); err == nil {
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
		sc, err := scanReplyJSON(ln, false, max)
		if err != nil {
			return replyScan{}, false
		}
		n++
		out.Segments = append(out.Segments, sc.Segments...)
		out.Calls = append(out.Calls, sc.Calls...)
		if out.Ambiguous == "" {
			out.Ambiguous = sc.Ambiguous
		}
	}
	return out, n > 0
}

// joinPromptSegments adds the segments of a body to the text the proxy
// already inspects (the user turn), once: a segment the text contains is left
// out. The walker has already left the canonical OpenClaw probes out of the
// user text, and only there (textWalker.add, GAP-0251); a segment that holds
// one elsewhere is never contained in the inspected text, which has none, so
// it is inspected.
func joinPromptSegments(inspect string, segs []string) string {
	budget := 64 << 20
	seen := map[string]bool{}
	var b strings.Builder
	b.WriteString(inspect)
	for _, s := range segs {
		if seen[s] || strings.TrimSpace(s) == "" {
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
