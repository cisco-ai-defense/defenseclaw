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

package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// The "message" tool call of OpenClaw (GAP-0177, GAP-0290..0292).
//
// OpenClaw channels name the message text differently: content, body, text,
// message, caption, or text nested in blocks and attachments. The gateway used
// to read only content and body from the call's args, and the OpenClaw plugin
// skipped the call when it found neither, so a call that carried its text
// anywhere else was never inspected. extractMessageArgs reads every string in
// the args instead. It mirrors extractMessage in
// extensions/defenseclaw/src/message-text.ts, which the plugin runs first and
// sends as the call's content (testdata/message_text_parity.json pins the two
// to the same answers). The gateway reads the args itself and its answer
// decides, so the limits and the routing values below never depend on the
// caller.
//
// A message call takes three checks, in this order:
//  1. the tool's static block list and MCP block, as for every tool call;
//  2. its text, through the message lane (rules, AI Defense, judge);
//  3. its routing values (the recipient, target, channel ...), through the
//     tool-policy lane like the destination of any other send tool.
//
// Text past the read limits is unknown, never clean (the bound rule,
// internal/guardrail/bounded): the call is judged at least at the unknown tier.

const (
	// messageTextMaxBytes bounds the text returned. A longer text keeps its
	// head and its tail.
	messageTextMaxBytes = 256 * 1024
	// messageTextMaxDepth is the nesting depth below the args object.
	messageTextMaxDepth = 8
	// messageTextMaxNodes is the number of values of any kind walked in one
	// call (a string, a number, an object, an array, a routing string). It
	// bounds the walk and the join, so a large array of empty objects or of
	// recipients costs a bounded amount; a 700-row table is within it.
	messageTextMaxNodes = 4096
	// messagePayloadMinBytes is the length from which a base64 value of an
	// attachment field is read as a payload, not as text.
	messagePayloadMinBytes = 1024
	// messagePayloadMaxChars is the base64 characters of attachments one call
	// has decoded and read (2 MiB, 1.5 MiB of bytes): a work budget in
	// characters, never wall-clock time, and about 10 ms of work. What is past
	// it is unread: the call is truncated, never skipped.
	messagePayloadMaxChars = 2 << 20
	// messagePayloadChunk is the decoded bytes read at a time.
	messagePayloadChunk = 32 << 10
	// messageRunMinBytes is the shortest run of text bytes read out of a
	// decoded attachment. Random binary data has such a run about once in 10^7
	// bytes, so a photo yields none.
	messageRunMinBytes = 16
)

// Key names are matched with asciiLowerPreservingBytes on both sides: a full
// Unicode lowercase would read a key like "İd" as "id" in Go and not in
// JavaScript.
//
// messageTextKeys hold the message text most often. They are read first, in
// this order, ahead of the remaining keys in sorted order.
var messageTextKeys = []string{
	"content", "body", "text", "message", "caption", "subject", "title",
	"summary", "description", "html", "markdown", "blocks", "attachments",
	"voicetext", "quotetext", "presentation",
}

// messageRoutingKeys name where a message goes or how it is sent, not what it
// says. A phone number or an address in "to" would only make the content rules
// alert on every message, so a string under one of them is not scanned as
// text. It goes to the tool-policy lane as a routing value instead.
var messageRoutingKeys = map[string]bool{
	"action": true, "channel": true, "provider": true, "accountid": true,
	"account": true, "to": true, "target": true, "targets": true, "from": true,
	"recipient": true, "recipients": true, "replyto": true, "threadid": true,
	"messageid": true, "chatid": true, "id": true, "type": true, "kind": true,
	"mode": true, "format": true, "parsemode": true, "silent": true,
	"dryrun": true, "timeoutms": true, "besteffort": true, "gatewayurl": true,
	"gatewaytoken": true,
}

// messageExtract is what a message call's args hold.
type messageExtract struct {
	// Text is every string outside the routing values, joined by newlines.
	Text string
	// Truncated holds the read limits the call hit with text left unread: a
	// value past the node limit (nodes), a value below the depth limit (depth),
	// a text past the size limit (bytes), or an attachment too long to decode
	// (bytes). A limit that drops nothing but empty containers is not a hit.
	Truncated bounded.CapSet
	// Routing holds the strings under routing keys, by dotted key path.
	Routing map[string]interface{}
}

// extractMessageArgs reads a message call's args once. Args that are not a
// JSON value yield nothing; the caller decides what an empty result means.
// Numbers are text too (a table cell, a count the message states): they are
// read as their JSON literal.
func extractMessageArgs(raw json.RawMessage) messageExtract {
	var out messageExtract
	if len(raw) == 0 {
		return out
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value interface{}
	if err := dec.Decode(&value); err != nil {
		return out
	}
	if _, err := dec.Token(); err != io.EOF {
		return out
	}
	w := messageWalk{routing: map[string]interface{}{}, routingSeen: map[string]int{}}
	w.walk(value, 0, "")
	text := strings.Join(w.parts, "\n")
	if len(text) > messageTextMaxBytes {
		// Head and tail, each cut at the start of a character.
		half := messageTextMaxBytes / 2
		head := half
		for head > 0 && !utf8.RuneStart(text[head]) {
			head--
		}
		tail := len(text) - half
		for tail < len(text) && !utf8.RuneStart(text[tail]) {
			tail++
		}
		text = text[:head] + "\n" + text[tail:]
		w.trunc.Hit(bounded.Bytes)
	}
	out.Text, out.Truncated = text, w.trunc.Set()
	if len(w.routing) > 0 {
		out.Routing = w.routing
	}
	return out
}

type messageWalk struct {
	payloadUsed int
	parts       []string
	nodes       int
	trunc       bounded.Truncated
	routing     map[string]interface{}
	routingSeen map[string]int
}

// leaf adds a string or number value to the text.
func (w *messageWalk) leaf(s string) {
	if messageBlank(s) {
		return
	}
	w.parts = append(w.parts, s)
}

// messageBlank reports a string of ASCII white space only: the one blank test
// both sides share (the Unicode white-space classes of Go and of JavaScript
// differ at U+0085 and U+FEFF).
func messageBlank(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\r', '\f', '\v':
		default:
			return false
		}
	}
	return true
}

// messageHasText reports a value with a non-blank string or a number anywhere
// inside. The cap that drops a value is a hit only when it holds text.
func messageHasText(value interface{}) bool {
	stack := []interface{}{value}
	for len(stack) > 0 {
		last := len(stack) - 1
		switch v := stack[last].(type) {
		case string:
			if !messageBlank(v) {
				return true
			}
			stack = stack[:last]
		case json.Number:
			return true
		case []interface{}:
			stack = append(stack[:last], v...)
		case map[string]interface{}:
			stack = stack[:last]
			for _, item := range v {
				stack = append(stack, item)
			}
		default:
			stack = stack[:last]
		}
	}
	return false
}

// drop records the cap that dropped value, when it held text.
func (w *messageWalk) drop(c bounded.Cap, value interface{}) {
	if messageHasText(value) {
		w.trunc.Hit(c)
	}
}

func (w *messageWalk) walk(value interface{}, depth int, path string) {
	if w.nodes >= messageTextMaxNodes {
		w.drop(bounded.Nodes, value)
		return
	}
	w.nodes++
	switch v := value.(type) {
	case string:
		w.leaf(v)
	case json.Number:
		w.leaf(v.String())
	case []interface{}:
		if depth > messageTextMaxDepth {
			w.drop(bounded.Depth, v)
			return
		}
		for _, item := range v {
			w.walk(item, depth+1, path)
		}
	case map[string]interface{}:
		if depth > messageTextMaxDepth {
			w.drop(bounded.Depth, v)
			return
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		rank := func(k string) int {
			lower := asciiLowerPreservingBytes(k)
			for i, t := range messageTextKeys {
				if t == lower {
					return i
				}
			}
			return len(messageTextKeys)
		}
		// Keys sort by rank, then by code point (the byte order of UTF-8).
		sort.Slice(keys, func(i, j int) bool {
			if ri, rj := rank(keys[i]), rank(keys[j]); ri != rj {
				return ri < rj
			}
			return keys[i] < keys[j]
		})
		for _, k := range keys {
			child := k
			if path != "" {
				child = path + "." + k
			}
			if messageRoutingKeys[asciiLowerPreservingBytes(k)] && w.routingValue(child, v[k]) {
				continue
			}
			if s, ok := v[k].(string); ok && messageAttachmentField(k) && w.attachment(s) {
				continue
			}
			w.walk(v[k], depth+1, child)
		}
	}
}

// routingValue files the strings of a routing key's value and reports whether
// the value held nothing else. A routing key that holds an object (a target
// with its own text) is read like any other: its strings are text and the
// routing keys inside it file their own.
func (w *messageWalk) routingValue(path string, value interface{}) bool {
	switch v := value.(type) {
	case string:
		w.fileRouting(path, v)
		return true
	case []interface{}:
		for _, item := range v {
			if _, nested := item.(map[string]interface{}); nested {
				return false
			}
			if _, nested := item.([]interface{}); nested {
				return false
			}
		}
		for _, item := range v {
			switch it := item.(type) {
			case string:
				w.fileRouting(path, it)
			case json.Number:
				w.fileRouting(path, it.String())
			}
		}
		return true
	case map[string]interface{}:
		return false
	case json.Number:
		w.fileRouting(path, v.String())
		return true
	default:
		// A flag or a null under a routing key is a control value.
		return true
	}
}

// fileRouting files a routing string under its path (a repeat gets #2, #3 ...).
// Each string spends one node of the budget, so a large array of recipients is
// bounded like any other walk, and the naming is one counter per path.
func (w *messageWalk) fileRouting(path, s string) {
	if messageBlank(s) {
		return
	}
	if w.nodes >= messageTextMaxNodes {
		w.trunc.Hit(bounded.Nodes)
		return
	}
	w.nodes++
	n := w.routingSeen[path] + 1
	w.routingSeen[path] = n
	if n == 1 {
		w.routing[path] = s
		return
	}
	w.routing[path+"#"+strconv.Itoa(n)] = s
}

// messageAttachmentField names the fields that carry an attachment: buffer
// ("Base64/data-URL attachment" in OpenClaw's schema) and media, at any depth
// (an attachments[] entry names its own). A text field (message, text,
// caption, content, body ...) is always text, whatever it holds.
func messageAttachmentField(key string) bool {
	switch asciiLowerPreservingBytes(key) {
	case "buffer", "media":
		return true
	}
	return false
}

// attachment reads a long value of an attachment field that is base64 all
// through (a data URL or the bare payload) and reports whether it did. It is
// decoded as a stream, within the call's budget of messagePayloadMaxChars
// characters, and read for text: a run of text bytes anywhere in it (a message
// sent as a file, text behind a binary header) is message text, and only a
// payload with no such run is binary and skipped, spending no text budget. The
// declared media type decides nothing; the bytes do. What is past the budget is
// unread: the call is truncated, never skipped and never decoded for seconds on
// the 200 ms path. A value with anything but base64 in it is not a payload and
// is read as text by the caller.
func (w *messageWalk) attachment(s string) bool {
	if len(s) < messagePayloadMinBytes {
		return false
	}
	payload := s
	if strings.HasPrefix(s, "data:") {
		head := s[:min(len(s), 256)]
		i := strings.Index(head, ";base64,")
		if i < 0 {
			return false
		}
		payload = s[i+len(";base64,"):]
	}
	if len(payload) < messagePayloadMinBytes {
		return false
	}
	// The part inside the budget (whole groups of four characters).
	read := payload
	if left := messagePayloadMaxChars - w.payloadUsed; len(payload) > left {
		read = payload[:max(left, 0)&^3]
		w.trunc.Hit(bounded.Bytes)
	}
	enc, ok := messageBase64Encoding(read, len(read) == len(payload))
	if !ok {
		return false
	}
	if w.nodes >= messageTextMaxNodes {
		w.trunc.Hit(bounded.Nodes)
		return true
	}
	w.nodes++
	w.payloadUsed += len(read)
	text, decoded := messageStreamTextRuns(base64.NewDecoder(enc, strings.NewReader(read)))
	if !decoded {
		return false
	}
	if text != "" {
		w.leaf(text)
	}
	return true
}

// messageBase64Encoding is the alphabet and padding of a base64 value, which
// must be base64 characters all through (either alphabet, padding and line
// breaks, not both alphabets).
func messageBase64Encoding(s string, whole bool) (*base64.Encoding, bool) {
	std, url := false, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '=', c == '\r', c == '\n':
		case c == '+' || c == '/':
			std = true
		case c == '-' || c == '_':
			url = true
		default:
			return nil, false
		}
	}
	if std && url {
		return nil, false
	}
	enc := base64.StdEncoding
	if url {
		enc = base64.URLEncoding
	}
	if !whole || !strings.HasSuffix(strings.TrimRight(s, "\r\n"), "=") {
		enc = enc.WithPadding(base64.NoPadding)
	}
	return enc, true
}

// messageStreamTextRuns reads decoded data in chunks and returns the runs of
// at least messageRunMinBytes text bytes (printable characters and white space
// of valid UTF-8) joined by newlines: all of a text file, the text of a binary
// file. It reports false when the stream is not valid base64. The text
// returned is bounded by messageTextMaxBytes, past it the reading stops.
func messageStreamTextRuns(r io.Reader) (string, bool) {
	var out []string
	var run []byte
	total := 0
	flush := func() {
		if len(run) >= messageRunMinBytes {
			out = append(out, string(run))
			total += len(run) + 1
		}
		run = run[:0]
	}
	buf := make([]byte, 0, messagePayloadChunk+utf8.UTFMax)
	for {
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		final := err != nil
		if err != nil && err != io.EOF {
			return "", false
		}
		end := len(buf)
		if !final {
			// A character cut by the end of the chunk waits for the next one.
			for k := 1; k < utf8.UTFMax && k <= len(buf); k++ {
				if utf8.RuneStart(buf[len(buf)-k]) {
					if !utf8.FullRune(buf[len(buf)-k:]) {
						end = len(buf) - k
					}
					break
				}
			}
		}
		for i := 0; i < end; {
			c := buf[i]
			if c < utf8.RuneSelf {
				if messagePrintableASCII[c] {
					run = append(run, c)
				} else {
					flush()
				}
				i++
				continue
			}
			rn, size := utf8.DecodeRune(buf[i:end])
			if rn == utf8.RuneError && size == 1 || !unicode.IsPrint(rn) {
				flush()
			} else {
				run = append(run, buf[i:i+size]...)
			}
			i += size
		}
		buf = append(buf[:0], buf[end:]...)
		if total+len(run) > messageTextMaxBytes {
			break
		}
		if final {
			break
		}
	}
	flush()
	return strings.Join(out, "\n"), true
}

// messagePrintableASCII marks the ASCII bytes of a text run: printable
// characters, newline, carriage return and tab.
var messagePrintableASCII = func() (t [utf8.RuneSelf]bool) {
	for c := byte(0x20); c < 0x7f; c++ {
		t[c] = true
	}
	t['\n'], t['\r'], t['\t'] = true, true, true
	return t
}()

// messageRoutingArgs is the args the tool-policy lane reads for a message
// call's routing values: the recipient, target and channel strings under
// their own keys. Nothing is left out of the call; text is read by the
// message lane.
func messageRoutingArgs(routing map[string]interface{}) json.RawMessage {
	if len(routing) == 0 {
		return nil
	}
	b, err := json.Marshal(routing)
	if err != nil {
		return nil
	}
	return b
}

// inspectMessageCall decides a message tool call that reached /inspect/tool.
// The args are parsed once; the text and the routing values come from them.
func (a *APIServer) inspectMessageCall(ctx context.Context, req *ToolInspectRequest) *ToolInspectVerdict {
	// A static block or an MCP block decides before any text is read.
	if v := a.toolBlockListVerdict(ctx, req, nil); v != nil {
		return v
	}
	// The gateway reads the args itself: its answer decides, whatever the
	// caller sent as content. A caller that sends no args (a hook that only
	// has the text) is read from its content.
	ex := extractMessageArgs(req.Args)
	text := ex.Text
	if req.Content != "" && !strings.Contains(text, req.Content) {
		// Text the caller read and the gateway did not (two keys that fold to
		// one when decoded) is scanned too.
		text = strings.TrimPrefix(text+"\n"+req.Content, "\n")
	}
	if text == "" && !ex.Truncated.Any() {
		if args := strings.TrimSpace(string(req.Args)); args == "" || args == "null" || args == "{}" || args == "[]" {
			// Nothing to inspect: an empty call.
			return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
		}
		// Arguments with no text (GAP-0177): the tool policy reads them.
		return a.inspectToolPolicyCtx(ctx, req)
	}
	textReq := *req
	textReq.Content = text
	verdict := a.inspectMessageContent(ctx, &textReq)
	if routing := messageRoutingArgs(ex.Routing); routing != nil {
		// The routing values are not text, but they are not skipped: a secret
		// in a recipient field or a destination the rules name is found by
		// the same lane that reads the destination of any other send tool.
		routeReq := *req
		routeReq.Args, routeReq.Content, routeReq.skipJudge = routing, "", true
		verdict = mergeToolInspectVerdicts(verdict, a.inspectToolPolicyCtx(ctx, &routeReq))
	}
	// Text the read limits dropped is unknown: the verdict of the part read
	// stands, and the call is at least at the unknown tier of the policy.
	verdict.floorBoundedTruncated(ex.Truncated, a.boundedTier(ctx, req.Connector))
	return verdict
}
