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
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
)

// The "message" tool call of OpenClaw (GAP-0177, GAP-0290..0292, GAP-0436).
//
// OpenClaw channels name the message text differently: content, body, text,
// message, caption, or text nested in blocks and attachments. extractMessageArgs
// reads every string in the args, once: the text, the routing values (the
// recipient, target, channel ...) and the attachments. The OpenClaw plugin
// reads none of it: it sends the params as they are. Over the request body
// limit it replaces only the attachments (by their size, type, hash and text)
// and never cuts the text: a call whose text is over the limit is blocked
// (extensions/defenseclaw/src/inspect-body-limit.ts). The gateway's reading
// decides.
//
// A message call takes three checks, in this order:
//  1. the tool's static block list and MCP block, as for every tool call;
//  2. its text, through the message lane (rules, AI Defense, judge): the rules
//     read all of the text that arrived, the judge at most messageJudgeMaxBytes;
//  3. its routing values (the recipient, target, channel ...), through the
//     tool-policy lane like the destination of any other send tool.
//
// Text past the read limits (nodes, depth, an attachment too long to decode) is
// unknown, never clean (the bound rule, internal/guardrail/bounded): the call is
// judged at least at the unknown tier of the policy.

const (
	// messageJudgeMaxBytes is the most of a message's text the judge is sent
	// (head and tail past it). The rules read all of the text that arrived.
	messageJudgeMaxBytes = 256 * 1024
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
	// or an attachment too long to decode (bytes). A limit that drops nothing
	// but empty containers is not a hit. The text itself is read whole: the
	// request body limit bounds it.
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
	return messageAttachmentKeys[asciiLowerPreservingBytes(key)]
}

// messageAttachmentKeys and messageDataURLHeaderMaxBytes are
// message_attachment_keys and message_data_url_header_max_bytes of the embedded
// limits file. The OpenClaw plugin reads the same file: over the body limit it
// replaces only the values of these fields that are attachments by the same
// test (by their size, type, hash and text), so the plugin and the gateway
// agree on what an attachment is (rel-1-0-10:GAP-0511).
var messageAttachmentKeys, messageDataURLHeaderMaxBytes = func() (map[string]bool, int) {
	var limits struct {
		Keys      []string `json:"message_attachment_keys"`
		HeaderMax int      `json:"message_data_url_header_max_bytes"`
	}
	if err := json.Unmarshal(publicschemas.InspectToolRequestLimits, &limits); err != nil || len(limits.Keys) == 0 || limits.HeaderMax <= 0 {
		panic("gateway: schemas/inspect-tool-request-limits.json has no message_attachment_keys or message_data_url_header_max_bytes")
	}
	keys := make(map[string]bool, len(limits.Keys))
	for _, k := range limits.Keys {
		keys[asciiLowerPreservingBytes(k)] = true
	}
	return keys, limits.HeaderMax
}()

// attachment reads a long value of an attachment field that is base64 all
// through (a data URL or the bare payload) and reports whether it did. It is
// decoded as a stream, within the call's budget of messagePayloadMaxChars
// characters, and read for text: a run of text bytes anywhere in it (a message
// sent as a file, text behind a binary header) is message text, and only a
// payload with no such run is binary and skipped, spending no text budget. The
// declared media type decides nothing; the bytes do. What is past the budget is
// unread: the call is truncated, never skipped and never decoded for seconds on
// the 200 ms path. A value with anything but base64 in it is not a payload and
// is read as text by the caller. A data URL is a payload only when its
// ";base64," ends within the first messageDataURLHeaderMaxBytes bytes (bytes,
// not characters: the plugin counts the same way, GAP-0511).
//
// Known limit (no gap, the GAP-0356 class): what an attachment value carries
// outside its decoded bytes is not read as text. That is a raw base64-alphabet
// value (key lines in buffer are decoded, never read as words), the parameters
// of an ASCII data URL header (data:...;name=...;base64,), and an attachment
// nested past messageTextMaxDepth (that one is TRUNCATED, the unknown tier).
func (w *messageWalk) attachment(s string) bool {
	if len(s) < messagePayloadMinBytes {
		return false
	}
	payload := s
	if strings.HasPrefix(s, "data:") {
		head := s[:min(len(s), messageDataURLHeaderMaxBytes)]
		i := strings.Index(head, ";base64,")
		if i < 0 {
			return false
		}
		payload = s[i+len(";base64,"):]
	}
	if len(payload) < messagePayloadMinBytes {
		return false
	}
	// Base64 all through, the whole value (a byte scan, about 2 ms per MB): a
	// value that is not is text, whatever its first part looks like. Base64 is
	// read as a lenient decoder reads it (Node's Buffer.from, which OpenClaw
	// may use): either alphabet, white space skipped, and a "=" ends a group
	// and starts the next one, so no value a receiver would decode is read as
	// plain text.
	spaced, ok := messageLenientBase64(payload)
	if !ok {
		return false
	}
	// The part inside the budget.
	read := payload
	if left := messagePayloadMaxChars - w.payloadUsed; len(payload) > left {
		read = payload[:max(left, 0)]
		w.trunc.Hit(bounded.Bytes)
	}
	if w.nodes >= messageTextMaxNodes {
		w.trunc.Hit(bounded.Nodes)
		return true
	}
	w.nodes++
	w.payloadUsed += len(read)
	if spaced {
		// Spaces or tabs in the value: base64 to a lenient decoder, and words
		// to a reader. Both readings are scanned, so neither hides the other.
		w.leaf(read)
	}
	if text := messageAttachmentText(read); text != "" {
		w.leaf(text)
	}
	return true
}

// messageAttachmentText is the text of a base64 payload: the runs of its 8-bit
// reading, and, when it looks like UTF-16 (a byte order mark, or a NUL beside
// every other byte), the runs of that reading too: a file that guesses wrong
// either way still gives up its text.
func messageAttachmentText(payload string) string {
	text := messageStreamTextRuns(newMessageBase64Reader(payload))
	head := make([]byte, messageUTF16ProbeBytes)
	n, _ := io.ReadFull(newMessageBase64Reader(payload), head)
	if be, skipBOM, ok := messageUTF16(head[:n]); ok {
		u16 := messageStreamTextRuns(&messageUTF16Reader{r: newMessageBase64Reader(payload), be: be, bom: skipBOM, buf: make([]byte, messagePayloadChunk)})
		switch {
		case text == "":
			text = u16
		case u16 != "" && u16 != text:
			text += "\n" + u16
		}
	}
	return text
}

// messageBase64Value is the class of each byte in a base64 value: its six
// bits, messageB64Skip for white space, messageB64Pad for "=", and
// messageB64Bad for anything else. Both alphabets are accepted together.
var messageBase64Value = func() (t [256]uint8) {
	for i := range t {
		t[i] = messageB64Bad
	}
	const std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for i := 0; i < len(std); i++ {
		t[std[i]] = uint8(i)
	}
	t['-'], t['_'] = 62, 63
	for _, c := range " \t\n\r\f\v" {
		t[c] = messageB64Skip
	}
	t['='] = messageB64Pad
	return t
}()

const (
	messageB64Skip = 64
	messageB64Pad  = 65
	messageB64Bad  = 255
)

// messageLenientBase64 reports a value made only of base64 characters (either
// alphabet), padding and ASCII white space, all through, and whether it has a
// space or a tab in it (line breaks alone are how base64 is wrapped).
func messageLenientBase64(s string) (spaced, ok bool) {
	for i := 0; i < len(s); i++ {
		switch messageBase64Value[s[i]] {
		case messageB64Bad:
			return false, false
		case messageB64Skip:
			if s[i] == ' ' || s[i] == '\t' {
				spaced = true
			}
		}
	}
	return spaced, true
}

// messageBase64Reader decodes a base64 value as a lenient decoder does: white
// space is skipped, either alphabet is read, and "=" drops the bits of the
// group it ends and starts the next group fresh.
type messageBase64Reader struct {
	s    string
	i    int
	acc  uint32
	bits uint
}

func newMessageBase64Reader(s string) *messageBase64Reader { return &messageBase64Reader{s: s} }

func (r *messageBase64Reader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) && r.i < len(r.s) {
		v := messageBase64Value[r.s[r.i]]
		r.i++
		switch {
		case v < 64:
			r.acc = r.acc<<6 | uint32(v)
			r.bits += 6
			if r.bits >= 8 {
				r.bits -= 8
				p[n] = byte(r.acc >> r.bits)
				r.acc &= 1<<r.bits - 1
				n++
			}
		case v == messageB64Pad:
			r.acc, r.bits = 0, 0
		}
	}
	if n == 0 && r.i >= len(r.s) {
		return 0, io.EOF
	}
	return n, nil
}

// messageStreamTextRuns reads decoded data in chunks and returns the runs of
// at least messageRunMinBytes text bytes (printable characters and white space
// of valid UTF-8) joined by newlines: all of a text file, the text of a binary
// file. The reading is bounded by the call's payload budget, not by a cap on
// the text.
func messageStreamTextRuns(r io.Reader) string {
	var out []string
	var run []byte
	flush := func() {
		if len(run) >= messageRunMinBytes {
			out = append(out, string(run))
		}
		run = run[:0]
	}
	buf := make([]byte, 0, messagePayloadChunk+utf8.UTFMax)
	for {
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		final := err != nil
		if err != nil && err != io.EOF {
			return strings.Join(out, "\n")
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
		if final {
			break
		}
	}
	flush()
	return strings.Join(out, "\n")
}

// messageUTF16ProbeBytes is how much of a decoded attachment is looked at to
// tell UTF-16 text.
const messageUTF16ProbeBytes = 4096

// messageUTF16 reports UTF-16 text and its byte order: a byte order mark, or
// bytes where at least three in ten of one parity are NUL and almost none of
// the other (ASCII text in either order).
func messageUTF16(head []byte) (be, bom, ok bool) {
	if len(head) >= 2 {
		switch {
		case head[0] == 0xff && head[1] == 0xfe:
			return false, true, true
		case head[0] == 0xfe && head[1] == 0xff:
			return true, true, true
		}
	}
	pairs := len(head) / 2
	if pairs < 16 {
		return false, false, false
	}
	even, odd := 0, 0
	for i := 0; i+1 < len(head); i += 2 {
		if head[i] == 0 {
			even++
		}
		if head[i+1] == 0 {
			odd++
		}
	}
	switch {
	case odd*10 >= pairs*3 && even*50 <= pairs:
		return false, false, true
	case even*10 >= pairs*3 && odd*50 <= pairs:
		return true, false, true
	}
	return false, false, false
}

// messageUTF16Reader converts a UTF-16 stream to UTF-8.
type messageUTF16Reader struct {
	r    io.Reader
	be   bool
	bom  bool // a leading byte order mark is dropped
	buf  []byte
	raw  []byte // bytes read and not yet converted: an odd byte, a high surrogate
	out  []byte // converted, not yet returned
	done bool
	err  error
}

func (u *messageUTF16Reader) Read(p []byte) (int, error) {
	for len(u.out) == 0 {
		if u.err != nil {
			return 0, u.err
		}
		n, err := u.r.Read(u.buf)
		u.err = err
		u.raw = append(u.raw, u.buf[:n]...)
		units := len(u.raw) / 2
		words := make([]uint16, units)
		for i := range words {
			if u.be {
				words[i] = uint16(u.raw[2*i])<<8 | uint16(u.raw[2*i+1])
			} else {
				words[i] = uint16(u.raw[2*i+1])<<8 | uint16(u.raw[2*i])
			}
		}
		consumed := units
		if units > 0 && err == nil && words[units-1] >= 0xd800 && words[units-1] < 0xdc00 {
			// A high surrogate waits for its pair.
			consumed--
		}
		words = words[:consumed]
		if u.bom && !u.done && len(words) > 0 {
			if words[0] == 0xfeff {
				words = words[1:]
			}
			u.done = true
		}
		for _, r := range utf16.Decode(words) {
			u.out = utf8.AppendRune(u.out, r)
		}
		u.raw = append(u.raw[:0], u.raw[2*consumed:]...)
		if err != nil && len(u.out) == 0 {
			return 0, err
		}
	}
	n := copy(p, u.out)
	u.out = u.out[n:]
	return n, nil
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

// messageJudgeText is the text the judge is sent: all of it up to
// messageJudgeMaxBytes, else its head and its tail around a newline, each cut
// at the start of a character.
func messageJudgeText(text string) string {
	if len(text) <= messageJudgeMaxBytes {
		return text
	}
	half := messageJudgeMaxBytes / 2
	head := half
	for head > 0 && !utf8.RuneStart(text[head]) {
		head--
	}
	tail := len(text) - half
	for tail < len(text) && !utf8.RuneStart(text[tail]) {
		tail++
	}
	return text[:head] + "\n" + text[tail:]
}

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
	// The rules read all of the text; the judge reads at most its cap of it.
	textReq.judgeContent = messageJudgeText(text)
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
