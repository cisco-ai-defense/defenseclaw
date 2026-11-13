// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const routeOnlyTextCap = 64 << 10

// routeOnlyRawTextLimit bounds the text kept per message before system
// reminders are stripped: stripReminders reads at most 4*routeOnlyTextCap
// bytes, and the bytes past that tell truncateUTF8 the text was longer.
const routeOnlyRawTextLimit = 4*routeOnlyTextCap + 4

// The JSON delimiters json.Decoder.Token returns.
const (
	jsonObjectOpen = json.Delim(0x7b) // {
	jsonArrayOpen  = json.Delim(0x5b) // [
)

// routeOnlyHumanText returns the newest text the user typed (never tool
// output, system reminders or developer items) and request facts.
//
// It is a json.Decoder token scan (S1 DESIGN 16.6): the body is not decoded
// into a second copy, the text kept per message is bounded, and the scan
// stops once the conversation (messages, or input on the Responses API) and
// tools are read. A body that is not valid JSON up to that point, or whose
// messages are not a list of objects with string roles, gives no text, as
// the full decode it replaces did. Two documented differences, both from
// stopping early and both limited to classifier input from a cooperative
// agent: with a repeated conversation key after tools the first one is read
// (the full decode kept the last), and bytes that are invalid after the
// conversation and tools no longer drop the text.
func routeOnlyHumanText(family string, body []byte) (text string, hasTools, toolTurn, images bool) {
	s := humanTextScan{responses: family == config.RoutingAPIResponses}
	s.dec = json.NewDecoder(bytes.NewReader(body))
	// Numbers stay text: an out-of-range number is not an error here.
	s.dec.UseNumber()
	if !s.document() {
		return "", false, false, false
	}
	return s.text, s.hasTools, s.toolTurn, s.images
}

type humanTextScan struct {
	dec       *json.Decoder
	responses bool

	text     string
	hasTools bool
	toolTurn bool
	images   bool
}

// humanTextMessage is one message (or Responses input item) being read.
type humanTextMessage struct {
	role       string
	kind       string // Responses item type
	parts      humanTextParts
	images     bool
	toolResult bool // a "tool_result" string anywhere in its content
}

func (m *humanTextMessage) text() string { return capText(stripReminders(m.parts.String())) }

// humanTextParts joins text parts with newlines and keeps at most
// routeOnlyRawTextLimit bytes, copied, so a large token is not retained.
type humanTextParts struct {
	b strings.Builder
	n int
}

func (p *humanTextParts) reset() { p.b.Reset(); p.n = 0 }

func (p *humanTextParts) add(s string) {
	if p.n > 0 {
		p.write("\n")
	}
	p.n++
	p.write(s)
}

func (p *humanTextParts) write(s string) {
	room := routeOnlyRawTextLimit - p.b.Len()
	if room <= 0 {
		return
	}
	if len(s) > room {
		s = s[:room]
	}
	p.b.WriteString(s)
}

func (p *humanTextParts) String() string { return p.b.String() }

func (s *humanTextScan) document() bool {
	tok, err := s.dec.Token()
	if err != nil {
		return false
	}
	if tok == nil {
		return true
	}
	if tok != jsonObjectOpen {
		return false
	}
	var conversation, tools bool
	for s.dec.More() {
		key, ok := s.key()
		if !ok {
			return false
		}
		switch {
		case !s.responses && strings.EqualFold(key, "messages"):
			ok, conversation = s.messages(), true
		case s.responses && strings.EqualFold(key, "input"):
			ok, conversation = s.input(), true
		case strings.EqualFold(key, "tools"):
			ok, tools = s.tools(), true
		default:
			ok = skipJSONValue(s.dec, nil)
		}
		if !ok {
			return false
		}
		if conversation && tools {
			// Nothing after these changes the answer.
			return true
		}
	}
	_, err = s.dec.Token()
	return err == nil
}

func (s *humanTextScan) key() (string, bool) {
	tok, err := s.dec.Token()
	if err != nil {
		return "", false
	}
	k, _ := tok.(string)
	return k, true
}

// consider records a user message: the newest one with text wins, and
// images covers it and every newer user message without text.
func (s *humanTextScan) consider(m *humanTextMessage) {
	if t := m.text(); t != "" {
		s.text, s.images = t, m.images
		return
	}
	s.images = s.images || m.images
}

// tools records whether the tools value is longer than an empty list.
func (s *humanTextScan) tools() bool {
	skip := jsonSkip{}
	if s.dec.Decode(&skip) != nil {
		return false
	}
	s.hasTools = skip.size > 2
	return true
}

// messages reads a messages list (Messages, Chat Completions, Bedrock):
// the newest user message with text wins; toolTurn is the shape of the last.
func (s *humanTextScan) messages() bool {
	s.text, s.toolTurn, s.images = "", false, false
	tok, err := s.dec.Token()
	if err != nil {
		return false
	}
	if tok == nil {
		return true
	}
	if tok != jsonArrayOpen {
		return false
	}
	for s.dec.More() {
		tok, err := s.dec.Token()
		if err != nil {
			return false
		}
		var m humanTextMessage
		switch tok {
		case nil:
		case jsonObjectOpen:
			if !s.message(&m) {
				return false
			}
		default:
			return false
		}
		s.toolTurn = m.role == "tool" || m.toolResult
		if m.role == "user" {
			s.consider(&m)
		}
	}
	_, err = s.dec.Token()
	return err == nil
}

// message reads one message object after its opening brace. A role that is
// not a string fails the scan (as the decode it replaces did).
func (s *humanTextScan) message(m *humanTextMessage) bool {
	for s.dec.More() {
		key, ok := s.key()
		if !ok {
			return false
		}
		switch {
		case strings.EqualFold(key, "role"):
			tok, err := s.dec.Token()
			if err != nil {
				return false
			}
			switch v := tok.(type) {
			case nil:
			case string:
				m.role = v
			default:
				return false
			}
		case strings.EqualFold(key, "content"):
			// Text is kept for user messages (and a role not seen yet).
			ok = s.content(m, m.role == "" || m.role == "user")
		default:
			ok = skipJSONValue(s.dec, nil)
		}
		if !ok {
			return false
		}
	}
	_, err := s.dec.Token()
	return err == nil
}

// content reads a content field: a string, or a list of blocks whose text
// blocks are joined; tool_result and other blocks give no text.
func (s *humanTextScan) content(m *humanTextMessage, collect bool) bool {
	m.parts.reset()
	m.images, m.toolResult = false, false
	if !collect {
		// Another role: only a tool_result string in it matters.
		return skipJSONValue(s.dec, &m.toolResult)
	}
	tok, err := s.dec.Token()
	if err != nil {
		return false
	}
	switch v := tok.(type) {
	case string:
		m.toolResult = v == "tool_result"
		m.parts.add(v)
		return true
	case json.Delim:
		if v != jsonArrayOpen {
			return skipJSONRest(s.dec, tok, &m.toolResult)
		}
	default:
		return true
	}
	for s.dec.More() {
		if !s.block(m, collect) {
			return false
		}
	}
	_, err = s.dec.Token()
	return err == nil
}

// block reads one content block; only its own type and text fields count.
func (s *humanTextScan) block(m *humanTextMessage, collect bool) bool {
	tok, err := s.dec.Token()
	if err != nil {
		return false
	}
	if tok != jsonObjectOpen {
		return skipJSONRest(s.dec, tok, &m.toolResult)
	}
	var kind, text string
	for s.dec.More() {
		key, ok := s.key()
		if !ok {
			return false
		}
		if key == "tool_result" {
			m.toolResult = true
		}
		switch {
		case strings.EqualFold(key, "type"):
			ok = s.stringField(&kind, &m.toolResult)
		case collect && strings.EqualFold(key, "text"):
			ok = s.stringField(&text, &m.toolResult)
		default:
			// Nested content (a tool_result body) is skipped unbuilt.
			ok = skipJSONValue(s.dec, &m.toolResult)
		}
		if !ok {
			return false
		}
	}
	if _, err := s.dec.Token(); err != nil {
		return false
	}
	switch kind {
	case "text", "input_text":
		if collect {
			m.parts.add(text)
		}
	case "image", "input_image", "image_url":
		m.images = true
	case "":
		if collect && text != "" {
			m.parts.add(text)
		}
	}
	return true
}

// stringField reads a value into *field when it is a string; a value of
// another type leaves the field as it was.
func (s *humanTextScan) stringField(field *string, note *bool) bool {
	tok, err := s.dec.Token()
	if err != nil {
		return false
	}
	if v, ok := tok.(string); ok {
		if v == "tool_result" {
			*note = true
		}
		*field = v
		return true
	}
	return skipJSONRest(s.dec, tok, note)
}

// input reads the Responses input: a string, or a list of items whose
// newest user message item with text wins; toolTurn is a last item of an
// *_output type (function_call_output and the like).
func (s *humanTextScan) input() bool {
	s.text, s.toolTurn, s.images = "", false, false
	tok, err := s.dec.Token()
	if err != nil {
		return false
	}
	switch v := tok.(type) {
	case string:
		var p humanTextParts
		p.add(v)
		s.text = capText(stripReminders(p.String()))
		return true
	case json.Delim:
		if v != jsonArrayOpen {
			return skipJSONRest(s.dec, tok, nil)
		}
	default:
		return true
	}
	for s.dec.More() {
		tok, err := s.dec.Token()
		if err != nil {
			return false
		}
		var it humanTextMessage
		if tok == jsonObjectOpen {
			if !s.item(&it) {
				return false
			}
		} else if !skipJSONRest(s.dec, tok, nil) {
			return false
		}
		s.toolTurn = strings.HasSuffix(it.kind, "_output")
		if it.role == "user" && (it.kind == "" || it.kind == "message") {
			s.consider(&it)
		}
	}
	_, err = s.dec.Token()
	return err == nil
}

// item reads one Responses input item after its opening brace; fields of
// another type are ignored, as the item decode it replaces ignored them.
func (s *humanTextScan) item(it *humanTextMessage) bool {
	var unused bool
	for s.dec.More() {
		key, ok := s.key()
		if !ok {
			return false
		}
		switch {
		case strings.EqualFold(key, "type"):
			ok = s.stringField(&it.kind, &unused)
		case strings.EqualFold(key, "role"):
			ok = s.stringField(&it.role, &unused)
		case strings.EqualFold(key, "content"):
			ok = s.content(it, it.role == "" || it.role == "user")
		default:
			ok = skipJSONValue(s.dec, nil)
		}
		if !ok {
			return false
		}
	}
	_, err := s.dec.Token()
	return err == nil
}

// toolResultJSON is a "tool_result" string as sent; the full decode this
// scan replaces looked for it in the raw content of the last message.
var toolResultJSON = []byte(`"tool_result"`)

// jsonSkip consumes one JSON value through json.Decoder.Decode without
// building it (no strings are allocated); note, when set, records a
// "tool_result" string anywhere in it and size is its length as sent.
type jsonSkip struct {
	note *bool
	size int
}

func (j *jsonSkip) UnmarshalJSON(raw []byte) error {
	if j.note != nil && !*j.note && bytes.Contains(raw, toolResultJSON) {
		*j.note = true
	}
	j.size = len(bytes.TrimSpace(raw))
	return nil
}

// skipJSONValue reads one whole value. The decoder buffers that value only
// (one block, one field), never the rest of the body.
func skipJSONValue(dec *json.Decoder, note *bool) bool {
	return dec.Decode(&jsonSkip{note: note}) == nil
}

// skipJSONRest reads the rest of the value whose first token was read.
func skipJSONRest(dec *json.Decoder, first json.Token, note *bool) bool {
	switch v := first.(type) {
	case string:
		if note != nil && v == "tool_result" {
			*note = true
		}
		return true
	case json.Delim:
		if v != jsonObjectOpen && v != jsonArrayOpen {
			return false
		}
		for dec.More() {
			if v == jsonObjectOpen {
				tok, err := dec.Token()
				if err != nil {
					return false
				}
				if k, _ := tok.(string); note != nil && k == "tool_result" {
					*note = true
				}
			}
			if !skipJSONValue(dec, note) {
				return false
			}
		}
		_, err := dec.Token()
		return err == nil
	}
	return true
}

// stripReminders removes <system-reminder> blocks in one pass. The input
// is bounded first (four times the classifier cap), so a large paste costs
// linear time on a bounded string.
func stripReminders(in string) string {
	in = truncateUTF8(in, 4*routeOnlyTextCap)
	const open, closeTag = "<system-reminder>", "</system-reminder>"
	var b strings.Builder
	for {
		i := strings.Index(in, open)
		if i < 0 {
			b.WriteString(in)
			break
		}
		b.WriteString(in[:i])
		j := strings.Index(in[i:], closeTag)
		if j < 0 {
			break
		}
		in = in[i+j+len(closeTag):]
	}
	return strings.TrimSpace(b.String())
}

func capText(s string) string { return truncateUTF8(s, routeOnlyTextCap) }
