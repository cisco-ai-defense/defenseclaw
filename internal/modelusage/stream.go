// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"bytes"
	"encoding/json"
)

const (
	// headBytes is how much of an oversize line is kept to read its event type.
	headBytes = 256
	// maxLineBytes bounds the one partial line a StreamParser keeps. A longer
	// line is dropped and counted; the response is never buffered.
	maxLineBytes = 64 << 10
	// maxTailBytes is the Gemini fallback window for non-SSE JSON streams.
	maxTailBytes = 64 << 10
)

// StreamParser reads usage out of a response stream as it is forwarded. It is
// a tee: Write never fails, never blocks, never retains the caller slice and
// holds at most one bounded partial line. SSE (messages, chat, responses,
// gemini alt=sse), NDJSON (ollama) and the AWS event stream (converse, invoke)
// are understood.
type StreamParser struct {
	family  APIFamily
	buf     []byte
	dropped int // oversize lines or frames (still read through their tail)

	// An oversize line keeps its first 256 bytes (the event type) and its
	// last maxTailBytes (the usage object comes last).
	big     bool
	head    []byte
	bigTail []byte

	u     Usage
	model string

	anth anthropicUsage // merged field by field across message_start/_delta
	// chat, responses, gemini and ollama blocks replace the previous one.
	hasBlock bool

	tail []byte // gemini non-SSE fallback
	es   eventStreamState
}

// NewStreamParser returns a parser for family f, or nil for a family that has
// no usage to read (the caller treats nil as no usage).
func NewStreamParser(f APIFamily) *StreamParser {
	switch f {
	case FamilyMessages, FamilyChat, FamilyResponses, FamilyGemini, FamilyOllama, FamilyConverse, FamilyInvoke:
		return &StreamParser{family: f}
	}
	return nil
}

// Dropped reports how many oversize lines or frames were skipped.
func (s *StreamParser) Dropped() int {
	if s == nil {
		return 0
	}
	return s.dropped
}

// Write feeds forwarded response bytes. Safe on a nil receiver.
func (s *StreamParser) Write(p []byte) {
	if s == nil || len(p) == 0 {
		return
	}
	defer func() { _ = recover() }()
	if s.family == FamilyConverse || s.family == FamilyInvoke {
		s.writeEventStream(p)
		return
	}
	if s.family == FamilyGemini {
		s.keepTail(p)
	}
	for len(p) > 0 {
		i := bytes.IndexByte(p, 0x0a)
		if i < 0 {
			s.appendPartial(p)
			return
		}
		s.appendPartial(p[:i])
		s.flushLine()
		p = p[i+1:]
	}
}

func (s *StreamParser) appendPartial(p []byte) {
	if s.big {
		appendTail(&s.bigTail, p, maxTailBytes)
		return
	}
	if len(s.buf)+len(p) > maxLineBytes {
		s.big = true
		s.dropped++
		s.head = append(s.head[:0], s.buf...)
		if room := headBytes - len(s.head); room > 0 {
			if room > len(p) {
				room = len(p)
			}
			s.head = append(s.head, p[:room]...)
		}
		if len(s.head) > headBytes {
			s.head = s.head[:headBytes]
		}
		s.bigTail = append(s.bigTail[:0], s.buf...)
		s.buf = s.buf[:0]
		appendTail(&s.bigTail, p, maxTailBytes)
		return
	}
	s.buf = append(s.buf, p...)
}

func (s *StreamParser) flushLine() {
	if s.big {
		s.big = false
		s.handleBigLine()
		s.head, s.bigTail = s.head[:0], s.bigTail[:0]
		return
	}
	line := s.buf
	s.buf = s.buf[:0]
	s.handleLine(line)
}

func (s *StreamParser) handleLine(line []byte) {
	line = bytes.TrimSpace(line)
	if bytes.HasPrefix(line, []byte("data:")) {
		line = bytes.TrimSpace(line[len("data:"):])
	}
	if len(line) == 0 || line[0] != 0x7b {
		return
	}
	s.handleJSON(line)
}

func (s *StreamParser) handleJSON(doc []byte) {
	switch s.family {
	case FamilyMessages, FamilyInvoke:
		s.handleAnthropic(doc)
	case FamilyChat:
		if !bytes.Contains(doc, []byte(`"usage"`)) || bytes.Contains(doc, []byte(`"usage":null`)) || bytes.Contains(doc, []byte(`"usage": null`)) {
			if m := chunkModel(doc); m != "" && s.model == "" {
				s.model = m
			}
			return
		}
		var c struct {
			Model       string     `json:"model"`
			ServiceTier string     `json:"service_tier"`
			Usage       *chatUsage `json:"usage"`
		}
		if json.Unmarshal(doc, &c) == nil && c.Usage != nil {
			var u Usage
			c.Usage.apply(&u)
			openAITierPartial(&u, c.ServiceTier)
			s.replace(u, c.Model)
		}
	case FamilyResponses:
		if !bytes.Contains(doc, []byte("response.completed")) && !bytes.Contains(doc, []byte("response.incomplete")) && !bytes.Contains(doc, []byte("response.failed")) {
			return
		}
		var c struct {
			Response *struct {
				Model       string          `json:"model"`
				ServiceTier string          `json:"service_tier"`
				Usage       *responsesUsage `json:"usage"`
			} `json:"response"`
		}
		if json.Unmarshal(doc, &c) == nil && c.Response != nil && c.Response.Usage != nil {
			var u Usage
			c.Response.Usage.apply(&u)
			openAITierPartial(&u, c.Response.ServiceTier)
			s.replace(u, c.Response.Model)
		}
	case FamilyGemini:
		if !bytes.Contains(doc, []byte("usageMetadata")) {
			return
		}
		var c struct {
			ModelVersion  string       `json:"modelVersion"`
			UsageMetadata *geminiUsage `json:"usageMetadata"`
		}
		if json.Unmarshal(doc, &c) == nil && c.UsageMetadata != nil {
			var u Usage
			c.UsageMetadata.apply(&u)
			s.replace(u, c.ModelVersion)
		}
	case FamilyOllama:
		if !bytes.Contains(doc, []byte(`"done":true`)) && !bytes.Contains(doc, []byte(`"done": true`)) {
			return
		}
		u := parseOllamaDoc(doc)
		s.replace(u, u.ResponseModel)
	}
}

func chunkModel(doc []byte) string {
	var c struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(doc, &c)
	return c.Model
}

// replace keeps the latest cumulative usage block.
func (s *StreamParser) replace(u Usage, model string) {
	if u.Has == 0 {
		return
	}
	s.u = u
	s.hasBlock = true
	if model != "" {
		s.model = model
	}
}

func (s *StreamParser) handleAnthropic(doc []byte) {
	if !bytes.Contains(doc, []byte("message_start")) && !bytes.Contains(doc, []byte("message_delta")) {
		if bytes.Contains(doc, []byte("amazon-bedrock-invocationMetrics")) {
			s.handleInvocationMetrics(doc)
		}
		return
	}
	var e struct {
		Type    string `json:"type"`
		Message *struct {
			Model string          `json:"model"`
			Usage *anthropicUsage `json:"usage"`
		} `json:"message"`
		Usage *anthropicUsage `json:"usage"`
	}
	if json.Unmarshal(doc, &e) != nil {
		return
	}
	switch e.Type {
	case "message_start":
		if e.Message != nil {
			if e.Message.Model != "" {
				s.model = e.Message.Model
			}
			s.mergeAnthropic(e.Message.Usage)
		}
	case "message_delta":
		s.mergeAnthropic(e.Usage)
	}
	if bytes.Contains(doc, []byte("amazon-bedrock-invocationMetrics")) {
		s.handleInvocationMetrics(doc)
	}
}

func (s *StreamParser) mergeAnthropic(in *anthropicUsage) {
	if in == nil {
		return
	}
	if in.InputTokens.ok {
		s.anth.InputTokens = in.InputTokens
	}
	if in.OutputTokens.ok {
		s.anth.OutputTokens = in.OutputTokens
	}
	if in.CacheCreationTokens.ok {
		s.anth.CacheCreationTokens = in.CacheCreationTokens
	}
	if in.CacheReadTokens.ok {
		s.anth.CacheReadTokens = in.CacheReadTokens
	}
	if in.ServiceTier != "" {
		s.anth.ServiceTier = in.ServiceTier
	}
	if in.CacheCreation != nil {
		s.anth.CacheCreation = in.CacheCreation
	}
	if in.ServerToolUse != nil {
		s.anth.ServerToolUse = in.ServerToolUse
	}
	s.hasBlock = true
}

// handleInvocationMetrics reads the Bedrock invoke-stream trailer, used only
// when the Anthropic events carried no usage.
func (s *StreamParser) handleInvocationMetrics(doc []byte) {
	var m struct {
		Metrics *struct {
			In  optInt `json:"inputTokenCount"`
			Out optInt `json:"outputTokenCount"`
		} `json:"amazon-bedrock-invocationMetrics"`
	}
	if json.Unmarshal(doc, &m) != nil || m.Metrics == nil {
		return
	}
	if !s.anth.InputTokens.ok {
		s.anth.InputTokens = m.Metrics.In
	}
	if !s.anth.OutputTokens.ok {
		s.anth.OutputTokens = m.Metrics.Out
	}
	s.hasBlock = true
}

func (s *StreamParser) keepTail(p []byte) { appendTail(&s.tail, p, maxTailBytes) }

// Usage finalises and returns the usage read so far. Call it after the body
// ended. Safe on a nil receiver (returns empty Usage).
func (s *StreamParser) Usage() Usage {
	if s == nil {
		return Usage{}
	}
	defer func() { _ = recover() }()
	if s.big {
		s.big = false
		s.handleBigLine()
	} else if len(s.buf) > 0 {
		s.handleLine(s.buf)
		s.buf = s.buf[:0]
	}
	var u Usage
	switch s.family {
	case FamilyMessages, FamilyInvoke:
		if s.hasBlock {
			s.anth.apply(&u)
		}
	case FamilyConverse:
		u = s.u
	default:
		u = s.u
		if s.family == FamilyGemini && u.Has == 0 {
			u = usageFromTail(FamilyGemini, s.tail)
		}
	}
	if u.Has != 0 {
		u.Source = SourceStreamFinal
	}
	if s.model != "" {
		u.ResponseModel = s.model
	}
	u.seal()
	return u
}

// appendTail keeps the last max bytes of everything appended.
func appendTail(dst *[]byte, p []byte, max int) {
	if len(p) >= max {
		*dst = append((*dst)[:0], p[len(p)-max:]...)
		return
	}
	if over := len(*dst) + len(p) - max; over > 0 {
		*dst = append((*dst)[:0], (*dst)[over:]...)
	}
	*dst = append(*dst, p...)
}

// lastObject returns the JSON object that follows the last occurrence of
// "key": in tail that is followed by an object, or nil. It walks back over
// earlier matches (a metadata string value can contain the key) and
// brace-matches ignoring braces inside strings.
func lastObject(tail []byte, key string) []byte {
	k := []byte(`"` + key + `"`)
	end := len(tail)
	for end > 0 {
		i := bytes.LastIndex(tail[:end], k)
		if i < 0 {
			return nil
		}
		end = i
		if obj := objectAfter(tail[i+len(k):]); obj != nil {
			return obj
		}
	}
	return nil
}

func objectAfter(rest []byte) []byte {
	rest = bytes.TrimLeft(rest, " \t\r\n")
	if len(rest) == 0 || rest[0] != 0x3a {
		return nil
	}
	rest = bytes.TrimLeft(rest[1:], " \t\r\n")
	if len(rest) == 0 || rest[0] != 0x7b {
		return nil
	}
	depth, inStr, esc := 0, false, false
	for n, c := range rest {
		switch {
		case esc:
			esc = false
		case inStr:
			switch c {
			case 0x5c:
				esc = true
			case 0x22:
				inStr = false
			}
		case c == 0x22:
			inStr = true
		case c == 0x7b:
			depth++
		case c == 0x7d:
			depth--
			if depth == 0 {
				return rest[:n+1]
			}
		}
	}
	return nil
}

// usageFromTail reads the last usage object of a response tail for family f.
// It serves oversize stream lines, non-SSE Gemini streams and huge bodies.
func usageFromTail(f APIFamily, tail []byte) Usage {
	var u Usage
	switch f {
	case FamilyGemini:
		if obj := lastObject(tail, "usageMetadata"); obj != nil {
			var g geminiUsage
			if json.Unmarshal(obj, &g) == nil {
				g.apply(&u)
			}
		}
	case FamilyChat:
		if obj := lastObject(tail, "usage"); obj != nil {
			var c chatUsage
			if json.Unmarshal(obj, &c) == nil {
				c.apply(&u)
				openAITierPartial(&u, tailTier(tail))
			}
		}
	case FamilyResponses:
		if obj := lastObject(tail, "usage"); obj != nil {
			var r responsesUsage
			if json.Unmarshal(obj, &r) == nil {
				r.apply(&u)
				openAITierPartial(&u, tailTier(tail))
			}
		}
	case FamilyMessages, FamilyInvoke:
		if obj := lastObject(tail, "usage"); obj != nil {
			var a anthropicUsage
			if json.Unmarshal(obj, &a) == nil {
				a.apply(&u)
			}
		}
	case FamilyConverse:
		if obj := lastObject(tail, "usage"); obj != nil {
			var c converseUsage
			if json.Unmarshal(obj, &c) == nil {
				c.apply(&u)
			}
		}
	}
	return u
}

// handleBigLine reads an oversize line from its head and tail.
func (s *StreamParser) handleBigLine() {
	head := bytes.TrimSpace(s.head)
	switch s.family {
	case FamilyResponses:
		if !bytes.Contains(head, []byte("response.completed")) && !bytes.Contains(head, []byte("response.incomplete")) && !bytes.Contains(head, []byte("response.failed")) {
			return
		}
	case FamilyMessages, FamilyInvoke:
		if !bytes.Contains(head, []byte("message_delta")) && !bytes.Contains(head, []byte("message_start")) {
			return
		}
	case FamilyOllama:
		return
	}
	u := usageFromTail(s.family, s.bigTail)
	if s.family == FamilyMessages || s.family == FamilyInvoke {
		var a anthropicUsage
		if obj := lastObject(s.bigTail, "usage"); obj != nil && json.Unmarshal(obj, &a) == nil {
			s.mergeAnthropic(&a)
		}
		return
	}
	s.replace(u, "")
}
