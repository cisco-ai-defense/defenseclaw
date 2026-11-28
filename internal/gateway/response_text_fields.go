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
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// The model text of a response, read per provider (GAP-0370). A client
// receives more model text than the answer: thinking or reasoning, a
// refusal, streamed tool input, and every choice or candidate. The
// completion checks read all of it. Each run of text (one field of one
// choice) is its own lane. The canonical text keeps the lanes on separate
// lines. CheckText adds only a same-choice reasoning-to-answer boundary
// line, so unrelated choices and tool input remain separate.

type responseField uint8

const (
	responseFieldAnswer responseField = iota
	responseFieldReasoning
	responseFieldRefusal
	responseFieldToolInput
	// The spoken answer of an audio reply and code the model wrote for a
	// code-execution tool (GAP-0523).
	responseFieldTranscript
	responseFieldCode
)

// responseLane names one run of model text: a choice (or candidate), a
// field of it, and for tool input the call within the choice.
type responseLane struct {
	choice int
	field  responseField
	part   int
}

type responsePiece struct {
	lane    responseLane
	text    string
	summary bool // Responses summary is not a reasoning-to-answer boundary
	// end: the provider ended lanes of lane.choice here
	// (rel-1-0-10:GAP-2154, GAP-2162). It carries no text.
	end laneEnd
}

// laneEnd is how far a provider signal ends the lanes of a choice.
type laneEnd uint8

const (
	// laneEndNone: a text piece.
	laneEndNone laneEnd = iota
	// laneEndBlock: a content block, an output item or one of its parts
	// ended. The same lane can resume in a later block (text on both sides
	// of a tool call, interleaved thinking, Responses summary parts), so an
	// open run is parked, not ended (GAP-2162).
	laneEndBlock
	// laneEndMessage: the choice or the whole message finished; nothing more
	// of its lanes comes.
	laneEndMessage
)

// laneEndPiece says a content block of choice ended (GAP-2154, GAP-2162).
func laneEndPiece(choice int) responsePiece {
	return responsePiece{lane: responseLane{choice: choice}, end: laneEndBlock}
}

// messageEndPiece says choice finished (GAP-2154, GAP-2162).
func messageEndPiece(choice int) responsePiece {
	return responsePiece{lane: responseLane{choice: choice}, end: laneEndMessage}
}

func answerPiece(choice int, text string) responsePiece {
	return responsePiece{lane: responseLane{choice: choice, field: responseFieldAnswer}, text: text}
}

func reasoningPiece(choice int, text string) responsePiece {
	return responsePiece{lane: responseLane{choice: choice, field: responseFieldReasoning}, text: text}
}

func summaryPiece(choice, part int, text string) responsePiece {
	return responsePiece{lane: responseLane{choice: choice, field: responseFieldReasoning, part: part}, text: text, summary: true}
}

func refusalPiece(choice int, text string) responsePiece {
	return responsePiece{lane: responseLane{choice: choice, field: responseFieldRefusal}, text: text}
}

func toolInputPiece(choice, call int, text string) responsePiece {
	return responsePiece{lane: responseLane{choice: choice, field: responseFieldToolInput, part: call}, text: text}
}

// responseText accumulates the model text of a response by lane, in the
// order the lanes first appear.
type responseBoundary struct {
	reasoning, answer         int
	reasoningEnd, answerStart int
	secret                    secretLane
	line                      string // cached once the first answer line is final
	final                     bool
	// Where line comes from, while it is not final (rel-1-0-10:GAP-2219):
	// line[:leftLen] is reasoning lane bytes from leftAt, line[split:] is
	// answer lane bytes from rightAt (split is leftLen plus the joining
	// space of a line break).
	leftAt, leftLen, split, rightAt int
}

type responseText struct {
	boundaries   []responseBoundary
	lastChoice   map[int]responseLane
	lastSummary  map[int]bool
	hasReasoning map[responseLane]bool
	lanes        []*strings.Builder
	secret       []secretLane // the open-secret state of each lane (stream_secret_hold.go)
	index        map[responseLane]int
	last         int // the lane of the last text added
	parked       int // lanes with a parked run (GAP-2162)
	n            int
	joined       string
	fresh        bool
}

func (r *responseText) Add(p responsePiece) {
	if p.end != laneEndNone {
		r.endChoice(p.lane.choice, p.end == laneEndMessage)
		return
	}
	if p.text == "" {
		return
	}
	previous, hadPrevious := r.lastChoice[p.lane.choice]
	previousSummary := r.lastSummary[p.lane.choice]
	previousIndex := r.index[previous]
	i, ok := r.index[p.lane]
	if ok && i != r.last {
		r.laneMoved(p.lane)
	}
	if !ok {
		if len(r.lanes) > 0 {
			r.laneMoved(p.lane)
		}
		if r.index == nil {
			r.index = make(map[responseLane]int)
		}
		i = len(r.lanes)
		r.index[p.lane] = i
		r.lanes = append(r.lanes, &strings.Builder{})
		r.secret = append(r.secret, secretLane{})
	}
	r.secret[i].mark(r.lanes[i].Len(), r.n)
	if p.lane.field == responseFieldAnswer && hadPrevious && previous.field == responseFieldReasoning && !previousSummary {
		r.boundaries = append(r.boundaries, responseBoundary{
			reasoning: previousIndex, answer: i,
			reasoningEnd: r.lanes[previousIndex].Len(), answerStart: r.lanes[i].Len(),
		})
	}
	if !hadPrevious || previous != p.lane {
		if r.lastChoice == nil {
			r.lastChoice = make(map[int]responseLane)
		}
		r.lastChoice[p.lane.choice] = p.lane
	}
	if p.summary != previousSummary {
		if r.lastSummary == nil {
			r.lastSummary = make(map[int]bool)
		}
		r.lastSummary[p.lane.choice] = p.summary
	}
	if p.lane.field == responseFieldReasoning && !p.summary && !r.hasReasoning[p.lane] {
		if r.hasReasoning == nil {
			r.hasReasoning = make(map[responseLane]bool)
		}
		r.hasReasoning[p.lane] = true
	}
	if r.secret[i].parked {
		// The lane resumed: its run goes on and is held as before (GAP-2162).
		r.secret[i].parked = false
		r.parked--
	}
	r.lanes[i].WriteString(p.text)
	r.n += len(p.text)
	r.fresh = false
	r.last = i
	if r.parked > 0 {
		r.expireParked()
	}
}

// A lane end holds an open token or digit run until the last possible
// piece has been checked. Message ends close the run. Block ends park it
// because the same lane can resume after an interleaved block (GAP-2162).
// A switch to a tool call also parks it. A switch from reasoning to answer
// parks its open run until reasoning resumes or the message ends, while
// the answer can stream with that run masked (GAP-2170). A refusal or code ends
// reasoning at once. Private-key blocks keep their own bounds.

// streamRunParkMax is how much reply text may follow the end of a block
// while its open run stays parked (GAP-2162): about 64 KiB of stream bytes
// in the providers' delta framing, more than a tool call or a thinking
// block between two halves of a secret has in practice.
const streamRunParkMax = 8 << 10

// endChoice ends (message) or parks (block) the open run of every lane of
// choice.
func (r *responseText) endChoice(choice int, message bool) {
	for k, i := range r.index {
		if k.choice != choice {
			continue
		}
		if message {
			r.endLane(i)
		} else {
			r.parkLane(i, streamRunParkMax)
		}
	}
	if message {
		delete(r.lastChoice, choice)
		delete(r.lastSummary, choice)
		for i := range r.boundaries {
			b := &r.boundaries[i]
			if lane, ok := r.laneForIndex(b.reasoning); ok && lane.choice == choice {
				b.secret.endRun(r.boundaryLine(b))
			}
		}
	}
}

// laneMoved ends or parks open runs of the new lane's choice. A short
// answer may precede more reasoning, while a tool call may be followed by
// more of the same lane. Summary parts are marked separately so they do not
// create a reasoning-to-answer check boundary.
func (r *responseText) laneMoved(l responseLane) {
	for k, i := range r.index {
		if k.choice != l.choice || k == l {
			continue
		}
		switch {
		case k.field == responseFieldReasoning && l.field == responseFieldAnswer:
			if r.lastSummary[l.choice] {
				r.endLane(i)
			} else {
				r.parkLane(i, streamReasoningAnswerParkMax)
			}
		case k.field == responseFieldReasoning && (l.field == responseFieldRefusal || l.field == responseFieldCode):
			r.endLane(i)
		case k.field == responseFieldReasoning && l.field == responseFieldToolInput,
			k.field == responseFieldToolInput && l.field == responseFieldToolInput && k.part < l.part:
			r.parkLane(i, streamRunParkMax)
		}
	}
}

// parkLane parks the open token or digit run of lane i (GAP-2162).
// A zero limit keeps a reasoning run parked until it resumes or the message
// ends. The wire release masks only that unresolved run (GAP-2170).
const streamReasoningAnswerParkMax = 0

func (r *responseText) parkLane(i, limit int) {
	s := &r.secret[i]
	if s.parked {
		if limit < s.parkLimit {
			s.parkLimit, s.parkedAt = limit, r.n
		}
		return
	}
	if !s.token(r.lanes[i].String()) {
		return
	}
	s.parked, s.parkedAt, s.parkLimit = true, r.n, limit
	r.parked++
}

// endLane ends the open run of lane i.
func (r *responseText) endLane(i int) {
	if r.secret[i].parked {
		r.secret[i].parked = false
		r.parked--
	}
	r.secret[i].endRun(r.lanes[i].String())
}

// expireParked ends parked runs after their own bounded byte budget.
func (r *responseText) expireParked() {
	for i := range r.secret {
		if r.secret[i].parked && r.secret[i].parkLimit > 0 && r.n-r.secret[i].parkedAt > r.secret[i].parkLimit {
			r.endLane(i)
		}
	}
}

func (r *responseText) AddAll(ps []responsePiece) {
	for _, p := range ps {
		r.Add(p)
	}
}

// Len is the number of model text bytes, separators not counted.
func (r *responseText) Len() int { return r.n }

// String is the canonical telemetry and audit text: lanes one per line.
func (r *responseText) String() string {
	switch len(r.lanes) {
	case 0:
		return ""
	case 1:
		return r.lanes[0].String()
	}
	if !r.fresh {
		var sb strings.Builder
		sb.Grow(r.n + len(r.lanes))
		for i, l := range r.lanes {
			if i > 0 {
				sb.WriteByte('\n')
			}
			sb.WriteString(l.String())
		}
		r.joined, r.fresh = sb.String(), true
	}
	return r.joined
}

func (r *responseText) laneForIndex(i int) (responseLane, bool) {
	for lane, n := range r.index {
		if n == i {
			return lane, true
		}
	}
	return responseLane{}, false
}

// boundaryLine copies the last reasoning line and the first answer line at
// this switch. Both searches see at most 513 bytes. A completed line is
// cached; a newline at the boundary becomes one space (GAP-2166, GAP-2177).
func (r *responseText) boundaryLine(b *responseBoundary) string {
	if b.final {
		return b.line
	}
	const maxSide = 512
	left := r.lanes[b.reasoning].String()[:b.reasoningEnd]
	right := r.lanes[b.answer].String()[b.answerStart:]
	hadBreak := strings.HasSuffix(left, "\n") || strings.HasPrefix(right, "\n")
	final := len(right) > maxSide
	// left is only cut from the front and trimmed at the back, right the
	// other way round: leftEnd and rightAt follow the trims (GAP-2219).
	leftEnd, rightAt := b.reasoningEnd, b.answerStart
	if len(left) > maxSide+1 {
		left = left[len(left)-maxSide-1:]
		for len(left) > 0 && !utf8.RuneStart(left[0]) {
			left = left[1:]
		}
	}
	if len(right) > maxSide+1 {
		right = right[:maxSide+1]
	}
	n := len(left)
	left = strings.TrimRight(left, "\r\n")
	leftEnd -= n - len(left)
	n = len(right)
	right = strings.TrimLeft(right, "\r\n")
	rightAt += n - len(right)
	if n := strings.LastIndexByte(left, '\n'); n >= 0 {
		left = left[n+1:]
	}
	if n := strings.IndexByte(right, '\n'); n >= 0 {
		right, final = right[:n], true
	}
	if len(left) > maxSide {
		left = left[len(left)-maxSide:]
		for len(left) > 0 && !utf8.RuneStart(left[0]) {
			left = left[1:]
		}
	}
	if len(right) > maxSide {
		right, final = right[:maxSide], true
		for len(right) > 0 {
			ch, size := utf8.DecodeLastRuneInString(right)
			if ch != utf8.RuneError || size > 1 {
				break
			}
			right = right[:len(right)-1]
		}
	}
	split := len(left)
	if hadBreak {
		trimmed := strings.TrimRight(left, " \t")
		leftEnd -= len(left) - len(trimmed)
		left = trimmed
		trimmed = strings.TrimLeft(right, " \t")
		rightAt += len(right) - len(trimmed)
		right = trimmed
		b.line, split = left+" "+right, len(left)+1
	} else {
		b.line = left + right
	}
	b.leftAt, b.leftLen, b.split, b.rightAt = leftEnd-len(left), len(left), split, rightAt
	b.final = final
	return b.line
}

// boundaryRunFrom is the reply text offset of the first byte of the open
// token or digit run of boundary b's line, -1 for none: an open run there
// can start where no lane run does, the lane and the line differing in their
// word boundary (rel-1-0-10:GAP-2219).
func (r *responseText) boundaryRunFrom(b *responseBoundary) int {
	line := r.boundaryLine(b)
	if b.final {
		return -1
	}
	st := b.secret.tokenStart(line)
	switch {
	case st < 0:
		return -1
	case st < b.leftLen:
		return r.secret[b.reasoning].textAt(b.leftAt + st)
	default:
		return r.secret[b.answer].textAt(b.rightAt + max(st-b.split, 0))
	}
}

// CheckText adds only same-choice reasoning-to-answer boundaries. String
// remains byte-for-byte the telemetry and audit view (GAP-2166).
func (r *responseText) CheckText() string {
	base := r.String()
	if len(r.boundaries) == 0 {
		return base
	}
	var sb strings.Builder
	sb.Grow(len(base) + len(r.boundaries)*64)
	sb.WriteString(base)
	for i := range r.boundaries {
		if line := r.boundaryLine(&r.boundaries[i]); line != "" {
			sb.WriteString("\n\x00\n")
			sb.WriteString(line)
		}
	}
	return sb.String()
}

// Buffered chat JSON gives the answer before reasoning. Pair them for
// checks in reasoning-then-answer order without changing String.
func (r *responseText) CheckTextNonStream() string {
	base := r.CheckText()
	joined := make(map[int]bool)
	for _, boundary := range r.boundaries {
		joined[boundary.reasoning] = true
	}
	for i := range r.lanes {
		lane, ok := r.laneForIndex(i)
		if !ok || lane.field != responseFieldReasoning || !r.hasReasoning[lane] || joined[i] {
			continue
		}
		answer, ok := r.index[responseLane{choice: lane.choice, field: responseFieldAnswer}]
		if !ok {
			continue
		}
		boundary := responseBoundary{reasoning: i, answer: answer, reasoningEnd: r.lanes[i].Len()}
		if line := r.boundaryLine(&boundary); line != "" {
			base += "\n\x00\n" + line
		}
	}
	return base
}

func responsePiecesCheckText(ps []responsePiece) string {
	var r responseText
	r.AddAll(ps)
	return r.CheckTextNonStream()
}

func responsePiecesText(ps []responsePiece) string {
	var r responseText
	r.AddAll(ps)
	return r.String()
}

// respJSONString is the value of raw when it is a JSON string, else "". A field
// some providers send as an object (reasoning) then never fails the decode
// of the whole event.
func respJSONString(raw json.RawMessage) string {
	if len(raw) == 0 || raw[0] != '"' {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// jsonArgsText is tool input as the client reads it: a JSON string's value,
// or an object's JSON text.
func jsonArgsText(raw json.RawMessage) string {
	if s := respJSONString(raw); s != "" {
		return s
	}
	switch t := strings.TrimSpace(string(raw)); t {
	case "", "null", "{}", "[]", `""`:
		return ""
	default:
		return t
	}
}

// chatShapeMessage is an OpenAI chat-shaped message or delta: content (a
// string or content parts), refusal, the reasoning fields OpenAI-compatible
// servers add (reasoning_content: DeepSeek, vLLM, xAI; reasoning:
// OpenRouter, Ollama), and tool calls.
type chatShapeMessage struct {
	Content          json.RawMessage `json:"content"`
	Refusal          json.RawMessage `json:"refusal"`
	ReasoningContent json.RawMessage `json:"reasoning_content"`
	Reasoning        json.RawMessage `json:"reasoning"`
	ToolCalls        []struct {
		Index    int `json:"index"`
		Function struct {
			Arguments json.RawMessage `json:"arguments"`
		} `json:"function"`
	} `json:"tool_calls"`
	FunctionCall *legacyFunctionCall `json:"function_call"`
	Audio        *struct {
		Transcript string `json:"transcript"`
	} `json:"audio"`
}

// legacyFunctionCall is the chat function_call that came before tool_calls
// (one call per choice). Servers still send it, and its arguments are tool
// input like a tool call's (GAP-0521).
type legacyFunctionCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// legacyFunctionCallIndex keeps the legacy call apart from the tool_calls
// of the same choice.
const legacyFunctionCallIndex = -1

// toolCalls is the legacy call in the tool_calls shape, so the tool-call
// checks read it as they read any call. nil when there is none.
func (f *legacyFunctionCall) toolCalls() json.RawMessage {
	if f == nil || f.Name == "" && len(f.Arguments) == 0 {
		return nil
	}
	type fn struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	}
	b, err := json.Marshal([]struct {
		Index    int    `json:"index"`
		Type     string `json:"type"`
		Function fn     `json:"function"`
	}{{Index: legacyFunctionCallIndex, Type: "function", Function: fn{Name: f.Name, Arguments: jsonArgsText(f.Arguments)}}})
	if err != nil {
		return nil
	}
	return b
}

type chatShapeChoice struct {
	Index        int               `json:"index"`
	Delta        *chatShapeMessage `json:"delta"`
	Message      *chatShapeMessage `json:"message"`
	Text         json.RawMessage   `json:"text"` // legacy completions
	FinishReason json.RawMessage   `json:"finish_reason"`
}

// chatContentPieces reads message content: a string, or parts of type
// text, output_text or refusal.
func chatContentPieces(choice int, raw json.RawMessage) []responsePiece {
	if s := respJSONString(raw); s != "" {
		return []responsePiece{answerPiece(choice, s)}
	}
	if len(raw) == 0 || raw[0] != '[' {
		return nil
	}
	var parts []struct {
		Type    string `json:"type"`
		Text    string `json:"text"`
		Refusal string `json:"refusal"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return nil
	}
	var out []responsePiece
	for _, p := range parts {
		switch p.Type {
		case "refusal":
			out = append(out, refusalPiece(choice, p.Refusal))
		case "text", "output_text", "":
			out = append(out, answerPiece(choice, p.Text))
		}
	}
	return out
}

// chatMessagePieces reads one chat-shaped message or delta. withTools adds
// tool-call arguments: the paths that do not inspect tool calls on their
// own read them as model text.
func chatMessagePieces(choice int, m *chatShapeMessage, withTools bool) []responsePiece {
	if m == nil {
		return nil
	}
	out := chatContentPieces(choice, m.Content)
	if s := respJSONString(m.Refusal); s != "" {
		out = append(out, refusalPiece(choice, s))
	}
	if s := respJSONString(m.ReasoningContent); s != "" {
		out = append(out, reasoningPiece(choice, s))
	}
	if s := respJSONString(m.Reasoning); s != "" {
		out = append(out, reasoningPiece(choice, s))
	}
	if m.Audio != nil && m.Audio.Transcript != "" {
		out = append(out, responsePiece{lane: responseLane{choice: choice, field: responseFieldTranscript}, text: m.Audio.Transcript})
	}
	if withTools {
		for _, tc := range m.ToolCalls {
			out = append(out, toolInputPiece(choice, tc.Index, jsonArgsText(tc.Function.Arguments)))
		}
		if m.FunctionCall != nil {
			out = append(out, toolInputPiece(choice, legacyFunctionCallIndex, jsonArgsText(m.FunctionCall.Arguments)))
		}
	}
	return out
}

// chatLegacyToolCalls is the legacy function_call of every choice, in the
// tool_calls shape, per choice: for the paths that check tool calls on
// their own (GAP-0521).
func chatLegacyToolCalls(choices []chatShapeChoice) []rawForwardToolCallDelta {
	var out []rawForwardToolCallDelta
	for _, c := range choices {
		for _, m := range []*chatShapeMessage{c.Delta, c.Message} {
			if m == nil {
				continue
			}
			if tc := m.FunctionCall.toolCalls(); tc != nil {
				out = append(out, rawForwardToolCallDelta{choiceIndex: c.Index, toolCalls: tc})
			}
		}
	}
	return out
}

func chatChoicesPieces(choices []chatShapeChoice, withTools bool) []responsePiece {
	var out []responsePiece
	for _, c := range choices {
		out = append(out, chatMessagePieces(c.Index, c.Delta, withTools)...)
		out = append(out, chatMessagePieces(c.Index, c.Message, withTools)...)
		if s := respJSONString(c.Text); s != "" {
			out = append(out, answerPiece(c.Index, s))
		}
		if respJSONString(c.FinishReason) != "" {
			out = append(out, messageEndPiece(c.Index)) // GAP-2154
		}
	}
	return out
}

// llmChoicesText is the model text of every choice of an /llm response the
// provider adapter returned: content as a string or as parts (text and
// refusal). Tool calls are inspected on their own.
func llmChoicesText(choices []ChatChoice) string {
	var r responseText
	for _, c := range choices {
		if c.Message == nil {
			continue
		}
		if c.Message.Content != "" {
			r.Add(answerPiece(c.Index, c.Message.Content))
			continue
		}
		r.AddAll(chatContentPieces(c.Index, c.Message.RawContent))
	}
	return r.String()
}

// llmToolCalls is the tool calls of every choice, one array.
func llmToolCalls(choices []ChatChoice) json.RawMessage {
	var out json.RawMessage
	for _, c := range choices {
		if c.Message != nil && len(c.Message.ToolCalls) > 0 {
			out = mergeToolCallChunks(out, c.Message.ToolCalls)
		}
	}
	return out
}

// anthropicContentPieces reads Anthropic content blocks: text and thinking.
// tool_use input is inspected as a tool call.
func anthropicContentPieces(body []byte) ([]responsePiece, bool) {
	var resp struct {
		Content []struct {
			Type     string `json:"type"`
			Text     string `json:"text"`
			Thinking string `json:"thinking"`
		} `json:"content"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil, false
	}
	var out []responsePiece
	for _, c := range resp.Content {
		switch c.Type {
		case "text":
			out = append(out, answerPiece(0, c.Text))
		case "thinking":
			out = append(out, reasoningPiece(0, c.Thinking))
		}
	}
	return out, true
}

// streamEventPieces reads the model text of one streamed event of provider:
// an SSE data payload, an NDJSON line or a decoded eventstream payload.
// Streamed tool input is model text here: the passthrough stream has no
// separate tool-call check.
func streamEventPieces(data, provider string) []responsePiece {
	switch provider {
	case "anthropic":
		return anthropicStreamPieces([]byte(data))
	case "gemini":
		return geminiPieces([]byte(data), true)
	case "bedrock":
		var ev struct {
			ContentBlockDelta *bedrockStreamDelta `json:"contentBlockDelta"`
			ContentBlockStop  json.RawMessage     `json:"contentBlockStop"`
			MessageStop       json.RawMessage     `json:"messageStop"`
		}
		if json.Unmarshal([]byte(data), &ev) != nil {
			return nil
		}
		if len(ev.MessageStop) > 0 {
			return []responsePiece{messageEndPiece(0)} // GAP-2154
		}
		if len(ev.ContentBlockStop) > 0 {
			return []responsePiece{laneEndPiece(0)} // GAP-2162: a block, parked
		}
		if ev.ContentBlockDelta == nil {
			return nil
		}
		return ev.ContentBlockDelta.pieces()
	case "ollama":
		return ollamaPieces([]byte(data), true)
	default:
		var ev struct {
			Type         string            `json:"type"`
			Delta        json.RawMessage   `json:"delta"`
			OutputIndex  int               `json:"output_index"`
			SummaryIndex int               `json:"summary_index"`
			Choices      []chatShapeChoice `json:"choices"`
		}
		if json.Unmarshal([]byte(data), &ev) != nil {
			return nil
		}
		if end := responsesLaneEnd(ev.Type); end != laneEndNone {
			return []responsePiece{{end: end}} // GAP-2154, GAP-2162
		}
		if strings.HasPrefix(ev.Type, "response.") && strings.Contains(ev.Type, ".delta") {
			// OpenAI Responses: every text delta the client receives.
			text := respJSONString(ev.Delta)
			switch {
			case text == "":
				return nil
			case strings.HasPrefix(ev.Type, "response.output_text."):
				return []responsePiece{answerPiece(0, text)}
			case strings.HasPrefix(ev.Type, "response.refusal."):
				return []responsePiece{refusalPiece(0, text)}
			case strings.HasPrefix(ev.Type, "response.reasoning_summary"):
				return []responsePiece{summaryPiece(0, ev.OutputIndex, text)}
			case strings.HasPrefix(ev.Type, "response.reasoning"):
				return []responsePiece{{lane: responseLane{field: responseFieldReasoning, part: ev.OutputIndex}, text: text}}
			default:
				return []responsePiece{toolInputPiece(0, ev.OutputIndex, text)}
			}
		}
		return chatChoicesPieces(ev.Choices, true)
	}
}

// responsesLaneEnd is how far an OpenAI Responses event ends the lanes it
// streamed: the response is done (message), or an output item, its text,
// its arguments or a summary part is done (block: the lane can resume in a
// later part, GAP-2162), GAP-2154.
func responsesLaneEnd(typ string) laneEnd {
	if !strings.HasPrefix(typ, "response.") {
		return laneEndNone
	}
	switch typ {
	case "response.completed", "response.incomplete", "response.failed":
		return laneEndMessage
	}
	if strings.HasSuffix(typ, ".done") {
		return laneEndBlock
	}
	return laneEndNone
}

func anthropicStreamPieces(data []byte) []responsePiece {
	var ev struct {
		Type  string `json:"type"`
		Index int    `json:"index"`
		Delta struct {
			Text        string `json:"text"`
			Thinking    string `json:"thinking"`
			PartialJSON string `json:"partial_json"`
		} `json:"delta"`
		ContentBlock struct {
			Text     string          `json:"text"`
			Thinking string          `json:"thinking"`
			Input    json.RawMessage `json:"input"`
		} `json:"content_block"`
	}
	if json.Unmarshal(data, &ev) != nil {
		return nil
	}
	switch ev.Type {
	case "content_block_delta":
		return []responsePiece{
			answerPiece(0, ev.Delta.Text),
			reasoningPiece(0, ev.Delta.Thinking),
			toolInputPiece(0, ev.Index, ev.Delta.PartialJSON),
		}
	case "content_block_start":
		return []responsePiece{
			answerPiece(0, ev.ContentBlock.Text),
			reasoningPiece(0, ev.ContentBlock.Thinking),
			toolInputPiece(0, ev.Index, jsonArgsText(ev.ContentBlock.Input)),
		}
	case "content_block_stop":
		// The block ended; the lane can resume in a later block (GAP-2162).
		return []responsePiece{laneEndPiece(0)}
	case "message_delta", "message_stop":
		return []responsePiece{messageEndPiece(0)} // GAP-2154
	}
	return nil
}

// bedrockStreamDelta is a ConverseStream contentBlockDelta: answer text,
// reasoning text, or a fragment of tool input.
type bedrockStreamDelta struct {
	ContentBlockIndex int `json:"contentBlockIndex"`
	Delta             struct {
		Text             string `json:"text"`
		ReasoningContent struct {
			Text string `json:"text"`
		} `json:"reasoningContent"`
		ToolUse struct {
			Input string `json:"input"`
		} `json:"toolUse"`
	} `json:"delta"`
}

func (d *bedrockStreamDelta) pieces() []responsePiece {
	return []responsePiece{
		answerPiece(0, d.Delta.Text),
		reasoningPiece(0, d.Delta.ReasoningContent.Text),
		toolInputPiece(0, d.ContentBlockIndex, d.Delta.ToolUse.Input),
	}
}

// jsonArrayElements is the elements of a body that is a JSON array. A
// Gemini streamGenerateContent reply without alt=sse is one: a JSON array
// of GenerateContentResponse chunks sent as application/json (GAP-0520).
func jsonArrayElements(body []byte) ([]json.RawMessage, bool) {
	b := bytes.TrimSpace(body)
	if len(b) == 0 || b[0] != '[' {
		return nil, false
	}
	var elems []json.RawMessage
	if json.Unmarshal(b, &elems) != nil {
		return nil, false
	}
	return elems, true
}

// geminiPieces reads every candidate: answer parts, thought parts, and with
// withTools the functionCall arguments. A JSON array body is read chunk by
// chunk, as the SSE stream is read event by event.
func geminiPieces(body []byte, withTools bool) []responsePiece {
	if elems, ok := jsonArrayElements(body); ok {
		var out []responsePiece
		for _, e := range elems {
			out = append(out, geminiResponsePieces(e, withTools)...)
		}
		return out
	}
	return geminiResponsePieces(body, withTools)
}

func geminiResponsePieces(body []byte, withTools bool) []responsePiece {
	var resp struct {
		Candidates []struct {
			Index        *int   `json:"index"`
			FinishReason string `json:"finishReason"`
			Content      struct {
				Parts []struct {
					Text         string `json:"text"`
					Thought      bool   `json:"thought"`
					FunctionCall *struct {
						Args json.RawMessage `json:"args"`
					} `json:"functionCall"`
					ExecutableCode *struct {
						Code string `json:"code"`
					} `json:"executableCode"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil
	}
	var out []responsePiece
	for ci, c := range resp.Candidates {
		choice := ci
		if c.Index != nil {
			choice = *c.Index
		}
		for pi, p := range c.Content.Parts {
			if p.Thought {
				out = append(out, reasoningPiece(choice, p.Text))
			} else {
				out = append(out, answerPiece(choice, p.Text))
			}
			if withTools && p.FunctionCall != nil {
				out = append(out, toolInputPiece(choice, pi, jsonArgsText(p.FunctionCall.Args)))
			}
			if p.ExecutableCode != nil && p.ExecutableCode.Code != "" {
				// Code execution has no tool-call check: its code is read as
				// model text on every path.
				out = append(out, responsePiece{lane: responseLane{choice: choice, field: responseFieldCode, part: pi}, text: p.ExecutableCode.Code})
			}
		}
		if c.FinishReason != "" {
			out = append(out, messageEndPiece(choice)) // GAP-2154
		}
	}
	return out
}

// ollamaPieces reads native Ollama chat and generate: content or response,
// thinking, and with withTools the tool-call arguments.
func ollamaPieces(body []byte, withTools bool) []responsePiece {
	var resp struct {
		Message struct {
			Content   string `json:"content"`
			Thinking  string `json:"thinking"`
			ToolCalls []struct {
				Function struct {
					Arguments json.RawMessage `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
		Response string `json:"response"`
		Thinking string `json:"thinking"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil
	}
	out := []responsePiece{
		answerPiece(0, resp.Message.Content),
		answerPiece(0, resp.Response),
		reasoningPiece(0, resp.Message.Thinking),
		reasoningPiece(0, resp.Thinking),
	}
	if withTools {
		for i, tc := range resp.Message.ToolCalls {
			out = append(out, toolInputPiece(0, i, jsonArgsText(tc.Function.Arguments)))
		}
	}
	return out
}
