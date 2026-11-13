// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// passthroughStream forwards a streamed provider reply (server-sent events,
// or the AWS eventstream of Bedrock) event by event (substrate-1 GAP-0189).
//
//   - The body is decoded as the buffered reply is: a Content-Encoding is
//     removed with a streaming decoder (decodeBody's rules), and an encoding
//     that cannot be decoded takes the fail mode.
//   - The stream is framed as the SSE specification does (sseFramer), and
//     only whole events are forwarded, so no part of an event reaches the agent
//     before the event has been read.
//   - Every string of every event (see scanReplyJSON) is handed to the
//     guardrail; the events of an open tool call are held, in action mode,
//     until the call has ended and the tool-call rules have decided, also
//     across the initial buffer; a call that cannot be held (too large) takes
//     the fail mode instead of being released.
//   - A Bedrock eventstream (InvokeModelWithResponseStream, ConverseStream) is
//     read frame by frame (bedrockEventStreamText) and forwarded in whole
//     frames. Its tool calls are assembled from the input parts and held in
//     the same way (GAP-0098); a refused stream ends with a block the agent
//     can show, in the model's own stream shape.
type passthroughStream struct {
	p              *GuardrailProxy
	w              http.ResponseWriter
	r              *http.Request
	resp           *http.Response
	mode           string
	label          string
	provider       string
	path           string
	model          string
	customBlockMsg string
	body           []byte
	promptID       string
	telemetry      ChatRequest
	bedrock        *bedrockEventStreamText
}

// snapshotEvent reports an event whose content repeats what earlier events
// of the stream carried (the finished item, the final response).
func snapshotEvent(typ string) bool {
	switch typ {
	case "response.completed", "response.created", "response.in_progress", "response.incomplete", "response.failed",
		"message_start", "message_delta", "message_stop":
		return true
	}
	return strings.HasSuffix(typ, ".done")
}

// eventContent feeds one event to the tool-call state machine and adds its
// text to the accumulated reply.
// It returns why the event can be read two ways (a repeated or differently
// spelled key), "" when it cannot.
func (s *passthroughStream) eventContent(ev sseEvent, calls *sseToolCalls, acc *strings.Builder, model *string) string {
	if !ev.HasData {
		return ""
	}
	data := ev.Data
	calls.Feed(data)
	if data == "[DONE]" {
		return ""
	}
	if *model == "" {
		*model = responseModelFromRawJSON([]byte(data))
	}
	sc, err := scanReplyJSON([]byte(data), true)
	if err != nil {
		// Not JSON: the text itself is the content.
		acc.WriteString(data)
		return ""
	}
	calls.AddCalls(sc.Calls)
	snapshot := snapshotEvent(sc.Type)
	for _, seg := range sc.Segments {
		if snapshot && strings.Contains(acc.String(), seg) {
			continue
		}
		acc.WriteString(seg)
	}
	return sc.Ambiguous
}

func (s *passthroughStream) copyHeaders() {
	for k, vs := range s.resp.Header {
		if s.bedrock != nil && http.CanonicalHeaderKey(k) == "Content-Length" {
			// A refused Bedrock stream ends with block frames of its own, so
			// the upstream length no longer holds.
			continue
		}
		for _, v := range vs {
			s.w.Header().Add(k, v)
		}
	}
	s.w.WriteHeader(s.resp.StatusCode)
}

// copyRest forwards what is left of src without inspection (the fail mode
// of an OSS install, after the alert).
func (s *passthroughStream) copyRest(src io.Reader) {
	flusher, _ := s.w.(http.Flusher)
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			_, _ = s.w.Write(buf[:n])
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *passthroughStream) run() {
	p, w, r, resp, mode, label := s.p, s.w, s.r, s.resp, s.mode, s.label
	ctx := r.Context()
	blockedReply := func(msg string) {
		out := w
		if s.bedrock != nil {
			// The reply headers are out already: the block frames follow them.
			out = &headersSentWriter{ResponseWriter: w}
		}
		p.writeBlockedPassthrough(out, s.path, s.provider, s.model, true, msg)
	}
	uninspectableMsg := blockMessage(s.customBlockMsg, "completion", "the provider reply could not be inspected")

	// One decoder: the Content-Encoding is removed before the stream is framed.
	src := io.Reader(resp.Body)
	encoded := uninspectableEncoding(resp.Header) != ""
	if encoded {
		dec, closeFn, err := newStreamDecoder(resp.Header, resp.Body)
		if err != nil {
			if p.uninspectableReply(ctx, label, mode, "content-encoding "+uninspectableEncoding(resp.Header)) {
				blockedReply(uninspectableMsg)
				return
			}
			s.copyHeaders()
			s.copyRest(resp.Body)
			return
		}
		defer closeFn()
		src = dec
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")
	}
	s.copyHeaders()

	flusher, _ := w.(http.Flusher)
	var accumulated strings.Builder
	streamResponseModel := ""
	lastScanLen := 0
	const scanInterval = 500
	const maxInitialBufBytes = 1 << 20 // 1 MiB cap on what the proxy holds back
	streamBufferSize := 1024
	if p.cfg != nil && p.cfg.StreamBufferBytes > 0 {
		streamBufferSize = p.cfg.StreamBufferBytes
	}

	var sseCalls *sseToolCalls
	if s.bedrock == nil {
		sseCalls = newSSEToolCalls()
	}
	framer := &sseFramer{}
	var queue [][]byte // events read and not yet sent
	queueBytes := 0
	relN := 0      // the first relN events of the queue may go out
	heldBytes := 0 // bytes of the events held behind an open tool call
	holding := false
	holdOff := false // the call cannot be held (too large): fail mode applied
	sseBlockMsg := ""
	brokenReported := false
	framerReported := false
	ambiguousReported := false
	streamEnded := false
	initialFlushed := mode != "action"
	preblocked := false // an SSE completion block before the first flush: nothing was sent

	writeQueue := func() {
		if relN == 0 {
			return
		}
		for _, ev := range queue[:relN] {
			_, _ = w.Write(ev)
			queueBytes -= len(ev)
		}
		queue = queue[relN:]
		if len(queue) == 0 {
			queue = nil
		}
		relN = 0
		if flusher != nil {
			flusher.Flush()
		}
	}

	// sseRefused runs the finished tool calls (of an SSE or a Bedrock stream)
	// through the rules and reports a refusal (sseBlockMsg is set).
	sseRefused := func() bool {
		if sseCalls != nil && sseCalls.Broken() && !brokenReported {
			brokenReported = true
			if p.uninspectableReply(ctx, label, mode, "a streamed tool call could not be inspected") {
				sseBlockMsg = blockMessage(s.customBlockMsg, "tool_call", "the provider reply could not be inspected")
				return true
			}
			holdOff, holding = true, false
		}
		var calls json.RawMessage
		if sseCalls != nil {
			calls = sseCalls.Take()
		} else {
			calls = s.bedrock.TakeToolCalls()
		}
		if calls == nil {
			return false
		}
		v := p.inspectToolCalls(ctx, calls)
		if v == nil {
			return false
		}
		refuse := v.Action == "block" && mode == "action"
		p.recordTelemetry(ctx, "tool-call", label, v, 0, mode, refuse)
		if !refuse {
			return false
		}
		fmt.Fprintf(os.Stderr, "[guardrail] PASSTHROUGH-STREAM-TOOL-BLOCK severity=%s %s\n", v.Severity, redaction.Reason(v.Reason))
		p.enqueueBlockNotification(v, "tool_call", s.model)
		sseBlockMsg = blockMessage(s.customBlockMsg, "tool_call", v.Reason)
		return true
	}

	flushInitial := func() bool {
		if initialFlushed || relN == 0 {
			return true
		}
		if accumulated.Len() > 0 {
			initVerdict := p.inspector.InspectMidStream(ctx, "completion", accumulated.String(),
				[]ChatMessage{{Role: "assistant", Content: accumulated.String()}}, label, mode)
			p.resolveConfirm(ctx, r, initVerdict, "completion", label, mode)
			if initVerdict.Severity != "NONE" && initVerdict.Action == "block" {
				fmt.Fprintf(os.Stderr, "[guardrail] PASSTHROUGH-STREAM-PREBLOCK severity=%s %s (blocked before any output sent to client)\n",
					initVerdict.Severity, logDisplayReason(initVerdict.Reason))
				p.recordTelemetry(ctx, "completion", label, initVerdict, 0, mode, true)
				if s.bedrock != nil {
					// The agent reads the block, not an empty stream.
					sseBlockMsg = blockMessage(s.customBlockMsg, "completion", initVerdict.Reason)
				} else {
					preblocked = true
				}
				return false
			}
		}
		lastScanLen = accumulated.Len()
		writeQueue()
		initialFlushed = true
		return true
	}

	// handle takes one event; true stops the stream.
	handle := func(ev sseEvent) bool {
		if sseCalls != nil {
			if why := s.eventContent(ev, sseCalls, &accumulated, &streamResponseModel); why != "" && !ambiguousReported {
				ambiguousReported = true
				if p.uninspectableReply(ctx, label, mode, why) {
					sseBlockMsg = uninspectableMsg
					return true
				}
			}
		}
		queue = append(queue, ev.Raw)
		queueBytes += len(ev.Raw)
		if sseCalls != nil && mode == "action" && !holdOff {
			if sseCalls.Open() {
				if !holding {
					holding = true
					relN = len(queue) - 1
					heldBytes = 0
				}
				heldBytes += len(ev.Raw)
			} else {
				holding = false
			}
		}
		if sseRefused() {
			return true
		}
		if s.bedrock != nil && mode == "action" && !holdOff {
			// The tool calls of a Bedrock stream: the bytes of an open call
			// are held until the rules decide, also across the initial buffer (GAP-0098).
			if s.bedrock.Holding() {
				if !holding {
					holding = true
					relN = len(queue) - 1
					heldBytes = 0
				}
				heldBytes += len(ev.Raw)
			} else {
				holding = false
			}
		}
		if holding && heldBytes > maxInitialBufBytes && !holdOff {
			// More is held behind the call than the proxy holds: the call
			// is not released, it takes the fail mode.
			if !brokenReported {
				brokenReported = true
				if p.uninspectableReply(ctx, label, mode, "a streamed tool call could not be inspected") {
					sseBlockMsg = blockMessage(s.customBlockMsg, "tool_call", "the provider reply could not be inspected")
					return true
				}
			}
			holdOff, holding = true, false
		}
		if !holding {
			relN = len(queue)
			heldBytes = 0
		}
		if !initialFlushed {
			if (!holding && accumulated.Len() >= streamBufferSize) || queueBytes-heldBytes > maxInitialBufBytes {
				if !flushInitial() {
					return true
				}
			}
			return false
		}
		writeQueue()
		if accumulated.Len()-lastScanLen >= scanInterval && mode == "action" {
			midVerdict := p.inspector.InspectMidStream(ctx, "completion", accumulated.String(),
				[]ChatMessage{{Role: "assistant", Content: accumulated.String()}}, label, mode)
			p.resolveConfirm(ctx, r, midVerdict, "completion", label, mode)
			if midVerdict.Severity != "NONE" && midVerdict.Action == "block" {
				fmt.Fprintf(os.Stderr, "[guardrail] PASSTHROUGH-STREAM-BLOCK severity=%s %s (WARNING: stream already forwarded to client)\n",
					midVerdict.Severity, logDisplayReason(midVerdict.Reason))
				p.recordTelemetry(ctx, "completion", label, midVerdict, 0, mode, true)
				if s.bedrock != nil {
					// The agent ends on a block it can show, not a cut stream.
					sseBlockMsg = blockMessage(s.customBlockMsg, "completion", midVerdict.Reason)
				}
				return true
			}
			lastScanLen = accumulated.Len()
		}
		return false
	}

	stopped := false
	rawTail := false          // the fail mode forwards what is left without inspection
	var bedrockPending []byte // the start of a Bedrock frame whose end has not come
	buf := make([]byte, 4096)
read:
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			var events []sseEvent
			if s.bedrock != nil {
				accumulated.WriteString(s.bedrock.Feed(chunk))
				if streamResponseModel == "" {
					streamResponseModel = s.bedrock.Model()
				}
				if s.bedrock.Broken() && !framerReported {
					framerReported = true
					if p.uninspectableReply(ctx, label, mode, "the event stream could not be framed") {
						// Nothing more of the upstream reaches the caller; a
						// block it can show takes its place.
						sseBlockMsg = uninspectableMsg
						stopped = true
						break read
					}
					// Forwarded with an alert: nothing is held any more.
					holdOff, holding = true, false
				}
				// Whole frames only (GAP-0225): the start of a frame that is cut
				// at the end of this read waits for the rest of it, so the agent
				// never gets half a frame and a block can follow a whole one.
				if why := s.bedrock.Ambiguous(); why != "" && !ambiguousReported {
					ambiguousReported = true
					if p.uninspectableReply(ctx, label, mode, why) {
						sseBlockMsg = uninspectableMsg
						stopped = true
						break read
					}
				}
				bedrockPending = append(bedrockPending, chunk...)
				keep := min(s.bedrock.PartialLen(), len(bedrockPending))
				if whole := bedrockPending[:len(bedrockPending)-keep]; len(whole) > 0 {
					events = []sseEvent{{Raw: append([]byte(nil), whole...)}}
				}
				bedrockPending = append([]byte(nil), bedrockPending[len(bedrockPending)-keep:]...)
			} else {
				events = framer.Write(chunk, false)
				if framer.Broken() && !framerReported {
					framerReported = true
					if p.uninspectableReply(ctx, label, mode, "the event stream could not be framed") {
						sseBlockMsg = uninspectableMsg
						stopped = true
						break read
					}
					rawTail = true
				}
			}
			for _, ev := range events {
				if handle(ev) {
					stopped = true
					break read
				}
			}
			if rawTail {
				break read
			}
		}
		if readErr != nil {
			if encoded && readErr != io.EOF && r.Context().Err() == nil {
				// A corrupt or oversized encoded stream cannot be read to its end.
				if p.uninspectableReply(ctx, label, mode, "the encoded stream could not be decoded") {
					sseBlockMsg = uninspectableMsg
					stopped = true
					break read
				}
			}
			streamEnded = true
			if s.bedrock != nil && len(bedrockPending) > 0 {
				// The upstream ended inside a frame: what it sent is forwarded as it is.
				pend := bedrockPending
				bedrockPending = nil
				if handle(sseEvent{Raw: pend}) {
					stopped = true
					break read
				}
			}
			if s.bedrock == nil {
				for _, ev := range framer.Write(nil, true) {
					if handle(ev) {
						stopped = true
						break read
					}
				}
			}
			break read
		}
	}

	if rawTail {
		// Let the agent have what was read, then the rest as it comes.
		relN = len(queue)
		if !initialFlushed {
			initialFlushed = true
		}
		writeQueue()
		// The bytes of the event the framer could not hold come first: the
		// agent gets every byte of the stream (GAP-0241).
		if held := framer.Held(); len(held) > 0 {
			_, _ = w.Write(held)
			if flusher != nil {
				flusher.Flush()
			}
		}
		s.copyRest(src)
		return
	}
	if preblocked {
		return
	}
	if sseBlockMsg == "" && streamEnded && !stopped {
		// The stream ended (or broke) inside a call: what is finished now is
		// checked before the held events go out.
		if sseCalls != nil {
			sseCalls.Finish()
		} else {
			s.bedrock.Finish()
		}
		sseRefused()
	}
	if sseBlockMsg == "" && streamEnded && !stopped && s.bedrock == nil && framer.DataEvents == 0 && framer.Unframed > 0 {
		// Labelled event-stream, but not framed as one: it cannot be read.
		if p.uninspectableReply(ctx, label, mode, "the event stream carried no data events") {
			sseBlockMsg = uninspectableMsg
		}
	}
	if sseBlockMsg != "" {
		// A refused tool call (or unreadable stream) never reaches the
		// agent: the whole block reply when nothing was sent yet, else the
		// block as the last assistant text of the stream under way. Held
		// events are dropped.
		if !initialFlushed {
			blockedReply(sseBlockMsg)
		} else if sseCalls != nil {
			sseCalls.writeSSEBlockTail(w, s.model, sseBlockMsg)
		} else {
			hw := &headersSentWriter{ResponseWriter: w}
			s.bedrock.writeBlockTail(hw, sseBlockMsg)
			hw.Flush()
		}
		return
	}
	if !streamEnded || stopped {
		return // a mid-stream block: what is queued is dropped
	}
	relN = len(queue)
	if !initialFlushed {
		if !flushInitial() {
			if sseBlockMsg != "" {
				blockedReply(sseBlockMsg)
			}
			return
		}
	} else {
		writeQueue()
	}

	// Final post-stream inspection on the full accumulated content.
	// Use a detached context: the request context may be cancelled after streaming.
	if accumulated.Len() > 0 {
		content := accumulated.String()
		responseReqForTelemetry := ChatRequest{Model: s.telemetry.Model, RawBody: s.body}
		responseMeta := proxyLLMEventMeta(p, r, &responseReqForTelemetry, s.provider)
		responseMeta.PromptID = s.promptID
		responseMeta.ResponseModel = streamResponseModel
		responseMeta.ResponseID = stableLLMEventID("response", responseMeta.Source, responseMeta.SessionID, responseMeta.RequestID, label)
		p.emitLLMResponseEventV8(ctx, responseMeta, content, content, nil)

		postCtx, postCancel := p.postCallContext(ctx)
		postCtx = proxyGuardrailWithoutEnforcement(postCtx)
		t0 := time.Now()
		respMessages := []ChatMessage{{Role: "assistant", Content: content}}
		verdict := p.inspector.Inspect(postCtx, "completion", content, respMessages, label, mode)
		postCancel()
		p.resolveConfirm(ctx, r, verdict, "completion", label, mode)
		elapsed := time.Since(t0)
		p.logPostCall(label, content, verdict, elapsed, nil)
		p.recordTelemetry(ctx, "completion", label, verdict, elapsed, mode, false)
		if verdict.Action == "block" {
			fmt.Fprintf(os.Stderr, "[guardrail] PASSTHROUGH-STREAM-VIOLATION severity=%s %s (stream already delivered %d bytes to client — cannot retract)\n",
				verdict.Severity, verdict.Reason, accumulated.Len())
		}
	}
}
