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

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
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
//   - The tail hold (rel-1-0-10:GAP-0212, proxy_stream_tail.go) sits on top
//     of the tool-call hold: in action mode an event the tool-call hold lets
//     out still waits until a mid-stream check has read its text, and the
//     final check is enforced, so a block withholds the events still held.
//     Its bounds (streamHoldMaxAge, streamHoldMaxBytes, the unfinished-event
//     bounds) apply only to the events the tool-call hold has let out: while
//     a call is held, it waits for its verdict, capped by the call's own
//     1 MiB fail mode and the request context.
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
	// ndjson: a native Ollama stream, one JSON event per line (GAP-0370).
	ndjson bool
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
// text to the accumulated reply: the typed fields of the provider, each in
// its lane (streamEventPieces, GAP-0370), and every other string the walker
// reads (withWalkerPieces).
// It returns why the event can be read two ways (a repeated or differently
// spelled key), "" when it cannot.
func (s *passthroughStream) eventContent(ev sseEvent, calls *sseToolCalls, acc *responseText, model *string) string {
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
	typed := streamEventPieces(data, s.provider)
	sc, err := scanReplyJSON([]byte(data), true, s.p.maxBodyValues())
	if err != nil {
		// Not JSON: the text itself is the content.
		acc.AddAll(withWalkerPieces(typed, []string{data}))
		return ""
	}
	calls.AddCalls(sc.Calls)
	segs := sc.Segments
	if snapshotEvent(sc.Type) {
		// A snapshot repeats what earlier events carried.
		kept := segs[:0:0]
		for _, seg := range segs {
			if !strings.Contains(acc.String(), seg) {
				kept = append(kept, seg)
			}
		}
		segs = kept
	}
	acc.AddAll(withWalkerPieces(typed, segs))
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

// streamRead is one read of the upstream reply on the reader goroutine; a
// panic in Read is handed back to the handler goroutine.
type streamRead struct {
	b     []byte
	err   error
	panic any
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
		// Deferred first, so it runs after the reader goroutine has ended.
		defer closeFn()
		src = dec
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")
	}
	s.copyHeaders()

	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		// The reply headers carry no model text: the client has them at
		// once, also while the initial buffer waits (GAP-0628).
		flusher.Flush()
	}
	var accumulated responseText
	streamResponseModel := ""
	lastScanLen := 0
	// lastFullScanLen is the text the last full mid-stream check read: the
	// scanInterval cadence counts from it, so a check due by age only (the
	// local one) does not put off AI Defense (GAP-0625).
	lastFullScanLen := 0
	const scanInterval = 500
	const maxInitialBufBytes = 1 << 20 // 1 MiB cap on what the proxy holds back
	streamBufferSize := 1024
	if p.cfg != nil && p.cfg.StreamBufferBytes > 0 {
		streamBufferSize = p.cfg.StreamBufferBytes
	}

	var sseCalls *sseToolCalls
	if s.bedrock == nil {
		sseCalls = newSSEToolCalls(p.maxBodyValues())
	}
	framer := &sseFramer{ndjson: s.ndjson}
	// tail is the wire shape of the block tail; sent is what the agent got
	// of the content blocks, from the marks of the events sent (GAP-1206).
	tail := streamTailOf(s.path, s.provider, s.ndjson)
	sent := newStreamSent()
	var bedrockPending []byte  // the start of a Bedrock frame whose end has not come
	var queue [][]byte         // events read and not yet sent
	var queueAt []time.Time    // when each event of the queue was read
	var queueMark []streamMark // the content blocks each event of the queue opens or closes
	var queueText []int        // the text length once each event of the queue was read (GAP-1306)
	// heldCut: the held bound behind an open token or digit run was passed;
	// only the first heldCut events may go out, the rest holds the run
	// (GAP-1306). -1: no cut.
	heldCut := -1
	queueBytes := 0
	relN := 0      // the first relN events of the queue are not held behind an open tool call
	heldBytes := 0 // bytes of the events held behind an open tool call
	callHold := false
	holdOff := false // the call cannot be held (too large): fail mode applied
	// The tail hold (GAP-0212): in action mode the first relN events are
	// sent only by a check that has read their text.
	tailHold := mode == "action"
	// earlyInitial: the initial buffer may go out once the upstream went
	// quiet (GAP-0628, initialEarlyRelease).
	earlyInitial := tailHold && p.initialEarlyRelease()
	var holdTimer streamHoldTimer
	defer holdTimer.stop()
	var lastRead time.Time // when the upstream last sent a byte
	// stallReported: the event in progress passed the stall bound and its
	// TRUNCATED alert is recorded; it stays held (GAP-0316).
	stallReported := false
	// overText: the event being handled carried more than streamLineMaxText
	// bytes of text (GAP-0624).
	overText := false
	released := 0 // bytes sent to the agent
	sseBlockMsg := ""
	brokenReported := false
	framerReported := false
	// frameCutReported: the stream ended inside a Bedrock frame and that cut
	// took the fail mode (one alert per cut).
	frameCutReported := false
	ambiguousReported := false
	streamEnded := false
	initialFlushed := mode != "action"
	// secretOpen: the text ended inside an open secret when last read;
	// secretKey: that secret is a private-key block; textAt is when the text
	// last grew (GAP-0429).
	secretOpen, secretKey := false, false
	var textAt time.Time
	textMark := 0
	// keepAt: when the client last got a keep-alive or a masked release
	// behind an open token or digit run; maskedRuns: lane to the start and
	// end of the run a masked release covered (GAP-1307, stream_keepalive.go).
	var keepAt time.Time
	maskedRuns := map[int][2]int{}

	writeQueue := func() {
		n := relN
		if heldCut >= 0 {
			n, heldCut = min(n, heldCut), -1
		}
		if n == 0 {
			return
		}
		for i, ev := range queue[:n] {
			_, _ = w.Write(ev)
			queueBytes -= len(ev)
			released += len(ev)
			sent.add(queueMark[i])
		}
		queue, queueAt, queueMark, queueText = queue[n:], queueAt[n:], queueMark[n:], queueText[n:]
		if len(queue) == 0 {
			queue, queueAt, queueMark, queueText = nil, nil, nil, nil
		}
		relN -= n
		if flusher != nil {
			flusher.Flush()
		}
	}
	sendRaw := func(b []byte) {
		if len(b) == 0 {
			return
		}
		_, _ = w.Write(b)
		released += len(b)
		if flusher != nil {
			flusher.Flush()
		}
	}
	// unread is the bytes of the event in progress (an SSE event or a
	// Bedrock frame that has not ended): no event to the agent yet, and
	// never sent before it ends and is read.
	unread := func() int {
		if s.bedrock != nil {
			return len(bedrockPending)
		}
		return len(framer.Held())
	}
	// endBlock ends a refused stream: the whole block reply when nothing was
	// sent yet, else the block as the last assistant text of the stream
	// under way, in its own shape after the last content block the agent
	// got (GAP-1206). Held events are dropped.
	endBlock := func() {
		switch {
		case released == 0:
			blockedReply(sseBlockMsg)
		case sseCalls != nil:
			writeStreamBlockTail(w, tail, sseCalls, sent, s.model, sseBlockMsg)
		default:
			hw := &headersSentWriter{ResponseWriter: w}
			s.bedrock.writeBlockTail(hw, sent.bedrock+1, sseBlockMsg)
			hw.Flush()
		}
	}
	// completionBlock records the shape of a completion block: the agent of
	// a Bedrock stream reads the block, an SSE stream ends where it is.
	completionBlock := func(reason string) {
		if s.bedrock != nil {
			sseBlockMsg = blockMessage(s.customBlockMsg, "completion", reason)
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
			holdOff, callHold = true, false
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
		p.enqueueBlockNotification(ctx, v, "tool_call", s.model)
		sseBlockMsg = blockMessage(s.customBlockMsg, "tool_call", v.Reason)
		return true
	}

	// scanText runs the mid-stream check over the whole text when text
	// arrived since the last one: the full check, or (full false) the
	// check of a hold due by age only (inspectStreamText). False: it
	// blocked.
	scanText := func(full bool) bool {
		if accumulated.Len() <= lastScanLen {
			return true
		}
		midVerdict, ranFull := p.inspectStreamText(ctx, accumulated.CheckText(), label, mode, full)
		p.resolveConfirm(ctx, r, midVerdict, "completion", label, mode)
		if midVerdict.Severity != "NONE" && midVerdict.Action == "block" {
			fmt.Fprintf(os.Stderr, "[guardrail] PASSTHROUGH-STREAM-BLOCK severity=%s %s (WARNING: %d bytes already forwarded to client, %d held back)\n",
				midVerdict.Severity, logDisplayReason(midVerdict.Reason), released, queueBytes+unread())
			p.recordTelemetry(ctx, "completion", label, midVerdict, 0, mode, true)
			completionBlock(midVerdict.Reason)
			return false
		}
		lastScanLen = accumulated.Len()
		if ranFull {
			lastFullScanLen = lastScanLen
		}
		return true
	}
	// boundHit is the verdict of a hold bound: TRUNCATED, the unknown tier
	// of the request's pack. The caller has checked the text read before the
	// bound. False: the stream is cut.
	var boundHit func(c bounded.Cap, why string) bool
	// secretBound decides an open secret at a hold bound (GAP-0429): the
	// text read so far is checked, then boundHit. That secret is not held
	// any more. False: the stream is cut.
	secretBound := func(c bounded.Cap, why string) bool {
		if !scanText(true) {
			return false
		}
		accumulated.ReleaseOpenSecret()
		secretOpen, secretKey = false, false
		return boundHit(c, why)
	}
	// maskParkedReasoning preserves an unresolved reasoning run without
	// holding unrelated answer events behind it (GAP-2170). The existing
	// lane-aware mask validator refuses an event it cannot rewrite safely.
	maskParkedReasoning := func() bool {
		// Anthropic and Bedrock sign thinking blocks. A masked byte with the
		// original signature breaks the next tool turn. Only OpenAI reasoning
		// is unsigned, so signed providers keep the original queued hold.
		if s.provider != "openai" || relN == 0 {
			return false
		}
		runs := accumulated.ParkedReasoningRuns()
		masked, ok := s.maskHeld(queue[:relN], relN, runs, maskedRuns)
		if !ok {
			return false
		}
		for i, ev := range masked {
			queueBytes += len(ev) - len(queue[i])
			queue[i] = ev
		}
		for _, run := range runs {
			maskedRuns[run.lane] = [2]int{run.start, run.start + len(run.text)}
		}
		return true
	}
	// secretWait reports that nothing may be sent now: the text ends inside
	// an open secret (rel-1-0-10:GAP-0429, stream_secret_hold.go). ok is
	// false when a bound on it blocked.
	secretWait := func() (wait, ok bool) {
		heldCut = -1
		if !tailHold {
			return false, true
		}
		o := accumulated.OpenSecret()
		secretOpen, secretKey = o.open, o.pem
		if o.reasoningOnly && maskParkedReasoning() {
			secretOpen = false
			return false, true
		}
		switch {
		case !o.open:
			return false, true
		case o.overCap:
			return false, secretBound(bounded.Bytes, fmt.Sprintf("a private-key block in a reply stream over %d bytes", streamSecretMaxPEM))
		case queueBytes > streamSecretMaxHeld && o.pem:
			return false, secretBound(bounded.Bytes, fmt.Sprintf("over %d reply stream bytes held behind an open secret", streamSecretMaxHeld))
		case queueBytes > streamSecretMaxHeld:
			// Only a token or a digit run is open (GAP-1265): the events
			// before the one with the run's first byte go out once the
			// check has read them, with no verdict, and the run stays held
			// (GAP-1306). When the events from the run's first byte are
			// over the bound themselves, the bound decides the run
			// (TRUNCATED, GAP-1767), then all go. When only reasoning runs parked
			// by the switch to the answer are open (o.answerParkedOnly,
			// GAP-2170: parked until the message ends while the answer
			// streams behind it), all go out as rel does, with no verdict: a
			// benign answer over the bound after thinking that ends in a
			// number is not cut. A run parked at a block end or a tool switch
			// keeps the verdict (GAP-2218).
			if k := heldBeforeRun(queueText, accumulated.OpenRunFrom()); k > 0 && queueBytes-bufferedBytes(queue[:k]) <= streamSecretMaxHeld {
				heldCut = k
				return false, true
			}
			if o.answerParkedOnly {
				return false, true
			}
			return false, secretBound(bounded.Bytes, streamRunHeldWhy)
		}
		return true, true
	}
	// checkHeld sends the events the tool-call hold lets out, once a check
	// (full, or the one due by age) has read their text and it ends inside
	// no open secret. False: the check blocked and nothing is sent.
	checkHeld := func(full bool) bool {
		if wait, ok := secretWait(); !ok || wait {
			return ok
		}
		if !scanText(full) {
			return false
		}
		writeQueue()
		return true
	}
	// keepHeld is the quiet bound of events held behind an open token or
	// digit run (GAP-1307): a content-free event of the stream's framing
	// (option a), else the held events, checked, with the run masked
	// (option b). The run stays held. False: the check blocked.
	keepHeld := func() bool {
		keepAt = time.Now()
		if ka := s.keepAlive(released > 0); ka != nil {
			_, _ = w.Write(ka)
			if flusher != nil {
				flusher.Flush()
			}
			return true
		}
		if !scanText(true) {
			return false
		}
		runs := accumulated.OpenRuns()
		// Bedrock reasoning can be signed and must reach the client unchanged.
		// Other Bedrock lanes still use the masked quiet release of GAP-1307.
		if s.provider == "bedrock" {
			for _, run := range runs {
				if run.key.field == responseFieldReasoning {
					return true
				}
			}
		}
		masked, ok := s.maskHeld(queue[:relN], relN, runs, maskedRuns)
		if !ok {
			return true // it cannot be masked: everything stays held
		}
		for i, ev := range masked {
			queueBytes += len(ev) - len(queue[i])
			queue[i] = ev
		}
		for _, run := range runs {
			maskedRuns[run.lane] = [2]int{run.start, run.start + len(run.text)}
		}
		initialFlushed = true
		writeQueue()
		return true
	}
	boundHit = func(c bounded.Cap, why string) bool {
		tv := p.streamTailTruncatedVerdict(ctx, c, why)
		p.recordTelemetry(ctx, "completion", label, tv, 0, mode, tv.Action == "block")
		if tv.Action == "block" {
			fmt.Fprintf(os.Stderr, "[guardrail] PASSTHROUGH-STREAM-BLOCK %s (%d bytes already forwarded to client, %d held back)\n",
				logDisplayReason(tv.Reason), released, queueBytes+unread())
			completionBlock(tv.Reason)
			return false
		}
		fmt.Fprintf(os.Stderr, "[guardrail] PASSTHROUGH-STREAM-TRUNCATED %s: forwarded with an alert\n", logDisplayReason(tv.Reason))
		return true
	}
	// truncateOverText decides an event with more than streamLineMaxText
	// bytes of text before any of it is sent (GAP-0624): its whole text is
	// checked, then the unknown tier decides.
	truncateOverText := func() bool {
		overText = false
		return scanText(true) && boundHit(bounded.Bytes, fmt.Sprintf("a reply stream line or frame with over %d bytes of text", streamLineMaxText))
	}
	// truncateStalled is the stall bound of an event in progress that got no
	// new byte for streamHoldMaxPartialAge: the events before it are checked
	// and sent, then the unknown tier decides, once per event. A block ends
	// the stream. An alert keeps the event held (GAP-0316): its bytes are not
	// read, and it may be the first event of a tool call the hold has not
	// seen yet, so they go out only once it ends and is read (the tool-call
	// rules decide first), or never, when the request or the upstream ends.
	// Only called with nothing queued.
	truncateStalled := func() bool {
		if !checkHeld(true) || !boundHit(bounded.Time, fmt.Sprintf("a reply stream line or frame unfinished, no new byte for %s", streamHoldMaxPartialAge)) {
			return false
		}
		stallReported = true
		return true
	}
	// sseOversize decides an SSE event over the framer's bound (sseEventMax,
	// the one bound of an unfinished event): it can never be read whole. The
	// text read before it is checked, then the bound rule decides (TRUNCATED,
	// the unknown tier of the pack), then the fail mode (a managed or strict
	// install refuses); whichever refuses wins. True: that event alone is
	// passed on unread, after the alerts (GAP-0241); the events after it are
	// held and checked as before, and the final check is still enforced
	// (GAP-0313).
	sseOversize := func() bool {
		if tailHold && (!scanText(true) || !boundHit(bounded.Bytes, fmt.Sprintf("a reply stream line or frame unfinished at %d bytes", sseEventMax))) {
			return false
		}
		if p.uninspectableReply(ctx, label, mode, "the event stream could not be framed") {
			sseBlockMsg = uninspectableMsg
			return false
		}
		return true
	}

	// flushInitial checks the initial buffer and sends it; at the end of the
	// stream it only checks it: its events wait for the final check.
	flushInitial := func(atEnd bool) bool {
		if initialFlushed || (relN == 0 && !atEnd) {
			return true
		}
		if !atEnd {
			if wait, ok := secretWait(); !ok || wait {
				return ok
			}
		}
		if accumulated.Len() > lastScanLen {
			checkContent := accumulated.CheckText()
			initVerdict := p.inspector.InspectMidStream(ctx, "completion", checkContent,
				[]ChatMessage{{Role: "assistant", Content: checkContent}}, label, mode)
			p.resolveConfirm(ctx, r, initVerdict, "completion", label, mode)
			if initVerdict.Severity != "NONE" && initVerdict.Action == "block" {
				fmt.Fprintf(os.Stderr, "[guardrail] PASSTHROUGH-STREAM-PREBLOCK severity=%s %s (blocked before any output sent to client)\n",
					initVerdict.Severity, logDisplayReason(initVerdict.Reason))
				p.recordTelemetry(ctx, "completion", label, initVerdict, 0, mode, true)
				// The agent of a Bedrock stream reads the block, not an empty stream.
				completionBlock(initVerdict.Reason)
				return false
			}
		}
		lastScanLen = accumulated.Len()
		lastFullScanLen = lastScanLen
		initialFlushed = true
		if !atEnd {
			writeQueue()
		}
		return true
	}

	// unreadEvent passes on a piece of an SSE event over sseEventMax. At its
	// first piece the event is decided (sseOversize); the events before it
	// go out first, checked. An open tool call cannot be held past it: the
	// call takes its fail mode, as one over the hold cap does.
	unreadEvent := func(ev sseEvent) bool {
		if ev.UnreadStart {
			if callHold && !holdOff {
				if !brokenReported {
					brokenReported = true
					if p.uninspectableReply(ctx, label, mode, "a streamed tool call could not be inspected") {
						sseBlockMsg = blockMessage(s.customBlockMsg, "tool_call", "the provider reply could not be inspected")
						return true
					}
				}
				holdOff, callHold = true, false
			}
			relN, heldBytes = len(queue), 0
			if !sseOversize() {
				return true
			}
			// sseOversize checked every byte of text read so far.
			initialFlushed = true
			writeQueue()
		}
		sendRaw(ev.Raw)
		return false
	}

	// handle takes one event; true stops the stream.
	handle := func(ev sseEvent) bool {
		stallReported = false
		if ev.Unread {
			return unreadEvent(ev)
		}
		if sseCalls != nil {
			textBefore := accumulated.Len()
			if why := s.eventContent(ev, sseCalls, &accumulated, &streamResponseModel); why != "" && !ambiguousReported {
				ambiguousReported = true
				if p.uninspectableReply(ctx, label, mode, why) {
					sseBlockMsg = blockMessage(s.customBlockMsg, "completion", replyRefusalReason(why))
					return true
				}
			}
			if accumulated.Len()-textBefore > streamLineMaxText {
				overText = true
			}
		}
		queue = append(queue, ev.Raw)
		queueAt = append(queueAt, lastRead)
		queueText = append(queueText, accumulated.Len())
		mark := noStreamMark
		switch {
		case s.bedrock != nil:
			mark.bedrock = s.bedrock.maxIndex
		case tail == streamTailAnthropic && ev.HasData:
			mark = anthropicStreamMark(ev.Data)
		}
		queueMark = append(queueMark, mark)
		queueBytes += len(ev.Raw)
		if sseCalls != nil && mode == "action" && !holdOff {
			if sseCalls.Open() {
				if !callHold {
					callHold = true
					relN = len(queue) - 1
					heldBytes = 0
				}
				heldBytes += len(ev.Raw)
			} else {
				callHold = false
			}
		}
		if sseRefused() {
			return true
		}
		if s.bedrock != nil && mode == "action" && !holdOff {
			// The tool calls of a Bedrock stream: the bytes of an open call
			// are held until the rules decide, also across the initial buffer (GAP-0098).
			if s.bedrock.Holding() {
				if !callHold {
					callHold = true
					relN = len(queue) - 1
					heldBytes = 0
				}
				heldBytes += len(ev.Raw)
			} else {
				callHold = false
			}
		}
		if callHold && heldBytes > maxInitialBufBytes && !holdOff {
			// More is held behind the call than the proxy holds: the call
			// is not released, it takes the fail mode.
			if !brokenReported {
				brokenReported = true
				if p.uninspectableReply(ctx, label, mode, "a streamed tool call could not be inspected") {
					sseBlockMsg = blockMessage(s.customBlockMsg, "tool_call", "the provider reply could not be inspected")
					return true
				}
			}
			holdOff, callHold = true, false
		}
		if !callHold {
			relN = len(queue)
			heldBytes = 0
		}
		// An event over the text bound is decided before any of it is sent.
		if overText && tailHold && !truncateOverText() {
			return true
		}
		overText = false
		if !initialFlushed {
			if (!callHold && accumulated.Len() >= streamBufferSize) || queueBytes-heldBytes > maxInitialBufBytes {
				if !flushInitial(false) {
					return true
				}
			}
		}
		return false
	}

	// The upstream is read on its own goroutine, so that a held event is
	// checked and sent on time while the upstream is quiet. On return the
	// body is closed, which ends a Read that waits, and the goroutine is
	// waited for before the decoder is closed.
	reads := make(chan streamRead)
	readsDone := make(chan struct{})
	readerExited := make(chan struct{})
	go func() {
		defer close(readerExited)
		for {
			var rd streamRead
			func() {
				defer func() {
					if v := recover(); v != nil {
						rd = streamRead{err: io.ErrUnexpectedEOF, panic: v}
					}
				}()
				b := make([]byte, 4096)
				n, err := src.Read(b)
				rd = streamRead{b: b[:n], err: err}
			}()
			select {
			case reads <- rd:
			case <-readsDone:
				return
			}
			if rd.err != nil {
				return
			}
		}
	}()
	defer func() {
		close(readsDone)
		_ = resp.Body.Close()
		<-readerExited
	}()

	stopped := false
	readTotal := 0
	// reportRead tells a test that every byte read so far is handled: sent,
	// or held by the initial buffer or the tool-call hold. Events the
	// tool-call hold let out are handled once the tail hold has sent them.
	reportRead := func() {
		if p.streamReadForTest != nil && (!tailHold || !initialFlushed || relN == 0) {
			p.streamReadForTest(readTotal)
		}
	}
read:
	for {
		// The hold's time bounds, on the events the tool-call hold lets out:
		// the oldest of them waits at most streamHoldMaxAge for a check; an
		// event in progress, with nothing queued, is reported once
		// streamHoldMaxPartialAge after the last byte. The initial buffer
		// (GAP-0628) is checked and sent once the upstream has sent nothing
		// for streamHoldMaxAge, when it holds reply text and no tool call is
		// open, and only when the mid-stream check decides as the final one
		// (initialEarlyRelease): a stream that keeps coming, or a call the
		// rules have not decided, still waits for stream_buffer_bytes, so a
		// block there still replaces the whole reply.
		var deadline time.Time
		keepDue := false
		switch {
		case !tailHold:
		case secretKey:
			// An open private-key block waits for more text at most
			// streamHoldMaxPartialAge (GAP-0429).
			deadline = textAt.Add(streamHoldMaxPartialAge)
		case secretOpen && relN > 0 && (initialFlushed || accumulated.Len() >= streamBufferSize || s.bedrock == nil):
			// Held behind a token or a digit run, which has no clock: the
			// next text or the end of the stream decides it (GAP-1265).
			// After streamKeepAliveAfter of no new text the client gets a
			// keep-alive (every framing but Bedrock has one before its
			// first event), or the held events with the run masked once
			// rel would have sent them (GAP-1307).
			deadline, keepDue = laterTime(textAt, keepAt).Add(streamKeepAliveAfter), true
		case !initialFlushed:
			if earlyInitial && relN > 0 && !callHold && accumulated.Len() > 0 && !secretOpen {
				deadline = lastRead.Add(streamHoldMaxAge)
			}
		case relN > 0 && !secretOpen:
			deadline = queueAt[0].Add(streamHoldMaxAge)
		case len(queue) == 0 && unread() > 0 && !stallReported:
			deadline = lastRead.Add(streamHoldMaxPartialAge)
		}
		var rd streamRead
		select {
		case rd = <-reads:
		case <-holdTimer.wait(deadline, time.Now()):
			select {
			case rd = <-reads:
				// A read is waiting: the upstream is not quiet, the proxy
				// was busy (a long event, a slow check). The read goes
				// first; a due hold is checked with it.
			default:
				if keepDue {
					if stopped = !keepHeld(); stopped {
						break read
					}
					reportRead()
					continue
				}
				if secretKey {
					o := accumulated.OpenSecret()
					secretOpen, secretKey = o.open, o.pem
					if o.pem && !secretBound(bounded.Time,
						fmt.Sprintf("a private-key block in a reply stream unfinished, no new text for %s", streamHoldMaxPartialAge)) {
						stopped = true
						break read
					}
					if !initialFlushed {
						stopped = !flushInitial(false)
					} else if relN > 0 {
						stopped = !checkHeld(false)
					}
				} else if relN > 0 && !initialFlushed {
					// Asked again: a reload may have made the final check
					// decide more (a judge strategy); then the buffer waits.
					if earlyInitial = p.initialEarlyRelease(); earlyInitial {
						stopped = !flushInitial(false)
					}
				} else if relN > 0 {
					stopped = !checkHeld(false)
				} else if len(queue) == 0 && unread() > 0 && !stallReported {
					stopped = !truncateStalled()
				}
				if stopped {
					break read
				}
				reportRead()
				continue
			}
		case <-ctx.Done():
			// The agent is gone: nothing more is sent.
			stopped = true
			break read
		}
		if rd.panic != nil {
			panic(rd.panic)
		}
		n, readErr := len(rd.b), rd.err
		wasFlushed := initialFlushed
		if n > 0 {
			readTotal += n
			lastRead = time.Now()
			chunk := rd.b
			var events []sseEvent
			if s.bedrock != nil {
				textBefore := accumulated.Len()
				accumulated.AddAll(s.bedrock.Feed(chunk))
				if accumulated.Len()-textBefore > streamLineMaxText {
					// One read completes at most the frame in progress plus
					// 4 KiB of others, so the text it adds is that frame's.
					overText = true
				}
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
					holdOff, callHold = true, false
				}
				// Whole frames only (GAP-0225): the start of a frame that is cut
				// at the end of this read waits for the rest of it, so the agent
				// never gets half a frame and a block can follow a whole one.
				if why := s.bedrock.Ambiguous(); why != "" && !ambiguousReported {
					ambiguousReported = true
					if p.uninspectableReply(ctx, label, mode, why) {
						sseBlockMsg = blockMessage(s.customBlockMsg, "completion", replyRefusalReason(why))
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
			}
			for _, ev := range events {
				if handle(ev) {
					stopped = true
					break read
				}
			}
		}
		if accumulated.Len() > textMark {
			textAt, textMark = time.Now(), accumulated.Len()
			if secretOpen && !initialFlushed {
				// The text that ends an open secret gives the early release
				// (GAP-0628) its clock back (GAP-1265).
				o := accumulated.OpenSecret()
				secretOpen, secretKey = o.open, o.pem
			}
		}
		if readErr != nil {
			if encoded && readErr != io.EOF && ctx.Err() == nil {
				// A corrupt or oversized encoded stream cannot be read to its end.
				if p.uninspectableReply(ctx, label, mode, "the encoded stream could not be decoded") {
					sseBlockMsg = uninspectableMsg
					stopped = true
					break read
				}
			}
			streamEnded = true
			if s.bedrock != nil && len(bedrockPending) > 0 {
				// The upstream ended inside a frame: the rest of the frame cannot
				// be read, so the stream takes the fail mode. A managed install
				// refuses it (the agent reads a block); otherwise what was sent
				// is forwarded as it is, after the alert.
				if ctx.Err() == nil {
					frameCutReported = true
					if p.uninspectableReply(ctx, label, mode, "the stream ended inside a frame") {
						sseBlockMsg = uninspectableMsg
						stopped = true
						break read
					}
				}
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
			// At the end the final check reads the tail.
			break read
		}
		if n > 0 && wasFlushed {
			now := time.Now()
			if !tailHold {
				writeQueue()
			} else if full := accumulated.Len()-lastFullScanLen >= scanInterval || queueBytes-heldBytes >= streamHoldMaxBytes; full ||
				(relN > 0 && !now.Before(queueAt[0].Add(streamHoldMaxAge))) || (secretOpen && relN > 0) {
				if !checkHeld(full) {
					stopped = true
					break read
				}
			}
		}
		if n > 0 {
			reportRead()
		}
	}

	if sseBlockMsg == "" && streamEnded && !stopped {
		// The stream ended (or broke) inside a call: what is finished now is
		// checked before the held events go out.
		if sseCalls != nil {
			sseCalls.Finish()
		} else {
			s.bedrock.Finish()
		}
		if !sseRefused() && s.bedrock != nil && s.bedrock.Cut() && !frameCutReported && ctx.Err() == nil {
			// The partial call passed the rules, but the stream was cut
			// inside it: the tier's fail mode applies, as it does to an SSE
			// stream cut inside a call (sseToolCalls.Finish, GAP-0987). A cut
			// inside a frame already took it, and a client that went away
			// gets no verdict.
			if p.uninspectableReply(ctx, label, mode, "the event stream ended inside a tool call") {
				sseBlockMsg = blockMessage(s.customBlockMsg, "tool_call", "the provider reply could not be inspected")
			}
		}
	}
	if sseBlockMsg == "" && streamEnded && !stopped && s.bedrock == nil && framer.DataEvents == 0 && framer.Unframed > 0 {
		// Labelled event-stream, but not framed as one: it cannot be read.
		if p.uninspectableReply(ctx, label, mode, "the event stream carried no data events") {
			sseBlockMsg = uninspectableMsg
		}
	}
	if sseBlockMsg != "" {
		// A refused tool call, an unreadable stream or a completion block of
		// a Bedrock stream never reaches the agent.
		endBlock()
		return
	}
	if !streamEnded || stopped {
		return // a block of an SSE stream: what is queued is dropped
	}
	relN = len(queue)
	heldBytes = 0
	if !flushInitial(true) || (tailHold && !scanText(true)) {
		// The initial buffer, or the tail, got the mid-stream check every
		// byte before it got, and it blocked.
		if sseBlockMsg != "" {
			endBlock()
		}
		return
	}
	if !tailHold {
		// Observe mode holds nothing: the final check only records.
		writeQueue()
	}
	// endedInKey: the stream ended inside an open private-key block, which
	// the checks never had whole (GAP-0429); decided after the final check.
	endedInKey := tailHold && accumulated.OpenSecret().pem

	// Final post-stream inspection on the full accumulated content, enforced
	// in action mode: a block withholds the events still held and ends the
	// stream as a mid-stream block does (GAP-0212).
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
		t0 := time.Now()
		checkContent := accumulated.CheckText()
		respMessages := []ChatMessage{{Role: "assistant", Content: checkContent}}
		verdict := p.inspector.Inspect(postCtx, "completion", checkContent, respMessages, label, mode)
		postCancel()
		p.resolveConfirm(ctx, r, verdict, "completion", label, mode)
		elapsed := time.Since(t0)
		p.logPostCall(label, content, verdict, elapsed, nil)
		enforced := tailHold && verdict.Action == "block"
		p.recordTelemetry(ctx, "completion", label, verdict, elapsed, mode, enforced)
		if enforced {
			fmt.Fprintf(os.Stderr, "[guardrail] PASSTHROUGH-STREAM-BLOCK severity=%s %s (final check: %d bytes already forwarded to client, %d held back)\n",
				verdict.Severity, logDisplayReason(verdict.Reason), released, queueBytes)
			completionBlock(verdict.Reason)
			if sseBlockMsg != "" {
				endBlock()
			}
			return
		}
		if verdict.Action == "block" {
			fmt.Fprintf(os.Stderr, "[guardrail] PASSTHROUGH-STREAM-VIOLATION severity=%s %s (observe mode: stream delivered %d bytes to client)\n",
				verdict.Severity, verdict.Reason, accumulated.Len())
		}
	}
	if endedInKey {
		accumulated.ReleaseOpenSecret()
		if !boundHit(bounded.Bytes, "a reply stream ended inside a private-key block") {
			if sseBlockMsg != "" {
				endBlock()
			}
			return
		}
	}
	writeQueue()
}
