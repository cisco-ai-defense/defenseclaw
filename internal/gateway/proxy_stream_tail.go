// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// The tail of a streamed completion (rel-1-0-10:GAP-0212). In action mode
// the passthrough and /llm streaming paths keep the bytes no check has
// covered yet in a streamHold and send them only after a check has read
// their text: the mid-stream scan (every 500 bytes of text, as before), the
// same scan once the oldest held byte has waited streamHoldMaxAge, and at the
// end of the stream the final post-stream check, which is enforced. A final
// check that blocks withholds the tail and ends the stream as a mid-stream
// block does. Observe mode holds nothing and only records the would-block.
//
// The initial buffer (guardrail.stream_buffer_bytes of text, checked before
// anything of the reply is sent) is bounded in time too
// (rel-1-0-10:GAP-0628): when the upstream has sent nothing for
// streamHoldMaxAge while it holds reply text and no tool call is open, it
// is checked and sent, so a short reply from an upstream that then goes
// quiet is not held until the upstream ends. A stream that keeps coming,
// or a call the rules have not decided, still waits for the buffer size,
// so a block there still replaces the whole reply. The reply headers are
// sent at once: they carry no model text, and the status and headers were
// already fixed (a block after them is written as it was).
//
// The check of a held byte that is due by its age only (rel-1-0-10:GAP-0625,
// inspectStreamText) keeps the guarantee of the full check: with
// scanner_mode remote or both AI Defense reads every byte before it is
// sent. Checks run one at a time on the stream's goroutine, so at most one
// AI Defense call is in flight per stream, the bytes stay held while it
// runs, and only the text it read goes out; it counts as the full check
// for the scanInterval cadence, so the two never both ask for one text.
// With scanner_mode local the check due by age is the local rules and the
// policy with no span (a slow stream would open one every
// streamHoldMaxAge). The full mid-stream check runs every scanInterval
// bytes of text counted from the last full one, and on the initial buffer,
// at a hold bound and at the end of the stream; the final check reads the
// whole reply. So a held byte waits at most streamHoldMaxAge (plus one
// check) after it arrived, p50 about half of it on a stream that sends
// often.
//
// The hold is bounded (the bound rule, internal/guardrail/bounded). In
// time: a held byte whose text was read is checked by the mid-stream check
// and sent at most streamHoldMaxAge after it arrived (plus that one scan),
// whether or not the upstream goes on sending (no final event, an idle
// connection), so it never waits for the final event. In bytes: held bytes
// whose text was read are checked and sent at streamHoldMaxBytes. The bytes
// of one SSE event or eventstream frame that has not ended (their text
// cannot be read, and they are no event to the client yet either) are held
// until it ends. streamHoldMaxPartialAge without a new byte makes the stream
// TRUNCATED: the text read so far is still checked, then the unknown tier
// of the pack decides, once per event: the strict pack blocks and ends the
// stream; the default and permissive packs alert and keep the event held,
// since its unread bytes may start a tool call (GAP-0316). It goes out once
// it ends and is read, or never, when the request or the upstream ends.
// In size an unfinished event is bounded by its framer: an SSE event over
// sseEventMax (the framer's bound) is TRUNCATED and also takes the fail mode, since it can
// never be read whole (a managed or strict install refuses; whichever rule
// refuses wins). Otherwise that event alone is passed on unread, and the
// events after it are held and checked as before (GAP-0313). An eventstream
// frame over bedrockStreamMaxFrame breaks framing, which takes the fail mode.
//
// On the passthrough these bounds apply to the events the tool-call hold
// (substrate-1 GAP-0189, GAP-0098) has let out; an open tool call waits for
// its verdict (passthroughStream).
//
// The text bound applies to the text the check reads, not to the raw bytes
// (rel-1-0-10:GAP-0624): a line or frame that carries a large payload the
// reply extractor does not read (a base64 image result, inlineData) is read
// whole once it ends and passes like any other line. One whose extracted
// text is over streamLineMaxText is TRUNCATED the same way: its text is
// checked, then the unknown tier decides.
const (
	streamHoldMaxAge        = 100 * time.Millisecond
	streamHoldMaxBytes      = 64 << 10
	streamLineMaxText       = 1 << 20
	streamHoldMaxPartialAge = 5 * time.Second
)

// streamHold is the bytes of one streamed reply waiting for a check, in
// stream order.
type streamHold struct {
	buf   []byte
	since time.Time // arrival of the oldest held byte; zero when empty
	// marks: piece by piece, the end of the piece in buf and the length of
	// the reply text once it was read (GAP-1306, heldBeforeRun).
	marks []holdMark
}

type holdMark struct{ end, text int }

// add holds b, a piece read when the reply had text bytes of text.
func (h *streamHold) add(b []byte, now time.Time, text int) {
	if len(b) == 0 {
		return
	}
	if len(h.buf) == 0 {
		h.since = now
	}
	h.buf = append(h.buf, b...)
	h.marks = append(h.marks, holdMark{end: len(h.buf), text: text})
}

// beforeRun is how many held bytes end before the reply text offset from:
// the pieces that hold no byte of the open run starting there (GAP-1306).
func (h *streamHold) beforeRun(from int) int {
	end := 0
	for _, m := range h.marks {
		if m.text > from {
			break
		}
		end = m.end
	}
	return end
}

// take removes and returns the first n held bytes; the rest stays held as
// if it had arrived now.
func (h *streamHold) take(n int, now time.Time) []byte {
	n = min(max(n, 0), len(h.buf))
	out := h.buf[:n:n]
	if n == len(h.buf) {
		h.buf, h.since, h.marks = nil, time.Time{}, nil
	} else if n > 0 {
		h.buf = append([]byte(nil), h.buf[n:]...)
		h.since = now
		k := 0
		for k < len(h.marks) && h.marks[k].end <= n {
			k++
		}
		h.marks = append([]holdMark(nil), h.marks[k:]...)
		for i := range h.marks {
			h.marks[i].end -= n
		}
	}
	return out
}

// due reports that the oldest held byte has waited streamHoldMaxAge.
func (h *streamHold) due(now time.Time) bool {
	return len(h.buf) > 0 && !now.Before(h.since.Add(streamHoldMaxAge))
}

// streamAgeInspector is an inspector with its own check for a stream hold
// that is due by age only (GuardrailInspector.InspectMidStreamAgeDue); full
// reports that it was the full check.
type streamAgeInspector interface {
	InspectMidStreamAgeDue(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) (*ScanVerdict, bool)
}

// inspectStreamText is the mid-stream check of a streamed reply's text.
// full: the check is due by text, a bound or the end (InspectMidStream);
// otherwise only a held byte's age made it due (InspectMidStreamAgeDue when
// the inspector has it, GAP-0625). ranFull reports that the full check ran.
func (p *GuardrailProxy) inspectStreamText(ctx context.Context, content, model, mode string, full bool) (v *ScanVerdict, ranFull bool) {
	msgs := []ChatMessage{{Role: "assistant", Content: content}}
	if !full {
		if li, ok := p.inspector.(streamAgeInspector); ok {
			return li.InspectMidStreamAgeDue(ctx, "completion", content, msgs, model, mode)
		}
	}
	return p.inspector.InspectMidStream(ctx, "completion", content, msgs, model, mode), true
}

// midStreamFinalInspector is an inspector that says whether its mid-stream
// check decides as its final check (GuardrailInspector.MidStreamDecidesAsFinal).
type midStreamFinalInspector interface {
	MidStreamDecidesAsFinal() bool
}

// initialEarlyRelease reports that the initial buffer of a stream may go out
// before the stream ends, once the upstream went quiet (GAP-0628): only when
// the mid-stream check that reads it decides as the final check, so a reply
// the final check would refuse whole is not sent first. An inspector that
// does not say keeps the initial buffer to the end, as before.
func (p *GuardrailProxy) initialEarlyRelease() bool {
	fi, ok := p.inspector.(midStreamFinalInspector)
	return ok && fi.MidStreamDecidesAsFinal()
}

// streamHoldTimer is the one timer of a stream's hold.
type streamHoldTimer struct{ t *time.Timer }

// wait arms the timer for deadline and returns its channel; nil (never
// ready) for a zero deadline.
func (s *streamHoldTimer) wait(deadline, now time.Time) <-chan time.Time {
	if deadline.IsZero() {
		if s.t != nil {
			s.t.Stop()
		}
		return nil
	}
	d := deadline.Sub(now)
	if s.t == nil {
		s.t = time.NewTimer(d)
	} else {
		s.t.Reset(d)
	}
	return s.t.C
}

func (s *streamHoldTimer) stop() {
	if s.t != nil {
		s.t.Stop()
	}
}

// streamTailTruncatedVerdict is the verdict of a stream whose held line or
// frame passed a hold bound (cap, why names it): TRUNCATED, the unknown tier
// of the request's pack. The caller has already checked the text read
// before the bound.
func (p *GuardrailProxy) streamTailTruncatedVerdict(ctx context.Context, cap bounded.Cap, why string) *ScanVerdict {
	var trunc bounded.Truncated
	trunc.Hit(cap)
	set := trunc.Set()
	tier := bounded.TierDefault
	if cfg := proxyDecisionConfig(ctx); cfg != nil {
		tier = bounded.TierOf(cfg.HookPolicyTierForConnector(p.proxyRequestConnector(ctx)))
	}
	v := &ScanVerdict{
		Action: bounded.Floor(bounded.Allow, set, tier).String(), Severity: "MEDIUM", Scanner: "proxy",
		Reason:   fmt.Sprintf("%s (%s): %s", boundedTruncatedTitle, set.Reason(), why),
		Findings: []string{evaluationLimitRuleID + ":" + boundedTruncatedTitle + " (" + set.Reason() + ")"},
	}
	if v.Action == bounded.Block.String() {
		v.Severity = "HIGH"
	}
	return v
}
