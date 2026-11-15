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
}

func (h *streamHold) add(b []byte, now time.Time) {
	if len(b) == 0 {
		return
	}
	if len(h.buf) == 0 {
		h.since = now
	}
	h.buf = append(h.buf, b...)
}

// take removes and returns the first n held bytes; the rest stays held as
// if it had arrived now.
func (h *streamHold) take(n int, now time.Time) []byte {
	n = min(max(n, 0), len(h.buf))
	out := h.buf[:n:n]
	if n == len(h.buf) {
		h.buf, h.since = nil, time.Time{}
	} else if n > 0 {
		h.buf = append([]byte(nil), h.buf[n:]...)
		h.since = now
	}
	return out
}

// due reports that the oldest held byte has waited streamHoldMaxAge.
func (h *streamHold) due(now time.Time) bool {
	return len(h.buf) > 0 && !now.Before(h.since.Add(streamHoldMaxAge))
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
