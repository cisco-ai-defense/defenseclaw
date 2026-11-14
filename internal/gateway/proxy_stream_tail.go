// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// The tail of a streamed completion (rel-1-0-10:GAP-0212). In action mode
// the passthrough and /llm streaming paths keep the bytes no check has
// covered yet in a streamHold and send them only after a check has read
// their text: the mid-stream scan (every 500 bytes of text, as before, or
// once the oldest held byte has waited streamHoldMaxAge), and at the end of
// the stream the mid-stream scan and the final post-stream check over the
// whole text; the final check is enforced. A mid-stream scan reads the text
// since the last scan plus streamScanOverlap bytes before it, not the whole
// text again (rel-1-0-10:GAP-0515: rel rescanned the whole text every 500
// bytes, quadratic in the reply length); a window that blocks is confirmed
// over the whole text (streamMidScan), so the stream is cut where rel cuts
// it (detection equality on the response corpora, long-stream variants of
// them in the three packs, and the random chunking property test). A final
// check that blocks withholds the tail and ends the stream as a mid-stream
// block does. Observe mode holds nothing and only records the would-block.
//
// The hold is bounded (the bound rule, internal/guardrail/bounded). In
// time: a held byte whose text was read is checked by the mid-stream check
// and sent at most streamHoldMaxAge after it arrived (plus that one scan),
// whether or not the upstream goes on sending (no final event, an idle
// connection), so it never waits for the final event. In bytes: held bytes
// whose text was read are checked and sent at streamHoldMaxBytes. The bytes
// of one SSE line or eventstream frame that has not ended (their text cannot
// be read, and they are no event to the client yet either) are held up to
// streamHoldMaxPartial bytes or streamHoldMaxPartialAge; past either the
// stream is TRUNCATED: the text read so far is still checked, then the
// unknown tier of the pack decides (alert and send in the default and
// permissive packs, block in the strict pack), never a silent release.
const (
	streamHoldMaxAge        = 100 * time.Millisecond
	streamHoldMaxBytes      = 64 << 10
	streamHoldMaxPartial    = 1 << 20
	streamHoldMaxPartialAge = 5 * time.Second
)

// streamScanOverlap is the text before the last scan that a mid-stream
// scan reads again with the new text, so a finding split across the two is
// read whole.
const streamScanOverlap = 4 << 10

// streamScanWindow is text from streamScanOverlap bytes before from, on a
// rune boundary.
func streamScanWindow(text string, from int) string {
	start := min(max(from-streamScanOverlap, 0), len(text))
	for start > 0 && start < len(text) && !utf8.RuneStart(text[start]) {
		start++
	}
	return text[start:]
}

// streamMidScan is the mid-stream check of a streamed reply whose text so
// far is text and whose last scan read it up to scanned: with window, the
// text since then plus streamScanOverlap before it, else the whole text. A
// window that blocks is checked again over the whole text and that verdict
// decides, so a stream is cut where the whole-text scan of rel cuts it: the
// window never misses a block of the whole text (detection equality), but
// it can block where the whole text does not, because a rule may read
// context outside the window (strict pack).
func (p *GuardrailProxy) streamMidScan(ctx context.Context, text string, scanned int, window bool, model, mode string) *ScanVerdict {
	part := text
	if window {
		part = streamScanWindow(text, scanned)
	}
	v := p.inspector.InspectMidStream(ctx, "completion", part, []ChatMessage{{Role: "assistant", Content: part}}, model, mode)
	if len(part) < len(text) && v != nil && v.Severity != "NONE" && v.Action == "block" {
		v = p.inspector.InspectMidStream(ctx, "completion", text, []ChatMessage{{Role: "assistant", Content: text}}, model, mode)
	}
	return v
}

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
// frame passed a hold bound before it ended (why names the bound):
// TRUNCATED (cap bytes or time), the unknown tier of the request's pack. The
// caller has already checked the text read before the bound.
func (p *GuardrailProxy) streamTailTruncatedVerdict(ctx context.Context, why string) *ScanVerdict {
	var trunc bounded.Truncated
	if strings.Contains(why, "unfinished") {
		trunc.Hit(bounded.Time)
	} else {
		trunc.Hit(bounded.Bytes)
	}
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
