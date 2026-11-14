// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"strings"
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
