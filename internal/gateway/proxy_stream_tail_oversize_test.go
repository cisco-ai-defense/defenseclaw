// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"
)

// GAP-0313: an SSE event over the framer's bound (sseEventMax) can never be
// read whole. A strict or managed install refuses the stream at that event.
// The default and permissive packs alert, and pass on that event alone,
// unread. The events after it are still held and checked, and the final
// check is still enforced, so a blocked marker after it never reaches the
// agent, whether the mid-stream check or only the final check flags it. The
// marker arrives with the end of the stream (streamTailAtomicEnd), so the
// mid=false rows do not depend on the clock (GAP-0626).
func TestStreamTailOversizeEventKeepsTheRestInspected(t *testing.T) {
	f := streamTailFormatNamed(t, "anthropic")
	big := f.delta(streamTailProse(sseEventMax + 4096))
	last := f.delta("and then " + streamTailMarker + " ends")
	body := f.head + f.delta(streamTailProse(1440)) + big + f.delta(streamTailProse(600)) + last + f.tail + f.terminal
	for _, tier := range streamTailTiers {
		for _, mid := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/mid=%v", tier.name, mid), func(t *testing.T) {
				covSetManaged(t, tier.managed)
				up := streamTailRawUpstream(t, f, body, 32<<10)
				streamTailAtomicEnd(t, last)
				insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: mid}
				proxy := streamTailProxy(t, f.provider, insp, "action")
				out, log := streamTailServeReq(t, proxy, streamTailWithTier(streamTailRequest(t, f, "", up.URL), tier.pack, tier.managed))
				if strings.Contains(streamTailReceivedText(f, out), streamTailMarker) || strings.Contains(out, last) {
					t.Fatalf("the blocked marker after the oversized event reached the client")
				}
				if streamTailSentTerminal(f, out) {
					t.Fatalf("a refused or blocked stream ended with its terminal event")
				}
				if tier.blocks || tier.managed {
					if len(out) > sseEventMax {
						t.Fatalf("the %s tier passed on the oversized event (%d bytes)", tier.name, len(out))
					}
					if tier.blocks && !strings.Contains(log, "PASSTHROUGH-STREAM-BLOCK") {
						t.Fatalf("no block line: %s", log)
					}
					if !tier.blocks && !strings.Contains(log, "refused") {
						t.Fatalf("the managed install did not refuse the oversized event: %s", log)
					}
					return
				}
				if !strings.Contains(out, big) {
					t.Fatalf("the %s tier did not pass on the oversized event after the alert (%d bytes)", tier.name, len(out))
				}
				if !strings.Contains(out, f.delta(streamTailProse(600))) {
					t.Fatalf("the checked event after the oversized one was not sent")
				}
				if !strings.Contains(log, "PASSTHROUGH-STREAM-TRUNCATED") || !strings.Contains(log, "PASSTHROUGH-STREAM-BLOCK") {
					t.Fatalf("want a TRUNCATED alert for the oversized event and a block for the marker: %s", log)
				}
			})
		}
	}
}
