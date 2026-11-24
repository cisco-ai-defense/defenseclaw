// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"strings"
	"testing"
)

// rel-1-0-10:GAP-1771 (P4, RV-ATTACH2): the GAP-0170 rows on long-poll. The
// fake relay's long-poll hello had no Input or Received, so the
// "may not have reached the agent" note after a cut was tested on the
// WebSocket only.

// Long-poll: keys the relay answered but lost before the attachment ended
// are reported as possibly lost on the next hello.
func TestGAP1771PollKeysLostBeforeTheEndAreCounted(t *testing.T) {
	r, _, o := suspendRig(t)
	o.Transport = TransportLongPoll
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("launcher stderr: %q", r.errb.String())
		}
	})
	run := r.start(o)
	waitFor(t, "screen", func() bool { return strings.Contains(r.out.String(), "screen:lp") })
	r.typ("ok\r")
	waitFor(t, "echo", func() bool { return strings.Contains(r.out.String(), "echo:ok") })
	r.typ("LOSE\r")
	waitFor(t, "reconnected with the count", func() bool {
		return strings.Contains(r.errb.String(), "Reconnected. 5 character(s) typed just before the connection dropped may not have reached the agent; check the prompt.")
	})
	r.typ("\x1d")
	if got := r.wait(run); got.err != nil || !got.res.Detached {
		t.Fatalf("%+v %v", got.res, got.err)
	}
	if _, polls, _, _ := r.relay.snapshot(); polls < 2 {
		t.Fatalf("%d long-poll attachments, want a reconnect", polls)
	}
}

// Long-poll: keys the relay delivered before the attachment ended are not
// counted as lost, and a legacy hello (no input id) claims nothing.
func TestGAP1771PollDeliveredKeysAreNotCountedAsLost(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		r, _, o := suspendRig(t)
		o.Transport = TransportLongPoll
		r.relay.legacyHello = legacy
		run := r.start(o)
		waitFor(t, "screen", func() bool { return strings.Contains(r.out.String(), "screen:lp") })
		key := "DROP\r"
		if legacy {
			key = "LOSE\r"
		}
		r.typ(key)
		waitFor(t, "reconnected", func() bool { return strings.Contains(r.errb.String(), "Reconnected.") })
		r.typ("\x1d")
		if got := r.wait(run); got.err != nil || !got.res.Detached {
			t.Fatalf("legacy=%v: %+v %v", legacy, got.res, got.err)
		}
		if strings.Contains(r.errb.String(), "character(s)") {
			t.Fatalf("legacy=%v: a loss was claimed: %q", legacy, r.errb.String())
		}
	}
}
