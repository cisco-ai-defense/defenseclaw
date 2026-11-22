// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"strings"
	"testing"
)

// GAP-0170: keys the launcher sent in the moment before a suspend cut the
// connection, which the relay had not counted when it greeted again, are
// reported as possibly lost (the old connection may still drain them), so
// the person checks the prompt instead of retyping keys that did arrive.
func TestKeysLostBeforeASuspendAreCounted(t *testing.T) {
	r, _, o := suspendRig(t)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("launcher stderr: %q", r.errb.String())
		}
	})
	run := r.start(o)
	waitFor(t, "screen 1", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	r.typ("ok\r")
	waitFor(t, "echo", func() bool { return strings.Contains(r.out.String(), "echo:ok") })
	r.typ("LOSE\r")
	waitFor(t, "screen 2", func() bool { return strings.Contains(r.out.String(), "screen:2") })
	waitFor(t, "reconnected with the count", func() bool {
		return strings.Contains(r.errb.String(), "Reconnected. 5 character(s) typed just before the connection dropped may not have reached the agent; check the prompt.")
	})
	r.typ("\x1d")
	if got := r.wait(run); got.err != nil || !got.res.Detached {
		t.Fatalf("%+v %v", got.res, got.err)
	}
}

// Keys the relay got before the connection dropped are not counted as lost
// (the drop itself is no loss), and a relay from before GAP-0170 (no input
// id in its hello) gets the old behaviour: nothing is claimed.
func TestDeliveredKeysAreNotCountedAsLost(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		r, _, o := suspendRig(t)
		r.relay.legacyHello = legacy
		run := r.start(o)
		waitFor(t, "screen 1", func() bool { return strings.Contains(r.out.String(), "screen:1") })
		key := "DROP\r"
		if legacy {
			key = "LOSE\r"
		}
		r.typ(key)
		waitFor(t, "screen 2", func() bool { return strings.Contains(r.out.String(), "screen:2") })
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
