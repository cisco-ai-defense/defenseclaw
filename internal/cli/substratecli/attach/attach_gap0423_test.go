// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"regexp"
	"strings"
	"testing"
)

// GAP-0423: while the link is down the status line names the attempt, the
// backoff before the next one and how long the link has been down.
func TestReconnectLineShowsAttemptBackoffAndDowntimeGAP0423(t *testing.T) {
	r := newRig(t, nil)
	run := r.start(r.options())
	waitFor(t, "screen 1", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	r.typ("DROP\r")
	waitFor(t, "screen 2", func() bool { return strings.Contains(r.out.String(), "screen:2") })
	r.typ("\x1d")
	if got := r.wait(run); got.err != nil || got.res.Reconnects != 1 {
		t.Fatalf("%+v %v", got.res, got.err)
	}
	line := regexp.MustCompile(`Connection lost; reconnecting: attempt 1, next in [0-9.]+m?s, down [0-9]+s \(Ctrl-\] detaches; keys typed now are offered when it is back\)\.\.\.`)
	if !line.MatchString(r.errb.String()) {
		t.Fatalf("no reconnect line with attempt, backoff and downtime: %q", r.errb.String())
	}
}
