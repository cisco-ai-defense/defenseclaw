// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// GAP-0588: with the gateway's session-seconds header the launcher renews
// the attachment before the session token ends, without the relay's cut.
func TestRenewBeforeTheSessionEndsGAP0588(t *testing.T) {
	r := newRig(t, nil)
	// 4 s left: the launcher renews RenewLead (2 s) before the end.
	r.relay.mu.Lock()
	r.relay.sessionSeconds = 2 + int(relay.RenewLead.Seconds())
	r.relay.mu.Unlock()
	run := r.start(r.options())
	waitFor(t, "screen 1", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	waitFor(t, "the planned renew", func() bool { return strings.Contains(r.out.String(), "screen:2") })
	r.typ("after\r")
	waitFor(t, "echo on the renewed connection", func() bool { return strings.Contains(r.out.String(), "echo:after") })
	r.typ("\x1d")
	got := r.wait(run)
	if got.err != nil || !got.res.Detached || got.res.Renewals < 1 {
		t.Fatalf("%+v %v", got.res, got.err)
	}
	if s := r.errb.String(); strings.Contains(s, lostMsg) || strings.Contains(s, "not sent") {
		t.Fatalf("a planned renew was reported as a loss: %q", s)
	}
	// The relay records the detach after Attach returns.
	waitFor(t, "relay saw the detach", func() bool { _, _, d, _ := r.relay.snapshot(); return d >= 1 })
	if _, _, detaches, _ := r.relay.snapshot(); detaches != 1 {
		t.Fatalf("%d detaches, want only the person's Ctrl-]: a renew is no detach", detaches)
	}
}

func TestLongPollSessionExpiryRenewsGAP0588(t *testing.T) {
	r := newRig(t, nil)
	o := r.options()
	o.Transport = TransportLongPoll
	run := r.start(o)
	waitFor(t, "screen", func() bool { return strings.Contains(r.out.String(), "screen:lp") })
	r.typ("EXPIRE\r")
	waitFor(t, "the renewed poll attachment", func() bool { return strings.Count(r.out.String(), "screen:lp") >= 2 })
	r.typ("\x1d")
	got := r.wait(run)
	if got.err != nil || !got.res.Detached || got.res.Renewals != 1 {
		t.Fatalf("%+v %v", got.res, got.err)
	}
	if s := r.errb.String(); strings.Contains(s, lostMsg) {
		t.Fatalf("a long-poll renew was reported as a loss: %q", s)
	}
	if _, polls, _, _ := r.relay.snapshot(); polls != 2 {
		t.Fatalf("%d poll attachments, want 2", polls)
	}
}

// Keys sent just before the cut that the relay had not counted are
// reported after a renew too (GAP-0170), not left for a later outage.
func TestRenewReportsKeysAtTheCutGAP0588(t *testing.T) {
	r := newRig(t, nil)
	run := r.start(r.options())
	waitFor(t, "screen 1", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	r.typ("EXPIRE-UNCOUNTED\r")
	waitFor(t, "screen 2", func() bool { return strings.Contains(r.out.String(), "screen:2") })
	waitFor(t, "the note", func() bool { return strings.Contains(r.errb.String(), "may not have reached the agent") })
	r.typ("\x1d")
	got := r.wait(run)
	if got.err != nil || !got.res.Detached || got.res.Renewals != 1 {
		t.Fatalf("%+v %v", got.res, got.err)
	}
	if s := r.errb.String(); strings.Contains(s, lostMsg) {
		t.Fatalf("a renew was reported as a loss: %q", s)
	}
}
