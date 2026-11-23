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
	"net/http"
	"strings"
	"testing"
)

// GAP-0588: the gateway caps a relay session token at the end of the
// sign-in, so the relay ends attachments with "session token expired"
// more often. The launcher renews: it reconnects at once with a fresh
// bearer, shows no "Connection lost" line, and what is typed goes to the
// new connection.

func TestSessionExpiryRenewsWithoutALossGAP0588(t *testing.T) {
	r := newRig(t, nil)
	run := r.start(r.options())
	waitFor(t, "screen 1", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	before := r.bearer.count()
	r.typ("EXPIRE\r")
	waitFor(t, "screen 2", func() bool { return strings.Contains(r.out.String(), "screen:2") })
	r.typ("after\r")
	waitFor(t, "echo on the renewed connection", func() bool { return strings.Contains(r.out.String(), "echo:after") })
	r.typ("\x1d")
	got := r.wait(run)
	if got.err != nil || !got.res.Detached {
		t.Fatalf("%+v %v", got.res, got.err)
	}
	if s := r.errb.String(); strings.Contains(s, lostMsg) || strings.Contains(s, "not sent") || strings.Contains(s, "retrying") {
		t.Fatalf("a planned renew was reported as a loss: %q", s)
	}
	if n := r.admin.count(isWS); n != 2 {
		t.Fatalf("%d handshakes, want 2", n)
	}
	if r.bearer.count() <= before {
		t.Fatal("the renew did not ask for a fresh bearer")
	}
}

func TestSessionExpiryWithAnEndedSignInSaysSignInGAP0588(t *testing.T) {
	r := newRig(t, nil)
	run := r.start(r.options())
	waitFor(t, "screen 1", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	// The sign-in itself has ended: the gateway refuses the next one.
	r.admin.setAnswer(func(*http.Request) (int, http.Header) { return http.StatusUnauthorized, nil })
	r.typ("EXPIRE\r")
	got := r.wait(run)
	if got.err == nil || !strings.Contains(got.err.Error(), "defenseclaw substrate login") {
		t.Fatalf("no sign-in-again message: %+v %v", got.res, got.err)
	}
	if s := r.errb.String(); strings.Contains(s, lostMsg) {
		t.Fatalf("an ended sign-in was reported as a lost connection: %q", s)
	}
	noSecrets(t, "error", got.err.Error())
}
