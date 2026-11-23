// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"strings"
	"testing"
	"time"
)

// relayInputs is everything the fake relay got from the launcher.
func relayInputs(r *rig) string {
	r.relay.mu.Lock()
	defer r.relay.mu.Unlock()
	return r.relay.inputs.String()
}

// outageThenBack drops the link, types keys while it is down, and brings it
// back, returning when the second screen is shown.
func outageThenBack(t *testing.T, r *rig, s *suspendable, keys string, wantCount string) {
	t.Helper()
	waitFor(t, "screen 1", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	s.down.Store(true)
	r.typ("DROP\r")
	waitFor(t, "reconnecting line", func() bool { return strings.Contains(r.errb.String(), "reconnecting") })
	r.typ(keys)
	waitFor(t, "outage count", func() bool { return strings.Contains(r.errb.String(), wantCount) })
	s.down.Store(false)
	waitFor(t, "screen 2", func() bool { return strings.Contains(r.out.String(), "screen:2") })
}

// B3.1: in ask mode (the default) the keys typed while disconnected are
// shown after the reconnect and go to the agent, before any live key, when
// the person presses Enter.
func TestReplayAskSendsOnEnter(t *testing.T) {
	r, s, o := suspendRig(t)
	run := r.start(o)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("launcher stderr: %q", r.errb.String())
		}
	})
	outageThenBack(t, r, s, "git sta", "7 typed character(s) held")
	waitFor(t, "ask line", func() bool {
		e := r.errb.String()
		return strings.Contains(e, "Reconnected.") && strings.HasSuffix(strings.TrimSpace(e), `7 keys typed while disconnected: "git sta". Enter sends them, Esc drops them.`)
	})
	if strings.Contains(r.errb.String(), "keys typed now are not sent") {
		t.Fatalf("ask mode says keys are not sent: %q", r.errb.String())
	}
	r.typ("\r")
	r.typ("tus\r")
	waitFor(t, "replayed then live", func() bool { return strings.Contains(relayInputs(r), "git status\r") })
	r.typ("\x1d")
	if got := r.wait(run); got.err != nil || !got.res.Detached {
		t.Fatalf("%+v %v", got.res, got.err)
	}
}

// Esc drops the offer: nothing typed while disconnected reaches the agent,
// and the person is told.
func TestReplayAskEscDrops(t *testing.T) {
	r, s, o := suspendRig(t)
	run := r.start(o)
	outageThenBack(t, r, s, "secret", "6 typed character(s) held")
	waitFor(t, "ask line", func() bool { return strings.Contains(r.errb.String(), "Enter sends them, Esc drops them.") })
	r.typ("\x1b")
	waitFor(t, "dropped note", func() bool {
		return strings.Contains(r.errb.String(), "6 typed character(s) were not sent; type them again.")
	})
	r.typ("after\r")
	waitFor(t, "echo", func() bool { return strings.Contains(r.out.String(), "echo:after") })
	r.typ("\x1d")
	r.wait(run)
	if strings.Contains(relayInputs(r), "secret") {
		t.Fatalf("dropped keys reached the agent: %q", relayInputs(r))
	}
}

// on sends the kept keys at once.
func TestReplayOnSendsAtOnce(t *testing.T) {
	r, s, o := suspendRig(t)
	o.KeyReplay = KeyReplayOn
	run := r.start(o)
	outageThenBack(t, r, s, "ls -l\r", "6 typed character(s) held")
	waitFor(t, "echo", func() bool { return strings.Contains(r.out.String(), "echo:ls -l") })
	waitFor(t, "sent note", func() bool {
		return strings.Contains(r.errb.String(), "Reconnected. Sent 6 key(s) typed while disconnected.")
	})
	r.typ("\x1d")
	r.wait(run)
}

// Past 4 KiB nothing is replayed (a cut-off sequence is worse than none),
// even in on mode, and there is no preview.
func TestReplayOverCapNothingSent(t *testing.T) {
	r, s, o := suspendRig(t)
	o.KeyReplay = KeyReplayOn
	run := r.start(o)
	big := strings.Repeat("y", ReplayMaxBytes+1)
	outageThenBack(t, r, s, big, "typed character(s)")
	waitFor(t, "count", func() bool {
		return strings.Contains(r.errb.String(), "Reconnected. 4097 typed character(s) were not sent; type them again.")
	})
	r.typ("after\r")
	waitFor(t, "echo", func() bool { return strings.Contains(r.out.String(), "echo:after") })
	r.typ("\x1d")
	r.wait(run)
	if strings.Contains(relayInputs(r), "yyyy") || strings.Contains(r.errb.String(), "keys typed while disconnected") {
		t.Fatalf("over-cap keys replayed or offered: %q", r.errb.String())
	}
}

// The buffer ends at the ask key (Ctrl-\): keys typed while disconnected
// never answer a DefenseClaw ask, and nothing of that outage is replayed.
func TestReplayStopsAtAskKey(t *testing.T) {
	r, s, o := suspendRig(t)
	o.KeyReplay = KeyReplayOn
	run := r.start(o)
	outageThenBack(t, r, s, "ab\x1cy\r", "5 typed character(s) not sent")
	waitFor(t, "count", func() bool {
		return strings.Contains(r.errb.String(), "Reconnected. 5 typed character(s) were not sent")
	})
	r.typ("after\r")
	waitFor(t, "echo", func() bool { return strings.Contains(r.out.String(), "echo:after") })
	r.typ("\x1d")
	r.wait(run)
	if in := relayInputs(r); strings.Contains(in, "\x1c") || strings.Contains(in, "ab") {
		t.Fatalf("keys from an outage with an ask key were replayed: %q", in)
	}
}

// off keeps the count message only.
func TestReplayOffKeepsTheCount(t *testing.T) {
	r, s, o := suspendRig(t)
	o.KeyReplay = KeyReplayOff
	run := r.start(o)
	outageThenBack(t, r, s, "blind", "5 typed character(s) not sent")
	waitFor(t, "count", func() bool {
		return strings.Contains(r.errb.String(), "Reconnected. 5 typed character(s) were not sent; type them again.")
	})
	if !strings.Contains(r.errb.String(), "keys typed now are not sent") {
		t.Fatalf("off mode lost its status text: %q", r.errb.String())
	}
	r.typ("\x1d")
	r.wait(run)
	if strings.Contains(relayInputs(r), "blind") {
		t.Fatalf("off mode replayed keys: %q", relayInputs(r))
	}
}

// Bytes that may have reached the agent (sent, but not counted by the next
// hello) are never replayed, in any mode; they are still named.
func TestReplayNeverSendsMaybeBytes(t *testing.T) {
	r, _, o := suspendRig(t)
	o.KeyReplay = KeyReplayOn
	run := r.start(o)
	waitFor(t, "screen 1", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	r.typ("LOSE\r")
	waitFor(t, "screen 2", func() bool { return strings.Contains(r.out.String(), "screen:2") })
	waitFor(t, "maybe note", func() bool {
		return strings.Contains(r.errb.String(), "5 character(s) typed just before the connection dropped may not have reached the agent")
	})
	r.typ("\x1d")
	r.wait(run)
	if n := strings.Count(relayInputs(r), "LOSE"); n > 1 {
		t.Fatalf("maybe bytes replayed (%d copies): %q", n, relayInputs(r))
	}
	if strings.Contains(r.errb.String(), "typed while disconnected") {
		t.Fatalf("maybe bytes offered: %q", r.errb.String())
	}
}

// The chunks the relay client read but could not send come before the keys
// typed during the outage, and the age limit counts from the first of them.
func TestUnsentChunkBytesReplayedFirst(t *testing.T) {
	now := time.Unix(1000, 0)
	var o outageBuf
	o.addTyped([]byte("live"), now.Add(time.Second))
	chunk := []byte("early")
	o.addUnsent(chunk, now)
	if string(chunk) != "\x00\x00\x00\x00\x00" {
		t.Fatalf("the client's copy was not zeroed: %q", chunk)
	}
	b, n := o.take(now.Add(2 * time.Second))
	if string(b) != "earlylive" || n != 9 {
		t.Fatalf("take = %q, %d", b, n)
	}
	o.addUnsent([]byte("old"), now)
	if b, n := o.take(now.Add(ReplayMaxAge + time.Second)); b != nil || n != 3 {
		t.Fatalf("past the age limit: take = %q, %d", b, n)
	}
}

// The launcher flag can only tighten the cluster value (D3.1-3).
func TestTightestKeyReplay(t *testing.T) {
	for _, c := range []struct{ cluster, flag, want string }{
		{"", "", KeyReplayAsk},
		{"bogus", "", KeyReplayAsk},
		{KeyReplayAsk, KeyReplayOn, KeyReplayAsk},
		{KeyReplayOn, KeyReplayAsk, KeyReplayAsk},
		{KeyReplayOff, KeyReplayOn, KeyReplayOff},
		{KeyReplayOn, "", KeyReplayOn},
		{KeyReplayAsk, KeyReplayOff, KeyReplayOff},
	} {
		if got := TightestKeyReplay(c.cluster, c.flag); got != c.want {
			t.Errorf("TightestKeyReplay(%q, %q) = %q, want %q", c.cluster, c.flag, got, c.want)
		}
	}
	if replayPreview([]byte("a\rb\x7f")) != "a^Mb^?" {
		t.Errorf("preview = %q", replayPreview([]byte("a\rb\x7f")))
	}
}
