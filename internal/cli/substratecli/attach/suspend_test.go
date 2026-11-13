// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// suspendable makes the fake relay look like a suspended actor: while down
// every route answers 502 (the agent is starting), as the attach route does
// while Substrate resumes the actor.
type suspendable struct {
	*fakeRelay
	down atomic.Bool
	// wake, when set, holds the next WebSocket handshake until it is
	// closed (the actor waking while the person types); arrived says the
	// handshake is waiting.
	wake    atomic.Pointer[chan struct{}]
	arrived chan struct{}
}

func (s *suspendable) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.down.Load() {
		http.Error(w, "starting", http.StatusBadGateway)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/ws") {
		if c := s.wake.Swap(nil); c != nil {
			s.arrived <- struct{}{}
			<-*c
		}
	}
	s.fakeRelay.ServeHTTP(w, r)
}

// pacedSleep sleeps for real (a few milliseconds), so a test can type while
// the launcher waits for the link.
func pacedSleep(ctx context.Context, _ time.Duration) error {
	select {
	case <-time.After(5 * time.Millisecond):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func suspendRig(t *testing.T) (*rig, *suspendable, Options) {
	fr := newFakeRelay(testToken)
	s := &suspendable{fakeRelay: fr, arrived: make(chan struct{}, 1)}
	r := newRig(t, s)
	r.relay = fr
	o := r.options()
	o.Sleep = pacedSleep
	o.Backoff.MaxAttempts = 100000 // the time bound decides
	return r, s, o
}

// GAP-0003: suspend cuts the connection; the launcher says it is
// reconnecting, keeps the keyboard (what is typed meanwhile is not sent,
// and it says so), and is back on the agent when the actor resumes.
func TestSuspendDropReconnects(t *testing.T) {
	r, s, o := suspendRig(t)
	run := r.start(o)
	waitFor(t, "screen 1", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	s.down.Store(true)
	r.typ("DROP\r")
	waitFor(t, "reconnecting line", func() bool { return strings.Contains(r.errb.String(), "reconnecting") })
	r.typ("blind")
	waitFor(t, "not-sent count", func() bool { return strings.Contains(r.errb.String(), "5 typed character(s) not sent") })
	s.down.Store(false)
	waitFor(t, "screen 2", func() bool { return strings.Contains(r.out.String(), "screen:2") })
	waitFor(t, "reconnected", func() bool {
		return strings.Contains(r.errb.String(), "Reconnected. 5 typed character(s) were not sent; type them again.")
	})
	r.typ("after\r")
	waitFor(t, "echo on the new connection", func() bool { return strings.Contains(r.out.String(), "echo:after") })
	r.typ("\x1d")
	got := r.wait(run)
	if got.err != nil || !got.res.Detached || got.res.Reconnects != 1 {
		t.Fatalf("%+v %v", got.res, got.err)
	}
	r.relay.mu.Lock()
	in := r.relay.inputs.String()
	r.relay.mu.Unlock()
	if strings.Contains(in, "blind") {
		t.Fatalf("keys typed while the link was down reached the agent: %q", in)
	}
}

// Ctrl-] while the link is down detaches at once.
func TestDetachWhileReconnecting(t *testing.T) {
	r, s, o := suspendRig(t)
	run := r.start(o)
	waitFor(t, "screen 1", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	s.down.Store(true)
	r.typ("DROP\r")
	waitFor(t, "reconnecting line", func() bool { return strings.Contains(r.errb.String(), "reconnecting") })
	r.typ("ab\x1d")
	got := r.wait(run)
	if got.err != nil || !got.res.Detached {
		t.Fatalf("%+v %v", got.res, got.err)
	}
	e := r.errb.String()
	if !strings.Contains(e, "Stopped reconnecting. The agent keeps running. Come back with: defenseclaw substrate connect cc-1") || !strings.Contains(e, "2 typed character(s) were not sent") {
		t.Fatalf("stderr %q", e)
	}
}

// A link that stays down ends after ReconnectFor with the next step.
func TestReconnectGivesUpAfterABoundedWait(t *testing.T) {
	r, s, o := suspendRig(t)
	o.ReconnectFor = 150 * time.Millisecond
	o.MaxWait = time.Hour
	run := r.start(o)
	waitFor(t, "screen 1", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	s.down.Store(true)
	r.typ("DROP\r")
	waitFor(t, "reconnecting line", func() bool { return strings.Contains(r.errb.String(), "reconnecting") })
	r.typ("x")
	start := time.Now()
	got := r.wait(run)
	if got.err == nil {
		t.Fatal("no error after the bound")
	}
	msg := got.err.Error()
	for _, want := range []string{"could not reconnect to cc-1", "the agent keeps running", "defenseclaw substrate connect cc-1"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q lacks %q", msg, want)
		}
	}
	if !strings.Contains(msg, "character(s) were not sent") {
		t.Errorf("the lost key is not mentioned: %q", msg)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("gave up after %s", time.Since(start))
	}
}

// Seen live on stk: keys typed while the reconnect handshake waited for the
// waking actor reached the agent once the link was back. The new
// connection takes keys only after the relay greets it.
func TestKeysTypedDuringASlowReconnectAreNotSent(t *testing.T) {
	r, s, o := suspendRig(t)
	run := r.start(o)
	waitFor(t, "screen 1", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	hold := make(chan struct{})
	s.wake.Store(&hold)
	r.typ("DROP\r")
	select {
	case <-s.arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("no reconnect handshake")
	}
	r.typ("during-handshake")
	waitFor(t, "counted", func() bool { return strings.Contains(r.errb.String(), "16 typed character(s) not sent") })
	close(hold)
	waitFor(t, "screen 2", func() bool { return strings.Contains(r.out.String(), "screen:2") })
	waitFor(t, "reconnected note", func() bool {
		return strings.Contains(r.errb.String(), "Reconnected. 16 typed character(s) were not sent")
	})
	r.typ("after\r")
	waitFor(t, "echo", func() bool { return strings.Contains(r.out.String(), "echo:after") })
	r.typ("\x1d")
	got := r.wait(run)
	if got.err != nil || !got.res.Detached {
		t.Fatalf("%+v %v", got.res, got.err)
	}
	r.relay.mu.Lock()
	in := r.relay.inputs.String()
	r.relay.mu.Unlock()
	if strings.Contains(in, "during-handshake") {
		t.Fatalf("keys typed during the handshake reached the agent: %q", in)
	}
}
