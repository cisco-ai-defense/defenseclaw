// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptrace"
	"runtime"
	"sync"
	"time"
)

// errPerUserGatewayFrozen ends a per-user call whose gateway took the
// connection and then answered nothing, while a probe of the same verified
// listener got no HTTP status either: the gateway is frozen (suspended or
// wedged), not busy. It is the outage of an unanswered listener
// (failPerUserListenerUnanswered), as on Linux and macOS, where a frozen
// gateway leaves the call in its accept queue (errPerUserListenerUnanswered).
//
// On Windows the Go runtime keeps an AcceptEx posted on the listener, so the
// kernel accepts the next connection even while the gateway process is
// suspended, and the accept-queue proof never applies there: every call to a
// frozen gateway was "taken and not answered". A prompt, a tool result or a
// stop event then waited its whole registered hook timeout (29 s, 89 s for
// Stop and PostToolBatch) and was blocked with "fail mode closed" in the open
// tier too (rel-1-0-10 GAP-1107).
var errPerUserGatewayFrozen = errors.New("this account's gateway took the call and answers nothing, not even two health probes")

// The first probe starts once the call has waited the tool-gate answer
// budget (hookAnswerBudget from hook start). A probe misses when its
// connection was made and verified and then no status came within
// perUserFrozenProbeWindow, counted from that verified connection: the dial
// and the Windows owner-tuple check are not in the window, so a loaded host
// that is slow to show the socket owner cannot make a live gateway look
// frozen. The gateway is frozen only after perUserFrozenMisses consecutive
// misses, the next probe perUserFrozenConfirmGap after a miss; a live
// gateway answers /health within milliseconds while it evaluates the call
// (the LLM judge of a prompt can take longer than the budget). A probe that
// proves nothing repeats after perUserFrozenProbeEvery while the call waits.
var (
	perUserFrozenProbeWindow  = 2 * time.Second
	perUserFrozenProbeEvery   = 5 * time.Second
	perUserFrozenConfirmGap   = 250 * time.Millisecond
	perUserFrozenProbeDialCap = 10 * time.Second
	// perUserFrozenClockSlip is the most the monotonic and wall clocks may
	// disagree over one probe window, and the most the window may run late,
	// for its miss to count. A host that sleeps and resumes mid-call (or
	// starves this process) ends the window late on one clock or both: that
	// miss proves nothing, the count restarts and the gateway is probed again.
	perUserFrozenClockSlip = time.Second
	// frozenProbeWall reads the wall clock without its monotonic reading.
	// Tests replace it.
	frozenProbeWall = func() time.Time { return time.Now().Round(0) }
)

const perUserFrozenMisses = 2

// perUserFrozenProbeOn reports whether the transport of this call needs the
// probe: the per-user Windows loopback client this hook built itself. Tests
// replace it.
var perUserFrozenProbeOn = func(opts Options) bool {
	return runtime.GOOS == "windows" && opts.perUserLoopbackDial
}

// perUserFrozenProbeCall reports a per-user Claude Code or Codex call that
// has no answer deadline of its own: every event but a tool gate (a prompt,
// a tool result, a stop or session event). A tool gate keeps its answer
// budget and the ordinary-call rule (noAnswerFailMode).
func perUserFrozenProbeCall(opts Options) bool {
	return !opts.ManagedEnterprise && opts.ManagedUnixSocket == "" && !opts.SecureClient &&
		opts.HTTPClient != nil && opts.answerBy.IsZero() && !opts.StartedAt.IsZero() &&
		lateOrdinaryConnector(opts.Connector) && !toolGateEvent(opts.Connector, opts.Event) &&
		perUserFrozenProbeOn(opts)
}

// frozenProbeResult is what one /health probe shows.
type frozenProbeResult int

const (
	// probeNotFrozen: a status came (any status, an error status included),
	// the verified connection failed on its own, or no verified connection
	// was made: no proof of a frozen gateway.
	probeNotFrozen frozenProbeResult = iota
	// probeInconclusive: the window ended with no status, but the clocks
	// show the host slept or this process was starved meanwhile.
	probeInconclusive
	// probeMissed: a verified connection got no status in the window.
	probeMissed
)

// perUserFrozenProbe runs one probe; tests replace it.
var perUserFrozenProbe = perUserProbeGateway

// watchPerUserFrozenGateway returns ctx for the request of the call, ended
// with errPerUserGatewayFrozen when consecutive probes prove the gateway
// frozen; stop, which ends the watch once the call has a response or an
// error; and release, which the call runs when it is done.
func watchPerUserFrozenGateway(ctx context.Context, opts Options) (watched context.Context, stop, release func()) {
	noop := func() {}
	if !perUserFrozenProbeCall(opts) {
		return ctx, noop, noop
	}
	watched, cancel := context.WithCancelCause(ctx)
	done := make(chan struct{})
	var once sync.Once
	stop = func() { once.Do(func() { close(done) }) }
	go func() {
		timer := time.NewTimer(time.Until(opts.StartedAt.Add(hookAnswerBudget)))
		defer timer.Stop()
		misses := 0
		for {
			select {
			case <-done:
				return
			case <-watched.Done():
				return
			case <-timer.C:
			}
			switch perUserFrozenProbe(watched, opts) {
			case probeMissed:
				if misses++; misses >= perUserFrozenMisses {
					select {
					case <-done:
					default:
						cancel(errPerUserGatewayFrozen)
					}
					return
				}
				timer.Reset(perUserFrozenConfirmGap)
			case probeInconclusive:
				misses = 0
				timer.Reset(perUserFrozenConfirmGap)
			default:
				misses = 0
				timer.Reset(perUserFrozenProbeEvery)
			}
		}
	}()
	return watched, stop, func() { stop(); cancel(nil) }
}

// perUserProbeGateway probes /health of the gateway through the verified
// client of the call, which proves the owner of the listener again; no
// token is sent. Its window starts at the verified connection (GotConn,
// which net/http reports after DialContext and its owner check returned).
func perUserProbeGateway(ctx context.Context, opts Options) frozenProbeResult {
	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	connected := make(chan struct{})
	var connOnce sync.Once
	var connMono, connWall time.Time
	trace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) {
		connOnce.Do(func() {
			connMono, connWall = time.Now(), frozenProbeWall()
			close(connected)
		})
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(probeCtx, trace), http.MethodGet,
		"http://"+opts.APIAddr+"/health", nil)
	if err != nil {
		return probeNotFrozen
	}
	answered := make(chan struct{})
	go func() {
		defer close(answered)
		if resp, err := opts.HTTPClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	dialCap := time.NewTimer(perUserFrozenProbeDialCap)
	defer dialCap.Stop()
	select {
	case <-connected:
	case <-answered:
		return probeNotFrozen
	case <-dialCap.C:
		return probeNotFrozen
	case <-ctx.Done():
		return probeNotFrozen
	}
	window := time.NewTimer(perUserFrozenProbeWindow)
	defer window.Stop()
	select {
	case <-answered:
		return probeNotFrozen
	case <-ctx.Done():
		return probeNotFrozen
	case <-window.C:
	}
	mono, wall := time.Since(connMono), frozenProbeWall().Sub(connWall)
	if slip := mono - wall; slip > perUserFrozenClockSlip || -slip > perUserFrozenClockSlip ||
		mono > perUserFrozenProbeWindow+perUserFrozenClockSlip {
		return probeInconclusive
	}
	return probeMissed
}

// perUserGatewayFrozen reports a call that watchPerUserFrozenGateway ended.
func perUserGatewayFrozen(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), errPerUserGatewayFrozen)
}
