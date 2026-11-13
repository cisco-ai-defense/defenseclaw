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
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"strconv"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
)

// link is what every operation shares: the tunnel through the gateway and
// the status line on Err.
type link struct {
	o      Options
	tun    *Tunnel
	errTTY bool
	// sayMu orders status lines: the reconnect loop, the outage input
	// reader and the relay hello can all write one.
	sayMu sync.Mutex
	// pending: a status line without a newline is on Err.
	pending bool
}

func newLink(ctx context.Context, o Options) (*link, error) {
	tun, err := NewTunnel(ctx, o.Gateway, o.Bearer, o.Target)
	if err != nil {
		return nil, err
	}
	return &link{o: o, tun: tun, errTTY: isTerminal(o.Err)}, nil
}

func (l *link) close() { l.tun.Close() }

type outcome int

const (
	outLost outcome = iota
	outFatal
	outWait
	outBlocked
)

// judge sorts an error of one try: fatal (a setting or a refusal), wait
// (the cluster is full or the agent is starting) or lost (try again).
func (l *link) judge(err error) (outcome, error) {
	var fe *fatalError
	if errors.As(err, &fe) {
		return outFatal, fe.err
	}
	var be *bearerError
	if errors.As(err, &be) {
		if be.transient() {
			return outLost, be
		}
		return outFatal, be
	}
	var re *RouteError
	if errors.As(err, &re) {
		return re.outcome(), re
	}
	var de *dialError
	if errors.As(err, &de) {
		if de.fatal {
			return outFatal, de
		}
		return outLost, de
	}
	if st := relayStatus(err); st != 0 {
		return l.statusOutcome(st, err)
	}
	return outLost, err
}

func (e *RouteError) outcome() outcome {
	switch {
	case e.waits():
		return outWait
	case e.final():
		return outFatal
	}
	return outLost
}

// statusOutcome sorts an HTTP status of the attach route. err is what to
// show for a status that is retried as a lost connection.
func (l *link) statusOutcome(st int, err error) (outcome, error) {
	re := routeError(st, nil, l.o.Target)
	switch {
	case re.waits():
		re.RetryAfter = l.tun.takeRetryAfter()
		return outWait, re
	case re.final():
		return outFatal, re
	}
	return outLost, err
}

// say prints a status message on Err. On a terminal a transient message
// stays on one line that the next one (or the agent's screen) overwrites.
func (l *link) say(msg string, final bool) {
	l.sayMu.Lock()
	defer l.sayMu.Unlock()
	// Error text in msg may come from the gateway or the relay.
	msg = safetext.Line(msg)
	w := l.o.Err
	if !l.errTTY {
		fmt.Fprintln(w, msg)
		return
	}
	if final {
		if l.pending {
			io.WriteString(w, "\r\x1b[2K")
		} else {
			io.WriteString(w, "\r\n")
		}
		io.WriteString(w, msg+"\r\n")
		l.pending = false
		return
	}
	io.WriteString(w, "\r\x1b[2K"+msg)
	l.pending = true
}

// endLine ends a pending status line so an error does not share it.
func (l *link) endLine() {
	l.sayMu.Lock()
	defer l.sayMu.Unlock()
	if l.pending {
		io.WriteString(l.o.Err, "\r\n")
		l.pending = false
	}
}

// gaveUpError is the end of a wait: its text says what to do, and it still
// unwraps to ErrStarting or ErrClusterFull, so callers can tell the case.
type gaveUpError struct {
	kind error
	msg  string
}

func (e *gaveUpError) Error() string { return e.msg }
func (e *gaveUpError) Unwrap() error { return e.kind }

// parker waits while the cluster is full (HTTP 503 or 429) or the agent is
// starting (502 or 504), for MaxWait in all.
type parker struct {
	l     *link
	r     *retry
	start time.Time
	said  error
}

func (l *link) newParker() *parker { return &parker{l: l, r: newRetry(l.o.Backoff)} }

func (p *parker) reset() {
	p.start, p.said = time.Time{}, nil
	p.r.reset()
}

// wait sleeps once for re (ErrClusterFull or ErrStarting).
func (p *parker) wait(ctx context.Context, re *RouteError) error {
	o := p.l.o
	now := o.Now()
	if p.start.IsZero() {
		p.start = now
	}
	waited := now.Sub(p.start)
	if waited >= o.MaxWait {
		p.l.endLine()
		if re.Kind == ErrStarting {
			return &gaveUpError{kind: re.Kind, msg: fmt.Sprintf("the agent %s did not start within %s; check it with: defenseclaw substrate status %s", o.Target.Name, fmtDur(o.MaxWait), o.Target.Name)}
		}
		return &gaveUpError{kind: re.Kind, msg: fmt.Sprintf("no room in the cluster after %s; try again later or ask your administrator to raise the pool", fmtDur(o.MaxWait))}
	}
	msg := fullMsg
	if re.Kind == ErrStarting {
		msg = startingMsg
	}
	switch {
	case p.said != re.Kind:
		p.said = re.Kind
		p.l.say(msg, false)
	case p.l.errTTY:
		p.l.say(msg+" "+fmtDur(waited.Round(time.Second)), false)
	}
	d := p.r.next()
	if re.RetryAfter > d {
		d = re.RetryAfter
	}
	if rem := o.MaxWait - waited; d > rem {
		d = rem
	}
	return ctxErr(ctx, o.Sleep(ctx, d))
}

func fmtDur(d time.Duration) string {
	if d >= time.Minute && d%time.Minute == 0 {
		return strconv.Itoa(int(d/time.Minute)) + "m"
	}
	if d >= time.Second {
		d = d.Round(time.Second)
	}
	return d.String()
}

func (b Backoff) withDefaults() Backoff {
	if b.Initial <= 0 {
		b.Initial = 500 * time.Millisecond
	}
	if b.Max <= 0 {
		b.Max = 10 * time.Second
	}
	if b.Max < b.Initial {
		b.Max = b.Initial
	}
	if b.Factor < 1 {
		b.Factor = 2
	}
	switch {
	case b.Jitter == 0:
		b.Jitter = 0.3
	case b.Jitter > 1:
		b.Jitter = 1
	}
	if b.MaxAttempts <= 0 {
		b.MaxAttempts = 12
	}
	return b
}

// retry yields backoff delays.
type retry struct {
	b Backoff
	n int
}

func newRetry(b Backoff) *retry { return &retry{b: b.withDefaults()} }

func (r *retry) reset() { r.n = 0 }

func (r *retry) next() time.Duration {
	d := float64(r.b.Initial) * math.Pow(r.b.Factor, float64(r.n))
	if d > float64(r.b.Max) || math.IsInf(d, 0) || math.IsNaN(d) {
		d = float64(r.b.Max)
	}
	if r.n < 64 {
		r.n++
	}
	if j := r.b.Jitter; j > 0 {
		d *= 1 + j*(2*rand.Float64()-1)
	}
	return time.Duration(d)
}
