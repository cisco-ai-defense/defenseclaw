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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"strconv"
	"time"
)

// refreshBefore: a session token with less time left than this is renewed
// before a (re)connect.
const refreshBefore = 60 * time.Second

// sessionCache holds the current session grant and renews it.
type sessionCache struct {
	src SessionSource
	t   Target
	now func() time.Time
	g   SessionGrant
	ok  bool
}

func (s *sessionCache) get(ctx context.Context, force bool) (SessionGrant, error) {
	if !force && s.ok && (s.g.Expires.IsZero() || s.g.Expires.Sub(s.now()) >= refreshBefore) {
		return s.g, nil
	}
	g, err := s.src.Session(ctx, s.t)
	if err != nil {
		if ctx.Err() != nil {
			return SessionGrant{}, ctx.Err()
		}
		if code, refused := sessionRefused(err); refused {
			if code == 401 {
				return SessionGrant{}, &fatalError{fmt.Errorf("the cluster did not accept your sign-in for %s; sign in again with: defenseclaw substrate login (%w)", s.t, err)}
			}
			return SessionGrant{}, &fatalError{fmt.Errorf("the cluster refused a session for %s (not allowed): %w", s.t, err)}
		}
		return SessionGrant{}, fmt.Errorf("could not get a session for %s: %w", s.t, err)
	}
	if g.Token == "" {
		return SessionGrant{}, &fatalError{fmt.Errorf("the cluster gave no session token for %s", s.t)}
	}
	s.g, s.ok = g, true
	return g, nil
}

func sessionRefused(err error) (int, bool) {
	if errors.Is(err, ErrSessionRefused) {
		return 403, true
	}
	var sc interface{ StatusCode() int }
	if errors.As(err, &sc) {
		if c := sc.StatusCode(); c == 401 || c == 403 {
			return c, true
		}
	}
	var hs interface{ HTTPStatus() int }
	if errors.As(err, &hs) {
		if c := hs.HTTPStatus(); c == 401 || c == 403 {
			return c, true
		}
	}
	return 0, false
}

func tokenRefused(t Target) error {
	return fmt.Errorf("the agent %s refused the session token twice; sign in again with: defenseclaw substrate login", t.Name)
}

// link is what every operation shares: the session and the tunnel, rebuilt
// when the session's client certificate changes, and the status line on Err.
type link struct {
	o       Options
	sess    *sessionCache
	tun     *Tunnel
	tunCert []byte
	errTTY  bool
	// pending: a status line without a newline is on Err.
	pending bool
}

func newLink(o Options) *link {
	return &link{o: o, sess: &sessionCache{src: o.Sessions, t: o.Target, now: o.Now}, errTTY: isTerminal(o.Err)}
}

func (l *link) grant(ctx context.Context, force bool) (SessionGrant, error) {
	g, err := l.sess.get(ctx, force)
	if err != nil {
		return SessionGrant{}, err
	}
	if l.tun == nil || !bytes.Equal(l.tunCert, g.ClientCertPEM) {
		t, err := NewTunnel(ctx, l.o.Router, g, l.o.Target)
		if err != nil {
			return SessionGrant{}, &fatalError{err}
		}
		if l.tun != nil {
			l.tun.Close()
		}
		l.tun, l.tunCert = t, bytes.Clone(g.ClientCertPEM)
	}
	return g, nil
}

func (l *link) close() {
	if l.tun != nil {
		l.tun.Close()
	}
}

// say prints a status message on Err. On a terminal a transient message
// stays on one line that the next one (or the agent's screen) overwrites.
func (l *link) say(msg string, final bool) {
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
	if l.pending {
		io.WriteString(l.o.Err, "\r\n")
		l.pending = false
	}
}

// parker waits while the cluster is full (HTTP 503 or 429).
type parker struct {
	l     *link
	r     *retry
	start time.Time
	said  bool
}

func (l *link) newParker() *parker { return &parker{l: l, r: newRetry(l.o.Backoff)} }

func (p *parker) reset() {
	p.start, p.said = time.Time{}, false
	p.r.reset()
}

func (p *parker) wait(ctx context.Context, retryAfter time.Duration) error {
	o := p.l.o
	now := o.Now()
	if p.start.IsZero() {
		p.start = now
	}
	waited := now.Sub(p.start)
	if waited >= o.MaxWait {
		p.l.endLine()
		return fmt.Errorf("no room in the cluster after %s; try again later or ask your administrator to raise the pool", fmtDur(o.MaxWait))
	}
	switch {
	case !p.said:
		p.said = true
		p.l.say(fullMsg, false)
	case p.l.errTTY:
		p.l.say(fullMsg+" "+fmtDur(waited.Round(time.Second)), false)
	}
	d := p.r.next()
	if retryAfter > d {
		d = retryAfter
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
