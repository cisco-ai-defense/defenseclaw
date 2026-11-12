// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package attach connects the launcher to the terminal of an agent in an
// Agent Substrate actor. It opens an mTLS CONNECT tunnel through the atenet
// router and speaks the actor relay's dcrelay/1 protocol inside it, through
// the relay package's client (internal/substrate/relay). On top it adds what
// a person at a terminal needs: a banner, raw mode and resize, Ctrl-] to
// detach, reconnect with backoff, waiting while the cluster is full, a
// long-poll fallback where WebSocket is blocked (E27) and inline asks.
package attach

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// Target names one actor.
type Target struct{ Atespace, Name string }

// String is atespace/name, the value of the ate-target-actor header.
func (t Target) String() string { return t.Atespace + "/" + t.Name }

// SessionGrant is a launcher session from the admin listener
// (POST /api/v1/substrate/session-cert). ClientCertPEM and ClientKeyPEM are
// optional: when both are present they are the client certificate for the
// router's mTLS and win over Router.CertFile and Router.KeyFile.
type SessionGrant struct {
	Token                       string
	Expires                     time.Time
	ClientCertPEM, ClientKeyPEM []byte
}

// SessionSource issues launcher sessions. An error that wraps
// ErrSessionRefused, or that has a StatusCode() or HTTPStatus() method
// answering 401 or 403, means the person may not reach the actor; it is not
// retried.
type SessionSource interface {
	Session(ctx context.Context, t Target) (SessionGrant, error)
}

// Router is how the launcher reaches the atenet router's CONNECT-TLS port.
type Router struct {
	// URL is https://HOST:PORT (the port is usually 8444).
	URL string
	// CAFile, when set, is the only CA trusted for the router's certificate;
	// without it the system roots are used.
	CAFile string
	// CertFile and KeyFile are a client certificate for the router's mTLS,
	// used when the session grant carries none.
	CertFile, KeyFile string
	// RelayPort is the actor port the relay listens on (default 8080).
	RelayPort int

	// dial and proxy replace the TCP dial and the proxy lookup (tests).
	dial  func(ctx context.Context, network, addr string) (net.Conn, error)
	proxy proxyFunc
}

// Ask is one pending ask (an approval a hook is waiting for).
type Ask struct {
	ID, Tool, Summary, Reason, Severity string
	Created                             time.Time
}

// Decision answers an ask.
type Decision string

// Decisions.
const (
	DecideOnce   Decision = "once"
	DecideAlways Decision = "always"
	DecideDeny   Decision = "deny"
)

// AskSource lists the pending asks of an actor and answers them.
type AskSource interface {
	Pending(ctx context.Context, t Target) ([]Ask, error)
	Decide(ctx context.Context, id string, d Decision) error
}

// Banner is what the launcher shows before it attaches.
type Banner struct {
	Name, Connector, Profile, Model, Route string
	AllowList                              []string
	// Asks says how asks work in this session ("" gives the default line).
	Asks string
	// Extra lines, shown while the banner stays within 8 lines.
	Extra []string
}

// Transports.
const (
	TransportAuto      = "auto"
	TransportWebSocket = "websocket"
	TransportLongPoll  = "longpoll"
)

// Backoff shapes retries. Zero fields take the defaults: Initial 500ms,
// Max 10s, Factor 2, Jitter 0.3 (a negative Jitter means none),
// MaxAttempts 12 consecutive failures.
type Backoff struct {
	Initial, Max time.Duration
	Factor       float64
	Jitter       float64
	MaxAttempts  int
}

// Options configure Attach, RunTask, FollowTask and Status.
type Options struct {
	Target   Target
	Router   Router
	Sessions SessionSource
	// Asks, when set (and In is a terminal and NoAsks is false), shows
	// pending asks inline while attached.
	Asks   AskSource
	Banner Banner
	// In is the keyboard (default os.Stdin); raw mode is used only when it
	// is a terminal.
	In       *os.File
	Out, Err io.Writer
	// Transport is auto (default), websocket or longpoll.
	Transport string
	Backoff   Backoff
	// MaxWait bounds the wait while the cluster is full (default 10m).
	MaxWait  time.Duration
	Now      func() time.Time
	Sleep    func(context.Context, time.Duration) error
	NoBanner bool
	NoAsks   bool
	// InitialSize is the terminal size when In is not a terminal
	// (default 80x24).
	InitialSize relay.Resize
	// SizeEvents adds size changes to the ones read from the terminal.
	SizeEvents <-chan relay.Resize
}

// Result is how an attachment ended.
type Result struct {
	// Detached: the person pressed Ctrl-] or the input ended; the agent
	// keeps running.
	Detached bool
	// ExitCode is the agent's exit status when it exited.
	ExitCode *int
	// Session is the relay session the attachment joined.
	Session string
	// Reconnects counts the connections after the first one.
	Reconnects int
	// Transport is the transport in use at the end.
	Transport string
}

const (
	// stableAfter: a connection that lasted this long resets the backoff.
	stableAfter = 30 * time.Second
	fullMsg     = "The cluster is full. Waiting for room (Ctrl-C to stop)..."
	lostMsg     = "Connection lost; reconnecting..."
	fallbackMsg = "WebSocket is blocked here; using the slower fallback"
)

func connectHint(name string) string { return "defenseclaw substrate connect " + name }

func (o *Options) normalize() error {
	if o.Target.Atespace == "" || o.Target.Name == "" {
		return errors.New("no actor named: an actor is atespace/name")
	}
	if o.Sessions == nil {
		return errors.New("no session source configured")
	}
	if o.In == nil {
		o.In = os.Stdin
	}
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if o.Err == nil {
		o.Err = os.Stderr
	}
	switch o.Transport {
	case "":
		o.Transport = TransportAuto
	case TransportAuto, TransportWebSocket, TransportLongPoll:
	default:
		return fmt.Errorf("unknown transport %q: use auto, websocket or longpoll", o.Transport)
	}
	o.Backoff = o.Backoff.withDefaults()
	if o.MaxWait <= 0 {
		o.MaxWait = 10 * time.Minute
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtx
	}
	if o.InitialSize.Cols == 0 || o.InitialSize.Rows == 0 {
		o.InitialSize = relay.Resize{Cols: 80, Rows: 24}
	}
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Attach shows the banner, then connects to the agent's terminal and copies
// the keyboard to the agent and its screen back until the person detaches
// (Ctrl-]), the agent exits, ctx ends or reconnecting fails. The terminal
// mode is restored on every return path.
func Attach(ctx context.Context, o Options) (res Result, err error) {
	if err := o.normalize(); err != nil {
		return Result{}, err
	}
	a := newAttacher(o)
	defer a.close()
	defer a.term.guard()
	if !o.NoBanner {
		writeBanner(o.Err, o.Banner, o.Target)
	}
	return a.run(ctx)
}

type attacher struct {
	*link
	term  *terminal
	hub   *inputHub
	scr   *screen
	asks  *askUI
	mode  string
	stop  chan struct{}
	close func()

	wsBlocked int

	sizeMu sync.Mutex
	size   relay.Resize
	sizeCh chan relay.Resize
}

func newAttacher(o Options) *attacher {
	a := &attacher{link: newLink(o), stop: make(chan struct{})}
	a.term = newTerminal(o.In, o.Out)
	a.term.enableVT()
	a.mode = TransportWebSocket
	if o.Transport == TransportLongPoll {
		a.mode = TransportLongPoll
	}
	a.scr = &screen{w: o.Out, now: o.Now}
	a.size = o.InitialSize
	if sz, ok := a.term.size(); ok {
		a.size = sz
	}
	a.hub = newInputHub(o.In, a.term.guard)
	if o.Asks != nil && !o.NoAsks && a.term.tty {
		a.asks = newAskUI(o.Asks, o.Target, a.scr, a.currentSize, o.Now, a.term.guard)
	}
	go a.watchSizes()
	var once sync.Once
	a.close = func() {
		once.Do(func() {
			close(a.stop)
			a.hub.close()
			a.term.close()
			a.link.close()
		})
	}
	return a
}

func (a *attacher) currentSize() relay.Resize {
	a.sizeMu.Lock()
	defer a.sizeMu.Unlock()
	return a.size
}

func (a *attacher) setSize(rs relay.Resize) {
	if rs.Cols == 0 || rs.Rows == 0 {
		return
	}
	a.sizeMu.Lock()
	if rs == a.size {
		a.sizeMu.Unlock()
		return
	}
	a.size = rs
	if a.sizeCh != nil {
		select {
		case a.sizeCh <- rs:
		default:
		}
	}
	a.sizeMu.Unlock()
	if a.asks != nil {
		a.asks.redraw()
	}
}

func (a *attacher) watchSizes() {
	defer a.term.guard()
	var changed <-chan struct{}
	if a.term.sizeOK {
		changed = a.term.watch(a.stop)
	}
	events := a.o.SizeEvents
	for {
		select {
		case <-a.stop:
			return
		case <-changed:
			if sz, ok := a.term.size(); ok {
				a.setSize(sz)
			}
		case rs, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			a.setSize(rs)
		}
	}
}

type outcome int

const (
	outLost outcome = iota
	outFatal
	outFull
	outUnauthorized
	outBlocked
)

func (a *attacher) run(ctx context.Context) (Result, error) {
	o := a.o
	var res Result
	rec := newRetry(o.Backoff)
	park := a.newParker()
	failures, unauthorized, connections := 0, 0, 0
	lostShown, force := false, false
	var lastErr error
	for {
		res.Transport = a.mode
		if err := ctx.Err(); err != nil {
			return res, err
		}
		var ar relay.AttachResult
		connected := false
		g, err := a.grant(ctx, force)
		force = false
		if err == nil {
			began := o.Now()
			ar, connected, err = a.once(ctx, g)
			if connected {
				connections++
				res.Reconnects = connections - 1
				park.reset()
				a.pending = false
				unauthorized, failures, lostShown = 0, 0, false
				if a.mode == TransportWebSocket {
					a.wsBlocked = 0
				}
				if o.Now().Sub(began) > stableAfter {
					rec.reset()
				}
			}
		}
		if ar.Session != "" {
			res.Session = ar.Session
		}
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if err == nil {
			switch {
			case ar.ExitCode != nil:
				res.ExitCode = ar.ExitCode
				return res, nil
			case ar.Detached || a.hub.ended():
				res.Detached = true
				a.say("Detached. The agent keeps running. Come back with: "+connectHint(o.Target.Name), true)
				return res, nil
			}
		}
		k, kerr := a.classify(err, connected)
		switch k {
		case outFatal:
			a.endLine()
			return res, kerr
		case outFull:
			if werr := park.wait(ctx, retryAfterOf(err)); werr != nil {
				return res, werr
			}
			continue
		case outUnauthorized:
			unauthorized++
			if unauthorized > 1 {
				a.endLine()
				return res, tokenRefused(o.Target)
			}
			force = true
			continue
		case outBlocked:
			a.wsBlocked++
			if a.wsBlocked >= 2 {
				a.mode = TransportLongPoll
				a.say(fallbackMsg, true)
				continue
			}
		}
		if err != nil {
			lastErr = err
		}
		failures++
		if failures >= o.Backoff.MaxAttempts {
			a.endLine()
			return res, giveUp(o.Target, connections > 0, failures, lastErr)
		}
		if !lostShown {
			lostShown = true
			if connections > 0 {
				a.say(lostMsg, false)
			} else if err != nil {
				a.say("Could not connect yet ("+err.Error()+"); retrying...", false)
			}
		}
		if serr := o.Sleep(ctx, rec.next()); serr != nil {
			return res, ctxErr(ctx, serr)
		}
	}
}

func giveUp(t Target, wasConnected bool, tries int, last error) error {
	why := ""
	if last != nil {
		why = " (" + last.Error() + ")"
	}
	if wasConnected {
		return fmt.Errorf("lost the connection to %s after %d tries%s; the agent keeps running. Come back with: %s", t.Name, tries, why, connectHint(t.Name))
	}
	return fmt.Errorf("could not connect to %s after %d tries%s; try again with: %s", t.Name, tries, why, connectHint(t.Name))
}

func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// once is one connection: one relay.Attach.
func (a *attacher) once(ctx context.Context, g SessionGrant) (relay.AttachResult, bool, error) {
	actx, cancel := context.WithCancel(ctx)
	defer cancel()
	in := a.hub.open()
	defer in.close()
	var r io.Reader = in
	if a.asks != nil {
		r = a.asks.filter(in)
		a.asks.start(actx)
	}
	ch := make(chan relay.Resize, 4)
	a.sizeMu.Lock()
	a.sizeCh = ch
	sz := a.size
	a.sizeMu.Unlock()
	defer func() {
		a.sizeMu.Lock()
		a.sizeCh = nil
		a.sizeMu.Unlock()
	}()
	var connected atomic.Bool
	opts := relay.AttachOptions{
		BaseURL: a.tun.BaseURL(), Token: g.Token, Cols: sz.Cols, Rows: sz.Rows,
		LongPoll: a.mode == TransportLongPoll, HTTPClient: a.tun.HTTPClient(), Dialer: a.tun.Dialer(),
		Resize: ch,
		OnControl: func(c relay.Control) {
			if c.Type == relay.CtlHello {
				connected.Store(true)
			}
		},
	}
	if err := a.term.raw(); err != nil {
		return relay.AttachResult{}, false, &fatalError{fmt.Errorf("could not switch the terminal to raw mode: %w", err)}
	}
	defer a.term.restore()
	ar, err := relay.Attach(actx, r, a.scr, opts)
	return ar, connected.Load(), err
}

// classify sorts how a connection ended and gives the error to show.
func (a *attacher) classify(err error, connected bool) (outcome, error) {
	ws := a.mode == TransportWebSocket
	auto := a.o.Transport == TransportAuto
	if err == nil {
		// A WebSocket that closed before the relay's first frame is what a
		// proxy that lets the upgrade through but not the frames does.
		if !connected && ws && auto {
			return outBlocked, nil
		}
		return outLost, nil
	}
	var fe *fatalError
	if errors.As(err, &fe) {
		return outFatal, fe.err
	}
	var te *TunnelError
	if errors.As(err, &te) {
		switch {
		case te.Kind == ErrClusterFull:
			return outFull, te
		case te.transient():
			return outLost, te
		}
		return outFatal, te
	}
	var de *dialError
	if errors.As(err, &de) {
		if de.fatal {
			return outFatal, de
		}
		return outLost, de
	}
	switch st := relayStatus(err); st {
	case 503, 429:
		return outFull, err
	case 401:
		return outUnauthorized, err
	case 403:
		if ws && auto {
			return outBlocked, err
		}
		return outFatal, statusError(403, nil, a.o.Target)
	case 404:
		return outFatal, statusError(404, nil, a.o.Target)
	case 200, 400, 426, 502:
		if ws && auto {
			return outBlocked, err
		}
		return outLost, err
	case 0:
	default:
		return outLost, err
	}
	if ws && auto && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || isBadHandshake(err)) {
		return outBlocked, err
	}
	return outLost, err
}
