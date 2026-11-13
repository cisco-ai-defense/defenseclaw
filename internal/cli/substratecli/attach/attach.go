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
// Agent Substrate actor. It reaches the actor relay only through the attach
// route of the cluster gateway's admin listener (HTTPS, the person's OIDC
// bearer on every request; the gateway checks ownership and adds the relay
// session itself) and speaks dcrelay/1 there through the relay package's
// client (internal/substrate/relay). On top it adds what
// a person at a terminal needs: a banner, raw mode and resize, Ctrl-] to
// detach, reconnect with backoff, waiting while the cluster is full, a
// long-poll fallback where WebSocket is blocked (E27) and inline asks.
package attach

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// Target names one actor.
type Target struct{ Atespace, Name string }

// String is atespace/name.
func (t Target) String() string { return t.Atespace + "/" + t.Name }

// Ask is one pending ask (an approval a hook is waiting for).
type Ask struct {
	ID, Tool, Summary, Reason, Severity string
	// Actor is the actor that raised it, atespace/name as the cluster
	// reports it. Attach shows only asks whose Actor is exactly the
	// attached actor.
	Actor   string
	Created time.Time
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
	Target Target
	// Gateway is the cluster's admin listener.
	Gateway Gateway
	// Bearer gives the person's OIDC token for every request.
	Bearer BearerFunc
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
	// MaxWait bounds the wait while the cluster is full or the agent is
	// starting (default 10m).
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
	startingMsg = "The agent is starting. Waiting for it (Ctrl-C to stop)..."
	lostMsg     = "Connection lost; reconnecting..."
	fallbackMsg = "WebSocket is blocked here; using the slower fallback"
)

func connectHint(name string) string { return "defenseclaw substrate connect " + name }

func (o *Options) normalize() error {
	if err := o.Target.validate(); err != nil {
		return err
	}
	if o.Bearer == nil {
		return errors.New("no sign-in configured for this cluster; run: defenseclaw substrate login")
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
	a, err := newAttacher(ctx, o)
	if err != nil {
		return Result{}, err
	}
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

func newAttacher(ctx context.Context, o Options) (*attacher, error) {
	l, err := newLink(ctx, o)
	if err != nil {
		return nil, err
	}
	a := &attacher{link: l, stop: make(chan struct{})}
	a.term = newTerminal(o.In, o.Out)
	a.term.enableVT()
	a.mode = TransportWebSocket
	if o.Transport == TransportLongPoll {
		a.mode = TransportLongPoll
	}
	a.scr = newScreen(o.Out, a.currentSize)
	a.size = o.InitialSize
	if sz, ok := a.term.size(); ok {
		a.size = sz
	}
	a.hub = newInputHub(o.In, a.term.guard)
	if o.Asks != nil && !o.NoAsks && a.term.tty {
		// The last row is the launcher's: the agent is told about one row
		// less and cannot draw there (GAP-0100).
		a.scr.reserve = true
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
	return a, nil
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
		case a.sizeCh <- reservedSize(rs, a.asks != nil):
		default:
		}
	}
	a.sizeMu.Unlock()
	if a.asks != nil {
		a.scr.redraw()
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

func (a *attacher) run(ctx context.Context) (Result, error) {
	o := a.o
	var res Result
	rec := newRetry(o.Backoff)
	park := a.newParker()
	failures, connections := 0, 0
	lostShown := false
	var lastErr error
	for {
		res.Transport = a.mode
		if err := ctx.Err(); err != nil {
			return res, err
		}
		began := o.Now()
		ar, connected, err := a.once(ctx)
		if connected {
			connections++
			res.Reconnects = connections - 1
			park.reset()
			a.pending = false
			failures, lostShown = 0, false
			if a.mode == TransportWebSocket {
				a.wsBlocked = 0
			}
			if o.Now().Sub(began) > stableAfter {
				rec.reset()
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
		k, kerr := a.classify(ctx, err, connected)
		switch k {
		case outFatal:
			a.endLine()
			return res, kerr
		case outWait:
			var re *RouteError
			errors.As(kerr, &re)
			if werr := park.wait(ctx, re); werr != nil {
				return res, werr
			}
			continue
		case outBlocked:
			a.wsBlocked++
			if a.wsBlocked >= 2 {
				a.mode = TransportLongPoll
				a.say(fallbackMsg, true)
				continue
			}
		}
		if kerr != nil {
			lastErr = kerr
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
			} else if kerr != nil {
				a.say("Could not connect yet ("+kerr.Error()+"); retrying...", false)
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
		why = " (" + safetext.Line(last.Error()) + ")"
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

// once is one connection: one relay.Attach with a fresh bearer.
func (a *attacher) once(ctx context.Context) (relay.AttachResult, bool, error) {
	tok, err := a.tun.Bearer(ctx)
	if err != nil {
		return relay.AttachResult{}, false, err
	}
	actx, cancel := context.WithCancel(ctx)
	defer cancel()
	in := a.hub.open()
	defer in.close()
	var r io.Reader = in
	ch := make(chan relay.Resize, 4)
	a.sizeMu.Lock()
	a.sizeCh = ch
	sz := reservedSize(a.size, a.asks != nil)
	a.sizeMu.Unlock()
	defer func() {
		a.sizeMu.Lock()
		a.sizeCh = nil
		a.sizeMu.Unlock()
	}()
	var connected atomic.Bool
	opts := relay.AttachOptions{
		// Token is the person's bearer: the WebSocket handshake carries it
		// from here, and HTTPClient puts a fresh one on every long-poll
		// request.
		BaseURL: a.tun.BaseURL(), Token: tok, Cols: sz.Cols, Rows: sz.Rows,
		LongPoll: a.mode == TransportLongPoll, HTTPClient: a.tun.HTTPClient(), Dialer: a.tun.Dialer(), FlatRoutes: true,
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
	a.scr.begin()
	defer a.scr.end()
	if a.asks != nil {
		r = a.asks.filter(in)
		a.asks.start(actx)
		defer a.asks.stop()
	}
	ar, err := relay.Attach(actx, r, a.scr, opts)
	return ar, connected.Load(), err
}

// classify sorts how a connection ended and gives the error to show.
func (a *attacher) classify(ctx context.Context, err error, connected bool) (outcome, error) {
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
	if ws {
		if st := relayStatus(err); st != 0 {
			return a.handshakeRefused(ctx, st, err)
		}
		if auto && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || isBadHandshake(err)) {
			return outBlocked, err
		}
		// The WebSocket dialer's own TLS and network errors.
		var fe *fatalError
		var be *bearerError
		if !errors.As(err, &fe) && !errors.As(err, &be) {
			err = a.tun.netError(err)
		}
	}
	return a.judge(err)
}

// handshakeRefused sorts a WebSocket handshake answered with status st. A
// proxy on the way may refuse the upgrade with any status, so a plain
// request to the same route (the relay status) tells the gateway's answer
// apart from the proxy's.
func (a *attacher) handshakeRefused(ctx context.Context, st int, err error) (outcome, error) {
	ps, perr := a.probe(ctx)
	switch {
	case perr != nil:
		if k, e := a.judge(perr); k == outFatal {
			return k, e
		}
		return a.statusOutcome(st, err)
	case ps == http.StatusOK:
		// Plain requests reach the relay: only the upgrade was refused.
		if a.o.Transport == TransportAuto {
			return outBlocked, err
		}
		return outLost, err
	}
	return a.statusOutcome(ps, err)
}

// probe asks the relay status through the route and returns the status.
func (a *attacher) probe(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, relay.RouteURL(a.tun.BaseURL(), relay.RouteStatus), nil)
	if err != nil {
		return 0, err
	}
	resp, err := a.tun.HTTPClient().Do(req)
	if err != nil {
		return 0, err
	}
	drain(resp)
	return resp.StatusCode, nil
}
