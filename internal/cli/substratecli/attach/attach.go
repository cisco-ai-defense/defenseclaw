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
	// Dir is the folder in the actor the agent starts in, and a task runs
	// in: the copy of the project (GAP-0163). "" keeps the relay default.
	Dir string
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
	MaxWait time.Duration
	// Health, when set, is asked before each such wait: an error (the agent
	// crashed) ends the wait with it, since waiting cannot bring the agent
	// back (GAP-0410).
	Health func(ctx context.Context) error
	// ReconnectFor bounds how long a lost connection is retried, as when
	// the agent is suspended and resumes (default 3m, GAP-0003).
	ReconnectFor time.Duration
	// KeyReplay is what happens to keys typed while the link is down
	// (B3.1): ask (the default) offers them after the reconnect, on sends
	// them, off drops them and says how many. The caller passes the tighter
	// of the cluster value and the launcher flag (TightestKeyReplay).
	KeyReplay string
	Now       func() time.Time
	Sleep     func(context.Context, time.Duration) error
	NoBanner  bool
	NoAsks    bool
	// InitialSize is the terminal size when In is not a terminal
	// (default 80x24).
	InitialSize relay.Resize
	// SizeEvents adds size changes to the ones read from the terminal.
	SizeEvents <-chan relay.Resize
	// Notices are lines to show the person while attached (a bridged MCP
	// server's stderr, a bridge that ended). They go on the launcher's row,
	// where the agent cannot draw; with no row they go to Err.
	Notices <-chan string
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
	// Renewals counts the reconnects that were planned renews of an
	// expired session token (GAP-0588); Reconnects includes them.
	Renewals int
	// Transport is the transport in use at the end.
	Transport string
}

// ClusterFullMessage is what connect, attach and run print while they wait
// for room in a full cluster (GAP-0528: one wording for both).
const ClusterFullMessage = "The cluster is full. Waiting for room (Ctrl-C to stop)..."

// renewQuick and maxQuickRenews bound the planned renew (GAP-0588): a relay
// that ends a connection for an expired session token is reconnected at
// once, but connections that keep ending within renewQuick take the
// reconnect path with its backoff after maxQuickRenews of them.
const (
	renewQuick     = 5 * time.Second
	maxQuickRenews = 3
)

const (
	// stableAfter: a connection that lasted this long resets the backoff.
	stableAfter = 30 * time.Second
	fullMsg     = ClusterFullMessage
	startingMsg = "The agent is starting. Waiting for it (Ctrl-C to stop)..."
	lostMsg     = "Connection lost; reconnecting"
	backMsg     = "Reconnected."
	stopMsg     = "Stopped reconnecting. The agent keeps running. Come back with: "
	fallbackMsg = "WebSocket is blocked here; using the slower fallback"
)

func connectHint(name string) string { return "defenseclaw substrate connect " + name }

// lostStatus is the reconnect line: the attempt, the backoff before the
// next one and how long the link has been down (GAP-0423).
func lostStatus(attempt int, next, down time.Duration, replay string) string {
	keys := "keys typed now are not sent"
	switch replay {
	case KeyReplayAsk:
		keys = "keys typed now are offered when it is back"
	case KeyReplayOn:
		keys = "keys typed now are sent when it is back"
	}
	return fmt.Sprintf("%s: attempt %d, next in %s, down %s (Ctrl-] detaches; %s)...",
		lostMsg, attempt, fmtDur(next), fmtDur(down.Truncate(time.Second)), keys)
}

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
	switch o.KeyReplay {
	case "":
		o.KeyReplay = KeyReplayAsk
	case KeyReplayAsk, KeyReplayOn, KeyReplayOff:
	default:
		return fmt.Errorf("unknown key replay %q: use ask, on or off", o.KeyReplay)
	}
	o.Backoff = o.Backoff.withDefaults()
	if o.MaxWait <= 0 {
		o.MaxWait = 10 * time.Minute
	}
	if o.ReconnectFor <= 0 {
		o.ReconnectFor = 3 * time.Minute
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
	res, err = a.run(ctx)
	// The relay's warning again once the terminal is the person's: a
	// full-screen agent cleared it from the screen (GAP-0151).
	if w := a.warningText(); w != "" {
		fmt.Fprintf(o.Err, "Warning: %s\n", w)
	}
	return res, err
}

// noteWarning keeps the relay's hello warning and shows it on the
// launcher's row while no ask is shown there (GAP-0151).
func (a *attacher) noteWarning(w string) {
	w = safetext.Line(w)
	if w == "" {
		return
	}
	a.warnMu.Lock()
	a.warning = w
	a.warnMu.Unlock()
	if a.asks != nil {
		a.asks.setNotice("DefenseClaw warning: " + w)
	}
}

// showNotices puts each notice on the launcher's row, or on w when there is
// no row (no terminal, or asks are off).
func (a *attacher) showNotices(ch <-chan string, w io.Writer) {
	for {
		select {
		case <-a.stop:
			return
		case n, ok := <-ch:
			if !ok {
				return
			}
			n = safetext.Line(n)
			switch {
			case n == "":
			case a.asks != nil:
				a.asks.setNotice(n)
			default:
				fmt.Fprintln(w, n)
			}
		}
	}
}

func (a *attacher) warningText() string {
	a.warnMu.Lock()
	defer a.warnMu.Unlock()
	return a.warning
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

	// Input while the link is down (GAP-0003): it never goes to a screen
	// the person cannot see. outage keeps, in memory, the chunks the relay
	// client read but could not send when the connection ended and the
	// keys typed during the outage; after the reconnect they are offered
	// or sent (KeyReplay, B3.1) within the replay limits, or counted and
	// the person is told. lost is set while a lost connection is retried.
	outage outageBuf
	// maybe counts bytes sent that the relay's next hello does not count
	// (GAP-0170): it can read that count while the old connection still
	// drains keys it got, so they are only possibly lost.
	maybe atomic.Int64
	// prevInput and prevSent are the last relay greeting's input count id
	// and the bytes sent on that connection (GAP-0170).
	prevInput string
	prevSent  int64
	lost      atomic.Bool
	// renewed is set by a planned renew until the next greeting, and
	// helloAt is when the relay last greeted, in Unix ns (GAP-0588).
	renewed atomic.Bool
	helloAt atomic.Int64
	// drain is the outage reader: it runs from a lost connection until
	// the relay greets the next one.
	drainMu     sync.Mutex
	drainCtx    context.Context
	drainStop   func()
	drainCancel []context.CancelCauseFunc

	sizeMu sync.Mutex
	size   relay.Resize
	sizeCh chan relay.Resize

	// warning is the relay's hello warning (GAP-0151).
	warnMu  sync.Mutex
	warning string
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
	if o.Notices != nil {
		go a.showNotices(o.Notices, o.Err)
	}
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
	quickRenews := 0
	var lastErr error
	var outageStart time.Time
	defer a.endAllDrains()
	cur := ctx // a reconnect uses the outage context: Ctrl-] ends it too
	for {
		res.Transport = a.mode
		if err := ctx.Err(); err != nil {
			return res, err
		}
		began := o.Now()
		ar, connected, err := a.once(cur)
		if connected {
			connections++
			res.Reconnects = connections - 1
			outageStart = time.Time{}
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
		// The session token of the attachment ends: the launcher closed it
		// just before (the gateway's SessionSecondsHeader), or the relay
		// ended it at exp. The gateway caps the token at the end of the
		// sign-in, so this is a planned renew, not a loss. Reconnect at
		// once with a fresh bearer and no "Connection lost" line; the
		// keyboard is not drained, so what is typed meanwhile goes to the
		// next connection (GAP-0588). When the sign-in cannot be renewed,
		// the next connection fails with the sign-in-again message.
		if ar.Renew && connected {
			// Measured from the greeting: a slow sign-in refresh does not
			// make an attachment that ended at once look long.
			if o.Now().Sub(time.Unix(0, a.helloAt.Load())) < renewQuick {
				quickRenews++
			} else {
				quickRenews = 0
			}
			if quickRenews <= maxQuickRenews {
				res.Renewals++
				a.renewed.Store(true)
				continue
			}
		}
		// The link is down from here until the next connection: the
		// keyboard is read here, so Ctrl-] still detaches and what is
		// typed is counted, not silently lost.
		wctx := ctx
		if connections > 0 {
			// Before the first connection, type-ahead goes to the agent
			// as in a shell; after a loss it does not.
			wctx = a.beginDrain(ctx)
			cur = wctx
			a.lost.Store(true)
			if outageStart.IsZero() {
				outageStart = o.Now()
			}
		}
		k, kerr := a.classify(wctx, err, connected)
		if a.outageStopped(wctx, &res) {
			return res, nil
		}
		if connections > 0 && o.Now().Sub(outageStart) >= o.ReconnectFor {
			a.endLine()
			return res, a.reconnectGaveUp(o.Target, o.ReconnectFor, kerr)
		}
		switch k {
		case outFatal:
			a.endLine()
			return res, kerr
		case outWait:
			var re *RouteError
			errors.As(kerr, &re)
			if werr := park.wait(wctx, re); werr != nil {
				if a.outageStopped(wctx, &res) {
					return res, nil
				}
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
			return res, a.notSentErr(giveUp(o.Target, connections > 0, failures, lastErr))
		}
		wait := rec.next()
		switch {
		case connections > 0:
			// Every attempt updates the line (GAP-0423).
			a.say(lostStatus(failures, wait, o.Now().Sub(outageStart), o.KeyReplay), false)
		case !lostShown && kerr != nil:
			lostShown = true
			a.say("Could not connect yet ("+kerr.Error()+"); retrying...", false)
		}
		if serr := o.Sleep(wctx, wait); serr != nil {
			if a.outageStopped(wctx, &res) {
				return res, nil
			}
			return res, ctxErr(ctx, serr)
		}
	}
}

// errOutageDetach and errOutageStop end a wait for the link: Ctrl-] or
// Ctrl-C typed while it was down.
var (
	errOutageDetach = errors.New("detached while reconnecting")
	errOutageStop   = errors.New("stopped while reconnecting")
)

// draining reports that the outage reader runs.
func (a *attacher) draining() bool {
	a.drainMu.Lock()
	defer a.drainMu.Unlock()
	return a.drainStop != nil
}

// beginDrain starts the outage reader (once per outage) and returns its
// context.
func (a *attacher) beginDrain(ctx context.Context) context.Context {
	a.drainMu.Lock()
	defer a.drainMu.Unlock()
	if a.drainStop == nil {
		var cancel context.CancelCauseFunc
		a.drainCtx, a.drainStop, cancel = a.drainInput(ctx)
		a.drainCancel = append(a.drainCancel, cancel)
	}
	return a.drainCtx
}

// endDrain stops the outage reader; its context stays valid for the
// connection it carried.
func (a *attacher) endDrain() {
	a.drainMu.Lock()
	stop := a.drainStop
	a.drainStop = nil
	a.drainMu.Unlock()
	if stop != nil {
		stop()
	}
}

func (a *attacher) endAllDrains() {
	a.endDrain()
	a.drainMu.Lock()
	defer a.drainMu.Unlock()
	for _, c := range a.drainCancel {
		c(nil)
	}
	a.drainCancel = nil
}

// drainInput reads the keyboard while the link is down, until stop is
// called. Ctrl-] or Ctrl-C cancel the returned context (the wait ends at
// once); every other byte is counted as not sent and the status line says
// so. A wait that uses the context ends when the person stops it.
func (a *attacher) drainInput(ctx context.Context) (context.Context, func(), context.CancelCauseFunc) {
	wctx, cancel := context.WithCancelCause(ctx)
	quit := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer a.term.guard()
		noted := false
		for {
			select {
			case <-quit:
				return
			case <-wctx.Done():
				return
			case <-a.hub.eof:
				return
			case b := <-a.hub.ch:
				for i, c := range b {
					switch c {
					case relay.DetachKey:
						a.outage.addTyped(b[:i], a.o.Now())
						cancel(errOutageDetach)
						return
					case 0x03:
						a.outage.addTyped(b[:i], a.o.Now())
						cancel(errOutageStop)
						return
					}
				}
				a.outage.addTyped(b, a.o.Now())
				if a.errTTY || !noted {
					noted = true
					a.say("Connection lost; reconnecting (Ctrl-] detaches)..."+a.notSentNote(" ", false), false)
				}
			}
		}
	}()
	var once sync.Once
	return wctx, func() {
		once.Do(func() {
			close(quit)
			<-done
		})
	}, cancel
}

// outageStopped reports a wait the person ended with Ctrl-] or Ctrl-C.
func (a *attacher) outageStopped(wctx context.Context, res *Result) bool {
	switch context.Cause(wctx) {
	case errOutageDetach, errOutageStop:
		res.Detached = true
		a.say(stopMsg+connectHint(a.o.Target.Name)+a.notSentNote(" ", true), true)
		return true
	}
	return false
}

// notSentNote says how much input was not sent (and with reset, starts
// counting again); "" when nothing was lost.
func (a *attacher) notSentNote(sep string, reset bool) string {
	n := a.outage.pending()
	if reset {
		var b []byte
		b, n = a.outage.take(a.o.Now())
		zero(b)
	} else if n > 0 && a.o.KeyReplay != KeyReplayOff && a.outage.held() {
		return sep + fmt.Sprintf("(%d typed character(s) held until it is back)", n)
	}
	return a.countNote(sep, n, reset)
}

// countNote says that n typed bytes were not sent and, with reset, names
// the bytes that may not have arrived (and starts counting them again).
func (a *attacher) countNote(sep string, n int64, reset bool) string {
	maybe := a.maybe.Load()
	if reset {
		a.maybe.Store(0)
	}
	note := ""
	switch {
	case n == 0:
	case reset:
		note = sep + notSentText(n)
	default:
		note = sep + fmt.Sprintf("(%d typed character(s) not sent)", n)
	}
	if maybe > 0 && reset {
		// Keys sent in the moment before the cut that the relay had not
		// counted when it greeted again: they may have reached the agent
		// after all (GAP-0170).
		note += sep + fmt.Sprintf("%d character(s) typed just before the connection dropped may not have reached the agent; check the prompt.", maybe)
	}
	return note
}

func (a *attacher) notSentErr(err error) error {
	if note := a.notSentNote(" ", true); note != "" {
		return fmt.Errorf("%w.%s", err, note)
	}
	return err
}

// reconnectGaveUp ends a reconnect that took longer than ReconnectFor.
func (a *attacher) reconnectGaveUp(t Target, d time.Duration, last error) error {
	why := ""
	if last != nil {
		why = " (" + safetext.Line(last.Error()) + ")"
	}
	return a.notSentErr(fmt.Errorf("could not reconnect to %s for %s%s; the agent keeps running (a suspended agent wakes when you connect). Come back with: %s", t.Name, fmtDur(d), why, connectHint(t.Name)))
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
	if a.draining() {
		in.gate = make(chan struct{})
	}
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
	// The relay's hello is read on the client's reader goroutine: it gets
	// copies, never the fields once() sets after the attach.
	resume, prevSent := a.prevInput, a.prevSent
	opts := relay.AttachOptions{
		// Token is the person's bearer: the WebSocket handshake carries it
		// from here, and HTTPClient puts a fresh one on every long-poll
		// request.
		BaseURL: a.tun.BaseURL(), Token: tok, Cols: sz.Cols, Rows: sz.Rows,
		LongPoll: a.mode == TransportLongPoll, HTTPClient: a.tun.HTTPClient(), Dialer: a.tun.Dialer(), FlatRoutes: true,
		Resize: ch, Dir: a.o.Dir, Resume: resume,
		OnControl: func(c relay.Control) {
			if c.Type == relay.CtlHello {
				connected.Store(true)
				a.noteWarning(c.Warning)
				a.helloAt.Store(a.o.Now().UnixNano())
				a.resumeHello(resume, prevSent, c.Received)
				a.endDrain()
				if a.lost.Swap(false) {
					a.renewed.Store(false)
					a.replayAfterReconnect(in)
				} else if a.renewed.Swap(false) {
					// A renew shows nothing, unless keys typed at the cut
					// may not have reached the agent (GAP-0170).
					in.openGate()
					if note := a.notSentNote(" ", true); note != "" {
						a.say(backMsg+note, true)
					}
				} else {
					in.openGate()
				}
			}
		},
		OnUnsent: func(b []byte) { a.outage.addUnsent(b, a.o.Now()) },
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
	if ar.Input != "" {
		a.prevInput, a.prevSent = ar.Input, ar.Sent
	}
	return ar, connected.Load(), err
}

// resumeHello squares what this launcher counted as sent on the input it
// resumes with what the relay's hello says it received. Fewer: the rest
// was lost on the way (a suspend) and may not have reached the agent.
// More: a chunk reported unsent did arrive (the reply was lost, long-poll
// through a proxy 502 or a gateway restart); those bytes lead the unsent
// part and are dropped, never replayed (RV1 P2-2). No count at all on a
// resumed input: the relay started a fresh session (the actor restarted),
// so the keys typed for the old prompt are never replayed into it, only
// counted (RV1 P3-1).
func (a *attacher) resumeHello(resume string, prevSent int64, received *int64) {
	if resume == "" {
		return
	}
	if received == nil {
		a.outage.spoil()
		return
	}
	switch got := *received; {
	case got < prevSent:
		a.maybe.Add(prevSent - got)
	case got > prevSent:
		a.outage.arrived(got - prevSent)
	}
}

// replayAfterReconnect opens the input of a connection the relay greeted
// after an outage (B3.1). The keys that did not reach the agent go first,
// before any live key, and only within the replay limits: in ask mode they
// are shown and the person's next key decides (Enter sends them), in on
// mode they are sent at once. Otherwise, or when nothing may be replayed,
// the person is told how many were not sent. The bytes that may have
// arrived (maybe) are never replayed.
func (a *attacher) replayAfterReconnect(in *inReader) {
	b, n := a.outage.take(a.o.Now())
	if b == nil || a.o.KeyReplay == KeyReplayOff || !in.gated() {
		zero(b)
		in.openGate()
		a.say(backMsg+a.countNote(" ", n, true), true)
		return
	}
	k := int64(len(b))
	if a.o.KeyReplay == KeyReplayOn {
		in.openGateReplay(b, false, nil)
		a.say(backMsg+fmt.Sprintf(" Sent %d key(s) typed while disconnected.", k)+a.countNote(" ", 0, true), true)
		return
	}
	text := replayAskText(b)
	in.openGateReplay(b, true, func(sent bool) {
		if !sent {
			a.say(notSentText(k), true)
		}
	})
	a.say(backMsg+a.countNote(" ", 0, true)+" "+text, true)
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
