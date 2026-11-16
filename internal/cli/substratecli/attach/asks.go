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
	"io"
	"sort"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

const (
	askPollEvery = 2 * time.Second
	askPollMax   = 30 * time.Second
	// askArmDelay: a key this soon after the answer prompt (or its
	// confirmation) appears was not typed in answer to it (a paste that
	// arrives one byte at a time); it cancels the prompt.
	askArmDelay    = 250 * time.Millisecond
	askConfirmFor  = 2 * time.Second
	askTick        = 200 * time.Millisecond
	askDecideLimit = 15 * time.Second
	// askChord is Ctrl-\. Raw mode turns the terminal's signal keys off, so
	// it arrives as a byte; it opens the answer prompt only when it is the
	// whole keyboard read and an ask is pending.
	askChord    = 0x1c
	askIDMax    = 16
	askActorMax = 64

	askHeadLabel   = "DefenseClaw ask "
	askAnnounceEnd = " -- press Ctrl-\\ to answer"
	askModalEnd    = " -- [o]nce [a]lways [d]eny [Esc] cancel"
	askAlwaysText  = ": Approve this and every later identical ask?"
	askAlwaysEnd   = " press y to confirm, anything else cancels"
)

type askMode int

const (
	modeNone    askMode = iota
	modeAsk             // the answer prompt is open
	modeConfirm         // "always" waits for y
)

// askUI shows the pending asks of the attached actor on the launcher's row
// (the last terminal row) and takes an answer only through a deliberate
// chord: Ctrl-\ opens a prompt that holds the agent's output and takes one
// key (o, d, or a then y). Ordinary typing and pastes reach the agent and
// never answer.
type askUI struct {
	src   AskSource
	t     Target
	scr   *screen
	size  func() relay.Resize
	now   func() time.Time
	guard func()

	mu           sync.Mutex
	ctx          context.Context
	cancel       context.CancelFunc
	active       bool
	queue        []Ask
	cur          *Ask
	mode         askMode
	armedAt      time.Time
	sending      string // the ask whose answer is in flight
	errText      string // why the last answer was not sent
	decided      map[string]bool
	confirm      string
	confirmUntil time.Time
}

func newAskUI(src AskSource, t Target, scr *screen, size func() relay.Resize, now func() time.Time, guard func()) *askUI {
	u := &askUI{src: src, t: t, scr: scr, size: size, now: now, guard: guard, decided: map[string]bool{}, ctx: context.Background(), active: true}
	scr.onOverflow = u.overflow
	return u
}

// start polls and redraws until ctx (one connection) ends or stop runs.
func (u *askUI) start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	u.mu.Lock()
	u.ctx, u.cancel, u.active, u.mode = ctx, cancel, true, modeNone
	u.drawLocked()
	u.mu.Unlock()
	go u.pollLoop(ctx)
	go u.drawLoop(ctx)
}

// stop ends one connection's prompt: an open prompt closes with no answer.
func (u *askUI) stop() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cancel != nil {
		u.cancel()
	}
	u.closeModalLocked()
	u.active = false
}

func (u *askUI) pollLoop(ctx context.Context) {
	defer u.guard()
	fails := 0
	for {
		list, err := u.src.Pending(ctx, u.t)
		wait := askPollEvery
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fails++
			wait = min(askPollEvery<<min(fails, 4), askPollMax)
		} else {
			fails = 0
			u.update(list)
		}
		if sleepCtx(ctx, wait) != nil {
			return
		}
	}
}

func (u *askUI) drawLoop(ctx context.Context) {
	defer u.guard()
	tick := time.NewTicker(askTick)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		u.tick()
	}
}

// tick clears an expired confirmation.
func (u *askUI) tick() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.confirm != "" && !u.now().Before(u.confirmUntil) {
		u.confirm = ""
		u.drawLocked()
	}
}

// update takes the pending list. Only asks of exactly this actor count; an
// ask no longer pending leaves (its prompt closes), new ones queue in the
// order they were created.
func (u *askUI) update(list []Ask) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.active {
		return
	}
	me := u.t.String()
	pending := map[string]bool{}
	var mine []Ask
	for _, a := range list {
		if a.ID == "" || a.Actor == "" || a.Actor != me {
			continue
		}
		pending[a.ID] = true
		mine = append(mine, a)
	}
	changed := false
	q := u.queue[:0]
	for _, a := range u.queue {
		if pending[a.ID] {
			q = append(q, a)
		}
	}
	u.queue = q
	if u.cur != nil && !pending[u.cur.ID] {
		u.closeModalLocked()
		u.cur, u.errText, changed = nil, "", true
	}
	known := map[string]bool{}
	if u.cur != nil {
		known[u.cur.ID] = true
	}
	for _, a := range u.queue {
		known[a.ID] = true
	}
	var fresh []Ask
	for _, a := range mine {
		if !known[a.ID] && !u.decided[a.ID] {
			known[a.ID] = true
			fresh = append(fresh, a)
		}
	}
	sort.SliceStable(fresh, func(i, j int) bool { return fresh[i].Created.Before(fresh[j].Created) })
	u.queue = append(u.queue, fresh...)
	for id := range u.decided {
		if !pending[id] {
			delete(u.decided, id)
		}
	}
	if u.cur == nil && len(u.queue) > 0 {
		u.showNextLocked()
		changed = true
	}
	if changed {
		u.drawLocked()
	}
}

func (u *askUI) showNextLocked() {
	a := u.queue[0]
	u.queue = u.queue[1:]
	u.cur, u.errText = &a, ""
}

// input routes one keyboard read and returns what reaches the agent. paste
// says the read is (in part) a bracketed paste. swallow asks the caller to
// drop the rest of a paste that closed the prompt.
func (u *askUI) input(b []byte, paste bool) (fwd []byte, swallow bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.mode == modeNone {
		if u.cur == nil || !u.active {
			return b, false
		}
		if !paste && len(b) == 1 && b[0] == askChord && u.sending != u.cur.ID {
			u.openModalLocked()
			return nil, false
		}
		// The chord inside a paste or a burst neither opens the prompt nor
		// reaches the agent.
		return dropByte(b, askChord), false
	}
	if bytes.IndexByte(b, relay.DetachKey) >= 0 {
		u.closeModalLocked()
		return []byte{relay.DetachKey}, paste
	}
	// Only one key on its own, after the prompt could be seen, answers.
	if paste || len(b) != 1 || u.now().Sub(u.armedAt) < askArmDelay {
		u.closeModalLocked()
		return nil, paste
	}
	switch k := b[0]; {
	case u.mode == modeAsk && (k == 'o' || k == 'O'):
		u.decideLocked(DecideOnce)
	case u.mode == modeAsk && (k == 'd' || k == 'D'):
		u.decideLocked(DecideDeny)
	case u.mode == modeAsk && (k == 'a' || k == 'A'):
		u.mode, u.armedAt = modeConfirm, u.now()
		u.drawLocked()
	case u.mode == modeConfirm && (k == 'y' || k == 'Y'):
		u.decideLocked(DecideAlways)
	default:
		u.closeModalLocked()
	}
	return nil, false
}

func dropByte(b []byte, c byte) []byte {
	if bytes.IndexByte(b, c) < 0 {
		return b
	}
	out := b[:0]
	for _, x := range b {
		if x != c {
			out = append(out, x)
		}
	}
	return out
}

func (u *askUI) openModalLocked() {
	u.mode, u.armedAt, u.errText = modeAsk, u.now(), ""
	u.scr.setHold(true)
	u.drawLocked()
}

// closeModalLocked closes the prompt with no answer and shows the held
// output.
func (u *askUI) closeModalLocked() {
	if u.mode == modeNone {
		return
	}
	u.mode = modeNone
	u.drawLocked()
	u.scr.setHold(false)
}

// overflow runs when the agent printed more than the screen holds: the
// prompt closes with no answer.
func (u *askUI) overflow() {
	go func() {
		defer u.guard()
		u.mu.Lock()
		defer u.mu.Unlock()
		if u.mode != modeNone {
			u.mode = modeNone
			u.errText = "the agent printed too much while the prompt was open, nothing was sent"
			u.drawLocked()
		}
	}()
}

// decideLocked sends the answer once, in the background. Until the cluster
// takes it the ask stays shown; a failure keeps it pending.
func (u *askUI) decideLocked(d Decision) {
	a := *u.cur
	u.sending, u.mode = a.ID, modeNone
	u.drawLocked()
	u.scr.setHold(false)
	ctx := u.ctx
	go func() {
		defer u.guard()
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), askDecideLimit)
		defer cancel()
		err := u.src.Decide(dctx, a.ID, d)
		u.mu.Lock()
		defer u.mu.Unlock()
		if u.sending == a.ID {
			u.sending = ""
		}
		here := u.cur != nil && u.cur.ID == a.ID
		if err != nil {
			if here {
				u.errText = safetext.Line(err.Error())
				u.drawLocked()
			}
			return
		}
		u.decided[a.ID] = true
		u.confirm, u.confirmUntil = doneText(d, a), u.now().Add(askConfirmFor)
		if here {
			u.cur, u.errText = nil, ""
			if len(u.queue) > 0 {
				u.showNextLocked()
			}
		}
		u.drawLocked()
	}()
}

func (u *askUI) drawLocked() {
	if !u.active {
		return
	}
	u.scr.setRow(u.rowLocked())
}

// rowLocked is the launcher's row. Every row about an ask starts with the
// fixed label and the ask id, and names the actor.
func (u *askUI) rowLocked() string {
	cols := int(u.size().Cols)
	a := u.cur
	switch {
	case a != nil && u.mode == modeAsk:
		return rowText(askHead(*a), askFrom(*a)+": "+askLabel(*a), askModalEnd, cols)
	case a != nil && u.mode == modeConfirm:
		return rowText(askHead(*a), askAlwaysText, askAlwaysEnd, cols)
	case u.confirm != "" && u.now().Before(u.confirmUntil):
		return fitWidth(u.confirm, max(cols-1, 1))
	case a != nil && u.sending == a.ID:
		return rowText(askHead(*a), askFrom(*a)+": sending the answer...", "", cols)
	case a != nil && u.errText != "":
		return rowText(askHead(*a), askFrom(*a)+": the answer was not sent: "+u.errText, askAnnounceEnd, cols)
	case a != nil:
		return rowText(askHead(*a), askFrom(*a)+": "+askLabel(*a), askAnnounceEnd, cols)
	}
	return ""
}

func askHead(a Ask) string { return askHeadLabel + fitWidth(safetext.Line(a.ID), askIDMax) }

func askFrom(a Ask) string { return " from " + fitWidth(safetext.Line(a.Actor), askActorMax) }

func askLabel(a Ask) string {
	s := safetext.Line(a.Summary)
	if s == "" {
		s = safetext.Line(a.Tool + " " + a.Reason)
	}
	if s == "" {
		s = "an action needs your answer"
	}
	if sev := safetext.Line(a.Severity); sev != "" {
		s = fitWidth(sev, 16) + ": " + s
	}
	return s
}

// rowText fits head+mid+tail to cols-1 columns (the last column would wrap
// on some terminals). The head and the keys stay; the middle is cut.
func rowText(head, mid, tail string, cols int) string {
	w := max(cols-1, 1)
	room := w - textWidth(head) - textWidth(tail)
	if room >= 4 {
		return head + fitWidth(mid, room) + tail
	}
	return fitWidth(head+mid+tail, w)
}

func doneText(d Decision, a Ask) string {
	what := "denied"
	switch d {
	case DecideOnce:
		what = "allowed once"
	case DecideAlways:
		what = "allowed always"
	}
	return askHead(a) + ": " + what + ": " + askLabel(a)
}

// runeWidth over-counts: anything from U+1100 on may be two columns wide.
func runeWidth(r rune) int {
	if r >= 0x1100 {
		return 2
	}
	return 1
}

func textWidth(s string) int {
	n := 0
	for _, r := range s {
		n += runeWidth(r)
	}
	return n
}

// fitWidth truncates s to n columns, ending in "..." when cut.
func fitWidth(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if textWidth(s) <= n {
		return s
	}
	tail := "..."
	if n <= 3 {
		tail = ""
	}
	room := n - len(tail)
	var b []rune
	w := 0
	for _, r := range s {
		if w+runeWidth(r) > room {
			break
		}
		w += runeWidth(r)
		b = append(b, r)
	}
	return string(b) + tail
}

// filter wraps the keyboard: while no prompt is open every byte reaches
// the agent (the chord excepted while an ask is pending); while it is open
// nothing does but Ctrl-], so the relay's detach keeps working.
func (u *askUI) filter(r io.Reader) io.Reader { return &askFilter{r: r, ui: u} }

type keySink interface {
	input(b []byte, paste bool) ([]byte, bool)
}

type askFilter struct {
	r  io.Reader
	ui keySink
	// st: 0 plain, 1 after ESC, 2 in a CSI sequence, 3 after ESC O.
	st      int
	params  []byte
	paste   bool
	swallow bool
}

func (f *askFilter) Read(p []byte) (int, error) {
	for {
		n, err := f.r.Read(p)
		if n > 0 {
			m := f.apply(p, n)
			if m > 0 || err != nil {
				return m, err
			}
			continue
		}
		return 0, err
	}
}

// apply routes the n bytes read into p and returns how many are kept.
func (f *askFilter) apply(p []byte, n int) int {
	b := p[:n]
	inPaste := f.paste
	paste := f.scan(b) || inPaste
	if f.swallow {
		f.swallow = f.paste
		if bytes.IndexByte(b, relay.DetachKey) >= 0 {
			p[0] = relay.DetachKey
			return 1
		}
		return 0
	}
	fwd, swallow := f.ui.input(b, paste)
	f.swallow = swallow && f.paste
	return copy(p, fwd)
}

// scan follows escape sequences across reads to see bracketed pastes
// (ESC[200~ ... ESC[201~); it reports whether one starts in b.
func (f *askFilter) scan(b []byte) (started bool) {
	for _, c := range b {
		switch f.st {
		case 1:
			switch c {
			case '[':
				f.st, f.params = 2, f.params[:0]
			case 'O':
				f.st = 3
			default:
				f.st = 0
			}
		case 2:
			if c >= 0x40 && c <= 0x7e {
				if c == '~' {
					switch string(f.params) {
					case "200":
						f.paste, started = true, true
					case "201":
						f.paste = false
					}
				}
				f.st = 0
			} else if len(f.params) < 16 {
				f.params = append(f.params, c)
			}
		case 3:
			f.st = 0
		default:
			if c == 0x1b {
				f.st = 1
			}
		}
	}
	return started
}
