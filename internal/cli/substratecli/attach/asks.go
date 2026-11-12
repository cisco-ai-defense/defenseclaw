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
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

const (
	askPollEvery = 2 * time.Second
	askPollMax   = 30 * time.Second
	// askArmDelay: keys typed this soon after a prompt appears were meant
	// for the agent (the person had not seen the prompt yet).
	askArmDelay    = 400 * time.Millisecond
	askConfirmFor  = 2 * time.Second
	askRedrawQuiet = 100 * time.Millisecond
	askTick        = 200 * time.Millisecond
	askDecideLimit = 15 * time.Second
	askPrefix      = "DefenseClaw asks: "
	askSuffix      = " [o]nce [a]lways [d]eny"
)

// screen is the agent's output. It remembers when the agent last wrote so
// the ask row is redrawn only once the agent's output settles.
type screen struct {
	mu    sync.Mutex
	w     io.Writer
	now   func() time.Time
	dirty bool
	last  time.Time
}

func (s *screen) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.w.Write(p)
	s.dirty, s.last = true, s.now()
	return n, err
}

func (s *screen) draw(seq string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = io.WriteString(s.w, seq)
}

// settled reports, once, that the agent wrote and then stayed quiet.
func (s *screen) settled(quiet time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirty && s.now().Sub(s.last) >= quiet {
		s.dirty = false
		return true
	}
	return false
}

// askUI shows pending asks on the bottom row of the terminal and takes the
// answer from the keyboard.
type askUI struct {
	src   AskSource
	t     Target
	scr   *screen
	size  func() relay.Resize
	now   func() time.Time
	guard func()

	mu           sync.Mutex
	ctx          context.Context
	queue        []Ask
	cur          *Ask
	shownAt      time.Time
	decided      map[string]bool
	confirm      string
	confirmUntil time.Time
	drawn        bool
}

func newAskUI(src AskSource, t Target, scr *screen, size func() relay.Resize, now func() time.Time, guard func()) *askUI {
	return &askUI{src: src, t: t, scr: scr, size: size, now: now, guard: guard, decided: map[string]bool{}, ctx: context.Background()}
}

// start polls and redraws until ctx (one connection) ends.
func (u *askUI) start(ctx context.Context) {
	u.mu.Lock()
	u.ctx = ctx
	u.mu.Unlock()
	go u.pollLoop(ctx)
	go u.drawLoop(ctx)
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

// tick redraws the row after the agent's output settles, and clears an
// expired confirmation.
func (u *askUI) tick() {
	u.mu.Lock()
	defer u.mu.Unlock()
	showing := u.cur != nil || (u.confirm != "" && u.now().Before(u.confirmUntil))
	switch {
	case showing && u.scr.settled(askRedrawQuiet):
		u.drawLocked()
	case !showing && u.drawn:
		u.confirm = ""
		u.drawLocked()
	}
}

// update takes the pending list: asks no longer pending leave (their
// prompt clears), new ones queue in the order they were created.
func (u *askUI) update(list []Ask) {
	u.mu.Lock()
	defer u.mu.Unlock()
	pending := make(map[string]bool, len(list))
	for _, a := range list {
		pending[a.ID] = true
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
		u.cur, changed = nil, true
	}
	known := map[string]bool{}
	if u.cur != nil {
		known[u.cur.ID] = true
	}
	for _, a := range u.queue {
		known[a.ID] = true
	}
	fresh := make([]Ask, 0, len(list))
	for _, a := range list {
		if a.ID != "" && !known[a.ID] && !u.decided[a.ID] {
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
	u.cur, u.shownAt = &a, u.now()
}

// key answers the shown ask. It reports false (the key goes to the agent)
// when no prompt is shown or it appeared too recently.
func (u *askUI) key(d Decision) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cur == nil || u.now().Sub(u.shownAt) < askArmDelay {
		return false
	}
	a := *u.cur
	u.decided[a.ID] = true
	u.cur = nil
	u.confirm, u.confirmUntil = confirmText(d, a), u.now().Add(askConfirmFor)
	if len(u.queue) > 0 {
		u.showNextLocked()
	}
	u.drawLocked()
	ctx := u.ctx
	go func() {
		defer u.guard()
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), askDecideLimit)
		defer cancel()
		if err := u.src.Decide(dctx, a.ID, d); err != nil {
			u.mu.Lock()
			u.confirm, u.confirmUntil = "DefenseClaw: the answer was not sent: "+clean(err.Error()), u.now().Add(askConfirmFor)
			if u.cur == nil {
				u.drawLocked()
			}
			u.mu.Unlock()
		}
	}()
	return true
}

func (u *askUI) redraw() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.drawn || u.cur != nil {
		u.drawLocked()
	}
}

func (u *askUI) drawLocked() {
	sz := u.size()
	cols, rows := int(sz.Cols), int(sz.Rows)
	var text string
	switch {
	case u.cur != nil:
		text = promptText(*u.cur, cols)
	case u.confirm != "" && u.now().Before(u.confirmUntil):
		text = fit(u.confirm, cols-1)
	default:
		if u.drawn {
			u.scr.draw(clearRow(rows))
			u.drawn = false
		}
		return
	}
	u.scr.draw(drawRow(rows, text))
	u.drawn = true
}

// drawRow writes text on the bottom row and puts the cursor back (ESC 7,
// ESC 8): nothing scrolls.
func drawRow(rows int, text string) string {
	return "\x1b7\x1b[" + strconv.Itoa(rows) + ";1H\x1b[2K\x1b[7m" + text + "\x1b[0m\x1b8"
}

func clearRow(rows int) string {
	return "\x1b7\x1b[" + strconv.Itoa(rows) + ";1H\x1b[2K\x1b8"
}

func askLabel(a Ask) string {
	s := clean(a.Summary)
	if s == "" {
		s = clean(strings.TrimSpace(a.Tool + " " + a.Reason))
	}
	if s == "" {
		s = "an action needs your answer"
	}
	return s
}

// promptText fits the prompt to cols-1 columns (the last column would wrap
// on some terminals), keeping the keys visible.
func promptText(a Ask, cols int) string {
	w := max(cols-1, 1)
	s := askLabel(a)
	room := w - len([]rune(askPrefix)) - len([]rune(askSuffix))
	if room >= 4 {
		return askPrefix + fit(s, room) + askSuffix
	}
	return fit(askPrefix+s+askSuffix, w)
}

func confirmText(d Decision, a Ask) string {
	switch d {
	case DecideOnce:
		return "DefenseClaw: allowed once: " + askLabel(a)
	case DecideAlways:
		return "DefenseClaw: allowed always: " + askLabel(a)
	}
	return "DefenseClaw: denied: " + askLabel(a)
}

// clean drops control characters: a summary must not move the cursor or
// change the terminal.
func clean(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return ' '
		}
		return r
	}, s))
}

// fit truncates s to n runes, ending in "..." when cut.
func fit(s string, n int) string {
	r := []rune(s)
	if n <= 0 {
		return ""
	}
	if len(r) <= n {
		return s
	}
	if n <= 3 {
		return string(r[:n])
	}
	return string(r[:n-3]) + "..."
}

// filter wraps the keyboard: while a prompt is shown o, a and d (either
// case) answer it instead of reaching the agent. Escape sequences (arrow
// keys and the like) and bracketed pastes always reach the agent, and so
// does Ctrl-], so the relay's detach keeps working.
func (u *askUI) filter(r io.Reader) io.Reader { return &askFilter{r: r, ui: u} }

type keySink interface{ key(Decision) bool }

type askFilter struct {
	r  io.Reader
	ui keySink
	// st: 0 plain, 1 after ESC, 2 in a CSI sequence, 3 after ESC O.
	st     int
	params []byte
	paste  bool
}

func (f *askFilter) Read(p []byte) (int, error) {
	for {
		n, err := f.r.Read(p)
		if n > 0 {
			m := f.apply(p[:n])
			if m > 0 || err != nil {
				return m, err
			}
			continue
		}
		return 0, err
	}
}

// apply filters b in place and returns the length kept.
func (f *askFilter) apply(b []byte) int {
	out := b[:0]
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
			out = append(out, c)
			continue
		case 2:
			out = append(out, c)
			if c >= 0x40 && c <= 0x7e {
				if c == '~' {
					switch string(f.params) {
					case "200":
						f.paste = true
					case "201":
						f.paste = false
					}
				}
				f.st = 0
			} else if len(f.params) < 16 {
				f.params = append(f.params, c)
			}
			continue
		case 3:
			out = append(out, c)
			f.st = 0
			continue
		}
		if c == 0x1b {
			f.st = 1
			out = append(out, c)
			continue
		}
		if !f.paste {
			if d, ok := decisionKey(c); ok && f.ui.key(d) {
				continue
			}
		}
		out = append(out, c)
	}
	return len(out)
}

func decisionKey(c byte) (Decision, bool) {
	switch c {
	case 'o', 'O':
		return DecideOnce, true
	case 'a', 'A':
		return DecideAlways, true
	case 'd', 'D':
		return DecideDeny, true
	}
	return "", false
}
