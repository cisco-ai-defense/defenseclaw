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
	"io"
	"strconv"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// holdMax bounds the agent output held while the person answers an ask.
// An agent that prints more closes the answer prompt (no decision).
const holdMax = 1 << 20

// screen is the agent's output on the person's terminal. Everything the
// agent writes goes through safetext.Stream (no clipboard, title, hyperlink,
// passthrough or window operations).
//
// With reserve set (asks on a terminal) the last row belongs to the
// launcher: the relay is told the terminal has one row less, cursor jumps
// and scroll regions that reach the last row are clamped, and the row is
// redrawn after every chunk of agent output, so the agent can neither hide
// it nor leave a forged one there. While hold is set (the person is
// answering an ask) the agent's output is kept back and shown afterwards.
type screen struct {
	mu   sync.Mutex
	w    io.Writer
	size func() relay.Resize
	f    safetext.Stream

	reserve bool
	active  bool
	row     string
	// rows is the height top and bot were set for; top and bot are the
	// agent's scroll region on the terminal (1-based, bot < rows).
	rows, top, bot int
	hold           bool
	held           []byte
	// onOverflow runs (under the screen's lock: it must not block) when the
	// held output passes holdMax and is shown.
	onOverflow func()
}

func newScreen(w io.Writer, size func() relay.Resize) *screen {
	return &screen{w: w, size: size}
}

// reservedSize is the size the agent is told: one row less when the
// launcher keeps the last row.
func reservedSize(rs relay.Resize, reserve bool) relay.Resize {
	if reserve && rs.Rows >= 2 {
		rs.Rows--
	}
	return rs
}

// layout reports the terminal size and whether the last row is reserved.
func (s *screen) layout() (rows, cols int, ok bool) {
	sz := s.size()
	rows, cols = int(sz.Rows), int(sz.Cols)
	if !s.reserve || !s.active || rows < 2 || cols < 1 {
		return rows, cols, false
	}
	if rows != s.rows {
		s.rows, s.top, s.bot = rows, 1, rows-1
	}
	return rows, cols, true
}

func (s *screen) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.f.Filter(p)
	rows, cols, ok := s.layout()
	if !ok {
		if len(b) > 0 {
			if _, err := s.w.Write(b); err != nil {
				return 0, err
			}
		}
		return len(p), nil
	}
	b = s.clampLocked(b, rows)
	if s.hold {
		if len(s.held)+len(b) <= holdMax {
			s.held = append(s.held, b...)
			return len(p), nil
		}
		b = append(s.held, b...)
		s.held, s.hold = nil, false
		if s.onOverflow != nil {
			s.onOverflow()
		}
	}
	if len(b) == 0 {
		return len(p), nil
	}
	if _, err := s.w.Write(append(b, s.rowSeqLocked(rows, cols)...)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// setRow sets the launcher's row ("" is a blank row) and draws it.
func (s *screen) setRow(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.row = text
	s.drawLocked()
}

func (s *screen) redraw() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drawLocked()
}

func (s *screen) drawLocked() {
	if rows, cols, ok := s.layout(); ok {
		_, _ = io.WriteString(s.w, s.rowSeqLocked(rows, cols))
	}
}

// setHold holds the agent's output (on) or shows what was held (off).
func (s *screen) setHold(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if on {
		s.hold = true
		return
	}
	if !s.hold {
		return
	}
	b := s.held
	s.hold, s.held = false, nil
	if rows, cols, ok := s.layout(); ok {
		_, _ = s.w.Write(append(b, s.rowSeqLocked(rows, cols)...))
	} else if len(b) > 0 {
		_, _ = s.w.Write(b)
	}
}

// begin starts one connection: a fresh filter, the cursor off the last row
// (a newline scrolls when it is there), the row and the scroll region drawn.
func (s *screen) begin() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active, s.f, s.rows, s.hold, s.held = true, safetext.Stream{}, 0, false, nil
	if rows, cols, ok := s.layout(); ok {
		_, _ = io.WriteString(s.w, "\r\n\x1b[A"+s.rowSeqLocked(rows, cols))
	}
}

// end gives the whole terminal back: held output shown, scroll region reset,
// the row cleared.
func (s *screen) end() {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.held
	if rows, _, ok := s.layout(); ok {
		b = append(b, "\x1b7\x1b[r\x1b["+strconv.Itoa(rows)+";1H\x1b[0m\x1b[2K\x1b8"...)
	}
	if len(b) > 0 {
		_, _ = s.w.Write(b)
	}
	s.active, s.hold, s.held, s.row = false, false, nil, ""
}

// rowSeqLocked draws the row: cursor and attributes saved (ESC 7) and
// restored (ESC 8), origin mode off, the agent's scroll region set again
// (it never includes the last row), every attribute and the character set
// reset, the row erased and written.
func (s *screen) rowSeqLocked(rows, cols int) string {
	var b bytes.Buffer
	b.WriteString("\x1b7\x1b[?6l\x1b[")
	b.WriteString(strconv.Itoa(s.top))
	b.WriteByte(';')
	b.WriteString(strconv.Itoa(s.bot))
	b.WriteString("r\x1b[")
	b.WriteString(strconv.Itoa(rows))
	b.WriteString(";1H\x1b[0m\x1b(B\x0f\x1b#5\x1b[2K")
	if t := fitWidth(safetext.Line(s.row), cols-1); t != "" {
		b.WriteString("\x1b[7m")
		b.WriteString(t)
		b.WriteString("\x1b[0m")
	}
	b.WriteString("\x1b8")
	return b.String()
}

// clampLocked rewrites agent output (already through safetext.Stream, so
// every CSI sequence is whole) so it cannot address the last row: cursor
// positions on or below it move to the row above, scroll regions end above
// it, and the sequences that reset the region or the terminal are dropped.
func (s *screen) clampLocked(b []byte, rows int) []byte {
	if bytes.IndexByte(b, 0x1b) < 0 {
		return b
	}
	out := make([]byte, 0, len(b)+16)
	for i := 0; i < len(b); {
		c := b[i]
		if c != 0x1b || i+1 >= len(b) {
			out = append(out, c)
			i++
			continue
		}
		switch b[i+1] {
		case 'c': // RIS: a full reset
			i += 2
			continue
		case '[':
		default:
			out = append(out, c)
			i++
			continue
		}
		j := i + 2
		for j < len(b) && b[j] >= 0x20 && b[j] <= 0x3f {
			j++
		}
		if j >= len(b) {
			break // an unfinished sequence (the filter never emits one): dropped
		}
		out = s.csiLocked(out, b[i:j+1], rows)
		i = j + 1
	}
	return out
}

func (s *screen) csiLocked(out, seq []byte, rows int) []byte {
	body, final := seq[2:len(seq)-1], seq[len(seq)-1]
	var priv byte
	if len(body) > 0 && body[0] >= 0x3c && body[0] <= 0x3f {
		priv, body = body[0], body[1:]
	}
	k := len(body)
	for k > 0 && body[k-1] >= 0x20 && body[k-1] <= 0x2f {
		k--
	}
	params, inter := body[:k], body[k:]
	plain := priv == 0 && len(inter) == 0
	switch {
	case plain && (final == 'H' || final == 'f' || final == 'd'):
		ps, ok := numbers(params)
		if !ok {
			return out
		}
		if len(ps) == 0 {
			ps = []int{-1}
		}
		if ps[0] >= rows {
			ps[0] = rows - 1
		}
		return appendCSI(out, ps, final)
	case plain && final == 'r':
		ps, ok := numbers(params)
		if !ok {
			return out
		}
		top, bot := 1, rows
		if len(ps) > 0 && ps[0] > 0 {
			top = ps[0]
		}
		if len(ps) > 1 && ps[1] > 0 {
			bot = ps[1]
		}
		bot = min(bot, rows-1)
		if top >= bot {
			return out
		}
		s.top, s.bot = top, bot
		return appendCSI(out, []int{top, bot}, 'r')
	case priv == '?' && final == 'r', // XTRESTORE: brings back saved modes
		len(inter) == 1 && inter[0] == '!' && final == 'p': // DECSTR: resets the region
		return out
	case priv == '?' && len(inter) == 0 && (final == 'h' || final == 'l'):
		// Left and right margins (mode 69) would let the agent fence the
		// row's erase; the other modes pass.
		parts := bytes.Split(params, []byte{';'})
		keep := parts[:0]
		for _, p := range parts {
			if string(p) != "69" {
				keep = append(keep, p)
			}
		}
		if len(keep) == 0 {
			return out
		}
		out = append(out, 0x1b, '[', '?')
		out = append(out, bytes.Join(keep, []byte{';'})...)
		return append(out, final)
	}
	return append(out, seq...)
}

// numbers parses CSI parameters; an empty one is -1 (the default).
func numbers(params []byte) ([]int, bool) {
	if len(params) == 0 {
		return nil, true
	}
	var ps []int
	for _, p := range bytes.Split(params, []byte{';'}) {
		if len(p) == 0 {
			ps = append(ps, -1)
			continue
		}
		if len(p) > 5 {
			return nil, false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return nil, false
			}
			n = n*10 + int(c-'0')
		}
		ps = append(ps, n)
	}
	return ps, true
}

func appendCSI(out []byte, ps []int, final byte) []byte {
	out = append(out, 0x1b, '[')
	for i, p := range ps {
		if i > 0 {
			out = append(out, ';')
		}
		if p >= 0 {
			out = strconv.AppendInt(out, int64(p), 10)
		}
	}
	return append(out, final)
}
