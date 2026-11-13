// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package safetext

import (
	"io"
	"unicode/utf8"
)

// Stream is a stateful filter for the raw terminal stream of an attached
// agent. A full-screen agent needs cursor movement, colors, charset
// selection and the alternate screen, so those pass. What cannot pass is
// everything that reaches outside the screen or changes how the terminal
// reads the bytes that follow:
//
//   - string sequences: OSC (clipboard, window title, hyperlinks,
//     notifications), DCS, APC, PM, SOS (tmux passthrough, graphics, queries
//     the terminal answers) and the screen/tmux title (ESC k);
//   - escapes that switch the coding system or the control set: ESC % (leave
//     or enter UTF-8), ESC SP (7- or 8-bit controls), ESC ! and ESC " (C0
//     and C1 sets), ESC & and ESC $. Once a terminal leaves UTF-8, an
//     ordinary character such as U+00DD (C3 9D) becomes an 8-bit OSC;
//   - CSI ... t (window operations and title reports), CSI ... i (media
//     copy) and CSI ... * y (screen checksum report);
//   - C1 controls, raw or UTF-8 encoded, and bytes that are not UTF-8
//     (shown as U+FFFD).
//
// It is a parser, not a byte blacklist: it follows the ECMA-48 states a
// terminal goes through (ground, escape, escape intermediate, CSI, control
// string) and lets a sequence out only when it is whole and allowed. C0
// controls inside a sequence act at once and the sequence goes on, as they
// do on a terminal; CAN and SUB cancel it; ESC starts a new one. A sequence
// may be split across writes: the filter remembers where it was, and the
// output of every write leaves the terminal in its ground state.
type Stream struct {
	// ASCII shows every character outside ASCII as '?'. It is for a
	// terminal that does not decode UTF-8 (TerminalUTF8 reports false),
	// which reads the bytes 0x80 to 0x9f of an ordinary character as C1
	// controls. The package default (UseASCII) applies when it is unset.
	ASCII bool

	state int
	n     int    // bytes swallowed in the current control string
	buf   []byte // parameters and intermediates of the sequence being read
	drop  bool   // the sequence being read is refused (or too long)
	rune_ []byte // the UTF-8 character being read
	need  int    // continuation bytes the character still needs
}

const (
	stGround    = iota
	stEsc       // after ESC
	stEscInt    // ESC with intermediates, waiting for the final byte
	stCSI       // inside a CSI sequence
	stString    // inside OSC/DCS/APC/PM/SOS/ESC k
	stStringEsc // ESC seen inside a string (ST, or the start of a new sequence)
	stStringC2  // 0xC2 seen inside a string (maybe U+009C, ST in UTF-8)
	stUTF8      // inside a multi-byte character
)

const (
	can = 0x18
	sub = 0x1a
	esc = 0x1b
)

// maxSeq bounds the parameters and intermediates of one CSI sequence; a
// longer one is read to its end and dropped.
const maxSeq = 64

// replacement is U+FFFD, shown for a byte that is not valid UTF-8.
var replacement = []byte("\xef\xbf\xbd")

// Filter returns p without what the agent must not be able to send. Bytes
// that are not valid UTF-8 are replaced by U+FFFD before anything else looks
// at them, so a stray lead byte or an 8-bit C1 control cannot hide or stand
// in for an escape sequence; a character cut by the end of p is held until
// the next call.
func (f *Stream) Filter(p []byte) []byte {
	out := make([]byte, 0, len(p)+8)
	for _, c := range p {
		out = f.step(c, out)
	}
	return out
}

func (f *Stream) ascii() bool { return f.ASCII || asciiOnly.Load() }

func (f *Stream) bad(out []byte) []byte {
	if f.ascii() {
		return append(out, '?')
	}
	return append(out, replacement...)
}

// begin starts reading a sequence in state st.
func (f *Stream) begin(st int) {
	f.state, f.buf, f.drop, f.n = st, f.buf[:0], false, 0
}

// isC0 reports a C0 control that acts at once, inside a sequence too.
func isC0(c byte) bool { return c < 0x20 && c != esc && c != can && c != sub }

// step feeds one byte to the filter and appends what it lets through.
func (f *Stream) step(c byte, out []byte) []byte {
	switch f.state {
	case stUTF8:
		if c >= 0x80 && c <= 0xbf {
			f.rune_ = append(f.rune_, c)
			f.need--
			if f.need > 0 {
				return out
			}
			f.state = stGround
			r, size := utf8.DecodeRune(f.rune_)
			switch {
			case r == utf8.RuneError && size <= 1:
				out = f.bad(out)
			case r >= 0x80 && r <= 0x9f:
				// A UTF-8 encoded C1 control: dropped; the ones that open
				// a string take the string with them.
				switch r {
				case 0x90, 0x98, 0x9d, 0x9e, 0x9f:
					f.begin(stString)
				}
			case f.ascii():
				out = append(out, '?')
			default:
				out = append(out, f.rune_...)
			}
			return out
		}
		// The character was cut short: it is replaced, and this byte is
		// read again as the start of whatever follows.
		out = f.bad(out)
		f.state = stGround
		return f.step(c, out)

	case stGround:
		switch {
		case c == esc:
			f.begin(stEsc)
		case c < 0x80:
			out = append(out, c)
		case c >= 0xc2 && c <= 0xf4:
			f.state, f.rune_ = stUTF8, append(f.rune_[:0], c)
			switch {
			case c <= 0xdf:
				f.need = 1
			case c <= 0xef:
				f.need = 2
			default:
				f.need = 3
			}
		default:
			// A continuation byte on its own, a raw C1 control, 0xc0, 0xc1
			// or 0xf5 and up.
			out = f.bad(out)
		}

	case stEsc:
		switch {
		case isC0(c):
			out = append(out, c)
		case c == can || c == sub:
			f.state = stGround
		case c == esc, c == 0x7f:
			// still waiting for what follows
		case c == ']' || c == 'P' || c == 'X' || c == '^' || c == '_' || c == 'k':
			f.begin(stString)
		case c == '[':
			f.begin(stCSI)
		case c >= 0x20 && c <= 0x2f:
			f.begin(stEscInt)
			f.buf = append(f.buf, c)
			f.drop = !escIntAllowed(c)
		case c == '\\':
			f.state = stGround // a string terminator with no string
		case c >= 0x30 && c <= 0x7e:
			f.state = stGround
			out = append(out, esc, c)
		default:
			f.state = stGround
			return f.step(c, out)
		}

	case stEscInt:
		switch {
		case isC0(c):
			out = append(out, c)
		case c == can || c == sub:
			f.state = stGround
		case c == esc:
			f.begin(stEsc)
		case c == 0x7f:
		case c >= 0x20 && c <= 0x2f:
			f.buf = append(f.buf, c)
			if len(f.buf) > 3 {
				f.drop = true
			}
		case c >= 0x30 && c <= 0x7e:
			f.state = stGround
			if !f.drop {
				out = append(out, esc)
				out = append(out, f.buf...)
				out = append(out, c)
			}
		default:
			f.state = stGround
			return f.step(c, out)
		}

	case stCSI:
		switch {
		case isC0(c):
			out = append(out, c)
		case c == can || c == sub:
			f.state = stGround
		case c == esc:
			f.begin(stEsc)
		case c == 0x7f:
		case c >= 0x20 && c <= 0x3f:
			if len(f.buf) < maxSeq {
				f.buf = append(f.buf, c)
			} else {
				f.drop = true
			}
		case c >= 0x40 && c <= 0x7e:
			f.state = stGround
			if !f.drop && csiAllowed(f.buf, c) {
				out = append(out, esc, '[')
				out = append(out, f.buf...)
				out = append(out, c)
			}
		default:
			// Not a CSI byte: the sequence is abandoned and shows nothing.
			f.state = stGround
			return f.step(c, out)
		}

	case stString:
		f.n++
		switch {
		case c == 0x07, c == can, c == sub:
			f.state = stGround
		case c == esc:
			f.state = stStringEsc
		case c == 0xc2:
			f.state = stStringC2
		case c == '\n' || f.n > maxString:
			// An unterminated string does not swallow the screen.
			f.state = stGround
			out = append(out, c)
		}

	case stStringC2:
		if c == 0x9c {
			f.state = stGround
			return out
		}
		f.state = stString
		return f.step(c, out)

	case stStringEsc:
		if c == '\\' {
			f.state = stGround
			return out
		}
		// ESC ends the string on a terminal and starts a new sequence.
		f.begin(stEsc)
		return f.step(c, out)
	}
	return out
}

// escIntAllowed reports the first intermediates of an escape sequence that
// may pass: charset designation (G0 to G3, 94 and 96 sets) and the DEC line
// attributes (ESC # 3..8). Everything else switches the coding system or the
// control set, or announces a conformance level.
func escIntAllowed(c byte) bool {
	switch c {
	case '(', ')', '*', '+', '-', '.', '/', '#':
		return true
	}
	return false
}

// csiAllowed reports whether a whole CSI sequence (parameters and
// intermediates in body, final byte final) may pass.
func csiAllowed(body []byte, final byte) bool {
	switch final {
	case 't': // window operations: resize, move, report the title back
		return false
	case 'i': // media copy: print the screen, start the printer channel
		return false
	case 'y': // DECRQCRA (CSI ... * y) reports a checksum of the screen
		for _, b := range body {
			if b == '*' {
				return false
			}
		}
	case 'p': // DECSCL (CSI Pl ; Pc " p) sets the conformance level and, with Pc 0 or 2, 8-bit controls (as ESC SP G)
		for _, b := range body {
			if b == '"' {
				return false
			}
		}
	}
	return true
}

// Writer wraps w so everything written to it is filtered first.
func (f *Stream) Writer(w io.Writer) io.Writer { return &streamWriter{f: f, w: w} }

type streamWriter struct {
	f *Stream
	w io.Writer
}

func (s *streamWriter) Write(p []byte) (int, error) {
	if _, err := s.w.Write(s.f.Filter(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}
