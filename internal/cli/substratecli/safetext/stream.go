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
// agent. A full-screen agent needs cursor movement, colors and the alternate
// screen, so those pass. What cannot pass is everything that reaches outside
// the screen: string sequences (OSC: the clipboard, window title, hyperlinks
// and notifications; DCS, APC, PM and SOS: tmux passthrough, graphics, queries
// the terminal answers), the CSI "window operation" family (CSI ... t), and 8-bit C1
// controls (invalid UTF-8 is replaced before anything else is read). A sequence may be split across writes; the filter remembers where it was.
type Stream struct {
	state int
	n     int    // bytes swallowed in the current string sequence
	buf   []byte // the CSI or ESC sequence being read
	rune_ []byte // the UTF-8 character being read
	need  int    // continuation bytes the character still needs
}

const (
	stText    = iota
	stEsc     // after ESC
	stCSI     // inside a CSI sequence
	stString  // inside OSC/DCS/APC/PM/SOS
	stStringE // ESC seen inside a string (maybe the terminator)
	stEscInt  // ESC with intermediates, waiting for the final byte
	stUTF8    // inside a multi-byte character
)

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
			f.state = stText
			r, size := utf8.DecodeRune(f.rune_)
			switch {
			case r == utf8.RuneError && size <= 1:
				out = append(out, replacement...)
			case r >= 0x80 && r <= 0x9f:
				// A UTF-8 encoded C1 control: dropped; the ones that open
				// a string take the string with them.
				switch r {
				case 0x90, 0x98, 0x9d, 0x9e, 0x9f:
					f.state, f.n = stString, 0
				}
			default:
				out = append(out, f.rune_...)
			}
			return out
		}
		// The character was cut short: it is replaced, and this byte is
		// read again as the start of whatever follows.
		out = append(out, replacement...)
		f.state = stText
		return f.step(c, out)
	case stText:
		switch {
		case c == 0x1b:
			f.state = stEsc
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
			// A continuation byte on its own, 0xc0, 0xc1 or 0xf5 and up.
			out = append(out, replacement...)
		}
	case stEsc:
		switch {
		case c == ']' || c == 'P' || c == 'X' || c == '^' || c == '_':
			f.state, f.n = stString, 0
		case c == '[':
			f.state, f.buf = stCSI, f.buf[:0]
		case c == 0x1b:
			// ESC ESC: still waiting for what follows the second.
		case c >= 0x20 && c <= 0x2f:
			f.state, f.buf = stEscInt, append(f.buf[:0], c)
		default:
			f.state = stText
			if c >= 0x30 && c <= 0x7e {
				out = append(out, 0x1b, c)
			} else if c >= 0x80 {
				return f.step(c, out)
			}
		}
	case stEscInt:
		switch {
		case c >= 0x20 && c <= 0x2f:
			f.buf = append(f.buf, c)
		default:
			f.state = stText
			if c >= 0x30 && c <= 0x7e { // charset selection, keypad modes: kept
				out = append(out, 0x1b)
				out = append(out, f.buf...)
				out = append(out, c)
			} else if c >= 0x80 {
				return f.step(c, out)
			}
		}
	case stCSI:
		switch {
		case c >= 0x20 && c <= 0x3f:
			f.buf = append(f.buf, c)
			if len(f.buf) > 64 {
				f.state, f.buf = stText, f.buf[:0]
			}
		case c >= 0x40 && c <= 0x7e:
			f.state = stText
			if c != 't' { // window operations: resize, report the title back, ...
				out = append(out, 0x1b, '[')
				out = append(out, f.buf...)
				out = append(out, c)
			}
			f.buf = f.buf[:0]
		default:
			// Not a CSI byte: the sequence is abandoned and shows nothing.
			f.state, f.buf = stText, f.buf[:0]
			if c >= 0x80 || c == 0x1b {
				return f.step(c, out)
			}
		}
	case stString:
		f.n++
		switch {
		case c == 0x07:
			f.state = stText
		case c == 0x1b:
			f.state = stStringE
		case c == '\n' || f.n > maxString:
			f.state = stText
			out = append(out, c)
		}
	case stStringE:
		switch c {
		case '\\':
			f.state = stText
		case 0x1b:
			// another ESC: stay
		default:
			f.state = stString
		}
	}
	return out
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
