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

import "io"

// Stream is a stateful filter for the raw terminal stream of an attached
// agent. A full-screen agent needs cursor movement, colors and the alternate
// screen, so those pass. What cannot pass is everything that reaches outside
// the screen: string sequences (OSC: the clipboard, window title, hyperlinks
// and notifications; DCS, APC, PM and SOS: tmux passthrough, graphics, queries
// the terminal answers), the CSI "window operation" family (CSI ... t), and 8-bit C1
// controls. A sequence may be split across writes; the filter remembers where it was.
type Stream struct {
	state int
	n     int    // bytes swallowed in the current string sequence
	buf   []byte // the CSI or ESC sequence being read
}

const (
	stText    = iota
	stEsc     // after ESC
	stCSI     // inside a CSI sequence
	stString  // inside OSC/DCS/APC/PM/SOS
	stStringE // ESC seen inside a string (maybe the terminator)
	stEscInt  // ESC with intermediates, waiting for the final byte
	stC1      // saw 0xC2, the first byte of a UTF-8 C1 control
)

// Filter returns p without what the agent must not be able to send. It never
// returns more bytes than it was given.
func (f *Stream) Filter(p []byte) []byte {
	out := make([]byte, 0, len(p))
	for _, c := range p {
		switch f.state {
		case stText:
			switch c {
			case 0x1b:
				f.state = stEsc
			case 0xc2:
				f.state = stC1
			default:
				out = append(out, c)
			}
		case stC1:
			f.state = stText
			if c < 0x80 || c > 0x9f {
				out = append(out, 0xc2, c)
				continue
			}
			// A UTF-8 C1 control (U+0080 to U+009F) is dropped; the ones
			// that introduce a string take the string with them.
			switch c {
			case 0x90, 0x98, 0x9d, 0x9e, 0x9f:
				f.state, f.n = stString, 0
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
