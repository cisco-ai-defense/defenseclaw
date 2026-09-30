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

package sandboxcli

import (
	"bytes"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// What a sandbox prints itself (a detached run's log, a headless harness's
// output) reaches the user's terminal through sandboxOutput. The agent
// controls that text (a prompt-injected model's answer, or the log file it
// can write directly), so it must not drive the terminal with escape
// sequences: write the clipboard (OSC 52), set the title, move the cursor
// or clear the screen. Color codes (SGR) pass, so a harness's colored
// output still reads as it should. A file or a pipe gets the bytes as the
// sandbox wrote them (`sandbox logs NAME | cat` shows them raw).

// maxSandboxLine is how much of a line without a newline sandboxOutput
// holds before it prints it in pieces.
const maxSandboxLine = 64 << 10

// sandboxOutput wraps w, a terminal when tty is set, for what a sandbox
// prints; flush writes a last line that has no newline.
func sandboxOutput(w io.Writer, tty bool) (io.Writer, func() error) {
	if !tty {
		return w, func() error { return nil }
	}
	s := &sanitizingWriter{w: w}
	return s, s.Flush
}

// sanitizingWriter writes each line through sandboxText.
type sanitizingWriter struct {
	w       io.Writer
	partial []byte
}

func (s *sanitizingWriter) Write(p []byte) (int, error) {
	s.partial = append(s.partial, p...)
	for {
		i := bytes.IndexByte(s.partial, '\n')
		if i < 0 {
			break
		}
		line := string(s.partial[:i+1])
		s.partial = s.partial[i+1:]
		if _, err := io.WriteString(s.w, sandboxText(line)); err != nil {
			return len(p), err
		}
	}
	if len(s.partial) > maxSandboxLine {
		// Cut where a character starts, so none prints as invalid.
		cut := len(s.partial)
		for cut > 0 && !utf8.RuneStart(s.partial[cut-1]) {
			cut--
		}
		if cut > 0 {
			cut--
		}
		if cut == 0 {
			cut = len(s.partial)
		}
		piece := string(s.partial[:cut])
		s.partial = s.partial[cut:]
		if _, err := io.WriteString(s.w, sandboxText(piece)); err != nil {
			return len(p), err
		}
	}
	if len(s.partial) == 0 {
		s.partial = s.partial[:0:0]
	}
	return len(p), nil
}

// Flush writes what is left of a last line without a newline.
func (s *sanitizingWriter) Flush() error {
	if len(s.partial) == 0 {
		return nil
	}
	line := string(s.partial)
	s.partial = nil
	_, err := io.WriteString(s.w, sandboxText(line))
	return err
}

// sandboxText is s made safe to print on a terminal: newlines, tabs and
// SGR color codes pass; every other control character (the escape
// sequences above, a carriage return that overwrites a line), C1 control,
// bidirectional override and invalid byte prints as U+FFFD, or a space
// (sandboxapi.DisplayText).
func sandboxText(s string) string {
	if plainText(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	start := 0
	for i := 0; i < len(s); {
		switch s[i] {
		case '\n', '\t':
			b.WriteString(sandboxapi.DisplayText(s[start:i]))
			b.WriteByte(s[i])
			i++
			start = i
			continue
		case 0x1b:
			if n := sgrLen(s[i:]); n > 0 {
				b.WriteString(sandboxapi.DisplayText(s[start:i]))
				b.WriteString(s[i : i+n])
				i += n
				start = i
				continue
			}
		}
		i++
	}
	b.WriteString(sandboxapi.DisplayText(s[start:]))
	return b.String()
}

// sgrLen is the length of the SGR sequence ("ESC [ 1 ; 31 m") s starts
// with, 0 when it starts with none. SGR only sets colors and attributes.
func sgrLen(s string) int {
	if len(s) < 3 || s[0] != 0x1b || s[1] != '[' {
		return 0
	}
	for i := 2; i < len(s) && i < 64; i++ {
		switch c := s[i]; {
		case c == 'm':
			return i + 1
		case c >= '0' && c <= '9', c == ';', c == ':':
		default:
			return 0
		}
	}
	return 0
}
