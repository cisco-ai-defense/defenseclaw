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
	"bytes"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// termCheck reads out the way a UTF-8 terminal does (the ECMA-48 states of
// the DEC parser: ground, escape, escape intermediate, CSI; C0 controls act
// inside a sequence, CAN and SUB cancel it, ESC starts a new one) and
// reports the first thing a filtered stream must never make the terminal
// do. ground reports whether the terminal is back in its ground state at
// the end, so the next write cannot finish a sequence this one started.
func termCheck(out []byte) (problem string, ground bool) {
	if !utf8.Valid(out) {
		return "invalid UTF-8", false
	}
	const (
		gnd = iota
		escS
		escI
		csiS
	)
	st := gnd
	var body []rune
	c0 := func(r rune) bool { return r < 0x20 && r != 0x1b && r != 0x18 && r != 0x1a }
	for _, r := range string(out) {
		if r >= 0x80 && r <= 0x9f {
			return fmt.Sprintf("C1 control %U", r), false
		}
		switch st {
		case gnd:
			if r == 0x1b {
				st = escS
			}
		case escS:
			switch {
			case c0(r), r == 0x1b, r == 0x7f:
			case r == 0x18 || r == 0x1a:
				st = gnd
			case strings.ContainsRune("]PX^_k", r):
				return "control string ESC " + string(r), false
			case r == '[':
				st, body = csiS, body[:0]
			case r >= 0x20 && r <= 0x2f:
				if !strings.ContainsRune("()*+-./#", r) {
					return fmt.Sprintf("coding system or control set switch ESC %q", r), false
				}
				st = escI
			default:
				st = gnd
			}
		case escI:
			switch {
			case c0(r), r == 0x7f, r >= 0x20 && r <= 0x2f:
			case r == 0x1b:
				st = escS
			default:
				st = gnd
			}
		case csiS:
			switch {
			case c0(r), r == 0x7f:
			case r == 0x18 || r == 0x1a:
				st = gnd
			case r == 0x1b:
				st = escS
			case r >= 0x20 && r <= 0x3f:
				body = append(body, r)
			case r >= 0x40 && r <= 0x7e:
				switch {
				case r == 't':
					return "window operation CSI " + string(body) + "t", false
				case r == 'i':
					return "media copy CSI " + string(body) + "i", false
				case r == 'y' && strings.ContainsRune(string(body), '*'):
					return "screen checksum report CSI " + string(body) + "y", false
				}
				st = gnd
			default:
				st = gnd
			}
		}
	}
	return "", st == gnd
}

func checkStreamOutput(t testing.TB, in, out []byte) {
	t.Helper()
	problem, ground := termCheck(out)
	if problem != "" {
		t.Fatalf("Stream(%q) = %q: %s", in, out, problem)
	}
	if !ground {
		t.Fatalf("Stream(%q) = %q leaves the terminal inside a sequence", in, out)
	}
}

// streamHostile are agent outputs aimed at the laptop terminal, beyond the
// hostile strings Clean is tested with.
var streamHostile = map[string]string{
	// GAP-0126: leave UTF-8, then an ordinary character is an 8-bit OSC.
	"leave utf8 then c3 9d osc52": "a\x1b%@\xc3\x9d52;c;cm0gLXJmIH4=\x07b",
	"enter utf8":                  "a\x1b%Gb",
	"docs with intermediate":      "a\x1b%/Ib",
	"8-bit controls s8c1t":        "a\x1b Gb",
	"7-bit controls s7c1t":        "a\x1b Fb",
	"c0 set designation":          "a\x1b!@b",
	"c1 set designation":          "a\x1b\"Cb",
	"multibyte charset":           "a\x1b$Bb",
	"revision":                    "a\x1b&@b",
	"screen tmux title":           "a\x1bkevil title\x1b\\b",
	"media copy":                  "a\x1b[5ib",
	"private media copy":          "a\x1b[?5ib",
	"checksum report":             "a\x1b[1;1;1;1;24;80*yb",
	"title report":                "a\x1b[21tb",
	"c0 inside csi window op":     "a\x1b[2\x081tb",
	"c0 inside osc intro":         "a\x1b\x08]52;c;AAAA\x07b",
	"can inside csi":              "a\x1b[2\x18]52;c;AAAA\x07b",
	"esc inside esc intermediate": "a\x1b(\x1b]52;c;AAAA\x07b",
	"esc inside csi":              "a\x1b[1;\x1b]52;c;AAAA\x07b",
	"del inside csi":              "a\x1b[2\x7f1tb",
	"long csi":                    "a\x1b[" + strings.Repeat("1;", 80) + "tb",
	"long esc intermediates":      "a\x1b((((((Bb",
	"utf8 st then osc":            "a\x1b]0;t\xc2\x9c\x1b]52;c;AAAA\x07b",
	"string then new escape":      "a\x1b]0;t\x1b]52;c;AAAA\x07b",
	"utf8 c1 csi":                 "a\xc2\x9b21tb",
	"utf8 c1 dcs":                 "a\xc2\x901000p\x1b\\b",
	"lone c2 osc52":               "a\xc2\x1b]52;c;AAAA\x07b",
	"lone c2 docs":                "a\xc2\x1b%@\xc3\x9d52;c;AAAA\x07b",
	"overlong esc":                "a\xc0\x9b2Jb",
}

func allHostile() map[string]string {
	all := map[string]string{}
	for k, v := range hostile {
		all[k] = v
	}
	for k, v := range streamHostile {
		all["stream "+k] = v
	}
	return all
}

// GAP-0126: every hostile case, whole, cut at every byte offset and fed one
// byte at a time, leaves the terminal in its ground state with nothing it
// refuses, and gives the same output however it is cut.
func TestStreamHostileAtEveryCut(t *testing.T) {
	for name, in := range allHostile() {
		var whole Stream
		w := append(whole.Filter([]byte(in)), whole.Filter([]byte{'.'})...)
		checkStreamOutput(t, []byte(in), w)
		for cut := 0; cut <= len(in); cut++ {
			var f Stream
			a := f.Filter([]byte(in[:cut]))
			checkStreamOutput(t, []byte(in[:cut]), a)
			b := f.Filter([]byte(in[cut:]))
			checkStreamOutput(t, []byte(in[cut:]), b)
			got := append(append(a, b...), f.Filter([]byte{'.'})...)
			if !bytes.Equal(got, w) {
				t.Fatalf("%s: cut at %d gives %q, whole gives %q", name, cut, got, w)
			}
		}
		var f Stream
		var one []byte
		for i := 0; i < len(in); i++ {
			chunk := f.Filter([]byte{in[i]})
			checkStreamOutput(t, []byte{in[i]}, chunk)
			one = append(one, chunk...)
		}
		one = append(one, f.Filter([]byte{'.'})...)
		if !bytes.Equal(one, w) {
			t.Fatalf("%s: one byte at a time gives %q, whole gives %q", name, one, w)
		}
	}
}

func TestStreamRefusesTheCodingSystemSwitch(t *testing.T) {
	var f Stream
	got := string(f.Filter([]byte("a\x1b%@\xc3\x9d52;c;AAAA\x07b")))
	if strings.Contains(got, "\x1b%") {
		t.Fatalf("ESC %% passed: %q", got)
	}
	// What follows is ordinary text on a UTF-8 terminal: it is shown.
	if got != "aÝ52;c;AAAA\x07b" {
		t.Errorf("got %q", got)
	}
}

func TestStreamFollowsTheTerminalInsideSequences(t *testing.T) {
	for in, want := range map[string]string{
		// A C0 control inside a sequence acts at once; the sequence goes on.
		"\x1b[3\x081m":   "\x08\x1b[31m",
		"\x1b(\r0x":      "\r\x1b(0x",
		"\x1b\nc":        "\n\x1bc",
		"\x1b[2\x081tok": "\x08ok",
		// CAN and SUB cancel it.
		"\x1b[31\x18mok": "mok",
		// ESC inside a string ends it and starts a new sequence.
		"\x1b]0;title\x1b[31mx": "\x1b[31mx",
		// U+009C in UTF-8 ends a string.
		"\x1b]0;title\xc2\x9cx": "x",
		// A quote mark inside a title does not end it.
		"\x1b]0;\xe2\x80\x9cq\xe2\x80\x9d\x07x": "x",
		// A string terminator with no string shows nothing.
		"a\x1b\\b": "ab",
		// Too long a CSI is read to its end and dropped.
		"\x1b[" + strings.Repeat("1", 100) + "mok": "ok",
	} {
		var f Stream
		if got := string(f.Filter([]byte(in))); got != want {
			t.Errorf("Filter(%q) = %q, want %q", in, got, want)
		}
	}
}

// A full-screen agent (Claude Code, Codex, an editor) keeps working.
func TestStreamKeepsWhatATUINeeds(t *testing.T) {
	for _, in := range []string{
		"\x1b[38;2;255;100;0mtrue color\x1b[48;5;236m256\x1b[0m",
		"\x1b[?1049h\x1b[?25l\x1b[?2004h\x1b[?1000h\x1b[?1006h\x1b[?1004h\x1b[?2026h",
		"\x1b[H\x1b[2J\x1b[3;5H\x1b[K\x1b[1A\x1b[2C\x1b[5;20r\x1b[S\x1b[T",
		"\x1b[6n\x1b[c\x1b[>c\x1b[?u\x1b[>1u\x1b[ q\x1b[2 q",
		"\x1b(0lqqqk\x1b(B\x1b)0\x0e\x0f\x1b*B\x1b+B",
		"\x1b#6\x1b#5\x1b7\x1b8\x1bM\x1bD\x1bE\x1b=\x1b>\x1bc",
		"╭──────╮ ✻ ⎿ ● 日本語 😀",
	} {
		var f Stream
		got := f.Filter([]byte(in))
		if string(got) != in {
			t.Errorf("Filter(%q) = %q, want it unchanged", in, got)
		}
		checkStreamOutput(t, []byte(in), got)
	}
}

func TestStreamASCIIForATerminalWithoutUTF8(t *testing.T) {
	f := Stream{ASCII: true}
	got := f.Filter([]byte("aÝ\xc3\x9d日😀\xffb\x1b[31mc"))
	for _, c := range got {
		if c >= 0x80 {
			t.Fatalf("ASCII stream has the byte %#x: %q", c, got)
		}
	}
	if string(got) != "a?????b\x1b[31mc" {
		t.Errorf("got %q", got)
	}
}

func TestUseASCII(t *testing.T) {
	UseASCII(true)
	defer UseASCII(false)
	if got := Clean("café \xc3\x9d"); got != "caf? ?" {
		t.Errorf("Clean = %q", got)
	}
	if got := Path("café.txt"); got != `"caf\u00e9.txt"` {
		t.Errorf("Path = %q", got)
	}
	var f Stream
	if got := string(f.Filter([]byte("é"))); got != "?" {
		t.Errorf("Stream = %q", got)
	}
}

func TestTerminalUTF8(t *testing.T) {
	for env, want := range map[string]bool{
		"":                           true,
		"LANG=C":                     true,
		"LANG=POSIX":                 true,
		"LANG=en_US.UTF-8":           true,
		"LANG=de_DE.utf8@euro":       true,
		"LANG=en_US":                 true,
		"LANG=en_US.ISO-8859-1":      false,
		"LANG=ja_JP.eucJP":           false,
		"LC_ALL=C.UTF-8 LANG=x.big5": true,
		"LC_CTYPE=en_US.ISO8859-15 LANG=en_US.UTF-8": false,
	} {
		m := map[string]string{}
		for _, kv := range strings.Fields(env) {
			k, v, _ := strings.Cut(kv, "=")
			m[k] = v
		}
		if got := TerminalUTF8(func(k string) string { return m[k] }); got != want {
			t.Errorf("%q: TerminalUTF8 = %v, want %v", env, got, want)
		}
	}
}

func FuzzStreamAgainstTheTerminal(f *testing.F) {
	for _, in := range allHostile() {
		f.Add([]byte(in), uint16(1), uint16(3), false)
	}
	f.Fuzz(func(t *testing.T, in []byte, cut1, cut2 uint16, ascii bool) {
		var whole Stream
		whole.ASCII = ascii
		w := append(whole.Filter(in), whole.Filter([]byte{'.'})...)
		checkStreamOutput(t, in, w)
		if ascii {
			for _, c := range w {
				if c >= 0x80 {
					t.Fatalf("ASCII Stream(%q) = %q has %#x", in, w, c)
				}
			}
		}
		i, j := 0, 0
		if len(in) > 0 {
			i, j = int(cut1)%(len(in)+1), int(cut2)%(len(in)+1)
		}
		if i > j {
			i, j = j, i
		}
		parts := Stream{ASCII: ascii}
		var g []byte
		for _, p := range [][]byte{in[:i], in[i:j], in[j:], {'.'}} {
			chunk := parts.Filter(p)
			checkStreamOutput(t, p, chunk)
			g = append(g, chunk...)
		}
		if !bytes.Equal(w, g) {
			t.Fatalf("cuts at %d and %d change the output of %q: %q vs %q", i, j, in, w, g)
		}
	})
}
