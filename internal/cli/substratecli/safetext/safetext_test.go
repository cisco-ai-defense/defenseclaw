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
	"strings"
	"testing"
	"unicode/utf8"
)

// hostile are strings an agent could put in a file name, a diff, a task log
// line or an ask summary.
var hostile = map[string]string{
	"cursor up and erase":     "ok.txt\x1b[2A\x1b[2K\x1b[1Gall clear",
	"conceal":                 "run\x1b[8m rm -rf ~ \x1b[0m",
	"osc 52 clipboard bel":    "a\x1b]52;c;cm0gLXJmIH4=\x07b",
	"osc 52 clipboard st":     "a\x1b]52;c;cm0gLXJmIH4=\x1b\\b",
	"osc 8 hyperlink":         "\x1b]8;;https://evil.example.test\x07click\x1b]8;;\x07",
	"window title":            "\x1b]0;sudo password:\x07x",
	"dcs":                     "a\x1bP1000p+q544e\x1b\\b",
	"apc":                     "a\x1b_Gf=100;AAAA\x1b\\b",
	"pm sos":                  "a\x1b^x\x1b\\b\x1bXy\x1b\\c",
	"title report request":    "a\x1b[21tb",
	"charset":                 "a\x1b(0b\x1b)Bc",
	"c1 csi":                  "a\u009b2Jb",
	"c1 osc":                  "a\u009d52;c;AAAA\u009cb",
	"raw c0":                  "a\x00\x07\x08\x0b\x0c\x0e\x7fb",
	"carriage return":         "safe\rEVIL",
	"bidi override":           "gnp.\u202etxt.exe",
	"isolate":                 "a\u2066b\u2069c",
	"zero width":              "ad\u200bmin\ufeff",
	"invalid utf8":            "a\xff\xfeb",
	"unterminated osc":        "a\x1b]52;c;AAAA",
	"split escape at the end": "tail\x1b",
	"nested":                  "\x1b]0;\x1b[2Jx\x07y",
}

func hasControl(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == utf8.RuneError {
			return true
		}
	}
	return false
}

func TestCleanRemovesEveryControl(t *testing.T) {
	for name, in := range hostile {
		t.Run(name, func(t *testing.T) {
			for fn, got := range map[string]string{"Clean": Clean(in), "Line": Line(in), "Visible": Visible(in)} {
				if hasControl(got) {
					t.Errorf("%s(%q) = %q still has a control", fn, in, got)
				}
				if strings.ContainsAny(got, "\u202e\u2066\u2069\u200b\ufeff") {
					t.Errorf("%s(%q) = %q still has a format character", fn, in, got)
				}
			}
		})
	}
}

func TestCleanKeepsOrdinaryText(t *testing.T) {
	for _, in := range []string{"plain text", "line one\nline two\n\ttabbed", "naïve café 日本語 😀", "src/a b/c.go:12: error"} {
		if got := Clean(in); got != in {
			t.Errorf("Clean(%q) = %q", in, got)
		}
	}
	if got := Clean("a\x1b[31mred\x1b[0mb"); got != "aredb" {
		t.Errorf("colors are removed in text: %q", got)
	}
	if got := Clean("before\x1b]0;title\nafter"); got != "before\nafter" {
		t.Errorf("an unterminated string ends at the newline: %q", got)
	}
}

func TestCleanDoesNotHideWhatFollowsASequence(t *testing.T) {
	if got := Clean("\x1b]52;c;AAAA\x07visible"); got != "visible" {
		t.Errorf("got %q", got)
	}
	if got := Clean("\x1b[2Jvisible"); got != "visible" {
		t.Errorf("got %q", got)
	}
}

func TestVisibleShowsWhatWasThere(t *testing.T) {
	got := Visible("a\x1b[2Jb\u202ec")
	if !strings.Contains(got, `\x1b`) || !strings.Contains(got, `\u202e`) {
		t.Errorf("Visible hides the escapes: %q", got)
	}
}

func TestPathQuotesUnusualNames(t *testing.T) {
	for in, want := range map[string]string{
		"src/main.go":            "src/main.go",
		"docs/a-b_c.md":          "docs/a-b_c.md",
		"my file.txt":            `"my file.txt"`,
		"a\x1b[2Kb":              `"a\x1b[2Kb"`,
		"x\u202eg.txt":           `"x\u202eg.txt"`,
		"line\nbreak":            `"line\nbreak"`,
		"quote\"s":               `"quote\"s"`,
		"bad\xffbyte":            `"bad\xffbyte"`,
		"tab\tname":              `"tab\tname"`,
		"back\\slash":            `"back\\slash"`,
		"\x1b]52;c;AAAA\x07.env": `"\x1b]52;c;AAAA\x07.env"`,
	} {
		got := Path(in)
		if got != want {
			t.Errorf("Path(%q) = %q, want %q", in, got, want)
		}
		if hasControl(got) {
			t.Errorf("Path(%q) = %q has a control", in, got)
		}
	}
}

func TestLineIsOneLine(t *testing.T) {
	if got := Line("a\n\nb\t c \x1b[2J d"); got != "a b c d" {
		t.Errorf("got %q", got)
	}
}

func TestStreamKeepsScreenControlsAndDropsTheRest(t *testing.T) {
	keep := []string{
		"hello\r\nworld",
		"\x1b[31mred\x1b[0m \x1b[1;1H\x1b[2J\x1b[?1049h\x1b[?25l",
		"\x1b(0lqqk\x1b(B",
		"\x1b7saved\x1b8",
		"naïve 日本語",
	}
	for _, in := range keep {
		var f Stream
		if got := f.Filter([]byte(in)); string(got) != in {
			t.Errorf("Filter(%q) = %q, want it unchanged", in, got)
		}
	}
	for name, in := range hostile {
		var f Stream
		got := string(f.Filter([]byte(in)))
		for _, bad := range []string{"\x1b]", "\x1bP", "\x1b_", "\x1b^", "\x1bX", "\x1b[21t", "\u009b", "\u009d", "\u0090"} {
			if strings.Contains(got, bad) {
				t.Errorf("%s: Filter left %q in %q", name, bad, got)
			}
		}
	}
}

func TestStreamHandlesSequencesSplitAcrossWrites(t *testing.T) {
	in := "a\x1b]52;c;cm0gLXJmIH4=\x07b\x1b[31mc\x1b[21td"
	for split := 1; split < len(in); split++ {
		var f Stream
		got := string(f.Filter([]byte(in[:split]))) + string(f.Filter([]byte(in[split:])))
		if got != "ab\x1b[31mcd" {
			t.Fatalf("split at %d: %q", split, got)
		}
	}
	// One byte at a time.
	var f Stream
	var out bytes.Buffer
	for i := 0; i < len(in); i++ {
		out.Write(f.Filter([]byte{in[i]}))
	}
	if out.String() != "ab\x1b[31mcd" {
		t.Errorf("byte at a time: %q", out.String())
	}
}

func TestStreamGivesUpOnAnEndlessString(t *testing.T) {
	var f Stream
	got := f.Filter(append([]byte("\x1b]52;c;"), bytes.Repeat([]byte("A"), maxString*2)...))
	more := f.Filter([]byte("tail"))
	if !strings.Contains(string(got)+string(more), "tail") {
		t.Error("an unterminated string must not swallow the screen forever")
	}
}

func FuzzCleanNeverLeavesAControl(f *testing.F) {
	for _, in := range hostile {
		f.Add(in)
	}
	f.Fuzz(func(t *testing.T, in string) {
		if got := Clean(in); hasControl(got) {
			t.Fatalf("Clean(%q) = %q", in, got)
		}
	})
}
