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

package asciifold

import (
	"math/rand/v2"
	"strings"
	"testing"
)

func TestLowerIsToLowerOnASCII(t *testing.T) {
	var every strings.Builder
	for c := range 128 {
		every.WriteByte(byte(c))
	}
	inputs := []string{"", every.String(), "ABC", "abc", "MiXeD-Case_09 ~/.DefenseClaw/Gateway.PID"}
	random := rand.New(rand.NewPCG(1914, 1914))
	for range 20000 {
		b := make([]byte, random.IntN(64))
		for i := range b {
			b[i] = byte(random.IntN(128))
		}
		inputs = append(inputs, string(b))
	}
	for _, s := range inputs {
		if got, want := Lower(s), strings.ToLower(s); got != want {
			t.Fatalf("Lower(%q) = %q, want strings.ToLower %q", s, got, want)
		}
	}
}

// Every byte but an ASCII capital stays where it is: offsets found in the
// result are offsets of the input, whatever runes it holds (U+023A grows
// under strings.ToLower, U+212A and U+0130 shrink to ASCII k and i, and
// invalid UTF-8 is kept byte for byte).
func TestLowerKeepsEveryOffset(t *testing.T) {
	for _, s := range []string{"\u023a\u023a.PID", "\u212a\u0130.Pid", "A\xffB\xc4", "\u0250\u0131\u017f X"} {
		got := Lower(s)
		if len(got) != len(s) {
			t.Fatalf("Lower(%q) = %q, length %d, want %d", s, got, len(got), len(s))
		}
		for i := range len(s) {
			c, want := got[i], s[i]
			if 'A' <= want && want <= 'Z' {
				want += 'a' - 'A'
			}
			if c != want {
				t.Fatalf("Lower(%q)[%d] = %#x, want %#x", s, i, c, want)
			}
		}
	}
	if got := Lower("\u212a"); got != "\u212a" {
		t.Errorf("Lower(Kelvin sign) = %q, want it unchanged", got)
	}
}

func TestLowerDoesNotAllocateWithoutCapitals(t *testing.T) {
	s := "pkill -f ~/.defenseclaw/gateway.pid \u023a"
	if allocs := testing.AllocsPerRun(100, func() { _ = Lower(s) }); allocs != 0 {
		t.Errorf("Lower of a text without capitals allocates %v times, want 0", allocs)
	}
}

var benchmarkSink string

func BenchmarkLower(b *testing.B) {
	for _, bench := range []struct{ name, text string }{
		{"lower", "cd /home/u/work && pkill -f ~/.defenseclaw/gateway.pid; " + strings.Repeat("done ", 40)},
		{"mixed", "cd /home/u/work && pkill -F ~/.DefenseClaw/Gateway.PID; " + strings.Repeat("Done ", 40)},
		{"upper", strings.Repeat("PKILL -F GATEWAY.PID ", 12)},
		{"unicode", "cd /home/\u00e9t\u00e9 && pkill -F ~/.DefenseClaw/Gateway.PID; " + strings.Repeat("D\u00f6ne ", 40)},
	} {
		b.Run(bench.name+"/asciifold", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				benchmarkSink = Lower(bench.text)
			}
		})
		b.Run(bench.name+"/strings", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				benchmarkSink = strings.ToLower(bench.text)
			}
		})
	}
}
