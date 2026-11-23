// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// gap1028Fit repeats unit (with {k} the repeat number) between prefix and
// suffix up to an 8 KB call.
func gap1028Fit(prefix, unit, suffix string) string {
	var b strings.Builder
	b.WriteString(prefix)
	for k := 0; ; k++ {
		piece := strings.ReplaceAll(unit, "{k}", fmt.Sprint(k))
		if b.Len()+len(piece)+len(suffix) > 8190 {
			break
		}
		b.WriteString(piece)
	}
	b.WriteString(suffix)
	return b.String()
}

// TestGAP1028GuestPlacementAllocations pins the memory the guest placement
// takes on an 8 KB call that repeats a few command texts hundreds of times:
// every text was parsed again by the simples pass and again for every script
// call (guestKnownFolders), some 6 MB a call, and with the collections it
// caused the sandbox hook ran 15-25 ms over rel (substrate-1 GAP-1028).
func TestGAP1028GuestPlacementAllocations(t *testing.T) {
	nest := strings.Repeat("for i in 1; do ", 20)
	// Bounds from measured numbers (dc-sub-gates, FIX-1028b): 2.54, 2.81 and
	// 4.11 MB at the fix, 8.55, 8.52 and 9.66 MB at 0fb85bd936. Shape 3 still
	// parses each of its distinct call texts once.
	shapes := []struct {
		name, command string
		bound         float64
	}{
		{"loop many CMD+decl", gap1028Fit("for i in 1; do ", "$C;f{k}(){ :;};", "done"), 3.2},
		{"nest20 many CMD+decl", gap1028Fit(nest, "$C;f{k}(){ :;};", strings.Repeat("done; ", 20)+"true"), 3.5},
		{"loop many CMD+decl+call", gap1028Fit("for i in 1; do ", "$C;f{k}(){ :;};f{k};", "done"), 5.2},
	}
	for _, shape := range shapes {
		input := actionfacts.Input{Tool: "Bash", Command: shape.command, CWD: "/home/alice/src", ActiveHome: "/home/alice"}
		facts := actionfacts.Analyze(input)
		new(guestReadingMemo).plan(input, facts).placements(false) // warm
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		new(guestReadingMemo).plan(input, facts).placements(false)
		runtime.ReadMemStats(&after)
		allocated := after.TotalAlloc - before.TotalAlloc
		t.Logf("%s: %d bytes, %.2f MB placed", shape.name, len(shape.command), float64(allocated)/1e6)
		if megabytes := float64(allocated) / 1e6; megabytes > shape.bound {
			t.Errorf("%s: the guest placement allocated %.2f MB, over %.1f MB (substrate-1 GAP-1028)", shape.name, megabytes, shape.bound)
		}
	}
}

// TestGAP1028GuestWordCounts pins that the one-pass count of a name of name
// bytes is the whole-word count the search gives.
func TestGAP1028GuestWordCounts(t *testing.T) {
	texts := []string{
		"", "f", "ff", "f f", "f;f(){ :;}; f", "f0 f01 f1 f10 f0", "a-b a-bc xa-b a-b", "f_ _f f_f f",
		"g(){ g; }; g; echo $g ${g} \"g\" 'g' g=1 gg", "f0(){ :;};f0;f00 f0x 0f0 -f0- f0",
		gap1028Fit("for i in 1; do ", "$C;f{k}(){ :;};f{k};", "done"),
	}
	names := []string{"f", "ff", "f0", "f01", "f1", "f10", "a-b", "f_", "_f", "g", "gg", "f00", "x", "-f0-", "f9", "f99", "f100"}
	for _, text := range texts {
		words := guestWordCounts(text)
		for _, name := range names {
			if !guestAllNameBytes(name) {
				t.Fatalf("%q: want a name of name bytes", name)
			}
			if got, want := words[name], guestWordCount(text, name); got != want {
				t.Errorf("text %.40q name %q: one pass counts %d, the search %d", text, name, got, want)
			}
		}
	}
	for _, name := range []string{"", "a.b", "f:x", "a b"} {
		if guestAllNameBytes(name) {
			t.Errorf("%q: not a name of name bytes", name)
		}
	}
}
