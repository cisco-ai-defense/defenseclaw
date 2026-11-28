// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestGAP1028CDReadingSkipsTheParseOfOtherPrograms: the guest placement
// reads every command text of a call for a cd (guestCDMemo.reading), and a
// call of thousands of commands parsed each text again. A text whose first
// word is a plain program other than the cd family reads as no cd without a
// parse; every other text still reads as its parse does (substrate-1
// GAP-1028).
func TestGAP1028CDReadingSkipsTheParseOfOtherPrograms(t *testing.T) {
	home := "/home/alice"
	texts := []string{
		"cd ~/.claude", "cd", "cd -", "cd -- x", "pushd src", "popd", "builtin cd ~/.ssh", "command cd x", "command -v cd",
		"c\\d ~/.ssh", "'cd' ~/.ssh", "\"cd\" x", "X=1 cd /tmp", "cd\tx", "cd;", "cd&", "cd|x", "./cd x", "cdx y",
		"touch out.txt", "f12", "f12 x", "echo x > a", "ls; cd x", "time cd x", "if true; then cd x; fi", ". ./env",
		"echo $(cd x)", "f0() { cd x; }", "cat<(cd x)", "env cd x", "exec cd x", "echo\\ cd", "e\"c\"ho x",
	}
	for _, text := range texts {
		want := gap1028ParsedCDReading(text, home)
		if got := newGuestCDMemo(home).reading(text); got != want {
			t.Errorf("%q reads %+v, its parse %+v", text, got, want)
		}
	}
	calls := make([]string, 200)
	for i := range calls {
		calls[i] = "f" + strconv.Itoa(i) + " out" + strconv.Itoa(i)
	}
	if allocs := testing.AllocsPerRun(5, func() {
		memo := newGuestCDMemo(home)
		for _, text := range calls {
			memo.reading(text)
		}
	}); allocs > 4 {
		t.Fatalf("reading %d calls of plain programs allocates %.0f times: each is parsed", len(calls), allocs)
	}
}

// gap1028ParsedCDReading is the reading of text by its parse.
func gap1028ParsedCDReading(text, home string) (reading guestCDReading) {
	if call, ok := guestCall(text); ok {
		program, static := hookpaths.StaticWord(call.Args[0], home)
		reading.changes = static && (program == "cd" || program == "pushd" || program == "popd")
		reading.operand, reading.moves = guestCallCDOperand(call, home)
	}
	return reading
}
