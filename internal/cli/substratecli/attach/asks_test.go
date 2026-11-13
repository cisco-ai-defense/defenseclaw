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
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

type fakeAsks struct {
	mu        sync.Mutex
	pending   []Ask
	decided   map[string]Decision
	calls     int
	err       error
	decideErr error
}

func (f *fakeAsks) Pending(context.Context, Target) ([]Ask, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Ask(nil), f.pending...), f.err
}

func (f *fakeAsks) Decide(_ context.Context, id string, d Decision) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.decideErr != nil {
		return f.decideErr
	}
	if f.decided == nil {
		f.decided = map[string]Decision{}
	}
	f.decided[id] = d
	return nil
}

func (f *fakeAsks) decision(id string) Decision {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.decided[id]
}

func (f *fakeAsks) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// writes records every Write the terminal gets.
type writes struct {
	mu  sync.Mutex
	all []string
}

func (w *writes) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.all = append(w.all, string(p))
	return len(p), nil
}

func (w *writes) list() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.all...)
}

func (w *writes) String() string { return strings.Join(w.list(), "") }

type uiRig struct {
	u     *askUI
	scr   *screen
	out   *writes
	src   *fakeAsks
	clock *fakeClock
	f     *askFilter
}

const (
	testRows, testCols = 24, 120
	myActor            = "a6-test/cc-1"
)

func newUIRig() *uiRig {
	clock := newFakeClock()
	out := &writes{}
	size := func() relay.Resize { return relay.Resize{Cols: testCols, Rows: testRows} }
	scr := newScreen(out, size)
	scr.reserve = true
	scr.begin()
	src := &fakeAsks{}
	u := newAskUI(src, testTarget, scr, size, clock.now, func() {})
	return &uiRig{u: u, scr: scr, out: out, src: src, clock: clock, f: &askFilter{ui: u}}
}

func myAsk(id string) Ask {
	return Ask{ID: id, Actor: myActor, Summary: "egress to unlisted.example.test", Created: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
}

// keys feeds keyboard reads; "+" lets the person see the prompt (300 ms).
func (r *uiRig) keys(parts ...string) string {
	var got []byte
	for _, s := range parts {
		if s == "+" {
			_ = r.clock.sleep(context.Background(), 300*time.Millisecond)
			continue
		}
		p := make([]byte, len(s)+8)
		n := copy(p, s)
		m := r.f.apply(p, n)
		got = append(got, p[:m]...)
	}
	return string(got)
}

func (r *uiRig) row() string {
	r.u.mu.Lock()
	defer r.u.mu.Unlock()
	return r.u.rowLocked()
}

func (r *uiRig) curID() string {
	r.u.mu.Lock()
	defer r.u.mu.Unlock()
	if r.u.cur == nil {
		return ""
	}
	return r.u.cur.ID
}

func (r *uiRig) mode() askMode {
	r.u.mu.Lock()
	defer r.u.mu.Unlock()
	return r.u.mode
}

func bytesOf(s string) []string {
	var out []string
	for i := range len(s) {
		out = append(out, s[i:i+1])
	}
	return out
}

func TestTypingNeverAnswers(t *testing.T) {
	r := newUIRig()
	r.u.update([]Ask{myAsk("k1")})
	if row := r.row(); !strings.HasPrefix(row, "DefenseClaw ask k1 from "+myActor+": ") || !strings.HasSuffix(row, "press Ctrl-\\ to answer") {
		t.Fatalf("announce row %q", row)
	}
	prose := "please add tests and a doc"
	for _, parts := range [][]string{bytesOf(prose), {prose}} {
		if got := r.keys(parts...); got != prose {
			t.Fatalf("forwarded %q, want %q", got, prose)
		}
	}
	_ = r.clock.sleep(context.Background(), time.Minute)
	if got := r.keys(bytesOf("oad OAD")...); got != "oad OAD" {
		t.Fatalf("forwarded %q", got)
	}
	if r.src.count() != 0 || r.mode() != modeNone {
		t.Fatalf("typing answered: %d calls, mode %d", r.src.count(), r.mode())
	}
}

func TestPasteNeverAnswers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		parts []string
		want  string
	}{
		{"plain paste", []string{"oad yes"}, "oad yes"},
		{"bracketed paste", []string{"\x1b[200~o a d\x1b[201~"}, "\x1b[200~o a d\x1b[201~"},
		{"chord and key in one read", []string{"\x1co"}, "o"},
		{"chord in a bracketed paste", []string{"\x1b[200~\x1co\x1b[201~"}, "\x1b[200~o\x1b[201~"},
		{"paste over several reads", []string{"\x1b[200~", "\x1c", "+", "o", "\x1b[201~"}, "\x1b[200~o\x1b[201~"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newUIRig()
			r.u.update([]Ask{myAsk("k1")})
			_ = r.clock.sleep(context.Background(), time.Minute)
			if got := r.keys(tc.parts...); got != tc.want {
				t.Fatalf("forwarded %q, want %q", got, tc.want)
			}
			if r.src.count() != 0 || r.mode() != modeNone {
				t.Fatalf("a paste answered: %d calls, mode %d", r.src.count(), r.mode())
			}
		})
	}
}

func TestChordAnswers(t *testing.T) {
	const chord = "\x1c"
	for _, tc := range []struct {
		name  string
		parts []string
		want  Decision
	}{
		{"once", []string{chord, "+", "o"}, DecideOnce},
		{"deny", []string{chord, "+", "D"}, DecideDeny},
		{"always confirmed", []string{chord, "+", "a", "+", "y"}, DecideAlways},
		{"always then n", []string{chord, "+", "a", "+", "n"}, ""},
		{"always then Esc", []string{chord, "+", "a", "+", "\x1b"}, ""},
		{"always then y too fast", []string{chord, "+", "a", "y"}, ""},
		{"Esc", []string{chord, "+", "\x1b"}, ""},
		{"other key", []string{chord, "+", "x"}, ""},
		{"arrow key", []string{chord, "+", "\x1b[A"}, ""},
		{"long chunk", []string{chord, "+", "please add tests"}, ""},
		{"short burst", []string{chord, "+", "oo"}, ""},
		{"bracketed paste", []string{chord, "+", "\x1b[200~o\x1b[201~"}, ""},
		{"key before the prompt shows", []string{chord, "o"}, ""},
		{"chord again", []string{chord, "+", chord}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newUIRig()
			r.u.update([]Ask{myAsk("k1")})
			if got := r.keys(tc.parts...); got != "" {
				t.Fatalf("keys reached the agent: %q", got)
			}
			if tc.want == "" {
				if r.src.count() != 0 || r.mode() != modeNone {
					t.Fatalf("%d calls, mode %d", r.src.count(), r.mode())
				}
				if row := r.row(); !strings.HasSuffix(row, askAnnounceEnd) {
					t.Fatalf("the ask is not pending again: %q", row)
				}
				return
			}
			waitFor(t, "decision", func() bool { return r.src.decision("k1") == tc.want })
			waitFor(t, "ask answered", func() bool { return r.curID() == "" })
			if r.src.count() != 1 {
				t.Fatalf("Decide called %d times", r.src.count())
			}
			// The ask is answered: keys reach the agent again, and the poll
			// that still lists it does not bring it back.
			r.u.update([]Ask{myAsk("k1")})
			if got := r.keys("+", "o", "\x1c"); got != "o\x1c" {
				t.Fatalf("after the answer forwarded %q", got)
			}
			if r.src.count() != 1 {
				t.Fatalf("Decide called %d times", r.src.count())
			}
		})
	}
}

func TestModalRowsAndDetach(t *testing.T) {
	r := newUIRig()
	r.u.update([]Ask{myAsk("k1")})
	r.keys("\x1c")
	if row := r.row(); !strings.HasPrefix(row, "DefenseClaw ask k1 from "+myActor) || !strings.HasSuffix(row, askModalEnd) {
		t.Fatalf("modal row %q", row)
	}
	r.keys("+", "a")
	if row := r.row(); !strings.Contains(row, "Approve this and every later identical ask? press y to confirm") {
		t.Fatalf("confirm row %q", row)
	}
	if got := r.keys("\x1d"); got != "\x1d" {
		t.Fatalf("Ctrl-] in the prompt forwarded %q", got)
	}
	if r.mode() != modeNone || r.src.count() != 0 {
		t.Fatal("detach left the prompt open or answered")
	}
}

func TestDecideFailureKeepsAsk(t *testing.T) {
	r := newUIRig()
	r.src.decideErr = errors.New("gateway said \x1b]52;c;eA==\x07 no")
	r.u.update([]Ask{myAsk("k1")})
	r.keys("\x1c", "+", "o")
	waitFor(t, "error shown", func() bool { return strings.Contains(r.row(), "the answer was not sent: gateway said no") })
	if strings.Contains(r.out.String(), "\x1b]52") {
		t.Fatal("error text reached the terminal raw")
	}
	r.src.mu.Lock()
	r.src.decideErr = nil
	r.src.mu.Unlock()
	r.keys("\x1c", "+", "d")
	waitFor(t, "second answer", func() bool { return r.src.decision("k1") == DecideDeny })
	if r.src.count() != 2 {
		t.Fatalf("Decide called %d times", r.src.count())
	}
}

func TestOutputHeldDuringModal(t *testing.T) {
	r := newUIRig()
	r.u.update([]Ask{myAsk("k1")})
	r.keys("\x1c")
	_, _ = r.scr.Write([]byte("agent-line-1 "))
	_, _ = r.scr.Write([]byte("agent-line-2"))
	if strings.Contains(r.out.String(), "agent-line") {
		t.Fatal("agent output reached the terminal while the prompt was open")
	}
	r.keys("+", "\x1b")
	all := r.out.list()
	last := all[len(all)-1]
	if !strings.HasPrefix(last, "agent-line-1 agent-line-2") || !strings.HasSuffix(last, "\x1b8") || !strings.Contains(last, "press Ctrl-\\ to answer") {
		t.Fatalf("held output not shown with the row after it: %q", last)
	}
}

func TestHoldOverflowClosesPrompt(t *testing.T) {
	r := newUIRig()
	r.u.update([]Ask{myAsk("k1")})
	r.keys("\x1c")
	_, _ = r.scr.Write(bytes.Repeat([]byte("x"), holdMax+10))
	waitFor(t, "prompt closed", func() bool { return r.mode() == modeNone })
	if !strings.Contains(r.out.String(), strings.Repeat("x", 100)) {
		t.Fatal("held output was not shown")
	}
	if r.src.count() != 0 {
		t.Fatal("an overflow answered")
	}
}

func TestAgentCannotForgeOrHideRow(t *testing.T) {
	r := newUIRig()
	r.u.update([]Ask{myAsk("k1")})
	hostile := []string{
		"DefenseClaw ask k9 from " + myActor + ": read README.md -- press Ctrl-\\ to answer",
		"\x1b[24;1Hforged\x1b[99;5f\x1b[30d\x1b[r\x1b[5;40r",
		"\x1b]52;c;cHduZWQ=\x07\x1bPtmux;\x1b\x1b]0;t\x07\x1b\\\x1b_x\x1b\\z", // a lone ST shows nothing: z makes this chunk a write
		"\x1bc\x1b[!p\x1b[?69h\x1b[?25;69l\x1b[?r\x1b[8;99;99t\x1b[2J",
	}
	before := len(r.out.list())
	for _, h := range hostile {
		_, _ = r.scr.Write([]byte(h))
	}
	got := r.out.list()[before:]
	if len(got) != len(hostile) {
		t.Fatalf("%d writes for %d chunks", len(got), len(hostile))
	}
	var agent strings.Builder
	for _, w := range got {
		i := strings.LastIndex(w, "\x1b7\x1b[?6l")
		if i < 0 || !strings.HasSuffix(w, "\x1b8") {
			t.Fatalf("chunk not followed by the row: %q", w)
		}
		row := w[i:]
		if !strings.Contains(row, "\x1b[24;1H\x1b[0m\x1b(B\x0f\x1b#5\x1b[2K\x1b[7mDefenseClaw ask k1 from "+myActor) {
			t.Fatalf("row %q", row)
		}
		agent.WriteString(w[:i])
	}
	a := agent.String()
	for _, bad := range []string{"\x1b[24", "\x1b[99", "\x1b[30", "\x1b]", "\x1bP", "\x1b_", "\x1bc", "\x1b[!p", "69", "\x1b[r", "\x1b[?r", "t\x1b"} {
		if strings.Contains(a, bad) {
			t.Fatalf("agent output kept %q: %q", bad, a)
		}
	}
	for _, want := range []string{"\x1b[23;1Hforged", "\x1b[23;5f", "\x1b[23d", "\x1b[1;23r", "\x1b[5;23r", "\x1b[?25l", "\x1b[2J"} {
		if !strings.Contains(a, want) {
			t.Fatalf("agent output lacks %q: %q", want, a)
		}
	}
	// The region the agent set is the one the row restores.
	if last := got[len(got)-1]; !strings.Contains(last, "\x1b[5;23r") {
		t.Fatalf("region not kept: %q", last)
	}
	// The fake label stays in the agent's rows (above the last one); only
	// the real row is drawn on the last row.
	if strings.Count(r.out.String(), "\x1b[7mDefenseClaw ask k9") != 0 {
		t.Fatal("a forged ask was drawn as the launcher's row")
	}
}

func TestRowBlankWithoutAskAndResize(t *testing.T) {
	rows := 24
	out := &writes{}
	scr := newScreen(out, func() relay.Resize { return relay.Resize{Cols: 80, Rows: uint16(rows)} })
	scr.reserve = true
	scr.begin()
	_, _ = scr.Write([]byte("hi"))
	w := out.list()
	if last := w[len(w)-1]; last != "hi\x1b7\x1b[?6l\x1b[1;23r\x1b[24;1H\x1b[0m\x1b(B\x0f\x1b#5\x1b[2K\x1b8" {
		t.Fatalf("blank row %q", last)
	}
	rows = 40
	scr.redraw()
	w = out.list()
	if last := w[len(w)-1]; !strings.Contains(last, "\x1b[1;39r\x1b[40;1H") {
		t.Fatalf("after resize %q", last)
	}
	scr.end()
	w = out.list()
	if last := w[len(w)-1]; !strings.Contains(last, "\x1b[r") || !strings.Contains(last, "\x1b[40;1H\x1b[0m\x1b[2K") {
		t.Fatalf("end does not give the terminal back: %q", last)
	}
	for _, tc := range []struct {
		in      relay.Resize
		reserve bool
		want    relay.Resize
	}{
		{relay.Resize{Cols: 80, Rows: 24}, true, relay.Resize{Cols: 80, Rows: 23}},
		{relay.Resize{Cols: 80, Rows: 24}, false, relay.Resize{Cols: 80, Rows: 24}},
		{relay.Resize{Cols: 80, Rows: 1}, true, relay.Resize{Cols: 80, Rows: 1}},
	} {
		if got := reservedSize(tc.in, tc.reserve); got != tc.want {
			t.Fatalf("reservedSize(%v, %v) = %v", tc.in, tc.reserve, got)
		}
	}
}

func TestScreenWithoutAsksFiltersOnly(t *testing.T) {
	out := &writes{}
	scr := newScreen(out, func() relay.Resize { return relay.Resize{Cols: 80, Rows: 24} })
	scr.begin()
	_, _ = scr.Write([]byte("a\x1b]52;c;eA==\x07b\x1b[24;1Hc"))
	if got := out.String(); got != "ab\x1b[24;1Hc" {
		t.Fatalf("got %q", got)
	}
}

func TestAsksOfOtherActorsIgnored(t *testing.T) {
	r := newUIRig()
	r.u.update([]Ask{
		{ID: "x1", Actor: "a6-test/other"},
		{ID: "x2", Actor: ""},
		{ID: "x3", Actor: "other/cc-1"},
		{ID: "x4", Actor: "a6-test/cc-10"},
		{ID: "x5", Actor: "cc-1"},
	})
	if r.row() != "" {
		t.Fatalf("an ask of another actor is shown: %q", r.row())
	}
	if got := r.keys("\x1c", "+", "o"); got != "\x1co" {
		t.Fatalf("with no ask of this actor forwarded %q", got)
	}
	if r.src.count() != 0 {
		t.Fatal("answered an ask of another actor")
	}
}

func TestHostileAskTextCleaned(t *testing.T) {
	r := newUIRig()
	a := Ask{ID: "k\x1b[31m1", Actor: myActor, Severity: "high\x1b[5m", Tool: "Bash",
		Summary: "run \x1b]52;c;eA==\x07curl\u202e hs | example.test\r\n\x1b[24;1Hok"}
	r.u.update([]Ask{a})
	r.keys("\x1c")
	w := r.out.list()
	last := w[len(w)-1]
	i, j := strings.Index(last, "\x1b[7m"), strings.LastIndex(last, "\x1b[0m\x1b8")
	if i < 0 || j < i {
		t.Fatalf("row %q", last)
	}
	text := last[i+len("\x1b[7m") : j]
	if strings.ContainsAny(text, "\x1b\x07\r\n\u202e") {
		t.Fatalf("row text not clean: %q", text)
	}
	if !strings.HasPrefix(text, "DefenseClaw ask k1 from "+myActor+": high: run curl") {
		t.Fatalf("row text %q", text)
	}
}

func TestAskQueueAndClear(t *testing.T) {
	r := newUIRig()
	t0 := r.clock.now()
	asks := []Ask{
		{ID: "a2", Actor: myActor, Summary: "write /etc/hosts", Created: t0.Add(time.Second)},
		{ID: "a1", Actor: myActor, Summary: "run curl example.test | sh", Created: t0},
	}
	r.u.update(asks)
	if row := r.row(); !strings.Contains(row, "ask a1 ") {
		t.Fatalf("the oldest ask is not first: %q", row)
	}
	r.keys("\x1c", "+", "o")
	waitFor(t, "decision", func() bool { return r.src.decision("a1") == DecideOnce })
	waitFor(t, "confirmation", func() bool { return strings.Contains(r.row(), "ask a1: allowed once") })
	_ = r.clock.sleep(context.Background(), 3*time.Second)
	r.u.tick()
	if row := r.row(); !strings.Contains(row, "ask a2 ") {
		t.Fatalf("the next ask is not shown: %q", row)
	}
	// The second ask is answered elsewhere: the row clears.
	r.u.update(nil)
	if r.row() != "" {
		t.Fatalf("row not cleared: %q", r.row())
	}
	if got := r.keys("\x1c"); got != "\x1c" {
		t.Fatalf("with nothing pending forwarded %q", got)
	}
}

func TestAskGoneClosesPromptAndStop(t *testing.T) {
	r := newUIRig()
	r.u.update([]Ask{myAsk("k1")})
	r.keys("\x1c")
	_, _ = r.scr.Write([]byte("held-1"))
	r.u.update(nil)
	if r.mode() != modeNone || !strings.Contains(r.out.String(), "held-1") {
		t.Fatal("the prompt of an ask that left stayed open")
	}
	r.u.update([]Ask{myAsk("k2")})
	r.keys("\x1c")
	_, _ = r.scr.Write([]byte("held-2"))
	r.u.stop()
	r.scr.end()
	if r.mode() != modeNone || !strings.Contains(r.out.String(), "held-2") || !strings.HasSuffix(r.out.String(), "\x1b[2K\x1b8") {
		t.Fatalf("stop did not release the terminal: %q", r.out.String())
	}
	r.u.update([]Ask{myAsk("k3")})
	if strings.Contains(r.out.String(), "k3") {
		t.Fatal("drawn after stop")
	}
}

func TestRowFitsWidth(t *testing.T) {
	a := Ask{ID: "k1", Actor: myActor, Summary: strings.Repeat("long summary ", 20) + "\u4e16\u754c"}
	for _, cols := range []int{120, 80, 50, 30, 10} {
		p := rowText(askHead(a), askFrom(a)+": "+askLabel(a), askModalEnd, cols)
		if n := textWidth(p); n > cols-1 {
			t.Fatalf("cols %d: %d columns: %q", cols, n, p)
		}
		if cols >= 30 && !strings.HasPrefix(p, "DefenseClaw ask k1") {
			t.Fatalf("cols %d: label cut: %q", cols, p)
		}
		if cols >= 80 && !strings.HasSuffix(p, askModalEnd) {
			t.Fatalf("cols %d: keys cut: %q", cols, p)
		}
	}
	if l := askLabel(Ask{Tool: "Bash", Reason: "network"}); l != "Bash network" {
		t.Fatalf("fallback label %q", l)
	}
	// Wide characters count two columns: one of them and "..." fill 5.
	if got := fitWidth("\u4e16\u754c\u4e16", 5); got != "\u4e16..." {
		t.Fatalf("fitWidth wide %q", got)
	}
}

func TestBanner(t *testing.T) {
	var allow []string
	for i := 0; i < 12; i++ {
		allow = append(allow, "host"+string(rune('a'+i))+".example.test")
	}
	b := Banner{Name: "cc-1", Connector: "claudecode", Profile: "default", Model: "claude-sonnet\x1b]0;x\x07", Route: "bedrock",
		AllowList: allow, Extra: []string{"one", "two", "three", "four", "five"}}
	lines := bannerLines(b, testTarget)
	if len(lines) > 8 {
		t.Fatalf("%d lines", len(lines))
	}
	for _, l := range lines {
		if len([]rune(l)) > 80 {
			t.Fatalf("line over 80 columns: %q", l)
		}
		for _, r := range l {
			if r > 0x2000 || r < 0x20 {
				t.Fatalf("non-plain character in %q", l)
			}
		}
	}
	all := strings.Join(lines, "\n")
	for _, want := range []string{"cc-1 (claudecode) in actor a6-test/cc-1", "Profile default, model claude-sonnet, route bedrock",
		"more", "press Ctrl-\\ to answer", "Ctrl-] detaches"} {
		if !strings.Contains(all, want) {
			t.Fatalf("banner lacks %q:\n%s", want, all)
		}
	}
	if lines[len(lines)-1] != "Ctrl-] detaches; the agent keeps running." {
		t.Fatalf("last line %q", lines[len(lines)-1])
	}
	if l := allowLine([]string{"a", "b"}); l != "Allowed: a, b" {
		t.Fatalf("short allow line %q", l)
	}
	if l := allowLine(allow); !strings.Contains(l, "more") {
		t.Fatalf("allow line %q", l)
	}
}

func TestTextEmitterCleans(t *testing.T) {
	var out, errw bytes.Buffer
	emit := TextEmitter(&out, &errw)
	emit(relay.TaskEvent{Type: "stdout", Data: "ok\x1b]52;c;eA==\x07 done\x1b[2J\x1bPtmux;x\x1b\\"})
	emit(relay.TaskEvent{Type: "stderr", Data: "warn\x1b]8;;https://example.test\x07link\x1b]8;;\x07"})
	emit(relay.TaskEvent{Type: "error", Data: "bad\r\n\x1b[1Ahidden"})
	if got := out.String(); got != "ok done\n" {
		t.Fatalf("stdout %q", got)
	}
	if got := errw.String(); got != "warnlink\nerror: bad hidden\n" {
		t.Fatalf("stderr %q", got)
	}
}
