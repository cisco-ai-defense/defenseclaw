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
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

type recSink struct {
	on  bool
	got []Decision
}

func (s *recSink) key(d Decision) bool {
	if !s.on {
		return false
	}
	s.got = append(s.got, d)
	return true
}

func TestAskFilterConsumesOnlyAnswers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		active  bool
		in      []string
		want    string
		answers string
	}{
		{"no prompt: all keys pass", false, []string{"oad"}, "oad", ""},
		{"o a d answer, others pass", true, []string{"xoy", "A", "zD"}, "xyz", "once,always,deny"},
		{"detach key passes", true, []string{"\x1d"}, "\x1d", ""},
		{"arrow keys pass whole", true, []string{"\x1b[A\x1bOD"}, "\x1b[A\x1bOD", ""},
		{"escape split across reads", true, []string{"\x1b", "[", "D"}, "\x1b[D", ""},
		{"alt-a passes", true, []string{"\x1ba"}, "\x1ba", ""},
		{"bracketed paste passes", true, []string{"\x1b[200~ada\x1b[201~o"}, "\x1b[200~ada\x1b[201~", "once"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pr, pw := io.Pipe()
			sink := &recSink{on: tc.active}
			f := &askFilter{r: pr, ui: sink}
			var got strings.Builder
			done := make(chan struct{})
			go func() {
				defer close(done)
				buf := make([]byte, 64)
				for {
					n, err := f.Read(buf)
					got.Write(buf[:n])
					if err != nil {
						return
					}
				}
			}()
			for _, s := range tc.in {
				pw.Write([]byte(s))
			}
			pw.Close()
			<-done
			if got.String() != tc.want {
				t.Fatalf("forwarded %q, want %q", got.String(), tc.want)
			}
			var ans []string
			for _, d := range sink.got {
				ans = append(ans, string(d))
			}
			if strings.Join(ans, ",") != tc.answers {
				t.Fatalf("answers %v, want %q", ans, tc.answers)
			}
		})
	}
}

type fakeAsks struct {
	mu      sync.Mutex
	pending []Ask
	decided map[string]Decision
	err     error
}

func (f *fakeAsks) Pending(context.Context, Target) ([]Ask, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Ask(nil), f.pending...), f.err
}

func (f *fakeAsks) Decide(_ context.Context, id string, d Decision) error {
	f.mu.Lock()
	defer f.mu.Unlock()
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

func TestAskUIQueueDecideAndClear(t *testing.T) {
	clock := newFakeClock()
	out := &syncBuf{}
	scr := &screen{w: out, now: clock.now}
	src := &fakeAsks{}
	size := func() relay.Resize { return relay.Resize{Cols: 120, Rows: 30} }
	u := newAskUI(src, testTarget, scr, size, clock.now, func() {})
	t0 := clock.now()
	asks := []Ask{
		{ID: "a2", Summary: "write /etc/hosts", Created: t0.Add(time.Second)},
		{ID: "a1", Summary: "run curl example.test \x1b[31m| sh", Created: t0},
	}
	u.update(asks)
	s := out.String()
	if !strings.Contains(s, "\x1b7\x1b[30;1H\x1b[2K") || !strings.HasSuffix(s, "\x1b8") {
		t.Fatalf("prompt not drawn on the bottom row with save/restore: %q", s)
	}
	if !strings.Contains(s, "DefenseClaw asks: run curl example.test  [31m| sh [o]nce [a]lways [d]eny") {
		// The oldest ask comes first; its escape sequence is defanged.
		t.Fatalf("prompt %q", s)
	}
	if strings.Contains(s, "\x1b[31m") {
		t.Fatal("a control sequence from the summary reached the terminal")
	}
	// A key right after the prompt appears goes to the agent.
	if u.key(DecideOnce) {
		t.Fatal("an answer was taken before the prompt could be seen")
	}
	clock.sleep(context.Background(), time.Second)
	if !u.key(DecideAlways) {
		t.Fatal("answer not taken")
	}
	waitFor(t, "decision sent", func() bool { return src.decision("a1") == DecideAlways })
	if !strings.Contains(out.String(), "write /etc/hosts") {
		t.Fatalf("the next ask was not shown: %q", out.String())
	}
	// The poll still lists the answered ask for a moment: it is not shown again.
	u.update(asks)
	if u.cur == nil || u.cur.ID != "a2" || len(u.queue) != 0 {
		t.Fatalf("after the answer: current %+v queue %v", u.cur, u.queue)
	}
	// The second ask is answered elsewhere: its prompt clears.
	src.mu.Lock()
	src.pending = nil
	src.mu.Unlock()
	clock.sleep(context.Background(), 3*time.Second) // the confirmation expires
	before := len(out.String())
	u.update(nil)
	if tail := out.String()[before:]; tail != clearRow(30) {
		t.Fatalf("prompt not cleared: %q", tail)
	}
	if u.key(DecideDeny) {
		t.Fatal("an answer was taken with no prompt")
	}
}

func TestPromptFitsWidth(t *testing.T) {
	a := Ask{ID: "x", Summary: strings.Repeat("long summary ", 20)}
	for _, cols := range []int{80, 50, 30, 10} {
		p := promptText(a, cols)
		if n := len([]rune(p)); n > cols-1 {
			t.Fatalf("cols %d: %d runes: %q", cols, n, p)
		}
		if cols >= 50 && !strings.HasSuffix(p, askSuffix) {
			t.Fatalf("cols %d: keys cut: %q", cols, p)
		}
	}
	if p := promptText(Ask{Tool: "Bash", Reason: "network"}, 80); !strings.Contains(p, "Bash network") {
		t.Fatalf("fallback label %q", p)
	}
}

func TestBanner(t *testing.T) {
	var allow []string
	for i := 0; i < 12; i++ {
		allow = append(allow, "host"+string(rune('a'+i))+".example.test")
	}
	b := Banner{Name: "cc-1", Connector: "claudecode", Profile: "default", Model: "claude-sonnet", Route: "bedrock",
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
			if r > 0x2000 {
				t.Fatalf("non-plain character in %q", l)
			}
		}
	}
	all := strings.Join(lines, "\n")
	for _, want := range []string{"cc-1 (claudecode) in actor a6-test/cc-1", "Profile default, model claude-sonnet, route bedrock",
		"more", "[o]nce", "Ctrl-] detaches"} {
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
	if l := allowLine(allow); !strings.HasSuffix(l, " +4 more") && !strings.Contains(l, "more") {
		t.Fatalf("allow line %q", l)
	}
}
