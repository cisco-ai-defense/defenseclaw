// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !race

package gateway

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const gap1041Env = "DC_TEST_GAP1041"

// TestGAP1041SettleChild settles a synthetic verdict on a synthetic flush
// record, in a child process, so its parent can see a skip from a failure.
// DC_TEST_GAP1041 is "<verdict kind>/<flush pattern>".
func TestGAP1041SettleChild(t *testing.T) {
	kind, pattern, ok := strings.Cut(os.Getenv(gap1041Env), "/")
	if !ok {
		return
	}
	p := &openLoopFlushProbe{stopping: make(chan struct{}), done: make(chan struct{})}
	close(p.done)
	t0 := time.Now().Add(-time.Minute)
	at := t0
	flush := func(took time.Duration) {
		gap1041Note(p, at, took)
		at = at.Add(max(took, openLoopFlushEvery))
	}
	for range 300 {
		flush(4 * time.Millisecond)
	}
	switch pattern {
	case "single": // one 50 ms flush, the rest quiet (EBS, CI runners)
		flush(openLoopFlushStall)
	case "run3": // three slow flushes in a row
		for range 3 {
			flush(110 * time.Millisecond)
		}
	case "run4s": // a stall of seconds, at 100 to 130 ms a flush
		for range 36 {
			flush(115 * time.Millisecond)
		}
	case "share": // every other flush slow: 30% of each second, never 3 in a row
		for range 10 {
			flush(60 * time.Millisecond)
			flush(4 * time.Millisecond)
		}
	}
	for range 300 {
		flush(4 * time.Millisecond)
	}
	settleOpenLoop(t, openLoopVerdict{kind, "synthetic " + kind + " verdict"}, nil, p, nil)
}

// substrate-1 GAP-1041 (RV-T6A): a disk stall turns a timing verdict into a
// skip only when it is sustained (openLoopFlushStallRun slow flushes in a row
// or openLoopFlushStallShare of a second), and an unanswered verdict only on
// a stall at least openLoopWait long. Before, one flush of 50 ms in the whole
// run turned a real failure (calls unanswered for 3.5 s) into a skip.
func TestGAP1041OneSlowFlushDoesNotHideAFailure(t *testing.T) {
	cases := []struct {
		kind, pattern string
		skip          bool
	}{
		{"unanswered", "single", false},
		{"slow", "single", false},
		{"inconclusive", "single", false},
		{"unanswered", "run3", false},
		{"slow", "run3", true},
		{"inconclusive", "run3", true},
		{"unanswered", "run4s", true},
		{"slow", "share", true},
		{"unanswered", "share", false},
		{"unanswered", "none", false},
	}
	for _, c := range cases {
		cmd := exec.Command(os.Args[0], "-test.run=^TestGAP1041SettleChild$", "-test.v", "-test.count=1")
		cmd.Env = append(os.Environ(), gap1041Env+"="+c.kind+"/"+c.pattern)
		out, _ := cmd.CombinedOutput()
		skipped := strings.Contains(string(out), "--- SKIP: TestGAP1041SettleChild")
		failed := strings.Contains(string(out), "--- FAIL: TestGAP1041SettleChild")
		if skipped == failed {
			t.Fatalf("%s/%s: the child neither skipped nor failed (or both):\n%s", c.kind, c.pattern, out)
		}
		if skipped != c.skip {
			t.Errorf("%s verdict with flush pattern %s: skipped %v, want %v\n%s", c.kind, c.pattern, skipped, c.skip, out)
		}
	}
}
