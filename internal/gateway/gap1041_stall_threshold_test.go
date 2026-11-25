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

// gap1041Budget is the p95 budget of the synthetic streams.
const gap1041Budget = 100 * time.Millisecond

// gap1041Scenario is a synthetic run: a flush record with pattern between
// 30 s of quiet flushes on each side, and a stream of 10 calls a second over
// the run. stream "local" makes only the calls inside the pattern slow or
// unanswered (the stall explains them); "everywhere" makes them so across the
// whole run (a real regression, with the stall somewhere in it).
func gap1041Scenario(kind, pattern, stream string) (*openLoopFlushProbe, openLoopResult) {
	p := &openLoopFlushProbe{stopping: make(chan struct{}), done: make(chan struct{})}
	close(p.done)
	t0 := time.Now().Add(-2 * time.Minute)
	at := t0
	flush := func(took time.Duration) {
		gap1041Note(p, at, took)
		at = at.Add(max(took, openLoopFlushEvery))
	}
	for range 300 {
		flush(4 * time.Millisecond)
	}
	patFrom := at
	switch pattern {
	case "single": // one 50 ms flush, the rest quiet (EBS, CI runners)
		flush(openLoopFlushStall)
	case "run3": // three slow flushes in a row: one 330 ms burst
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
	patTo := at
	for range 300 {
		flush(4 * time.Millisecond)
	}
	r := openLoopResult{problems: map[string]int{}}
	for n, c := 0, t0; c.Before(at); n, c = n+1, c.Add(100*time.Millisecond) {
		bad := stream == "everywhere" || (!c.Before(patFrom) && c.Before(patTo))
		if kind == "unanswered" && stream == "everywhere" {
			bad = n%4 == 0 // about 27% unanswered across the run
		}
		r.offered++
		switch {
		case bad && kind == "unanswered":
			r.calls = append(r.calls, openLoopCall{issued: c})
		case bad && kind == "slow":
			r.calls = append(r.calls, openLoopCall{issued: c, elapsed: 2 * gap1041Budget, answered: true})
			r.latencies = append(r.latencies, 2*gap1041Budget)
		default:
			r.calls = append(r.calls, openLoopCall{issued: c, elapsed: 20 * time.Millisecond, answered: true})
			r.latencies = append(r.latencies, 20*time.Millisecond)
		}
	}
	return p, r
}

// TestGAP1041SettleChild settles a synthetic verdict on a synthetic run, in a
// child process, so its parent can see a skip from a failure.
// DC_TEST_GAP1041 is "<verdict kind>/<flush pattern>/<stream>".
func TestGAP1041SettleChild(t *testing.T) {
	parts := strings.Split(os.Getenv(gap1041Env), "/")
	if len(parts) != 3 {
		return
	}
	kind := parts[0]
	p, got := gap1041Scenario(kind, parts[1], parts[2])
	settleOpenLoop(t, openLoopVerdict{kind, "synthetic " + kind + " verdict"}, nil, p, nil, &openLoopTiming{got, gap1041Budget})
}

// substrate-1 GAP-1041. RV-T6A: a disk stall turns a timing verdict into a
// skip only when it is sustained (openLoopFlushStallRun slow flushes in a row
// or openLoopFlushStallShare of a second), and an unanswered verdict only on
// a stall at least openLoopWait long; before, one flush of 50 ms in the whole
// run turned a real failure into a skip. RV-T6B: a stall explains a timing
// verdict only when the calls it does not overlap pass; before, a real
// regression (every call slow, or a quarter unanswered, across the run) with
// one 330 ms burst or one 4 s stall somewhere in it was a skip.
func TestGAP1041OneSlowFlushDoesNotHideAFailure(t *testing.T) {
	cases := []struct {
		kind, pattern, stream string
		skip                  bool
	}{
		{"unanswered", "single", "local", false},
		{"slow", "single", "local", false},
		{"inconclusive", "single", "local", false},
		{"unanswered", "run3", "local", false},
		{"slow", "run3", "local", true},
		{"inconclusive", "run3", "local", true},
		{"unanswered", "run4s", "local", true},
		{"slow", "share", "local", true},
		{"unanswered", "share", "local", false},
		{"unanswered", "none", "local", false},
		// RV-T6B: a real regression with one burst in it fails.
		{"slow", "run3", "everywhere", false},
		{"slow", "share", "everywhere", false},
		{"slow", "run4s", "everywhere", false},
		{"unanswered", "run4s", "everywhere", false},
	}
	for _, c := range cases {
		cmd := exec.Command(os.Args[0], "-test.run=^TestGAP1041SettleChild$", "-test.v", "-test.count=1")
		cmd.Env = append(os.Environ(), gap1041Env+"="+c.kind+"/"+c.pattern+"/"+c.stream)
		out, _ := cmd.CombinedOutput()
		skipped := strings.Contains(string(out), "--- SKIP: TestGAP1041SettleChild")
		failed := strings.Contains(string(out), "--- FAIL: TestGAP1041SettleChild")
		if skipped == failed {
			t.Fatalf("%s/%s/%s: the child neither skipped nor failed (or both):\n%s", c.kind, c.pattern, c.stream, out)
		}
		if skipped != c.skip {
			t.Errorf("%s verdict, flush pattern %s, failing calls %s: skipped %v, want %v\n%s", c.kind, c.pattern, c.stream, skipped, c.skip, out)
		}
	}
}
