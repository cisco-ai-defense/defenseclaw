// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// A call with thousands of operands answers inside the hook deadline for both
// connectors, per-user and managed, and a protected file named among them
// still blocks (GAP-0943). The ordinary call is unresolved past
// the operand bound: it is allowed with an alert that names the bound in the
// default tier, which is the tier of this fixture.
//
// Outside a race build one untimed row runs first, then every row is
// answered three times and the median time of each call, the client reading
// included, is held to the one-second budget, with up to 25 percent over it
// passing on a shared runner. Every answer of every run checks its verdict.
func TestLongOperandListAnswersInsideHookDeadlineAndKeepsProtectedBlocks(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	const perCall = time.Second
	const tolerated = perCall + perCall/4
	words := operandWords(5000)
	rows := []struct {
		command string
		verdict string
	}{
		{"touch " + words, "alert"},
		{"echo " + words + " > out.txt", "alert"},
		{"touch " + words + " ../.ssh/authorized_keys", "block"},
		{strings.Repeat("touch "+operandWords(1000)+"; ", 5), "alert"},
		{"touch " + operandWords(1023) + " " + quotedOperandWords(1025) + " ../.ssh/authorized_keys", "block"},
		{"touch " + pathOperandWords(5000) + " ../.ssh/authorized_keys", "block"},
		{"tee ../.ssh/authorized_keys " + words + " < /dev/null", "block"},
		{"echo " + words + " >> ../.ssh/authorized_keys", "block"},
	}
	// Under -race the same call takes tens of seconds, so a race build
	// answers each row once and checks only its verdicts.
	runs := 3
	if hookAnswerRaceBuild {
		runs = 1
	} else {
		f.answerOperandRow(t, rows[0].command, rows[0].verdict)
	}
	for _, row := range rows {
		var timed [][]time.Duration
		for range runs {
			timed = append(timed, f.answerOperandRow(t, row.command, row.verdict))
		}
		var slowest time.Duration
		for call := range timed[0] {
			var times []time.Duration
			for _, run := range timed {
				times = append(times, run[call])
			}
			slices.Sort(times)
			slowest = max(slowest, times[len(times)/2])
		}
		t.Logf("%.40s...: slowest median call %s, runs %v", row.command, slowest.Round(time.Millisecond), timed)
		if !hookAnswerRaceBuild && slowest > tolerated {
			t.Errorf("%.40s...: slowest median call took %s, want under %s (%s budget, 25 percent tolerance)",
				row.command, slowest.Round(time.Millisecond), tolerated, perCall)
		}
	}
}

// answerOperandRow answers command for both connectors, managed and per-user,
// checks each verdict, and returns each call's time with the client reading.
func (f b36ManagedHookFixture) answerOperandRow(t *testing.T, command, verdict string) []time.Duration {
	t.Helper()
	payload := f.payload(t, command)
	start := time.Now()
	header := f.clientHeader(t, payload)
	client := time.Since(start)
	var times []time.Duration
	for _, call := range everyMode(command[:16], payload, header) {
		mode := os.FileMode(0o700)
		if call.managed {
			mode = 0
		}
		if err := os.Chmod(f.homes, mode); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		call.verdict, call.body = f.serve(call)
		times = append(times, client+time.Since(start))
		switch {
		case verdict == "block" && call.verdict != "block":
			t.Errorf("%s: verdict %s, want block; body %.200s", call.name, call.verdict, call.body)
		case verdict == "alert" && !strings.Contains(call.body, `"action":"alert"`+","):
			t.Errorf("%s: want an alert that allows; verdict %s body %.200s", call.name, call.verdict, call.body)
		case verdict == "alert" && !strings.Contains(call.body, operandBoundRuleID):
			t.Errorf("%s: the alert does not name %s: %.200s", call.name, operandBoundRuleID, call.body)
		}
	}
	if err := os.Chmod(f.homes, 0o700); err != nil {
		t.Fatal(err)
	}
	return times
}
