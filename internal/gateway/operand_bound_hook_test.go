// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"strings"
	"testing"
	"time"
)

// A call with thousands of operands answers inside the hook deadline for both
// connectors, per-user and managed, and a protected file named among them
// still blocks (GAP-0943). The ordinary call is unresolved past
// the operand bound: it is allowed with an alert that names the bound in the
// default tier, which is the tier of this fixture.
func TestLongOperandListAnswersInsideHookDeadlineAndKeepsProtectedBlocks(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	const perCall = time.Second
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
	for _, row := range rows {
		payload := f.payload(t, row.command)
		start := time.Now()
		header := f.clientHeader(t, payload)
		client := time.Since(start)
		var slowest time.Duration
		for _, call := range everyMode(row.command[:16], payload, header) {
			mode := os.FileMode(0o700)
			if call.managed {
				mode = 0
			}
			if err := os.Chmod(f.homes, mode); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			call.verdict, call.body = f.serve(call)
			slowest = max(slowest, client+time.Since(start))
			switch {
			case row.verdict == "block" && call.verdict != "block":
				t.Errorf("%s: verdict %s, want block; body %.200s", call.name, call.verdict, call.body)
			case row.verdict == "alert" && !strings.Contains(call.body, `"action":"alert"`+","):
				t.Errorf("%s: want an alert that allows; verdict %s body %.200s", call.name, call.verdict, call.body)
			case row.verdict == "alert" && !strings.Contains(call.body, operandBoundRuleID):
				t.Errorf("%s: the alert does not name %s: %.200s", call.name, operandBoundRuleID, call.body)
			}
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
		t.Logf("%.40s...: slowest call %s", row.command, slowest.Round(time.Millisecond))
		// Under -race the same call takes tens of seconds, so only the
		// verdicts above are checked; the non-race budget is unchanged.
		if !hookAnswerRaceBuild && slowest > perCall {
			t.Errorf("%.40s...: slowest call took %s, want under %s", row.command, slowest.Round(time.Millisecond), perCall)
		}
	}
}
