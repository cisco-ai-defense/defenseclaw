// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"runtime"
	"strings"
	"testing"
)

// A managed call the running gateway did not decide within its answer
// budget, or kept refusing with 429, is blocked as before (fail closed), and
// its text names capacity, not policy (owner decision on H1, S8 DESIGN 18).
// A stopped or restarting gateway keeps its own words.
func TestManagedOverloadDenyNamesCapacityNotPolicy(t *testing.T) {
	status := "`" + managedStatusCommand(runtime.GOOS) + "` shows the recent hook load."
	for _, tc := range []struct {
		event, reason, subject string
	}{
		{"PreToolUse", managedGatewayNoAnswerReason, "tool call"},
		{"UserPromptSubmit", managedGatewayNoAnswerReason, "prompt"},
		{"PreToolUse", managedGatewayBusyRefusal, "tool call"},
	} {
		got := managedStandaloneFailClosedText(tc.event, "transport", tc.reason)
		for _, want := range []string{
			"DefenseClaw blocked this " + tc.subject + ": DefenseClaw on this computer is at capacity or not responding",
			"could not finish checking this " + tc.subject + " in time",
			"This is not a policy decision.",
			status,
			"(" + managedGatewayNoAnswerReason + ")",
		} {
			if !strings.Contains(got, want) {
				t.Fatalf("%s %q: text %q lacks %q", tc.event, tc.reason, got, want)
			}
		}
	}
	over := managedStandaloneFailClosedText("PreToolUse", "transport", managedCallerOverLimitRefusal)
	for _, want := range []string{
		"DefenseClaw blocked this tool call: this account sent more agent hook calls than its DefenseClaw limit allows at once",
		"This is not a policy decision.", status, "(" + callerBusyReason + ")",
	} {
		if !strings.Contains(over, want) {
			t.Fatalf("account over its budget: text %q lacks %q", over, want)
		}
	}
	if strings.Contains(over, "at capacity") {
		t.Fatalf("account over its own budget: %q says the computer is at capacity", over)
	}
	for _, reason := range []string{managedGatewayNotRunningReason, managedGatewayRestartingReason} {
		if got := managedStandaloneFailClosedText("PreToolUse", "transport", reason); strings.Contains(got, "capacity") {
			t.Fatalf("%s: %q names capacity", reason, got)
		}
	}
}
