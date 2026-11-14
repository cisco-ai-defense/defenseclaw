// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

type fakeCapacityClock struct{ t time.Time }

func (c *fakeCapacityClock) now() time.Time { return c.t }

// withHookCapacity swaps the process counter for a counter on a fake clock.
func withHookCapacity(t *testing.T, start time.Time) *fakeCapacityClock {
	t.Helper()
	clock := &fakeCapacityClock{t: start}
	saved := hookCapacity
	hookCapacity = newHookCapacityCounter(clock.now)
	t.Cleanup(func() { hookCapacity = saved })
	return clock
}

func TestHookCapacityCountsByMinuteAndExpiresTheWindow(t *testing.T) {
	start := time.Date(2026, 11, 14, 14, 0, 30, 0, time.UTC)
	clock := withHookCapacity(t, start)
	hookCapacity.note(hookCapacityAnswered, time.Time{}, 90)
	hookCapacity.note(hookCapacityDeadlineDeny, time.Time{}, 3)
	clock.t = start.Add(2 * time.Minute)
	hookCapacity.note(hookCapacityAnswered, time.Time{}, 40)
	hookCapacity.note(hookCapacityLateAllow, time.Time{}, 5)
	hookCapacity.note(hookCapacityShed, time.Time{}, 2)
	// A line stamped in the future or before the window is not counted.
	hookCapacity.note(hookCapacityDeadlineDeny, clock.t.Add(2*time.Minute), 7)
	hookCapacity.note(hookCapacityDeadlineDeny, clock.t.Add(-61*time.Minute), 7)

	snap := hookCapacity.snapshot()
	if snap.LastMinute != (HookCapacityCounts{Answered: 40, LateAllows: 5, Shed: 2}) {
		t.Fatalf("last minute = %+v", snap.LastMinute)
	}
	if snap.Window != (HookCapacityCounts{Answered: 130, DeadlineDenies: 3, LateAllows: 5, Shed: 2}) {
		t.Fatalf("window = %+v", snap.Window)
	}
	if snap.Last5Minutes != snap.Window {
		t.Fatalf("last 5 minutes = %+v, want the window %+v", snap.Last5Minutes, snap.Window)
	}
	if snap.PeakMinute.LateAllows != 5 || snap.PeakMinuteStart == nil || !snap.PeakMinuteStart.Equal(start.Add(2*time.Minute).Truncate(time.Minute)) {
		t.Fatalf("peak = %+v at %v", snap.PeakMinute, snap.PeakMinuteStart)
	}
	if snap.AnsweredPerMinutePeak != 90 || !snap.Overloaded || snap.WindowMinutes != hookCapacityWindow || snap.SizingDoc == "" {
		t.Fatalf("snapshot = %+v", snap)
	}

	// 60 minutes later the first minute has left the window; a bucket that is
	// reused for a new minute starts from zero.
	clock.t = start.Add(60 * time.Minute)
	hookCapacity.note(hookCapacityAnswered, time.Time{}, 1)
	snap = hookCapacity.snapshot()
	if snap.Window != (HookCapacityCounts{Answered: 41, LateAllows: 5, Shed: 2}) {
		t.Fatalf("window after an hour = %+v", snap.Window)
	}
	clock.t = start.Add(3 * time.Hour)
	if snap = hookCapacity.snapshot(); snap.Overloaded || snap.Window != (HookCapacityCounts{}) {
		t.Fatalf("an idle hour later = %+v", snap)
	}
}

func TestHookCapacityCountsOnlyTheDeadlineLinesOfHooks(t *testing.T) {
	now := time.Date(2026, 11, 14, 14, 10, 0, 0, time.UTC)
	withHookCapacity(t, now)
	stamp := now.Add(-30 * time.Second).Format(time.RFC3339Nano)
	for _, line := range []hookFailureLine{
		{TS: stamp, Reason: hookexec.PerUserGatewayNoAnswerReason, Outcome: "fail_open"},
		{TS: stamp, Reason: hookexec.PerUserGatewayNoAnswerReason, Outcome: "fail_open"},
		{TS: stamp, Reason: hookexec.PerUserGatewayNoAnswerReason, Outcome: "fail_closed"},
		// Not capacity: an unreachable gateway, a line the gateway wrote,
		// a line without a time stamp.
		{TS: stamp, Reason: "gateway unreachable", Outcome: "fail_open"},
		{TS: stamp, Reason: hookexec.PerUserGatewayNoAnswerReason, Outcome: hookActionUnconfirmed},
		{Reason: hookexec.PerUserGatewayNoAnswerReason, Outcome: "fail_closed"},
	} {
		noteHookFailureCapacity(line)
	}
	if got := hookCapacity.snapshot().Window; got != (HookCapacityCounts{LateAllows: 2, DeadlineDenies: 1}) {
		t.Fatalf("window = %+v", got)
	}
}

func TestHookCapacityManagedCallsCountTheirRecordedOutcome(t *testing.T) {
	withHookCapacity(t, time.Date(2026, 11, 14, 14, 20, 0, 0, time.UTC))
	managedAPI := &APIServer{scannerCfg: &config.Config{DeploymentMode: "managed_enterprise", Enterprise: config.EnterpriseConfig{Profile: "standalone"}}}
	perUserAPI := &APIServer{scannerCfg: &config.Config{}}

	managedAPI.noteHookCallCapacity(agentHookResponse{Action: "allow"}, false)
	managedAPI.noteHookCallCapacity(agentHookResponse{Action: "block", Reason: "policy"}, false)
	managedAPI.noteHookCallCapacity(agentHookResponse{Action: "block", Reason: hookexec.ManagedGatewayNoAnswerReason}, true)
	managedAPI.noteHookCallCapacity(agentHookResponse{Action: "block", Reason: hookexec.ManagedGatewayNoAnswerReason}, false)
	managedAPI.noteHookCallCapacity(agentHookResponse{Action: hookActionUnconfirmed, Reason: hookexec.ManagedGatewayNoAnswerReason}, true)
	// A per-user late call is counted from its hook line, not here.
	perUserAPI.noteHookCallCapacity(agentHookResponse{Action: "allow"}, false)
	perUserAPI.noteHookCallCapacity(agentHookResponse{Action: hookActionUnconfirmed, Reason: hookexec.PerUserGatewayNoAnswerReason}, true)

	want := HookCapacityCounts{Answered: 3, DeadlineDenies: 2, LateAllows: 1}
	if got := hookCapacity.snapshot().Window; got != want {
		t.Fatalf("window = %+v, want %+v", got, want)
	}
}

func TestHookCapacityCountsEachReportedLineOnceAcrossReportRuns(t *testing.T) {
	_, logger := testStoreAndLogger(t)
	logDir := filepath.Join(t.TempDir(), "logs")
	now := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	withHookCapacity(t, now)
	late := func(ts, outcome, call string) string {
		return `{"ts":"` + ts + `","connector":"claudecode","hook":"claude-code-hook","reason":"gateway did not answer in time","category":"transport","fail_mode":"open","outcome":"` + outcome + `","session_id":"s1","call_id":"` + call + `","tool_id":"` + call + `","event":"PreToolUse"}` + "\n"
	}
	appendHookFailures(t, logDir, late("2026-11-01T00:59:01Z", "fail_open", "c1"), late("2026-11-01T00:59:02Z", "fail_closed", "c2"))
	if err := reportHookFailureCallsIn(logDir, logger, now); err != nil {
		t.Fatal(err)
	}
	// A second run reads only the line appended after the first.
	appendHookFailures(t, logDir, late("2026-11-01T00:59:40Z", "fail_open", "c3"))
	for range 2 {
		if err := reportHookFailureCallsIn(logDir, logger, now); err != nil {
			t.Fatal(err)
		}
	}
	if got := hookCapacity.snapshot().Window; got != (HookCapacityCounts{LateAllows: 2, DeadlineDenies: 1}) {
		t.Fatalf("window = %+v, want 2 late allows and 1 deadline deny", got)
	}
}
