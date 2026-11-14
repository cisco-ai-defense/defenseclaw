// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
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

// On a managed gateway a deadline is counted only from evidence of one (S8
// review P2-1): a late or open receipt (the hook says which it did) or a
// client that left before the answer (by the no-answer fail mode). An
// unconfirmed row without that evidence (no receipt, an older hook) and the
// journal-failure 503 are not deadline outcomes in either fail mode: before
// the fix a default closed host counted them as calls that ran unchecked.
func TestHookCapacityManagedCallsCountOnlyDeadlineEvidence(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want HookCapacityCounts
	}{
		{"closed", HookCapacityCounts{Answered: 3, DeadlineDenies: 2, LateAllows: 1}},
		{"open", HookCapacityCounts{Answered: 3, DeadlineDenies: 1, LateAllows: 2}},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			withHookCapacity(t, time.Date(2026, 11, 14, 14, 20, 0, 0, time.UTC))
			cfg := &config.Config{DeploymentMode: "managed_enterprise", Enterprise: config.EnterpriseConfig{Profile: "standalone"}}
			cfg.Guardrail.HookFailMode = tc.mode
			api := &APIServer{scannerCfg: cfg}
			ctx := t.Context()
			receipt := func(line string) context.Context {
				return context.WithValue(ctx, hookCapacityReceiptContextKey{}, hookCapacityReceipt{line: line})
			}
			allow := agentHookResponse{Action: "allow", Mode: "action"}
			// Answered in time.
			api.noteHookCallCapacity(ctx, "claudecode", allow, false)
			api.noteHookCallCapacity(ctx, "claudecode", agentHookResponse{Action: "block", Reason: "policy"}, false)
			api.noteHookCallCapacity(receipt(hookexec.HookDeliveryReceiptAck), "claudecode", allow, false)
			// The receipt says what the hook did at its deadline.
			api.noteHookCallCapacity(receipt(hookexec.HookDeliveryReceiptLate), "claudecode",
				api.deliveredHookDecision("claudecode", allow, hookexec.HookDeliveryReceiptLate), false)
			api.noteHookCallCapacity(receipt(hookexec.HookDeliveryReceiptOpen), "claudecode",
				api.deliveredHookDecision("claudecode", allow, hookexec.HookDeliveryReceiptOpen), false)
			// No deadline evidence: no receipt for an offered allow or a
			// policy block, an unreceipted older hook, the journal 503.
			api.noteHookCallCapacity(receipt(""), "claudecode", api.deliveredHookDecision("claudecode", allow, ""), false)
			api.noteHookCallCapacity(receipt(""), "claudecode", agentHookResponse{Action: "block", Reason: "policy"}, false)
			api.noteHookCallCapacity(ctx, "claudecode", unconfirmedHookDelivery(allow), false)
			api.noteHookCallCapacity(context.WithValue(ctx, hookCapacityExcludedContextKey{}, true), "claudecode",
				pendingFailureHookDecision(allow), false)
			// A client that left before the answer follows the fail mode.
			api.noteHookCallCapacity(ctx, "claudecode", unconfirmedHookDelivery(allow), true)
			if got := hookCapacity.snapshot().Window; got != tc.want {
				t.Fatalf("window = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// A per-user late call is counted from its hook line, not from the gateway
// row of the call.
func TestHookCapacityPerUserCallsCountOnlyTheAnsweredOnes(t *testing.T) {
	withHookCapacity(t, time.Date(2026, 11, 14, 14, 20, 0, 0, time.UTC))
	api := &APIServer{scannerCfg: &config.Config{}}
	ctx := t.Context()
	api.noteHookCallCapacity(ctx, "claudecode", agentHookResponse{Action: "allow"}, false)
	api.noteHookCallCapacity(ctx, "claudecode", agentHookResponse{Action: hookActionUnconfirmed, Reason: hookexec.PerUserGatewayNoAnswerReason}, true)
	api.noteHookCallCapacity(context.WithValue(ctx, hookCapacityReceiptContextKey{}, hookCapacityReceipt{line: hookexec.HookDeliveryReceiptOpen}),
		"claudecode", api.deliveredHookDecision("claudecode", agentHookResponse{Action: "allow"}, hookexec.HookDeliveryReceiptOpen), false)
	if got := hookCapacity.snapshot().Window; got != (HookCapacityCounts{Answered: 1}) {
		t.Fatalf("window = %+v, want one answered call", got)
	}
}

// A panic of the counter or its telemetry sink is recovered where it
// happens, so it never reaches the hook answer (S8 review P3-3).
func TestHookCapacityNotePanicNeverReachesTheCaller(t *testing.T) {
	withHookCapacity(t, time.Date(2026, 11, 14, 14, 20, 0, 0, time.UTC))
	hookCapacity.setSink(func(string, uint64) { panic("sink") })
	api := &APIServer{scannerCfg: &config.Config{DeploymentMode: "managed_enterprise", Enterprise: config.EnterpriseConfig{Profile: "standalone"}}}
	api.noteHookCallCapacity(t.Context(), "claudecode", agentHookResponse{Action: "block"}, true)
	api.noteHookCallerGoneCapacity("claudecode", true)
	(&APIServer{}).recordHookDeadlineOutcomeMetric(hookCapacityShed, 1)
	if got := hookCapacity.snapshot().Window; got != (HookCapacityCounts{DeadlineDenies: 1, Shed: 1}) {
		t.Fatalf("window = %+v: the counts stay even when the sink panics", got)
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

func TestHookCapacityExportsOnlyDeadlineOutcomes(t *testing.T) {
	withHookCapacity(t, time.Date(2026, 11, 14, 14, 30, 0, 0, time.UTC))
	exported := map[string]uint64{}
	hookCapacity.setSink(func(outcome string, n uint64) { exported[outcome] += n })
	hookCapacity.note(hookCapacityAnswered, time.Time{}, 50)
	hookCapacity.note(hookCapacityDeadlineDeny, time.Time{}, 2)
	hookCapacity.note(hookCapacityLateAllow, time.Time{}, 3)
	hookCapacity.note(hookCapacityShed, time.Time{}, 1)
	// Outside the window: neither counted nor exported.
	hookCapacity.note(hookCapacityDeadlineDeny, time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC), 9)
	want := map[string]uint64{hookCapacityDeadlineDeny: 2, hookCapacityLateAllow: 3, hookCapacityShed: 1}
	if len(exported) != len(want) {
		t.Fatalf("exported %v, want %v", exported, want)
	}
	for k, v := range want {
		if exported[k] != v {
			t.Fatalf("exported %v, want %v", exported, want)
		}
	}
	// An API server without a bound runtime exports nothing and does not panic.
	(&APIServer{}).recordHookDeadlineOutcomeMetric(hookCapacityDeadlineDeny, 1)
}
