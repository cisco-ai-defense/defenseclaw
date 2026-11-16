// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A per-user hook that started slowly (the PowerShell adapter in front of a
// Windows Cursor hook, a loaded host) reaches its first try after the
// restart budget, which counts from the start of the call. It still asks
// its running gateway and takes the answer: a spent budget ends the
// retries, not the first try. Before, the first try was cancelled before it
// connected, so a Cursor sessionStart was answered locally and never
// reached the gateway, and a tool call was blocked as if the gateway were
// restarting.
func TestASlowStartingPerUserHookStillAsksItsGateway(t *testing.T) {
	for _, event := range []string{"SessionStart", "PreToolUse"} {
		t.Run(event, func(t *testing.T) {
			var asked atomic.Int32
			addr := gatewayAt(t, func(w http.ResponseWriter, _ *http.Request) {
				asked.Add(1)
				_, _ = w.Write([]byte(`{"action":"allow"}`))
			})
			result, _ := runAgainstGateway(t, "claudecode", addr, func(opts *Options) {
				opts.Event = event
				opts.FailMode = "closed"
				opts.StartedAt = time.Now().Add(-gatewayRestartBudget - 200*time.Millisecond)
			})
			if got := asked.Load(); got != 1 {
				t.Fatalf("the gateway was asked %d times, want once", got)
			}
			if result.code != 0 || strings.Contains(result.stdout+result.stderr, "restarting or not running") ||
				strings.Contains(result.stdout, `"permissionDecision":"deny"`) {
				t.Fatalf("code=%d stdout=%q stderr=%q, want the gateway's allow", result.code, result.stdout, result.stderr)
			}
		})
	}
}

// The first try's window only extends a spent budget; it never shortens a
// budget that has time left, and a call with no restart budget keeps none.
func TestFirstTryConnectDeadline(t *testing.T) {
	now := time.Now()
	if got := firstTryConnectDeadline(time.Time{}, now); !got.IsZero() {
		t.Fatalf("no budget: %v, want none", got)
	}
	if later := now.Add(2 * time.Second); !firstTryConnectDeadline(later, now).Equal(later) {
		t.Fatal("a budget with time left was changed")
	}
	if got := firstTryConnectDeadline(now.Add(-time.Second), now); !got.Equal(now.Add(firstTryConnectWindow)) {
		t.Fatalf("spent budget: %v, want now + %s", got.Sub(now), firstTryConnectWindow)
	}
}
