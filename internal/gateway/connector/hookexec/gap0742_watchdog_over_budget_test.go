// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"
)

// GAP-0742 N2: a managed call whose resends meet a full gateway first and
// then its account's own limit, and that the watchdog answers between them,
// names the per-account refusal, as Run does; the reverse names the full
// gateway again. The answer stays closed.
func TestWatchdogAnswerFollowsTheLastBusyRefusal(t *testing.T) {
	sp, _ := specFor("claudecode")
	for _, tc := range []struct {
		name          string
		first, second bool
		want, notWant string
	}{
		{"full gateway, then the account limit", false, true, managedCallerOverLimitRefusal, managedGatewayNoAnswerReason},
		{"the account limit, then a full gateway", true, false, managedGatewayNoAnswerReason, managedCallerOverLimitRefusal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			opts := Options{Stdout: &stdout, Stderr: &stderr, Exit: func(int) {}}
			managedCodex(&opts)
			w := prepareAnswerWatchdog(&opts, sp, "closed", time.Time{})
			opts.callerOverBudget = tc.first
			markManagedAnsweredError(&opts, sp, http.StatusTooManyRequests)
			opts.callerOverBudget = tc.second
			markManagedAnsweredError(&opts, sp, http.StatusTooManyRequests)
			w.mu.Lock()
			out, shown, code := string(w.fallback.out), string(w.fallback.out)+string(w.fallback.err), w.fallback.code
			w.mu.Unlock()
			if !strings.Contains(shown, tc.want) || strings.Contains(shown, tc.notWant) {
				t.Fatalf("watchdog answer %q, want %s, not %s", shown, tc.want, tc.notWant)
			}
			if !blocked(runResult{code: code, stdout: out}) || !w.closedKnown {
				t.Fatalf("watchdog answer code %d (closed %v), want the closed block", code, w.closedKnown)
			}
		})
	}
}
