// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRV518NoAnswerWarningOncePerSession(t *testing.T) {
	home := t.TempDir()
	sp, _ := specFor("claudecode")
	for i := 0; i < 2; i++ {
		stdout, stderr := newClaimedStopWriter(), newClaimedStopWriter()
		exited := make(chan int, 1)
		opts := perUserRestartOptions(home, "open", false, stdout, stderr, func(code int) { exited <- code })
		opts.failurePayload = []byte(`{"session_id":"same-session","tool_call_id":"call"}`)
		w := prepareAnswerWatchdog(&opts, sp, "open", time.Time{})
		w.perUserOutageSeen(opts, sp, "open", syscall.ECONNREFUSED)
		code, shown := fireAnswerDeadline(t, w, exited, stdout, stderr)
		if code != 0 {
			t.Fatalf("call %d returned code %d", i, code)
		}
		warning := strings.Contains(shown, "DefenseClaw is not checking this session")
		if warning != (i == 0) {
			t.Fatalf("call %d warning=%v answer=%q", i, warning, shown)
		}
	}
	if rows := claimedStopRows(t, home); len(rows) != 2 {
		t.Fatalf("failure rows = %d, want one for each call", len(rows))
	}
}
