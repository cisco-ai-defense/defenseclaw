// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"strings"
	"testing"
)

func TestHookCapacityWarning(t *testing.T) {
	for _, body := range []string{``, `{}`, `{"hook_capacity":null}`, `not json`,
		`{"hook_capacity":{"window_minutes":60,"window":{"answered":10}}}`} {
		if message, ok := HookCapacityWarning([]byte(body)); ok {
			t.Fatalf("%q: warning %q, want none", body, message)
		}
	}
	message, ok := HookCapacityWarning([]byte(`{"hook_capacity":{"window_minutes":60,"window":{"answered":4000,"deadline_denies":12,"late_allows":0,"shed":7},"peak_minute_start":"2026-11-14T15:02:00Z","sizing_doc":"/docs/reference/hook-sizing"}}`))
	if !ok {
		t.Fatal("no warning for 12 deadline denies")
	}
	for _, want := range []string{"12 agent tool call(s) were blocked", "0 ran unchecked", "4000 answered in time",
		"7 call(s) refused by the admission limits at least once; a call no resend got in is blocked when its budget ends",
		"this host is over its hook capacity, not a policy result", "busiest minute 2026-11-14T15:02:00Z", "sizing: /docs/reference/hook-sizing"} {
		if !strings.Contains(message, want) {
			t.Fatalf("warning %q lacks %q", message, want)
		}
	}
}

// A call the admission limits keep refusing is blocked by its hook with the
// capacity text, so status and verify warn for shed alone (S8 review P2-3).
func TestHookCapacityWarningForShedAlone(t *testing.T) {
	message, ok := HookCapacityWarning([]byte(`{"hook_capacity":{"window_minutes":60,"window":{"answered":300,"shed":5}}}`))
	if !ok {
		t.Fatal("no warning for 5 calls refused by the admission limits")
	}
	for _, want := range []string{"in the last 60 min 5 call(s) refused by the admission limits at least once; a call no resend got in is blocked when its budget ends",
		"(300 answered in time)", "an account is over its hook budget or this host is over its hook capacity, not a policy result"} {
		if !strings.Contains(message, want) {
			t.Fatalf("warning %q lacks %q", message, want)
		}
	}
	if strings.Contains(message, "ran unchecked") {
		t.Fatalf("warning %q names deadline outcomes that did not happen", message)
	}
}
