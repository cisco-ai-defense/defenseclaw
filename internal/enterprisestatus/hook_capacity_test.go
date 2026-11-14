// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"strings"
	"testing"
)

func TestHookCapacityWarning(t *testing.T) {
	for _, body := range []string{``, `{}`, `{"hook_capacity":null}`, `not json`,
		`{"hook_capacity":{"window_minutes":60,"window":{"answered":10,"shed":3}}}`} {
		if message, ok := HookCapacityWarning([]byte(body)); ok {
			t.Fatalf("%q: warning %q, want none", body, message)
		}
	}
	message, ok := HookCapacityWarning([]byte(`{"hook_capacity":{"window_minutes":60,"window":{"answered":4000,"deadline_denies":12,"late_allows":0,"shed":7},"peak_minute_start":"2026-11-14T15:02:00Z","sizing_doc":"/docs/reference/hook-sizing"}}`))
	if !ok {
		t.Fatal("no warning for 12 deadline denies")
	}
	for _, want := range []string{"12 agent tool call(s) were blocked", "0 ran unchecked", "4000 answered in time", "7 refused",
		"not a policy result", "busiest minute 2026-11-14T15:02:00Z", "sizing: /docs/reference/hook-sizing"} {
		if !strings.Contains(message, want) {
			t.Fatalf("warning %q lacks %q", message, want)
		}
	}
}
