// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import "testing"

func TestHookPanicArgumentParsing(t *testing.T) {
	args := []string{"hook", "--connector", "ClaudeCode", "--event=PreToolUse", "--enterprise-managed"}
	if got := hookPanicFlagValue(args, "--connector"); got != "ClaudeCode" {
		t.Fatalf("connector = %q", got)
	}
	if got := hookPanicFlagValue(args, "--event"); got != "PreToolUse" {
		t.Fatalf("event = %q", got)
	}
	if !hookPanicManagedFlag(args) {
		t.Fatal("managed flag not detected")
	}
	if hookPanicManagedFlag([]string{"hook", "--connector", "codex"}) {
		t.Fatal("unmanaged hook detected as managed")
	}
	if got := hookPanicFlagValue([]string{"hook", "--connector"}, "--connector"); got != "" {
		t.Fatalf("dangling flag value = %q, want empty", got)
	}
}

// A Codex notification is best-effort: a panic there exits 0.
func TestHookPanicExitNotifyIsBestEffort(t *testing.T) {
	if code := hookPanicExit([]string{"notify", `{}`}, "boom"); code != 0 {
		t.Fatalf("notify panic exit = %d, want 0", code)
	}
}
