// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"
)

func TestAllActionsUnique(t *testing.T) {
	seen := make(map[Action]bool)
	for _, a := range AllActions() {
		if seen[a] {
			t.Errorf("duplicate action in AllActions(): %q", a)
		}
		seen[a] = true
	}
}

func TestAllActionsNonEmpty(t *testing.T) {
	for _, a := range AllActions() {
		if a == "" {
			t.Errorf("empty action string in AllActions()")
		}
	}
}

func TestIsKnownAction(t *testing.T) {
	for _, a := range AllActions() {
		if !IsKnownAction(string(a)) {
			t.Errorf("IsKnownAction(%q) = false, want true", a)
		}
	}
	for _, bad := range []string{"", "not-a-real-action", "SCAN", "unknown"} {
		if IsKnownAction(bad) {
			t.Errorf("IsKnownAction(%q) = true, want false", bad)
		}
	}
}

// TestIsKnownActionPrefix_CodexNotifyFamily pins the dynamic-suffix
// contract for codex.notify.<sanitized-type>. The gateway's
// sanitizeNotifyType allow-list ([a-z0-9._-]{1,64}) is the source
// of truth — IsKnownActionPrefix mirrors it so audit-event
// validators stay tight even when a future codex release
// introduces a new notify type the static enum doesn't cover.
func TestIsKnownActionPrefix_CodexNotifyFamily(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    bool
		comment string
	}{
		{"happy path", "codex.notify.agent-turn-complete", true, "the canonical type today"},
		{"unknown future type", "codex.notify.tool-approved", true, "extending the suffix family is a non-breaking change"},
		{"underscore", "codex.notify.user_idle", true, "underscores are part of the allow-list"},
		{"digits", "codex.notify.v2", true, "digits permitted"},
		{"dots", "codex.notify.foo.bar", true, "intra-suffix dots permitted (sanitizeNotifyType keeps them)"},
		{"empty suffix", "codex.notify.", false, "empty suffix is treated as missing"},
		{"missing prefix", "notify.agent-turn-complete", false, "wrong prefix family"},
		{"upper-case suffix", "codex.notify.AgentTurnComplete", false, "sanitization lower-cases"},
		{"slash", "codex.notify.foo/bar", false, "slashes are stripped by sanitization"},
		{"long suffix", "codex.notify." + strings.Repeat("a", 65), false, "suffix > 64 chars exceeds bounded cardinality"},
		{"unrelated action", "scan", false, "static enum members are not part of this family"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := IsKnownActionPrefix(c.input)
			if got != c.want {
				t.Errorf("IsKnownActionPrefix(%q) = %v, want %v (%s)", c.input, got, c.want, c.comment)
			}
		})
	}
}
