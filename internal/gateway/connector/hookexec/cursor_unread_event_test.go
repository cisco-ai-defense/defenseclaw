// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"
	"testing"
)

func TestCursorUnreadEventBlockExitsTwoAndAllowStaysAllowed(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		event          string
		wantExit       int
		wantOutput     string
	}{
		{name: "gateway block", event: "someUnknownEvent", response: `{"action":"block","reason":"policy"}`, wantExit: blockExit, wantOutput: "{}"},
		{name: "unregistered casing", event: "PreToolUse", response: `{"action":"block","reason":"policy"}`, wantExit: blockExit, wantOutput: cursorActionOutput("PreToolUse", "block", "policy")},
		{name: "gateway allow", event: "someUnknownEvent", response: `{"action":"allow"}`, wantExit: 0, wantOutput: "{}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := run(t, "cursor", ok(tc.response), func(opts *Options) { opts.Event = tc.event })
			if result.code != tc.wantExit || strings.TrimSpace(result.stdout) != tc.wantOutput {
				t.Fatalf("code=%d stdout=%q, want code=%d stdout=%q", result.code, result.stdout, tc.wantExit, tc.wantOutput)
			}
		})
	}
}

func TestCursorUnreadEventClosedFailureExitsTwo(t *testing.T) {
	result := run(t, "cursor", &stubRT{status: 500}, func(opts *Options) {
		opts.Event = "someUnknownEvent"
		opts.FailMode = "closed"
	})
	if result.code != blockExit || strings.TrimSpace(result.stdout) != "{}" {
		t.Fatalf("code=%d stdout=%q, want code=%d stdout={}", result.code, result.stdout, blockExit)
	}
}

func TestCursorUnreadEventSecureClientExitUnchanged(t *testing.T) {
	opts := Options{Event: "someUnknownEvent", SecureClient: true}
	if got := cursorClosedExit(opts, 0); got != 0 {
		t.Fatalf("Secure Client exit=%d, want 0", got)
	}
}
