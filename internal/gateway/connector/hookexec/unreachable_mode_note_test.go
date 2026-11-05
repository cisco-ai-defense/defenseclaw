// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"
	"testing"
)

// A verified no-status deadline follows the per-user mode; an unverified
// listener remains closed independently of that mode.
func TestUnreachableModeNoteSaysWhyANonOutageBlocks(t *testing.T) {
	home := t.TempDir()
	for _, tc := range []struct {
		name string
		opts Options
		want string
	}{
		{"per-user call the gateway did not answer", Options{FailMode: "closed", perUserOutage: true, Home: home}, "fail mode closed"},
		{"per-user outage the mode closed", Options{perUserOutage: true, Home: home}, "fail mode closed"},
		{"strict availability", Options{StrictAvailability: true, Home: home}, "fail mode closed"},
		{"managed", Options{ManagedEnterprise: true, Home: home}, "fail mode closed"},
	} {
		if got := unreachableModeNote(tc.opts, perUserGatewayNoAnswerReason); got != tc.want {
			t.Fatalf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := perUserGatewayDownText(Options{Event: "PreToolUse", Home: home}, perUserGatewayNoAnswerReason); got == "" ||
		!strings.Contains(got, "(fail mode closed)") {
		t.Fatalf("no-answer block %q does not name the closed mode", got)
	}
}
