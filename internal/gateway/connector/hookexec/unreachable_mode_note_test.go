// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"
	"testing"
)

// GAP-1735: a per-user call the gateway took and did not answer is blocked in
// every fail mode, so its line must not say "fail mode closed" beside a saved
// open mode; an outage the mode closed still says so.
func TestUnreachableModeNoteSaysWhyANonOutageBlocks(t *testing.T) {
	home := t.TempDir()
	for _, tc := range []struct {
		name string
		opts Options
		want string
	}{
		{"per-user call the gateway did not answer", Options{FailMode: "open", Home: home}, "not a gateway outage, so it is blocked in every fail mode"},
		{"per-user outage the mode closed", Options{perUserOutage: true, Home: home}, "fail mode closed"},
		{"strict availability", Options{StrictAvailability: true, Home: home}, "fail mode closed"},
		{"managed", Options{ManagedEnterprise: true, Home: home}, "fail mode closed"},
	} {
		if got := unreachableModeNote(tc.opts, perUserGatewayNoAnswerReason); got != tc.want {
			t.Fatalf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := perUserGatewayDownText(Options{Event: "PreToolUse", Home: home}, perUserGatewayNoAnswerReason); got == "" ||
		strings.Contains(got, "(fail mode closed)") {
		t.Fatalf("no-answer text %q names a fail mode", got)
	}
}
