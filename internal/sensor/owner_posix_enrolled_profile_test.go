// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"testing"
	"time"
)

// p0-round GAP-1389: on managed Linux a Claude Code session that wrote only
// its own ~/.claude/settings.json and exited before the poll was reported
// unattributed: the enrolled-account table had no Linux entries, and an
// account without a SID was never an enrolled profile. A POSIX account is
// identified by its name; paths compare exactly, and paths in two homes
// still name no account.
func TestAnExitedPOSIXSessionIsAttributedToTheEnrolledProfileItWrote(t *testing.T) {
	resolver := &ownerResolver{book: newOwnerBook(OwnerLookups{}, time.Hour), accounts: []Account{
		{Name: "dcr-rv15m1", Home: "/home/dcr-rv15m1"},
		{Name: "ann", Home: "/home/ann"},
		{Name: "Ann", Home: "/home/Ann"},
		{Name: "mac1", Home: "/Users/mac1/"},
	}}
	for _, tc := range []struct {
		name        string
		paths       []string
		user        string
		attribution string
	}{
		{"one enrolled home", []string{"/home/dcr-rv15m1/.claude/settings.json"}, "dcr-rv15m1", AttributionEnrolledProfile},
		{"macOS home", []string{"/Users/mac1/.codex/config.toml"}, "mac1", AttributionEnrolledProfile},
		{"case is another account", []string{"/home/Ann/.claude/settings.json"}, "Ann", AttributionEnrolledProfile},
		{"a name prefix is not the home", []string{"/home/dcr-rv15m1x/.claude/settings.json"}, "", AttributionUnattributed},
		{"two homes", []string{"/home/ann/.claude/settings.json", "/home/Ann/.claude/settings.json"}, "", AttributionUnattributed},
		{"outside every home", []string{"/srv/project/AGENTS.md"}, "", AttributionUnattributed},
	} {
		got := resolver.resolve(nil, tc.paths)
		if got.User != tc.user || got.Attribution != tc.attribution || got.SID != "" {
			t.Fatalf("%s: got %+v, want user %q attribution %s", tc.name, got, tc.user, tc.attribution)
		}
	}
}
