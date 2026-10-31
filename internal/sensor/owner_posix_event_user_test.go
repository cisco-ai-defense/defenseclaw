// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"testing"
	"time"
)

// p0-round GAP-1389: a managed Linux session that exited before the poll and
// wrote no configuration file the sensor saw (a terminal session that only
// ran and ended) was unattributed, although its creation event named the
// account that ran it. The creation event's name is the last source, after
// the enrolled profile, and never covers a descendant (a setuid child) or
// two accounts.
func TestAnExitedPOSIXSessionIsAttributedToTheAccountItsCreationEventNamed(t *testing.T) {
	previous := ownerGOOS
	t.Cleanup(func() { ownerGOOS = previous })
	resolver := &ownerResolver{book: newOwnerBook(OwnerLookups{}, time.Hour), accounts: []Account{
		{Name: "dcr-rv15m1", Home: "/home/dcr-rv15m1"},
	}}
	root := procRef{PID: 4100, Name: "claude", User: "dcr-rv15m1"}
	child := procRef{PID: 4101, Name: "bash", User: "root", Descendant: true}
	for _, tc := range []struct {
		name        string
		goos        string
		processes   []procRef
		paths       []string
		user        string
		attribution string
	}{
		{"root named by its event", "linux", []procRef{root, child}, nil, "dcr-rv15m1", AttributionProcessOwner},
		{"macOS too", "darwin", []procRef{root}, nil, "dcr-rv15m1", AttributionProcessOwner},
		{"the enrolled profile still comes first", "linux", []procRef{root}, []string{"/home/dcr-rv15m1/.claude/settings.json"}, "dcr-rv15m1", AttributionEnrolledProfile},
		{"a descendant alone names nothing", "linux", []procRef{{PID: 1, Name: "claude"}, child}, nil, "", AttributionUnattributed},
		{"two accounts name none", "linux", []procRef{root, {PID: 4102, Name: "claude", User: "other"}}, nil, "", AttributionUnattributed},
		{"no name in the event", "linux", []procRef{{PID: 4100, Name: "claude"}}, nil, "", AttributionUnattributed},
		{"Windows needs a SID", "windows", []procRef{root}, nil, "", AttributionUnattributed},
	} {
		ownerGOOS = tc.goos
		got := resolver.resolve(tc.processes, tc.paths)
		if got.User != tc.user || got.Attribution != tc.attribution || got.SID != "" {
			t.Fatalf("%s: got %+v, want user %q attribution %s", tc.name, got, tc.user, tc.attribution)
		}
	}
}
