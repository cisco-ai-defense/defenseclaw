// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	pb "github.com/defenseclaw/defenseclaw/proto/defenseclaw/secureclient/v1"
)

// u64p wraps a uint64 into a *uint64 for populating optional proto
// fields in table-driven tests. Named short because it appears at
// every counter assignment.
func u64p(v uint64) *uint64 { return &v }

// equalU64Ptr compares two *uint64 slots semantically: both nil is
// equal, one-nil-one-set is not, both-set compares values. Used only
// for readable test diagnostics — production code compares via the
// generated GetX() accessors, which fold nil into 0.
func equalU64Ptr(a, b *uint64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

type fakeStats struct {
	counts audit.Counts
	err    error
}

func (f fakeStats) GetCounts() (audit.Counts, error) { return f.counts, f.err }

func TestSnapshotStats(t *testing.T) {
	cases := []struct {
		name              string
		src               fakeStats
		wantAvail         pb.StatsAvailability
		wantScans         *uint64
		wantBlockedSkills *uint64
		wantErr           bool
	}{
		{
			name: "healthy DB → AVAILABLE with counters",
			src: fakeStats{counts: audit.Counts{
				BlockedSkills: 2, AllowedSkills: 5,
				BlockedMCPs: 1, AllowedMCPs: 3,
				Alerts: 4, TotalScans: 12,
			}},
			wantAvail:         pb.StatsAvailability_STATS_AVAILABILITY_AVAILABLE,
			wantScans:         u64p(12),
			wantBlockedSkills: u64p(2),
		},
		{
			// The error branch returns before assigning any counter
			// fields, so both KPI counters and secondary counters stay
			// nil under STATS_AVAILABILITY_ERROR. The availability enum
			// carries the "unreachable" signal; consumers should never
			// try to render counter values on an ERROR snapshot.
			name:              "DB error → ERROR with counters absent",
			src:               fakeStats{err: errors.New("db closed")},
			wantAvail:         pb.StatsAvailability_STATS_AVAILABILITY_ERROR,
			wantScans:         nil,
			wantBlockedSkills: nil,
			wantErr:           true,
		},
		{
			// TotalScans stays present (alwaysU64Ptr) with the clamped
			// value 7. BlockedSkills clamps to 0 and, because it uses
			// nonZeroU64Ptr, drops to nil.
			name: "negative counter clamped to zero → KPI still present, secondary absent",
			src: fakeStats{counts: audit.Counts{
				BlockedSkills: -3, TotalScans: 7,
			}},
			wantAvail:         pb.StatsAvailability_STATS_AVAILABILITY_AVAILABLE,
			wantScans:         u64p(7),
			wantBlockedSkills: nil,
		},
		{
			// Regression guard for the mixed presence contract on a
			// fresh install with zero scans:
			//   TotalScans, ActiveAlerts   — ALWAYS present, value 0
			//                                (KPI tiles must render "0",
			//                                 not em-dash).
			//   BlockedSkills, AllowedSkills, BlockedMcpServers,
			//   AllowedMcpServers          — nil (secondary drill-downs
			//                                stay hidden until real data).
			// A future refactor that unifies these back into a single
			// policy breaks this case.
			name:              "all zero counters → AVAILABLE with KPI counters *0 + secondaries nil",
			src:               fakeStats{counts: audit.Counts{}},
			wantAvail:         pb.StatsAvailability_STATS_AVAILABILITY_AVAILABLE,
			wantScans:         u64p(0),
			wantBlockedSkills: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := snapshotStats(tc.src)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Availability != tc.wantAvail {
				t.Errorf("availability: got %v want %v", got.Availability, tc.wantAvail)
			}
			if !equalU64Ptr(got.TotalScans, tc.wantScans) {
				t.Errorf("total scans: got %v want %v", got.TotalScans, tc.wantScans)
			}
			if !equalU64Ptr(got.BlockedSkills, tc.wantBlockedSkills) {
				t.Errorf("blocked skills: got %v want %v", got.BlockedSkills, tc.wantBlockedSkills)
			}
			if got.SchemaVersion != schemaVersion {
				t.Errorf("schema version: got %d want %d", got.SchemaVersion, schemaVersion)
			}
			// Mixed presence contract: on the AVAILABLE-with-zero-inputs
			// case, ActiveAlerts must be present at *0 (KPI tile
			// renders "0"), while the four secondary counters must be
			// nil. If any of those four regress to present-*0, the AVC
			// UI would render "0" tiles instead of the intended
			// "not yet observed" hidden/em-dash state.
			if tc.name == "all zero counters → AVAILABLE with KPI counters *0 + secondaries nil" {
				if got.ActiveAlerts == nil {
					t.Errorf("active_alerts: expected present *0, got nil")
				} else if *got.ActiveAlerts != 0 {
					t.Errorf("active_alerts: expected *0, got *%d", *got.ActiveAlerts)
				}
				if got.AllowedSkills != nil {
					t.Errorf("allowed_skills: expected nil, got %v", got.AllowedSkills)
				}
				if got.BlockedMcpServers != nil {
					t.Errorf("blocked_mcp_servers: expected nil, got %v", got.BlockedMcpServers)
				}
				if got.AllowedMcpServers != nil {
					t.Errorf("allowed_mcp_servers: expected nil, got %v", got.AllowedMcpServers)
				}
			}
		})
	}
}

func TestStatsChanged(t *testing.T) {
	base := &pb.StatsSnapshot{
		Availability:      pb.StatsAvailability_STATS_AVAILABILITY_AVAILABLE,
		TotalScans:        u64p(5),
		ActiveAlerts:      u64p(2),
		BlockedSkills:     u64p(1),
		AllowedSkills:     u64p(3),
		BlockedMcpServers: nil, // was 0; nil is the new "0"
		AllowedMcpServers: u64p(4),
	}

	cases := []struct {
		name string
		mut  func(*pb.StatsSnapshot)
		want bool
	}{
		{"identical", func(s *pb.StatsSnapshot) {}, false},
		{"total_scans differs", func(s *pb.StatsSnapshot) { s.TotalScans = u64p(6) }, true},
		{"active_alerts differs", func(s *pb.StatsSnapshot) { s.ActiveAlerts = u64p(3) }, true},
		{"blocked_skills differs", func(s *pb.StatsSnapshot) { s.BlockedSkills = u64p(2) }, true},
		{"allowed_mcp differs", func(s *pb.StatsSnapshot) { s.AllowedMcpServers = u64p(5) }, true},
		{"availability transition", func(s *pb.StatsSnapshot) {
			s.Availability = pb.StatsAvailability_STATS_AVAILABILITY_STALE
		}, true},
		// Locks in the semantic contract on the compare side: nil
		// (absent) and *0 (present-zero) must collapse to "equal".
		// If someone "improves" statsChanged to a raw pointer compare,
		// this case starts failing.
		{"absent → present-zero is not a change",
			func(s *pb.StatsSnapshot) { s.BlockedMcpServers = u64p(0) }, false},
		// Nil-ing a counter whose base value was non-zero IS a change
		// (1 → 0 in the fixture) — proves the accessor collapses nil
		// to 0, which is exactly what makes the "1 → nil" transition
		// register as a real value drop.
		{"present-nonzero → absent is a change",
			func(s *pb.StatsSnapshot) { s.BlockedSkills = nil }, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Reconstruct the base fields on a fresh proto message
			// rather than value-copying — the protobuf internal state
			// carries a sync.Mutex that vet rightly complains about.
			cur := &pb.StatsSnapshot{
				Availability:      base.Availability,
				TotalScans:        base.TotalScans,
				ActiveAlerts:      base.ActiveAlerts,
				BlockedSkills:     base.BlockedSkills,
				AllowedSkills:     base.AllowedSkills,
				BlockedMcpServers: base.BlockedMcpServers,
				AllowedMcpServers: base.AllowedMcpServers,
			}
			tc.mut(cur)
			if got := statsChanged(base, cur); got != tc.want {
				t.Errorf("statsChanged: got %v want %v", got, tc.want)
			}
		})
	}
}
