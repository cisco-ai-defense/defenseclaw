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

type fakeStats struct {
	counts audit.Counts
	err    error
}

func (f fakeStats) GetCounts() (audit.Counts, error) { return f.counts, f.err }

func TestSnapshotStats(t *testing.T) {
	cases := []struct {
		name      string
		src       fakeStats
		wantAvail pb.StatsAvailability
		wantScans uint64
		wantErr   bool
	}{
		{
			name: "healthy DB → AVAILABLE with counters",
			src: fakeStats{counts: audit.Counts{
				BlockedSkills: 2, AllowedSkills: 5,
				BlockedMCPs: 1, AllowedMCPs: 3,
				Alerts: 4, TotalScans: 12,
			}},
			wantAvail: pb.StatsAvailability_STATS_AVAILABILITY_AVAILABLE,
			wantScans: 12,
		},
		{
			name:      "DB error → ERROR with zero counters",
			src:       fakeStats{err: errors.New("db closed")},
			wantAvail: pb.StatsAvailability_STATS_AVAILABILITY_ERROR,
			wantScans: 0,
			wantErr:   true,
		},
		{
			name: "negative counter clamped to zero (defensive)",
			src: fakeStats{counts: audit.Counts{
				BlockedSkills: -3, TotalScans: 7,
			}},
			wantAvail: pb.StatsAvailability_STATS_AVAILABILITY_AVAILABLE,
			wantScans: 7,
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
			if got.TotalScans != tc.wantScans {
				t.Errorf("total scans: got %d want %d", got.TotalScans, tc.wantScans)
			}
			if got.SchemaVersion != schemaVersion {
				t.Errorf("schema version: got %d want %d", got.SchemaVersion, schemaVersion)
			}
		})
	}
}

func TestStatsChanged(t *testing.T) {
	base := &pb.StatsSnapshot{
		Availability:      pb.StatsAvailability_STATS_AVAILABILITY_AVAILABLE,
		TotalScans:        5,
		ActiveAlerts:      2,
		BlockedSkills:     1,
		AllowedSkills:     3,
		BlockedMcpServers: 0,
		AllowedMcpServers: 4,
	}

	cases := []struct {
		name string
		mut  func(*pb.StatsSnapshot)
		want bool
	}{
		{"identical", func(s *pb.StatsSnapshot) {}, false},
		{"total_scans differs", func(s *pb.StatsSnapshot) { s.TotalScans = 6 }, true},
		{"active_alerts differs", func(s *pb.StatsSnapshot) { s.ActiveAlerts = 3 }, true},
		{"blocked_skills differs", func(s *pb.StatsSnapshot) { s.BlockedSkills = 2 }, true},
		{"allowed_mcp differs", func(s *pb.StatsSnapshot) { s.AllowedMcpServers = 5 }, true},
		{"availability transition", func(s *pb.StatsSnapshot) {
			s.Availability = pb.StatsAvailability_STATS_AVAILABILITY_STALE
		}, true},
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
