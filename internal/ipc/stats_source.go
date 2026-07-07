// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"github.com/defenseclaw/defenseclaw/internal/audit"
	pb "github.com/defenseclaw/defenseclaw/proto/defenseclaw/secureclient/v1"
)

// schemaVersion is the response schema version stamped on every
// snapshot / record. Bumped only on breaking payload changes; new
// fields are additive per the versioning rules in the contract.
const schemaVersion uint32 = 1

// statsSource wraps the audit store so tests can inject an in-memory
// fake. Production wiring passes *audit.Store.
type statsSource interface {
	GetCounts() (audit.Counts, error)
}

// snapshotStats reads the current aggregate counters and returns a
// StatsSnapshot with the AVC-required schema_version + availability
// fields set. On DB error the counters are zeroed and availability
// is ERROR — the consumer relies on the enum to distinguish real
// zeros from unavailability. The error is returned for structured
// logging by the caller (never propagated over the stream — the
// contract has a dedicated availability enum for that).
func snapshotStats(src statsSource) (*pb.StatsSnapshot, error) {
	c, err := src.GetCounts()
	if err != nil {
		return &pb.StatsSnapshot{
			SchemaVersion: schemaVersion,
			Availability:  pb.StatsAvailability_STATS_AVAILABILITY_ERROR,
		}, err
	}
	return &pb.StatsSnapshot{
		SchemaVersion:     schemaVersion,
		Availability:      pb.StatsAvailability_STATS_AVAILABILITY_AVAILABLE,
		TotalScans:        uint64(clampNonNeg(c.TotalScans)),
		ActiveAlerts:      uint64(clampNonNeg(c.Alerts)),
		BlockedSkills:     uint64(clampNonNeg(c.BlockedSkills)),
		AllowedSkills:     uint64(clampNonNeg(c.AllowedSkills)),
		BlockedMcpServers: uint64(clampNonNeg(c.BlockedMCPs)),
		AllowedMcpServers: uint64(clampNonNeg(c.AllowedMCPs)),
	}, nil
}

// statsChanged reports whether the counter portions of two
// StatsSnapshots differ. Availability is not compared here — the
// service layer already handles availability transitions as its own
// signal.
func statsChanged(a, b *pb.StatsSnapshot) bool {
	if a == nil || b == nil {
		return a != b
	}
	return a.TotalScans != b.TotalScans ||
		a.ActiveAlerts != b.ActiveAlerts ||
		a.BlockedSkills != b.BlockedSkills ||
		a.AllowedSkills != b.AllowedSkills ||
		a.BlockedMcpServers != b.BlockedMcpServers ||
		a.AllowedMcpServers != b.AllowedMcpServers ||
		a.Availability != b.Availability
}

// clampNonNeg guards against a negative int slipping into a uint64
// conversion (SQLite COUNT should never return negative, but the Go
// type is signed).
func clampNonNeg(n int) int {
	if n < 0 {
		return 0
	}
	return n
}
