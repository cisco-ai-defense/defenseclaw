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
// StatsSnapshot with the schema_version + availability fields set.
// On DB error the counters are zeroed and availability is ERROR —
// the consumer relies on the enum to distinguish real zeros from
// unavailability. The error is returned alongside the snapshot so
// callers can log it locally; it is never propagated over the
// stream because the wire contract has a dedicated availability
// enum for that.
func snapshotStats(src statsSource) (*pb.StatsSnapshot, error) {
	c, err := src.GetCounts()
	if err != nil {
		return &pb.StatsSnapshot{
			SchemaVersion: schemaVersion,
			Availability:  pb.StatsAvailability_STATS_AVAILABILITY_ERROR,
		}, err
	}
	// Only set a counter when it's strictly positive. A zero-valued
	// counter is left as nil (absent on the wire) — proto3 `optional`
	// lets us distinguish "supported and zero" from "not supported /
	// unavailable" without a schema bump. See the doc comment on
	// StatsSnapshot in secureclient.proto for the semantic contract.
	return &pb.StatsSnapshot{
		SchemaVersion:     schemaVersion,
		Availability:      pb.StatsAvailability_STATS_AVAILABILITY_AVAILABLE,
		TotalScans:        nonZeroU64Ptr(c.TotalScans),
		ActiveAlerts:      nonZeroU64Ptr(c.Alerts),
		BlockedSkills:     nonZeroU64Ptr(c.BlockedSkills),
		AllowedSkills:     nonZeroU64Ptr(c.AllowedSkills),
		BlockedMcpServers: nonZeroU64Ptr(c.BlockedMCPs),
		AllowedMcpServers: nonZeroU64Ptr(c.AllowedMCPs),
	}, nil
}

// statsChanged reports whether two StatsSnapshots differ across any
// field the consumer cares about — counter values AND availability.
// The availability comparison matters because a database going down
// on a fresh install produces zero counters in both the AVAILABLE
// and ERROR snapshots; only the enum transition tells the consumer
// "we lost our stats source" and it must be surfaced as an update.
//
// GetX() returns 0 for both nil and *x=0, so absent-vs-present-zero
// collapses to "equal" — the intended semantics under the new proto3
// `optional` contract (presence signals supported/unsupported, value
// signals the count; the availability enum signals reachability). Do
// NOT switch to raw pointer comparison; a nil ↔ *0 flip is not a
// change from the consumer's perspective.
func statsChanged(a, b *pb.StatsSnapshot) bool {
	if a == nil || b == nil {
		return a != b
	}
	return a.GetTotalScans() != b.GetTotalScans() ||
		a.GetActiveAlerts() != b.GetActiveAlerts() ||
		a.GetBlockedSkills() != b.GetBlockedSkills() ||
		a.GetAllowedSkills() != b.GetAllowedSkills() ||
		a.GetBlockedMcpServers() != b.GetBlockedMcpServers() ||
		a.GetAllowedMcpServers() != b.GetAllowedMcpServers() ||
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

// nonZeroU64Ptr clamps a signed count to non-negative and returns a
// pointer only when the result is strictly positive. Nil signals
// "counter absent" on the wire (proto3 optional); a positive value
// is present on the wire. Present-zero is reserved for a future
// consumer contract where 0 must be distinguishable from missing —
// today's server always omits zeros so absent means "no data yet or
// counter unsupported".
func nonZeroU64Ptr(n int) *uint64 {
	v := clampNonNeg(n)
	if v == 0 {
		return nil
	}
	u := uint64(v)
	return &u
}
