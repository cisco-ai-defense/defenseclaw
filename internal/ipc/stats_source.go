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
	// Counter-presence policy under proto3 `optional`:
	//
	//   TotalScans, ActiveAlerts — ALWAYS present, even at zero.
	//   AVC's UI treats these as the two primary KPI tiles and needs to
	//   render "0" on a fresh install; leaving them absent would force
	//   an em-dash / hidden state that miscommunicates "unsupported"
	//   for a counter that is actually zero. Use alwaysU64Ptr.
	//
	//   BlockedSkills, AllowedSkills, BlockedMcpServers, AllowedMcpServers
	//   — omitted when zero (nonZeroU64Ptr). These feed secondary
	//   drill-down views where "absent" is a useful signal ("this
	//   endpoint hasn't observed any skill / MCP activity yet"). Absent
	//   also lets AVC hide the corresponding tile until real data lands.
	//
	// See the doc comment on StatsSnapshot in secureclient.proto for
	// the wire contract this policy composes with.
	return &pb.StatsSnapshot{
		SchemaVersion:     schemaVersion,
		Availability:      pb.StatsAvailability_STATS_AVAILABILITY_AVAILABLE,
		TotalScans:        alwaysU64Ptr(c.TotalScans),
		ActiveAlerts:      alwaysU64Ptr(c.Alerts),
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
// is present on the wire. Used for the secondary counters
// (blocked/allowed skills + MCP servers) where consumers benefit
// from an explicit "not yet observed" absent state.
func nonZeroU64Ptr(n int) *uint64 {
	v := clampNonNeg(n)
	if v == 0 {
		return nil
	}
	u := uint64(v)
	return &u
}

// alwaysU64Ptr clamps a signed count to non-negative and returns a
// pointer that is ALWAYS present, even at zero. Used for TotalScans
// and ActiveAlerts, which back AVC's primary KPI tiles — those tiles
// must render "0" on a fresh install rather than the em-dash /
// hidden state that absent implies. Every other counter should use
// nonZeroU64Ptr instead.
func alwaysU64Ptr(n int) *uint64 {
	u := uint64(clampNonNeg(n))
	return &u
}
