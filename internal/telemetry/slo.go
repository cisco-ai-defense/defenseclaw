// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// SLO histogram helpers (Track 7):
//   - RecordSLOBlockLatency — admission path, target <2000ms
//   - RecordSLOTUIRefresh — TUI panels, target <5000ms
// Both use explicit ms buckets: 50, 100, 250, 500, 1000, 2000, 5000, 10000.
//
// Implementations are on Provider in metrics.go (defenseclaw.slo.block.latency,
// defenseclaw.slo.tui.refresh).

package telemetry
