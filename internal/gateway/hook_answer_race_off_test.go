// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package gateway

const hookAnswerRaceBuild = false

// raceScanBudgetScale multiplies the 200 ms inspect scan deadline
// (inspectScanTimeout) of the gap0437Server tests (rel-1-0-10:GAP-1472). The
// race detector makes the scan worker about 5.6x slower (all FiveTiers rows x
// 5 packs on dc-build-2: plain p99 26 ms, max 55 ms; race p99 116-137 ms, the
// slowest row 235-282 ms per call), so the -race FiveTiers run missed the
// deadline on rows the product answers well inside it. A plain build keeps
// the production deadline (scale 1) on every row, so a slower product still
// fails there; no row is skipped under either build.
const raceScanBudgetScale = 1

// raceLargeAttachmentScale multiplies the 200 ms inspect scan deadline of
// TestFnvOpenClawLargeAttachmentStaysInTheScanBudget (GAP-0338). The race
// detector makes that request about 10x slower (the whole 4 MB / 6 MB request
// on dc-build-2: plain 0.23-0.38 s, race 2.7-3.6 s), more than
// raceScanBudgetScale covers (5/5 red under -race at 800 ms), so the race leg
// gets 10 s. A plain build keeps the production deadline (scale 1).
const raceLargeAttachmentScale = 1
