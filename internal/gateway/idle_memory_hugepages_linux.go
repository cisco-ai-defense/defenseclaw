// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import "golang.org/x/sys/unix"

// disableTransparentHugePages keeps khugepaged from refilling the memory the
// idle release returns (rel-1-0-3 GAP-0244). RHEL ships transparent huge
// pages "always" with khugepaged max_ptes_none 511: khugepaged turns any 2 MB
// range of the gateway heap (and of SQLite page cache) that still has one
// resident page back into a whole huge page, so the pages debug.FreeOSMemory
// had returned came back resident minutes later. On a managed RHEL 9.8
// gateway the resident size fell from 309 MB to 217 MB after a flood and
// climbed back to 311 MB between +321 s and +421 s of idle, with no calls,
// audit rows or log lines. The setting is per process and kept by the
// processes the gateway starts.
func disableTransparentHugePages() error {
	return unix.Prctl(unix.PR_SET_THP_DISABLE, 1, 0, 0, 0)
}
