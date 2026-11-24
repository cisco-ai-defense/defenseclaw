// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

// enterpriseHookEnrolledAccountGone reports whether a removed guardian row
// also takes its account out of the enrolled-accounts record. On Windows a
// row is removed for a deleted local account and for a removed profile
// (GAP-0430, GAP-1657), but only the first one is gone for good: an
// FSLogix-style profile disk that is detached, with its local profile
// cleaned up, reads as a removed profile while its domain account still
// exists and signs in again. That account stays enrolled, so a per-user
// DefenseClaw entry planted for its next sign-in is tamper, not a first
// adoption (GAP-2133).
func enterpriseHookEnrolledAccountGone(row enterpriseHookReconcileRow) bool {
	return windowsEnterpriseAccountDeleted(row.SID)
}
