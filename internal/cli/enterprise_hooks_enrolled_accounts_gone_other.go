// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

// enterpriseHookEnrolledAccountGone: off Windows a removed row is an account
// the guardian confirmed gone, as before (GAP-2133 changes only Windows).
func enterpriseHookEnrolledAccountGone(enterpriseHookReconcileRow) bool {
	return true
}
