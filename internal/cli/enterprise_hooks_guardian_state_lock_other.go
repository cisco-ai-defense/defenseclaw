//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

// lockEnterpriseHookGuardianState takes no lock here. The release protection
// record that two interleaved writers could split from its ledger is kept
// only on Windows (GAP-1885), and the standalone Unix guardian already holds
// reconcile.lock for its whole pass (lockEnterpriseHookReconcile): a flock
// taken again on a new descriptor in the same process would wait on itself.
func lockEnterpriseHookGuardianState(string) (func(), error) {
	return func() {}, nil
}
