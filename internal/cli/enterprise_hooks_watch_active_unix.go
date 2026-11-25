//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

// targetKey names the protected target of an account's connector for the
// standalone Unix guardian's workers and user cleanup, the only callers.
func (w *enterpriseHookWatchActiveWorkers) targetKey(home, user, connector string) string {
	if key := w.targetKeys[enterpriseHookWatchTargetID(home, connector)]; key != "" {
		return key
	}
	return enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: user, UserHome: home, Connector: connector})
}
