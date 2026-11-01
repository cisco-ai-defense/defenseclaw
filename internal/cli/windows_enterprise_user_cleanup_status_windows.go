//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// windowsEnterpriseUserCleanupFailureMin is how many failed guardian passes
// make a per-user cleanup worth a status warning: one failure is usually a
// file an agent holds for a moment.
const windowsEnterpriseUserCleanupFailureMin = 3

// windowsEnterpriseUserCleanupsForStatus reads the guardian's per-user
// cleanup ledger; tests replace it.
var windowsEnterpriseUserCleanupsForStatus = func() ([]enterpriseHookUserCleanup, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return nil, err
	}
	return loadEnterpriseHookUserCleanups(layout.DataDir)
}

// applyWindowsEnterpriseUserCleanupFailures warns in status and verify about
// each per-user cleanup (DefenseClaw's registration of a connector the
// account is no longer enrolled for) the guardian failed to finish on
// several passes. It retried such a cleanup forever, with the reason only in
// its log, while status said nothing (GAP-2380). A cleanup that waits for a
// signed-out account is not a failure and is not named here.
func applyWindowsEnterpriseUserCleanupFailures(result *enterprisestatus.Result) {
	pending, err := windowsEnterpriseUserCleanupsForStatus()
	if err != nil {
		return
	}
	var failing []string
	for _, entry := range pending {
		if entry.Attempts < windowsEnterpriseUserCleanupFailureMin || strings.TrimSpace(entry.LastError) == "" {
			continue
		}
		failing = append(failing, fmt.Sprintf("%s for %s (%d passes): %s",
			strings.ToLower(strings.TrimSpace(entry.Connector)), strings.TrimSpace(entry.UserHome), entry.Attempts,
			windowsEnterpriseBoundedDiagnostic(entry.LastError)))
	}
	if len(failing) == 0 {
		return
	}
	result.AddWarning("user_cleanup_failing", fmt.Sprintf(
		"the hook guardian could not remove DefenseClaw's registration of %d connector(s) an account is no longer enrolled for, and retries it on every pass: %s. "+
			"The registration stays in that account's agent configuration until it is removed. Fix what the reason names, then run %s",
		len(failing), windowsEnterpriseBoundedLabels(failing), windowsEnterpriseAdminCommand("repair")))
}
