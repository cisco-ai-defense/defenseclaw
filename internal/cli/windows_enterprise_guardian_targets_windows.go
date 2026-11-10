//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// windowsEnterpriseGuardianStateForStatus reads the standalone guardian's
// last pass; tests replace it.
var windowsEnterpriseGuardianStateForStatus = func() (enterpriseHookGuardianState, bool, error) {
	layout, err := windowsManagedLayout.standalone()
	if err != nil {
		return enterpriseHookGuardianState{}, false, err
	}
	return loadEnterpriseHookGuardianState(layout.DataDir)
}

// windowsEnterpriseInstalledConfigForStatus reads the deployment's
// installed config; tests replace it.
var windowsEnterpriseInstalledConfigForStatus = func() (*config.Config, error) {
	return loadWindowsEnterpriseStandaloneConfig("")
}

// applyWindowsEnterpriseGuardianTargets applies the guardian's last pass and
// the targets' hook files to status and verify (GAP-0146).
func applyWindowsEnterpriseGuardianTargets(result *enterprisestatus.Result) {
	applyWindowsEnterpriseGuardianTargetsFrom(result, windowsEnterpriseGuardianStateForStatus, windowsEnterpriseInstalledConfigForStatus)
	applyWindowsEnterpriseGuardianStateHold(result)
}
