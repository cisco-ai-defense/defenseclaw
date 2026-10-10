// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// These tests run as Administrator on real Windows hosts, some of them managed
// standalone deployments. Until a test stubs them itself, no deployment is
// installed and nothing reaches the machine's DefenseClaw event log or
// lifecycle log: a lifecycle test that took the host's standalone profile ran
// the real installer runner and logged failed "uninstall" events on a managed
// host (GAP-0265), and with a valid installer path it would have uninstalled it.
func init() {
	windowsEnterpriseDeploymentInspector = func(profile string) (winpath.EnterpriseDeployment, error) {
		return winpath.EnterpriseDeployment{Profile: profile, State: winpath.EnterpriseDeploymentAbsent}, nil
	}
	windowsEnterpriseStandaloneObserver = func(*enterprisestatus.Result, *windowsEnterpriseLifecycleOptions) string { return "" }
}
