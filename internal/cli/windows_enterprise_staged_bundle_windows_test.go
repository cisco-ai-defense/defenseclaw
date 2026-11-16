// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "testing"

// A single-app first install stages the deployment with NOSTART=1 and then
// delivers its first signed bundle. The hot path needs a running gateway, so
// ensure must recognise the staged deployment and apply the bundle with the
// transaction that starts the services; any other state keeps the hot path.
func TestStagedNotStartedDeploymentTakesTheFirstBundleByTransaction(t *testing.T) {
	staged := func() *windowsEnterpriseInstallerReport {
		return &windowsEnterpriseInstallerReport{
			Installed: true, GatewayService: "DefenseClawGateway", GuardianService: "DefenseClawHookGuardian",
			ServiceStartModes: map[string]string{"DefenseClawGateway": "disabled", "DefenseClawHookGuardian": "disabled",
				"DefenseClawHookEnumerator": "disabled", "DefenseClawSensorHelper": "disabled"},
		}
	}
	if !windowsEnterpriseStagedNotStarted(staged()) {
		t.Fatal("a NOSTART=1 deployment that never started was not recognised")
	}
	for name, change := range map[string]func(*windowsEnterpriseInstallerReport){
		"running gateway":     func(r *windowsEnterpriseInstallerReport) { r.GatewayReady = true },
		"pending transaction": func(r *windowsEnterpriseInstallerReport) { r.TransactionPending = true },
		"gateway automatic":   func(r *windowsEnterpriseInstallerReport) { r.ServiceStartModes["DefenseClawGateway"] = "auto" },
		"guardian manual":     func(r *windowsEnterpriseInstallerReport) { r.ServiceStartModes["DefenseClawHookGuardian"] = "manual" },
		"no start modes":      func(r *windowsEnterpriseInstallerReport) { r.ServiceStartModes = nil },
		"not installed":       func(r *windowsEnterpriseInstallerReport) { r.Installed = false },
		"failed probe":        func(r *windowsEnterpriseInstallerReport) { r.probeFailed = true },
		"unnamed gateway":     func(r *windowsEnterpriseInstallerReport) { r.GatewayService = "" },
	} {
		report := staged()
		change(report)
		if windowsEnterpriseStagedNotStarted(report) {
			t.Errorf("%s: read as a staged deployment", name)
		}
	}
	if windowsEnterpriseStagedNotStarted(nil) {
		t.Fatal("a missing report read as a staged deployment")
	}
}
