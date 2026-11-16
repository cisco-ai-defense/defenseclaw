// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// W2B-G-win review, loop round 2: a self-uninstall that left InstallRoot in
// place (a program held a file in it past the rename retry, so the detached
// finalizer finishes the folder and the committed cleanup, with purge the
// purge, later) is not a finished uninstall. Whatever ok the installer
// reported, the result is the retryable uninstall_in_use failure with a
// nonzero exit, and the registration an MDM detects stays. A self-uninstall
// that retired InstallRoot succeeds and says the retired copy goes once the
// CLI exits.
func TestWindowsEnterpriseSelfUninstallWithInstallRootLeftFails(t *testing.T) {
	savedGone := windowsEnterpriseInstallRootGone
	windowsEnterpriseInstallRootGone = func() bool { return false }
	t.Cleanup(func() { windowsEnterpriseInstallRootGone = savedGone })

	const base = `{"schema_version":1,"action":"uninstall","installed":false,"transaction_pending":false,` +
		`"gateway_service":"DefenseClawGateway","gateway_service_state":"missing","cached_enterprise_clients_require_reload":true,` +
		`"self_uninstall_receipt_path":"C:\\ProgramData\\Cisco\\DefenseClaw-Lifecycle\\self-uninstall-0.json",` +
		`"retired_install_root":"C:\\Program Files\\Cisco\\DefenseClaw.retired-0"`
	const deferred = `"install_root_retirement_deferred":"a program holds a file in C:\\Program Files\\Cisco\\DefenseClaw ` +
		`(The process cannot access the file because it is being used by another process.); the detached cleanup removes it"`
	const installerInUse = `uninstall_in_use: a program holds a file in C:\\Program Files\\Cisco\\DefenseClaw (held), so the ` +
		`uninstall could not remove that folder. Close the program, then run the uninstall with PURGE=1 again to confirm that it finished`

	for _, tc := range []struct {
		name   string
		report string
		purge  bool
		// wantDetail is in the uninstall_in_use message.
		wantDetail string
	}{
		{
			name: "installer reports uninstall_in_use",
			report: base + `,"ok":false,"self_uninstall_cleanup_pending":true,"canonical_install_root_absent":false,` + deferred +
				`,"errors":["` + installerInUse + `"]}`,
			purge:      true,
			wantDetail: "PURGE=1 again",
		},
		{
			name:       "ok with a deferred retirement and InstallRoot present",
			report:     base + `,"ok":true,"self_uninstall_cleanup_pending":true,"canonical_install_root_absent":false,` + deferred + `,"errors":[]}`,
			purge:      true,
			wantDetail: "being used by another process",
		},
		{
			name:       "ok with InstallRoot present and no deferral note",
			report:     base + `,"ok":true,"self_uninstall_cleanup_pending":true,"canonical_install_root_absent":false,"errors":[]}`,
			wantDetail: "run the uninstall again",
		},
		{
			name:       "ok with a deferral note and no InstallRoot field",
			report:     base + `,"ok":true,"self_uninstall_cleanup_pending":true,` + deferred + `,"errors":[]}`,
			wantDetail: "being used by another process",
		},
		{
			name:       "ok with InstallRoot present and no pending flag",
			report:     base + `,"ok":true,"canonical_install_root_absent":false,"errors":[]}`,
			wantDetail: "install folder",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, err := parseWindowsEnterpriseInstallerReport([]byte(tc.report))
			if err != nil {
				t.Fatal(err)
			}
			if report.probeFailed || windowsEnterpriseRecoveredFailedInstall(report) {
				t.Fatalf("report read as probe failure %t or recovered install", report.probeFailed)
			}
			result := enterprisestatus.New("uninstall", "standalone", "windows", "test")
			applyWindowsEnterpriseInstallerReport(result, &windowsEnterpriseLifecycleOptions{purge: tc.purge}, report, windowsEnterpriseStandaloneRun{})
			if len(result.Errors) != 1 || result.Errors[0].Code != "uninstall_in_use" ||
				!strings.Contains(result.Errors[0].Message, tc.wantDetail) {
				t.Fatalf("errors = %+v", result.Errors)
			}
			if windowsEnterpriseResultHasWarning(result, "self_uninstall_cleanup_pending") {
				t.Fatalf("a stranded self-uninstall warned as if only the retired copy were left: %+v", result.Warnings)
			}
			code := result.Finish("windows", windowsEnterpriseFailureCodeFor(result))
			if result.OK || code != enterprisestatus.WindowsExitFailure {
				t.Fatalf("a self-uninstall with InstallRoot left finished ok=%t exit %d, want a %d failure", result.OK, code, enterprisestatus.WindowsExitFailure)
			}
			if result.Installed {
				t.Fatal("the uninstall committed, so the result is not installed")
			}
			if windowsEnterprisePurgeRemovedMachineDeployment(result) {
				t.Fatal("the MDM registration would be removed while InstallRoot is left")
			}
		})
	}

	t.Run("retired InstallRoot succeeds", func(t *testing.T) {
		report, err := parseWindowsEnterpriseInstallerReport([]byte(base +
			`,"ok":true,"self_uninstall_cleanup_pending":true,"canonical_install_root_absent":true,"errors":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		result := enterprisestatus.New("uninstall", "standalone", "windows", "test")
		applyWindowsEnterpriseInstallerReport(result, &windowsEnterpriseLifecycleOptions{purge: true}, report, windowsEnterpriseStandaloneRun{})
		if len(result.Errors) != 0 {
			t.Fatalf("errors = %+v", result.Errors)
		}
		if !windowsEnterpriseResultHasWarning(result, "self_uninstall_cleanup_pending") {
			t.Fatalf("warnings = %+v", result.Warnings)
		}
		for _, warning := range result.Warnings {
			if warning.Code == "self_uninstall_cleanup_pending" && !strings.Contains(warning.Message, `C:\Program Files\Cisco\DefenseClaw.retired-0`) {
				t.Fatalf("the pending cleanup does not name the retired folder: %q", warning.Message)
			}
		}
		if code := result.Finish("windows", windowsEnterpriseFailureCodeFor(result)); !result.OK || code != 0 {
			t.Fatalf("a retired self-uninstall finished ok=%t exit %d", result.OK, code)
		}
	})

	t.Run("an uninstall that is not a self-uninstall is unchanged", func(t *testing.T) {
		report, err := parseWindowsEnterpriseInstallerReport([]byte(
			`{"schema_version":1,"ok":true,"action":"uninstall","installed":false,"transaction_pending":false,"errors":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		result := enterprisestatus.New("uninstall", "standalone", "windows", "test")
		applyWindowsEnterpriseInstallerReport(result, nil, report, windowsEnterpriseStandaloneRun{})
		if len(result.Errors) != 0 || len(result.Warnings) != 0 {
			t.Fatalf("errors %+v warnings %+v", result.Errors, result.Warnings)
		}
		if code := result.Finish("windows", windowsEnterpriseFailureCodeFor(result)); !result.OK || code != 0 {
			t.Fatalf("finished ok=%t exit %d", result.OK, code)
		}
	})
}
