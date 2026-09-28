// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func stubWindowsUnprotectedAgents(t *testing.T, agents []enterprisehooks.UnprotectedAgent, err error) {
	t.Helper()
	previous := windowsEnterpriseUnprotectedAgentsReader
	t.Cleanup(func() { windowsEnterpriseUnprotectedAgentsReader = previous })
	windowsEnterpriseUnprotectedAgentsReader = func() ([]enterprisehooks.UnprotectedAgent, error) { return agents, err }
}

// Agents the enumerator found installed but could not enroll run without
// DefenseClaw (or are refused by machine policy); status names them and
// reports the deployment security-incomplete, and verify fails.
func TestWindowsStandaloneStatusAndVerifyReportUnprotectedAgents(t *testing.T) {
	stubWindowsUnprotectedAgents(t, []enterprisehooks.UnprotectedAgent{{
		User: "alice", SID: "S-1-5-21-1-2-3-1001", Connector: "cursor", Version: "4.1.0",
		Code:   enterprisehooks.UnprotectedCodeHookContractUnverified,
		Reason: "version 4.1.0 is not verified against a known hook contract; its machine-policy hooks refuse this user's tool calls until it is enrolled",
	}}, nil)
	status := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.0")
	applyWindowsEnterpriseInstallerReport(status, &windowsEnterpriseLifecycleOptions{}, &windowsEnterpriseInstallerReport{
		OK: true, Installed: true, SecurityComplete: true, GuardianReady: true, GatewayReady: true,
	}, windowsEnterpriseStandaloneRun{})
	if status.SecurityComplete {
		t.Fatal("status reports security_complete with an unprotected agent")
	}
	found := false
	for _, warning := range status.Warnings {
		found = found || (warning.Code == enterprisehooks.UnprotectedCodeHookContractUnverified &&
			strings.Contains(warning.Message, "cursor 4.1.0 for user alice (S-1-5-21-1-2-3-1001) is not protected"))
	}
	if !found || len(status.Errors) != 0 {
		t.Fatalf("status warnings %+v errors %+v", status.Warnings, status.Errors)
	}

	verify := enterprisestatus.New("verify", managed.ProfileStandalone, "windows", "1.0.0")
	applyWindowsEnterpriseUnprotectedAgents(verify)
	if len(verify.Errors) != 1 || verify.Errors[0].Code != enterprisehooks.UnprotectedCodeHookContractUnverified {
		t.Fatalf("verify errors = %+v, want the unprotected agent", verify.Errors)
	}

	// No record, or a record this token cannot read, reports nothing.
	for _, err := range []error{os.ErrNotExist, os.ErrPermission} {
		stubWindowsUnprotectedAgents(t, nil, err)
		quiet := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.0")
		quiet.SecurityComplete = true
		applyWindowsEnterpriseUnprotectedAgents(quiet)
		if !quiet.SecurityComplete || len(quiet.Warnings) != 0 {
			t.Fatalf("%v: %+v", err, quiet)
		}
	}
	// A record that is present but untrusted or malformed is itself a gap.
	stubWindowsUnprotectedAgents(t, nil, errors.New("noncanonical owner"))
	broken := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.0")
	broken.SecurityComplete = true
	applyWindowsEnterpriseUnprotectedAgents(broken)
	if broken.SecurityComplete || len(broken.Warnings) != 1 || !strings.Contains(broken.Warnings[0].Message, "record is unreadable") {
		t.Fatalf("broken record: %+v", broken)
	}
}

// Status names why an installed gateway is not running, from the last error
// it logged, and reports the rows DefenseClaw keeps for a deleted account
// whose profile folder is still there.
func TestWindowsStandaloneStatusNamesGatewayStartFailureAndDeletedAccount(t *testing.T) {
	stubWindowsUnprotectedAgents(t, nil, os.ErrNotExist)
	previousFailure, previousAccounts, previousDeleted, previousFolder := windowsEnterpriseGatewayStartFailure, windowsEnterpriseManifestAccounts, windowsEnterpriseAccountDeleted, windowsEnterpriseAccountCreatedDataDir
	t.Cleanup(func() {
		windowsEnterpriseGatewayStartFailure, windowsEnterpriseManifestAccounts, windowsEnterpriseAccountDeleted, windowsEnterpriseAccountCreatedDataDir = previousFailure, previousAccounts, previousDeleted, previousFolder
	})
	windowsEnterpriseAccountCreatedDataDir = func(string, string) bool { return false }
	windowsEnterpriseGatewayStartFailure = func() (string, string) {
		return `failed to load config: observability.local.path: cannot inspect configured path C:\ProgramData\Cisco\DefenseClaw\runtime\audit.db: Access is denied.`,
			`C:\ProgramData\Cisco\DefenseClaw\logs\gateway\gateway.log`
	}
	home := t.TempDir()
	windowsEnterpriseManifestAccounts = func() ([]windowsEnterpriseManifestAccount, error) {
		return []windowsEnterpriseManifestAccount{
			{User: "alice", SID: "S-1-5-21-1-2-3-1001", Home: home, Rows: 2},
			{User: "bob", SID: "S-1-5-21-1-2-3-1002", Home: home, Rows: 1},
		}, nil
	}
	windowsEnterpriseAccountDeleted = func(sid string) bool { return sid == "S-1-5-21-1-2-3-1001" }
	status := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.0")
	applyWindowsEnterpriseInstallerReport(status, &windowsEnterpriseLifecycleOptions{}, &windowsEnterpriseInstallerReport{
		Installed: true, GatewayService: "DefenseClawGateway", GatewayServiceState: "stopped",
	}, windowsEnterpriseStandaloneRun{ExitCode: 1})
	if len(status.Errors) != 1 || status.Errors[0].Code != "gateway_start_failed" ||
		!strings.Contains(status.Errors[0].Message, "cannot inspect configured path") ||
		!strings.Contains(status.Errors[0].Message, "enterprise windows repair") {
		t.Fatalf("errors = %+v, want the gateway's start failure named", status.Errors)
	}
	deleted := 0
	for _, warning := range status.Warnings {
		if warning.Code == "deleted_account_rows" {
			deleted++
			if !strings.Contains(warning.Message, "alice (S-1-5-21-1-2-3-1001)") || !strings.Contains(warning.Message, "2 enrollment row(s)") {
				t.Fatalf("deleted account warning %q", warning.Message)
			}
		}
	}
	if deleted != 1 {
		t.Fatalf("warnings = %+v, want one deleted-account warning", status.Warnings)
	}
	// An unresolvable SID outside this computer's accounts (a domain account
	// whose directory may be unreachable) is never reported deleted.
	if previousDeleted("S-1-5-21-1-2-3-1001") {
		t.Fatal("a non-local SID whose lookup failed was reported deleted")
	}
}
