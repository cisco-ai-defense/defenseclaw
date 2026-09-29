// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

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
// DefenseClaw (or are refused by machine policy); status and verify name
// them for their account and report the deployment security-incomplete, and
// verify still passes.
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
	verify.SecurityComplete = true
	applyWindowsEnterpriseUnprotectedAgents(verify)
	if len(verify.Errors) != 0 || len(verify.Warnings) != 1 ||
		verify.Warnings[0].Code != enterprisehooks.UnprotectedCodeHookContractUnverified || verify.SecurityComplete {
		t.Fatalf("verify = %+v, want a warning for the unprotected agent", verify)
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

	// Human status prints the start failure once: the summary lists it, and
	// the returned error names only its code.
	previousObserver := windowsEnterpriseStandaloneObserver
	t.Cleanup(func() { windowsEnterpriseStandaloneObserver = previousObserver })
	windowsEnterpriseStandaloneObserver = func(*enterprisestatus.Result, *windowsEnterpriseLifecycleOptions) string { return "" }
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	err := finishWindowsEnterpriseStandalone(cmd, &windowsEnterpriseLifecycleOptions{}, status, 0)
	if err == nil || strings.Count(out.String()+err.Error(), "cannot inspect configured path") != 1 {
		t.Fatalf("human status printed the start failure other than once: %q, %v", out.String(), err)
	}

	// Verify names the service whose access a managed path lost, and what
	// restores it, instead of only its service SID.
	previousServiceName := windowsEnterpriseServiceSIDName
	t.Cleanup(func() { windowsEnterpriseServiceSIDName = previousServiceName })
	windowsEnterpriseServiceSIDName = func(string) string { return "DefenseClawGateway" }
	verify := enterprisestatus.New("verify", managed.ProfileStandalone, "windows", "1.0.0")
	applyWindowsEnterpriseInstallerReport(verify, &windowsEnterpriseLifecycleOptions{}, &windowsEnterpriseInstallerReport{
		Installed: true, GatewayService: "DefenseClawGateway", GatewayServiceState: "running",
		Errors: []string{`managed path is missing required rights for S-1-5-80-1-2-3-4-5 (required=ReadAndExecute actual=0): C:\ProgramData\Cisco\DefenseClaw`},
	}, windowsEnterpriseStandaloneRun{ExitCode: 1})
	named := false
	for _, message := range verify.Errors {
		named = named || (strings.Contains(message.Message, "DefenseClawGateway service") &&
			strings.Contains(message.Message, "enterprise windows repair"))
	}
	if !named {
		t.Fatalf("verify errors = %+v, want the service named with the repair that restores it", verify.Errors)
	}
}

// Every Windows per-user row is written deferred; status counts as pending
// only the targets the guardian's last reconcile left waiting for a session.
func TestWindowsStandaloneEnrollmentCountsOnlyPendingTargets(t *testing.T) {
	previousCfg := cfg
	t.Cleanup(func() { cfg = previousCfg })
	cfg = nil
	dir := t.TempDir()
	manifest := filepath.Join(dir, "targets.yaml")
	if err := os.WriteFile(manifest, []byte("version: 1\ntargets:\n"+
		"  - {sid: S-1-5-21-1-2-3-1001, connector: codex, enabled: true, deferred: true}\n"+
		"  - {sid: S-1-5-21-1-2-3-1002, connector: codex, enabled: true, deferred: true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(enterpriseHookGuardianState{
		Version: 1, OK: true, TargetCount: 2, SuccessCount: 1, PendingCount: 1,
		Results: []enterpriseHookReconcileRow{
			{SID: "S-1-5-21-1-2-3-1001", Connector: "codex", OK: true},
			{SID: "S-1-5-21-1-2-3-1002", Connector: "codex", Pending: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hookGuardianStateFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	enrollment, err := readWindowsEnterpriseStandaloneEnrollmentAt(manifest, dir)
	if err != nil || enrollment.Targets != 2 || enrollment.Pending != 1 {
		t.Fatalf("enrollment = %+v, %v; want 2 targets, 1 pending", enrollment, err)
	}
}
