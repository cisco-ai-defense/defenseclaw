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
