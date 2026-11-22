// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rel-1-0-10 GAP-0802: after the managed 1.0.9 to 1.0.10 Setup /ensure the
// bounded home scan of two enrolled accounts did not finish, and the Setup
// result and status called claudecode, codex, copilot and opencode of those
// accounts not protected (coverage_complete false), while the machine-wide
// managed hook fired for them. With the hook verified for the account
// (enrollment state enrolled) a scan gap is an agent_install_scan_partial
// warning that names the folder; the Setup result (ensure) and status and
// verify agree. A copy the scan found outside the hook contract, and a gap
// of an account whose hook is not verified, stay not protected.
func TestWindowsInstallScanGapOfAVerifiedAccountKeepsCoverage(t *testing.T) {
	const alice, bob = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	folder := `C:\Users\alice\AppData\Local\huge`
	gap := func(user, sid, connector string) enterprisehooks.UnprotectedAgent {
		return enterprisehooks.UnprotectedAgent{User: user, SID: sid, Connector: connector,
			Code: enterprisehooks.UnprotectedCodeInstallScanIncomplete, Skipped: enterprisehooks.PrivateInstallSkippedHome, Folder: folder,
			Reason: "the bounded scan of this account private agent installs was incomplete; use application control to exclude unapproved agent binaries"}
	}
	connectors := []string{"claudecode", "codex", "copilot", "opencode"}
	var aliceGaps []enterprisehooks.UnprotectedAgent
	for _, connector := range connectors {
		aliceGaps = append(aliceGaps, gap("alice", alice, connector))
	}
	accounts := []enterprisestatus.EnrollmentAccount{
		{Account: `C:\Users\alice`, SID: strings.ToLower(alice), Connectors: map[string]string{
			"claudecode": "enrolled", "codex": "enrolled", "copilot": "enrolled", "opencode": "enrolled", "hermes": "enrolled"}},
		{Account: `C:\Users\bob`, SID: bob, Connectors: map[string]string{
			"claudecode": "pending", "codex": "pending", "copilot": "pending", "opencode": "pending"}},
	}
	run := func(action string) *enterprisestatus.Result {
		result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.10")
		result.CoverageComplete, result.SecurityComplete = true, true
		result.Enrollment.Accounts = accounts
		applyWindowsEnterpriseUnprotectedAgents(result)
		return result
	}
	count := func(result *enterprisestatus.Result, code string) int {
		n := 0
		for _, warning := range result.Warnings {
			if warning.Code == code {
				n++
			}
		}
		return n
	}

	// (1) and (4): verified managed hooks, scan gaps: the Setup result
	// (ensure), status and verify all report coverage complete.
	stubWindowsUnprotectedAgents(t, aliceGaps, nil)
	for _, action := range []string{"ensure", "status", "verify"} {
		result := run(action)
		if !result.CoverageComplete || !result.SecurityComplete || len(result.Errors) != 0 ||
			count(result, enterprisehooks.UnprotectedCodeInstallScanPartial) != len(connectors) ||
			count(result, enterprisehooks.UnprotectedCodeInstallScanIncomplete) != 0 {
			t.Fatalf("%s: verified hooks with scan gaps = coverage %t security %t warnings %+v errors %+v",
				action, result.CoverageComplete, result.SecurityComplete, result.Warnings, result.Errors)
		}
		for _, warning := range result.Warnings {
			if !strings.Contains(warning.Message, folder) || strings.Contains(warning.Message, "not protected") {
				t.Fatalf("%s: partial scan warning = %q", action, warning.Message)
			}
		}
	}

	// (2) A copy the scan found outside the hook contract: not protected.
	found := enterprisehooks.UnprotectedAgent{User: "alice", SID: alice, Connector: "claudecode", Version: "1.0.0",
		Code: enterprisehooks.UnprotectedCodeHookContractUnverified, Reason: "unsupported version"}
	stubWindowsUnprotectedAgents(t, append(append([]enterprisehooks.UnprotectedAgent{}, aliceGaps...), found), nil)
	for _, action := range []string{"ensure", "status", "verify"} {
		if result := run(action); result.CoverageComplete || count(result, enterprisehooks.UnprotectedCodeHookContractUnverified) != 1 {
			t.Fatalf("%s: a found copy outside the contract = coverage %t warnings %+v", action, result.CoverageComplete, result.Warnings)
		}
	}

	// (3) An account whose hook is not verified (pending) keeps its gap
	// blocking, on every action alike.
	stubWindowsUnprotectedAgents(t, append(append([]enterprisehooks.UnprotectedAgent{}, aliceGaps...), gap("bob", bob, "claudecode")), nil)
	for _, action := range []string{"ensure", "status", "verify"} {
		result := run(action)
		incomplete := ""
		for _, warning := range result.Warnings {
			if warning.Code == enterprisehooks.UnprotectedCodeInstallScanIncomplete {
				incomplete += warning.Message
			}
		}
		if result.CoverageComplete || !strings.Contains(incomplete, "claudecode for user bob ("+bob+") is not protected") ||
			!strings.Contains(incomplete, folder) || count(result, enterprisehooks.UnprotectedCodeInstallScanPartial) != len(connectors) {
			t.Fatalf("%s: unverified hook with a scan gap = coverage %t warnings %+v", action, result.CoverageComplete, result.Warnings)
		}
	}
}
