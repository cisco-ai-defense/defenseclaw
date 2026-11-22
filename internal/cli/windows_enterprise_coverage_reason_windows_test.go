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
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rel-1-0-10 GAP-0812: the managed Windows ensure in r3mgd ended with
// coverage_complete false and no reason (three failed enrollment rows). Every
// input that turns coverage_complete false on Windows must name itself, and
// the finished result (the Setup result, status and verify) must carry a
// coverage_incomplete warning that lists the reasons.
func TestWindowsCoverageIncompleteAlwaysNamesItsReason(t *testing.T) {
	healthy := windowsEnterpriseInstallerReport{OK: true, Installed: true, SecurityComplete: true, GuardianReady: true, GatewayReady: true}
	previousFolders := windowsEnterpriseVendorFolderProblems
	t.Cleanup(func() { windowsEnterpriseVendorFolderProblems = previousFolders })
	windowsEnterpriseVendorFolderProblems = func() []enterprisepolicy.VendorFolderProblem { return nil }
	type input struct {
		name   string
		report windowsEnterpriseInstallerReport
		agents []enterprisehooks.UnprotectedAgent
		err    error
		after  func(*enterprisestatus.Result)
	}
	guardianDown, pending := healthy, healthy
	guardianDown.GuardianReady = false
	pending.TransactionPending = true
	inputs := []input{
		{name: "guardian not ready", report: guardianDown},
		{name: "transaction pending", report: pending},
		{name: "unprotected record missing", report: healthy, err: os.ErrNotExist},
		{name: "unprotected record unreadable", report: healthy, err: errors.New("noncanonical owner")},
		{name: "agent without a hook contract", report: healthy, agents: []enterprisehooks.UnprotectedAgent{{
			User: "alice", SID: "S-1-5-21-1-2-3-1001", Connector: "codex", Version: "0.1.0",
			Code: enterprisehooks.UnprotectedCodeHookContractUnverified, Reason: "unsupported version"}}},
		{name: "vendor folder not held", report: healthy, after: func(*enterprisestatus.Result) {
			windowsEnterpriseVendorFolderProblems = func() []enterprisepolicy.VendorFolderProblem {
				return []enterprisepolicy.VendorFolderProblem{{Connector: "copilot", Message: "a standard account can change the folder"}}
			}
		}},
		{name: "launch coverage", report: healthy, after: func(result *enterprisestatus.Result) {
			windowsLaunchCoverageWarning(result, windowsManagedLaunchUninspected, "a running agent started without its hook")
		}},
		{name: "enrollment failed", report: healthy, after: func(result *enterprisestatus.Result) {
			result.MarkCoverageIncomplete("enrollment_failed")
		}},
	}
	for _, action := range []string{"ensure", "status", "verify"} {
		for _, in := range inputs {
			windowsEnterpriseVendorFolderProblems = func() []enterprisepolicy.VendorFolderProblem { return nil }
			stubWindowsUnprotectedAgents(t, in.agents, in.err)
			result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.10")
			report := in.report
			if in.after != nil && in.name == "vendor folder not held" {
				in.after(result)
			}
			applyWindowsEnterpriseInstallerReport(result, &windowsEnterpriseLifecycleOptions{}, &report, windowsEnterpriseStandaloneRun{})
			if in.after != nil && in.name != "vendor folder not held" {
				in.after(result)
			}
			reasons := result.CoverageReasons()
			result.Finish("windows", 0)
			named := ""
			for _, warning := range result.Warnings {
				if warning.Code == enterprisestatus.CodeCoverageIncomplete {
					named = warning.Message
				}
			}
			if result.CoverageComplete || len(reasons) == 0 || named == "" {
				t.Fatalf("%s %s: coverage_complete=%t reasons=%q coverage warning=%q warnings=%+v",
					action, in.name, result.CoverageComplete, reasons, named, result.Warnings)
			}
			for _, reason := range reasons {
				if !strings.Contains(named, reason) {
					t.Fatalf("%s %s: coverage warning %q does not name %q", action, in.name, named, reason)
				}
			}
		}
	}
}
