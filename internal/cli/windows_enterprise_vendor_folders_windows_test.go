// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func vendorFolderSeams(t *testing.T, healed []enterprisepolicy.ReprotectedFolder, blocked []enterprisepolicy.VendorFolderProblem) *[]string {
	t.Helper()
	previousHeal, previousAudit, previousProblems := windowsEnterpriseVendorFolderHeal, windowsEnterpriseHookRepairedAudit, windowsEnterpriseVendorFolderProblems
	t.Cleanup(func() {
		windowsEnterpriseVendorFolderHeal, windowsEnterpriseHookRepairedAudit, windowsEnterpriseVendorFolderProblems = previousHeal, previousAudit, previousProblems
	})
	var audited []string
	windowsEnterpriseVendorFolderHeal = func() ([]enterprisepolicy.ReprotectedFolder, []enterprisepolicy.VendorFolderProblem) {
		return healed, blocked
	}
	windowsEnterpriseHookRepairedAudit = func(folder enterprisepolicy.ReprotectedFolder, actor string) error {
		audited = append(audited, actor+":"+folder.Connector+":"+folder.Dir)
		return nil
	}
	windowsEnterpriseVendorFolderProblems = func() []enterprisepolicy.VendorFolderProblem {
		return append([]enterprisepolicy.VendorFolderProblem(nil), blocked...)
	}
	return &audited
}

func standaloneVendorOpts() *windowsEnterpriseLifecycleOptions {
	return &windowsEnterpriseLifecycleOptions{profile: managed.ProfileStandalone, resolvedProfile: managed.ProfileStandalone}
}

// GAP-0756, GAP-0760: a vendor folder DefenseClaw can prove clean is
// re-protected before the install-like action, reported in the changes and
// audited once; one it cannot prove is refused by name before anything
// changes, with the gate's wording; Secure Client does neither.
func TestWindowsEnterpriseVendorFolderGateReprotectsOrRefuses(t *testing.T) {
	folder := enterprisepolicy.ReprotectedFolder{Connector: "devincascade", Dir: `C:\ProgramData\Devin`, File: `C:\ProgramData\Devin\hooks.json`,
		Why: `C:\ProgramData\Devin lets an account other than SYSTEM delete or replace DefenseClaw's file`, Before: "weak", After: "protected"}
	t.Run("healed", func(t *testing.T) {
		audited := vendorFolderSeams(t, []enterprisepolicy.ReprotectedFolder{folder}, nil)
		opts := standaloneVendorOpts()
		if err := refuseWindowsEnterpriseUntrustedVendorFolders(opts); err != nil {
			t.Fatalf("a folder that was put right refused the action: %v", err)
		}
		if len(opts.recoveryChanges) != 1 || !strings.Contains(opts.recoveryChanges[0], "re-protected "+folder.Dir) {
			t.Fatalf("changes = %q; want one line naming %s", opts.recoveryChanges, folder.Dir)
		}
		if len(*audited) != 1 || (*audited)[0] != "defenseclaw-setup:devincascade:"+folder.Dir {
			t.Fatalf("audit rows = %q; want exactly one repaired row from Setup", *audited)
		}
	})
	t.Run("refused", func(t *testing.T) {
		blocked := enterprisepolicy.VendorFolderProblem{Connector: "devincascade", Dir: folder.Dir,
			Message: folder.Dir + ` lets an account other than SYSTEM delete or replace DefenseClaw's file; it holds foreign.json. icacls "` + folder.Dir + `" /setowner "*S-1-5-32-544"`,
			Blocker: "foreign.json"}
		audited := vendorFolderSeams(t, nil, []enterprisepolicy.VendorFolderProblem{blocked})
		opts := standaloneVendorOpts()
		err := refuseWindowsEnterpriseUntrustedVendorFolders(opts)
		if err == nil || !strings.HasPrefix(err.Error(), windowsEnterpriseGateRefusal) || !strings.Contains(err.Error(), folder.Dir) ||
			!strings.Contains(err.Error(), "foreign.json") || !strings.Contains(err.Error(), "icacls") {
			t.Fatalf("err = %v; want the gate refusal naming the folder, what blocks it and the fix", err)
		}
		if len(opts.recoveryChanges) != 0 || len(*audited) != 0 {
			t.Fatalf("a refusal changed or audited something as repaired: %q %q", opts.recoveryChanges, *audited)
		}
	})
	t.Run("secure client", func(t *testing.T) {
		audited := vendorFolderSeams(t, []enterprisepolicy.ReprotectedFolder{folder},
			[]enterprisepolicy.VendorFolderProblem{{Connector: "devincascade", Dir: folder.Dir, Message: "m"}})
		opts := &windowsEnterpriseLifecycleOptions{profile: managed.ProfileSecureClient, resolvedProfile: managed.ProfileSecureClient}
		if err := refuseWindowsEnterpriseUntrustedVendorFolders(opts); err != nil || len(opts.recoveryChanges) != 0 || len(*audited) != 0 {
			t.Fatalf("Secure Client: %v %q %q; want no gate", err, opts.recoveryChanges, *audited)
		}
	})
}

// Verify fails and status warns while a folder does not protect the file, and
// coverage and security are incomplete either way.
func TestWindowsEnterpriseVendorFoldersAreReportedByVerifyAndStatus(t *testing.T) {
	problem := enterprisepolicy.VendorFolderProblem{Connector: "copilot", Dir: `C:\ProgramData\GitHub\Copilot\policy.d`, Message: `policy.d lets users add files`, Reprotectable: true}
	vendorFolderSeams(t, nil, []enterprisepolicy.VendorFolderProblem{problem})
	for _, action := range []string{"verify", "status", "ensure"} {
		result := &enterprisestatus.Result{Action: action, CoverageComplete: true, SecurityComplete: true}
		applyWindowsEnterpriseVendorFolders(result)
		wantErrors := 0
		if action == "verify" {
			wantErrors = 1
		}
		if len(result.Errors) != wantErrors || result.CoverageComplete || result.SecurityComplete ||
			!windowsEnterpriseResultHasMessage(result, windowsEnterpriseVendorFolderCode, "copilot: policy.d lets users add files") {
			t.Fatalf("%s: errors %v warnings %v coverage %v security %v", action, result.Errors, result.Warnings, result.CoverageComplete, result.SecurityComplete)
		}
	}
	vendorFolderSeams(t, nil, nil)
	result := &enterprisestatus.Result{Action: "verify", CoverageComplete: true, SecurityComplete: true}
	applyWindowsEnterpriseVendorFolders(result)
	if len(result.Errors) != 0 || len(result.Warnings) != 0 || !result.CoverageComplete {
		t.Fatalf("a protected host is reported: %+v", result)
	}
}

func windowsEnterpriseResultHasMessage(result *enterprisestatus.Result, code, message string) bool {
	for _, list := range [][]enterprisestatus.Message{result.Errors, result.Warnings} {
		for _, entry := range list {
			if entry.Code == code && entry.Message == message {
				return true
			}
		}
	}
	return false
}

// The guardian: a re-protected folder gets one HIGH repaired row and one log
// line; a refusal gets one alert (and no repaired row), written again only
// when the refusal changes.
func TestWindowsGuardianAuditsReprotectedFoldersAndRefusals(t *testing.T) {
	previousRepaired, previousAlert, previousRefusal := enterpriseHookWindowsHookRepairedAudit, enterpriseHookWindowsVendorFolderAlert, windowsIsVendorFolderRefusal
	t.Cleanup(func() {
		enterpriseHookWindowsHookRepairedAudit, enterpriseHookWindowsVendorFolderAlert, windowsIsVendorFolderRefusal = previousRepaired, previousAlert, previousRefusal
		windowsGuardianVendorFolderMu.Lock()
		windowsGuardianVendorFolderRefusals = map[string]string{}
		windowsGuardianVendorFolderMu.Unlock()
	})
	var repaired, alerts []string
	enterpriseHookWindowsHookRepairedAudit = func(folder enterprisepolicy.ReprotectedFolder, actor string) error {
		repaired = append(repaired, actor+":"+folder.Dir)
		return nil
	}
	enterpriseHookWindowsVendorFolderAlert = func(source, summary string, details map[string]any) error {
		alerts = append(alerts, source+":"+summary+":"+details["message"].(string))
		return nil
	}
	windowsIsVendorFolderRefusal = func(error) bool { return true }
	var log bytes.Buffer

	published := enterprisepolicy.Result{States: []enterprisepolicy.State{{Connector: "devincascade",
		Reprotected: []enterprisepolicy.ReprotectedFolder{{Connector: "devincascade", Dir: `C:\ProgramData\Devin`, Why: "weak", Before: "b", After: "a"}}}}}
	reportWindowsGuardianVendorFolders(&log, published, nil)
	if len(repaired) != 1 || repaired[0] != `defenseclaw-hook-guardian:C:\ProgramData\Devin` || len(alerts) != 0 ||
		!strings.Contains(log.String(), "re-protected C:\\ProgramData\\Devin") {
		t.Fatalf("re-protect: repaired %q alerts %q log %q", repaired, alerts, log.String())
	}
	reportWindowsGuardianVendorFolders(&log, enterprisepolicy.Result{}, errors.New("devincascade: refusal one"))
	reportWindowsGuardianVendorFolders(&log, enterprisepolicy.Result{}, errors.New("devincascade: refusal one"))
	if len(repaired) != 1 || len(alerts) != 1 || !strings.Contains(alerts[0], "refusal one") {
		t.Fatalf("refusal: repaired %q alerts %q; want one alert, no repaired row, and not repeated", repaired, alerts)
	}
	reportWindowsGuardianVendorFolders(&log, enterprisepolicy.Result{}, errors.New("devincascade: refusal two"))
	if len(alerts) != 2 {
		t.Fatalf("a changed refusal must be reported again: %q", alerts)
	}
}
