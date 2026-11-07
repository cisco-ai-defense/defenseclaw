// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func vendorFolderSeams(t *testing.T, healed []enterprisepolicy.ReprotectedFolder, blocked []enterprisepolicy.VendorFolderProblem) *[]string {
	t.Helper()
	previousHeal, previousAudit, previousProblems := windowsEnterpriseVendorFolderHeal, windowsEnterpriseHookRepairedAudit, windowsEnterpriseVendorFolderProblems
	previousAlert, previousDelay := windowsEnterpriseVendorFolderAlert, windowsEnterpriseAuditRetryDelay
	t.Cleanup(func() {
		windowsEnterpriseVendorFolderHeal, windowsEnterpriseHookRepairedAudit, windowsEnterpriseVendorFolderProblems = previousHeal, previousAudit, previousProblems
		windowsEnterpriseVendorFolderAlert, windowsEnterpriseAuditRetryDelay = previousAlert, previousDelay
	})
	windowsEnterpriseVendorFolderAlert = func(string, string, map[string]any) error { return nil }
	windowsEnterpriseAuditRetryDelay = 0
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

// fakeVendorFolderRefusals is a publish error carrying vendor folder refusals.
type fakeVendorFolderRefusals []enterprisepolicy.VendorFolderRefusal

func (fakeVendorFolderRefusals) Error() string { return "vendor folder refusals" }

// guardianVendorFolderSeams records the guardian's repaired rows and alerts;
// failAlert, when set, makes the alert for that folder fail once.
func guardianVendorFolderSeams(t *testing.T) (repaired, alerts *[]string, failAlert *string) {
	t.Helper()
	previousRepaired, previousAlert, previousRefusals := enterpriseHookWindowsHookRepairedAudit, enterpriseHookWindowsVendorFolderAlert, windowsVendorFolderRefusals
	resetGuardian := func() {
		windowsGuardianVendorFolderMu.Lock()
		windowsGuardianVendorFolderRefusals = map[string]string{}
		windowsGuardianVendorFolderMu.Unlock()
	}
	resetGuardian()
	t.Cleanup(func() {
		enterpriseHookWindowsHookRepairedAudit, enterpriseHookWindowsVendorFolderAlert, windowsVendorFolderRefusals = previousRepaired, previousAlert, previousRefusals
		resetGuardian()
	})
	repaired, alerts, failAlert = &[]string{}, &[]string{}, new(string)
	enterpriseHookWindowsHookRepairedAudit = func(folder enterprisepolicy.ReprotectedFolder, actor string) error {
		*repaired = append(*repaired, actor+":"+folder.Dir)
		return nil
	}
	enterpriseHookWindowsVendorFolderAlert = func(source, summary string, details map[string]any) error {
		if *failAlert != "" && details["path"] == *failAlert {
			*failAlert = ""
			return errors.New("gateway unavailable")
		}
		*alerts = append(*alerts, source+":"+summary+":"+details["path"].(string)+":"+details["message"].(string))
		return nil
	}
	windowsVendorFolderRefusals = func(err error) []enterprisepolicy.VendorFolderRefusal {
		var fake fakeVendorFolderRefusals
		if errors.As(err, &fake) {
			return fake
		}
		return nil
	}
	return repaired, alerts, failAlert
}

// The guardian: a re-protected folder gets one HIGH repaired row and one log
// line; a refusal gets one alert (and no repaired row), written again only
// when the refusal changes.
func TestWindowsGuardianAuditsReprotectedFoldersAndRefusals(t *testing.T) {
	repairedRows, alertRows, _ := guardianVendorFolderSeams(t)
	devin := `C:\ProgramData\Devin`
	refusal := func(message string) error {
		return fakeVendorFolderRefusals{{Dir: devin, Message: message}}
	}
	var log bytes.Buffer

	published := enterprisepolicy.Result{States: []enterprisepolicy.State{{Connector: "devincascade",
		Reprotected: []enterprisepolicy.ReprotectedFolder{{Connector: "devincascade", Dir: `C:\ProgramData\Devin`, Why: "weak", Before: "b", After: "a"}}}}}
	reportWindowsGuardianVendorFolders(&log, published, nil)
	repaired, alerts := *repairedRows, *alertRows
	if len(repaired) != 1 || repaired[0] != `defenseclaw-hook-guardian:C:\ProgramData\Devin` || len(alerts) != 0 ||
		!strings.Contains(log.String(), "re-protected C:\\ProgramData\\Devin") {
		t.Fatalf("re-protect: repaired %q alerts %q log %q", repaired, alerts, log.String())
	}
	reportWindowsGuardianVendorFolders(&log, enterprisepolicy.Result{}, refusal("refusal one"))
	reportWindowsGuardianVendorFolders(&log, enterprisepolicy.Result{}, refusal("refusal one"))
	repaired, alerts = *repairedRows, *alertRows
	if len(repaired) != 1 || len(alerts) != 1 || !strings.Contains(alerts[0], "refusal one") {
		t.Fatalf("refusal: repaired %q alerts %q; want one alert, no repaired row, and not repeated", repaired, alerts)
	}
	reportWindowsGuardianVendorFolders(&log, enterprisepolicy.Result{}, refusal("refusal two"))
	if alerts = *alertRows; len(alerts) != 2 {
		t.Fatalf("a changed refusal must be reported again: %q", alerts)
	}
}

// g582 round 11 review S4: the alert is remembered per folder. A refusal that
// comes back after the folder was healed, or after a clean pass, is alerted
// again; two folders with the same text each get their alert once; an alert
// the gateway did not take is tried again at the next pass.
func TestWindowsGuardianVendorFolderAlertIsPerFolderAndComesBackAfterARecovery(t *testing.T) {
	_, alertRows, failAlert := guardianVendorFolderSeams(t)
	devin, copilot := `C:\ProgramData\Devin`, `C:\ProgramData\GitHub\Copilot\policy.d`
	var log bytes.Buffer
	pass := func(refusals ...enterprisepolicy.VendorFolderRefusal) {
		t.Helper()
		var err error
		if len(refusals) != 0 {
			err = fakeVendorFolderRefusals(refusals)
		}
		reportWindowsGuardianVendorFolders(&log, enterprisepolicy.Result{}, err)
	}
	want := func(step string, n int) {
		t.Helper()
		if len(*alertRows) != n {
			t.Fatalf("%s: alerts %q; want %d", step, *alertRows, n)
		}
	}
	pass(enterprisepolicy.VendorFolderRefusal{Dir: devin, Message: "refused"})
	want("first refusal", 1)
	pass(enterprisepolicy.VendorFolderRefusal{Dir: devin, Message: "refused"})
	want("same refusal again", 1)
	pass()
	want("clean pass", 1)
	pass(enterprisepolicy.VendorFolderRefusal{Dir: devin, Message: "refused"})
	want("refused again after the clean pass", 2)
	reportWindowsGuardianVendorFolders(&log, enterprisepolicy.Result{States: []enterprisepolicy.State{{Reprotected: []enterprisepolicy.ReprotectedFolder{{Dir: devin}}}}}, nil)
	pass(enterprisepolicy.VendorFolderRefusal{Dir: devin, Message: "refused"})
	want("refused again after the heal", 3)

	pass()
	same := "the same refusal text"
	pass(enterprisepolicy.VendorFolderRefusal{Dir: devin, Message: same}, enterprisepolicy.VendorFolderRefusal{Dir: copilot, Message: same})
	want("two folders with the same text", 5)
	if !strings.Contains((*alertRows)[3], devin) || !strings.Contains((*alertRows)[4], copilot) {
		t.Fatalf("alerts %q; want one per folder, each naming its folder", *alertRows)
	}
	pass(enterprisepolicy.VendorFolderRefusal{Dir: devin, Message: same}, enterprisepolicy.VendorFolderRefusal{Dir: copilot, Message: same})
	want("both again", 5)

	pass()
	*failAlert = copilot
	pass(enterprisepolicy.VendorFolderRefusal{Dir: copilot, Message: same})
	want("an alert the gateway did not take", 5)
	if !strings.Contains(log.String(), "could not be written") {
		t.Fatalf("log %q; want the failed alert logged", log.String())
	}
	pass(enterprisepolicy.VendorFolderRefusal{Dir: copilot, Message: same})
	want("the failed alert is tried again", 6)
}

// g582 round 11 review S6: a Setup refusal writes the same
// managed_vendor_folder_not_protected alert as the guardian pass, and a
// repaired row or an alert the gateway did not take is tried once more.
func TestWindowsEnterpriseVendorFolderGateAlertsARefusalAndRetriesItsRows(t *testing.T) {
	folder := enterprisepolicy.ReprotectedFolder{Connector: "devincascade", Dir: `C:\ProgramData\Devin`, Why: "weak", Before: "b", After: "a"}
	blocked := enterprisepolicy.VendorFolderProblem{Connector: "devincascade", Dir: folder.Dir, Message: "refused: foreign.json", Blocker: "foreign.json"}
	t.Run("refusal alert", func(t *testing.T) {
		vendorFolderSeams(t, nil, []enterprisepolicy.VendorFolderProblem{blocked})
		var alerts []map[string]any
		windowsEnterpriseVendorFolderAlert = func(source, summary string, details map[string]any) error {
			if source != "managed-vendor-folder" || summary != "managed_vendor_folder_not_protected" {
				t.Fatalf("alert %s %s", source, summary)
			}
			alerts = append(alerts, details)
			return nil
		}
		err := refuseWindowsEnterpriseUntrustedVendorFolders(standaloneVendorOpts())
		if err == nil || len(alerts) != 1 || alerts[0]["path"] != folder.Dir || alerts[0]["message"] != blocked.Message ||
			alerts[0]["connector"] != "devincascade" || alerts[0]["actor"] != "defenseclaw-setup" || alerts[0]["coverage_state"] != "incomplete" {
			t.Fatalf("err = %v, alerts = %+v; want the refusal and one alert naming the folder", err, alerts)
		}
		if strings.Contains(err.Error(), "could not be written") {
			t.Fatalf("a written alert is reported as failed: %v", err)
		}
	})
	t.Run("refusal alert not taken", func(t *testing.T) {
		vendorFolderSeams(t, nil, []enterprisepolicy.VendorFolderProblem{blocked})
		calls := 0
		windowsEnterpriseVendorFolderAlert = func(string, string, map[string]any) error {
			calls++
			return errors.New("gateway unavailable")
		}
		err := refuseWindowsEnterpriseUntrustedVendorFolders(standaloneVendorOpts())
		if calls != 2 || err == nil || !strings.HasPrefix(err.Error(), windowsEnterpriseGateRefusal) ||
			!strings.Contains(err.Error(), "the alert row could not be written: gateway unavailable") {
			t.Fatalf("calls = %d, err = %v; want one retry and the refusal saying the alert was not written", calls, err)
		}
	})
	for _, failures := range []int{1, 2} {
		t.Run("repaired row failing "+strconv.Itoa(failures)+" time(s)", func(t *testing.T) {
			vendorFolderSeams(t, []enterprisepolicy.ReprotectedFolder{folder}, nil)
			calls := 0
			windowsEnterpriseHookRepairedAudit = func(enterprisepolicy.ReprotectedFolder, string) error {
				calls++
				if calls <= failures {
					return errors.New("gateway unavailable")
				}
				return nil
			}
			opts := standaloneVendorOpts()
			if err := refuseWindowsEnterpriseUntrustedVendorFolders(opts); err != nil {
				t.Fatal(err)
			}
			lost := strings.Contains(strings.Join(opts.recoveryChanges, " "), "the audit row could not be written")
			if calls != 2 || len(opts.recoveryChanges) != 1 || lost != (failures == 2) {
				t.Fatalf("calls = %d, changes = %q; want one retry, and the change to say the row was lost only when the retry failed", calls, opts.recoveryChanges)
			}
		})
	}
	t.Run("secure client", func(t *testing.T) {
		vendorFolderSeams(t, nil, []enterprisepolicy.VendorFolderProblem{blocked})
		alerts := 0
		windowsEnterpriseVendorFolderAlert = func(string, string, map[string]any) error {
			alerts++
			return nil
		}
		opts := &windowsEnterpriseLifecycleOptions{profile: managed.ProfileSecureClient, resolvedProfile: managed.ProfileSecureClient}
		if err := refuseWindowsEnterpriseUntrustedVendorFolders(opts); err != nil || alerts != 0 {
			t.Fatalf("Secure Client: %v, %d alerts; want no gate and no alert", err, alerts)
		}
	})
}
