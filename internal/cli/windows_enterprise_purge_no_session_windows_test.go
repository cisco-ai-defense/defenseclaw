//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-2231: a LocalSystem PURGE=1 with an enrolled account signed out or
// disconnected cannot act as that account, so its agent registrations stay
// and its DefenseClaw folder is kept for their connector_backups. That is the
// documented Windows limit, not a failed purge: it finished 1603 and the
// message blamed an open file. It now warns, names the kept folder and the
// next step, and exits 0. A purge that did not run as LocalSystem, or a
// removal that failed, still fails.
func TestWindowsEnterprisePurgeWithAccountsWithoutASessionFinishesWithWarnings(t *testing.T) {
	const base = `{"schema_version":1,"ok":true,"action":"Uninstall","installed":false,"transaction_pending":false`
	const kept = "kept: the account's agent registrations were not all removed, and its connector_backups restore them"
	sid := "S-1-5-21-1000000000-2000000000-3000000000-1018"
	apply := func(line string) *enterprisestatus.Result {
		t.Helper()
		report, err := parseWindowsEnterpriseInstallerReport([]byte(line))
		if err != nil {
			t.Fatalf("parse %s: %v", line, err)
		}
		result := enterprisestatus.New("uninstall", "standalone", "windows", "test")
		applyWindowsEnterpriseInstallerReport(result, &windowsEnterpriseLifecycleOptions{purge: true}, report, windowsEnterpriseStandaloneRun{})
		return result
	}
	keptEntry := `"user_state_remaining":["` + sid + `: C:\\Users\\dan\\.defenseclaw: ` + kept + `"]`

	signedOut := apply(base + `,"user_registrations_pending":["copilot/` + sid + `","hermes/` + sid + `"],"user_registrations_failed":[],` + keptEntry + `}`)
	codes := map[string]string{}
	for _, warning := range signedOut.Warnings {
		codes[warning.Code] = warning.Message
	}
	if len(signedOut.Errors) != 0 || codes["user_registrations_pending"] == "" || codes["per_user_state_remaining"] == "" {
		t.Fatalf("signed-out purge: errors %+v warnings %+v", signedOut.Errors, signedOut.Warnings)
	}
	state := codes["per_user_state_remaining"]
	if strings.Contains(state, "holds a file") ||
		!strings.Contains(state, `kept the DefenseClaw folder %USERPROFILE%\.defenseclaw of 1 enrolled account(s) whose agent registrations stay`) ||
		!strings.Contains(state, "/uninstall PURGE=1, both as LocalSystem") ||
		!strings.HasSuffix(state, `Accounts: `+sid+`: C:\Users\dan\.defenseclaw`) {
		t.Fatalf("kept-folder warning = %q", state)
	}
	if code := signedOut.Finish("windows", windowsEnterpriseFailureCodeFor(signedOut)); !signedOut.OK || code != 0 {
		t.Fatalf("signed-out purge finished ok=%t exit %d", signedOut.OK, code)
	}

	// Not LocalSystem: nothing was removed for anyone, the purge fails.
	notSystem := apply(base + `,"user_registrations_pending":["copilot/` + sid + `"],` +
		`"user_registrations_failed":["per-user registrations were not removed: requires the LocalSystem guardian service"]}`)
	if len(notSystem.Errors) != 1 || notSystem.Errors[0].Code != "user_registrations_pending" {
		t.Fatalf("not-LocalSystem purge errors = %+v", notSystem.Errors)
	}

	// A removal that failed still fails the purge; the kept folder stays a
	// warning next to it.
	failed := apply(base + `,"user_registrations_failed":["kiro/` + sid + `: C:\\Users\\dan\\.kiro\\hooks\\defenseclaw.json still holds DefenseClaw's hook"],` + keptEntry + `}`)
	if len(failed.Errors) != 1 || failed.Errors[0].Code != "user_registrations_failed" {
		t.Fatalf("failed-removal purge: errors %+v warnings %+v", failed.Errors, failed.Warnings)
	}
	if code := failed.Finish("windows", windowsEnterpriseFailureCodeFor(failed)); failed.OK || code == 0 {
		t.Fatalf("failed-removal purge finished ok=%t exit %d", failed.OK, code)
	}
}
