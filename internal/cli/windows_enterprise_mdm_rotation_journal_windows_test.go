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

// GAP-1913: an uninstall that kept the MDM kit credential rotation journal
// (plain uninstall) or left it (a purge that found a folder in it) names it in
// the JSON result with the next step, and still succeeds; an uninstall that
// removed it, and any other action, says nothing.
func TestWindowsEnterpriseUninstallNamesAKeptMdmRotationJournal(t *testing.T) {
	const base = `{"schema_version":1,"action":"uninstall","installed":false,"transaction_pending":false,"ok":true,"errors":[]`
	const kept = `kept the MDM kit credential rotation journal C:\\ProgramData\\Cisco\\DefenseClaw-MDM\\rotation ` +
		`(it can hold a copy of an earlier credential); run the uninstall with PURGE=1 to remove it`
	const left = `left the MDM kit credential rotation journal C:\\ProgramData\\Cisco\\DefenseClaw-MDM\\rotation as it is: ` +
		`it holds foreign, which the MDM kit does not write; check it and remove it by hand`
	for _, tc := range []struct {
		name, action, report, want string
		purge                      bool
	}{
		{name: "plain uninstall keeps it", action: "uninstall", report: base + `,"mdm_rotation_journal_kept":"` + kept + `"}`, want: "PURGE=1"},
		{name: "purge leaves a journal with a folder", action: "uninstall", purge: true, report: base + `,"mdm_rotation_journal_kept":"` + left + `"}`, want: "holds foreign"},
		{name: "purge removed it", action: "uninstall", purge: true, report: base + `}`},
		{name: "not an uninstall", action: "repair", report: `{"schema_version":1,"action":"repair","installed":true,"ok":true,"errors":[],"mdm_rotation_journal_kept":"x"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, err := parseWindowsEnterpriseInstallerReport([]byte(tc.report))
			if err != nil {
				t.Fatal(err)
			}
			result := enterprisestatus.New(tc.action, "standalone", "windows", "test")
			addWindowsEnterpriseMdmRotationJournalKept(result, report)
			var got string
			for _, w := range result.Warnings {
				if w.Code == "mdm_rotation_journal_kept" {
					got = w.Message
				}
			}
			if tc.want == "" {
				if got != "" {
					t.Fatalf("unexpected mdm_rotation_journal_kept warning %q", got)
				}
				return
			}
			if !strings.Contains(got, `DefenseClaw-MDM\rotation`) || !strings.Contains(got, tc.want) {
				t.Fatalf("warnings = %+v, want mdm_rotation_journal_kept naming the journal and %q", result.Warnings, tc.want)
			}
			if len(result.Errors) != 0 {
				t.Fatalf("a kept journal is a warning, not an error: %+v", result.Errors)
			}
		})
	}
}
