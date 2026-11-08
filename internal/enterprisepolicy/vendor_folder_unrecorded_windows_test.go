//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0930. A purge keeps a policy file another account can change
// (keepUntrustedRecordedFile) and drops the record, so the next install finds
// a vendor folder with no recorded file (E3 case b) that holds a file the
// publish can neither read nor merge into nor move aside (an administrator
// owns it). Setup's status, verify and ensure must not call that connector
// covered while machine-policy verify calls it uncovered.

const (
	// unrecordedAdminOnlyDACL is a file only SYSTEM and Administrators can
	// change: the trusted case.
	unrecordedAdminOnlyDACL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
	// unrecordedUsersModifyDACL is the file the purge leaves: Users modify.
	unrecordedUsersModifyDACL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;BU)"
)

// unrecordedCase prepares the vendor folder as the vendor or an administrator
// would, and names the unrecorded file a leftover leaves in it.
type unrecordedCase struct {
	vendorFolderCase
	leftover func(folder string) string
	content  string
}

func unrecordedCases() []unrecordedCase {
	var out []unrecordedCase
	for _, tc := range vendorFolderCases() {
		switch tc.connector {
		case ConnectorOpenCode:
			out = append(out, unrecordedCase{vendorFolderCase: tc, content: `{"$schema":"https://opencode.ai/config.json"}`,
				leftover: func(folder string) string { return filepath.Join(folder, "opencode.json") }})
		case ConnectorCopilot:
			out = append(out, unrecordedCase{vendorFolderCase: tc, content: `{"version":1,"hooks":{}}`,
				leftover: func(folder string) string { return filepath.Join(folder, "50-leftover.json") }})
		}
	}
	return out
}

// plantUnrecorded makes the vendor folder, then the leftover file with dacl.
func plantUnrecorded(t *testing.T, tc unrecordedCase, dacl string) (Options, string, string) {
	t.Helper()
	pinReclaimStandalone(t, true)
	opts := tc.options(t)
	folder := filepath.Dir(tc.file(t, opts))
	tc.prepare(t, opts, tc.file(t, opts))
	if opts.OpenCodePluginPath != "" {
		// The guardian installs the managed plugin before it reconciles
		// OpenCode; without it OpenCode is on the per-user route.
		if _, err := InstallOpenCodeManagedPlugin(opts); err != nil {
			t.Fatal(err)
		}
	}
	file := tc.leftover(folder)
	if err := os.WriteFile(file, []byte(tc.content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applySDDL(file, dacl); err != nil {
		t.Fatal(err)
	}
	return opts, folder, file
}

func fileSDDL(t *testing.T, path string) string { return folderSDDL(t, path) }

func requireUnrecordedProblem(t *testing.T, problems []VendorFolderProblem, tc unrecordedCase, folder, file string) VendorFolderProblem {
	t.Helper()
	if len(problems) != 1 {
		t.Fatalf("problems = %+v; want one for %s", problems, file)
	}
	problem := problems[0]
	if !problem.UnrecordedFile || problem.Reprotectable || problem.Connector != tc.connector || !strings.EqualFold(problem.File, file) ||
		!strings.EqualFold(problem.Dir, folder) {
		t.Fatalf("problem = %+v; want an unrecorded-file problem of %s for %s", problem, tc.connector, file)
	}
	for _, want := range []string{
		file + " is not covered", "no record of writing it", "S-1-5-32-545",
		`icacls "` + file + `" /remove:g "*S-1-5-32-545"`, "Setup", "/ensure",
	} {
		if !strings.Contains(problem.Message, want) {
			t.Fatalf("message %q lacks %q", problem.Message, want)
		}
	}
	if tc.siblings && !strings.Contains(problem.Message, "for every user") {
		t.Fatalf("message %q lacks what the vendor loads", problem.Message)
	}
	return problem
}

// The bug: a leftover file another account can change, no record. Setup's
// inspection (status, verify, ensure's gate), machine-policy verify and the
// publish all say the connector is not covered, with the file, the reason and
// the exact recovery; after the recovery all of them say covered.
func TestInspectReportsAnUnrecordedPolicyFileAnotherAccountCanChange(t *testing.T) {
	for _, tc := range unrecordedCases() {
		t.Run(tc.name, func(t *testing.T) {
			opts, folder, file := plantUnrecorded(t, tc, unrecordedUsersModifyDACL)
			beforeSDDL, beforeBytes := fileSDDL(t, file), readFile(t, file)

			problem := requireUnrecordedProblem(t, InspectRecordedVendorFolders(opts, []string{tc.request}), tc, folder, file)

			verify, _ := VerifyAll(opts, []string{tc.request})
			if state, ok := stateNamed(verify, tc.connector); !ok || state.Covered || len(state.Conflicts) == 0 || state.Conflicts[0] != problem.Message {
				t.Fatalf("verify state = %+v, %v; want %s uncovered with the inspection's message first", state, ok, tc.connector)
			}
			healed, blocked := ReprotectRecordedVendorFolders(opts, []string{tc.request})
			if len(healed) != 0 {
				t.Fatalf("the safe transaction healed %+v; it heals folders, not a file", healed)
			}
			requireUnrecordedProblem(t, blocked, tc, folder, file)
			if state, _ := publishVendorCase(t, tc.vendorFolderCase, opts); state.Covered {
				t.Fatalf("publish covered %s while the file stands: %+v", tc.connector, state)
			}
			if fileSDDL(t, file) != beforeSDDL || readFile(t, file) != beforeBytes {
				t.Fatalf("the file was changed: %s %q", fileSDDL(t, file), readFile(t, file))
			}

			// The recovery: take the entry off the file. Everything agrees.
			if err := applySDDL(file, unrecordedAdminOnlyDACL); err != nil {
				t.Fatal(err)
			}
			if problems := InspectRecordedVendorFolders(opts, []string{tc.request}); len(problems) != 0 {
				t.Fatalf("a fixed file is still reported: %+v", problems)
			}
			if state, err := publishVendorCase(t, tc.vendorFolderCase, opts); err != nil || !state.Covered {
				t.Fatalf("publish after the recovery: %+v, %v; want covered", state, err)
			}
			verify, _ = VerifyAll(opts, []string{tc.request})
			if state, ok := stateNamed(verify, tc.connector); ok && strings.Contains(strings.Join(state.Conflicts, " "), "is not covered") {
				t.Fatalf("verify still names the file: %+v", state.Conflicts)
			}
		})
	}
}

// The trusted case is as it was: an unrecorded file only administrators can
// change is used, merged into and recorded.
func TestInspectLeavesAnUnrecordedPolicyFileOnlyAdministratorsCanChange(t *testing.T) {
	for _, tc := range unrecordedCases() {
		t.Run(tc.name, func(t *testing.T) {
			opts, _, _ := plantUnrecorded(t, tc, unrecordedAdminOnlyDACL)
			if problems := InspectRecordedVendorFolders(opts, []string{tc.request}); len(problems) != 0 {
				t.Fatalf("a trusted unrecorded file is reported: %+v", problems)
			}
			if healed, blocked := ReprotectRecordedVendorFolders(opts, []string{tc.request}); len(healed) != 0 || len(blocked) != 0 {
				t.Fatalf("Setup's gate on a trusted unrecorded file: %+v %+v", healed, blocked)
			}
			if state, err := publishVendorCase(t, tc.vendorFolderCase, opts); err != nil || !state.Covered {
				t.Fatalf("publish: %+v, %v; want covered as before", state, err)
			}
		})
	}
}

// The designed case: a vendor folder with no file at all passes, and the
// first publish takes it over.
func TestInspectPassesAVendorFolderWithNoFile(t *testing.T) {
	for _, tc := range unrecordedCases() {
		t.Run(tc.name, func(t *testing.T) {
			pinReclaimStandalone(t, true)
			opts := tc.options(t)
			tc.prepare(t, opts, tc.file(t, opts))
			if err := applySDDL(filepath.Dir(tc.file(t, opts)), programDataDefaultDACL); err != nil {
				t.Fatal(err)
			}
			if problems := InspectRecordedVendorFolders(opts, []string{tc.request}); len(problems) != 0 {
				t.Fatalf("an empty vendor folder is reported: %+v", problems)
			}
			if state, err := publishVendorCase(t, tc.vendorFolderCase, opts); err != nil || !state.Covered {
				t.Fatalf("first publish: %+v, %v; want covered", state, err)
			}
		})
	}
}

// A file a standard user owns is moved aside by the publish, as before; it is
// not a problem for Setup. The inherited-defaults folder is the normal case.
func TestInspectLeavesAnUnrecordedPolicyFileAStandardUserOwns(t *testing.T) {
	for _, tc := range unrecordedCases() {
		t.Run(tc.name, func(t *testing.T) {
			opts, _, file := plantUnrecorded(t, tc, unrecordedUsersModifyDACL)
			ownAs(t, file, wellKnownSID(t, windows.WinBuiltinUsersSid))
			if problems := InspectRecordedVendorFolders(opts, []string{tc.request}); len(problems) != 0 {
				t.Fatalf("a file a standard user owns is reported: %+v", problems)
			}
			if state, err := publishVendorCase(t, tc.vendorFolderCase, opts); err != nil || !state.Covered {
				t.Fatalf("publish: %+v, %v; want the file moved aside and the connector covered", state, err)
			}
		})
	}
}

// What DefenseClaw does not publish through is not asked: OpenCode on the
// per-user route (no managed plugin), a connector whose ownership is off, and
// Secure Client (the 1.0.8 takeover).
func TestInspectAsksOnlyWhatThePublishUses(t *testing.T) {
	for _, tc := range unrecordedCases() {
		t.Run(tc.name+" off", func(t *testing.T) {
			opts, _, _ := plantUnrecorded(t, tc, unrecordedUsersModifyDACL)
			opts = withPolicy(opts, tc.connector, func(p *config.EnterpriseConnectorPolicy) { p.Ownership = config.MachinePolicyOwnershipOff })
			if problems := InspectRecordedVendorFolders(opts, []string{tc.request}); len(problems) != 0 {
				t.Fatalf("ownership off reports a file: %+v", problems)
			}
		})
		t.Run(tc.name+" secure client", func(t *testing.T) {
			opts, _, _ := plantUnrecorded(t, tc, unrecordedUsersModifyDACL)
			pinReclaimStandalone(t, false)
			if problems := InspectRecordedVendorFolders(opts, []string{tc.request}); len(problems) != 0 {
				t.Fatalf("Secure Client reports a file: %+v", problems)
			}
			if healed, blocked := ReprotectRecordedVendorFolders(opts, []string{tc.request}); len(healed) != 0 || len(blocked) != 0 {
				t.Fatalf("Secure Client gate: %+v %+v", healed, blocked)
			}
			verify, _ := VerifyAll(opts, []string{tc.request})
			if state, ok := stateNamed(verify, tc.connector); ok && strings.Contains(strings.Join(state.Conflicts, " "), "no record of writing it") {
				t.Fatalf("Secure Client verify names the file: %+v", state.Conflicts)
			}
		})
	}
	t.Run("opencode per-user route", func(t *testing.T) {
		for _, tc := range unrecordedCases() {
			if tc.connector != ConnectorOpenCode {
				continue
			}
			opts, _, _ := plantUnrecorded(t, tc, unrecordedUsersModifyDACL)
			opts.OpenCodePluginPath = ""
			if problems := InspectRecordedVendorFolders(opts, []string{tc.request}); len(problems) != 0 {
				t.Fatalf("OpenCode on the per-user route reports a file: %+v", problems)
			}
		}
	})
}

// DefenseClaw's own Copilot drop-in name is replaced by the publish whatever
// its access list says, so it is not a problem; any other *.json is.
func TestInspectDoesNotAskTheCopilotDropInNameItReplaces(t *testing.T) {
	for _, tc := range unrecordedCases() {
		if tc.connector != ConnectorCopilot {
			continue
		}
		tc.leftover = func(folder string) string { return filepath.Join(folder, DefenseClawDropInName) }
		opts, _, _ := plantUnrecorded(t, tc, unrecordedUsersModifyDACL)
		if problems := InspectRecordedVendorFolders(opts, []string{tc.request}); len(problems) != 0 {
			t.Fatalf("DefenseClaw's own drop-in name is reported: %+v", problems)
		}
		if state, err := publishVendorCase(t, tc.vendorFolderCase, opts); err != nil || !state.Covered {
			t.Fatalf("publish: %+v, %v; want the drop-in replaced and covered", state, err)
		}
	}
}

// OpenCode loads opencode.jsonc and opencode.json: each one another account
// can change is named.
func TestInspectNamesEachOpenCodeConfigAnotherAccountCanChange(t *testing.T) {
	for _, tc := range unrecordedCases() {
		if tc.connector != ConnectorOpenCode {
			continue
		}
		opts, folder, file := plantUnrecorded(t, tc, unrecordedUsersModifyDACL)
		jsonc := filepath.Join(folder, "opencode.jsonc")
		if err := os.WriteFile(jsonc, []byte(tc.content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := applySDDL(jsonc, unrecordedUsersModifyDACL); err != nil {
			t.Fatal(err)
		}
		problems := InspectRecordedVendorFolders(opts, []string{tc.request})
		if len(problems) != 2 || !strings.EqualFold(problems[0].File, jsonc) || !strings.EqualFold(problems[1].File, file) {
			t.Fatalf("problems = %+v; want opencode.jsonc then opencode.json", problems)
		}
	}
}
