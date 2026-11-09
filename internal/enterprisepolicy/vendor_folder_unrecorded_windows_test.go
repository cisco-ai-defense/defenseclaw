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
		file + " is not covered", "no record of writing it", "S-1-5-32-545", "Setup", "/ensure",
		// One recovery for every cause: owner, default access list, protected access list.
		`icacls '` + file + `' /setowner '*S-1-5-32-544', then icacls '` + file + `' /reset, then icacls '` + file +
			`' /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-32-545:RX'`,
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

// A file a standard user owns is moved aside by the publish, as before, so it
// blocks nothing; but until it has been, Setup says the connector is not
// covered, as machine-policy verify does (pending, named). Under verify_only
// nothing ever moves it, so it is a plain problem with the recovery.
func TestInspectNamesAnUnrecordedPolicyFileAStandardUserOwnsAsPending(t *testing.T) {
	for _, tc := range unrecordedCases() {
		t.Run(tc.name, func(t *testing.T) {
			opts, folder, file := plantUnrecorded(t, tc, unrecordedUsersModifyDACL)
			ownAs(t, file, wellKnownSID(t, windows.WinBuiltinUsersSid))

			problems := InspectRecordedVendorFolders(opts, []string{tc.request})
			if len(problems) != 1 || !problems[0].UnrecordedFile || !problems[0].PendingMoveAside || !strings.EqualFold(problems[0].File, file) ||
				!strings.Contains(problems[0].Message, "not covered yet") || !strings.Contains(problems[0].Message, "moves such a file aside") {
				t.Fatalf("problems = %+v; want %s pending its move aside", problems, file)
			}
			verify, _ := VerifyAll(opts, []string{tc.request})
			if state, ok := stateNamed(verify, tc.connector); !ok || state.Covered || len(state.Conflicts) == 0 || state.Conflicts[0] != problems[0].Message {
				t.Fatalf("verify state = %+v, %v; want uncovered with the same message first", state, ok)
			}
			if healed, blocked := ReprotectRecordedVendorFolders(opts, []string{tc.request}); len(healed) != 0 || len(blocked) != 0 {
				t.Fatalf("a pending file blocks the gate: %+v %+v", healed, blocked)
			}
			if state, err := publishVendorCase(t, tc.vendorFolderCase, opts); err != nil || !state.Covered {
				t.Fatalf("publish: %+v, %v; want the file moved aside and the connector covered", state, err)
			}
			if problems := InspectRecordedVendorFolders(opts, []string{tc.request}); len(problems) != 0 {
				t.Fatalf("after the move aside: %+v", problems)
			}
			verify, _ = VerifyAll(opts, []string{tc.request})
			if state, ok := stateNamed(verify, tc.connector); ok && strings.Contains(strings.Join(state.Conflicts, " "), "not covered") {
				t.Fatalf("verify still names the file: %+v", state.Conflicts)
			}
			_ = folder
		})
		t.Run(tc.name+" verify_only", func(t *testing.T) {
			opts, _, file := plantUnrecorded(t, tc, unrecordedUsersModifyDACL)
			ownAs(t, file, wellKnownSID(t, windows.WinBuiltinUsersSid))
			opts = withPolicy(opts, tc.connector, func(p *config.EnterpriseConnectorPolicy) { p.Ownership = config.MachinePolicyOwnershipVerifyOnly })
			problems := InspectRecordedVendorFolders(opts, []string{tc.request})
			if len(problems) != 1 || problems[0].PendingMoveAside || !strings.Contains(problems[0].Message, "verify_only") ||
				!strings.Contains(problems[0].Message, "/setowner") {
				t.Fatalf("problems = %+v; want a plain problem with the recovery under verify_only", problems)
			}
			if _, blocked := ReprotectRecordedVendorFolders(opts, []string{tc.request}); len(blocked) != 1 {
				t.Fatalf("blocked = %+v; want the gate to name it", blocked)
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
			if problems := MachinePolicyProblems(opts, []string{tc.request}); len(problems) != 0 {
				t.Fatalf("Secure Client: Setup's machine policy problems = %+v", problems)
			}
			if problems := UnrecordedPolicyFileProblems(opts, []string{tc.request}); len(problems) != 0 {
				t.Fatalf("Secure Client: the guardian's unrecorded files = %+v", problems)
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

// A link or other entry that is not a regular file, which an administrator
// owns, is a problem the publish fails on (it removes only a standard user's):
// reported with the move-aside recovery, not skipped.
func TestInspectReportsAnUnrecordedLinkAnAdministratorOwns(t *testing.T) {
	for _, tc := range unrecordedCases() {
		t.Run(tc.name, func(t *testing.T) {
			opts, folder, file := plantUnrecorded(t, tc, unrecordedAdminOnlyDACL)
			target := filepath.Join(t.TempDir(), "elsewhere.json")
			if err := os.WriteFile(target, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(file); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, file); err != nil {
				t.Skipf("creating a symbolic link needs the privilege: %v", err)
			}
			// An administrator's link: the owner is the Administrators group
			// whoever ran the test (a runner account owns what it creates).
			ownAs(t, file, wellKnownSID(t, windows.WinBuiltinAdministratorsSid))
			problems := InspectRecordedVendorFolders(opts, []string{tc.request})
			if len(problems) != 1 || !problems[0].UnrecordedFile || problems[0].PendingMoveAside || !strings.EqualFold(problems[0].File, file) ||
				!strings.EqualFold(problems[0].Dir, folder) || !strings.Contains(problems[0].Message, "not a regular file") ||
				!strings.Contains(problems[0].Message, `Rename-Item -LiteralPath '`+file+`' -NewName '`+filepath.Base(file)+`.moved-aside'`) {
				t.Fatalf("problems = %+v; want the link named with the move-aside recovery", problems)
			}
		})
	}
}

// Machine-policy verify and Setup are fed by one function: another conflict
// the target raises (an administrator's sibling that is not valid JSON) shows
// in Setup's problems too, and a healthy folder shows none.
func TestMachinePolicyProblemsCarryEveryMachinePolicyConflict(t *testing.T) {
	for _, tc := range unrecordedCases() {
		if tc.connector != ConnectorCopilot {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			opts, folder, file := plantUnrecorded(t, tc, unrecordedAdminOnlyDACL)
			if err := os.WriteFile(file, []byte("{not json"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := applySDDL(file, unrecordedAdminOnlyDACL); err != nil {
				t.Fatal(err)
			}
			if state, err := publishVendorCase(t, tc.vendorFolderCase, opts); err != nil || state.Covered {
				t.Fatalf("publish beside an invalid sibling: %+v, %v; want not covered (verify says so)", state, err)
			}
			verify, _ := VerifyAll(opts, []string{tc.request})
			state, ok := stateNamed(verify, tc.connector)
			if !ok || state.Covered || len(state.Conflicts) == 0 {
				t.Fatalf("verify state = %+v, %v; want a conflict", state, ok)
			}
			problems := MachinePolicyProblems(opts, []string{tc.request})
			found := false
			for _, problem := range problems {
				if problem.Conflict && problem.Connector == tc.connector && strings.Contains(problem.Message, "not valid JSON") && strings.Contains(problem.Message, file) {
					found = true
				}
			}
			if !found {
				t.Fatalf("problems = %+v; want the conflict machine-policy verify raises (%q)", problems, state.Conflicts)
			}
			if err := os.Remove(file); err != nil {
				t.Fatal(err)
			}
			_ = folder
			// The host may lack the hook executable; only the sibling matters here.
			for _, problem := range MachinePolicyProblems(opts, []string{tc.request}) {
				if strings.Contains(problem.Message, "not valid JSON") || strings.Contains(problem.Message, file) {
					t.Fatalf("the removed sibling is still reported: %+v", problem)
				}
			}
		})
	}
}

// Copilot's own conflict about the same file is replaced by the new message,
// not listed beside it.
func TestVerifyListsAnUnrecordedCopilotFileOnce(t *testing.T) {
	for _, tc := range unrecordedCases() {
		if tc.connector != ConnectorCopilot {
			continue
		}
		opts, _, file := plantUnrecorded(t, tc, unrecordedUsersModifyDACL)
		// The publish writes the drop-in; the leftover stays.
		_, _ = publishVendorCase(t, tc.vendorFolderCase, opts)
		verify, _ := VerifyAll(opts, []string{tc.request})
		state, _ := stateNamed(verify, tc.connector)
		count := 0
		for _, conflict := range state.Conflicts {
			if strings.Contains(strings.ToLower(conflict), strings.ToLower(file)) {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("conflicts = %q; want the file named once", state.Conflicts)
		}
	}
}

// A weak recorded folder's own message names the foreign file it holds; the
// file is not listed a second time as an unrecorded file (whoever owns it).
func TestInspectDoesNotListTheForeignFileOfAFolderAlreadyReportedWeak(t *testing.T) {
	for _, tc := range vendorFolderCases() {
		if !tc.siblings {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			opts, file, folder := publishedWeakCase(t, tc, vendorFolderAddOnlyDACL)
			foreign := filepath.Join(folder, "foreign.json")
			if tc.connector == ConnectorOpenCode {
				foreign = filepath.Join(folder, "opencode.jsonc")
			}
			if err := os.WriteFile(foreign, []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
			ownAs(t, foreign, wellKnownSID(t, windows.WinBuiltinUsersSid))
			_ = file
			problems := InspectRecordedVendorFolders(opts, []string{tc.request})
			if len(problems) != 1 || problems[0].UnrecordedFile || !strings.EqualFold(problems[0].Dir, folder) {
				t.Fatalf("problems = %+v; want only the weak folder", problems)
			}
			if _, blocked := ReprotectRecordedVendorFolders(opts, []string{tc.request}); len(blocked) != 1 || blocked[0].UnrecordedFile {
				t.Fatalf("blocked = %+v; want only the weak folder", blocked)
			}
		})
	}
}

// D1: the recovery is for an elevated PowerShell prompt, so a path with a $,
// a backtick or a quote cannot expand or end its literal early.
func TestUnrecordedFileFixQuotesEveryPathAsAPowerShellLiteral(t *testing.T) {
	path := "C:\\ProgramData\\opencode\\it's $env:TEMP `x`.json"
	fix := unrecordedFileFix(path, true)
	quoted := "'C:\\ProgramData\\opencode\\it''s $env:TEMP `x`.json'"
	if strings.Count(fix, quoted) != 3 || strings.Contains(fix, `"`) {
		t.Fatalf("fix = %s; want the path as the single-quoted literal %s three times and no double quote", fix, quoted)
	}
	rename := unrecordedFileFix(path, false)
	if !strings.HasPrefix(rename, "Rename-Item -LiteralPath "+quoted+" -NewName ") || strings.Contains(rename, "Move-Item") {
		t.Fatalf("rename = %s; want Rename-Item (it fails when the name exists, Move-Item would move into a planted folder)", rename)
	}
}

// The property the lead asked for: for every connector on the machine policy
// route, if machine-policy verify says uncovered for any reason, Setup's
// problems name that connector; where it says covered, they name nothing for
// it. Checked unpublished, after the Go-owned publish, and with a conflict an
// administrator's sibling adds.
func TestMachinePolicyProblemsNameEveryConnectorMachinePolicyVerifyCallsUncovered(t *testing.T) {
	pinReclaimStandalone(t, true)
	opts := windowsOpenCodeTestOptions(t)
	opts.CopilotCLIPolicyOnly = true
	all := []string{ConnectorCodex, ConnectorClaudeCode, ConnectorCursor, ConnectorCopilot, ConnectorOpenCode}
	check := func(step string) map[string]bool {
		t.Helper()
		verify, err := VerifyAll(opts, all)
		problems := MachinePolicyProblems(opts, all)
		named := map[string]bool{}
		for _, problem := range problems {
			named[problem.Connector] = true
		}
		uncovered := 0
		for _, state := range verify.States {
			if state.Route != RouteMachinePolicy {
				continue
			}
			if !state.Covered {
				uncovered++
				if !named[state.Connector] {
					t.Fatalf("%s: machine-policy verify calls %s uncovered (%+v) but Setup names nothing for it: %+v", step, state.Connector, state, problems)
				}
			} else if named[state.Connector] {
				t.Fatalf("%s: %s is covered but Setup names a problem: %+v", step, state.Connector, problems)
			}
		}
		if (err != nil || uncovered > 0) && len(problems) == 0 {
			t.Fatalf("%s: machine-policy verify is not complete (err %v, %d uncovered) and Setup has no problem", step, err, uncovered)
		}
		return named
	}
	// OpenCode is on the per-user route until its managed plugin is installed,
	// so machine-policy verify does not call it uncovered yet.
	if named := check("nothing published"); !named[ConnectorCopilot] || !named[ConnectorCodex] || !named[ConnectorClaudeCode] || !named[ConnectorCursor] {
		t.Fatalf("nothing published: Copilot, Codex, Claude Code and Cursor must be named: %v", named)
	}
	if _, err := PublishWindowsGoOwned(opts, []string{ConnectorCopilot, ConnectorOpenCode}); err != nil {
		t.Logf("publish: %v", err)
	}
	check("after the Go-owned publish")
	folder, err := CopilotPolicyDir(opts)
	if err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(folder, "70-bad.json")
	if err := os.WriteFile(sibling, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applySDDL(sibling, unrecordedAdminOnlyDACL); err != nil {
		t.Fatal(err)
	}
	if named := check("an invalid administrator sibling"); !named[ConnectorCopilot] {
		t.Fatalf("an invalid sibling must be named for Copilot: %v", named)
	}
}
