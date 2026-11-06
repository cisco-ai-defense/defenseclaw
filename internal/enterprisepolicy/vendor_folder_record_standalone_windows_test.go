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
)

// Vendor folder descriptors for the g582 review 6 M2 and review 7 M1/S1 rows
// (GAP-0652 E3).
const (
	// vendorFolderAddOnlyDACL lets standard users add files and folders but
	// not delete, rename or replace an existing entry.
	vendorFolderAddOnlyDACL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200af;;;BU)"
	// vendorFolderReplaceableDACL lets standard users delete any entry of
	// the folder (full control on the folder itself, not inherited, so the
	// entries keep the SYSTEM and Administrators entries they inherit).
	vendorFolderReplaceableDACL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FA;;;BU)"
	// usersWritableRecordDACL is an ownership record a standard user can
	// rewrite: it must not count as an administrator record.
	usersWritableRecordDACL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)"
)

// vendorFolderCase is one connector whose machine policy file lives in a
// vendor folder under ProgramData.
type vendorFolderCase struct {
	name      string
	connector string // the State.Connector the publish reports
	request   string // the connector name passed to the public API
	record    string // the ownership record of the file
	options   func(t *testing.T) Options
	file      func(t *testing.T, opts Options) string
	// prepare makes the vendor folder before the first publish, as the
	// vendor (or an administrator) would.
	prepare func(t *testing.T, opts Options, file string)
	// siblings: the vendor loads more than DefenseClaw's file name from the
	// folder (Copilot's policy.d, OpenCode's opencode.json and .jsonc), so a
	// folder standard users may add files to does not protect the connector
	// (g582 review 7 M1).
	siblings bool
}

func vendorFolderCases() []vendorFolderCase {
	vendorDirs := func(t *testing.T, dirs ...string) {
		t.Helper()
		for _, dir := range dirs {
			if err := createProtectedDir(dir); err != nil {
				t.Fatal(err)
			}
		}
	}
	return []vendorFolderCase{
		{
			name: "Devin", connector: ConnectorDevinCascade, request: "devin", record: ConnectorDevinCascade,
			options: windowsTestOptions,
			file: func(t *testing.T, opts Options) string {
				path, err := DevinSystemHooksPath(opts)
				if err != nil {
					t.Fatal(err)
				}
				return path
			},
			prepare: func(t *testing.T, _ Options, file string) { vendorDirs(t, filepath.Dir(file)) },
		},
		{
			name: "Windsurf", connector: ConnectorDevinCascade, request: "devin", record: devinCascadeLegacyRecord,
			options: windowsTestOptions,
			file: func(t *testing.T, opts Options) string {
				path, err := devinCascadeLegacyHooksPath(opts)
				if err != nil {
					t.Fatal(err)
				}
				return path
			},
			prepare: func(t *testing.T, _ Options, file string) {
				// Only the pre-rename file exists, so the publish merges into
				// the Windsurf folder and records that file.
				vendorDirs(t, filepath.Dir(file))
				writeFile(t, file, "{\n  \"hooks\": {}\n}\n")
			},
		},
		{
			name: "opencode", connector: ConnectorOpenCode, request: ConnectorOpenCode, record: ConnectorOpenCode,
			options: windowsOpenCodeTestOptions,
			file: func(t *testing.T, opts Options) string {
				path, err := OpenCodeManagedConfigPath(opts)
				if err != nil {
					t.Fatal(err)
				}
				return path
			},
			prepare:  func(t *testing.T, _ Options, file string) { vendorDirs(t, filepath.Dir(file)) },
			siblings: true,
		},
		{
			name: "Copilot", connector: ConnectorCopilot, request: ConnectorCopilot, record: copilotConnector,
			options: func(t *testing.T) Options {
				opts := windowsTestOptions(t)
				// The policy.d drop-in only: no VS Code device policy or
				// Copilot managed setting in this host's HKLM.
				opts.CopilotCLIPolicyOnly = true
				return opts
			},
			file: func(t *testing.T, opts Options) string {
				dir, err := CopilotPolicyDir(opts)
				if err != nil {
					t.Fatal(err)
				}
				return filepath.Join(dir, DefenseClawDropInName)
			},
			prepare: func(t *testing.T, opts Options, file string) {
				// GitHub Copilot's installer (an administrator) made
				// GitHub\Copilot\policy.d.
				github := filepath.Join(opts.WindowsProgramData, "GitHub")
				vendorDirs(t, github, filepath.Join(github, "Copilot"), filepath.Dir(file))
			},
			siblings: true,
		},
	}
}

func folderSDDL(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

func pinReclaimStandalone(t *testing.T, standalone bool) {
	t.Helper()
	previous := reclaimRefusesContentDrift
	reclaimRefusesContentDrift = func() bool { return standalone }
	t.Cleanup(func() { reclaimRefusesContentDrift = previous })
}

func stateNamed(result Result, connector string) (State, bool) {
	for _, state := range result.States {
		if state.Connector == connector {
			return state, true
		}
	}
	return State{}, false
}

// publishVendorCase runs the Windows guardian publish (PublishWindowsGoOwned)
// for the case's connector.
func publishVendorCase(t *testing.T, tc vendorFolderCase, opts Options) (State, error) {
	t.Helper()
	result, err := PublishWindowsGoOwned(opts, []string{tc.request})
	state, _ := stateNamed(result, tc.connector)
	return state, err
}

// requireCleanFirstPublish publishes into a healthy vendor folder, which
// leaves an administrator-only ownership record naming the file.
func requireCleanFirstPublish(t *testing.T, tc vendorFolderCase, opts Options) {
	t.Helper()
	state, err := publishVendorCase(t, tc, opts)
	if err != nil || !state.Covered {
		t.Fatalf("first publish: state = %+v, err = %v", state, err)
	}
}

// requireFolderFix checks the administrator's fix in text: the owner, the
// inherited entries and the explicit grants, so it also works on an
// inherited entry (g582 review 7 M1, L3).
func requireFolderFix(t *testing.T, text, folder string) {
	t.Helper()
	for _, want := range []string{
		`icacls "` + folder + `" /setowner "*S-1-5-32-544"`,
		`icacls "` + folder + `" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("%q lacks the fix %s", text, want)
		}
	}
}

func requireNotTakenOverMessage(t *testing.T, err error, folder string, siblings bool) {
	t.Helper()
	if err == nil {
		t.Fatalf("the publish passed; want it to fail closed naming %s", folder)
	}
	text := err.Error()
	if !strings.Contains(text, folder) || !strings.Contains(text, "does not take it over") ||
		!strings.Contains(text, "Setup /ensure") {
		t.Fatalf("err = %v; want the one message naming %s and the fix", err, folder)
	}
	requireFolderFix(t, text, folder)
	reason := "delete or replace"
	if siblings {
		reason = "add files to it"
	}
	if !strings.Contains(text, reason) {
		t.Fatalf("err = %v; want the reason %q", err, reason)
	}
	if count := strings.Count(text, "does not take it over"); count != 1 {
		t.Fatalf("err names the folder %d times, want one message: %v", count, err)
	}
}

// removeVendorCase runs the uninstall's machine policy removal and checks
// that it went on: no error, the folder exactly as it was, DefenseClaw's
// record gone and one warning naming the folder and the fix (g582 review 7
// S1).
func removeVendorCase(t *testing.T, tc vendorFolderCase, opts Options, folder, before string) State {
	t.Helper()
	result, err := RemoveWindowsGoOwned(opts)
	if err != nil {
		t.Fatalf("the uninstall failed closed on a vendor folder it does not take over: %v", err)
	}
	if after := folderSDDL(t, folder); after != before {
		t.Fatalf("the uninstall took the folder over in place: %s, was %s", after, before)
	}
	if record, err := loadRecord(opts, tc.record); err != nil || record != nil {
		t.Fatalf("record after the uninstall = %+v, %v; want it dropped", record, err)
	}
	state, _ := stateNamed(result, tc.connector)
	named := 0
	for _, warning := range state.Warnings {
		if strings.Contains(warning, folder) && strings.Contains(warning, "without taking the folder over") {
			requireFolderFix(t, warning, folder)
			named++
		}
	}
	if named != 1 {
		t.Fatalf("warnings = %q; want one naming %s and the fix", state.Warnings, folder)
	}
	return state
}

// requireDefenseClawEntryGone checks that file, if it is still there, holds
// no DefenseClaw entry.
func requireDefenseClawEntryGone(t *testing.T, file string) {
	t.Helper()
	data, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(data)), "defenseclaw") {
		t.Fatalf("%s still holds DefenseClaw's entry after the uninstall:\n%s", file, data)
	}
}

// g582 review 6 M2 (GAP-0652 E3, lead ruling, case c): on standalone a
// vendor folder DefenseClaw did not create that holds a file DefenseClaw
// recorded is never taken over. When a standard user can delete or replace
// that file there, the publish (ensure, repair, the guardian pass) fails
// closed with one message naming the folder and the fix, the folder is left
// as it was, and Verify reports the connector not covered. The uninstall
// does not fail closed on it (review 7 S1): it strips DefenseClaw's entry
// from the recorded file, which is still the one DefenseClaw wrote, drops
// the record, leaves the folder as it was and names it.
func TestStandaloneRecordedVendorFolderAStandardUserCanReplaceFailsClosed(t *testing.T) {
	for _, tc := range vendorFolderCases() {
		t.Run(tc.name, func(t *testing.T) {
			pinReclaimStandalone(t, true)
			opts := tc.options(t)
			file := tc.file(t, opts)
			folder := filepath.Dir(file)
			tc.prepare(t, opts, file)
			requireCleanFirstPublish(t, tc, opts)
			if err := applySDDL(folder, vendorFolderReplaceableDACL); err != nil {
				t.Fatal(err)
			}
			before := folderSDDL(t, folder)
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}

			state, err := publishVendorCase(t, tc, opts)
			requireNotTakenOverMessage(t, err, folder, false)
			if state.Covered {
				t.Fatalf("publish state = %+v, want not covered", state)
			}
			if after := folderSDDL(t, folder); after != before {
				t.Fatalf("the folder was taken over in place: %s, was %s", after, before)
			}
			if after, err := os.ReadFile(file); err != nil || string(after) != string(data) {
				t.Fatalf("recorded file changed: %q, %v", after, err)
			}

			verify, verifyErr := VerifyAll(opts, []string{tc.request})
			if state, ok := stateNamed(verify, tc.connector); ok && state.Covered && verifyErr == nil {
				t.Fatalf("verify reports %s covered: %+v", tc.connector, state)
			}

			removeVendorCase(t, tc, opts, folder, before)
			requireDefenseClawEntryGone(t, file)
		})
	}
}

// Case c, benign twin: a vendor folder where standard users may only add
// entries is left as it is (no takeover) and the publish goes on, when the
// vendor reads only DefenseClaw's file name there (Devin and Windsurf read
// only hooks.json): the recorded file keeps its own administrator-only
// access list.
func TestStandaloneRecordedVendorFolderUsersMayOnlyAddIsLeftAndPublished(t *testing.T) {
	for _, tc := range vendorFolderCases() {
		if tc.siblings {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			pinReclaimStandalone(t, true)
			opts := tc.options(t)
			file := tc.file(t, opts)
			folder := filepath.Dir(file)
			tc.prepare(t, opts, file)
			requireCleanFirstPublish(t, tc, opts)
			if err := applySDDL(folder, vendorFolderAddOnlyDACL); err != nil {
				t.Fatal(err)
			}
			before := folderSDDL(t, folder)

			state, err := publishVendorCase(t, tc, opts)
			if err != nil || !state.Covered {
				t.Fatalf("publish: state = %+v, err = %v; want published", state, err)
			}
			if after := folderSDDL(t, folder); after != before {
				t.Fatalf("the folder was taken over: %s, was %s", after, before)
			}
			left := false
			for _, detail := range state.Details {
				if strings.HasPrefix(detail, "left "+folder+" as it is") {
					left = true
				}
			}
			if !left {
				t.Fatalf("details = %q, want the folder named as left as it is", state.Details)
			}
			if err := validateTrustedFile(file); err != nil {
				t.Fatalf("the recorded file is not administrator-only: %v", err)
			}
		})
	}
}

// g582 review 7 M1: in case c a folder standard users may add files to does
// not protect a connector whose vendor loads more than DefenseClaw's file
// from it. Copilot loads every *.json in policy.d, and OpenCode prefers an
// opencode.jsonc over DefenseClaw's opencode.json, and nothing moves a file
// a user adds there aside (the folder is not DefenseClaw's). So the publish
// fails closed with the one message, the folder stays as it was, Verify
// reports the connector not covered, and the uninstall still goes on.
func TestStandaloneRecordedVendorFolderUsersMayAddFailsClosedWhenTheVendorLoadsMoreThanOneFile(t *testing.T) {
	for _, tc := range vendorFolderCases() {
		if !tc.siblings {
			continue
		}
		for _, variant := range []string{"add-only folder", "a user file already added"} {
			t.Run(tc.name+" ("+variant+")", func(t *testing.T) {
				pinReclaimStandalone(t, true)
				opts := tc.options(t)
				file := tc.file(t, opts)
				folder := filepath.Dir(file)
				tc.prepare(t, opts, file)
				requireCleanFirstPublish(t, tc, opts)
				if err := applySDDL(folder, vendorFolderAddOnlyDACL); err != nil {
					t.Fatal(err)
				}
				planted := ""
				if variant == "a user file already added" {
					planted = filepath.Join(folder, "50-user.json")
					if tc.name == "opencode" {
						planted = filepath.Join(folder, "opencode.jsonc")
					}
					writeFile(t, planted, "{}\n")
					if err := applySDDL(planted, usersWritableRecordDACL); err != nil {
						t.Fatal(err)
					}
				}
				before := folderSDDL(t, folder)
				data, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}

				state, err := publishVendorCase(t, tc, opts)
				requireNotTakenOverMessage(t, err, folder, true)
				if state.Covered {
					t.Fatalf("publish state = %+v, want not covered", state)
				}
				if after := folderSDDL(t, folder); after != before {
					t.Fatalf("the folder was taken over in place: %s, was %s", after, before)
				}
				if after, err := os.ReadFile(file); err != nil || string(after) != string(data) {
					t.Fatalf("recorded file changed: %q, %v", after, err)
				}
				if planted != "" {
					if _, err := os.Lstat(planted); err != nil {
						t.Fatalf("the user's file was moved out of a folder DefenseClaw does not hold: %v", err)
					}
				}

				verify, verifyErr := VerifyAll(opts, []string{tc.request})
				if state, ok := stateNamed(verify, tc.connector); ok && state.Covered && verifyErr == nil {
					t.Fatalf("verify reports %s covered: %+v", tc.connector, state)
				}

				removeVendorCase(t, tc, opts, folder, before)
				requireDefenseClawEntryGone(t, file)
				if planted != "" {
					if got := readFile(t, planted); got != "{}\n" {
						t.Fatalf("the uninstall changed the user's file: %q", got)
					}
				}
			})
		}
	}
}

// g582 review 7 S1: in a case c folder that does not protect it, the
// uninstall strips DefenseClaw's entry only from a recorded file it can
// still trust. A file that changed after DefenseClaw wrote it, or that
// another account can now change, is left byte for byte; the record still
// goes and the folder is named.
func TestStandaloneRecordedVendorFolderRemovalLeavesAFileItCannotTrust(t *testing.T) {
	for _, tc := range vendorFolderCases() {
		for _, variant := range []string{"changed after DefenseClaw wrote it", "another account can change it"} {
			t.Run(tc.name+" ("+variant+")", func(t *testing.T) {
				pinReclaimStandalone(t, true)
				opts := tc.options(t)
				file := tc.file(t, opts)
				folder := filepath.Dir(file)
				tc.prepare(t, opts, file)
				requireCleanFirstPublish(t, tc, opts)
				if err := applySDDL(folder, vendorFolderReplaceableDACL); err != nil {
					t.Fatal(err)
				}
				switch variant {
				case "changed after DefenseClaw wrote it":
					handle, err := os.OpenFile(file, os.O_WRONLY|os.O_APPEND, 0)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := handle.WriteString("\n"); err != nil {
						t.Fatal(err)
					}
					if err := handle.Close(); err != nil {
						t.Fatal(err)
					}
				default:
					if err := applySDDL(file, usersWritableRecordDACL); err != nil {
						t.Fatal(err)
					}
				}
				before := folderSDDL(t, folder)
				data, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}

				state := removeVendorCase(t, tc, opts, folder, before)
				if after, err := os.ReadFile(file); err != nil || string(after) != string(data) {
					t.Fatalf("the uninstall changed a recorded file it cannot trust: %q, %v", after, err)
				}
				left := false
				for _, warning := range state.Warnings {
					if strings.Contains(warning, "left "+file+" as it is") {
						left = true
					}
				}
				if !left {
					t.Fatalf("warnings = %q; want %s named as left", state.Warnings, file)
				}
			})
		}
	}
}

// Case a: a folder DefenseClaw created (created_dirs) is DefenseClaw's own,
// so the repair re-stamps it; a recorded file in it that another account
// can change is replaced, never trusted as found.
func TestStandaloneVendorFolderDefenseClawCreatedIsRestamped(t *testing.T) {
	for _, tc := range vendorFolderCases() {
		if tc.name == "Windsurf" {
			// DefenseClaw never creates the pre-rename folder: it writes
			// there only when the vendor file already exists.
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			pinReclaimStandalone(t, true)
			opts := tc.options(t)
			file := tc.file(t, opts)
			folder := filepath.Dir(file)
			requireCleanFirstPublish(t, tc, opts)
			record, err := loadRecord(opts, tc.record)
			if err != nil || record == nil {
				t.Fatalf("record = %+v, %v", record, err)
			}
			created := false
			for _, dir := range record.CreatedDirs {
				if strings.EqualFold(filepath.Clean(dir), folder) {
					created = true
				}
			}
			if !created {
				t.Fatalf("created_dirs = %q, want %s", record.CreatedDirs, folder)
			}
			if err := applySDDL(folder, vendorFolderReplaceableDACL); err != nil {
				t.Fatal(err)
			}
			if err := applySDDL(file, usersWritableRecordDACL); err != nil {
				t.Fatal(err)
			}

			state, err := publishVendorCase(t, tc, opts)
			if trustErr := validateTrustedLeafDir(folder); trustErr != nil {
				t.Fatalf("the created folder was not re-stamped: %v", trustErr)
			}
			if err != nil || !state.Covered {
				// The other outcome the class allows: the recorded file is
				// refused and named, never trusted as found (OpenCode does not
				// move an Administrators-owned file aside).
				if err == nil || state.Covered || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(file)) {
					t.Fatalf("publish: state = %+v, err = %v; want the file written new, or refused by name", state, err)
				}
				return
			}
			if err := validateTrustedFile(tc.file(t, opts)); err != nil {
				t.Fatalf("the recorded file another account could change was kept: %v", err)
			}
		})
	}
}

// Case b and the twins that keep the documented takeover: a vendor folder
// with no ownership record, one whose record a standard user can rewrite
// (planted, ignored), and Secure Client.
func TestVendorFolderWithoutAnAdministratorRecordKeepsTheTakeover(t *testing.T) {
	for _, tc := range vendorFolderCases() {
		for _, variant := range []string{"no record", "users-writable record", "secure client"} {
			t.Run(tc.name+" ("+variant+")", func(t *testing.T) {
				pinReclaimStandalone(t, variant != "secure client")
				opts := tc.options(t)
				file := tc.file(t, opts)
				folder := filepath.Dir(file)
				tc.prepare(t, opts, file)
				if variant != "no record" {
					requireCleanFirstPublish(t, tc, opts)
				}
				if variant == "users-writable record" {
					path, err := recordPath(opts, tc.record)
					if err != nil {
						t.Fatal(err)
					}
					if err := applySDDL(path, usersWritableRecordDACL); err != nil {
						t.Fatal(err)
					}
				}
				if err := applySDDL(folder, vendorFolderReplaceableDACL); err != nil {
					t.Fatal(err)
				}

				state, err := publishVendorCase(t, tc, opts)
				if err != nil || !state.Covered {
					t.Fatalf("publish: state = %+v, err = %v; want the takeover and the publish", state, err)
				}
				if err := validateTrustedLeafDir(folder); err != nil {
					t.Fatalf("the folder was not taken back: %v", err)
				}
			})
		}
	}
}
