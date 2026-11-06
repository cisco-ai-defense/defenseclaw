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

// Vendor folder descriptors for the g582 review 6 M2 rows (GAP-0652 E3).
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
	options   func(t *testing.T) Options
	file      func(t *testing.T, opts Options) string
	// prepare makes the vendor folder before the first publish, as the
	// vendor (or an administrator) would; with created set it is left
	// missing so the publish creates it.
	prepare func(t *testing.T, opts Options, file string)
	// removalNamesFolder: the uninstall takes back this folder first
	// (takeBackWindowsGoOwnedForRemoval), so it fails closed with the
	// same message.
	removalNamesFolder bool
}

func vendorFolderCases() []vendorFolderCase {
	vendorDir := func(t *testing.T, file string) {
		t.Helper()
		if err := createProtectedDir(filepath.Dir(file)); err != nil {
			t.Fatal(err)
		}
	}
	return []vendorFolderCase{
		{
			name: "Devin", connector: ConnectorDevinCascade, request: "devin",
			options: windowsTestOptions,
			file: func(t *testing.T, opts Options) string {
				path, err := DevinSystemHooksPath(opts)
				if err != nil {
					t.Fatal(err)
				}
				return path
			},
			prepare:            func(t *testing.T, _ Options, file string) { vendorDir(t, file) },
			removalNamesFolder: true,
		},
		{
			name: "Windsurf", connector: ConnectorDevinCascade, request: "devin",
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
				vendorDir(t, file)
				writeFile(t, file, "{\n  \"hooks\": {}\n}\n")
			},
		},
		{
			name: "opencode", connector: ConnectorOpenCode, request: ConnectorOpenCode,
			options: windowsOpenCodeTestOptions,
			file: func(t *testing.T, opts Options) string {
				path, err := OpenCodeManagedConfigPath(opts)
				if err != nil {
					t.Fatal(err)
				}
				return path
			},
			prepare:            func(t *testing.T, _ Options, file string) { vendorDir(t, file) },
			removalNamesFolder: true,
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

func requireNotTakenOverMessage(t *testing.T, err error, folder string) {
	t.Helper()
	if err == nil {
		t.Fatalf("the publish passed; want it to fail closed naming %s", folder)
	}
	text := err.Error()
	if !strings.Contains(text, folder) || !strings.Contains(text, "does not take it over") ||
		!strings.Contains(text, "/setowner *S-1-5-32-544") || !strings.Contains(text, "Setup /ensure") {
		t.Fatalf("err = %v; want the one message naming %s and the fix", err, folder)
	}
	if count := strings.Count(text, "does not take it over"); count != 1 {
		t.Fatalf("err names the folder %d times, want one message: %v", count, err)
	}
}

// g582 review 6 M2 (GAP-0652 E3, lead ruling, case c): on standalone a
// vendor folder DefenseClaw did not create that holds a file DefenseClaw
// recorded is never taken over. When a standard user can delete or replace
// that file there, the publish (ensure, repair, the guardian pass) and the
// uninstall fail closed with one message naming the folder and the fix, the
// folder is left as it was, and Verify reports the connector not covered.
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
			requireNotTakenOverMessage(t, err, folder)
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

			_, removeErr := RemoveWindowsGoOwned(opts)
			if tc.removalNamesFolder {
				requireNotTakenOverMessage(t, removeErr, folder)
			}
			if after := folderSDDL(t, folder); after != before {
				t.Fatalf("the uninstall took the folder over in place: %s, was %s", after, before)
			}
			if _, err := os.Lstat(file); err != nil {
				t.Fatalf("the uninstall removed the recorded file from a folder it refused: %v", err)
			}
		})
	}
}

// Case c, benign twin: a vendor folder where standard users may only add
// entries is left as it is (no takeover) and the publish goes on: the
// recorded file keeps its own administrator-only access list.
func TestStandaloneRecordedVendorFolderUsersMayOnlyAddIsLeftAndPublished(t *testing.T) {
	for _, tc := range vendorFolderCases() {
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
			record, err := loadRecord(opts, tc.connector)
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
			if err != nil || !state.Covered {
				t.Fatalf("publish: state = %+v, err = %v", state, err)
			}
			if err := validateTrustedLeafDir(folder); err != nil {
				t.Fatalf("the created folder was not re-stamped: %v", err)
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
					name := tc.connector
					if tc.name == "Windsurf" {
						name = devinCascadeLegacyRecord
					}
					path, err := recordPath(opts, name)
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
