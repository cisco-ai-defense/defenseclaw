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

// programDataDefaultDACL is what a folder a vendor's installer makes under
// C:\ProgramData gets from the parent: SYSTEM and Administrators full
// control, CREATOR OWNER full control of what it creates, Users read and
// execute, and Users create files and folders (not delete or replace).
const programDataDefaultDACL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;GA;;;CO)(A;OICI;0x1200a9;;;BU)(A;CI;0x107;;;BU)"

// weakDACLs are the ways a vendor folder DefenseClaw recorded a file in stops
// protecting it, per the vendor's use of the folder.
func weakDACLs(tc vendorFolderCase) map[string]string {
	weak := map[string]string{"another account can delete or replace the file": vendorFolderReplaceableDACL}
	if tc.siblings {
		weak["another account can add a file the vendor loads"] = vendorFolderAddOnlyDACL
		weak["the inherited ProgramData default"] = programDataDefaultDACL
	}
	return weak
}

// publishedWeakCase publishes into a healthy vendor folder and makes it weak.
func publishedWeakCase(t *testing.T, tc vendorFolderCase, dacl string) (Options, string, string) {
	t.Helper()
	pinReclaimStandalone(t, true)
	opts := tc.options(t)
	file := tc.file(t, opts)
	folder := filepath.Dir(file)
	tc.prepare(t, opts, file)
	requireCleanFirstPublish(t, tc, opts)
	if problems := InspectRecordedVendorFolders(opts, []string{tc.request}); len(problems) != 0 {
		t.Fatalf("a protected folder is reported: %+v", problems)
	}
	if err := applySDDL(folder, dacl); err != nil {
		t.Fatal(err)
	}
	return opts, file, folder
}

// GAP-0756 and GAP-0760: one judgement of a recorded vendor folder that does
// not protect DefenseClaw's file. The inspection Setup, the guardian and
// machine-policy verify ask names the folder and the unsafe entry and says
// whether the safe transaction would put it right; the publish reaches the
// same verdict: a clean folder is re-protected (reported once), a folder
// something holds or changed is refused with the same message.
func TestInspectRecordedVendorFoldersIsTheVerdictThePublishReaches(t *testing.T) {
	for _, tc := range vendorFolderCases() {
		for variant, dacl := range weakDACLs(tc) {
			t.Run(tc.name+" ("+variant+", clean)", func(t *testing.T) {
				opts, file, folder := publishedWeakCase(t, tc, dacl)
				before := folderSDDL(t, folder)
				data := readFile(t, file)

				problems := InspectRecordedVendorFolders(opts, []string{tc.request})
				if len(problems) != 1 || !problems[0].Reprotectable || !strings.EqualFold(problems[0].Dir, folder) ||
					!strings.Contains(problems[0].Message, "S-1-5-32-545") {
					t.Fatalf("problems = %+v; want %s, put right by the next reconcile", problems, folder)
				}
				if after := folderSDDL(t, folder); after != before {
					t.Fatalf("inspecting changed the folder: %s, was %s", after, before)
				}
				verify, _ := VerifyAll(opts, []string{tc.request})
				if state, ok := stateNamed(verify, tc.connector); !ok || state.Covered || len(state.Conflicts) == 0 || state.Conflicts[0] != problems[0].Message {
					t.Fatalf("verify state = %+v, %v; want %s uncovered with the inspection's message first", state, ok, tc.connector)
				}

				state, err := publishVendorCase(t, tc, opts)
				if err != nil || !state.Covered || len(state.Reprotected) != 1 {
					t.Fatalf("publish: state = %+v, err = %v; want the folder re-protected and covered", state, err)
				}
				rf := state.Reprotected[0]
				if !strings.EqualFold(rf.Dir, folder) || rf.Connector != tc.connector || rf.Before != before || rf.After == before || rf.After == "" {
					t.Fatalf("re-protected = %+v; want %s with its access list before (%s) and after", rf, folder, before)
				}
				reported := false
				for _, detail := range state.Details {
					if strings.HasPrefix(detail, "re-protected "+folder) {
						reported = true
					}
				}
				if !reported {
					t.Fatalf("details = %q; want one line saying %s was re-protected", state.Details, folder)
				}
				if got := readFile(t, file); got != data {
					t.Fatalf("the recorded file changed: %q", got)
				}
				if err := validateTrustedLeafDir(folder); err != nil {
					t.Fatalf("the re-protected folder is still weak: %v", err)
				}
				if problems := InspectRecordedVendorFolders(opts, []string{tc.request}); len(problems) != 0 {
					t.Fatalf("a re-protected folder is still reported: %+v", problems)
				}
				// A second pass reports nothing: the heal is once.
				if again, err := publishVendorCase(t, tc, opts); err != nil || len(again.Reprotected) != 0 {
					t.Fatalf("second publish: %+v, %v; want no second re-protection", again, err)
				}
			})
		}
	}
}

// What stops the safe transaction: each case is refused by name, with the
// folder's access list and the recorded file exactly as they were, the same
// message from the inspection, the publish and machine-policy verify, and the
// uncovered verdict. Once the blocker is gone the next pass re-protects.
func TestSafeTransactionRefusesWhatItCannotProve(t *testing.T) {
	type blockerCase struct {
		name  string
		want  string
		arm   func(t *testing.T, tc vendorFolderCase, file, folder string) (release func())
		multi bool // only for a vendor that loads every file in the folder
	}
	openHeld := func(t *testing.T, path string, access, share uint32) windows.Handle {
		t.Helper()
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := windows.CreateFile(name, access, share, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			t.Fatalf("hold %s: %v", path, err)
		}
		return handle
	}
	cases := []blockerCase{
		{name: "the recorded file was renamed", want: "is not there", arm: func(t *testing.T, tc vendorFolderCase, file, folder string) func() {
			moved := file + ".moved"
			if err := os.Rename(file, moved); err != nil {
				t.Fatal(err)
			}
			return func() {
				if err := os.Rename(moved, file); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{name: "the recorded file was changed", want: "was changed after DefenseClaw wrote it", arm: func(t *testing.T, tc vendorFolderCase, file, folder string) func() {
			original := readFile(t, file)
			appendToRecordedFile(t, file)
			return func() { writeFile(t, file, original) }
		}},
		{name: "a foreign file", want: "which DefenseClaw did not write", multi: true, arm: func(t *testing.T, tc vendorFolderCase, file, folder string) func() {
			foreign := filepath.Join(folder, "50-foreign.json")
			writeFile(t, foreign, "{}\n")
			return func() { _ = os.Remove(foreign) }
		}},
		{name: "a handle with DELETE access holds the recorded file", want: "another program holds", arm: func(t *testing.T, tc vendorFolderCase, file, folder string) func() {
			handle := openHeld(t, file, windows.GENERIC_READ|windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
			return func() { _ = windows.CloseHandle(handle) }
		}},
		{name: "a handle with write access holds the recorded file", want: "another program holds", arm: func(t *testing.T, tc vendorFolderCase, file, folder string) func() {
			handle := openHeld(t, file, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
			return func() { _ = windows.CloseHandle(handle) }
		}},
		{name: "a handle that does not share reading holds the recorded file", want: "another program holds", arm: func(t *testing.T, tc vendorFolderCase, file, folder string) func() {
			handle := openHeld(t, file, windows.GENERIC_READ, windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
			return func() { _ = windows.CloseHandle(handle) }
		}},
		{name: "a handle with DELETE access holds the folder", want: "another program holds", arm: func(t *testing.T, tc vendorFolderCase, file, folder string) func() {
			name, err := windows.UTF16PtrFromString(folder)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := windows.CreateFile(name, windows.DELETE|windows.FILE_LIST_DIRECTORY, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
				windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
			if err != nil {
				t.Fatal(err)
			}
			return func() { _ = windows.CloseHandle(handle) }
		}},
		{name: "the recorded file has a second hard link", want: "2 hard links", arm: func(t *testing.T, tc vendorFolderCase, file, folder string) func() {
			link := filepath.Join(t.TempDir(), "second-link")
			if err := os.Link(file, link); err != nil {
				t.Fatal(err)
			}
			return func() { _ = os.Remove(link) }
		}},
	}
	for _, tc := range vendorFolderCases() {
		for _, blocker := range cases {
			if blocker.multi && !tc.siblings {
				continue
			}
			t.Run(tc.name+" ("+blocker.name+")", func(t *testing.T) {
				opts, file, folder := publishedWeakCase(t, tc, vendorFolderReplaceableDACL)
				before := folderSDDL(t, folder)
				recordedBytes := readFile(t, file)
				release := blocker.arm(t, tc, file, folder)
				released := false
				defer func() {
					if !released {
						release()
					}
				}()

				problems := InspectRecordedVendorFolders(opts, []string{tc.request})
				state, publishErr := publishVendorCase(t, tc, opts)
				if len(problems) != 1 || problems[0].Reprotectable || !strings.Contains(problems[0].Blocker, blocker.want) {
					t.Fatalf("problems = %+v; want %s refused for %q", problems, folder, blocker.want)
				}
				requireNotTakenOverMessage(t, publishErr, folder, false)
				if !strings.Contains(publishErr.Error(), problems[0].Blocker) || !strings.Contains(publishErr.Error(), problems[0].Message) {
					t.Fatalf("the publish error and the inspection differ:\n%v\n%s", publishErr, problems[0].Message)
				}
				if !IsVendorFolderRefusal(publishErr) || state.Covered || len(state.Reprotected) != 0 {
					t.Fatalf("publish: state = %+v, err = %v; want a refusal, not covered and nothing re-protected", state, publishErr)
				}
				if after := folderSDDL(t, folder); after != before {
					t.Fatalf("a refused folder was changed: %s, was %s", after, before)
				}

				verify, _ := VerifyAll(opts, []string{tc.request})
				if vs, ok := stateNamed(verify, tc.connector); !ok || vs.Covered || len(vs.Conflicts) == 0 || vs.Conflicts[0] != problems[0].Message {
					t.Fatalf("verify = %+v, %v; want %s uncovered with the same message", vs, ok, tc.connector)
				}

				release()
				released = true
				if blocker.name != "the recorded file was changed" {
					if got := readFile(t, file); got != recordedBytes {
						t.Fatalf("the recorded file changed during the refusal")
					}
				}
				healed, err := publishVendorCase(t, tc, opts)
				if err != nil || !healed.Covered || len(healed.Reprotected) != 1 {
					t.Fatalf("publish after the blocker is gone: %+v, %v; want the folder re-protected", healed, err)
				}
			})
		}
	}
}

// Setup's own entry point: the same transaction, called before an install-like
// action, heals what it can and returns what it cannot.
func TestReprotectRecordedVendorFoldersHealsTheCleanAndReturnsTheBlocked(t *testing.T) {
	for _, tc := range vendorFolderCases() {
		t.Run(tc.name, func(t *testing.T) {
			opts, file, folder := publishedWeakCase(t, tc, vendorFolderReplaceableDACL)
			healed, blocked := ReprotectRecordedVendorFolders(opts, []string{tc.request})
			if len(blocked) != 0 || len(healed) != 1 || !strings.EqualFold(healed[0].Dir, folder) || healed[0].Connector != tc.connector {
				t.Fatalf("healed = %+v, blocked = %+v; want %s re-protected", healed, blocked, folder)
			}
			if err := validateTrustedLeafDir(folder); err != nil {
				t.Fatalf("still weak: %v", err)
			}
			if healed, blocked := ReprotectRecordedVendorFolders(opts, []string{tc.request}); len(healed) != 0 || len(blocked) != 0 {
				t.Fatalf("second call: healed = %+v, blocked = %+v; want nothing", healed, blocked)
			}
			if err := applySDDL(folder, vendorFolderReplaceableDACL); err != nil {
				t.Fatal(err)
			}
			appendToRecordedFile(t, file)
			before := folderSDDL(t, folder)
			healed, blocked = ReprotectRecordedVendorFolders(opts, []string{tc.request})
			if len(healed) != 0 || len(blocked) != 1 || blocked[0].Blocker == "" || folderSDDL(t, folder) != before {
				t.Fatalf("healed = %+v, blocked = %+v; want a refusal and the folder unchanged", healed, blocked)
			}
		})
	}
}

// Balanced defaults: a vendor folder that only has what ProgramData gives it
// (Users create files and folders) is the normal fresh install, E3 case b.
// Nothing is recorded yet, so neither the inspection nor the publish refuses
// it: the first publish takes it over and records the file, and after that
// the folder passes.
func TestInspectRecordedVendorFoldersPassesAFreshInstallOnTheInheritedDefaults(t *testing.T) {
	for _, tc := range vendorFolderCases() {
		t.Run(tc.name, func(t *testing.T) {
			pinReclaimStandalone(t, true)
			opts := tc.options(t)
			file := tc.file(t, opts)
			folder := filepath.Dir(file)
			tc.prepare(t, opts, file)
			if err := applySDDL(folder, programDataDefaultDACL); err != nil {
				t.Fatal(err)
			}
			if problems := InspectRecordedVendorFolders(opts, []string{tc.request}); len(problems) != 0 {
				t.Fatalf("a vendor-made folder with no DefenseClaw file is reported before the first publish: %+v", problems)
			}
			verifyFresh, _ := VerifyAll(opts, []string{tc.request})
			if state, ok := stateNamed(verifyFresh, tc.connector); ok && strings.Contains(strings.Join(state.Conflicts, " "), "does not take it over") {
				t.Fatalf("verify refuses a fresh folder as case c: %+v", state)
			}
			state, err := publishVendorCase(t, tc, opts)
			if err != nil || !state.Covered || len(state.Reprotected) != 0 {
				t.Fatalf("first publish on the inherited defaults: state = %+v, err = %v; want a covered install taken over as case b", state, err)
			}
			if problems := InspectRecordedVendorFolders(opts, []string{tc.request}); len(problems) != 0 {
				t.Fatalf("the folder the first publish protected is reported: %+v", problems)
			}
			if verify, err := VerifyAll(opts, []string{tc.request}); err != nil || !verify.Complete() {
				t.Fatalf("verify after the first publish: %+v, %v", verify, err)
			}
		})
	}
}

// Devin and Windsurf read only hooks.json, so the inherited default (Users
// may add files) leaves the recorded file protected: the inspection reports
// nothing, as the publish leaves the folder as it is.
func TestInspectRecordedVendorFoldersLeavesAnAddOnlyFolderOfASingleFileVendor(t *testing.T) {
	for _, tc := range vendorFolderCases() {
		if tc.siblings {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			opts, _, _ := publishedWeakCase(t, tc, programDataDefaultDACL)
			if problems := InspectRecordedVendorFolders(opts, []string{tc.request}); len(problems) != 0 {
				t.Fatalf("an add-only folder of a one-file vendor is reported: %+v", problems)
			}
			if state, err := publishVendorCase(t, tc, opts); err != nil || !state.Covered || len(state.Reprotected) != 0 {
				t.Fatalf("publish: state = %+v, err = %v", state, err)
			}
		})
	}
}

// Secure Client keeps the takeover of 1.0.8: nothing is inspected, nothing is
// refused, whatever the folder allows.
func TestInspectRecordedVendorFoldersReportsNothingOffStandalone(t *testing.T) {
	for _, tc := range vendorFolderCases() {
		t.Run(tc.name, func(t *testing.T) {
			opts, _, _ := publishedWeakCase(t, tc, vendorFolderReplaceableDACL)
			pinReclaimStandalone(t, false)
			if problems := InspectRecordedVendorFolders(opts, []string{tc.request}); len(problems) != 0 {
				t.Fatalf("Secure Client reports a vendor folder: %+v", problems)
			}
			if healed, blocked := ReprotectRecordedVendorFolders(opts, []string{tc.request}); len(healed) != 0 || len(blocked) != 0 {
				t.Fatalf("Secure Client runs the safe transaction: %+v %+v", healed, blocked)
			}
			if VendorFolderProblemFor(opts, tc.connector) != nil {
				t.Fatalf("Secure Client reports a vendor folder")
			}
			verify, _ := VerifyAll(opts, []string{tc.request})
			if state, ok := stateNamed(verify, tc.connector); ok && strings.Contains(strings.Join(state.Conflicts, " "), "does not take it over") {
				t.Fatalf("Secure Client verify names a vendor folder refusal: %+v", state.Conflicts)
			}
			// Its publish is the 1.0.8 takeover: the folder is taken back,
			// with no safe-transaction report.
			if state, err := publishVendorCase(t, tc, opts); err != nil || !state.Covered || len(state.Reprotected) != 0 {
				t.Fatalf("Secure Client publish: %+v, %v; want the plain takeover", state, err)
			}
		})
	}
}

// GAP-0761: an uninstall never writes through a recorded file another account
// can change. It leaves it byte for byte, drops the record, and warns once:
// the file's DefenseClaw hook entries now name removed programs, with the fix.
func TestRemovalKeepsAnUntrustedRecordedFileAndWarnsOnce(t *testing.T) {
	for _, tc := range vendorFolderCases() {
		t.Run(tc.name, func(t *testing.T) {
			pinReclaimStandalone(t, true)
			opts := tc.options(t)
			file := tc.file(t, opts)
			folder := filepath.Dir(file)
			tc.prepare(t, opts, file)
			requireCleanFirstPublish(t, tc, opts)
			if err := applySDDL(file, usersWritableRecordDACL); err != nil {
				t.Fatal(err)
			}
			data := readFile(t, file)
			before := folderSDDL(t, folder)

			result, err := RemoveWindowsGoOwned(opts)
			if err != nil {
				t.Fatalf("the uninstall failed on a file it must keep: %v", err)
			}
			if got := readFile(t, file); got != data {
				t.Fatalf("the uninstall wrote through an untrusted file")
			}
			if after := folderSDDL(t, folder); after != before {
				t.Fatalf("the uninstall changed the folder: %s, was %s", after, before)
			}
			if record, err := loadRecord(opts, tc.record); err != nil || record != nil {
				t.Fatalf("record = %+v, %v; want it dropped", record, err)
			}
			// The lifecycle's result names the file once, from the folder as it
			// is after the uninstall, whatever record is left.
			kept := KeptUntrustedPolicyFiles(opts)
			if len(kept) != 1 || !strings.HasPrefix(kept[0], file+": "+StaleHookKept) || !strings.Contains(kept[0], "S-1-5-32-545") {
				t.Fatalf("kept = %q; want one entry for %s naming the account", kept, file)
			}
			if err := applySDDL(file, publicFileSDDL); err != nil {
				t.Fatal(err)
			}
			if kept := KeptUntrustedPolicyFiles(opts); len(kept) != 0 {
				t.Fatalf("a file only administrators can change is listed: %q", kept)
			}
			state, _ := stateNamed(result, tc.connector)
			named := 0
			for _, warning := range state.Warnings {
				if strings.Contains(warning, file) && strings.Contains(warning, "byte for byte") &&
					strings.Contains(warning, "defenseclaw-hook.exe") && strings.Contains(warning, "S-1-5-32-545") {
					named++
				}
			}
			if named != 1 || len(state.Warnings) != 1 {
				t.Fatalf("warnings = %q; want exactly one naming %s, the stale hook entries and the account", state.Warnings, file)
			}
		})
	}
}
