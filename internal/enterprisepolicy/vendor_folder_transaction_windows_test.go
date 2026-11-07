//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// armAddDuringReprotect runs add once, between the safe transaction's checks
// of folder and its stamp, while the transaction's handles are open.
func armAddDuringReprotect(t *testing.T, folder string, add func()) {
	t.Helper()
	previous := reprotectBeforeStamp
	t.Cleanup(func() { reprotectBeforeStamp = previous })
	reprotectBeforeStamp = func(dir string) {
		if strings.EqualFold(dir, folder) {
			reprotectBeforeStamp = previous
			add()
		}
	}
}

// g582 round 11 review S1: the transaction's listing and its stamp are not one
// step (the folder handle shares writing), so an account that may add files
// to the folder can add one between them. The folder is listed again after the
// stamp: a file a standard user added in between is moved aside, as the
// publish moves aside a file a standard user left in the folder; one
// DefenseClaw does not move aside (an administrator's) refuses the folder by
// name, and the change that was made is still reported.
func TestSafeTransactionHandlesAFileAddedBetweenTheCheckAndTheStamp(t *testing.T) {
	for _, tc := range vendorFolderCases() {
		if !tc.siblings {
			continue
		}
		added := "50-added.json"
		if tc.connector == ConnectorOpenCode {
			added = "opencode.jsonc"
		}
		for _, variant := range []struct {
			name, by string
			publish  bool
		}{
			{name: "Setup, a standard user's file", by: "user"},
			{name: "guardian publish, a standard user's file", by: "user", publish: true},
			{name: "Setup, an administrator's file", by: "administrator"},
		} {
			t.Run(tc.name+" ("+variant.name+")", func(t *testing.T) {
				opts, file, folder := publishedWeakCase(t, tc, programDataDefaultDACL)
				data := readFile(t, file)
				path := filepath.Join(folder, added)
				armAddDuringReprotect(t, folder, func() {
					if variant.by == "user" {
						plantAsUser(t, path, "file")
					} else {
						writeFile(t, path, "{}\n")
					}
				})

				var healed []ReprotectedFolder
				var blocked []VendorFolderProblem
				if variant.publish {
					state, err := publishVendorCase(t, tc, opts)
					if err != nil {
						t.Fatalf("publish: %v", err)
					}
					healed = state.Reprotected
					moved := false
					for _, detail := range state.Details {
						if strings.Contains(detail, "moved "+path+" aside") {
							moved = true
						}
					}
					if !moved {
						t.Fatalf("details = %q; want the file added during the transaction moved aside", state.Details)
					}
				} else {
					healed, blocked = ReprotectRecordedVendorFolders(opts, []string{tc.request})
				}
				if len(healed) != 1 || !strings.EqualFold(healed[0].Dir, folder) {
					t.Fatalf("healed = %+v; want %s re-protected and reported", healed, folder)
				}
				if err := validateTrustedLeafDir(folder); err != nil {
					t.Fatalf("the folder is still weak after the stamp: %v", err)
				}
				if got := readFile(t, file); got != data {
					t.Fatalf("the recorded file changed")
				}
				_, statErr := os.Lstat(path)
				if variant.by == "user" {
					if len(blocked) != 0 || len(healed[0].Displaced) != 1 || !strings.Contains(healed[0].Displaced[0], path) {
						t.Fatalf("healed = %+v, blocked = %+v; want %s moved aside and no refusal", healed, blocked, path)
					}
					if !errors.Is(statErr, os.ErrNotExist) || len(displacedEntries(t, folder)) != 1 {
						t.Fatalf("%s is still in the folder (%v) or was not moved aside: %q", path, statErr, displacedEntries(t, folder))
					}
					return
				}
				if len(blocked) != 1 || !strings.Contains(blocked[0].Blocker, "appeared in "+folder) || !strings.Contains(blocked[0].Blocker, path) {
					t.Fatalf("blocked = %+v; want the administrator's file named as the refusal", blocked)
				}
				if statErr != nil {
					t.Fatalf("an administrator's file was removed: %v", statErr)
				}
			})
		}
	}
}

// g582 round 11 review L2: a weak GitHub\Copilot and a weak policy.d are both
// put right by one Setup call. The inspection stops at the first weak folder
// of a path, so the heal walks the path again until nothing is weak.
func TestReprotectRecordedVendorFoldersHealsAWeakParentAndAWeakPolicyFolderInOnePass(t *testing.T) {
	for _, tc := range vendorFolderCases() {
		if tc.connector != ConnectorCopilot {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			opts, _, folder := publishedWeakCase(t, tc, vendorFolderReplaceableDACL)
			parent := filepath.Dir(folder)
			if err := applySDDL(parent, vendorFolderReplaceableDACL); err != nil {
				t.Fatal(err)
			}
			healed, blocked := ReprotectRecordedVendorFolders(opts, []string{tc.request})
			if len(blocked) != 0 || len(healed) != 2 || !strings.EqualFold(healed[0].Dir, parent) || !strings.EqualFold(healed[1].Dir, folder) {
				t.Fatalf("healed = %+v, blocked = %+v; want %s, then %s, re-protected in one call", healed, blocked, parent, folder)
			}
			if err := validateTrustedDir(parent); err != nil {
				t.Fatalf("%s is still weak: %v", parent, err)
			}
			if err := validateTrustedLeafDir(folder); err != nil {
				t.Fatalf("%s is still weak: %v", folder, err)
			}
			if problems := InspectRecordedVendorFolders(opts, []string{tc.request}); len(problems) != 0 {
				t.Fatalf("still reported after the heal: %+v", problems)
			}
		})
	}
}

// g582 round 11 review S5: the kept-file report never reads through a link. A
// vendor folder that is a junction (the teardown reports it as a kept link)
// gives no stale hook entry, even when the file behind it names DefenseClaw
// and another account can change it; the same file in a plain folder does.
func TestKeptUntrustedPolicyFilesSkipsALinkedVendorFolder(t *testing.T) {
	for _, tc := range vendorFolderCases() {
		t.Run(tc.name, func(t *testing.T) {
			pinReclaimStandalone(t, true)
			opts := tc.options(t)
			file := tc.file(t, opts)
			folder := filepath.Dir(file)
			if err := os.MkdirAll(filepath.Dir(folder), 0o755); err != nil {
				t.Fatal(err)
			}
			const stale = "{\"hooks\": {\"x\": [{\"command\": \"C:\\\\Program Files\\\\Cisco\\\\DefenseClaw\\\\bin\\\\defenseclaw-hook.exe\"}]}}\n"
			plant := func(dir string) {
				t.Helper()
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, filepath.Base(file))
				writeFile(t, path, stale)
				if err := applySDDL(path, usersWritableRecordDACL); err != nil {
					t.Fatal(err)
				}
			}
			target := filepath.Join(t.TempDir(), "elsewhere")
			plant(target)
			if out, err := exec.Command("cmd", "/c", "mklink", "/J", folder, target).CombinedOutput(); err != nil {
				t.Skipf("mklink /J unavailable: %v %s", err, out)
			}
			if kept := KeptUntrustedPolicyFiles(opts); len(kept) != 0 {
				t.Fatalf("kept = %q; a file behind a linked vendor folder must not be read or listed", kept)
			}
			if err := os.Remove(folder); err != nil {
				t.Fatal(err)
			}
			plant(folder)
			if kept := KeptUntrustedPolicyFiles(opts); len(kept) != 1 || !strings.HasPrefix(kept[0], file+": "+StaleHookKept) {
				t.Fatalf("kept = %q; want the file in the plain folder listed once", kept)
			}
		})
	}
}

// g582 round 11 review S4: the guardian keys its refusal alert by folder, so
// VendorFolderRefusals returns every refused folder a joined publish error
// carries, once per folder, and nothing for any other error.
func TestVendorFolderRefusalsListsEachRefusedFolderOnce(t *testing.T) {
	root := t.TempDir()
	devin, copilot := filepath.Join(root, "Devin"), filepath.Join(root, "GitHub", "Copilot", "policy.d")
	refusal := func(dir string) error {
		return &recordedVendorFolderError{dir: dir, file: filepath.Join(dir, "hooks.json"), err: errors.New("Users may delete entries")}
	}
	err := errors.Join(
		fmt.Errorf("devincascade: %w", refusal(devin)),
		errors.New("opencode: some other failure"),
		fmt.Errorf("copilot: %w", refusal(copilot)),
		fmt.Errorf("legacy devin folder: %w", refusal(strings.ToUpper(devin))),
	)
	got := VendorFolderRefusals(err)
	if len(got) != 2 || got[0].Dir != devin || got[1].Dir != copilot ||
		got[0].Message != refusal(devin).Error() || !strings.Contains(got[1].Message, copilot) {
		t.Fatalf("refusals = %+v; want %s and %s once each with their own message", got, devin, copilot)
	}
	if got := VendorFolderRefusals(errors.New("not a vendor folder refusal")); got != nil {
		t.Fatalf("refusals of another error = %+v", got)
	}
	if got := VendorFolderRefusals(nil); got != nil {
		t.Fatalf("refusals of nil = %+v", got)
	}
}
