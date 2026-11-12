//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// g582 review 3 M1-M3: the guardian's self-heal refused an untrusted
// DefenseClaw policy file or folder on standalone, but every privileged
// selector read and transaction, every Cursor snapshot and every policy
// transaction (the read-only targets readers the guardian calls each pass
// included) still re-stamped the same objects in place through
// repairWindowsManagedMachineFile and repairWindowsManagedPolicyFolder. Those
// helpers now refuse on standalone themselves; the lock files, trusted-only
// drift, a folder with no DefenseClaw file and Secure Client keep the repair.

func isGAP633Refusal(err error) bool {
	var refused *managed.StandaloneContentDriftError
	return errors.As(err, &refused)
}

// gap633SelectorFixture writes a canonical Codex runtime selector into a
// canonical policy folder under the test's temp directory and points the
// selector resolver at it.
func gap633SelectorFixture(t *testing.T, standalone bool) (selectorPath, lockPath string) {
	t.Helper()
	setGAP633Profile(t, standalone, nil)
	previousPath := windowsManagedRuntimeSelectorPathResolver
	previousDir, previousAncestor := windowsManagedPolicyDirTrustCheck, windowsManagedPolicyAncestorTrustCheck
	t.Cleanup(func() {
		windowsManagedRuntimeSelectorPathResolver = previousPath
		windowsManagedPolicyDirTrustCheck, windowsManagedPolicyAncestorTrustCheck = previousDir, previousAncestor
	})
	folder := filepath.Join(t.TempDir(), "policy")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	stampGAP633SDDL(t, folder, gap633CanonicalFolderSDDL)
	// The temp folders above the fixture are not machine-trusted; the
	// folder itself is judged on its own descriptor, as on a real host.
	folderLeaf := windowsManagedPolicyLeafTrust(managed.ObjectInstallDirectory)
	windowsManagedPolicyDirTrustCheck = folderLeaf
	windowsManagedPolicyAncestorTrustCheck = folderLeaf
	selectorPath = filepath.Join(folder, windowsManagedRuntimeSelectorFile)
	windowsManagedRuntimeSelectorPathResolver = func(string) (string, error) { return selectorPath, nil }
	data, err := marshalWindowsManagedRuntimeSelector(windowsManagedRuntimeSelector{
		SchemaVersion: windowsManagedRuntimeGenerationSchema,
		Connector:     "codex",
		Targets:       []windowsManagedRuntimeSelectorTarget{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeWindowsManagedFile(selectorPath, data, true); err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsManagedMachineFileDescriptor(selectorPath, true); err != nil {
		t.Fatalf("selector fixture is not canonical: %v", err)
	}
	return selectorPath, filepath.Join(folder, windowsManagedRuntimeSelectorLockFile)
}

func TestWindowsManagedRuntimeSelectorStandaloneNeverRestampsAnUntrustedSelectorInPlace(t *testing.T) {
	requireGAP633Elevated(t)
	for _, tc := range []struct {
		name       string
		sddl       string
		standalone bool
		refused    bool
	}{
		{name: "Users Modify", sddl: gap633UsersModifyFile, standalone: true, refused: true},
		{name: "Users owner", sddl: gap633UsersOwnerFile, standalone: true, refused: true},
		{name: "twin: missing Users read is repaired", sddl: gap633NoUsersReadFile, standalone: true},
		{name: "twin: Secure Client with Users Modify is repaired", sddl: gap633UsersModifyFile},
	} {
		for _, via := range []string{"read", "transaction"} {
			t.Run(tc.name+" ("+via+")", func(t *testing.T) {
				selectorPath, _ := gap633SelectorFixture(t, tc.standalone)
				stampGAP633SDDL(t, selectorPath, tc.sddl)
				before := gap633Descriptor(t, selectorPath)

				var err error
				called := false
				if via == "read" {
					_, _, _, err = readWindowsManagedRuntimeSelector("codex", false)
				} else {
					err = withWindowsManagedRuntimeSelectorTransaction("codex", func() error {
						called = true
						return nil
					})
				}

				after := gap633Descriptor(t, selectorPath)
				if tc.refused {
					if after != before {
						t.Fatalf("the selector %s re-stamped an untrusted selector in place: %s -> %s", via, before, after)
					}
					if !isGAP633Refusal(err) || !strings.Contains(err.Error(), "does not repair this file in place") ||
						!strings.Contains(err.Error(), "delete the file") {
						t.Fatalf("the selector %s did not return the standalone refusal: %v", via, err)
					}
					if called {
						t.Fatal("the selector transaction ran on an untrusted selector")
					}
					return
				}
				if err != nil {
					t.Fatalf("the selector %s refused a repairable selector: %v", via, err)
				}
				if via == "transaction" && !called {
					t.Fatal("the selector transaction did not run")
				}
				if err := validateWindowsManagedMachineFileDescriptor(selectorPath, true); err != nil || gap633UsersCanWrite(after) {
					t.Fatalf("the selector %s did not repair %s: %s (%v)", via, tc.sddl, after, err)
				}
			})
		}
	}
}

// The selector lock carries no content: a Users Modify entry on it is
// repaired in place on standalone too, and the transaction runs.
func TestWindowsManagedRuntimeSelectorLockKeepsTheRepairOnStandalone(t *testing.T) {
	requireGAP633Elevated(t)
	_, lockPath := gap633SelectorFixture(t, true)
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stampGAP633SDDL(t, lockPath, gap633UsersModifyFile)
	called := false
	if err := withWindowsManagedRuntimeSelectorTransaction("codex", func() error {
		called = true
		return nil
	}); err != nil || !called {
		t.Fatalf("the selector transaction refused a drifted lock: called=%t err=%v", called, err)
	}
	if after := gap633Descriptor(t, lockPath); gap633UsersCanWrite(after) {
		t.Fatalf("the selector lock was not repaired: %s", after)
	}
}

// g582 review 3 M2: the Cursor rollback receipt (the hooks.json teardown
// restores for every Cursor user) is not re-stamped by a privileged
// snapshot on standalone; the read refuses it.
func TestWindowsCursorSnapshotStandaloneNeverRestampsAnUntrustedReceiptInPlace(t *testing.T) {
	requireGAP633Elevated(t)
	for _, standalone := range []bool{true, false} {
		name := "standalone"
		if !standalone {
			name = "twin: Secure Client"
		}
		t.Run(name, func(t *testing.T) {
			paths := installWindowsCursorStandaloneGuardForTest(t, `C:\Program Files\Cisco\DefenseClaw\defenseclaw-hook.exe`, true)
			if _, err := os.Lstat(paths.Receipt); err != nil {
				t.Fatalf("fixture has no rollback receipt: %v", err)
			}
			// Every reader judges the receipt's own descriptor.
			setGAP633Profile(t, standalone, windowsManagedPolicyLeafTrust(managed.ObjectInstallFile))
			stampGAP633SDDL(t, paths.Receipt, "O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1301bf;;;BU)")
			before := gap633Descriptor(t, paths.Receipt)

			_, _, err := ReadWindowsCursorManagedPolicyTargets()

			after := gap633Descriptor(t, paths.Receipt)
			if standalone {
				if after != before {
					t.Fatalf("the Cursor snapshot re-stamped an untrusted receipt in place: %s -> %s", before, after)
				}
				if err == nil || !strings.Contains(err.Error(), "untrusted Cursor rollback receipt") {
					t.Fatalf("the Cursor read did not refuse the untrusted receipt: %v", err)
				}
				return
			}
			if err != nil || gap633UsersCanWrite(after) {
				t.Fatalf("Secure Client: the receipt was not repaired (%s) or the read failed: %v", after, err)
			}
		})
	}
}

// g582 review 3 M3: a policy folder that holds a DefenseClaw marker and that
// an untrusted account can write is not taken over by the policy
// transaction the read-only Claude Code targets reader runs (the guardian
// calls it every pass); the read refuses it. A folder with no DefenseClaw
// file is still adopted, and Secure Client keeps the takeover.
func TestWindowsClaudeManagedPolicyReaderStandaloneNeverTakesOverAnUntrustedManagedFolder(t *testing.T) {
	requireGAP633Elevated(t)
	for _, standalone := range []bool{true, false} {
		name := "standalone"
		if !standalone {
			name = "twin: Secure Client"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
			if _, err := Install(context.Background(), windowsManagedInstallOptions(fixture)); err != nil {
				t.Fatal(err)
			}
			previousTransaction := windowsClaudeManagedPolicyTransaction
			previousStandalone := windowsManagedPolicySelfHealRefusesContentDrift
			windowsClaudeManagedPolicyTransaction = withWindowsClaudeManagedPolicyTransaction
			windowsManagedPolicySelfHealRefusesContentDrift = func() bool { return standalone }
			t.Cleanup(func() {
				windowsClaudeManagedPolicyTransaction = previousTransaction
				windowsManagedPolicySelfHealRefusesContentDrift = previousStandalone
			})
			folder := filepath.Dir(fixture.policyPath)
			state := filepath.Join(folder, windowsClaudeManagedStateFile)
			if _, err := os.Lstat(state); err != nil {
				t.Fatalf("fixture has no state record: %v", err)
			}
			if standalone {
				// The fixture's policy writer stamps the test account as
				// owner; in production it is Administrators, and only an
				// Administrators, SYSTEM or TrustedInstaller owned marker
				// counts (g582 review 5 S2). Secure Client never asks for a
				// marker, and its reader checks the fixture owner.
				stampGAP633SDDL(t, state, gap633CanonicalFile)
			}
			current := gap633Descriptor(t, folder)
			stampGAP633SDDL(t, folder, current[:strings.Index(current, "D:")]+"G:SY"+
				strings.Replace(current[strings.Index(current, "D:"):], ")", ")(A;OICI;0x1301bf;;;BU)", 1))
			before := gap633Descriptor(t, folder)
			if !gap633UsersCanWrite(before) {
				t.Fatalf("fixture drift was not applied: %s", before)
			}

			_, _, err := ReadWindowsClaudeManagedPolicyTargets()

			after := gap633Descriptor(t, folder)
			if standalone {
				if after != before {
					t.Fatalf("the Claude Code targets reader took over an untrusted managed folder: %s -> %s", before, after)
				}
				if !isGAP633Refusal(err) || !strings.Contains(err.Error(), windowsClaudeManagedStateFile) {
					t.Fatalf("the reader did not refuse the folder and name its marker: %v", err)
				}
				return
			}
			if err != nil || gap633UsersCanWrite(after) {
				t.Fatalf("Secure Client: the folder was not repaired (%s) or the read failed: %v", after, err)
			}
		})
	}
}

func TestWindowsManagedPolicyFolderWithoutAMarkerIsStillAdoptedOnStandalone(t *testing.T) {
	requireGAP633Elevated(t)
	setGAP633Profile(t, true, nil)
	previousDir, previousAncestor := windowsManagedPolicyDirTrustCheck, windowsManagedPolicyAncestorTrustCheck
	folderLeaf := windowsManagedPolicyLeafTrust(managed.ObjectInstallDirectory)
	windowsManagedPolicyDirTrustCheck, windowsManagedPolicyAncestorTrustCheck = folderLeaf, folderLeaf
	t.Cleanup(func() {
		windowsManagedPolicyDirTrustCheck, windowsManagedPolicyAncestorTrustCheck = previousDir, previousAncestor
	})
	folder := filepath.Join(t.TempDir(), "policy")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	// A vendor file is not a DefenseClaw marker.
	if err := os.WriteFile(filepath.Join(folder, "managed-settings.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	stampGAP633SDDL(t, folder, gap633UsersModifyFolder)
	if err := ensureWindowsManagedPolicyDirectory(folder); err != nil {
		t.Fatalf("a pre-created folder with no DefenseClaw file was refused: %v", err)
	}
	if after := gap633Descriptor(t, folder); gap633UsersCanWrite(after) {
		t.Fatalf("the pre-created folder was not adopted: %s", after)
	}
}
