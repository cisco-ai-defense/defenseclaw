// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
)

// Removal of the Codex machine guard (uninstall, or configured Codex with no
// enrolled account being turned off) rewrites or deletes the shared
// requirements.toml. An administrator does not take the DefenseClaw lock, so
// a requirement saved while the removal runs must be kept: the write or
// delete is a compare-and-swap against the file the removal was computed
// from, and on a change the removal is computed again from the newer file.

type windowsCodexRemovalRowForTest struct {
	name string
	// requirements is the administrator's file before the install; nil for
	// none, so the removal deletes the file DefenseClaw created.
	requirements []byte
	// editAfterInstall adds a requirement after the install, so the removal
	// takes DefenseClaw's lines out instead of restoring the preimage.
	editAfterInstall bool
	// keys must survive the removal, with admin_concurrent.
	keys []string
}

var windowsCodexRemovalRowsForTest = []windowsCodexRemovalRowForTest{
	{name: "restore the preimage", requirements: []byte(windowsCodexOperatorRequirementForTest), keys: []string{"allowed_sandbox_modes"}},
	{name: "delete the file DefenseClaw created"},
	{name: "remove DefenseClaw's lines from an edited file", requirements: []byte(windowsCodexOperatorRequirementForTest), editAfterInstall: true, keys: []string{"allowed_sandbox_modes", "admin_earlier"}},
}

// installWindowsCodexGuardForRemovalTest installs the configured guard with
// no enrolled account, as the empty-enrollment activation leaves it.
func installWindowsCodexGuardForRemovalTest(t *testing.T, row windowsCodexRemovalRowForTest) WindowsCodexMachineRequirementsOptions {
	t.Helper()
	opts := newWindowsCodexMachineGuardFixtureForTest(t, row.requirements)
	if report, err := ReconcileWindowsCodexMachineRequirements(opts); err != nil || !report.OK {
		t.Fatalf("install the configured guard: %+v err=%v", report, err)
	}
	if row.requirements != nil {
		requireWindowsCodexGuardForTest(t, opts, []WindowsCodexManagedRuntimeTarget{}, "allowed_sandbox_modes")
	} else {
		requireWindowsCodexGuardForTest(t, opts, []WindowsCodexManagedRuntimeTarget{})
	}
	if row.editAfterInstall {
		prependWindowsCodexRequirementForTest(t, opts.RequirementsPath, "admin_earlier")
	}
	return opts
}

// saveOnWindowsCodexRequirementsCheckForTest runs save on each check of the
// requirements file for which when reports true. call counts the checks from
// here on: the removal reads the file on the first, and checks it again on
// the second, just before it writes or deletes it.
func saveOnWindowsCodexRequirementsCheckForTest(
	t *testing.T,
	opts WindowsCodexMachineRequirementsOptions,
	when func(call int) bool,
	save func(),
) {
	t.Helper()
	previous := windowsCodexMachineTrustedFileCheck
	call := 0
	windowsCodexMachineTrustedFileCheck = func(path, label string) error {
		if strings.EqualFold(path, opts.RequirementsPath) {
			call++
			if when(call) {
				save()
			}
		}
		return previous(path, label)
	}
	t.Cleanup(func() { windowsCodexMachineTrustedFileCheck = previous })
}

func requireWindowsCodexGuardRemovedForTest(
	t *testing.T,
	opts WindowsCodexMachineRequirementsOptions,
	report WindowsCodexMachineRequirementsReport,
	err error,
	keys ...string,
) {
	t.Helper()
	if err != nil || !report.OK || !report.SafeToRemoveBinary {
		t.Fatalf("remove: %+v err=%v", report, err)
	}
	requirements, readErr := os.ReadFile(opts.RequirementsPath)
	if readErr != nil {
		t.Fatalf("the removal deleted the administrator's saved requirements: %v", readErr)
	}
	for _, key := range keys {
		if !bytes.Contains(requirements, []byte(key)) {
			t.Fatalf("the removal lost the administrator's %q:\n%s", key, requirements)
		}
	}
	if contains, containsErr := windowsCodexRequirementsContainExactManagedHook(requirements, opts); containsErr != nil || contains {
		t.Fatalf("DefenseClaw's managed hooks remain after removal (err %v):\n%s", containsErr, requirements)
	}
	if references, refErr := windowsCodexOwnedPathReferenceCount(requirements, opts); refErr != nil || references != 0 {
		t.Fatalf("%d references to the DefenseClaw install remain (err %v):\n%s", references, refErr, requirements)
	}
	for _, path := range []string{opts.OwnershipPath, opts.ManagedStatePath} {
		if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
			t.Fatalf("a committed removal left %s: %v", path, statErr)
		}
	}
}

// A save after the removal read the requirements and before it writes or
// deletes them is kept, for each way the removal ends.
func TestWindowsCodexMachineRemovalKeepsAConcurrentRequirement(t *testing.T) {
	for _, row := range windowsCodexRemovalRowsForTest {
		t.Run(row.name, func(t *testing.T) {
			opts := installWindowsCodexGuardForRemovalTest(t, row)
			saved := false
			saveOnWindowsCodexRequirementsCheckForTest(t, opts, func(call int) bool { return call == 2 && !saved }, func() {
				saved = true
				prependWindowsCodexRequirementForTest(t, opts.RequirementsPath, "admin_concurrent")
			})
			report, err := RemoveWindowsCodexMachineRequirements(opts)
			if !saved {
				t.Fatal("fixture: the removal did not race the save")
			}
			requireWindowsCodexGuardRemovedForTest(t, opts, report, err, append([]string{"admin_concurrent"}, row.keys...)...)
		})
	}
}

// A save after the comparison, just before the replacement or deletion, is
// caught by the compare-and-swap itself.
func TestWindowsCodexMachineRemovalSwapKeepsASaveAfterTheComparison(t *testing.T) {
	for _, row := range windowsCodexRemovalRowsForTest {
		t.Run(row.name, func(t *testing.T) {
			opts := installWindowsCodexGuardForRemovalTest(t, row)
			saved := false
			previous := windowsCodexMachineBeforeConditionalSwap
			windowsCodexMachineBeforeConditionalSwap = func(path string) {
				if !saved && strings.EqualFold(path, opts.RequirementsPath) {
					saved = true
					prependWindowsCodexRequirementForTest(t, opts.RequirementsPath, "admin_concurrent")
				}
				previous(path)
			}
			t.Cleanup(func() { windowsCodexMachineBeforeConditionalSwap = previous })
			report, err := RemoveWindowsCodexMachineRequirements(opts)
			if !saved {
				t.Fatal("fixture: the removal did not race the save at its swap")
			}
			requireWindowsCodexGuardRemovedForTest(t, opts, report, err, append([]string{"admin_concurrent"}, row.keys...)...)
		})
	}
}

// A save right after the removal published its candidate is kept, and the
// removal still commits: it is computed again from the newer file, which no
// longer holds anything DefenseClaw owns.
func TestWindowsCodexMachineRemovalKeepsASaveAfterItsWrite(t *testing.T) {
	for _, row := range windowsCodexRemovalRowsForTest {
		if row.requirements == nil {
			continue // the removal deletes the file; nothing is published
		}
		t.Run(row.name, func(t *testing.T) {
			opts := installWindowsCodexGuardForRemovalTest(t, row)
			start, err := os.ReadFile(opts.RequirementsPath)
			if err != nil {
				t.Fatal(err)
			}
			saved := false
			saveOnWindowsCodexRequirementsCheckForTest(t, opts, func(int) bool {
				if saved {
					return false
				}
				onDisk, readErr := os.ReadFile(opts.RequirementsPath)
				return readErr == nil && !bytes.Equal(onDisk, start)
			}, func() {
				saved = true
				prependWindowsCodexRequirementForTest(t, opts.RequirementsPath, "admin_concurrent")
			})
			report, err := RemoveWindowsCodexMachineRequirements(opts)
			if !saved {
				t.Fatal("fixture: the save did not land after the removal's write")
			}
			requireWindowsCodexGuardRemovedForTest(t, opts, report, err, append([]string{"admin_concurrent"}, row.keys...)...)
		})
	}
}

// An administrator who keeps saving: the removal gives up after a bounded
// number of attempts, keeps the last save and keeps its ownership record and
// runtime state (so the installer keeps the hook binary), and the next quiet
// removal commits with every save.
func TestWindowsCodexMachineRemovalStopsAgainstAWriterThatNeverStops(t *testing.T) {
	row := windowsCodexRemovalRowsForTest[0]
	opts := installWindowsCodexGuardForRemovalTest(t, row)
	saves := 0
	saveOnWindowsCodexRequirementsCheckForTest(t, opts, func(call int) bool { return call >= 2 && saves < 100 }, func() {
		saves++
		prependWindowsCodexRequirementForTest(t, opts.RequirementsPath, fmt.Sprintf("admin_save_%d", saves))
	})
	report, err := RemoveWindowsCodexMachineRequirements(opts)
	if err == nil || report.OK || report.SafeToRemoveBinary || !strings.Contains(err.Error(), "changed concurrently") {
		t.Fatalf("removal against a writer that never stops: %+v err=%v", report, err)
	}
	if saves < 2 || saves > 10 {
		t.Fatalf("the removal ran with %d saves; want a small bounded number of attempts", saves)
	}
	last := []byte(fmt.Sprintf("admin_save_%d", saves))
	if data, readErr := os.ReadFile(opts.RequirementsPath); readErr != nil || !bytes.Contains(data, last) || !bytes.Contains(data, []byte("allowed_sandbox_modes")) {
		t.Fatalf("the removal did not keep the last save (err %v):\n%s", readErr, data)
	}
	for _, path := range []string{opts.OwnershipPath, opts.ManagedStatePath} {
		if _, statErr := os.Lstat(path); statErr != nil {
			t.Fatalf("a stopped removal dropped %s: %v", path, statErr)
		}
	}
	windowsCodexMachineTrustedFileCheck = func(string, string) error { return nil }
	report, err = RemoveWindowsCodexMachineRequirements(opts)
	keys := []string{"allowed_sandbox_modes"}
	for save := 1; save <= saves; save++ {
		keys = append(keys, fmt.Sprintf("admin_save_%d", save))
	}
	requireWindowsCodexGuardRemovedForTest(t, opts, report, err, keys...)
}
