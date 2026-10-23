// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// A save that lands after the requirements write compared the file, right
// before it swaps its file in, is caught by the compare-and-swap itself: the
// newer file is kept and the merge runs again on it.
func TestWindowsCodexMachineReconcileSwapKeepsASaveAfterTheComparison(t *testing.T) {
	opts := newWindowsCodexMachineGuardFixtureForTest(t, []byte(windowsCodexOperatorRequirementForTest))
	previous := windowsCodexMachineBeforeConditionalSwap
	t.Cleanup(func() { windowsCodexMachineBeforeConditionalSwap = previous })
	swaps := 0
	windowsCodexMachineBeforeConditionalSwap = func(path string) {
		if strings.EqualFold(path, opts.RequirementsPath) {
			swaps++
			if swaps == 1 {
				prependWindowsCodexRequirementForTest(t, opts.RequirementsPath, "admin_concurrent")
			}
		}
	}
	if report, err := ReconcileWindowsCodexMachineRequirements(opts); err != nil || !report.OK {
		t.Fatalf("reconcile: %+v err=%v", report, err)
	}
	if swaps != 2 {
		t.Fatalf("the reconcile swapped %d times; want a refused swap and a second merge", swaps)
	}
	requireWindowsCodexGuardForTest(t, opts, []WindowsCodexManagedRuntimeTarget{}, "allowed_sandbox_modes", "admin_concurrent")
}

// The conditional write refuses any other file than the one it was given,
// including a file that appeared or disappeared, and leaves it in place.
func TestWriteWindowsCodexMachineFileIfUnchangedRefusesAnotherFile(t *testing.T) {
	opts := newWindowsCodexMachineGuardFixtureForTest(t, nil)
	path := opts.RequirementsPath
	const limit = windowsCodexMachineRequirementsLimit
	const label = "Codex machine requirements"
	absent := windowsCodexStableFile{}
	if err := writeWindowsCodexMachineFileIfUnchanged(path, absent, []byte("ours = 1\n"), limit, label); err != nil {
		t.Fatalf("create over an absent file: %v", err)
	}
	ours := windowsCodexStableFile{existed: true, data: []byte("ours = 1\n")}
	for _, test := range []struct {
		name     string
		expected windowsCodexStableFile
		onDisk   []byte // nil: absent
	}{
		{"a different file", ours, []byte("admin = 1\n")},
		{"a file that appeared", absent, []byte("admin = 1\n")},
		{"a file that disappeared", ours, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.onDisk == nil {
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, test.onDisk, 0o600); err != nil {
				t.Fatal(err)
			}
			err := writeWindowsCodexMachineFileIfUnchanged(path, test.expected, []byte("render = 1\n"), limit, label)
			if !errors.Is(err, errWindowsCodexMachineFileChanged) {
				t.Fatalf("conditional write over %s: %v", test.name, err)
			}
			data, readErr := os.ReadFile(path)
			if test.onDisk == nil {
				if !os.IsNotExist(readErr) {
					t.Fatalf("the refused write created the file: %q %v", data, readErr)
				}
				return
			}
			if readErr != nil || string(data) != string(test.onDisk) {
				t.Fatalf("the refused write changed the file: %q %v", data, readErr)
			}
		})
	}
}
