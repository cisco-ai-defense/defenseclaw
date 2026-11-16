// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/safefile/sharedfiletest"
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

// The shared requirements write refuses any other file than the one it was
// given, including a file that appeared or disappeared and one whose access
// list changed, and leaves it in place.
func TestPublishWindowsCodexRequirementsRefusesAnotherFile(t *testing.T) {
	opts := newWindowsCodexMachineGuardFixtureForTest(t, nil)
	path := opts.RequirementsPath
	absent := safefile.SharedFile{Path: path}
	if err := publishWindowsCodexRequirements(absent, []byte("ours = 1\n"), false); err != nil {
		t.Fatalf("create over an absent file: %v", err)
	}
	ours, err := readWindowsCodexSharedRequirements(path)
	if err != nil || !ours.Exists {
		t.Fatalf("read the created file: %+v err=%v", ours, err)
	}
	for _, test := range []struct {
		name     string
		expected safefile.SharedFile
		onDisk   []byte // nil: absent
		acl      bool
	}{
		{name: "a different file", expected: ours, onDisk: []byte("admin = 1\n")},
		{name: "a file that appeared", expected: absent, onDisk: []byte("admin = 1\n")},
		{name: "a file that disappeared", expected: ours},
		{name: "a changed access list", expected: ours, onDisk: []byte("ours = 1\n"), acl: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.onDisk == nil {
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, test.onDisk, 0o600); err != nil {
				t.Fatal(err)
			}
			if test.acl {
				sharedfiletest.GrantBackupOperatorsRead(t, path)
			}
			// A removal over an absent file changes nothing and is not written.
			for _, remove := range []bool{false, test.expected.Exists} {
				err := publishWindowsCodexRequirements(test.expected, []byte("render = 1\n"), remove)
				if !errors.Is(err, errWindowsCodexMachineFileChanged) {
					t.Fatalf("conditional write (remove %t) over %s: %v", remove, test.name, err)
				}
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
			if test.acl {
				sharedfiletest.RequireBackupOperatorsRead(t, path)
			}
		})
	}
}
