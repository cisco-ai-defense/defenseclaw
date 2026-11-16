// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile/sharedfiletest"
)

// Every DefenseClaw write of the shared Codex requirements.toml goes through
// the shared writer (windowsCodexRequirementsWriter), the one the Cursor
// hooks.json writes use. This is the same concurrency harness as the Cursor
// one: for setup, repair and both kinds of removal, an administrator changes
// requirements.toml (its bytes, its access list or an attribute) just before
// DefenseClaw's write or just after it lands. The change must be kept, the guard
// must end as promised, and a reader that watches the file throughout must
// never find it missing. (Codex has no rollback of requirements.toml: a
// reconcile or removal that meets a newer file computes its edit again.)

const windowsCodexSharedWriterAdminKey = "admin_concurrent"

func windowsCodexSharedWriterAdmin(opts WindowsCodexMachineRequirementsOptions) sharedfiletest.Admin {
	return sharedfiletest.Admin{
		Path: opts.RequirementsPath,
		Edit: func(data []byte) []byte {
			return append([]byte(windowsCodexSharedWriterAdminKey+" = true\n"), data...)
		},
		Kept: func(data []byte) bool { return bytes.Contains(data, []byte(windowsCodexSharedWriterAdminKey)) },
	}
}

// interleaveWindowsCodexSharedWriterForTest runs change just before
// DefenseClaw's first requirements.toml swap (before), or as soon as
// DefenseClaw's write has landed: the first time DefenseClaw checks the file
// after its managed hooks appeared in it or went from it.
func interleaveWindowsCodexSharedWriterForTest(t *testing.T, opts WindowsCodexMachineRequirementsOptions, before bool, change func()) *bool {
	t.Helper()
	path := opts.RequirementsPath
	guarded := func() bool {
		data, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		contains, err := windowsCodexRequirementsContainExactManagedHook(data, opts)
		return err == nil && contains
	}
	initial := guarded()
	changed := false
	previousSwap, previousTrust := windowsCodexMachineBeforeConditionalSwap, windowsCodexMachineTrustedFileCheck
	windowsCodexMachineBeforeConditionalSwap = func(swapPath string) {
		if before && !changed && strings.EqualFold(swapPath, path) {
			changed = true
			change()
		}
		previousSwap(swapPath)
	}
	windowsCodexMachineTrustedFileCheck = func(checked, label string) error {
		if !before && !changed && strings.EqualFold(checked, path) && guarded() != initial {
			changed = true
			change()
		}
		return previousTrust(checked, label)
	}
	t.Cleanup(func() {
		windowsCodexMachineBeforeConditionalSwap, windowsCodexMachineTrustedFileCheck = previousSwap, previousTrust
	})
	return &changed
}

func TestWindowsCodexSharedWriterKeepsConcurrentAdministratorChanges(t *testing.T) {
	type op struct {
		name    string
		prepare func(t *testing.T, opts WindowsCodexMachineRequirementsOptions)
		run     func(opts WindowsCodexMachineRequirementsOptions) error
		guarded bool
	}
	reconcile := func(opts WindowsCodexMachineRequirementsOptions) error {
		report, err := ReconcileWindowsCodexMachineRequirements(opts)
		if err == nil && !report.OK {
			err = errors.New("reconcile did not report OK")
		}
		return err
	}
	remove := func(opts WindowsCodexMachineRequirementsOptions) error {
		report, err := RemoveWindowsCodexMachineRequirements(opts)
		if err == nil && (!report.OK || !report.SafeToRemoveBinary) {
			err = errors.New("removal did not finish")
		}
		return err
	}
	install := func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) {
		if err := reconcile(opts); err != nil {
			t.Fatalf("install the configured guard: %v", err)
		}
	}
	ops := []op{
		{name: "setup", prepare: func(*testing.T, WindowsCodexMachineRequirementsOptions) {}, run: reconcile, guarded: true},
		{name: "repair", prepare: func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) {
			install(t, opts)
			sharedfiletest.Admin{Path: opts.RequirementsPath, Edit: func([]byte) []byte {
				return []byte(windowsCodexOperatorRequirementForTest)
			}}.Apply(t, sharedfiletest.Content)
		}, run: reconcile, guarded: true},
		{name: "removal restores the preimage", prepare: install, run: remove},
		{name: "removal keeps a later edit", prepare: func(t *testing.T, opts WindowsCodexMachineRequirementsOptions) {
			install(t, opts)
			sharedfiletest.Admin{Path: opts.RequirementsPath, Edit: func(data []byte) []byte {
				return append([]byte("admin_earlier = true\n"), data...)
			}}.Apply(t, sharedfiletest.Content)
		}, run: remove},
	}
	for _, test := range ops {
		for _, change := range sharedfiletest.Changes {
			for _, before := range []bool{true, false} {
				timing := map[bool]string{true: "before", false: "after"}[before]
				t.Run(test.name+"/"+string(change)+" "+timing, func(t *testing.T) {
					opts := newWindowsCodexMachineGuardFixtureForTest(t, []byte(windowsCodexOperatorRequirementForTest))
					test.prepare(t, opts)
					admin := windowsCodexSharedWriterAdmin(opts)
					changed := interleaveWindowsCodexSharedWriterForTest(t, opts, before, func() { admin.Apply(t, change) })
					watch := sharedfiletest.StartWatch(func() error {
						_, exists, err := sharedfiletest.ReadShared(opts.RequirementsPath)
						if err == nil && !exists {
							return errors.New("requirements.toml was missing")
						}
						return nil
					})
					err := test.run(opts)
					watchErr := watch.Stop()
					if err != nil {
						t.Fatalf("operation: %v", err)
					}
					if !*changed {
						t.Fatal("fixture: the administrator's change did not land")
					}
					if watchErr != nil {
						t.Fatalf("watch: %v", watchErr)
					}
					admin.RequireKept(t, change)
					if test.guarded {
						keys := []string{"allowed_sandbox_modes"}
						if change == sharedfiletest.Content {
							keys = append(keys, windowsCodexSharedWriterAdminKey)
						}
						requireWindowsCodexGuardForTest(t, opts, []WindowsCodexManagedRuntimeTarget{}, keys...)
						return
					}
					data, _, err := sharedfiletest.ReadShared(opts.RequirementsPath)
					if err != nil {
						t.Fatal(err)
					}
					if contains, err := windowsCodexRequirementsContainExactManagedHook(data, opts); err != nil || contains {
						t.Fatalf("the removal left DefenseClaw's managed hooks (err %v):\n%s", err, data)
					}
					if !bytes.Contains(data, []byte("allowed_sandbox_modes")) {
						t.Fatalf("the removal lost the administrator's requirement:\n%s", data)
					}
				})
			}
		}
	}
}
