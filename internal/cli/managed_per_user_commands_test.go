// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// managedPerUserSeams makes this process a managed Windows computer (or not)
// for the test, as TestManagedWindowsSetupAnswer does.
func managedPerUserSeams(t *testing.T, managedHost bool) string {
	t.Helper()
	where := `HKLM\SOFTWARE\Cisco\DefenseClaw\Enterprise`
	restore, restoreAccount, restoreReport := managedHostWindowsStandalone, managedHostCurrentAccount, reportManagedCommandRefusal
	t.Cleanup(func() {
		managedHostWindowsStandalone, managedHostCurrentAccount, reportManagedCommandRefusal = restore, restoreAccount, restoreReport
	})
	managedHostWindowsStandalone = func() (string, bool) { return where, managedHost }
	managedHostCurrentAccount = func() string { return `HOST\dcuser` }
	reportManagedCommandRefusal = func(string, string) {}
	return where
}

// managedPerUserRoot is a root like the installed managed Windows binary's: the
// real pre-run, and the commands that binary serves itself.
func managedPerUserRoot() (*cobra.Command, map[string]*cobra.Command) {
	root := &cobra.Command{Use: "defenseclaw", PersistentPreRunE: rootPersistentPreRunE}
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	native := map[string]*cobra.Command{}
	for _, name := range []string{"status", "audit", "config", "policy", "sandbox"} {
		native[name] = &cobra.Command{Use: name, RunE: func(*cobra.Command, []string) error { return nil }}
		root.AddCommand(native[name])
	}
	return root, native
}

// GAP-0795: `defenseclaw alerts` as an enrolled standard user on a managed
// Windows computer printed the generic unknown-command usage (rc 2) and named
// no administrator command, while doctor and upgrade did. The class is every
// command of the per-user CLI, so this runs the whole per-user command table:
// each one the binary does not serve itself gets the managed sentence, the
// administrator commands and doctor's exit code, with or without arguments
// and with --help.
func TestManagedWindowsAnswersEveryPerUserCommand(t *testing.T) {
	where := managedPerUserSeams(t, true)
	root, native := managedPerUserRoot()
	addManagedWindowsPerUserAnswers(root, where)
	root.SetArgs([]string{"doctor"})
	doctorRC := executeResult(root, root.Execute())
	if doctorRC != 1 {
		t.Fatalf("doctor exit code %d, want 1", doctorRC)
	}
	for _, name := range perUserCommands() {
		if served, ok := native[name]; ok {
			if found, _, err := root.Find([]string{name}); err != nil || found != served {
				t.Errorf("%s: the command the binary serves was replaced by an answer", name)
			}
			continue
		}
		for _, args := range [][]string{{name}, {name, "--json"}, {name, "list", "--limit", "5"}} {
			root.SetArgs(args)
			err := root.Execute()
			if err == nil {
				t.Errorf("%v on a managed Windows computer gave no answer", args)
				continue
			}
			answer := err.Error()
			for _, want := range []string{
				"managed by your organization",
				// The administrator commands, as typed in PowerShell.
				"' enterprise windows status --profile standalone",
				"' enterprise policy show --user",
				"Nothing was changed.",
			} {
				if !strings.Contains(answer, want) {
					t.Errorf("%v: answer lacks %q: %s", args, want, answer)
				}
			}
			if strings.Contains(answer, "unknown command") || strings.Contains(answer, "Usage:") {
				t.Errorf("%v: generic usage instead of the managed answer: %s", args, answer)
			}
			if problems := managedWindowsCommandProblems(answer); len(problems) > 0 {
				t.Errorf("%v names commands that do not run as typed %q: %s", args, problems, answer)
			}
			if rc := executeResult(root, err); rc != doctorRC {
				t.Errorf("%v exit code %d, want doctor's %d", args, rc, doctorRC)
			}
		}
		var out strings.Builder
		root.SetOut(&out)
		root.SetArgs([]string{name, "--help"})
		if err := root.Execute(); err != nil || !strings.Contains(out.String(), "managed by your organization") {
			t.Errorf("%s --help: err %v, output %q", name, err, out.String())
		}
		root.SetOut(io.Discard)
	}
}

// The installed binary's whole root: no word of the per-user CLI is left as
// the generic unknown-command usage, whichever code answers it.
func TestManagedWindowsRootLeavesNoPerUserCommandUnknown(t *testing.T) {
	managedPerUserSeams(t, true)
	root, native := managedPerUserRoot()
	addManagedWindowsSetupAnswer(root)
	for _, name := range perUserCommands() {
		if native[name] != nil {
			continue
		}
		root.SetArgs([]string{name})
		err := root.Execute()
		if err == nil || strings.Contains(err.Error(), "unknown command") || !strings.Contains(strings.ToLower(err.Error()), "managed") {
			t.Errorf("%s on a managed Windows computer: %v", name, err)
		}
	}
}

// The twins: a word that is no per-user command is still an unknown command
// (rc 2), and a host that is not a managed Windows computer gets no managed
// answers.
func TestManagedWindowsKeepsUnknownCommandsUnknown(t *testing.T) {
	where := managedPerUserSeams(t, true)
	root, _ := managedPerUserRoot()
	addManagedWindowsPerUserAnswers(root, where)
	root.SetArgs([]string{"frobnicate"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), `unknown command "frobnicate"`) || strings.Contains(err.Error(), "managed by your organization") {
		t.Fatalf("an unknown word on a managed Windows computer: %v", err)
	}
	if rc := executeResult(root, err); rc != 2 {
		t.Fatalf("an unknown word exit code %d, want 2", rc)
	}

	managedPerUserSeams(t, false)
	other, _ := managedPerUserRoot()
	addManagedWindowsSetupAnswer(other)
	if slices.ContainsFunc(other.Commands(), func(c *cobra.Command) bool { return c.Name() == "alerts" }) {
		t.Fatal("a host that is not a managed Windows computer got the per-user command answers")
	}
}

func TestPerUserCommandTableIsSortedAndUnique(t *testing.T) {
	names := perUserCommands()
	if !slices.IsSorted(names) || len(slices.Compact(slices.Clone(names))) != len(names) {
		t.Fatalf("embed/per-user-commands.json is not sorted and unique: %v", names)
	}
	for _, name := range []string{"alerts", "doctor", "tui", "upgrade"} {
		if !slices.Contains(names, name) {
			t.Errorf("per-user command %q missing from the table", name)
		}
	}
}
