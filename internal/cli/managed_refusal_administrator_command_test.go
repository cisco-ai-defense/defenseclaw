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
	"slices"
	"strings"
	"testing"
)

// managedRefusalInvocations are the argument lists the refusal of one table
// probe is read for: the probe alone, and the probe followed by each writer
// word the launcher audits for that command (config set, guardrail disable,
// skill block, ...), because a writer may be answered by other code than the
// bare command.
func managedRefusalInvocations(probe []string) [][]string {
	invocations := [][]string{probe}
	for verb := range launcherWriters[probe[0]] {
		if len(probe) == 1 {
			invocations = append(invocations, []string{probe[0], verb, "x"})
		}
	}
	slices.SortFunc(invocations, func(a, b []string) int { return strings.Compare(strings.Join(a, " "), strings.Join(b, " ")) })
	return invocations
}

// Every command the table marks Refused answers an enrolled standard user on a
// managed Windows computer the same way: the managed message, the
// administrator command that shows the deployment or the account's agents,
// and that nothing was changed. config set and config unset had their own
// sentence that named none; the table is walked, not the commands someone
// noticed.
func TestManagedWindowsRefusedCommandsNameAnAdministratorCommand(t *testing.T) {
	managedPerUserSeams(t, true)
	root, native := managedPerUserRoot()
	addManagedWindowsSetupAnswer(root)
	checked := 0
	for _, row := range managedCommands {
		if row.Windows != managedRefused {
			continue
		}
		for _, probe := range row.Probes {
			for _, args := range managedRefusalInvocations(probe) {
				var err error
				if args[0] == "config" {
					child, _, findErr := configCmd.Find(args[1:2])
					if findErr != nil || child == configCmd {
						t.Errorf("%v: no managed answer on the config command: %v", args, findErr)
						continue
					}
					err = child.RunE(child, args[2:])
				} else if native[args[0]] != nil {
					continue
				} else {
					root.SetArgs(args)
					err = root.Execute()
				}
				checked++
				if err == nil {
					t.Errorf("%v on a managed Windows computer gave no answer", args)
					continue
				}
				answer := err.Error()
				if !strings.Contains(answer, "managed") || !strings.HasSuffix(answer, "Nothing was changed.") {
					t.Errorf("%v: the answer is not the managed message that says nothing was changed: %s", args, answer)
				}
				if !slices.ContainsFunc([]string{"' enterprise windows status --profile standalone", "' enterprise policy show --user", "' policy show`"},
					func(command string) bool { return strings.Contains(answer, command) }) {
					t.Errorf("%v: the answer names no administrator command: %s", args, answer)
				}
				if problems := managedWindowsCommandProblems(answer); len(problems) > 0 {
					t.Errorf("%v names commands that do not run as typed %q: %s", args, problems, answer)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no refused command was checked")
	}
}

// The writer refusal keeps what a user needs to read first: which file is the
// administrator's and which command was refused, with the account in the
// command it hands on exactly as the other answers write it.
func TestManagedWindowsConfigWriterRefusalNamesTheCommandAndTheAccount(t *testing.T) {
	managedPerUserSeams(t, true)
	answer := managedWindowsConfigWriterRefusal("config unset").Error()
	for _, want := range []string{
		"This device is managed: change config.yaml in the admin config (MDM or management plane); config unset did not change it.",
		"' enterprise windows status --profile standalone",
		"' enterprise policy show --user dcuser",
		"Nothing was changed.",
	} {
		if !strings.Contains(answer, want) {
			t.Errorf("answer lacks %q: %s", want, answer)
		}
	}
}
