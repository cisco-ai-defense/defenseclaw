// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestMachinePolicyPresentTracksOwnedEntries(t *testing.T) {
	opts := publishTestOptions(t)
	installTestOpenCodePlugin(t, &opts)
	connectors := []string{"claudecode", "codex", "copilot", "cursor", "devin", "opencode"}
	machine := []string{"claudecode", "codex", "copilot", "cursor", "opencode"}
	for _, name := range connectors {
		if present, err := MachinePolicyPresent(opts, name); err != nil || present {
			t.Fatalf("%s before publish: present=%v err=%v", name, present, err)
		}
	}
	result, err := Publish(opts, connectors)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.MachinePolicyConnectors, machine) {
		t.Fatalf("descriptor set = %v, want %v", result.MachinePolicyConnectors, machine)
	}
	for _, name := range machine {
		if present, err := MachinePolicyPresent(opts, name); err != nil || !present {
			t.Fatalf("%s after publish: present=%v err=%v", name, present, err)
		}
	}
	if present, _ := MachinePolicyPresent(opts, "devin"); present {
		t.Fatal("a per-user connector has no machine policy")
	}

	path, _ := CodexRequirementsPath(opts)
	writeFile(t, path, "[hooks\n")
	if _, err := MachinePolicyPresent(opts, "codex"); err == nil {
		t.Fatal("an unparsable requirements file must be an error, not absent")
	}
	verify, _ := VerifyAll(opts, connectors)
	if reflect.DeepEqual(verify.MachinePolicyConnectors, machine) {
		t.Fatalf("a broken Codex file must drop codex from the reconciled set: %v", verify.MachinePolicyConnectors)
	}

	if _, err := RemoveAll(opts); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"claudecode", "copilot", "cursor", "opencode"} {
		if present, err := MachinePolicyPresent(opts, name); err != nil || present {
			t.Fatalf("%s after removal: present=%v err=%v", name, present, err)
		}
	}
}

func TestMachinePolicyMayRemainFailsClosedOnLeftovers(t *testing.T) {
	opts := testOptions(t)
	if MachinePolicyMayRemain(opts, "codex") || MachinePolicyMayRemain(opts, "amp") {
		t.Fatal("a clean host has no leftover machine policy")
	}
	path, _ := CodexRequirementsPath(opts)
	writeFile(t, path, "[[hooks.PreToolUse]]\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"'"+testHookBinary+"' hook --connector codex\"\ntimeout = 1\n")
	if present, _ := MachinePolicyPresent(opts, "codex"); present {
		t.Fatal("a drifted entry is not an exact DefenseClaw registration")
	}
	if !MachinePolicyMayRemain(opts, "codex") {
		t.Fatal("a drifted entry naming the hook binary must keep the hook fail-closed")
	}
	writeFile(t, path, "[hooks\n")
	if !MachinePolicyMayRemain(opts, "codex") {
		t.Fatal("an unparsable requirements file must keep the hook fail-closed")
	}
	dir, _ := CopilotPolicyDir(opts)
	writeFile(t, filepath.Join(dir, DefenseClawDropInName), "{}")
	if !MachinePolicyMayRemain(opts, "copilot") {
		t.Fatal("DefenseClaw's own drop-in, even emptied, is DefenseClaw policy")
	}
}
