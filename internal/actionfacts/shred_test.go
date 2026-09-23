// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestShredMultipleFileRemovalProjectsExactDeleteFacts(t *testing.T) {
	facts := Analyze(Input{
		Tool:    "shell",
		Command: "shred -u /home/alice/project/.env /home/alice/project/config/secrets.yaml /home/alice/project/credentials.json",
	})
	if facts.Parse.Status != StatusComplete || len(facts.Commands) != 1 {
		t.Fatalf("facts = %+v", facts)
	}
	command := facts.Commands[0]
	if !commandHasOperation(command, OperationWrite) || !commandHasOperation(command, OperationDelete) {
		t.Fatalf("operations = %v", command.Operations)
	}
	if len(facts.Paths) != 3 {
		t.Fatalf("paths = %+v", facts.Paths)
	}
	for _, path := range facts.Paths {
		if path.CommandID != command.ID || path.Access != PathAccessDelete || !path.Absolute {
			t.Fatalf("path = %+v", path)
		}
	}
}

func TestShredWithoutRemovalProjectsOverwriteOnly(t *testing.T) {
	facts := Analyze(Input{Tool: "shell", Command: "shred -n 2 /tmp/fixture.bin"})
	if facts.Parse.Status != StatusComplete || len(facts.Commands) != 1 || len(facts.Paths) != 1 {
		t.Fatalf("facts = %+v", facts)
	}
	command := facts.Commands[0]
	if !commandHasOperation(command, OperationWrite) || commandHasOperation(command, OperationDelete) ||
		facts.Paths[0].Access != PathAccessWrite {
		t.Fatalf("facts = %+v", facts)
	}
}

func TestShredRetainsRawDeviceWipeSemantics(t *testing.T) {
	facts := Analyze(Input{Tool: "shell", Command: "shred -n 1 /dev/sda"})
	if facts.Parse.Status != StatusComplete || len(facts.Commands) != 1 || len(facts.Paths) != 1 {
		t.Fatalf("facts = %+v", facts)
	}
	if !commandHasOperation(facts.Commands[0], OperationDiskWrite) ||
		facts.Paths[0].Access != PathAccessWrite {
		t.Fatalf("facts = %+v", facts)
	}
}

func TestShredMixedDeviceAndFileOperandsAbstains(t *testing.T) {
	facts := Analyze(Input{Tool: "shell", Command: "shred -u /dev/sda /tmp/fixture.bin"})
	if facts.Parse.Status != StatusPartial {
		t.Fatalf("parse status = %q, want partial: %+v", facts.Parse.Status, facts)
	}
}
