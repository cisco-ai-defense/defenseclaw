// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// The Windows machine policy must not register afterAgentThought: the Cursor
// Agent CLI awaits a ~1.2 s PowerShell hook per streamed reasoning chunk and
// the server drops the stalled stream.
func TestWindowsCursorEnterpriseHookEventsOmitAfterAgentThought(t *testing.T) {
	want := []string{
		"sessionStart", "sessionEnd", "preToolUse", "postToolUse",
		"postToolUseFailure", "subagentStart", "subagentStop",
		"beforeShellExecution", "beforeMCPExecution", "afterShellExecution",
		"afterMCPExecution", "beforeReadFile", "beforeTabFileRead",
		"afterFileEdit", "afterTabFileEdit", "beforeSubmitPrompt",
		"afterAgentResponse", "stop", "preCompact", "workspaceOpen",
	}
	if !reflect.DeepEqual(cursorEnterpriseHookEvents, want) {
		t.Fatalf("cursorEnterpriseHookEvents = %v, want %v", cursorEnterpriseHookEvents, want)
	}
	if !reflect.DeepEqual(cursorEnterpriseRetiredHookEvents, []string{"afterAgentThought"}) {
		t.Fatalf("retired events = %v", cursorEnterpriseRetiredHookEvents)
	}
	// The user-level (OSS) roster and the contract's supported events keep it.
	if !containsString(cursorHookEvents, "afterAgentThought") || len(cursorHookEvents) != 21 {
		t.Fatalf("user-level Cursor roster changed: %v", cursorHookEvents)
	}
	contract := resolveHookContractForOS("cursor", "", "windows").Contract
	if !containsString(contract.Events, "afterAgentThought") {
		t.Fatalf("Cursor contract %s no longer lists afterAgentThought as supported", contract.ContractID)
	}
	for _, event := range contract.Capabilities.BlockEvents {
		if !cursorHookEventManaged(event) {
			t.Fatalf("machine policy dropped block event %s", event)
		}
	}

	merged, err := MergeWindowsCursorEnterpriseHooks(nil, testWindowsCursorAdapter, "closed")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := decodeCursorHooksJSON(merged)
	if err != nil {
		t.Fatal(err)
	}
	hooks := cfg["hooks"].(map[string]interface{})
	if _, exists := hooks["afterAgentThought"]; exists {
		t.Fatalf("machine hooks.json registers afterAgentThought:\n%s", merged)
	}
	if len(hooks) != len(want) {
		t.Fatalf("machine hooks.json has %d events, want %d", len(hooks), len(want))
	}

	groups, err := ManagedHookGroupsForOS("cursor", "", "windows")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != len(want) {
		t.Fatalf("windows Cursor machine groups = %d, want %d", len(groups), len(want))
	}
	for i, group := range groups {
		if group.Event != want[i] {
			t.Fatalf("windows Cursor machine group %d = %s, want %s", i, group.Event, want[i])
		}
	}
	darwin, err := ManagedHookGroupsForOS("cursor", "", "darwin")
	if err != nil {
		t.Fatal(err)
	}
	if len(darwin) != len(cursorHookEvents) {
		t.Fatalf("non-Windows Cursor machine groups = %d, want %d", len(darwin), len(cursorHookEvents))
	}
}

// windowsCursorPreRetirementHooks renders the hooks.json an earlier release
// wrote: the current roster plus one DefenseClaw entry on afterAgentThought,
// after any foreign afterAgentThought entries.
func windowsCursorPreRetirementHooks(t *testing.T, base []byte, command string, foreign ...interface{}) []byte {
	t.Helper()
	merged, err := MergeWindowsCursorEnterpriseHooks(base, testWindowsCursorAdapter, "closed")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := decodeCursorHooksJSON(merged)
	if err != nil {
		t.Fatal(err)
	}
	hooks := cfg["hooks"].(map[string]interface{})
	if command != "" {
		for _, event := range cursorEnterpriseHookEvents {
			entries := hooks[event].([]interface{})
			entries[len(entries)-1].(map[string]interface{})["command"] = command
		}
	} else {
		command, _, err = windowsCursorEnterpriseHookCommands(testWindowsCursorAdapter)
		if err != nil {
			t.Fatal(err)
		}
	}
	hooks["afterAgentThought"] = append(append([]interface{}{}, foreign...),
		windowsCursorEnterpriseHookEntry(command))
	body, err := encodeCursorHooksJSON(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestWindowsCursorEnterpriseRepairsPreRetirementAfterAgentThought(t *testing.T) {
	current, _, err := windowsCursorEnterpriseHookCommands(testWindowsCursorAdapter)
	if err != nil {
		t.Fatal(err)
	}
	foreign := map[string]interface{}{"type": "command", "command": "operator-thought-hook"}

	for name, tc := range map[string]struct {
		original []byte
		command  string
		foreign  []interface{}
	}{
		"current_command":            {},
		"previous_encoded_command":   {command: previousWindowsCursorEnterpriseHookCommand(testWindowsCursorAdapter)},
		"preexisting_operator_hooks": {original: []byte(`{"version":1,"operator":true,"hooks":{"afterAgentThought":[{"type":"command","command":"operator-thought-hook"}]}}`), foreign: []interface{}{foreign}},
	} {
		t.Run(name, func(t *testing.T) {
			legacy := windowsCursorPreRetirementHooks(t, tc.original, tc.command, tc.foreign...)

			// Readers that gate a protected pre-upgrade policy (artifact
			// validation, lifecycle snapshot restore, hook presence) accept it.
			if err := VerifyWindowsCursorEnterpriseHooksForMigration(legacy, testWindowsCursorAdapter, "closed"); err != nil {
				t.Fatalf("migration verifier refused the pre-retirement policy: %v", err)
			}
			if tc.command == "" {
				if err := VerifyWindowsCursorEnterpriseHooksRegistered(legacy, testWindowsCursorAdapter, "closed"); err != nil {
					t.Fatalf("presence verifier refused the pre-retirement policy: %v", err)
				}
			}
			// Strict verification flags it, so reconcile rewrites the file.
			err := VerifyWindowsCursorEnterpriseHooks(legacy, testWindowsCursorAdapter, "closed")
			if err == nil || (tc.command == "" && !strings.Contains(err.Error(), "afterAgentThought")) {
				t.Fatalf("strict verifier error = %v, want an afterAgentThought finding", err)
			}

			repaired, err := MergeWindowsCursorEnterpriseHooks(legacy, testWindowsCursorAdapter, "closed")
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyWindowsCursorEnterpriseHooks(repaired, testWindowsCursorAdapter, "closed"); err != nil {
				t.Fatalf("repaired policy failed strict verification: %v\n%s", err, repaired)
			}
			again, err := MergeWindowsCursorEnterpriseHooks(repaired, testWindowsCursorAdapter, "closed")
			if err != nil || !bytes.Equal(again, repaired) {
				t.Fatalf("repair is not byte-idempotent: %v", err)
			}
			cfg, err := decodeCursorHooksJSON(repaired)
			if err != nil {
				t.Fatal(err)
			}
			hooks := cfg["hooks"].(map[string]interface{})
			thought, exists := hooks["afterAgentThought"]
			if len(tc.foreign) == 0 {
				if exists {
					t.Fatalf("repair left an afterAgentThought key: %#v", thought)
				}
			} else {
				entries := thought.([]interface{})
				if len(entries) != 1 || cursorHookCommand(entries[0]) != "operator-thought-hook" {
					t.Fatalf("repair did not keep only the foreign afterAgentThought hook: %#v", entries)
				}
			}
			for _, event := range cursorEnterpriseHookEvents {
				entries := hooks[event].([]interface{})
				if cursorHookCommand(entries[len(entries)-1]) != current {
					t.Fatalf("repair did not publish the current command on %s", event)
				}
			}

			// Teardown of the un-repaired file removes every DefenseClaw entry,
			// afterAgentThought included, and restores the original.
			cleaned, err := RemoveWindowsCursorEnterpriseHooks(legacy, testWindowsCursorAdapter)
			if err != nil {
				t.Fatal(err)
			}
			if !WindowsCursorEnterpriseHooksOwnedRemainderEqual(cleaned, tc.original) {
				t.Fatalf("teardown remainder differs from the original\ncleaned: %s\noriginal: %s", cleaned, tc.original)
			}
			if tc.original == nil && !WindowsCursorEnterpriseHooksEmpty(cleaned) {
				t.Fatalf("teardown of a DefenseClaw-created file left content: %s", cleaned)
			}
			// The repaired file tears down to the same remainder.
			cleanedRepaired, err := RemoveWindowsCursorEnterpriseHooks(repaired, testWindowsCursorAdapter)
			if err != nil {
				t.Fatal(err)
			}
			if !WindowsCursorEnterpriseHooksOwnedRemainderEqual(cleanedRepaired, tc.original) {
				t.Fatalf("repaired teardown remainder differs: %s", cleanedRepaired)
			}
		})
	}
}

func TestWindowsCursorEnterpriseRetiredEventStillRejectsBadOwnedEntries(t *testing.T) {
	current, _, err := windowsCursorEnterpriseHookCommands(testWindowsCursorAdapter)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := windowsCursorPreRetirementHooks(t, nil, "", windowsCursorEnterpriseHookEntry(current))
	if err := VerifyWindowsCursorEnterpriseHooksForMigration(duplicate, testWindowsCursorAdapter, "closed"); err == nil {
		t.Fatal("migration verifier accepted two DefenseClaw afterAgentThought entries")
	}
	drifted := windowsCursorPreRetirementHooks(t, nil, "", map[string]interface{}{
		"type": "command", "command": current, "timeout": 1, "failClosed": true,
	})
	if err := VerifyWindowsCursorEnterpriseHooksForMigration(drifted, testWindowsCursorAdapter, "closed"); err == nil {
		t.Fatal("migration verifier accepted a drifted DefenseClaw afterAgentThought entry")
	}
	// Mixed versions: current roster, previous command on afterAgentThought.
	mixed := windowsCursorPreRetirementHooks(t, nil, "")
	cfg, err := decodeCursorHooksJSON(mixed)
	if err != nil {
		t.Fatal(err)
	}
	thought := cfg["hooks"].(map[string]interface{})["afterAgentThought"].([]interface{})
	thought[0].(map[string]interface{})["command"] = previousWindowsCursorEnterpriseHookCommand(testWindowsCursorAdapter)
	mixedBody, err := encodeCursorHooksJSON(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWindowsCursorEnterpriseHooksForMigration(mixedBody, testWindowsCursorAdapter, "closed"); err == nil {
		t.Fatal("migration verifier accepted mixed command versions across the retired event")
	}
	if err := VerifyWindowsCursorEnterpriseHooksRegistered(mixedBody, testWindowsCursorAdapter, "closed"); err == nil {
		t.Fatal("presence verifier accepted the previous encoded command")
	}
}

func TestWindowsCursorEnterpriseOwnedRemainderIgnoresEmptyRetiredEvent(t *testing.T) {
	original := []byte(`{"version":1,"hooks":{"afterAgentThought":[]}}`)
	managed, err := MergeWindowsCursorEnterpriseHooks(original, testWindowsCursorAdapter, "closed")
	if err != nil {
		t.Fatal(err)
	}
	cleaned, err := RemoveWindowsCursorEnterpriseHooks(managed, testWindowsCursorAdapter)
	if err != nil {
		t.Fatal(err)
	}
	if !WindowsCursorEnterpriseHooksOwnedRemainderEqual(cleaned, original) {
		t.Fatalf("empty retired-event scaffolding broke the remainder match: %s", cleaned)
	}
}
