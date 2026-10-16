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

import "testing"

func TestWindowsCursorEnterpriseMigratesPreviousEncodedCommand(t *testing.T) {
	current, _, err := windowsCursorEnterpriseHookCommands(testWindowsCursorAdapter)
	if err != nil {
		t.Fatal(err)
	}
	previous := previousWindowsCursorEnterpriseHookCommand(testWindowsCursorAdapter)
	if previous == current {
		t.Fatal("previous encoded command equals the current command")
	}
	wantPreviousScript := "$reader=[IO.StreamReader]::new([Console]::OpenStandardInput()," +
		"[Text.UTF8Encoding]::new($false,$true),$false);" +
		"try{$payload=$reader.ReadToEnd()}finally{$reader.Dispose()};" +
		"$payload | & " + powershellQuoteLiteral(testWindowsCursorAdapter)
	if decoded := decodePowerShellEncodedCommandForTest(t, previous); decoded != wantPreviousScript {
		t.Fatalf("previous encoded command changed: %q", decoded)
	}

	seed, err := MergeWindowsCursorEnterpriseHooks(nil, testWindowsCursorAdapter, "closed")
	if err != nil {
		t.Fatal(err)
	}
	makePrevious := func() map[string]interface{} {
		t.Helper()
		cfg, err := decodeCursorHooksJSON(seed)
		if err != nil {
			t.Fatal(err)
		}
		hooks := cfg["hooks"].(map[string]interface{})
		for _, event := range cursorHookEvents {
			entry := hooks[event].([]interface{})[0].(map[string]interface{})
			entry["command"] = previous
		}
		return cfg
	}
	encode := func(cfg map[string]interface{}) []byte {
		t.Helper()
		body, err := encodeCursorHooksJSON(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}

	cfg := makePrevious()
	hooks := cfg["hooks"].(map[string]interface{})
	nearMatch := previous + " --operator-owned"
	hooks["beforeShellExecution"] = append(hooks["beforeShellExecution"].([]interface{}),
		map[string]interface{}{"type": "command", "command": nearMatch})
	priorBody := encode(cfg)
	if err := VerifyWindowsCursorEnterpriseHooksForMigration(priorBody, testWindowsCursorAdapter, "closed"); err != nil {
		t.Fatalf("previous policy rejected before migration: %v", err)
	}
	if err := VerifyWindowsCursorEnterpriseHooks(priorBody, testWindowsCursorAdapter, "closed"); err == nil {
		t.Fatal("strict verifier accepted the previous encoded command")
	}

	migrated, err := MergeWindowsCursorEnterpriseHooks(priorBody, testWindowsCursorAdapter, "closed")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWindowsCursorEnterpriseHooks(migrated, testWindowsCursorAdapter, "closed"); err != nil {
		t.Fatalf("migrated policy rejected by strict verifier: %v", err)
	}
	migratedCfg, err := decodeCursorHooksJSON(migrated)
	if err != nil {
		t.Fatal(err)
	}
	migratedEntries := migratedCfg["hooks"].(map[string]interface{})["beforeShellExecution"].([]interface{})
	if len(migratedEntries) != 2 || cursorHookCommand(migratedEntries[0]) != nearMatch || cursorHookCommand(migratedEntries[1]) != current {
		t.Fatalf("migration did not preserve the near match and replace the previous command: %#v", migratedEntries)
	}

	removed, err := RemoveWindowsCursorEnterpriseHooks(priorBody, testWindowsCursorAdapter)
	if err != nil {
		t.Fatal(err)
	}
	removedCfg, err := decodeCursorHooksJSON(removed)
	if err != nil {
		t.Fatal(err)
	}
	remaining := removedCfg["hooks"].(map[string]interface{})["beforeShellExecution"].([]interface{})
	if len(remaining) != 1 || cursorHookCommand(remaining[0]) != nearMatch {
		t.Fatalf("removal did not isolate the previous owned command: %#v", remaining)
	}

	mixed := makePrevious()
	mixed["hooks"].(map[string]interface{})["preToolUse"].([]interface{})[0].(map[string]interface{})["command"] = current
	if err := VerifyWindowsCursorEnterpriseHooksForMigration(encode(mixed), testWindowsCursorAdapter, "closed"); err == nil {
		t.Fatal("migration verifier accepted mixed command versions")
	}
	drifted := makePrevious()
	drifted["hooks"].(map[string]interface{})["preToolUse"].([]interface{})[0].(map[string]interface{})["timeout"] = 1
	if err := VerifyWindowsCursorEnterpriseHooksForMigration(encode(drifted), testWindowsCursorAdapter, "closed"); err == nil {
		t.Fatal("migration verifier accepted a drifted previous entry")
	}
}
