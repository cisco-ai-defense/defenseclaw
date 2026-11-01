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
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// removedRollbackSetup is an OpenHands setup of an older release: its hook
// script, and a hooks.json that runs it, with or without an operator hook
// next to it. A setup receipt says whether hooks.json was there before.
func removedRollbackSetup(t *testing.T, operatorHook bool) (dataDir, config, original string) {
	t.Helper()
	home, dataDir := removedTestHome(t)
	script := filepath.Join(dataDir, "hooks", removedOpenHandsHookScript)
	removedTestWrite(t, script, removedTestHook, 0o700)
	config = filepath.Join(home, ".openhands", "hooks.json")
	commands := []string{script}
	if operatorHook {
		commands = append(commands, "/usr/local/bin/my-own-hook --check")
	}
	original = removedTestHooksJSON(t, commands...)
	removedTestWrite(t, config, original, 0o640)
	receipt, err := json.Marshal(map[string]any{"version": managedBackupVersion, "connector": removedOpenHandsID,
		"logical_name": "config", "path": config, "existed": operatorHook})
	if err != nil {
		t.Fatal(err)
	}
	removedTestWrite(t, managedFileBackupPath(dataDir, removedOpenHandsID, "config"), string(receipt), 0o600)
	return dataDir, config, original
}

func removedRollbackRestore(t *testing.T, dataDir, toVersion string) []RemovedRollbackResult {
	t.Helper()
	results, err := RestoreRemovedConnectorFilesForRollback(dataDir, toVersion)
	if err != nil {
		t.Fatalf("RestoreRemovedConnectorFilesForRollback(%q): %v", toVersion, err)
	}
	return results
}

// GAP-2136: the 1.0.5 upgrade removed the hooks.json an OpenHands setup made
// (or DefenseClaw's hooks from the operator's), and 'defenseclaw rollback'
// to 1.0.2 did not bring it back: the data swap covers only the data folder,
// and the 1.0.2 gateway writes hooks.json again only when it can probe the
// agent's version, so its doctor failed "OpenHands hooks". A rollback to a
// release before 1.0.5 puts the file back as the teardown found it.
func TestRemovedConnectorRollbackPutsBackTheAgentFilesTheTeardownChanged(t *testing.T) {
	for _, operatorHook := range []bool{false, true} {
		dataDir, config, original := removedRollbackSetup(t, operatorHook)
		removedTestTeardown(t, removedOpenHandsID, SetupOpts{DataDir: dataDir})
		if data, err := os.ReadFile(config); operatorHook && (err != nil || string(data) == original) || !operatorHook && err == nil {
			t.Fatalf("operatorHook=%v: the teardown did not change %s: %q, %v", operatorHook, config, data, err)
		}

		results := removedRollbackRestore(t, dataDir, "1.0.2")
		if len(results) != 1 || !results[0].Restored || results[0].Path != config {
			t.Fatalf("operatorHook=%v: results = %+v, want %s put back", operatorHook, results, config)
		}
		data, err := os.ReadFile(config)
		if err != nil || string(data) != original {
			t.Fatalf("operatorHook=%v: %s after the rollback = %q, %v; want the file the older setup left", operatorHook, config, data, err)
		}
		if info, err := os.Stat(config); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o640 {
			t.Fatalf("operatorHook=%v: mode after the rollback: %v %v", operatorHook, info, err)
		}
		removedTestGone(t, filepath.Join(dataDir, removedRollbackFile))
		if again := removedRollbackRestore(t, dataDir, "1.0.2"); len(again) != 0 {
			t.Fatalf("a second rollback did something: %+v", again)
		}
	}
}

// A file changed after the upgrade is the user's now: it stays, and so does
// a file the user made where the teardown removed one.
func TestRemovedConnectorRollbackKeepsAFileChangedSinceTheUpgrade(t *testing.T) {
	for _, operatorHook := range []bool{false, true} {
		dataDir, config, _ := removedRollbackSetup(t, operatorHook)
		removedTestTeardown(t, removedOpenHandsID, SetupOpts{DataDir: dataDir})
		mine := removedTestHooksJSON(t, "/usr/local/bin/added-after-the-upgrade")
		removedTestWrite(t, config, mine, 0o600)

		results := removedRollbackRestore(t, dataDir, "1.0.4")
		if len(results) != 1 || results[0].Restored || results[0].Reason == "" {
			t.Fatalf("operatorHook=%v: results = %+v, want the file kept with a reason", operatorHook, results)
		}
		if data, err := os.ReadFile(config); err != nil || string(data) != mine {
			t.Fatalf("operatorHook=%v: %s = %q, %v; want the user's file", operatorHook, config, data, err)
		}
	}
}

// A rollback to 1.0.5 or later (no OpenHands there) and a managed teardown
// (no rollback command) bring nothing back.
func TestRemovedConnectorRollbackOnlyToAReleaseThatStillGuardsIt(t *testing.T) {
	dataDir, config, _ := removedRollbackSetup(t, false)
	removedTestTeardown(t, removedOpenHandsID, SetupOpts{DataDir: dataDir})
	for _, version := range []string{"", "1.0.5", "1.0.5-rc.3", "1.0.6", "1.1.0"} {
		if results := removedRollbackRestore(t, dataDir, version); len(results) != 0 {
			t.Fatalf("rollback to %q: %+v, want nothing", version, results)
		}
		removedTestGone(t, config)
	}
	if _, err := os.Stat(filepath.Join(dataDir, removedRollbackFile)); err != nil {
		t.Fatalf("the record went without a rollback that uses it: %v", err)
	}

	managedDir, managedConfig, _ := removedRollbackSetup(t, true)
	removedTestTeardown(t, removedOpenHandsID, SetupOpts{DataDir: managedDir, ManagedEnterprise: true})
	removedTestGone(t, filepath.Join(managedDir, removedRollbackFile))
	if results := removedRollbackRestore(t, managedDir, "1.0.2"); len(results) != 0 {
		t.Fatalf("managed: %+v, want nothing (%s)", results, managedConfig)
	}
}
