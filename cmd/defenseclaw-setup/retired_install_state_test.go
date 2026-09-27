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

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// writeRetiredInstallState writes a valid install state for connector plus the
// given extra top-level fields, as a pre-release build wrote it.
func writeRetiredInstallState(t *testing.T, connector string, extra map[string]any) (installRoot, dataRoot, maintenancePath string) {
	t.Helper()
	installRoot, dataRoot, maintenancePath = testTransactionRoots(t)
	state := testInstallState(installRoot, dataRoot, maintenancePath, testPreviousTransactionID, "1.0.0")
	state.Connector = connector
	writeInstallTree(t, installRoot, state)
	path := filepath.Join(installRoot, "installer", "install-state.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	for key, value := range extra {
		document[key] = value
	}
	data, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return installRoot, dataRoot, maintenancePath
}

func retiredConnectorNames() []string {
	names := make([]string, 0, len(retiredInstallStateConnectors))
	for name := range retiredInstallStateConnectors {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func TestLoadInstallStateAcceptsRetiredConnectorState(t *testing.T) {
	bindings := map[string]any{}
	for _, field := range retiredInstallStateFields {
		bindings[field] = filepath.Join(string(filepath.Separator)+"profile", field)
	}
	for _, retired := range retiredConnectorNames() {
		t.Run(retired, func(t *testing.T) {
			installRoot, dataRoot, maintenancePath := writeRetiredInstallState(t, retired, bindings)
			state, err := loadInstallStateFromTreeForRoots(installRoot, installRoot, dataRoot, maintenancePath)
			if err != nil {
				t.Fatalf("load pre-release state: %v", err)
			}
			if state.Connector != "none" {
				t.Fatalf("loaded connector = %q, want none", state.Connector)
			}
			replacement, ok := retiredConnectorReplacementAt(installRoot)
			if !ok || replacement != retiredInstallStateConnectors[retired] {
				t.Fatalf("replacement = %q, %v; want %q", replacement, ok, retiredInstallStateConnectors[retired])
			}
			// Rewriting the state (as PATH ownership updates do) drops the
			// retired bindings.
			if err := updateInstalledPathOwnership(installRoot, true, false, false); err != nil {
				t.Fatalf("rewrite state: %v", err)
			}
			data, err := os.ReadFile(filepath.Join(installRoot, "installer", "install-state.json"))
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range retiredInstallStateFields {
				if strings.Contains(string(data), `"`+field+`"`) {
					t.Fatalf("rewritten state still carries %s", field)
				}
			}
		})
	}

	t.Run("current connector with leftover bindings", func(t *testing.T) {
		installRoot, dataRoot, maintenancePath := writeRetiredInstallState(t, "codex", bindings)
		state, err := loadInstallStateFromTreeForRoots(installRoot, installRoot, dataRoot, maintenancePath)
		if err != nil {
			t.Fatalf("load state with leftover bindings: %v", err)
		}
		if state.Connector != "codex" {
			t.Fatalf("connector = %q, want codex", state.Connector)
		}
		if _, retired := retiredConnectorReplacementAt(installRoot); retired {
			t.Fatal("a current connector must not be treated as retired")
		}
	})
}

func TestLoadInstallStateStaysStrictForOtherFields(t *testing.T) {
	installRoot, dataRoot, maintenancePath := writeRetiredInstallState(t, "codex", map[string]any{"unexpected_home": "/x"})
	if _, err := loadInstallStateFromTreeForRoots(installRoot, installRoot, dataRoot, maintenancePath); err == nil ||
		!strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error = %v, want strict rejection", err)
	}

	installRoot, dataRoot, maintenancePath = writeRetiredInstallState(t, "codex", map[string]any{retiredInstallStateFields[0]: 7})
	if _, err := loadInstallStateFromTreeForRoots(installRoot, installRoot, dataRoot, maintenancePath); err == nil {
		t.Fatal("a non-string retired binding must be rejected")
	}

	installRoot, dataRoot, maintenancePath = writeRetiredInstallState(t, "unknown-agent", nil)
	if _, err := loadInstallStateFromTreeForRoots(installRoot, installRoot, dataRoot, maintenancePath); err == nil {
		t.Fatal("an unknown connector must still be rejected")
	}
}
