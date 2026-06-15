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
	"reflect"
	"testing"
)

func readRawConnectorState(t *testing.T, dir string) connectorState {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, activeConnectorFile))
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	var state connectorState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal state file: %v", err)
	}
	return state
}

// TestSaveActiveConnectors_RoundTripSorted verifies the plural set persists
// and reloads as a stable, de-duped, sorted set in v2 form.
func TestSaveActiveConnectors_RoundTripSorted(t *testing.T) {
	dir := t.TempDir()
	if err := SaveActiveConnectors(dir, []string{"cursor", "codex", "cursor", " ", "copilot"}); err != nil {
		t.Fatalf("SaveActiveConnectors: %v", err)
	}
	got := LoadActiveConnectors(dir)
	want := []string{"codex", "copilot", "cursor"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LoadActiveConnectors = %v, want %v", got, want)
	}

	state := readRawConnectorState(t, dir)
	if state.Version != activeConnectorStateVersion {
		t.Errorf("version = %d, want %d", state.Version, activeConnectorStateVersion)
	}
	// The legacy "name" field is mirrored to the primary for cross-language
	// / older readers (notably the Python boot drift detector).
	if state.Name != "codex" {
		t.Errorf("legacy name mirror = %q, want %q (primary)", state.Name, "codex")
	}
}

// TestLoadActiveConnectors_LegacyMigrationOnRead verifies a pre-v2 file with
// only a "name" field is surfaced as a one-element set.
func TestLoadActiveConnectors_LegacyMigrationOnRead(t *testing.T) {
	dir := t.TempDir()
	legacy := []byte(`{"name":"codex"}`)
	if err := os.WriteFile(filepath.Join(dir, activeConnectorFile), legacy, 0o600); err != nil {
		t.Fatalf("write legacy file: %v", err)
	}

	if got := LoadActiveConnectors(dir); !reflect.DeepEqual(got, []string{"codex"}) {
		t.Errorf("legacy LoadActiveConnectors = %v, want [codex]", got)
	}
	if got := LoadActiveConnector(dir); got != "codex" {
		t.Errorf("legacy LoadActiveConnector = %q, want codex", got)
	}
}

// TestSaveActiveConnector_ShimWritesV2 verifies the singular shim preserves
// its contract (save X → load X) while writing the new v2 layout.
func TestSaveActiveConnector_ShimWritesV2(t *testing.T) {
	dir := t.TempDir()
	if err := SaveActiveConnector(dir, "claudecode"); err != nil {
		t.Fatalf("SaveActiveConnector: %v", err)
	}
	if got := LoadActiveConnector(dir); got != "claudecode" {
		t.Errorf("LoadActiveConnector = %q, want claudecode", got)
	}
	if got := LoadActiveConnectors(dir); !reflect.DeepEqual(got, []string{"claudecode"}) {
		t.Errorf("LoadActiveConnectors = %v, want [claudecode]", got)
	}
	state := readRawConnectorState(t, dir)
	if state.Version != activeConnectorStateVersion || state.Name != "claudecode" {
		t.Errorf("state = %+v, want version %d name claudecode", state, activeConnectorStateVersion)
	}
}

// TestSaveActiveConnector_EmptyName preserves the prior behavior that saving
// an empty name yields an empty load (no connector active).
func TestSaveActiveConnector_EmptyName(t *testing.T) {
	dir := t.TempDir()
	if err := SaveActiveConnector(dir, ""); err != nil {
		t.Fatalf("SaveActiveConnector(empty): %v", err)
	}
	if got := LoadActiveConnector(dir); got != "" {
		t.Errorf("LoadActiveConnector = %q, want empty", got)
	}
	if got := LoadActiveConnectors(dir); got != nil {
		t.Errorf("LoadActiveConnectors = %v, want nil", got)
	}
}

// TestLoadActiveConnectors_AbsentFile returns nil with no error semantics.
func TestLoadActiveConnectors_AbsentFile(t *testing.T) {
	dir := t.TempDir()
	if got := LoadActiveConnectors(dir); got != nil {
		t.Errorf("LoadActiveConnectors(absent) = %v, want nil", got)
	}
	if got := LoadActiveConnector(dir); got != "" {
		t.Errorf("LoadActiveConnector(absent) = %q, want empty", got)
	}
}

// TestClearActiveConnector_RemovesSet confirms clear wipes the whole set.
func TestClearActiveConnector_RemovesSet(t *testing.T) {
	dir := t.TempDir()
	if err := SaveActiveConnectors(dir, []string{"codex", "cursor"}); err != nil {
		t.Fatalf("SaveActiveConnectors: %v", err)
	}
	ClearActiveConnector(dir)
	if got := LoadActiveConnectors(dir); got != nil {
		t.Errorf("after clear LoadActiveConnectors = %v, want nil", got)
	}
}
