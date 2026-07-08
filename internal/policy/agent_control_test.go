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

package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validAgentControlDocument = `{
  "agent_control": {
    "schema_version": 1,
    "enabled": true,
    "precedence": "stricter",
    "source_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "guardrail": {
      "block_threshold": 3,
      "alert_threshold": 2,
      "cisco_trust_level": "full"
    }
  }
}
`

func writePolicyFixture(t *testing.T, dataJSON string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte(dataJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "test.rego"), []byte("package test\nimport rego.v1\nallow := true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAgentControlDataMissingIsDisabled(t *testing.T) {
	dir := writePolicyFixture(t, `{}`)
	engine, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	status := engine.Status()
	if status.Generation != 1 {
		t.Fatalf("generation = %d, want 1", status.Generation)
	}
	if status.AgentControl.Present || status.AgentControl.Enabled {
		t.Fatalf("unexpected Agent Control status: %+v", status.AgentControl)
	}
	if status.AgentControl.SchemaVersion != 1 {
		t.Fatalf("schema version = %d, want 1", status.AgentControl.SchemaVersion)
	}
}

func TestAgentControlDataValidStatus(t *testing.T) {
	dir := writePolicyFixture(t, `{}`)
	path := filepath.Join(dir, agentControlDataFilename)
	raw := []byte(validAgentControlDocument)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	status := engine.Status().AgentControl
	if !status.Present || !status.Enabled || status.SchemaVersion != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}
	if status.SourceDigest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("source digest = %q", status.SourceDigest)
	}
	sum := sha256.Sum256(raw)
	want := "sha256:" + hex.EncodeToString(sum[:])
	if status.ArtifactDigest != want {
		t.Fatalf("artifact digest = %q, want %q", status.ArtifactDigest, want)
	}
}

func TestAgentControlDataRejectsInvalidDocuments(t *testing.T) {
	tests := map[string]string{
		"unknown top-level":         `{"agent_control":{"schema_version":1,"enabled":false,"precedence":"stricter"},"other":true}`,
		"unknown nested":            `{"agent_control":{"schema_version":1,"enabled":false,"precedence":"stricter","other":true}}`,
		"unsupported version":       `{"agent_control":{"schema_version":2,"enabled":false,"precedence":"stricter"}}`,
		"missing enabled":           `{"agent_control":{"schema_version":1,"precedence":"stricter"}}`,
		"bad precedence":            `{"agent_control":{"schema_version":1,"enabled":false,"precedence":"merge"}}`,
		"disabled with guardrail":   `{"agent_control":{"schema_version":1,"enabled":false,"precedence":"stricter","guardrail":{}}}`,
		"bad source digest":         strings.Replace(validAgentControlDocument, strings.Repeat("a", 64), "abc", 1),
		"alert exceeds block":       strings.Replace(validAgentControlDocument, `"alert_threshold": 2`, `"alert_threshold": 4`, 1),
		"unsupported trust":         strings.Replace(validAgentControlDocument, `"full"`, `"trusted"`, 1),
		"multiple JSON values":      validAgentControlDocument + `{}`,
		"missing agent_control key": `{}`,
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			dir := writePolicyFixture(t, `{}`)
			if err := os.WriteFile(filepath.Join(dir, agentControlDataFilename), []byte(document), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := New(dir); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestAgentControlDataRejectsReservedBaseKey(t *testing.T) {
	dir := writePolicyFixture(t, `{"agent_control":{"enabled":false}}`)
	if _, err := New(dir); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("expected reserved-key error, got %v", err)
	}
}

func TestAgentControlDataRejectsLinkedManagedFile(t *testing.T) {
	t.Run("hard link", func(t *testing.T) {
		dir := writePolicyFixture(t, `{}`)
		path := filepath.Join(dir, agentControlDataFilename)
		if err := os.WriteFile(path, []byte(validAgentControlDocument), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(path, filepath.Join(dir, "alias.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := New(dir); err == nil || !strings.Contains(err.Error(), "hard links") {
			t.Fatalf("expected hard-link rejection, got %v", err)
		}
	})

	t.Run("symbolic link", func(t *testing.T) {
		dir := writePolicyFixture(t, `{}`)
		target := filepath.Join(dir, "target.json")
		if err := os.WriteFile(target, []byte(validAgentControlDocument), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, agentControlDataFilename)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := New(dir); err == nil || !strings.Contains(err.Error(), "non-symlink") {
			t.Fatalf("expected symlink rejection, got %v", err)
		}
	})
}

func TestAgentControlReloadIsAtomicWithStatus(t *testing.T) {
	dir := writePolicyFixture(t, `{}`)
	path := filepath.Join(dir, agentControlDataFilename)
	if err := os.WriteFile(path, []byte(validAgentControlDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	before := engine.Status()
	if err := os.WriteFile(path, []byte(`{"agent_control":{"schema_version":1}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := engine.Reload(); err == nil {
		t.Fatal("expected reload failure")
	}
	afterFailure := engine.Status()
	if afterFailure != before {
		t.Fatalf("status changed after failed reload: before=%+v after=%+v", before, afterFailure)
	}

	disabled := []byte(`{"agent_control":{"schema_version":1,"enabled":false,"precedence":"stricter"}}`)
	if err := os.WriteFile(path, disabled, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := engine.Reload(); err != nil {
		t.Fatal(err)
	}
	afterSuccess := engine.Status()
	if afterSuccess.Generation != before.Generation+1 || afterSuccess.AgentControl.Enabled {
		t.Fatalf("unexpected status after reload: %+v", afterSuccess)
	}
}
