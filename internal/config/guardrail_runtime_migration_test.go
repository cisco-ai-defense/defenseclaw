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

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFromFileWithRuntimeMigration_MigratesAndDeletesGuardrailRuntime(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, DefaultConfigName)
	runtimePath := filepath.Join(dir, GuardrailRuntimeFileName)
	original := `config_version: 6
data_dir: ` + dir + `
# guardrail settings
guardrail:
  # mode stays commented
  mode: observe
  scanner_mode: local
  hilt:
    enabled: false
    min_severity: HIGH
`
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	runtime := `{
		"mode": "action",
		"scanner_mode": "both",
		"block_message": "Custom block",
		"connector": "codex",
		"hilt_enabled": true,
		"hilt_min_severity": "medium"
	}`
	if err := os.WriteFile(runtimePath, []byte(runtime), 0o600); err != nil {
		t.Fatalf("write runtime: %v", err)
	}

	cfg, err := LoadFromFileWithRuntimeMigration(configPath)
	if err != nil {
		t.Fatalf("LoadFromFileWithRuntimeMigration: %v", err)
	}
	if cfg.Guardrail.Mode != "action" {
		t.Fatalf("mode = %q, want action", cfg.Guardrail.Mode)
	}
	if cfg.Guardrail.ScannerMode != "both" {
		t.Fatalf("scanner_mode = %q, want both", cfg.Guardrail.ScannerMode)
	}
	if cfg.Guardrail.BlockMessage != "Custom block" {
		t.Fatalf("block_message = %q, want Custom block", cfg.Guardrail.BlockMessage)
	}
	if cfg.Guardrail.Connector != "codex" {
		t.Fatalf("connector = %q, want codex", cfg.Guardrail.Connector)
	}
	if !cfg.Guardrail.HILT.Enabled || cfg.Guardrail.HILT.MinSeverity != "MEDIUM" {
		t.Fatalf("hilt = %#v, want enabled MEDIUM", cfg.Guardrail.HILT)
	}
	if _, err := os.Stat(runtimePath); !os.IsNotExist(err) {
		t.Fatalf("runtime file still exists or stat failed: %v", err)
	}
	patched, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read patched config: %v", err)
	}
	if !strings.Contains(string(patched), "# mode stays commented") {
		t.Fatalf("patched config did not preserve comments:\n%s", string(patched))
	}
}

func TestLoadFromFileWithRuntimeMigration_InvalidGuardrailRuntimeFailsWithoutDeleting(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, DefaultConfigName)
	runtimePath := filepath.Join(dir, GuardrailRuntimeFileName)
	original := "config_version: 6\ndata_dir: " + dir + "\nguardrail:\n  mode: observe\n"
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(runtimePath, []byte(`{"mode":"invalid"}`), 0o600); err != nil {
		t.Fatalf("write runtime: %v", err)
	}

	if _, err := LoadFromFileWithRuntimeMigration(configPath); err == nil {
		t.Fatal("LoadFromFileWithRuntimeMigration succeeded with invalid runtime mode")
	}
	if _, err := os.Stat(runtimePath); err != nil {
		t.Fatalf("runtime file should remain after failed migration: %v", err)
	}
	current, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(current) != original {
		t.Fatalf("config changed after failed migration:\n%s", string(current))
	}
}

func TestLoadFromFileWithRuntimeMigration_MissingPrimaryConfigPreservesRuntime(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, DefaultConfigName)
	runtimePath := filepath.Join(dir, GuardrailRuntimeFileName)
	if err := os.WriteFile(runtimePath, []byte(`{"mode":"action"}`), 0o600); err != nil {
		t.Fatalf("write runtime: %v", err)
	}

	if _, err := LoadFromFileWithRuntimeMigration(configPath); err == nil {
		t.Fatal("LoadFromFileWithRuntimeMigration succeeded without primary config")
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("primary config should remain absent: %v", err)
	}
	if _, err := os.Stat(runtimePath); err != nil {
		t.Fatalf("runtime file should remain after failed migration: %v", err)
	}
}

func TestLoadFromFile_IgnoresGuardrailRuntime(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, DefaultConfigName)
	runtimePath := filepath.Join(dir, GuardrailRuntimeFileName)
	if err := os.WriteFile(configPath, []byte("config_version: 6\ndata_dir: "+dir+"\nguardrail:\n  mode: observe\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(runtimePath, []byte(`{"mode":"action"}`), 0o600); err != nil {
		t.Fatalf("write runtime: %v", err)
	}

	cfg, err := LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if cfg.Guardrail.Mode != "observe" {
		t.Fatalf("mode = %q, want observe from config.yaml", cfg.Guardrail.Mode)
	}
	if _, err := os.Stat(runtimePath); err != nil {
		t.Fatalf("runtime file should be ignored and left in place: %v", err)
	}
}
