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

package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShouldRunWizard(t *testing.T) {
	t.Run("detects_missing_config", func(t *testing.T) {
		origHome := os.Getenv("HOME")
		tmpDir := t.TempDir()
		os.Setenv("HOME", tmpDir)
		t.Cleanup(func() { os.Setenv("HOME", origHome) })

		if !ShouldRunWizard() {
			t.Error("ShouldRunWizard should return true when config.yaml is missing")
		}
	})

	t.Run("detects_existing_config", func(t *testing.T) {
		origHome := os.Getenv("HOME")
		tmpDir := t.TempDir()
		os.Setenv("HOME", tmpDir)
		t.Cleanup(func() { os.Setenv("HOME", origHome) })

		dcDir := filepath.Join(tmpDir, ".defenseclaw")
		if err := os.MkdirAll(dcDir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dcDir, "config.yaml"), []byte("claw:\n  mode: openclaw\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}

		if ShouldRunWizard() {
			t.Error("ShouldRunWizard should return false when config.yaml exists")
		}
	})
}

func TestWizardResultDefaults(t *testing.T) {
	result := &WizardResult{
		DataDir:       defaultDataDir(),
		GatewayHost:   "localhost",
		GatewayPort:   "9090",
		GuardrailMode: "observe",
		ScannerMode:   "local",
		LLMProvider:   "openai",
		LLMModel:      "gpt-4o",
	}

	if result.GatewayHost != "localhost" {
		t.Errorf("default GatewayHost = %q, want localhost", result.GatewayHost)
	}
	if result.GatewayPort != "9090" {
		t.Errorf("default GatewayPort = %q, want 9090", result.GatewayPort)
	}
	if result.GuardrailMode != "observe" {
		t.Errorf("default GuardrailMode = %q, want observe", result.GuardrailMode)
	}
	if result.ScannerMode != "local" {
		t.Errorf("default ScannerMode = %q, want local", result.ScannerMode)
	}
}

func TestDefaultDataDir(t *testing.T) {
	dir := defaultDataDir()
	if dir == "" {
		t.Fatal("defaultDataDir returned empty string")
	}
	if !strings.Contains(dir, ".defenseclaw") {
		t.Errorf("expected .defenseclaw in data dir path, got: %s", dir)
	}
}
