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

package unit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/capability"
)

func TestApprovePolicySuccess(t *testing.T) {
	dir := t.TempDir()

	// Generate a policy and write it
	pol := capability.GeneratePolicy(capability.GenerateRequest{
		Name: "test-service",
		Type: "mcp",
		Tools: []capability.ToolInfo{
			{Name: "get_data", Description: "Get data"},
		},
		ScanResult: &capability.ScanResultSummary{TotalFindings: 0},
	})
	if _, err := capability.WritePolicy(pol, dir); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Verify auto file exists
	autoPath := filepath.Join(dir, "auto-test-service.capability.yaml")
	if _, err := os.Stat(autoPath); err != nil {
		t.Fatalf("auto file should exist: %v", err)
	}

	// Approve
	approved, err := capability.ApprovePolicy(dir, "test-service")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Verify approved policy
	if !approved.Approved {
		t.Error("expected Approved = true")
	}
	if approved.Agent != "test-service" {
		t.Errorf("Agent = %q, want %q", approved.Agent, "test-service")
	}

	// Verify auto file removed
	if _, err := os.Stat(autoPath); !os.IsNotExist(err) {
		t.Error("auto file should have been removed")
	}

	// Verify manual file exists
	manualPath := filepath.Join(dir, "test-service.capability.yaml")
	if _, err := os.Stat(manualPath); err != nil {
		t.Errorf("manual file should exist: %v", err)
	}
}

func TestApprovePolicyNoAutoFile(t *testing.T) {
	dir := t.TempDir()

	_, err := capability.ApprovePolicy(dir, "nonexistent")
	if err == nil {
		t.Fatal("expected error when no auto file exists")
	}
}

func TestApprovePolicyManualExists(t *testing.T) {
	dir := t.TempDir()

	// Write both auto and manual files
	pol := capability.GeneratePolicy(capability.GenerateRequest{
		Name: "dual-service",
		Type: "mcp",
		Tools: []capability.ToolInfo{{Name: "get_x"}},
		ScanResult: &capability.ScanResultSummary{TotalFindings: 0},
	})
	if _, err := capability.WritePolicy(pol, dir); err != nil {
		t.Fatalf("write auto: %v", err)
	}

	// Create a manual file too
	manualPath := filepath.Join(dir, "dual-service.capability.yaml")
	if err := os.WriteFile(manualPath, []byte("agent: dual-service\n"), 0o644); err != nil {
		t.Fatalf("write manual: %v", err)
	}

	_, err := capability.ApprovePolicy(dir, "dual-service")
	if err == nil {
		t.Fatal("expected error when manual file already exists")
	}
}
