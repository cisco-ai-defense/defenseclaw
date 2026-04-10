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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestSkillScanEndpointConfigured(t *testing.T) {
	cfg := config.DefaultConfig()

	if cfg.Scanners.SkillScanner.Binary == "" {
		t.Error("expected default skill-scanner binary to be set")
	}
	if cfg.Scanners.SkillScanner.Binary != "skill-scanner" {
		t.Errorf("expected 'skill-scanner', got %q", cfg.Scanners.SkillScanner.Binary)
	}
}

func TestMCPScanEndpointConfigured(t *testing.T) {
	cfg := config.DefaultConfig()

	if cfg.Scanners.MCPScanner.Binary == "" {
		t.Error("expected default mcp-scanner binary to be set")
	}
	if cfg.Scanners.MCPScanner.Binary != "mcp-scanner" {
		t.Errorf("expected 'mcp-scanner', got %q", cfg.Scanners.MCPScanner.Binary)
	}
	if cfg.InspectLLM.Timeout != 30 {
		t.Errorf("expected InspectLLM.Timeout=30, got %d", cfg.InspectLLM.Timeout)
	}
	if cfg.InspectLLM.MaxRetries != 3 {
		t.Errorf("expected InspectLLM.MaxRetries=3, got %d", cfg.InspectLLM.MaxRetries)
	}
}

func TestSkillWatcherConfigDefaults(t *testing.T) {
	cfg := config.DefaultConfig()

	if !cfg.Gateway.Watcher.Skill.Enabled {
		t.Error("expected skill watcher enabled by default")
	}
	if !cfg.Gateway.Watcher.Skill.TakeAction {
		t.Error("expected skill watcher take_action=true by default")
	}
}
