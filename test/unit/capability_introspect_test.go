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

func TestIntrospectMCP(t *testing.T) {
	tests := []struct {
		name      string
		file      string
		wantTools int
		wantErr   bool
	}{
		{
			name:      "3 tools",
			file:      "tools-mcp.json",
			wantTools: 3,
		},
		{
			name:      "empty tools array",
			file:      "no-tools-mcp.json",
			wantTools: 0,
		},
		{
			name:      "existing clean MCP with 1 tool",
			file:      "clean-mcp.json",
			wantTools: 1,
		},
		{
			name:    "missing file",
			file:    "nonexistent.json",
			wantErr: true,
		},
	}

	fixtureDir := filepath.Join("..", "..", "test", "fixtures", "mcps")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(fixtureDir, tt.file)
			tools, err := capability.IntrospectMCP(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(tools) != tt.wantTools {
				t.Errorf("got %d tools, want %d", len(tools), tt.wantTools)
			}
		})
	}
}

func TestIntrospectMCPToolDetails(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "test", "fixtures", "mcps")
	tools, err := capability.IntrospectMCP(filepath.Join(fixtureDir, "tools-mcp.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tools[0].Name != "get_weather" {
		t.Errorf("tools[0].Name = %q, want %q", tools[0].Name, "get_weather")
	}
	if tools[0].Description != "Get current weather for a location" {
		t.Errorf("tools[0].Description = %q, want %q", tools[0].Description, "Get current weather for a location")
	}
	if tools[0].Parameters == nil {
		t.Error("tools[0].Parameters should not be nil")
	}
}

func TestIntrospectMCPMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := capability.IntrospectMCP(path)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestIntrospectSkill(t *testing.T) {
	tests := []struct {
		name      string
		dir       string
		wantName  string
		wantPerms int
		wantErr   bool
	}{
		{
			name:      "skill with read-only permission",
			dir:       filepath.Join("..", "..", "test", "fixtures", "skills", "permissioned-skill"),
			wantName:  "permissioned-skill",
			wantPerms: 1,
		},
		{
			name:      "clean-skill with read-only",
			dir:       filepath.Join("..", "..", "test", "fixtures", "skills", "clean-skill"),
			wantName:  "clean-skill",
			wantPerms: 1,
		},
		{
			name:    "missing directory",
			dir:     filepath.Join("..", "..", "test", "fixtures", "skills", "nonexistent"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := capability.IntrospectSkill(tt.dir)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", info.Name, tt.wantName)
			}
			if len(info.Permissions) != tt.wantPerms {
				t.Errorf("got %d permissions, want %d", len(info.Permissions), tt.wantPerms)
			}
		})
	}
}

func TestIntrospectSkillNoPermissions(t *testing.T) {
	dir := t.TempDir()
	content := []byte("name: bare-skill\nversion: \"1.0.0\"\ndescription: no perms\n")
	if err := os.WriteFile(filepath.Join(dir, "skill.yaml"), content, 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := capability.IntrospectSkill(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Name != "bare-skill" {
		t.Errorf("Name = %q, want %q", info.Name, "bare-skill")
	}
	if len(info.Permissions) != 0 {
		t.Errorf("got %d permissions, want 0", len(info.Permissions))
	}
}
