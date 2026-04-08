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

package capability

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// mcpManifest is the top-level structure of an MCP server's JSON manifest.
type mcpManifest struct {
	Name  string    `json:"name"`
	Tools []mcpTool `json:"tools"`
}

// mcpTool is a single tool entry in the MCP manifest.
type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// skillManifest is the top-level structure of a skill's YAML manifest.
type skillManifest struct {
	Name        string   `yaml:"name"`
	Permissions []string `yaml:"permissions"`
}

// IntrospectMCP parses an MCP server's JSON manifest file and returns
// per-tool metadata. Returns an empty slice (not error) for empty tools arrays.
func IntrospectMCP(path string) ([]ToolInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("introspect: read MCP manifest %s: %w", path, err)
	}

	var manifest mcpManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("introspect: parse MCP manifest %s: %w", path, err)
	}

	tools := make([]ToolInfo, 0, len(manifest.Tools))
	for _, t := range manifest.Tools {
		tools = append(tools, ToolInfo{
			Name:        t.Name,
			Description: t.Description,
			Parameters:  t.Parameters,
		})
	}

	return tools, nil
}

// IntrospectSkill parses a skill's skill.yaml manifest and returns the
// skill name and declared permissions. The path parameter is the skill
// directory (containing skill.yaml).
func IntrospectSkill(dir string) (*SkillInfo, error) {
	path := filepath.Join(dir, "skill.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("introspect: read skill manifest %s: %w", path, err)
	}

	var manifest skillManifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("introspect: parse skill manifest %s: %w", path, err)
	}

	return &SkillInfo{
		Name:        manifest.Name,
		Permissions: manifest.Permissions,
	}, nil
}
