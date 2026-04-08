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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// readLikePrefixes are tool name prefixes considered read-only operations.
var readLikePrefixes = []string{
	"get_", "list_", "read_", "search_",
	"fetch_", "query_", "describe_", "show_",
}

// GeneratePolicy creates an AgentPolicy from introspection results and scan posture.
func GeneratePolicy(req GenerateRequest) *AgentPolicy {
	posture := classifyPosture(req.ScanResult)

	pol := &AgentPolicy{
		Agent:     "auto-" + req.Name,
		Generated: true,
		Approved:  false,
	}

	// Build capabilities from tools or wildcard fallback
	switch {
	case req.Type == "skill":
		pol.Description = fmt.Sprintf("Auto-generated from skill scan (%s)", posture)
		pol.Capabilities = []Capability{{
			Name:        req.Name,
			Resource:    req.Name + ".*",
			Constraints: map[string]any{},
		}}
	case len(req.Tools) > 0:
		pol.Description = fmt.Sprintf("Auto-generated from MCP scan (%s)", posture)
		pol.Capabilities = buildMCPCapabilities(req.Name, req.Tools, posture)
	default:
		pol.Description = fmt.Sprintf("Auto-generated from MCP scan (%s)", posture)
		pol.Capabilities = []Capability{{
			Name:        req.Name,
			Resource:    req.Name + ".*",
			Constraints: map[string]any{},
		}}
	}

	// Apply posture-based restrictions and conditions
	pol.Restrictions, pol.Conditions = postureRestrictionsAndConditions(posture)

	// Skill permission overrides: read-only adds no_write + no_delete
	if req.SkillInfo != nil {
		for _, perm := range req.SkillInfo.Permissions {
			if perm == "read-only" {
				pol.Restrictions = addUniqueStrings(pol.Restrictions, "no_write", "no_delete")
			}
		}
	}

	return pol
}

// WritePolicy marshals the policy to YAML and writes it to the given directory.
// Returns the full path of the written file.
func WritePolicy(pol *AgentPolicy, dir string) (string, error) {
	data, err := yaml.Marshal(pol)
	if err != nil {
		return "", fmt.Errorf("capability: marshal policy: %w", err)
	}

	filename := pol.Agent + ".capability.yaml"
	path := filepath.Join(dir, filename)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("capability: create dir %s: %w", dir, err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("capability: write %s: %w", path, err)
	}

	return path, nil
}

// ApprovePolicy reads auto-<agent>.capability.yaml, sets approved=true,
// writes <agent>.capability.yaml, and removes the auto file.
func ApprovePolicy(dir, agent string) (*AgentPolicy, error) {
	autoFile := filepath.Join(dir, "auto-"+agent+".capability.yaml")
	manualFile := filepath.Join(dir, agent+".capability.yaml")

	// Check manual file doesn't already exist
	if _, err := os.Stat(manualFile); err == nil {
		return nil, fmt.Errorf("capability: manual policy %s already exists — edit it directly", manualFile)
	}

	pol, err := LoadPolicy(autoFile)
	if err != nil {
		return nil, fmt.Errorf("capability: no pending auto-generated policy for %q", agent)
	}

	pol.Agent = agent
	pol.Approved = true

	data, yamlErr := yaml.Marshal(pol)
	if yamlErr != nil {
		return nil, fmt.Errorf("capability: marshal approved policy: %w", yamlErr)
	}

	if err := os.WriteFile(manualFile, data, 0o644); err != nil {
		return nil, fmt.Errorf("capability: write %s: %w", manualFile, err)
	}

	if err := os.Remove(autoFile); err != nil {
		return nil, fmt.Errorf("capability: remove auto file %s: %w", autoFile, err)
	}

	return pol, nil
}

type posture string

const (
	posturePermissive  posture = "permissive"
	postureCautious    posture = "cautious"
	postureRestrictive posture = "restrictive"
)

func classifyPosture(scan *ScanResultSummary) posture {
	if scan == nil || scan.TotalFindings == 0 {
		return posturePermissive
	}
	switch scan.MaxSeverity {
	case "HIGH", "CRITICAL":
		return postureRestrictive
	case "MEDIUM", "LOW":
		return postureCautious
	default:
		return posturePermissive
	}
}

func buildMCPCapabilities(serverName string, tools []ToolInfo, p posture) []Capability {
	caps := make([]Capability, 0, len(tools))
	for _, tool := range tools {
		if p == postureRestrictive && !isReadLike(tool.Name) {
			continue
		}
		caps = append(caps, Capability{
			Name:        tool.Name,
			Resource:    serverName + "." + tool.Name,
			Constraints: map[string]any{},
		})
	}
	return caps
}

func isReadLike(toolName string) bool {
	for _, prefix := range readLikePrefixes {
		if strings.HasPrefix(toolName, prefix) {
			return true
		}
	}
	return false
}

func postureRestrictionsAndConditions(p posture) ([]string, Conditions) {
	switch p {
	case postureCautious:
		return []string{"no_bulk_export"}, Conditions{
			RateLimit: &Rate{MaxCalls: 100, WindowSeconds: 3600},
		}
	case postureRestrictive:
		return []string{"no_write", "no_delete", "no_bulk_export"}, Conditions{
			RateLimit: &Rate{MaxCalls: 50, WindowSeconds: 3600},
		}
	default:
		return nil, Conditions{}
	}
}

func addUniqueStrings(slice []string, vals ...string) []string {
	existing := make(map[string]bool, len(slice))
	for _, s := range slice {
		existing[s] = true
	}
	for _, v := range vals {
		if !existing[v] {
			slice = append(slice, v)
			existing[v] = true
		}
	}
	return slice
}
