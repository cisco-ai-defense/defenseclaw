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

import "time"

// AgentPolicy defines the capabilities, restrictions, and conditions for a
// single agent identity. Loaded from a .capability.yaml manifest file.
type AgentPolicy struct {
	Agent        string       `yaml:"agent"`
	Description  string       `yaml:"description"`
	Generated    bool         `yaml:"generated,omitempty"`
	Approved     bool         `yaml:"approved,omitempty"`
	Capabilities []Capability `yaml:"capabilities"`
	Restrictions []string     `yaml:"restrictions"`
	Conditions   Conditions   `yaml:"conditions"`
}

// Capability grants access to a specific resource under constraints.
// Resource uses "server.tool" format (e.g. "jira.get_issue").
// Constraints are matched against request parameters.
type Capability struct {
	Name        string         `yaml:"name"`
	Resource    string         `yaml:"resource"`
	Constraints map[string]any `yaml:"constraints"`
}

// Conditions are global to an agent — they apply to all capabilities.
type Conditions struct {
	TimeWindow   string   `yaml:"time_window"`
	Environments []string `yaml:"environments"`
	RateLimit    *Rate    `yaml:"rate_limit"`
}

// Rate defines a sliding-window rate limit.
type Rate struct {
	MaxCalls      int `yaml:"max_calls"`
	WindowSeconds int `yaml:"window_seconds"`
}

// EvalRequest is the input to the capability evaluator.
type EvalRequest struct {
	Agent       string
	Resource    string
	Params      map[string]any
	Environment string
	Timestamp   time.Time
}

// Decision is the output of the capability evaluator.
type Decision struct {
	Allowed    bool   `json:"allowed"`
	Reason     string `json:"reason"`
	Capability string `json:"capability,omitempty"`
}

// Deny creates a deny decision with the given reason.
func Deny(reason string) Decision {
	return Decision{Allowed: false, Reason: reason}
}

// Allow creates an allow decision for the given capability.
func Allow(capName string) Decision {
	return Decision{Allowed: true, Reason: "capability matched", Capability: capName}
}

// ToolInfo holds metadata for a single tool discovered from an MCP manifest.
type ToolInfo struct {
	Name        string
	Description string
	Parameters  map[string]any
}

// SkillInfo holds metadata extracted from a skill manifest.
type SkillInfo struct {
	Name        string
	Permissions []string
}

// ScanResultSummary is a lightweight view of scanner.ScanResult
// to avoid importing the scanner package into capability.
type ScanResultSummary struct {
	MaxSeverity   string // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", ""
	TotalFindings int
}

// GenerateRequest bundles the inputs for policy generation.
// Uses primitive types to avoid circular dependency with watcher package.
type GenerateRequest struct {
	Name       string             // skill/MCP name (from InstallEvent.Name)
	Type       string             // "skill" or "mcp"
	Tools      []ToolInfo         // from introspection (nil if introspection failed)
	SkillInfo  *SkillInfo         // from skill introspection (nil for MCP)
	ScanResult *ScanResultSummary // scan posture summary
}
