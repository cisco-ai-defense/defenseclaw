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

	"github.com/defenseclaw/defenseclaw/internal/capability"
)

func TestGeneratePolicyCleanMCP(t *testing.T) {
	req := capability.GenerateRequest{
		Name: "weather-service",
		Type: "mcp",
		Tools: []capability.ToolInfo{
			{Name: "get_weather", Description: "Get weather"},
			{Name: "create_alert", Description: "Create alert"},
			{Name: "delete_alert", Description: "Delete alert"},
		},
		ScanResult: &capability.ScanResultSummary{
			MaxSeverity:   "",
			TotalFindings: 0,
		},
	}

	pol := capability.GeneratePolicy(req)

	if pol.Agent != "auto-weather-service" {
		t.Errorf("Agent = %q, want %q", pol.Agent, "auto-weather-service")
	}
	if !pol.Generated {
		t.Error("expected Generated = true")
	}
	if pol.Approved {
		t.Error("expected Approved = false")
	}
	if len(pol.Capabilities) != 3 {
		t.Errorf("got %d capabilities, want 3", len(pol.Capabilities))
	}
	if len(pol.Restrictions) != 0 {
		t.Errorf("got %d restrictions, want 0", len(pol.Restrictions))
	}
	if pol.Conditions.RateLimit != nil {
		t.Error("expected no rate limit for clean scan")
	}
	if pol.Capabilities[0].Resource != "weather-service.get_weather" {
		t.Errorf("cap[0].Resource = %q, want %q", pol.Capabilities[0].Resource, "weather-service.get_weather")
	}
}

func TestGeneratePolicyCautiousMCP(t *testing.T) {
	req := capability.GenerateRequest{
		Name: "data-service",
		Type: "mcp",
		Tools: []capability.ToolInfo{
			{Name: "get_data", Description: "Get data"},
			{Name: "create_record", Description: "Create record"},
			{Name: "delete_record", Description: "Delete record"},
		},
		ScanResult: &capability.ScanResultSummary{
			MaxSeverity:   "MEDIUM",
			TotalFindings: 2,
		},
	}

	pol := capability.GeneratePolicy(req)

	if len(pol.Capabilities) != 3 {
		t.Errorf("got %d capabilities, want 3", len(pol.Capabilities))
	}
	if len(pol.Restrictions) != 1 || pol.Restrictions[0] != "no_bulk_export" {
		t.Errorf("restrictions = %v, want [no_bulk_export]", pol.Restrictions)
	}
	if pol.Conditions.RateLimit == nil {
		t.Fatal("expected rate limit for MEDIUM scan")
	}
	if pol.Conditions.RateLimit.MaxCalls != 100 {
		t.Errorf("MaxCalls = %d, want 100", pol.Conditions.RateLimit.MaxCalls)
	}
	if pol.Conditions.RateLimit.WindowSeconds != 3600 {
		t.Errorf("WindowSeconds = %d, want 3600", pol.Conditions.RateLimit.WindowSeconds)
	}
}

func TestGeneratePolicyRestrictiveMCP(t *testing.T) {
	req := capability.GenerateRequest{
		Name: "risky-service",
		Type: "mcp",
		Tools: []capability.ToolInfo{
			{Name: "get_status", Description: "Get status"},
			{Name: "list_items", Description: "List items"},
			{Name: "create_item", Description: "Create item"},
			{Name: "delete_item", Description: "Delete item"},
		},
		ScanResult: &capability.ScanResultSummary{
			MaxSeverity:   "HIGH",
			TotalFindings: 3,
		},
	}

	pol := capability.GeneratePolicy(req)

	if len(pol.Capabilities) != 2 {
		t.Errorf("got %d capabilities, want 2 (read-like only)", len(pol.Capabilities))
	}
	for _, cap := range pol.Capabilities {
		name := cap.Name
		if name != "get_status" && name != "list_items" {
			t.Errorf("unexpected capability %q in restrictive policy", name)
		}
	}

	wantRestrictions := map[string]bool{
		"no_write":       true,
		"no_delete":      true,
		"no_bulk_export": true,
	}
	if len(pol.Restrictions) != 3 {
		t.Errorf("got %d restrictions, want 3", len(pol.Restrictions))
	}
	for _, r := range pol.Restrictions {
		if !wantRestrictions[r] {
			t.Errorf("unexpected restriction %q", r)
		}
	}

	if pol.Conditions.RateLimit == nil {
		t.Fatal("expected rate limit for HIGH scan")
	}
	if pol.Conditions.RateLimit.MaxCalls != 50 {
		t.Errorf("MaxCalls = %d, want 50", pol.Conditions.RateLimit.MaxCalls)
	}
}

func TestGeneratePolicyFallbackWildcard(t *testing.T) {
	req := capability.GenerateRequest{
		Name:  "unknown-service",
		Type:  "mcp",
		Tools: nil,
		ScanResult: &capability.ScanResultSummary{
			MaxSeverity:   "",
			TotalFindings: 0,
		},
	}

	pol := capability.GeneratePolicy(req)

	if len(pol.Capabilities) != 1 {
		t.Fatalf("got %d capabilities, want 1 (wildcard)", len(pol.Capabilities))
	}
	if pol.Capabilities[0].Resource != "unknown-service.*" {
		t.Errorf("Resource = %q, want %q", pol.Capabilities[0].Resource, "unknown-service.*")
	}
}

func TestGeneratePolicySkillReadOnly(t *testing.T) {
	req := capability.GenerateRequest{
		Name: "my-skill",
		Type: "skill",
		SkillInfo: &capability.SkillInfo{
			Name:        "my-skill",
			Permissions: []string{"read-only"},
		},
		ScanResult: &capability.ScanResultSummary{
			MaxSeverity:   "",
			TotalFindings: 0,
		},
	}

	pol := capability.GeneratePolicy(req)

	if len(pol.Capabilities) != 1 {
		t.Fatalf("got %d capabilities, want 1", len(pol.Capabilities))
	}
	if pol.Capabilities[0].Resource != "my-skill.*" {
		t.Errorf("Resource = %q, want %q", pol.Capabilities[0].Resource, "my-skill.*")
	}

	wantRestrictions := map[string]bool{"no_write": true, "no_delete": true}
	for _, r := range pol.Restrictions {
		if !wantRestrictions[r] {
			t.Errorf("unexpected restriction %q", r)
		}
		delete(wantRestrictions, r)
	}
	if len(wantRestrictions) > 0 {
		t.Errorf("missing restrictions: %v", wantRestrictions)
	}
}

func TestGeneratePolicySkillNoPermissions(t *testing.T) {
	req := capability.GenerateRequest{
		Name: "free-skill",
		Type: "skill",
		SkillInfo: &capability.SkillInfo{
			Name:        "free-skill",
			Permissions: nil,
		},
		ScanResult: &capability.ScanResultSummary{
			MaxSeverity:   "",
			TotalFindings: 0,
		},
	}

	pol := capability.GeneratePolicy(req)

	if len(pol.Restrictions) != 0 {
		t.Errorf("got %d restrictions, want 0 for skill with no permissions", len(pol.Restrictions))
	}
}

func TestGeneratePolicyNilScanResult(t *testing.T) {
	req := capability.GenerateRequest{
		Name:       "allowed-service",
		Type:       "mcp",
		Tools:      []capability.ToolInfo{{Name: "do_thing"}},
		ScanResult: nil,
	}

	pol := capability.GeneratePolicy(req)

	if len(pol.Restrictions) != 0 {
		t.Errorf("got %d restrictions, want 0 for nil scan result", len(pol.Restrictions))
	}
	if pol.Conditions.RateLimit != nil {
		t.Error("expected no rate limit for nil scan result")
	}
}
