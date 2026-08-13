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

package inventory

import (
	"sort"
	"strings"
	"testing"
)

// TestSupportedConnectorParityMatrix enforces Vineet's [P1] "single
// source of truth" contract for issue #3: every signature carrying a
// non-empty supported_connector MUST declare at least one of
// mcp_paths / skill_paths / plugin_paths. A connector with none of
// those was invisible to the direct-home reader in
// perConnectorMCPEntries — Vineet's exact concern about OpenClaw,
// Antigravity, OpenCode, and Amp coverage gaps.
//
// The test enumerates the failure per-connector-per-artifact so a
// regression names the exact gap (e.g. "windsurf: skill_paths
// empty") instead of a monolithic "some connector broke".
func TestSupportedConnectorParityMatrix(t *testing.T) {
	t.Parallel()

	sigs, err := LoadAISignatures()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	// Build the connector -> artifacts map so we can produce a
	// deterministic report ordered by connector slug.
	type coverage struct {
		mcp    bool
		skill  bool
		plugin bool
	}
	byConnector := map[string]coverage{}
	for _, sig := range sigs {
		slug := strings.TrimSpace(sig.SupportedConnector)
		if slug == "" {
			continue
		}
		cov := byConnector[slug]
		cov.mcp = cov.mcp || len(sig.MCPPaths) > 0
		cov.skill = cov.skill || len(sig.SkillPaths) > 0
		cov.plugin = cov.plugin || len(sig.PluginPaths) > 0
		byConnector[slug] = cov
	}

	connectors := make([]string, 0, len(byConnector))
	for c := range byConnector {
		connectors = append(connectors, c)
	}
	sort.Strings(connectors)

	// Connectors that legitimately have zero user-facing artifact
	// surfaces are exempt — record the reason inline so a future
	// regression can't hide behind "some connector should be here".
	// Keep this list narrow and audited.
	zeroSurfacesExempt := map[string]string{
		"omnigent": "custom policy bridge with ALLOW/ASK/DENY enforcement — no MCP, skill, or plugin surfaces are user-facing",
	}

	var fails []string
	for _, c := range connectors {
		cov := byConnector[c]
		if cov.mcp || cov.skill || cov.plugin {
			continue
		}
		if reason, ok := zeroSurfacesExempt[c]; ok {
			t.Logf("connector %q is exempt from parity matrix: %s", c, reason)
			continue
		}
		fails = append(fails, c+": ZERO surfaces declared (no mcp / skill / plugin paths) — invisible to direct-home reader")
	}

	if len(fails) > 0 {
		t.Fatalf("supported_connector parity gaps:\n  - %s\n\nEvery supported_connector must declare at least one of mcp_paths / skill_paths / plugin_paths so the direct-home MCP reader and the discovery walker can enumerate it. Add the missing surface(s) to internal/inventory/ai_signatures.json — or exempt the slug with a documented reason if it legitimately has no user-facing artifacts.",
			strings.Join(fails, "\n  - "))
	}
}

// TestSupportedConnectorMCPOnEveryConnector asserts every
// supported_connector has an MCP path declared, which is the specific
// gap Vineet cited on inventory_events.go:373 ("This second connector
// switch ... omits OpenClaw/Antigravity/OpenCode/Amp"). Skill/plugin
// paths are optional (some agents don't have those surfaces), but MCP
// is universal — every supported connector has a config file where
// MCP servers get declared, and if the walker skips it the SAM misses
// the connector's MCP inventory entirely.
func TestSupportedConnectorMCPOnEveryConnector(t *testing.T) {
	t.Parallel()
	sigs, err := LoadAISignatures()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	// Some connectors (e.g. omnigent) intentionally use a custom
	// non-standard config surface. Track the exemption set so a
	// regression that DROPS mcp_paths from a non-exempted connector
	// still fails, while genuinely-MCP-less agents don't trip the
	// test. Keep this list narrow and audited.
	mcpExempt := map[string]bool{
		"omnigent": true, // OmniGent uses a proprietary custom policy bridge, not MCP.
	}

	var fails []string
	for _, sig := range sigs {
		slug := strings.TrimSpace(sig.SupportedConnector)
		if slug == "" {
			continue
		}
		if mcpExempt[slug] {
			continue
		}
		if len(sig.MCPPaths) == 0 {
			fails = append(fails, slug+": mcp_paths empty — MCP server discovery will silently miss this connector")
		}
	}
	if len(fails) > 0 {
		t.Fatalf("supported_connector MCP coverage gaps:\n  - %s\n\nAdd mcp_paths to the signature or add the slug to mcpExempt with a documented reason.",
			strings.Join(fails, "\n  - "))
	}
}

// TestSupportedConnectorCountMatchesRegistry pins the number of
// supported_connectors so an accidental addition (which drags a
// silent inventory gap along with it) trips this test until an
// operator explicitly acknowledges the new connector by bumping the
// count AND ensuring the parity tests above still pass.
func TestSupportedConnectorCountMatchesRegistry(t *testing.T) {
	t.Parallel()
	sigs, err := LoadAISignatures()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	seen := map[string]bool{}
	for _, sig := range sigs {
		s := strings.TrimSpace(sig.SupportedConnector)
		if s != "" {
			seen[s] = true
		}
	}
	const expected = 14
	if len(seen) != expected {
		names := make([]string, 0, len(seen))
		for n := range seen {
			names = append(names, n)
		}
		sort.Strings(names)
		t.Fatalf("supported_connector count = %d, want %d\ngot: %v\n\nIf a new connector was added intentionally, bump `expected` here AND confirm the parity matrix tests above pass for it.",
			len(seen), expected, names)
	}
}
