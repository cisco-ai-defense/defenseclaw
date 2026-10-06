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

import "strings"

// Explicit list verdicts returned by AssetListDecision and ToolListDecision.
const (
	AssetListDeny  = "deny"
	AssetListAllow = "allow"
)

// AssetListDecision matches the operator lists asset_policy.<type>.denied
// and .allowed, the only block/allow source since config_version 9 (they
// replace the audit.db actions rows). The lists apply whether or not
// asset_policy is enabled and in either mode; enabled/mode govern only the
// default, registry and runtime-detection rules. A rule scoped to the
// connector decides before an unscoped one, and at the same scope denied
// wins. It returns "" when no rule matches.
func (c *Config) AssetListDecision(in AssetPolicyInput) (string, AssetPolicyRule) {
	if c == nil {
		return "", AssetPolicyRule{}
	}
	var p AssetTypePolicy
	switch normalizeAssetToken(in.TargetType) {
	case "mcp":
		p = c.AssetPolicy.MCP
	case "skill":
		p = c.AssetPolicy.Skill
	case "plugin":
		p = c.AssetPolicy.Plugin
	default:
		return "", AssetPolicyRule{}
	}
	for _, scoped := range []bool{true, false} {
		for _, list := range []struct {
			verdict string
			rules   []AssetPolicyRule
		}{{AssetListDeny, p.Denied}, {AssetListAllow, p.Allowed}} {
			for _, rule := range list.rules {
				if (strings.TrimSpace(rule.Connector) != "") != scoped || !assetRuleMatches(rule, in) {
					continue
				}
				if list.verdict == AssetListAllow && !allowPinMatches(rule.SourcePathContains, in.SourcePath) {
					continue
				}
				return list.verdict, rule
			}
		}
	}
	return "", AssetPolicyRule{}
}

// ToolListDecision matches asset_policy.tool.denied and .allowed for a tool
// call on connector, with the same precedence as AssetListDecision: a rule
// for this connector decides before an unscoped rule, and denied wins at
// the same scope. Tool names match case-sensitively, as the actions table
// did. It returns "" when no rule matches.
func (c *Config) ToolListDecision(tool, connector string) (string, AssetPolicyToolRule) {
	if c == nil {
		return "", AssetPolicyToolRule{}
	}
	tool, connector = strings.TrimSpace(tool), strings.TrimSpace(connector)
	if tool == "" {
		return "", AssetPolicyToolRule{}
	}
	for _, scoped := range []bool{true, false} {
		for _, list := range []struct {
			verdict string
			rules   []AssetPolicyToolRule
		}{{AssetListDeny, c.AssetPolicy.Tool.Denied}, {AssetListAllow, c.AssetPolicy.Tool.Allowed}} {
			for _, rule := range list.rules {
				ruleConnector := strings.TrimSpace(rule.Connector)
				if strings.TrimSpace(rule.Name) != tool || (ruleConnector != "") != scoped {
					continue
				}
				if scoped && !SameConnector(ruleConnector, connector) {
					continue
				}
				return list.verdict, rule
			}
		}
	}
	return "", AssetPolicyToolRule{}
}

// SameConnector reports whether two connector names name the same connector
// once aliases are normalized (claude-code and claude_code are claudecode,
// open-hands and open_hands are openhands). asset_policy rules compare
// connectors this way, as the Python lists do (connector_paths.normalize):
// the runtime always passes the canonical name.
func SameConnector(a, b string) bool {
	return normalizeConnectorKey(a) == normalizeConnectorKey(b)
}

// allowPinMatches is the stricter path test for an allow rule: a pinned
// allow only matches when the presented path contains the pin as whole path
// components (F-0941), so a look-alike sibling never inherits the allow.
func allowPinMatches(pins []string, path string) bool {
	if len(pins) == 0 {
		return true
	}
	for _, pin := range pins {
		if PathHasComponents(path, pin) {
			return true
		}
	}
	return false
}

// PathHasComponents reports whether path contains marker as a contiguous
// run of whole path components, case-insensitively and with either slash
// (F-0543): ".defenseclaw-evil" never matches ".defenseclaw". It is the Go
// twin of admission.rego _provenance_prefix_matches.
func PathHasComponents(path, marker string) bool {
	pathParts, markerParts := pathComponents(path), pathComponents(marker)
	n := len(markerParts)
	if n == 0 || len(pathParts) < n {
		return false
	}
	for i := 0; i+n <= len(pathParts); i++ {
		match := true
		for j := range markerParts {
			if pathParts[i+j] != markerParts[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func pathComponents(value string) []string {
	var out []string
	for _, part := range strings.Split(strings.ReplaceAll(strings.ToLower(value), "\\", "/"), "/") {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
