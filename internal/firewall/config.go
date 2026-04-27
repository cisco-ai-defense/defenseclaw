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

// Package firewall provides egress firewall policy config, rule compilation,
// observation, and status checking for DefenseClaw.
// It never requires root — compilation is pure Go, applying rules is the
// administrator's responsibility.
package firewall

import (
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DefaultAnchorName   = "com.defenseclaw"
	DefaultPFConfPath   = "/etc/pf.anchors/com.defenseclaw"
	DefaultConfigName   = "firewall.yaml"
	DefaultRulesName    = "firewall.pf.conf"
	DefaultIPTablesName = "firewall.iptables"
)

// FirewallConfig is the top-level firewall configuration.
type FirewallConfig struct {
	Version       string          `yaml:"version"`
	DefaultAction string          `yaml:"default_action"` // allow or deny
	Rules         []Rule          `yaml:"rules"`
	Allowlist     AllowlistConfig `yaml:"allowlist"`
	Logging       LoggingConfig   `yaml:"logging"`
}

// Rule defines a single named firewall rule.
type Rule struct {
	Name        string `yaml:"name"`
	Direction   string `yaml:"direction,omitempty"` // outbound only
	Protocol    string `yaml:"protocol,omitempty"`  // tcp, udp, any
	Destination string `yaml:"destination,omitempty"`
	Port        int    `yaml:"port,omitempty"`
	PortRange   string `yaml:"port_range,omitempty"`
	Action      string `yaml:"action"` // allow or deny
}

// AllowlistConfig defines allowed outbound destinations.
type AllowlistConfig struct {
	Domains []string `yaml:"domains"`
	IPs     []string `yaml:"ips"`
	Ports   []int    `yaml:"ports"`
}

// LoggingConfig configures firewall logging.
type LoggingConfig struct {
	Enabled   bool   `yaml:"enabled"`
	RateLimit string `yaml:"rate_limit"`
	Prefix    string `yaml:"prefix"`
}

// Load reads a FirewallConfig from a YAML file.
func Load(path string) (*FirewallConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("firewall: read config %s: %w", path, err)
	}
	var cfg FirewallConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("firewall: parse config: %w", err)
	}
	applyDefaults(&cfg)
	return &cfg, nil
}

// Save writes a FirewallConfig to a YAML file.
func Save(cfg *FirewallConfig, path string) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("firewall: marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}

// Validate checks the configuration for errors.
func (c *FirewallConfig) Validate() error {
	if c.DefaultAction != "allow" && c.DefaultAction != "deny" {
		return fmt.Errorf("firewall: default_action must be 'allow' or 'deny', got %q", c.DefaultAction)
	}
	for i, rule := range c.Rules {
		if rule.Name == "" {
			return fmt.Errorf("firewall: rule %d: missing name", i)
		}
		if rule.Action != "allow" && rule.Action != "deny" {
			return fmt.Errorf("firewall: rule %q: action must be 'allow' or 'deny'", rule.Name)
		}
		if rule.Direction != "" && rule.Direction != "outbound" {
			return fmt.Errorf("firewall: rule %q: only 'outbound' direction is supported", rule.Name)
		}
		if rule.Destination != "" {
			if err := validateDestination(rule.Destination); err != nil {
				return fmt.Errorf("firewall: rule %q: %w", rule.Name, err)
			}
		}
	}
	for _, ip := range c.Allowlist.IPs {
		if err := validateDestination(ip); err != nil {
			return fmt.Errorf("firewall: allowlist IP %q: %w", ip, err)
		}
	}
	return nil
}

// DefaultFirewallConfig returns a safe deny-by-default config with common
// allowlists pre-populated for the four built-in connectors.
//
// The list folds in domains every connector commonly reaches:
//
//   - api.openai.com          (OpenClaw + Codex baseline LLM)
//   - api.anthropic.com       (Claude Code baseline LLM)
//   - openrouter.ai           (ZeptoClaw default broker)
//   - api.together.xyz        (ZeptoClaw alt broker)
//   - api.github.com / github.com / objects.githubusercontent.com
//     (Codex update channel + skill/plugin pulls)
//   - claude.ai / docs.anthropic.com / console.anthropic.com
//     (Claude Code skill + plugin registry)
//   - openai.com / platform.openai.com (Codex docs/templates)
//   - us.api.inspect.aidefense.security.cisco.com (OpenClaw plugin)
//   - proxy.golang.org / sum.golang.org / registry.npmjs.org / pypi.org
//     (build-time package downloads when the agent shells out to
//      go/npm/pip during a tool call)
//
// The list is intentionally generous: a Codex / Claude Code /
// ZeptoClaw user with a deny-by-default firewall would otherwise see
// "DNS lookup blocked" on first chat, which is unactionable. See
// S3.3 / F26.
//
// Connectors that ship with a more-restrictive contract should
// implement connector.AllowedHostsProvider; sidecar bootstrap merges
// those values onto the static baseline before the firewall starts.
func DefaultFirewallConfig() *FirewallConfig {
	cfg := &FirewallConfig{
		Version:       "1.0",
		DefaultAction: "deny",
		Rules: []Rule{
			{
				Name:        "block-cloud-metadata",
				Direction:   "outbound",
				Protocol:    "tcp",
				Destination: "169.254.169.254",
				Action:      "deny",
			},
		},
		Allowlist: AllowlistConfig{
			Domains: []string{
				// LLM endpoints (per built-in connector).
				"api.anthropic.com",
				"api.openai.com",
				"openrouter.ai",
				"api.together.xyz",
				// Skill / plugin registries + docs CDNs.
				"claude.ai",
				"docs.anthropic.com",
				"console.anthropic.com",
				"openai.com",
				"platform.openai.com",
				// Code distribution + GitHub release artifacts.
				"api.github.com",
				"github.com",
				"objects.githubusercontent.com",
				"proxy.golang.org",
				"sum.golang.org",
				"registry.npmjs.org",
				"pypi.org",
				"files.pythonhosted.org",
				// Cisco AI Defense inspect endpoint (OpenClaw plugin).
				"us.api.inspect.aidefense.security.cisco.com",
			},
			IPs:   []string{},
			Ports: []int{443, 80},
		},
		Logging: LoggingConfig{
			Enabled:   true,
			RateLimit: "5/min",
			Prefix:    "[DEFENSECLAW-BLOCKED]",
		},
	}
	applyDefaults(cfg)
	return cfg
}

// MergeAllowedHosts adds extra hostnames to the firewall config's
// allow-list, deduplicating and skipping anything that fails
// validateDestination. This is the entrypoint for boot-time merging
// of per-connector contributions (connector.AllowedHostsProvider).
//
// The function is a method on *FirewallConfig rather than a free
// function so callers can chain `firewall.DefaultFirewallConfig().
// MergeAllowedHosts(extra)` without an intermediate variable, and
// so future fields (Ports, IPs) can hang off the same surface.
func (c *FirewallConfig) MergeAllowedHosts(extra []string) *FirewallConfig {
	if c == nil || len(extra) == 0 {
		return c
	}
	seen := make(map[string]struct{}, len(c.Allowlist.Domains)+len(extra))
	for _, d := range c.Allowlist.Domains {
		seen[d] = struct{}{}
	}
	for _, host := range extra {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if _, dup := seen[host]; dup {
			continue
		}
		// validateDestination accepts hostnames, IPs, and CIDRs;
		// AllowedHostsProvider should only return DNS names but the
		// validator catches typos cheaply.
		if err := validateDestination(host); err != nil {
			continue
		}
		seen[host] = struct{}{}
		c.Allowlist.Domains = append(c.Allowlist.Domains, host)
	}
	return c
}

func applyDefaults(cfg *FirewallConfig) {
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = "deny"
	}
	if cfg.Logging.Prefix == "" {
		cfg.Logging.Prefix = "[DEFENSECLAW-BLOCKED]"
	}
	if cfg.Logging.RateLimit == "" {
		cfg.Logging.RateLimit = "5/min"
	}
}

func validateDestination(dest string) error {
	if strings.Contains(dest, "/") {
		if _, _, err := net.ParseCIDR(dest); err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", dest, err)
		}
		return nil
	}
	if net.ParseIP(dest) != nil {
		return nil
	}
	if len(dest) == 0 || len(dest) > 253 {
		return fmt.Errorf("invalid hostname length: %q", dest)
	}
	return nil
}
