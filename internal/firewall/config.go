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
// allowlists pre-populated for OpenClaw.
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
				"api.anthropic.com",
				"api.openai.com",
				"api.github.com",
				"github.com",
				"proxy.golang.org",
				"sum.golang.org",
				"registry.npmjs.org",
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
