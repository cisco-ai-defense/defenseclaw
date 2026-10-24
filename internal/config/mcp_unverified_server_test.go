// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// GAP-1195 (review loop 2): the gateway reads scanners.mcp_scanner.
// unverified_server as mcp set does: an explicit value wins, unset is warn,
// including managed standalone (Secure Client keeps its own admission).
func TestMCPUnverifiedServerBlocks(t *testing.T) {
	standalone := func(value string) *Config {
		return &Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone"},
			Scanners: ScannersConfig{MCPScanner: MCPScannerConfig{UnverifiedServer: value}}}
	}
	perUser := func(value string) *Config {
		return &Config{Scanners: ScannersConfig{MCPScanner: MCPScannerConfig{UnverifiedServer: value}}}
	}
	for _, tc := range []struct {
		name string
		cfg  *Config
		want bool
	}{
		{"per-user unset", perUser(""), false},
		{"per-user warn", perUser("warn"), false},
		{"per-user block", perUser(" Block "), true},
		{"standalone unset", standalone(""), false},
		{"standalone warn", standalone("warn"), false},
		{"standalone block", standalone("block"), true},
		{"no config", nil, true},
	} {
		if got := tc.cfg.MCPUnverifiedServerBlocks(); got != tc.want {
			t.Errorf("%s: MCPUnverifiedServerBlocks() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
