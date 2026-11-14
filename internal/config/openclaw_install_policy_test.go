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

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// connectors.openclaw.install_policy: auto is on only in the strict tier
// and on managed installs (balanced defaults), on and off win, and the
// outage answer closes in strict and managed.
func TestOpenClawInstallPolicyResolution(t *testing.T) {
	standalone := func(c *Config) {
		c.DeploymentMode = managed.DeploymentModeManagedEnterprise
		c.Enterprise.Profile = managed.ProfileStandalone
	}
	for _, tc := range []struct {
		name       string
		setup      func(*Config)
		on, closed bool
	}{
		{"OSS default", func(*Config) {}, false, false},
		{"OSS permissive", func(c *Config) { c.Guardrail.RulePack = "permissive" }, false, false},
		{"OSS strict", func(c *Config) { c.Guardrail.RulePack = "strict" }, true, true},
		{"OSS strict openclaw pack", func(c *Config) {
			c.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"openclaw": {RulePack: "strict"}}
		}, true, true},
		{"OSS strict other connector", func(c *Config) {
			c.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"codex": {RulePack: "strict"}}
		}, false, false},
		{"OSS default, on", func(c *Config) { c.Connectors.OpenClaw.InstallPolicy = "on" }, true, false},
		{"OSS default, saved closed", func(c *Config) { c.Guardrail.HookFailMode = "closed" }, false, true},
		{"OSS strict, off", func(c *Config) {
			c.Guardrail.RulePack = "strict"
			c.Connectors.OpenClaw.InstallPolicy = "OFF"
		}, false, true},
		{"managed default", standalone, true, true},
		{"managed, administrator open", func(c *Config) { standalone(c); c.Guardrail.HookFailMode = "open" }, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			tc.setup(cfg)
			if got := cfg.OpenClawInstallPolicyOn(); got != tc.on {
				t.Errorf("OpenClawInstallPolicyOn = %v, want %v", got, tc.on)
			}
			if got := cfg.OpenClawInstallPolicyFailsClosed(); got != tc.closed {
				t.Errorf("OpenClawInstallPolicyFailsClosed = %v, want %v", got, tc.closed)
			}
		})
	}
	if (*Config)(nil).OpenClawInstallPolicyOn() || !(*Config)(nil).OpenClawInstallPolicyFailsClosed() {
		t.Fatal("a nil config must not turn install admission on and must fail closed")
	}
}

func TestOpenClawInstallPolicyValidationAndTimeout(t *testing.T) {
	for _, v := range []string{"", "auto", "on", "off", "On"} {
		cfg := &Config{}
		cfg.Connectors.OpenClaw.InstallPolicy = v
		if err := cfg.ValidateOpenClawConnector(); err != nil {
			t.Errorf("install_policy %q refused: %v", v, err)
		}
	}
	cfg := &Config{}
	cfg.Connectors.OpenClaw.InstallPolicy = "yes"
	if err := cfg.ValidateOpenClawConnector(); err == nil || !strings.Contains(err.Error(), "install_policy") {
		t.Fatalf("install_policy yes accepted: %v", err)
	}
	cfg = &Config{}
	if got := cfg.OpenClawInstallPolicyTimeoutMs(); got != (defaultSkillScannerScanTimeoutS+15)*1000 {
		t.Errorf("default timeout = %d", got)
	}
	cfg.Scanners.SkillScanner.Timeouts.ScanS = 5
	if got := cfg.OpenClawInstallPolicyTimeoutMs(); got != 135000 {
		t.Errorf("timeout with a 5 s skill scan = %d, want the 120 s plugin scan + 15 s", got)
	}
	cfg.Scanners.SkillScanner.Timeouts.ScanS = 3600
	if got := cfg.OpenClawInstallPolicyTimeoutMs(); got != 600000 {
		t.Errorf("timeout cap = %d, want 600000", got)
	}
}
