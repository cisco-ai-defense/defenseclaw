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
	"os"
	"path/filepath"
	"testing"
)

func legacyShimConfig(mode, guardrailHost, apiBind string) *Config {
	cfg := &Config{}
	cfg.OpenShell.Mode = mode
	cfg.Guardrail.Host = guardrailHost
	cfg.Gateway.APIBind = apiBind
	return cfg
}

func TestLegacyStandaloneAPIHost(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *Config
		wantHost string
		wantOK   bool
	}{
		{"nil config", nil, "", false},
		{"host mode", legacyShimConfig("", "10.200.0.1", ""), "", false},
		{"unknown mode", legacyShimConfig("cluster", "10.200.0.1", ""), "", false},
		{"legacy veth host", legacyShimConfig("standalone", "10.200.0.1", ""), "10.200.0.1", true},
		{"legacy host trimmed", legacyShimConfig("standalone", " 10.200.0.1 ", ""), "10.200.0.1", true},
		{"legacy localhost", legacyShimConfig("standalone", "localhost", ""), "", false},
		{"legacy guardrail unset", legacyShimConfig("standalone", "", ""), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, ok := LegacyStandaloneAPIHost(tt.cfg)
			if host != tt.wantHost || ok != tt.wantOK {
				t.Fatalf("LegacyStandaloneAPIHost() = (%q, %v), want (%q, %v)", host, ok, tt.wantHost, tt.wantOK)
			}
			if got, want := IsLegacyStandalone(tt.cfg), tt.cfg != nil && tt.cfg.OpenShell.Mode == "standalone"; got != want {
				t.Fatalf("IsLegacyStandalone() = %v, want %v", got, want)
			}
		})
	}
}

func TestAPIBindHostPrecedence(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want string
	}{
		{"nil config", nil, "127.0.0.1"},
		{"default loopback", legacyShimConfig("", "localhost", ""), "127.0.0.1"},
		{"host mode ignores guardrail host", legacyShimConfig("", "10.200.0.1", ""), "127.0.0.1"},
		{"legacy shim", legacyShimConfig("standalone", "10.200.0.1", ""), "10.200.0.1"},
		{"legacy localhost stays loopback", legacyShimConfig("standalone", "localhost", ""), "127.0.0.1"},
		{"explicit api_bind wins over shim", legacyShimConfig("standalone", "10.200.0.1", "0.0.0.0"), "0.0.0.0"},
		{"explicit api_bind", legacyShimConfig("", "localhost", "::1"), "::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := APIBindHost(tt.cfg); got != tt.want {
				t.Fatalf("APIBindHost() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLegacyStandalonePlainGatewayWS(t *testing.T) {
	legacy := legacyShimConfig("standalone", "10.200.0.1", "")
	legacy.Gateway.Host = "10.200.0.2"
	if !LegacyStandalonePlainGatewayWS(legacy) {
		t.Fatal("legacy veth link must stay on plain WS")
	}
	legacy.Gateway.TLS = true
	if LegacyStandalonePlainGatewayWS(legacy) {
		t.Fatal("gateway.tls must force TLS on a legacy install")
	}
	host := legacyShimConfig("", "localhost", "")
	host.Gateway.Host = "10.200.0.2"
	if LegacyStandalonePlainGatewayWS(host) {
		t.Fatal("the shim must not disable TLS for a remote gateway outside legacy mode")
	}
	if LegacyStandalonePlainGatewayWS(nil) {
		t.Fatal("nil config must not report legacy plain WS")
	}
}

func TestLegacySandboxHome(t *testing.T) {
	if got := LegacySandboxHome(legacyShimConfig("", "", "")); got != "" {
		t.Fatalf("host mode sandbox home = %q, want empty", got)
	}
	legacy := legacyShimConfig("standalone", "10.200.0.1", "")
	if got := LegacySandboxHome(legacy); got != DefaultSandboxHome {
		t.Fatalf("legacy default sandbox home = %q, want %q", got, DefaultSandboxHome)
	}
	legacy.OpenShell.SandboxHome = "/srv/sandbox"
	if got := LegacySandboxHome(legacy); got != "/srv/sandbox" {
		t.Fatalf("legacy recorded sandbox home = %q, want /srv/sandbox", got)
	}
}

// A legacy host's config must keep loading after the integration is removed:
// the v8 schema still accepts every legacy openshell sub-key, the ignored ones
// are dropped, and the shim fields drive the API bind and sandbox home.
func TestLegacyOpenShellConfigStillLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := `config_version: 8
data_dir: ` + dir + `
guardrail:
  host: 10.200.0.1
openshell:
  binary: openshell
  policy_dir: /etc/openshell/policies
  mode: standalone
  version: 0.6.2
  sandbox_home: /srv/sandbox
  auto_pair: true
  host_networking: true
`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if !IsLegacyStandalone(cfg) {
		t.Fatalf("openshell.mode = %q, want standalone", cfg.OpenShell.Mode)
	}
	if got := APIBindHost(cfg); got != "10.200.0.1" {
		t.Fatalf("APIBindHost() = %q, want the legacy veth host", got)
	}
	if cfg.Gateway.SandboxHome != "/srv/sandbox" {
		t.Fatalf("gateway sandbox home = %q, want /srv/sandbox", cfg.Gateway.SandboxHome)
	}
}
