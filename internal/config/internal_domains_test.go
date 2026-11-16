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
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestInternalDomainHostMatchesDomainAndSubdomains(t *testing.T) {
	g := &GuardrailConfig{InternalDomains: []string{"Corp.Example.com", ".artifacts.example.org."}}
	for host, want := range map[string]bool{
		"corp.example.com":          true,
		"mirror.corp.example.com":   true,
		"MIRROR.CORP.EXAMPLE.COM.":  true,
		"a.artifacts.example.org":   true,
		"notcorp.example.com":       false,
		"corp.example.com.evil.net": false,
		"example.com":               false,
		"203.0.113.7":               false,
		"":                          false,
	} {
		if got := g.IsInternalDomainHost(host); got != want {
			t.Errorf("IsInternalDomainHost(%q) = %t, want %t", host, got, want)
		}
	}
	var unset *GuardrailConfig
	if unset.IsInternalDomainHost("corp.example.com") || (&GuardrailConfig{}).IsInternalDomainHost("corp.example.com") {
		t.Fatal("no internal domains configured, yet a host matched")
	}
}

func TestValidateInternalDomainsRejectsNonDomains(t *testing.T) {
	for _, bad := range []string{
		"https://corp.example.com", "corp.example.com:8443", "corp.example.com/path",
		"*.corp.example.com", "10.0.0.5", "-corp.example.com", "corp..example.com", " ",
		strings.Repeat("a", 64) + ".example.com",
	} {
		err := (&GuardrailConfig{InternalDomains: []string{bad}}).Validate()
		if err == nil || !strings.Contains(err.Error(), "guardrail.internal_domains") {
			t.Errorf("Validate(%q) = %v, want a guardrail.internal_domains error", bad, err)
		}
	}
	for _, good := range []string{"corp.example.com", ".corp.example.com", "CORP.example.com.", "lab"} {
		if err := (&GuardrailConfig{InternalDomains: []string{good}}).Validate(); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", good, err)
		}
	}
	tooMany := make([]string, maxInternalDomains+1)
	for index := range tooMany {
		tooMany[index] = "d" + strings.Repeat("x", index%40) + ".example.com"
	}
	if err := (&GuardrailConfig{InternalDomains: tooMany}).Validate(); err == nil {
		t.Fatal("Validate accepted more than maxInternalDomains entries")
	}
}

// TestInternalDomainsLoadFromConfig drives the key through the closed schema
// and the boot and reload loaders, and pins that the schema rejects a URL.
func TestInternalDomainsLoadFromConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(home, ".defenseclaw"))
	dataDir := filepath.Join(home, "state")
	document := func(entry string) []byte {
		return []byte(`config_version: 8
data_dir: ` + dataDir + `
guardrail:
  enabled: true
  internal_domains:
    - ` + entry + `
observability: {}
`)
	}
	raw := document("corp.example.com")
	options := ObservabilityV8CompileOptions{DefaultDataDir: dataDir}
	if _, err := ParseCompileObservabilityV8("config.yaml", raw, options); err != nil {
		t.Fatalf("v8 schema/compile rejected guardrail.internal_domains: %v", err)
	}
	for name, load := range map[string]func() (*Config, error){
		"activation": func() (*Config, error) { return LoadRuntimeV8FromBytes("config.yaml", raw) },
		"candidate":  func() (*Config, error) { return LoadRuntimeV8CandidateFromBytes("config.yaml", raw) },
	} {
		cfg, err := load()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := cfg.Guardrail.InternalDomains; !reflect.DeepEqual(got, []string{"corp.example.com"}) {
			t.Errorf("%s: InternalDomains = %v", name, got)
		}
		if !cfg.Guardrail.IsInternalDomainHost("mirror.corp.example.com") {
			t.Errorf("%s: mirror.corp.example.com is not internal", name)
		}
	}
	if _, err := ParseCompileObservabilityV8("config.yaml", document("https://corp.example.com/r"), options); err == nil {
		t.Fatal("the schema accepted a URL in guardrail.internal_domains")
	}
}
