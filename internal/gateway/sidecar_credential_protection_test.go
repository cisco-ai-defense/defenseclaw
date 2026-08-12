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

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestCredentialProtectionCoverageDoesNotClaimDirectUpstreamProtection(t *testing.T) {
	cfg := &config.Config{}
	if got := credentialProtectionCoverage(cfg, true); got != "disabled" {
		t.Fatalf("disabled coverage = %q", got)
	}
	cfg.CredentialProtection.Enabled = true
	if got := credentialProtectionCoverage(cfg, false); got != "not_in_direct_upstream_path" {
		t.Fatalf("direct-upstream coverage = %q", got)
	}
	if got := credentialProtectionCoverage(cfg, true); got != "proxy_tokenization" {
		t.Fatalf("proxy coverage = %q", got)
	}
}

func TestCredentialProtectionConfigChangeRestartsGuardrail(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := config.DefaultConfig()
	newCfg.CredentialProtection.Enabled = true

	if !guardrailNeedsRestart(oldCfg, newCfg) {
		t.Fatal("credential protection change did not restart the guardrail runtime")
	}
}

func TestGuardrailProxyCredentialProtectionCoverageRequiresTokenizer(t *testing.T) {
	proxy := &GuardrailProxy{}
	if got := proxy.credentialProtectionCoverage(); got != "disabled" {
		t.Fatalf("default coverage = %q", got)
	}
	proxy.SetCredentialTokenizer(true, nil)
	if got := proxy.credentialProtectionCoverage(); got != "unavailable" {
		t.Fatalf("missing tokenizer coverage = %q", got)
	}
	proxy.SetCredentialTokenizer(true, &fakeCredentialTokenizer{})
	if got := proxy.credentialProtectionCoverage(); got != "proxy_tokenization" {
		t.Fatalf("ready coverage = %q", got)
	}
}

func TestCredentialTokenizerStartsOnlyForEnabledProxyPath(t *testing.T) {
	registry := connector.NewDefaultRegistry()
	openclaw, ok := registry.Get("openclaw")
	if !ok {
		t.Fatal("openclaw connector is unavailable")
	}
	codex, ok := registry.Get("codex")
	if !ok {
		t.Fatal("codex connector is unavailable")
	}

	cfg := &config.Config{}
	cfg.Guardrail.Enabled = true
	cfg.CredentialProtection.Enabled = true
	if !credentialTokenizerRequired(cfg, openclaw) {
		t.Fatal("enabled proxy connector did not require the tokenizer")
	}
	if credentialTokenizerRequired(cfg, codex) {
		t.Fatal("direct-upstream connector required the proxy tokenizer")
	}

	cfg.Guardrail.Enabled = false
	if credentialTokenizerRequired(cfg, openclaw) {
		t.Fatal("disabled guardrail required the proxy tokenizer")
	}
}
