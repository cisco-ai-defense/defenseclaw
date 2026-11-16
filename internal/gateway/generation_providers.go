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
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/configs"
)

// llmBaseURLProviderName is the in-memory provider that makes llm.base_url's
// host a known provider domain when no built-in or custom provider covers
// it. It replaces the seeder that overwrote custom-providers.json with this
// one entry.
const llmBaseURLProviderName = "custom-gateway"

// buildGenerationProviders is a generation's LLM provider registry: the
// embedded providers.json, the legacy operator overlay for non-managed
// profiles (configs.LoadProviders skips a derived one), then llm_providers
// from config, then llm.base_url's host when nothing above knows it. While a
// legacy overlay is a live input (its fold into config.yaml was refused),
// llm_providers merges with the header rule that overlay had before 1.0.3
// (configs.ApplyLegacyOverlay), so the upgrade changes no header in use
// (GAP-0184); once config.yaml is the only input, same-name entries keep
// their headers (GAP-0361).
// Managed standalone uses only config.yaml additions (GAP-0443); loading a
// per-user overlay would make an offline bundle depend on the signer's home.
func buildGenerationProviders(cfg *config.Config) (*generationProviders, error) {
	return buildGenerationProvidersForScope(cfg, digestScope{}, false)
}

func buildGenerationProvidersForScope(cfg *config.Config, scope digestScope, offline bool) (*generationProviders, error) {
	var reg *configs.ProvidersConfig
	var err error
	legacyOverlay := false
	if cfg != nil && cfg.StandaloneEnterprise() {
		reg, err = configs.LoadEmbeddedProviders()
	} else {
		reg, legacyOverlay, err = configs.LoadProvidersWithOverlay()
	}
	if err != nil || reg == nil {
		reg = &configs.ProvidersConfig{}
	}
	if cfg != nil {
		overlay := configs.ProvidersConfig{OllamaPorts: append([]int(nil), cfg.LLMProviders.OllamaPorts...)}
		for _, custom := range cfg.LLMProviders.Custom {
			if offline && custom.TLS != nil && !scope.bundleFile(custom.TLS.CACertFile) {
				copy := *custom.TLS
				copy.CACertFile = ""
				custom.TLS = &copy
			}
			provider, err := providerFromConfig(custom)
			if err != nil {
				return nil, err
			}
			overlay.Providers = append(overlay.Providers, provider)
		}
		if legacyOverlay {
			configs.ApplyLegacyOverlay(reg, overlay)
		} else {
			configs.ApplyOverlay(reg, overlay)
		}
		if host := llmBaseURLHost(cfg.LLM.BaseURL); host != "" && !registryKnowsHost(reg, host) {
			configs.ApplyOverlay(reg, configs.ProvidersConfig{Providers: []configs.Provider{{
				Name: llmBaseURLProviderName, Domains: []string{host}, EnvKeys: []string{"LLM_GATEWAY"},
			}}})
		}
	}
	return &generationProviders{Providers: reg.Providers, OllamaPorts: reg.OllamaPorts, OverlayApplied: legacyOverlay}, nil
}

// providerFromConfig converts one llm_providers.custom entry. A TLS CA file
// is read into the inline PEM the provider adapter takes. A configured CA
// must be available before the generation can be published.
func providerFromConfig(in config.LLMCustomProvider) (configs.Provider, error) {
	out := configs.Provider{
		Name:                 in.Name,
		Domains:              append([]string(nil), in.Domains...),
		EnvKeys:              append([]string(nil), in.EnvKeys...),
		BaseProviderType:     in.BaseProviderType,
		BaseURL:              in.BaseURL,
		AllowedRequests:      append([]string(nil), in.AllowedRequests...),
		AvailableModels:      append([]string(nil), in.AvailableModels...),
		RequestPathOverrides: in.RequestPathOverrides,
		ExtraHeaders:         in.ExtraHeaders,
	}
	if id := strings.TrimSpace(in.ProfileID); id != "" {
		out.ProfileID = &id
	}
	if in.TLS != nil {
		tls := &configs.ProviderTLS{InsecureSkipVerify: in.TLS.InsecureSkipVerify}
		if path := strings.TrimSpace(in.TLS.CACertFile); path != "" {
			pem, err := os.ReadFile(path) // #nosec G304 -- llm_providers.custom[].tls.ca_cert_file.
			if err != nil {
				return configs.Provider{}, fmt.Errorf("llm_providers.custom %q: read CA file %q: %w", in.Name, path, err)
			} else {
				tls.CACertPEM = string(pem)
			}
		}
		out.TLS = tls
	}
	if b := in.Bedrock; b != nil {
		out.Bedrock = &configs.ProviderBedrock{
			Region: b.Region, AuthMode: b.AuthMode, AccessKeyEnv: b.AccessKeyEnv, SecretKeyEnv: b.SecretKeyEnv,
			SessionTokenEnv: b.SessionTokenEnv, ProfileName: b.ProfileName, InferenceProfile: b.InferenceProfile,
			DeploymentAliases: b.DeploymentAliases,
		}
	}
	if v := in.Vertex; v != nil {
		out.Vertex = &configs.ProviderVertex{
			ProjectID: v.ProjectID, Region: v.Region, AuthMode: v.AuthMode, ServiceAccountJSONEnv: v.ServiceAccountJSONEnv,
		}
	}
	if a := in.Azure; a != nil {
		out.Azure = &configs.ProviderAzure{
			Endpoint: a.Endpoint, APIVersion: a.APIVersion, AuthMode: a.AuthMode, DeploymentAliases: a.DeploymentAliases,
		}
	}
	return out, nil
}

// llmBaseURLHost is llm.base_url's lower-cased host, "" for an empty,
// unparseable or loopback URL (local models are matched by port).
func llmBaseURLHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || host == "127.0.0.1" || host == "localhost" || host == "::1" {
		return ""
	}
	return host
}

func registryKnowsHost(reg *configs.ProvidersConfig, host string) bool {
	for _, provider := range reg.Providers {
		for _, domain := range provider.Domains {
			if strings.EqualFold(domain, host) {
				return true
			}
		}
	}
	return false
}

// digest is the providers component of the effective policy digest.
func (p *generationProviders) digest() string {
	if p == nil {
		return ""
	}
	raw, _ := json.Marshal(struct {
		Providers   []configs.Provider `json:"providers"`
		OllamaPorts []int              `json:"ollama_ports"`
	}{p.Providers, p.OllamaPorts})
	return sha256Digest(raw)
}

// digestForBundle removes external CA bytes from the signed provider view.
// The configured path remains in config; only bundle-shipped CA bytes are
// content-addressed by a bundle.
func (p *generationProviders) digestForBundle(cfg *config.Config, scope digestScope) string {
	if p == nil || scope.bundleRoot == "" {
		return p.digest()
	}
	copy := *p
	copy.Providers = append([]configs.Provider(nil), p.Providers...)
	for _, custom := range cfg.LLMProviders.Custom {
		if custom.TLS == nil || scope.bundleFile(custom.TLS.CACertFile) {
			continue
		}
		for i := range copy.Providers {
			if copy.Providers[i].Name == custom.Name && copy.Providers[i].TLS != nil {
				tls := *copy.Providers[i].TLS
				tls.CACertPEM = ""
				copy.Providers[i].TLS = &tls
			}
		}
	}
	return copy.digest()
}

// applyGenerationProviders makes p the proxy's provider registry.
func applyGenerationProviders(p *generationProviders) {
	if p == nil {
		return
	}
	setProviderRegistryWithOverlay(&configs.ProvidersConfig{Providers: p.Providers, OllamaPorts: p.OllamaPorts}, p.OverlayApplied)
}
