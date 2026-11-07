// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/configs"
)

// overlayRegistryForTest is the embedded provider registry with the overlay
// in overlayJSON merged over it, built without reading the environment, the
// data directory or the process-wide registry. A request carries it in
// ChatRequest.providers, as a request pinned to a generation does in the
// gateway (GAP-1294), so the resolver tests below depend on no state that
// another test or a background reload can change (GAP-0741).
func overlayRegistryForTest(t *testing.T, overlayJSON string) *configs.ProvidersConfig {
	t.Helper()
	registry, err := configs.LoadEmbeddedProviders()
	if err != nil {
		t.Fatalf("LoadEmbeddedProviders: %v", err)
	}
	var overlay configs.ProvidersConfig
	if err := json.Unmarshal([]byte(overlayJSON), &overlay); err != nil {
		t.Fatalf("parse overlay: %v", err)
	}
	configs.ApplyOverlay(registry, overlay)
	return registry
}

// GAP-0741: the overlay resolver test failed once under a -race gate run,
// after it had reloaded the process-wide registry from the environment. That
// registry, the live generation and the managed ignore-environment flag are
// written by other tests and by sidecar goroutines. The resolver must return
// the overlay-bound provider from the registry the request carries, whatever
// those hold.
func TestResolveProvider_InstanceOverlay_IgnoresProcessWideState(t *testing.T) {
	previousRegistry, _, _ := providerRegistrySnapshot()
	previousGeneration := liveGeneration.Load()
	t.Cleanup(func() {
		liveGeneration.Store(previousGeneration)
		configs.SetIgnoreCustomProvidersPathEnv(false)
		if previousRegistry != nil {
			setProviderRegistry(previousRegistry)
		}
	})
	// What a leaked managed sidecar or a concurrent reload leaves behind: a
	// published generation without the overlay, the environment path ignored
	// and a registry that does not know the host.
	liveGeneration.Store(&Generation{Config: &config.Config{}})
	configs.SetIgnoreCustomProvidersPathEnv(true)
	setProviderRegistry(&configs.ProvidersConfig{Providers: []configs.Provider{{Name: "unrelated", Domains: []string{"unrelated.example"}}}})

	registry := overlayRegistryForTest(t, `{
		"providers": [{
			"name": "acme-bedrock",
			"domains": ["llm.acme.internal"],
			"base_provider_type": "bedrock",
			"base_url": "https://llm.acme.internal:8443"
		}]
	}`)
	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	proxy.cfg.LLM.InstanceName = "acme-bedrock"
	got := proxy.resolveProviderFromHeaders(&ChatRequest{
		Model:        "acme-bedrock/anthropic.claude-3-opus-20240229-v1:0",
		Messages:     []ChatMessage{{Role: "user", Content: "hi"}},
		TargetAPIKey: "test-key",
		TargetURL:    "https://llm.acme.internal:8443",
		providers:    registry,
	})
	bp, ok := got.(*bifrostProvider)
	if !ok {
		t.Fatalf("resolved %T, want the overlay-bound *bifrostProvider", got)
	}
	if bp.baseURL != "https://llm.acme.internal:8443" {
		t.Fatalf("baseURL = %q, want the overlay's", bp.baseURL)
	}
}
