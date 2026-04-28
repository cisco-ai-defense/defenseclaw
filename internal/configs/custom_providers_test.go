// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package configs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadProviders_NoOverlay verifies the baseline: when the overlay
// file is absent the built-in registry is returned unchanged.
func TestLoadProviders_NoOverlay(t *testing.T) {
	dir := t.TempDir()
	// Point the overlay at a non-existent file.
	t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", filepath.Join(dir, "missing.json"))
	cfg, err := LoadProviders()
	if err != nil {
		t.Fatalf("LoadProviders: %v", err)
	}
	if len(cfg.Providers) == 0 {
		t.Fatalf("expected built-in providers, got none")
	}
}

// TestLoadProviders_OverlayExtendsBuiltins covers the common case:
// an operator adds a brand-new provider entry. The built-ins must
// still be present and the new entry must be appended.
func TestLoadProviders_OverlayExtendsBuiltins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-providers.json")
	body := `{
		"providers": [
			{"name": "LocalVLLM", "domains": ["llm.internal.example.com"], "env_keys": ["LOCAL_KEY"]}
		],
		"ollama_ports": [31234]
	}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", path)

	cfg, err := LoadProviders()
	if err != nil {
		t.Fatalf("LoadProviders: %v", err)
	}

	var gotCustom *Provider
	for i := range cfg.Providers {
		if strings.EqualFold(cfg.Providers[i].Name, "LocalVLLM") {
			gotCustom = &cfg.Providers[i]
			break
		}
	}
	if gotCustom == nil {
		t.Fatalf("overlay provider not merged; providers=%+v", cfg.Providers)
		return
	}
	if len(gotCustom.Domains) != 1 || gotCustom.Domains[0] != "llm.internal.example.com" {
		t.Fatalf("unexpected domains: %v", gotCustom.Domains)
	}

	// Ollama ports must also union in.
	seen := false
	for _, p := range cfg.OllamaPorts {
		if p == 31234 {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("custom ollama port not merged: %v", cfg.OllamaPorts)
	}

	// A built-in must still be present — we never replace.
	foundOpenAI := false
	for _, p := range cfg.Providers {
		if strings.EqualFold(p.Name, "openai") {
			foundOpenAI = true
			break
		}
	}
	if !foundOpenAI {
		t.Fatalf("built-in openai entry dropped after overlay merge")
	}
}

// TestLoadProviders_OverlayExtendsExistingProvider covers the case
// where an operator adds a new internal domain to an already-known
// provider (e.g., an Azure-OpenAI instance on a custom hostname).
// The match is case-insensitive by Name and additive on Domains.
func TestLoadProviders_OverlayExtendsExistingProvider(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-providers.json")
	// Note the name is uppercased to prove case-insensitive match.
	body := `{
		"providers": [
			{"name": "OPENAI", "domains": ["openai.internal.example.com"]}
		]
	}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", path)

	cfg, err := LoadProviders()
	if err != nil {
		t.Fatalf("LoadProviders: %v", err)
	}
	// Find openai and check the custom domain was appended.
	found := false
	for _, p := range cfg.Providers {
		if !strings.EqualFold(p.Name, "openai") {
			continue
		}
		for _, d := range p.Domains {
			if d == "openai.internal.example.com" {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatalf("overlay domain not unioned into openai entry")
	}
}

// TestLoadProviders_OverlayParseErrorIsNonFatal: a malformed overlay
// MUST fall back to built-ins rather than take the guardrail offline.
// This is the single most important property of the overlay system.
func TestLoadProviders_OverlayParseErrorIsNonFatal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-providers.json")
	if err := os.WriteFile(path, []byte(`{this is not json`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", path)

	cfg, err := LoadProviders()
	if err != nil {
		t.Fatalf("LoadProviders should tolerate overlay parse errors: %v", err)
	}
	if len(cfg.Providers) == 0 {
		t.Fatalf("parse error must not drop built-in providers")
	}
}

// TestLoadProviders_OverlayTooLargeIsRejected guards the 1 MiB
// overlay read cap. An accidental (or malicious) overlay that grows
// past the cap must fall back to the built-in list instead of
// reading unbounded memory into the guardrail process.
func TestLoadProviders_OverlayTooLargeIsRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-providers.json")
	// Write a file just over the 1 MiB cap. Padding inside a JSON
	// comment-ish key makes the file both valid-looking and large;
	// the parser never runs because the size gate trips first.
	big := make([]byte, maxOverlayBytes+1024)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(path, big, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", path)

	cfg, err := LoadProviders()
	if err != nil {
		t.Fatalf("LoadProviders should tolerate oversize overlay: %v", err)
	}
	if len(cfg.Providers) == 0 {
		t.Fatalf("oversize overlay must not drop built-in providers")
	}
}

// TestApplyOverlay_NormalizesDomainCase locks in the fix for
// silently dead entries: a hand-edited overlay with mixed-case
// domain must match traffic to the lowercase equivalent. Before the
// fix, inferProviderFromURL would lowercase the request host but
// compare against the raw overlay entry — producing a never-match.
func TestApplyOverlay_NormalizesDomainCase(t *testing.T) {
	base := ProvidersConfig{
		Providers: []Provider{{Name: "openai", Domains: []string{"api.openai.com"}}},
	}
	overlay := ProvidersConfig{
		Providers: []Provider{
			{Name: "InternalLLM", Domains: []string{"LLM.CORP.Example.COM", "Api.OpenAI.Com"}},
		},
	}
	applyOverlay(&base, overlay)
	// InternalLLM must have both domains in lowercase form.
	var internal *Provider
	for i := range base.Providers {
		if strings.EqualFold(base.Providers[i].Name, "InternalLLM") {
			internal = &base.Providers[i]
			break
		}
	}
	if internal == nil {
		t.Fatalf("InternalLLM not merged into registry")
		return
	}
	for _, d := range internal.Domains {
		if d != strings.ToLower(d) {
			t.Errorf("overlay domain not lowercased: %q", d)
		}
	}
	// The "Api.OpenAI.Com" overlay entry should NOT double up the
	// base openai entry — it's case-equivalent to "api.openai.com".
	// (Since it was attached to a different provider name here it
	// will land on InternalLLM; the dedup property is asserted by
	// TestApplyOverlay_DeduplicatesDomains when names match.)
}

// TestApplyOverlay_DeduplicatesDomains ensures that if the overlay
// lists a domain that the built-in registry already advertised, we
// don't end up with a duplicate matcher (perf + log noise cost).
func TestApplyOverlay_DeduplicatesDomains(t *testing.T) {
	base := ProvidersConfig{
		Providers: []Provider{
			{Name: "openai", Domains: []string{"api.openai.com"}},
		},
		OllamaPorts: []int{11434},
	}
	overlay := ProvidersConfig{
		Providers: []Provider{
			{Name: "openai", Domains: []string{"api.openai.com", "api.openai.com"}},
		},
		OllamaPorts: []int{11434, 11434},
	}
	applyOverlay(&base, overlay)
	var count int
	for _, d := range base.Providers[0].Domains {
		if d == "api.openai.com" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected domain to remain unique, got %d copies", count)
	}
	var portCount int
	for _, p := range base.OllamaPorts {
		if p == 11434 {
			portCount++
		}
	}
	if portCount != 1 {
		t.Fatalf("expected ollama port to remain unique, got %d copies", portCount)
	}
}
