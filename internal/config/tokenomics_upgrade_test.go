// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// observability.tokenomics and observability.pricing are additive: a config
// written by an earlier release has neither block, and the 1.0.10 loader reads
// it as tokenomics off, no price table, the same behaviour as before. The
// goldens are the config_version 9 files earlier upgrades left. The home of a
// real 1.0.8 and 1.0.9 install is covered by the live upgrade cells.
func TestEarlierReleaseConfigsHaveTokenomicsOffAndNoPrices(t *testing.T) {
	goldens, err := filepath.Glob(filepath.Join("testdata", "upgrade", "*", "config.golden.yaml"))
	if err != nil || len(goldens) == 0 {
		t.Fatalf("no upgrade goldens: %v", err)
	}
	for _, golden := range goldens {
		raw, err := os.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.ReplaceAll(string(raw), "@HOME@", t.TempDir())
		var doc struct {
			Observability ObservabilityV8Source `yaml:"observability"`
		}
		if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
			t.Fatalf("%s: %v", golden, err)
		}
		tok, price := doc.Observability.Tokenomics, doc.Observability.Pricing
		if tok.Enabled || tok.LocalStore.Enabled || len(price.Models) != 0 || price.Version != "" {
			t.Errorf("%s: an earlier config must read as tokenomics off with no prices: %+v %+v", golden, tok, price)
		}
		if !tok.RecordsRoutingProvenance() || !tok.ComputesCost() || tok.UsageRetentionDays() != TokenomicsDefaultRetentionDays {
			t.Errorf("%s: defaults drifted", golden)
		}
		if err := (&ObservabilityConfig{Tokenomics: tok, Pricing: price}).Validate(); err != nil {
			t.Errorf("%s: %v", golden, err)
		}
	}
}

func TestTokenomicsDefaultsAndValidation(t *testing.T) {
	var tok TokenomicsConfig
	if tok.Enabled || len(tok.MetricLabels()) != len(TokenomicsMetricLabels) || !tok.RoleEnabled("router_classifier") {
		t.Fatalf("zero config must be off with every role and the closed label set: %+v", tok)
	}
	bad := []TokenomicsConfig{
		{Metrics: TokenomicsMetricsConfig{Labels: []string{"user"}}},
		{Metrics: TokenomicsMetricsConfig{Labels: []string{"connector", "connector"}}},
		{Metrics: TokenomicsMetricsConfig{Labels: []string{"nonsense"}}},
		{Roles: []string{"intruder"}},
		{Cost: TokenomicsCostConfig{Currency: "EUR"}},
		{LocalStore: TokenomicsLocalStoreConfig{RetentionDays: 4000}},
		{LocalStore: TokenomicsLocalStoreConfig{Granularity: "day"}},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("case %d: %+v was accepted", i, c)
		}
	}
	one := 1.0
	badPrice := []PricingConfig{
		{Models: []PriceEntryConfig{{Provider: "a", Model: "b", PriceRatesConfig: PriceRatesConfig{InputPerMTok: &one, OutputPerMTok: &one}}}}, // no version
		{Version: "v", Models: []PriceEntryConfig{{Provider: "a", Model: "b", PriceRatesConfig: PriceRatesConfig{InputPerMTok: &one}}}},        // no output price
		{Version: "v", Models: []PriceEntryConfig{{Provider: "a", Model: "b*c", PriceRatesConfig: PriceRatesConfig{InputPerMTok: &one, OutputPerMTok: &one}}}},
		{Version: "v", UnknownModel: "fallback"},
		{Version: "v", UnknownModel: "guess"},
	}
	for i, c := range badPrice {
		if err := c.Validate(); err == nil {
			t.Errorf("price case %d was accepted: %+v", i, c)
		}
	}
	neg := -1.0
	if err := (PricingConfig{Version: "v", Models: []PriceEntryConfig{{Provider: "a", Model: "b", PriceRatesConfig: PriceRatesConfig{InputPerMTok: &neg, OutputPerMTok: &one}}}}).Validate(); err == nil {
		t.Error("a negative price was accepted")
	}
	dup := PricingConfig{Version: "v", Models: []PriceEntryConfig{
		{Provider: "A", Model: "B", PriceRatesConfig: PriceRatesConfig{InputPerMTok: &one, OutputPerMTok: &one}},
		{Provider: "a ", Model: " b", PriceRatesConfig: PriceRatesConfig{InputPerMTok: &one, OutputPerMTok: &one}},
	}}
	if err := dup.Validate(); err == nil {
		t.Error("a duplicate provider/model (case and spaces) was accepted")
	}
}
