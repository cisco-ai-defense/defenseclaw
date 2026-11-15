// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func baselineTable() config.PricingConfig {
	rate := func(in, out float64) config.PriceRatesConfig {
		return config.PriceRatesConfig{InputPerMTok: f(in), OutputPerMTok: f(out)}
	}
	return config.PricingConfig{Version: "b1", Models: []config.PriceEntryConfig{
		{Provider: "anthropic", Model: "claude-haiku-4-5*", PriceRatesConfig: rate(1, 5)},
		{Provider: "anthropic", Model: "claude-sonnet-4-5*", PriceRatesConfig: rate(3, 15)},
	}}
}

func priced(t *testing.T, mut func(*CallFacts)) Record {
	t.Helper()
	e := NewEngine(newCapture())
	e.Apply(enabled(), baselineTable())
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	fa := facts()
	if mut != nil {
		mut(&fa)
	}
	c := e.Begin(context.Background(), fa)
	c.Usage(ParsedUsage{Input: 1000, Output: 500, Has: HasInput | HasOutput})
	return c.End(nil)
}

func TestBaselinePricesTheRequestedModelOnTheSameTokens(t *testing.T) {
	rec := priced(t, nil)
	if rec.Cost.USD == nil || rec.Cost.BaselineUSD == nil || *rec.Cost.USD != 0.0035 || *rec.Cost.BaselineUSD != 0.0105 {
		t.Fatalf("cost %+v", rec.Cost)
	}
}

func TestBaselineIsAbsentNotZero(t *testing.T) {
	for name, mut := range map[string]func(*CallFacts){
		"requested model has no price": func(fa *CallFacts) { fa.RequestedModel = "claude-unpriced-9" },
		"no requested model":           func(fa *CallFacts) { fa.RequestedModel = "" },
		"not an agent call":            func(fa *CallFacts) { fa.CallRole = RoleJudge },
		"the call itself has no price": func(fa *CallFacts) { fa.SelectedModel = "claude-unpriced-9" },
	} {
		if rec := priced(t, mut); rec.Cost.BaselineUSD != nil {
			t.Errorf("%s: baseline = %v, want absent", name, *rec.Cost.BaselineUSD)
		}
	}
	// With cost computation off nothing is priced at all.
	e := NewEngine(newCapture())
	tok := enabled()
	off := false
	tok.Cost.Compute = &off
	e.Apply(tok, baselineTable())
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	c := e.Begin(context.Background(), facts())
	c.Usage(ParsedUsage{Input: 1000, Output: 500, Has: HasInput | HasOutput})
	if rec := c.End(nil); rec.Cost.BaselineUSD != nil || rec.Cost.USD != nil {
		t.Fatalf("cost off: %+v", rec.Cost)
	}
}

func TestBaselineEqualsCostForAnUnroutedCall(t *testing.T) {
	rec := priced(t, func(fa *CallFacts) { fa.RequestedModel = fa.SelectedModel })
	if rec.Cost.BaselineUSD == nil || *rec.Cost.BaselineUSD != *rec.Cost.USD {
		t.Fatalf("unrouted call: %+v", rec.Cost)
	}
}
