// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestPriceLookupSharedCases runs the price-table cases that the CLI's
// cli/defenseclaw/price_lookup.py (doctor, routing rules list) is held to as
// well, so the two never disagree on whether a model has a price
// (rel-1-0-10 GAP-1108).
func TestPriceLookupSharedCases(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "price_lookup_cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Tables []struct {
			Name    string               `yaml:"name"`
			Pricing config.PricingConfig `yaml:"pricing"`
			Cases   []struct {
				Provider string  `yaml:"provider"`
				Model    string  `yaml:"model"`
				Entry    *string `yaml:"entry"`
			} `yaml:"cases"`
		} `yaml:"tables"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, table := range doc.Tables {
		tb := NewPriceTable(table.Pricing)
		for _, c := range table.Cases {
			n++
			want := ""
			if c.Entry != nil {
				want = *c.Entry
			}
			_, got, ok := tb.Compute(c.Provider, c.Model, Usage{Input: 1, Output: 1, Has: HasInput | HasOutput})
			if !ok {
				got = ""
			}
			if got != want {
				t.Errorf("%s: %s/%q priced by %q, want %q", table.Name, c.Provider, c.Model, got, want)
			}
		}
	}
	if n < 20 {
		t.Fatalf("only %d cases loaded", n)
	}
}
