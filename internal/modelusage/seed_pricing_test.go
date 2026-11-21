package modelusage

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// loadSeedPricing reads the reviewed seed the CLI writes into config.yaml (JSON is YAML).
func loadSeedPricing(t *testing.T) config.PricingConfig {
	t.Helper()
	raw, err := os.ReadFile("../../bundles/pricing/default-pricing.json")
	if err != nil {
		t.Fatal(err)
	}
	var p config.PricingConfig
	if err := yaml.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSeedPatternsMatchTheirModels pins which model ids each seeded row
// prices (GAP-0041). The gpt-5.2 row used to be written gpt-5-2*, which
// matched dated gpt-5 snapshots such as gpt-5-2025-08-07 and never gpt-5.2.
func TestSeedPatternsMatchTheirModels(t *testing.T) {
	tb := NewPriceTable(loadSeedPricing(t))
	cases := []struct {
		provider, model, want string
	}{
		{"openai", "gpt-5", "openai/gpt-5"},
		{"openai", "gpt-5.2", "openai/gpt-5.2*"},
		{"openai", "gpt-5.2-mini", "openai/gpt-5.2*"},
		{"openai", "gpt-5.2-2025-12-11", "openai/gpt-5.2*"},
		{"openai", "gpt-5-2025-08-07", "other"},
		{"openai", "gpt-5-2-mini", "other"},
		{"openai", "gpt-5.1", "other"},
		{"anthropic", "claude-haiku-4-5-20251001", "anthropic/claude-haiku-4-5*"},
		{"anthropic", "claude-sonnet-4-5-20250929", "anthropic/claude-sonnet-4-5*"},
		{"anthropic", "claude-opus-4-5-20251101", "anthropic/claude-opus-4-5*"},
		{"bedrock", "us.anthropic.claude-haiku-4-5-20251001-v1:0", "bedrock/claude-haiku-4-5*"},
		{"bedrock", "global.anthropic.claude-sonnet-4-5-20250929-v1:0", "bedrock/claude-sonnet-4-5*"},
		{"bedrock", "anthropic.claude-opus-4-5-20251101-v1:0", "bedrock/claude-opus-4-5*"},
		{"anthropic", "claude-sonnet-4-6", "other"},
	}
	for _, c := range cases {
		if got := tb.ModelKey(c.provider, c.model); got != c.want {
			t.Errorf("%s/%s -> %q, want %q", c.provider, c.model, got, c.want)
		}
	}
	// The pattern fix changes no price: gpt-5.2 keeps the seeded rate.
	u := Usage{Input: 1_000_000, Output: 1_000_000, Has: HasInput | HasOutput}
	usd, _, ok := tb.Compute("openai", "gpt-5.2", u)
	if !ok || !near(usd, 1.25+10.0) {
		t.Fatalf("gpt-5.2 usd=%v ok=%v, want the seeded 1.25/10.00", usd, ok)
	}
}
