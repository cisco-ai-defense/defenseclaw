package modelusage

import (
	"math"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func f(v float64) *float64 { return &v }

func testPricing() config.PricingConfig {
	rate := func(in, out float64) config.PriceRatesConfig {
		return config.PriceRatesConfig{InputPerMTok: f(in), OutputPerMTok: f(out)}
	}
	haiku := rate(1, 5)
	haiku.CacheReadPerMTok, haiku.CacheWritePerMTok = f(0.1), f(1.25)
	gpt := rate(2, 10)
	gpt.ReasoningPerMTok = f(12)
	return config.PricingConfig{
		Version: "t1",
		Models: []config.PriceEntryConfig{
			{Provider: "anthropic", Model: "claude-haiku-4-5*", PriceRatesConfig: haiku},
			{Provider: "anthropic", Model: "claude-haiku-4-5-special", PriceRatesConfig: rate(9, 9)},
			{Provider: "openai", Model: "gpt-5*", PriceRatesConfig: gpt},
			{Provider: "*", Model: "gemini-2.5-pro", PriceRatesConfig: rate(1.25, 10)},
		},
		AIDefense: config.PricingAIDefenseConfig{PerCallUSD: f(0.002)},
	}
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-12 }

func TestComputeFormula(t *testing.T) {
	tb := NewPriceTable(testPricing())
	// 2112 input of which 2000 cache read and 100 cache creation: uncached 12.
	u := ParseBody(FamilyMessages, fixture(t, "anthropic_messages.json"))
	usd, key, ok := tb.Compute("anthropic", "claude-haiku-4-5-20251001", u)
	want := (12*1.0 + 2000*0.1 + 100*1.25 + 34*5.0) / 1e6
	if !ok || !near(usd, want) || key != "anthropic/claude-haiku-4-5*" {
		t.Fatalf("usd=%v key=%q ok=%v want %v", usd, key, ok, want)
	}
	// OpenAI: reasoning (30 of 80 output) is priced at reasoning_per_mtok, the rest at output;
	// cached 64 of 120 input has no cache rate so it is priced at the input rate.
	g := ParseBody(FamilyChat, fixture(t, "openai_chat.json"))
	usd, _, ok = tb.Compute("openai", "gpt-5-2025-08-07", g)
	want = (56*2.0 + 64*2.0 + 50*10.0 + 30*12.0) / 1e6
	if !ok || !near(usd, want) {
		t.Fatalf("usd=%v want %v", usd, want)
	}
}

func TestLongestPrefixAndExactWin(t *testing.T) {
	tb := NewPriceTable(testPricing())
	u := Usage{Input: 1_000_000, Output: 1_000_000, Has: HasInput | HasOutput}
	usd, key, _ := tb.Compute("anthropic", "claude-haiku-4-5-special", u)
	if key != "anthropic/claude-haiku-4-5-special" || !near(usd, 18) {
		t.Fatalf("exact entry must beat the prefix: %v %q", usd, key)
	}
	// provider * matches any provider
	if _, key, ok := tb.Compute("vertex", "gemini-2.5-pro", u); !ok || key != "*/gemini-2.5-pro" {
		t.Fatalf("wildcard provider: %q %v", key, ok)
	}
}

func TestBedrockModelNormalisation(t *testing.T) {
	p := testPricing()
	p.Models = append(p.Models, config.PriceEntryConfig{Provider: "bedrock", Model: "claude-sonnet-4-5*",
		PriceRatesConfig: config.PriceRatesConfig{InputPerMTok: f(3), OutputPerMTok: f(15)}})
	tb := NewPriceTable(p)
	for _, m := range []string{
		"us.anthropic.claude-sonnet-4-5-20250929-v1:0",
		"global.anthropic.claude-sonnet-4-5-20250929-v1:0",
		"anthropic.claude-sonnet-4-5-20250929-v1:0",
		"arn:aws:bedrock:us-east-1:111122223333:inference-profile/us.anthropic.claude-sonnet-4-5-20250929-v1:0",
	} {
		if got := tb.ModelKey("bedrock", m); got != "bedrock/claude-sonnet-4-5*" {
			t.Errorf("%s -> %q", m, got)
		}
	}
	if got := tb.ModelKey("bedrock", "some-client-chosen-name"); got != "other" {
		t.Fatalf("unknown model label must be other, got %q", got)
	}
}

func TestAbsentStaysAbsent(t *testing.T) {
	tb := NewPriceTable(testPricing())
	if _, _, ok := tb.Compute("anthropic", "mystery", Usage{Input: 5, Output: 5, Has: HasInput | HasOutput}); ok {
		t.Fatal("unknown model must have no cost")
	}
	if _, _, ok := tb.Compute("openai", "gpt-5", Usage{Input: 5, Has: HasInput}); ok {
		t.Fatal("incomplete usage must have no cost")
	}
	// a real zero-token call costs a real 0
	usd, _, ok := tb.Compute("openai", "gpt-5", Usage{Has: HasInput | HasOutput})
	if !ok || usd != 0 {
		t.Fatalf("zero tokens priced: %v %v", usd, ok)
	}
	var nilTable *PriceTable
	if _, _, ok := nilTable.Compute("a", "b", Usage{Has: HasInput | HasOutput}); ok {
		t.Fatal("nil table")
	}
	if _, _, ok := NewPriceTable(config.PricingConfig{}).Compute("a", "b", Usage{Has: HasInput | HasOutput}); ok {
		t.Fatal("empty table")
	}
}

func TestUnknownModelFallback(t *testing.T) {
	p := testPricing()
	p.UnknownModel = config.PricingUnknownFallback
	p.Fallback = config.PriceRatesConfig{InputPerMTok: f(3), OutputPerMTok: f(15)}
	tb := NewPriceTable(p)
	usd, key, ok := tb.Compute("x", "unseen", Usage{Input: 1_000_000, Output: 1_000_000, Has: HasInput | HasOutput})
	if !ok || key != "fallback" || !near(usd, 18) {
		t.Fatalf("%v %q %v", usd, key, ok)
	}
}

func TestInconsistentUsageHasNoCost(t *testing.T) {
	tb := NewPriceTable(testPricing())
	bad := Usage{Input: 10, Output: 5, CacheRead: 50, Has: HasInput | HasOutput | HasCacheRead}
	if _, _, ok := tb.Compute("openai", "gpt-5", bad); ok {
		t.Fatal("negative uncached input must give no cost")
	}
}

func TestResolveBasisRules(t *testing.T) {
	tb := NewPriceTable(testPricing())
	c := Resolve(tb, f(0.5), "e", nil, true, "")
	if c.Basis != BasisComputed || *c.USD != 0.5 || c.TableVersion != "t1" || c.TableDigest == "" {
		t.Fatalf("%+v", c)
	}
	c = Resolve(tb, f(0.5), "e", f(0.7), true, "")
	if c.Basis != BasisReported || *c.USD != 0.7 || *c.ComputedUSD != 0.5 || *c.ReportedUSD != 0.7 {
		t.Fatalf("reported wins and computed is kept: %+v", c)
	}
	c = Resolve(tb, f(0.5), "e", f(0.7), false, "")
	if c.Basis != BasisComputed || *c.USD != 0.5 {
		t.Fatalf("keep_reported=false: %+v", c)
	}
	c = Resolve(tb, nil, "", nil, true, "service_tier:flex")
	if c.USD != nil || c.Basis != BasisNone || c.PriceEntry != "" || c.Partial != "service_tier:flex" {
		t.Fatalf("no cost must be absent, not 0: %+v", c)
	}
	c = Resolve(tb, nil, "", f(-1), true, "")
	if c.USD != nil || c.Basis != BasisNone {
		t.Fatalf("a negative reported cost is ignored: %+v", c)
	}
	if c = Resolve(tb, nil, "", f(2), false, ""); c.USD != nil {
		t.Fatalf("%+v", c)
	}
}

func TestDigestChangesWithPricesNotOrder(t *testing.T) {
	a := testPricing()
	b := testPricing()
	b.Models[0], b.Models[2] = b.Models[2], b.Models[0]
	if NewPriceTable(a).Digest() != NewPriceTable(b).Digest() {
		t.Fatal("entry order must not change the digest")
	}
	c := testPricing()
	c.Models[0].InputPerMTok = f(1.01)
	if NewPriceTable(a).Digest() == NewPriceTable(c).Digest() {
		t.Fatal("a price edit under the same version must change the digest")
	}
}

func TestAIDefenseCost(t *testing.T) {
	if v, ok := NewPriceTable(testPricing()).AIDefenseCost(); !ok || v != 0.002 {
		t.Fatal(v, ok)
	}
	if _, ok := NewPriceTable(config.PricingConfig{}).AIDefenseCost(); ok {
		t.Fatal("no per-call price configured")
	}
}
