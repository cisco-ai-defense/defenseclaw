// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Cost basis values.
const (
	BasisComputed = "computed" // tokens x the price table in config.yaml
	BasisReported = "reported" // a per-call cost the provider or the agent reported
	BasisNone     = "none"     // no cost known: absent, never 0
)

// Cost is the cost of one call. USD is nil when the cost is unknown; it is
// never 0 for "unknown".
type Cost struct {
	USD          *float64
	Basis        string
	Partial      string // billing feature the flat table cannot price (see Usage.Partial)
	PriceEntry   string // matched table key, "" if none
	TableVersion string
	TableDigest  string
	ComputedUSD  *float64 // kept next to a reported cost for comparison
	ReportedUSD  *float64
}

type priceEntry struct {
	key      string // provider/model as written, lower-cased
	provider string // lower-cased; "*" matches any provider
	model    string // lower-cased, without the trailing *
	prefix   bool
	rates    rates
}

type rates struct {
	in, out    float64
	cr, cw, rs *float64
}

// PriceTable is the price list of observability.pricing, built from the
// loaded config. It is immutable; a config reload builds a new one.
type PriceTable struct {
	version  string
	digest   string
	entries  []priceEntry // exact entries first, then prefixes by descending length
	fallback *rates
	aiDef    *float64
}

// NewPriceTable builds the table from config. A nil or empty config yields a
// table that prices nothing.
func NewPriceTable(p config.PricingConfig) *PriceTable {
	t := &PriceTable{version: strings.TrimSpace(p.Version)}
	for _, m := range p.Models {
		r, ok := ratesOf(m.PriceRatesConfig)
		if !ok {
			continue
		}
		model := strings.ToLower(strings.TrimSpace(m.Model))
		e := priceEntry{
			key:      strings.ToLower(strings.TrimSpace(m.Provider)) + "/" + model,
			provider: strings.ToLower(strings.TrimSpace(m.Provider)),
			rates:    r,
		}
		if strings.HasSuffix(model, "*") {
			e.prefix, e.model = true, strings.TrimSuffix(model, "*")
		} else {
			e.model = model
		}
		t.entries = append(t.entries, e)
	}
	sort.SliceStable(t.entries, func(i, j int) bool {
		a, b := t.entries[i], t.entries[j]
		if a.prefix != b.prefix {
			return !a.prefix
		}
		if len(a.model) != len(b.model) {
			return len(a.model) > len(b.model)
		}
		return a.key < b.key
	})
	if p.UnknownModel == config.PricingUnknownFallback {
		if r, ok := ratesOf(p.Fallback); ok {
			t.fallback = &r
		}
	}
	t.aiDef = p.AIDefense.PerCallUSD
	t.digest = digestOf(p)
	return t
}

func ratesOf(c config.PriceRatesConfig) (rates, bool) {
	if c.InputPerMTok == nil || c.OutputPerMTok == nil {
		return rates{}, false
	}
	return rates{in: *c.InputPerMTok, out: *c.OutputPerMTok, cr: c.CacheReadPerMTok, cw: c.CacheWritePerMTok, rs: c.ReasoningPerMTok}, true
}

func digestOf(p config.PricingConfig) string {
	canon := struct {
		V string                    `json:"v"`
		M []config.PriceEntryConfig `json:"m"`
		U string                    `json:"u"`
		F config.PriceRatesConfig   `json:"f"`
		A *float64                  `json:"a"`
	}{p.Version, append([]config.PriceEntryConfig(nil), p.Models...), p.UnknownModel, p.Fallback, p.AIDefense.PerCallUSD}
	sort.SliceStable(canon.M, func(i, j int) bool {
		return strings.ToLower(canon.M[i].Provider+"/"+canon.M[i].Model) < strings.ToLower(canon.M[j].Provider+"/"+canon.M[j].Model)
	})
	b, _ := json.Marshal(canon)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Version returns the table version ("" for an empty table).
func (t *PriceTable) Version() string {
	if t == nil {
		return ""
	}
	return t.version
}

// Digest returns the sha256 of the canonical table, so a reused version with
// edited prices is still told apart.
func (t *PriceTable) Digest() string {
	if t == nil {
		return ""
	}
	return t.digest
}

// lookup finds the entry for provider/model: exact, then the longest prefix;
// an entry whose provider is * matches after a provider-specific one.
func (t *PriceTable) lookup(provider, model string) (rates, string, bool) {
	if t == nil {
		return rates{}, "", false
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	for _, cand := range modelKeys(model) {
		for _, wild := range []bool{false, true} {
			for _, e := range t.entries {
				if wild != (e.provider == "*") || (!wild && e.provider != provider) {
					continue
				}
				if (e.prefix && strings.HasPrefix(cand, e.model)) || (!e.prefix && cand == e.model) {
					return e.rates, e.key, true
				}
			}
		}
	}
	return rates{}, "", false
}

// ModelKey returns the metric label value for a model: the matched table
// entry key, else "other". It bounds cardinality, because the client sends
// the model string on passthrough.
func (t *PriceTable) ModelKey(provider, model string) string {
	if _, key, ok := t.lookup(provider, model); ok {
		return key
	}
	return "other"
}

// modelKeys lists the lower-cased forms of a model id to try: as sent, with
// Bedrock region prefixes and inference-profile ARNs reduced, and without the
// vendor prefix.
func modelKeys(model string) []string {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" {
		return nil
	}
	if i := strings.LastIndex(m, "/"); i >= 0 && strings.HasPrefix(m, "arn:") {
		m = m[i+1:]
	}
	keys := []string{m}
	for _, rp := range []string{"us-gov.", "global.", "apac.", "us.", "eu.", "jp.", "au.", "ca."} {
		if strings.HasPrefix(m, rp) {
			m = strings.TrimPrefix(m, rp)
			keys = append(keys, m)
			break
		}
	}
	for _, vp := range []string{"anthropic.", "openai.", "google.", "meta.", "mistral.", "amazon.", "cohere."} {
		if strings.HasPrefix(m, vp) {
			keys = append(keys, strings.TrimPrefix(m, vp))
			break
		}
	}
	return keys
}

// Compute prices usage u for provider/model. It returns ok=false (cost
// absent) when the usage lacks the input or output count, or no entry matches
// and unknown_model is omit. The formula:
//
//	uncached = input - cache_read - cache_creation
//	usd = (uncached*in + cache_read*(cr or in) + cache_creation*(cw or in)
//	       + (output-reasoning)*out + reasoning*(rs or out)) / 1e6
func (t *PriceTable) Compute(provider, model string, u Usage) (usd float64, entry string, ok bool) {
	if t == nil || u.Has&HasInput == 0 || u.Has&HasOutput == 0 {
		return 0, "", false
	}
	r, key, found := t.lookup(provider, model)
	if !found {
		if t.fallback == nil {
			return 0, "", false
		}
		r, key = *t.fallback, "fallback"
	}
	var cacheRead, cacheCreate, reasoning int64
	if u.Has&HasCacheRead != 0 {
		cacheRead = u.CacheRead
	}
	if u.Has&HasCacheCreation != 0 {
		cacheCreate = u.CacheCreation
	}
	if u.Has&HasReasoning != 0 {
		reasoning = u.Reasoning
	}
	uncached := u.Input - cacheRead - cacheCreate
	if uncached < 0 || u.Output < reasoning {
		return 0, "", false
	}
	pick := func(p *float64, def float64) float64 {
		if p == nil {
			return def
		}
		return *p
	}
	usd = (float64(uncached)*r.in +
		float64(cacheRead)*pick(r.cr, r.in) +
		float64(cacheCreate)*pick(r.cw, r.in) +
		float64(u.Output-reasoning)*r.out +
		float64(reasoning)*pick(r.rs, r.out)) / 1e6
	if math.IsNaN(usd) || math.IsInf(usd, 0) {
		return 0, "", false
	}
	return usd, key, true
}

// AIDefenseCost is the flat price of one Cisco AI Defense inspection call.
func (t *PriceTable) AIDefenseCost() (float64, bool) {
	if t == nil || t.aiDef == nil {
		return 0, false
	}
	return *t.aiDef, true
}

// Resolve combines a computed cost, a per-call reported cost and the
// keep_reported switch into the record Cost. Absent stays absent.
func Resolve(t *PriceTable, computed *float64, entry string, reported *float64, keepReported bool, partial string) Cost {
	c := Cost{Basis: BasisNone, Partial: partial, PriceEntry: entry, TableVersion: t.Version(), TableDigest: t.Digest()}
	if computed != nil {
		v := *computed
		c.ComputedUSD = &v
	}
	if reported != nil && !math.IsNaN(*reported) && *reported >= 0 && !math.IsInf(*reported, 0) {
		v := *reported
		c.ReportedUSD = &v
	}
	switch {
	case c.ReportedUSD != nil && keepReported:
		c.USD, c.Basis = c.ReportedUSD, BasisReported
	case c.ComputedUSD != nil:
		c.USD, c.Basis = c.ComputedUSD, BasisComputed
	}
	if c.Basis == BasisNone {
		c.PriceEntry = ""
	}
	return c
}
