// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func nativeRecord(reported *float64) Record {
	return Record{
		Facts: CallFacts{
			Connector: "claudecode", Listener: "native_otel", APIFamily: FamilyMessages,
			SelectedProvider: "anthropic", SelectedModel: "claude-haiku-4-5-20251001",
			Subject: "u1", IdentityVerified: true, SessionID: "s1",
		},
		Usage: Usage{
			Input: 1300, CacheRead: 200, CacheCreation: 100, Output: 50,
			Has: HasInput | HasCacheRead | HasCacheCreation | HasOutput,
		},
		Cost:    Cost{ReportedUSD: reported, USD: reported, Basis: "made up by the caller"},
		Status:  200,
		Total:   1500 * time.Millisecond,
		EndedAt: time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC),
	}
}

func TestRecordNativeIsGatedByTokenomicsAndConnector(t *testing.T) {
	off := false
	for name, tok := range map[string]config.TokenomicsConfig{
		"tokenomics off": {},
		"import off":     {Enabled: true, NativeOTelImport: config.TokenomicsNativeImportConfig{ClaudeCode: &off}},
		"agent role off": {Enabled: true, Roles: []string{"judge"}},
	} {
		sink := newCapture()
		e := NewEngine(sink)
		e.Apply(tok, testPricing())
		usd := 0.42
		if _, ok := e.RecordNative(nativeRecord(&usd)); ok || e.NativeImportEnabled("claudecode") {
			t.Fatalf("%s: native usage must not be recorded", name)
		}
		e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
		if len(sink.recs) != 0 {
			t.Fatalf("%s: sink got %d records", name, len(sink.recs))
		}
	}
	var nilEngine *Engine
	if _, ok := nilEngine.RecordNative(nativeRecord(nil)); ok || nilEngine.NativeImportEnabled("codex") {
		t.Fatal("nil engine recorded")
	}
	e := NewEngine()
	e.Apply(enabled(), config.PricingConfig{})
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	if e.NativeImportEnabled("opencode") || !e.NativeImportEnabled("codex") || !e.NativeImportEnabled("claudecode") {
		t.Fatal("native import defaults: on for claudecode and codex only")
	}
}

func TestRecordNativeReportedPerCallCostWinsAndIsRepriced(t *testing.T) {
	sink := newCapture()
	e := NewEngine(sink)
	e.Apply(enabled(), testPricing())
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	usd := 0.0123
	rec, ok := e.RecordNative(nativeRecord(&usd))
	if !ok {
		t.Fatal("not recorded")
	}
	if rec.Cost.Basis != BasisReported || rec.Cost.USD == nil || *rec.Cost.USD != usd {
		t.Fatalf("reported per-call cost must win: %+v", rec.Cost)
	}
	// 1000 uncached in, 200 cache read, 100 cache write, 50 out on 1/5/0.1/1.25 per Mtok.
	want := (1000*1 + 200*0.1 + 100*1.25 + 50*5) / 1e6
	if rec.Cost.ComputedUSD == nil || abs(*rec.Cost.ComputedUSD-want) > 1e-12 {
		t.Fatalf("computed cost %v want %v", rec.Cost.ComputedUSD, want)
	}
	if rec.Cost.PriceEntry == "" || rec.Cost.TableVersion != "t1" {
		t.Fatalf("price table facts missing: %+v", rec.Cost)
	}
	if rec.Usage.Source != SourceNativeOTel || rec.Facts.CallRole != RoleAgent || rec.Outcome != "completed" {
		t.Fatalf("defaults: %+v", rec)
	}
	if !rec.Facts.StartedAt.Equal(rec.EndedAt.Add(-rec.Total)) {
		t.Fatalf("start %v end %v total %v", rec.Facts.StartedAt, rec.EndedAt, rec.Total)
	}
	if len(rec.Labels) == 0 {
		t.Fatal("labels missing")
	}
	got := sink.wait(t, 1)
	if got[0].Facts.SessionID != "s1" || got[0].Cost.Basis != BasisReported {
		t.Fatalf("sink record %+v", got[0])
	}
}

type nativeChargeSink struct {
	keys [][]string
	usd  []float64
}

func (s *nativeChargeSink) Charge(keys []string, usd float64, _ time.Time) {
	s.keys, s.usd = append(s.keys, keys), append(s.usd, usd)
}

func TestRecordNativeChargesBudgetsOnlyWithChargeKeys(t *testing.T) {
	e := NewEngine()
	charges := &nativeChargeSink{}
	e.SetSpendSink(charges)
	e.Apply(enabled(), testPricing())
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	usd := 0.0123
	if _, ok := e.RecordNative(nativeRecord(&usd)); !ok || len(charges.usd) != 0 {
		t.Fatalf("a native record without budget keys charged %v", charges.usd)
	}
	rec := nativeRecord(&usd)
	rec.Facts.ChargeKeys = []string{"user:u1"}
	out, ok := e.RecordNative(rec)
	want, known := ChargedUSD(out.Cost)
	if !ok || !known || len(charges.usd) != 1 || charges.usd[0] != want || charges.keys[0][0] != "user:u1" {
		t.Fatalf("charges=%v keys=%v want %v", charges.usd, charges.keys, want)
	}
}

func TestRecordNativeKeepsAbsentAbsent(t *testing.T) {
	sink := newCapture()
	e := NewEngine(sink)
	e.Apply(enabled(), config.PricingConfig{})
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	rec := nativeRecord(nil)
	rec.Facts.SelectedModel = "gpt-5.4"
	rec.Usage = Usage{Output: 0, Has: HasOutput}
	out, ok := e.RecordNative(rec)
	if !ok {
		t.Fatal("not recorded")
	}
	if out.Usage.Has != HasOutput || out.Usage.Output != 0 {
		t.Fatalf("a real zero must stay present and nothing else appear: %+v", out.Usage)
	}
	if out.Cost.USD != nil || out.Cost.ComputedUSD != nil || out.Cost.ReportedUSD != nil || out.Cost.Basis != BasisNone {
		t.Fatalf("no price and no reported cost must leave cost absent: %+v", out.Cost)
	}
	none := nativeRecord(nil)
	none.Usage = Usage{}
	out, ok = e.RecordNative(none)
	if !ok || out.Usage.Has != 0 || out.Usage.Source != "" {
		t.Fatalf("empty usage must stay empty: %+v", out.Usage)
	}
	sink.wait(t, 2)
}

func TestRecordNativeSealsInconsistentCounts(t *testing.T) {
	e := NewEngine()
	e.Apply(enabled(), config.PricingConfig{})
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	rec := nativeRecord(nil)
	rec.Usage = Usage{Output: 10, Reasoning: 20, Has: HasOutput | HasReasoning}
	out, _ := e.RecordNative(rec)
	if out.Usage.Has&HasReasoning != 0 || out.Usage.Anomaly != "inconsistent_reasoning" {
		t.Fatalf("reasoning above output must be dropped: %+v", out.Usage)
	}
}

func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}
