// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// observability.tokenomics and observability.pricing: what every model call
// cost. Both blocks are off or absent by default; an absent block is exactly
// the pre-1.0.10 behaviour. Prices are never compiled into a binary: the
// gateway prices only from the table in config.yaml (managed hosts: the admin
// config.yaml in the signed bundle).

const (
	// TokenomicsMaxPriceModels bounds observability.pricing.models.
	TokenomicsMaxPriceModels = 2000
	// TokenomicsMaxPerMTok bounds one price (USD per million tokens).
	TokenomicsMaxPerMTok = 100000.0
	// TokenomicsMinRetentionDays and TokenomicsMaxRetentionDays bound
	// observability.tokenomics.local_store.retention_days.
	TokenomicsMinRetentionDays = 1
	TokenomicsMaxRetentionDays = 3650
	// TokenomicsDefaultRetentionDays is the local usage store window.
	TokenomicsDefaultRetentionDays = 30
	// PricingUnknownOmit leaves the cost absent for a model with no price entry.
	PricingUnknownOmit = "omit"
	// PricingUnknownFallback prices it with observability.pricing.fallback.
	PricingUnknownFallback = "fallback"
)

// TokenomicsRoles are the call roles a usage record can carry.
var TokenomicsRoles = []string{"agent", "judge", "decision_model", "ai_defense", "router_classifier"}

// TokenomicsMetricLabels is the closed set of labels defenseclaw.model.cost
// and defenseclaw.model.tokens may carry. Identity labels are refused.
var TokenomicsMetricLabels = []string{"connector", "provider", "model", "route_decision", "call_role", "profile"}

var tokenomicsIdentityLabels = map[string]bool{
	"user": true, "user_id": true, "user_name": true, "user_email": true, "email": true,
	"group": true, "groups": true, "principal": true, "identity": true, "subject": true,
	"session": true, "session_id": true, "agent_id": true, "device": true, "host": true,
	"account": true, "tenant": true, "request_id": true,
}

// TokenomicsConfig is observability.tokenomics.
type TokenomicsConfig struct {
	Enabled                 bool                         `mapstructure:"enabled" yaml:"enabled,omitempty"`
	RecordRoutingProvenance *bool                        `mapstructure:"record_routing_provenance" yaml:"record_routing_provenance,omitempty"`
	Roles                   []string                     `mapstructure:"roles" yaml:"roles,omitempty"`
	NativeOTelImport        TokenomicsNativeImportConfig `mapstructure:"native_otel_import" yaml:"native_otel_import,omitempty"`
	Cost                    TokenomicsCostConfig         `mapstructure:"cost" yaml:"cost,omitempty"`
	LocalStore              TokenomicsLocalStoreConfig   `mapstructure:"local_store" yaml:"local_store,omitempty"`
	Metrics                 TokenomicsMetricsConfig      `mapstructure:"metrics" yaml:"metrics,omitempty"`
}

// TokenomicsNativeImportConfig switches the agent OTLP usage import per connector.
type TokenomicsNativeImportConfig struct {
	ClaudeCode *bool `mapstructure:"claudecode" yaml:"claudecode,omitempty"`
	Codex      *bool `mapstructure:"codex" yaml:"codex,omitempty"`
}

// TokenomicsCostConfig controls cost computation.
type TokenomicsCostConfig struct {
	Compute      *bool  `mapstructure:"compute" yaml:"compute,omitempty"`
	Currency     string `mapstructure:"currency" yaml:"currency,omitempty"`
	KeepReported *bool  `mapstructure:"keep_reported" yaml:"keep_reported,omitempty"`
}

// TokenomicsLocalStoreConfig controls the local hourly usage aggregate.
type TokenomicsLocalStoreConfig struct {
	Enabled       bool   `mapstructure:"enabled" yaml:"enabled,omitempty"`
	RetentionDays int    `mapstructure:"retention_days" yaml:"retention_days,omitempty"`
	Granularity   string `mapstructure:"granularity" yaml:"granularity,omitempty"`
}

// TokenomicsMetricsConfig selects the metric labels.
type TokenomicsMetricsConfig struct {
	Labels []string `mapstructure:"labels" yaml:"labels,omitempty"`
}

// PricingConfig is observability.pricing.
type PricingConfig struct {
	Version      string                 `mapstructure:"version" yaml:"version,omitempty"`
	Models       []PriceEntryConfig     `mapstructure:"models" yaml:"models,omitempty"`
	AIDefense    PricingAIDefenseConfig `mapstructure:"ai_defense" yaml:"ai_defense,omitempty"`
	UnknownModel string                 `mapstructure:"unknown_model" yaml:"unknown_model,omitempty"`
	Fallback     PriceRatesConfig       `mapstructure:"fallback" yaml:"fallback,omitempty"`
}

// PriceRatesConfig is one set of per-million-token USD rates. A nil rate is
// absent. Cache and reasoning rates fall back to the input and output rates
// in the cost formula (internal/modelusage).
type PriceRatesConfig struct {
	InputPerMTok      *float64 `mapstructure:"input_per_mtok" yaml:"input_per_mtok,omitempty"`
	OutputPerMTok     *float64 `mapstructure:"output_per_mtok" yaml:"output_per_mtok,omitempty"`
	CacheReadPerMTok  *float64 `mapstructure:"cache_read_per_mtok" yaml:"cache_read_per_mtok,omitempty"`
	CacheWritePerMTok *float64 `mapstructure:"cache_write_per_mtok" yaml:"cache_write_per_mtok,omitempty"`
	ReasoningPerMTok  *float64 `mapstructure:"reasoning_per_mtok" yaml:"reasoning_per_mtok,omitempty"`
}

// PriceEntryConfig prices one provider/model. Model may end with * (longest
// prefix wins).
type PriceEntryConfig struct {
	Provider         string `mapstructure:"provider" yaml:"provider,omitempty"`
	Model            string `mapstructure:"model" yaml:"model,omitempty"`
	PriceRatesConfig `mapstructure:",squash" yaml:",inline"`
}

// PricingAIDefenseConfig prices a Cisco AI Defense inspection call.
type PricingAIDefenseConfig struct {
	PerCallUSD *float64 `mapstructure:"per_call_usd" yaml:"per_call_usd,omitempty"`
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// RecordsRoutingProvenance reports whether routing facts go on usage records.
func (t TokenomicsConfig) RecordsRoutingProvenance() bool {
	return boolOr(t.RecordRoutingProvenance, true)
}

// RoleEnabled reports whether calls of role are recorded. An empty roles list
// means every role.
func (t TokenomicsConfig) RoleEnabled(role string) bool {
	if len(t.Roles) == 0 {
		return true
	}
	for _, r := range t.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// NativeImportEnabled reports the per-connector native OTLP usage import switch.
func (t TokenomicsConfig) NativeImportEnabled(connector string) bool {
	switch connector {
	case "claudecode":
		return boolOr(t.NativeOTelImport.ClaudeCode, true)
	case "codex":
		return boolOr(t.NativeOTelImport.Codex, true)
	}
	return false
}

// ComputesCost reports whether cost is computed from the price table.
func (t TokenomicsConfig) ComputesCost() bool { return boolOr(t.Cost.Compute, true) }

// KeepsReportedCost reports whether a per-call provider/agent reported cost is kept.
func (t TokenomicsConfig) KeepsReportedCost() bool { return boolOr(t.Cost.KeepReported, true) }

// UsageRetentionDays is the effective local usage store window.
func (t TokenomicsConfig) UsageRetentionDays() int {
	if t.LocalStore.RetentionDays == 0 {
		return TokenomicsDefaultRetentionDays
	}
	return t.LocalStore.RetentionDays
}

// MetricLabels is the effective label set, in canonical order.
func (t TokenomicsConfig) MetricLabels() []string {
	if len(t.Metrics.Labels) == 0 {
		return append([]string(nil), TokenomicsMetricLabels...)
	}
	want := make(map[string]bool, len(t.Metrics.Labels))
	for _, l := range t.Metrics.Labels {
		want[l] = true
	}
	out := make([]string, 0, len(want))
	for _, l := range TokenomicsMetricLabels {
		if want[l] {
			out = append(out, l)
		}
	}
	return out
}

// Validate checks observability.tokenomics. Every refusal names the key.
func (t TokenomicsConfig) Validate() error {
	seenRole := map[string]bool{}
	for _, r := range t.Roles {
		if !containsString(TokenomicsRoles, r) {
			return fmt.Errorf("observability.tokenomics.roles: %q is not a call role (use %s)", r, strings.Join(TokenomicsRoles, ", "))
		}
		if seenRole[r] {
			return fmt.Errorf("observability.tokenomics.roles: %q is listed twice", r)
		}
		seenRole[r] = true
	}
	if c := t.Cost.Currency; c != "" && c != "USD" {
		return fmt.Errorf("observability.tokenomics.cost.currency: %q is not supported; prices and cost are USD only", c)
	}
	if g := t.LocalStore.Granularity; g != "" && g != "hour" {
		return fmt.Errorf("observability.tokenomics.local_store.granularity: %q is not supported; the aggregate is hourly", g)
	}
	if d := t.LocalStore.RetentionDays; d != 0 && (d < TokenomicsMinRetentionDays || d > TokenomicsMaxRetentionDays) {
		return fmt.Errorf("observability.tokenomics.local_store.retention_days: %d is outside %d..%d", d, TokenomicsMinRetentionDays, TokenomicsMaxRetentionDays)
	}
	seenLabel := map[string]bool{}
	for _, l := range t.Metrics.Labels {
		key := strings.ToLower(strings.TrimSpace(l))
		if tokenomicsIdentityLabels[key] {
			return fmt.Errorf("observability.tokenomics.metrics.labels: %q identifies a person or device and is never a metric label (use the usage API for per-user rollups)", l)
		}
		if !containsString(TokenomicsMetricLabels, l) {
			return fmt.Errorf("observability.tokenomics.metrics.labels: %q is not allowed (use %s)", l, strings.Join(TokenomicsMetricLabels, ", "))
		}
		if seenLabel[l] {
			return fmt.Errorf("observability.tokenomics.metrics.labels: %q is listed twice", l)
		}
		seenLabel[l] = true
	}
	return nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func validRate(path string, p *float64, required bool) error {
	if p == nil {
		if required {
			return fmt.Errorf("%s: is required", path)
		}
		return nil
	}
	v := *p
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > TokenomicsMaxPerMTok {
		return fmt.Errorf("%s: %v is outside 0..%v USD per million tokens", path, v, TokenomicsMaxPerMTok)
	}
	return nil
}

func (r PriceRatesConfig) validate(path string, requireBase bool) error {
	for _, f := range []struct {
		name string
		v    *float64
		req  bool
	}{
		{"input_per_mtok", r.InputPerMTok, requireBase},
		{"output_per_mtok", r.OutputPerMTok, requireBase},
		{"cache_read_per_mtok", r.CacheReadPerMTok, false},
		{"cache_write_per_mtok", r.CacheWritePerMTok, false},
		{"reasoning_per_mtok", r.ReasoningPerMTok, false},
	} {
		if err := validRate(path+"."+f.name, f.v, f.req); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks observability.pricing. Every refusal names the key.
func (p PricingConfig) Validate() error {
	if len(p.Models) > TokenomicsMaxPriceModels {
		return fmt.Errorf("observability.pricing.models: %d entries, maximum is %d", len(p.Models), TokenomicsMaxPriceModels)
	}
	if len(p.Models) > 0 && strings.TrimSpace(p.Version) == "" {
		return fmt.Errorf("observability.pricing.version: is required when models are listed (records carry the table version)")
	}
	seen := make(map[string]bool, len(p.Models))
	for i, m := range p.Models {
		path := fmt.Sprintf("observability.pricing.models[%d]", i)
		if strings.TrimSpace(m.Provider) == "" || strings.TrimSpace(m.Model) == "" {
			return fmt.Errorf("%s: provider and model are required", path)
		}
		if strings.Contains(strings.TrimSuffix(strings.TrimSpace(m.Model), "*"), "*") {
			return fmt.Errorf("%s.model: %q may use * only as the last character", path, m.Model)
		}
		key := strings.ToLower(strings.TrimSpace(m.Provider)) + "/" + strings.ToLower(strings.TrimSpace(m.Model))
		if seen[key] {
			return fmt.Errorf("%s: %s/%s is listed twice", path, m.Provider, m.Model)
		}
		seen[key] = true
		if err := m.validate(path, true); err != nil {
			return err
		}
	}
	switch p.UnknownModel {
	case "", PricingUnknownOmit:
	case PricingUnknownFallback:
		if err := p.Fallback.validate("observability.pricing.fallback", true); err != nil {
			return fmt.Errorf("%w (unknown_model: fallback needs input_per_mtok and output_per_mtok)", err)
		}
	default:
		return fmt.Errorf("observability.pricing.unknown_model: %q is not allowed (use %s or %s)", p.UnknownModel, PricingUnknownOmit, PricingUnknownFallback)
	}
	if p.UnknownModel != PricingUnknownFallback {
		if err := p.Fallback.validate("observability.pricing.fallback", false); err != nil {
			return err
		}
	}
	return validRate("observability.pricing.ai_defense.per_call_usd", p.AIDefense.PerCallUSD, false)
}

// PricingModelKeys lists provider/model keys in a stable order (for messages
// and digests).
func (p PricingConfig) PricingModelKeys() []string {
	out := make([]string, 0, len(p.Models))
	for _, m := range p.Models {
		out = append(out, strings.ToLower(m.Provider)+"/"+strings.ToLower(m.Model))
	}
	sort.Strings(out)
	return out
}
