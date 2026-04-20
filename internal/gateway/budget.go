// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

// BudgetTracker maintains per-subject sliding-window usage counters in
// memory. It supports three windows (minute, hour, day) for tokens and
// requests, and two windows (hour, day) for cost. The bucketed layout
// avoids per-event allocations: each window is split into fixed buckets
// indexed by time, and stale buckets are trimmed lazily on access.
type BudgetTracker struct {
	mu       sync.Mutex
	subjects map[string]*subjectUsage
	now      func() time.Time
}

// NewBudgetTracker creates an empty tracker. The clock is injected so
// tests can exercise window rollover without sleeping.
func NewBudgetTracker() *BudgetTracker {
	return &BudgetTracker{
		subjects: make(map[string]*subjectUsage),
		now:      time.Now,
	}
}

// subjectUsage holds sliding-window buckets for one subject. The bucket
// counts are stored as parallel slices to keep the hot path allocation-free.
type subjectUsage struct {
	// Minute-granularity bucket for tokens_last_minute and
	// requests_last_minute. Each bucket represents 1 second; 60 buckets.
	minuteTokens   [60]int64
	minuteRequests [60]int64
	minuteCost     [60]float64
	lastMinuteTS   int64 // unix seconds of most recent bucket write

	// Hour-granularity buckets; each bucket represents 60 seconds; 60 buckets.
	hourTokens   [60]int64
	hourRequests [60]int64
	hourCost     [60]float64
	lastHourTS   int64 // unix seconds of most recent bucket write

	// Day-granularity buckets; each bucket represents 1440 seconds (24 min); 60 buckets.
	dayTokens   [60]int64
	dayRequests [60]int64
	dayCost     [60]float64
	lastDayTS   int64 // unix seconds of most recent bucket write
}

// Snapshot returns the current sliding-window usage for a subject, used
// by the enforcer to build the OPA input.
func (t *BudgetTracker) Snapshot(subject string) policy.BudgetUsage {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.subjects[subject]
	if !ok {
		return policy.BudgetUsage{}
	}
	now := t.now()
	t.trim(s, now)
	return policy.BudgetUsage{
		TokensLastMinute:   sumInt(s.minuteTokens[:]),
		TokensLastHour:     sumInt(s.hourTokens[:]),
		TokensLastDay:      sumInt(s.dayTokens[:]),
		RequestsLastMinute: sumInt(s.minuteRequests[:]),
		RequestsLastHour:   sumInt(s.hourRequests[:]),
		RequestsLastDay:    sumInt(s.dayRequests[:]),
		CostLastHour:       sumFloat(s.hourCost[:]),
		CostLastDay:        sumFloat(s.dayCost[:]),
	}
}

// Record adds an observation (one request plus token/cost usage) to the
// counters for the subject. Callers should invoke this once per completed
// LLM request using the upstream-reported token usage.
func (t *BudgetTracker) Record(subject string, tokens int64, cost float64) {
	if subject == "" {
		subject = "default"
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.subjects[subject]
	if !ok {
		s = &subjectUsage{}
		t.subjects[subject] = s
	}
	now := t.now()
	t.trim(s, now)

	// Minute bucket: one slot per second.
	minuteIdx := int(now.Unix() % 60)
	s.minuteTokens[minuteIdx] += tokens
	s.minuteRequests[minuteIdx]++
	s.minuteCost[minuteIdx] += cost
	s.lastMinuteTS = now.Unix()

	// Hour bucket: one slot per 60 seconds.
	hourIdx := int((now.Unix() / 60) % 60)
	s.hourTokens[hourIdx] += tokens
	s.hourRequests[hourIdx]++
	s.hourCost[hourIdx] += cost
	s.lastHourTS = now.Unix()

	// Day bucket: one slot per 1440 seconds (24 minutes).
	dayIdx := int((now.Unix() / 1440) % 60)
	s.dayTokens[dayIdx] += tokens
	s.dayRequests[dayIdx]++
	s.dayCost[dayIdx] += cost
	s.lastDayTS = now.Unix()
}

// trim zeros any buckets that fell out of the sliding window since the
// last write. Callers must hold t.mu.
func (t *BudgetTracker) trim(s *subjectUsage, now time.Time) {
	nowSec := now.Unix()

	// Minute window: each bucket is 1 s. If >=60 s has elapsed since the
	// last write, everything is stale.
	if nowSec-s.lastMinuteTS >= 60 || s.lastMinuteTS == 0 {
		for i := range s.minuteTokens {
			s.minuteTokens[i] = 0
			s.minuteRequests[i] = 0
			s.minuteCost[i] = 0
		}
	} else if nowSec > s.lastMinuteTS {
		for i := s.lastMinuteTS + 1; i <= nowSec; i++ {
			idx := int(i % 60)
			s.minuteTokens[idx] = 0
			s.minuteRequests[idx] = 0
			s.minuteCost[idx] = 0
		}
	}

	// Hour window: each bucket is 60 s.
	if (nowSec/60)-(s.lastHourTS/60) >= 60 || s.lastHourTS == 0 {
		for i := range s.hourTokens {
			s.hourTokens[i] = 0
			s.hourRequests[i] = 0
			s.hourCost[i] = 0
		}
	} else if nowSec/60 > s.lastHourTS/60 {
		for i := (s.lastHourTS / 60) + 1; i <= nowSec/60; i++ {
			idx := int(i % 60)
			s.hourTokens[idx] = 0
			s.hourRequests[idx] = 0
			s.hourCost[idx] = 0
		}
	}

	// Day window: each bucket is 1440 s.
	if (nowSec/1440)-(s.lastDayTS/1440) >= 60 || s.lastDayTS == 0 {
		for i := range s.dayTokens {
			s.dayTokens[i] = 0
			s.dayRequests[i] = 0
			s.dayCost[i] = 0
		}
	} else if nowSec/1440 > s.lastDayTS/1440 {
		for i := (s.lastDayTS / 1440) + 1; i <= nowSec/1440; i++ {
			idx := int(i % 60)
			s.dayTokens[idx] = 0
			s.dayRequests[idx] = 0
			s.dayCost[idx] = 0
		}
	}
}

func sumInt(xs []int64) int64 {
	var n int64
	for _, v := range xs {
		n += v
	}
	return n
}

func sumFloat(xs []float64) float64 {
	var n float64
	for _, v := range xs {
		n += v
	}
	return n
}

// BudgetDecision captures the outcome of a pre-call budget check. Allowed
// true means the caller should proceed; false means the proxy should
// refuse (in enforce mode) or log (in monitor mode).
type BudgetDecision struct {
	Allowed   bool
	Monitor   bool // decision was "deny" but mode == monitor, so traffic was allowed
	Subject   string
	Model     string
	Reason    string
	Rule      string
	Limit     float64
	Remaining float64
}

// BudgetEnforcer combines the OPA budget policy with the in-memory tracker
// to make pre-call decisions and record post-call usage.
type BudgetEnforcer struct {
	cfg     config.BudgetConfig
	opa     *policy.Engine
	tracker *BudgetTracker
	pricing *PricingTable
}

// NewBudgetEnforcer constructs an enforcer. A nil opa or disabled cfg
// yields a permissive no-op enforcer (safe default: do not block).
func NewBudgetEnforcer(cfg config.BudgetConfig, opa *policy.Engine) *BudgetEnforcer {
	return &BudgetEnforcer{
		cfg:     cfg,
		opa:     opa,
		tracker: NewBudgetTracker(),
		pricing: NewPricingTable(opa),
	}
}

// Enabled reports whether enforcement is active.
func (e *BudgetEnforcer) Enabled() bool {
	return e != nil && e.opa != nil && e.cfg.Enabled
}

// Check consults the OPA policy for a pre-call decision. It always returns
// a non-nil BudgetDecision — when the enforcer is disabled it returns
// {Allowed: true}. Estimated tokens is a coarse projection (prompt tokens +
// max completion tokens); estimated cost is derived from the pricing table
// in data.json.
func (e *BudgetEnforcer) Check(ctx context.Context, r *http.Request, model string, estTokens int64) *BudgetDecision {
	subject := e.SubjectFor(r)
	if !e.Enabled() {
		return &BudgetDecision{Allowed: true, Subject: subject, Model: model}
	}

	usage := e.tracker.Snapshot(subject)
	estCost := e.pricing.EstimateCost(model, estTokens, 0)

	out, err := e.opa.EvaluateBudget(ctx, policy.BudgetInput{
		Subject:         subject,
		Model:           model,
		EstimatedTokens: estTokens,
		EstimatedCost:   estCost,
		Usage:           usage,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[budget] policy eval error for subject=%q model=%q: %v — failing open\n",
			subject, model, err)
		return &BudgetDecision{Allowed: true, Subject: subject, Model: model}
	}

	denied := strings.EqualFold(out.Action, "deny")
	if !denied {
		return &BudgetDecision{
			Allowed: true,
			Subject: subject,
			Model:   model,
		}
	}

	// Monitor mode: surface the decision but let the request through.
	if !e.cfg.IsEnforcing() {
		return &BudgetDecision{
			Allowed:   true,
			Monitor:   true,
			Subject:   subject,
			Model:     model,
			Reason:    out.Reason,
			Rule:      out.Rule,
			Limit:     out.Limit,
			Remaining: out.Remaining,
		}
	}
	return &BudgetDecision{
		Allowed:   false,
		Subject:   subject,
		Model:     model,
		Reason:    out.Reason,
		Rule:      out.Rule,
		Limit:     out.Limit,
		Remaining: out.Remaining,
	}
}

// Record persists observed usage into the tracker. Callers pass the
// upstream-reported token usage; cost is derived from the pricing table.
// Safe to call when the enforcer is disabled — the tracker still counts
// so telemetry dashboards remain accurate.
func (e *BudgetEnforcer) Record(subject, model string, promptTokens, completionTokens int64) {
	if e == nil || e.tracker == nil {
		return
	}
	if subject == "" {
		subject = "default"
	}
	cost := e.pricing.EstimateCost(model, promptTokens, completionTokens)
	e.tracker.Record(subject, promptTokens+completionTokens, cost)
}

// SubjectFor resolves the subject identifier from a request. Falls back
// to DefaultSubject when no header is present so the default policy
// entry still applies.
func (e *BudgetEnforcer) SubjectFor(r *http.Request) string {
	if e == nil {
		return "default"
	}
	if r != nil {
		header := e.cfg.EffectiveSubjectHeader()
		if header != "" {
			if v := strings.TrimSpace(r.Header.Get(header)); v != "" {
				// Cap subject length to prevent log / memory abuse.
				if len(v) > 128 {
					v = v[:128]
				}
				return v
			}
		}
	}
	return e.cfg.EffectiveDefaultSubject()
}

// BlockMessage returns the configured block message, or a default.
func (e *BudgetEnforcer) BlockMessage(d *BudgetDecision) string {
	if e != nil && e.cfg.BlockMessage != "" {
		return e.cfg.BlockMessage
	}
	if d != nil && d.Reason != "" {
		return fmt.Sprintf("Request denied by DefenseClaw budget policy: %s", d.Reason)
	}
	return "Request denied by DefenseClaw budget policy — token/cost limit exceeded."
}

// LogAllowed reports whether successful allow decisions should be audited.
func (e *BudgetEnforcer) LogAllowed() bool {
	return e != nil && e.cfg.LogAllowed
}

// ---------------------------------------------------------------------------
// PricingTable — cost estimates derived from data.budget.pricing
// ---------------------------------------------------------------------------

// modelPricing is one entry in the pricing table. Costs are per 1k tokens
// in USD. Zero values mean "unknown" and the default entry is used.
type modelPricing struct {
	InputPer1K  float64 `json:"input_per_1k"`
	OutputPer1K float64 `json:"output_per_1k"`
}

// PricingTable looks up per-1k token pricing for a model. It is loaded
// lazily from the OPA data layer so a restart-less reload picks up
// pricing updates. A nil engine yields zero-cost estimates.
type PricingTable struct {
	opa *policy.Engine
	mu  sync.RWMutex
	// cache captures the last successful load; refreshed every 60 s.
	cache      map[string]modelPricing
	loadedAt   time.Time
	defaultVal modelPricing
}

// NewPricingTable returns a pricing table that reads the budget pricing
// map from data.budget.pricing.
func NewPricingTable(opa *policy.Engine) *PricingTable {
	return &PricingTable{opa: opa}
}

// EstimateCost returns a USD estimate for a request with the given token
// counts. Unknown models fall back to data.budget.pricing.default.
func (p *PricingTable) EstimateCost(model string, promptTokens, completionTokens int64) float64 {
	if p == nil {
		return 0
	}
	table := p.loadTable()
	if table == nil {
		return 0
	}
	mp, ok := table[strings.ToLower(model)]
	if !ok {
		mp = p.defaultVal
	}
	if mp.InputPer1K == 0 && mp.OutputPer1K == 0 {
		return 0
	}
	inputCost := (float64(promptTokens) / 1000.0) * mp.InputPer1K
	outputCost := (float64(completionTokens) / 1000.0) * mp.OutputPer1K
	return inputCost + outputCost
}

// loadTable returns the cached pricing table, refreshing from the OPA
// data layer at most once per minute. On failure the last good value is
// retained to avoid flapping.
func (p *PricingTable) loadTable() map[string]modelPricing {
	if p == nil || p.opa == nil {
		return nil
	}
	p.mu.RLock()
	if p.cache != nil && time.Since(p.loadedAt) < time.Minute {
		table := p.cache
		p.mu.RUnlock()
		return table
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cache != nil && time.Since(p.loadedAt) < time.Minute {
		return p.cache
	}

	raw := p.opa.ReadPath("budget/pricing")
	if raw == nil {
		if p.cache != nil {
			return p.cache
		}
		return map[string]modelPricing{}
	}

	b, err := json.Marshal(raw)
	if err != nil {
		if p.cache != nil {
			return p.cache
		}
		return map[string]modelPricing{}
	}
	var parsed map[string]modelPricing
	if err := json.Unmarshal(b, &parsed); err != nil {
		if p.cache != nil {
			return p.cache
		}
		return map[string]modelPricing{}
	}

	// Normalize keys to lowercase and extract default entry.
	lowered := make(map[string]modelPricing, len(parsed))
	for k, v := range parsed {
		lowered[strings.ToLower(k)] = v
	}
	if def, ok := lowered["default"]; ok {
		p.defaultVal = def
	}
	p.cache = lowered
	p.loadedAt = time.Now()
	return p.cache
}
