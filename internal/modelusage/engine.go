// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const (
	// queueSize bounds records waiting for the sinks. A full queue drops the
	// record and counts it; the response path never waits.
	queueSize = 4096
	// stopDeadline bounds the drain when the engine is turned off.
	stopDeadline  = 2 * time.Second
	maxLabelBytes = 128
	// dropReportEvery is how often lost records are reported.
	dropReportEvery = 10 * time.Second
)

var (
	profileLabelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// snapshot is the immutable view of the config one call is recorded under.
type snapshot struct {
	enabled    bool
	tok        config.TokenomicsConfig
	table      *PriceTable
	labels     []string
	roles      map[CallRole]bool
	allRoles   bool
	cost       bool
	keepRep    bool
	provenance bool
}

// Engine records model calls. It is created once, always non-nil, and inert
// until Apply enables it: no goroutine, no buffer. Apply is the hot-reload
// entry; it never needs a restart.
type Engine struct {
	snap     atomic.Pointer[snapshot]
	applyMu  sync.Mutex // serialises Apply so the snapshot and the worker never disagree
	dropped  atomic.Int64
	dropMu   sync.Mutex
	dropSeen map[string]int64
	// budgetSink receives agent call costs for routing.admin budgets.
	budgetSink atomic.Pointer[spendSinkBox]

	mu      sync.RWMutex
	sinks   []Sink
	q       chan Record
	done    chan struct{}
	running bool
}

// NewEngine returns an inert engine that will deliver to sinks once enabled.
func NewEngine(sinks ...Sink) *Engine {
	e := &Engine{sinks: sinks}
	e.snap.Store(&snapshot{})
	return e
}

// AddSink appends a sink (before or after Apply).
func (e *Engine) AddSink(s Sink) {
	e.mu.Lock()
	e.sinks = append(e.sinks, s)
	e.mu.Unlock()
}

// Apply installs the tokenomics and pricing config. It starts the worker when
// the engine becomes enabled and stops it, with a short drain, when it
// becomes disabled.
func (e *Engine) Apply(tok config.TokenomicsConfig, pricing config.PricingConfig) {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	s := &snapshot{
		enabled:    tok.Enabled,
		tok:        tok,
		table:      NewPriceTable(pricing),
		labels:     tok.MetricLabels(),
		cost:       tok.ComputesCost(),
		keepRep:    tok.KeepsReportedCost(),
		provenance: tok.RecordsRoutingProvenance(),
		allRoles:   len(tok.Roles) == 0,
		roles:      map[CallRole]bool{},
	}
	for _, r := range tok.Roles {
		s.roles[CallRole(r)] = true
	}
	e.snap.Store(s)
	if s.enabled {
		e.start()
	} else {
		e.stop()
	}
}

// Enabled reports whether calls are being recorded.
func (e *Engine) Enabled() bool { return e != nil && e.snap.Load().enabled }

// Dropped reports records dropped because the queue was full.
func (e *Engine) Dropped() int64 {
	if e == nil {
		return 0
	}
	return e.dropped.Load()
}

func (e *Engine) start() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		return
	}
	e.q = make(chan Record, queueSize)
	e.done = make(chan struct{})
	e.running = true
	go e.work(e.q, e.done)
}

func (e *Engine) stop() {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return
	}
	e.running = false
	close(e.q)
	done := e.done
	e.mu.Unlock()
	select {
	case <-done:
	case <-time.After(stopDeadline):
	}
}

func (e *Engine) work(q chan Record, done chan struct{}) {
	defer close(done)
	tick := time.NewTicker(dropReportEvery)
	defer tick.Stop()
	for {
		select {
		case rec, ok := <-q:
			if !ok {
				e.reportDrops()
				return
			}
			e.mu.RLock()
			sinks := e.sinks
			e.mu.RUnlock()
			for _, s := range sinks {
				emitSafe(s, rec)
			}
		case <-tick.C:
			e.reportDrops()
		}
	}
}

// reportDrops tells the drop reporters how many records were lost since the
// last report: the engine queue and every sink that counts its own losses.
// Lost records are never silent: the absent-cost panels would read low.
func (e *Engine) reportDrops() {
	e.mu.RLock()
	sinks := e.sinks
	e.mu.RUnlock()
	totals := map[string]int64{"queue": e.dropped.Load()}
	for _, s := range sinks {
		for kind, n := range dropTotalsSafe(s) {
			totals[kind] += n
		}
	}
	e.dropMu.Lock()
	if e.dropSeen == nil {
		e.dropSeen = map[string]int64{}
	}
	var lost int64
	for kind, n := range totals {
		if d := n - e.dropSeen[kind]; d > 0 {
			lost += d
			e.dropSeen[kind] = n
		}
	}
	e.dropMu.Unlock()
	if lost == 0 {
		return
	}
	for _, s := range sinks {
		if r, ok := s.(DropReporter); ok {
			reportSafe(r, lost)
		}
	}
}

// dropTotalsSafe asks a sink for its loss counters; a sink that panics reports none.
func dropTotalsSafe(s Sink) (out map[string]int64) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
		}
	}()
	if src, ok := s.(DropSource); ok {
		return src.DropTotals()
	}
	return nil
}

func reportSafe(r DropReporter, n int64) {
	defer func() { _ = recover() }()
	r.ReportDrops(n)
}

func emitSafe(s Sink, rec Record) {
	defer func() { _ = recover() }()
	s.Emit(context.Background(), rec)
}

func (e *Engine) enqueue(rec Record) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if !e.running {
		return
	}
	select {
	case e.q <- rec:
	default:
		e.dropped.Add(1)
	}
}

// Begin implements Recorder.
func (e *Engine) Begin(ctx context.Context, f CallFacts) Call {
	if e == nil {
		return noopCall{}
	}
	s := e.snap.Load()
	if f.CallRole == "" {
		f.CallRole = RoleAgent
	}
	if !s.records(f.CallRole) {
		return noopCall{}
	}
	now := time.Now()
	if f.StartedAt.IsZero() {
		f.StartedAt = now
	}
	c := &call{e: e, s: s, f: s.withoutProvenance(f), start: now}
	if f.Streaming {
		c.parser = NewStreamParser(f.APIFamily)
	}
	return c
}

func (s *snapshot) records(role CallRole) bool {
	return s.enabled && (s.allRoles || s.roles[role])
}

// withoutProvenance drops the routing facts when the operator turned
// observability.tokenomics.record_routing_provenance off.
func (s *snapshot) withoutProvenance(f CallFacts) CallFacts {
	if !s.provenance {
		f.Route = RouteFacts{Decision: f.Route.Decision}
		f.RequestedProvider, f.RequestedModel = "", ""
		f.ProfileName, f.ProfileDigest = "", ""
	}
	return f
}

// NativeImportEnabled reports whether usage imported from the OTLP telemetry
// of connector is recorded: tokenomics on, the agent role recorded and
// observability.tokenomics.native_otel_import.<connector> on.
func (e *Engine) NativeImportEnabled(connector string) bool {
	if e == nil {
		return false
	}
	s := e.snap.Load()
	return s.records(RoleAgent) && s.tok.NativeImportEnabled(connector)
}

// RecordNative records a model call the engine did not see itself: usage an
// agent reported in its own telemetry (native OTLP). rec carries the facts,
// the usage, the times and, in Cost.ReportedUSD only, a per-call cost the
// agent reported; every other Cost field and the labels are recomputed here
// with the current price table, exactly as for a proxied call. A running
// total (a session or cumulative cost counter) must never be passed as
// ReportedUSD. The record is dropped when tokenomics, the call role or the
// native import of rec.Facts.Connector is off. It returns the record as
// recorded and whether it was recorded.
func (e *Engine) RecordNative(rec Record) (out Record, ok bool) {
	if e == nil {
		return Record{}, false
	}
	defer func() {
		if r := recover(); r != nil {
			out, ok = Record{}, false
		}
	}()
	s := e.snap.Load()
	if rec.Facts.CallRole == "" {
		rec.Facts.CallRole = RoleAgent
	}
	if !s.records(rec.Facts.CallRole) || !s.tok.NativeImportEnabled(rec.Facts.Connector) {
		return Record{}, false
	}
	rec.Facts = s.withoutProvenance(rec.Facts)
	rec.Usage.seal()
	if rec.Usage.Has != 0 && rec.Usage.Source == "" {
		rec.Usage.Source = SourceNativeOTel
	}
	if rec.EndedAt.IsZero() {
		rec.EndedAt = time.Now()
	}
	if rec.Facts.StartedAt.IsZero() {
		rec.Facts.StartedAt = rec.EndedAt.Add(-rec.Total)
	}
	if rec.Outcome == "" {
		rec.Outcome = "completed"
	}
	reported := rec.Cost.ReportedUSD
	rec.Cost = s.price(rec.Facts, rec.Status, rec.Usage, reported)
	s.bound(&rec)
	e.chargeBudgets(rec.Facts, rec)
	e.enqueue(rec)
	return rec, true
}

type call struct {
	e      *Engine
	s      *snapshot
	f      CallFacts
	start  time.Time
	parser *StreamParser

	mu        sync.Mutex
	status    int
	ttfb      time.Duration
	hdrUsage  Usage
	bodyUse   Usage
	streamUse Usage
	given     *Usage
	done      bool
	rec       Record
}

func (c *call) UpstreamHeader(status int, h http.Header) {
	defer func() { _ = recover() }()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status = status
	if c.ttfb == 0 {
		c.ttfb = time.Since(c.start)
	}
	if c.f.APIFamily == FamilyInvoke {
		c.hdrUsage = ParseBedrockHeaders(h)
	}
}

func (c *call) Chunk(p []byte) {
	if c.parser == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.done {
		c.parser.Write(p)
	}
}

func (c *call) Body(p []byte) {
	defer func() { _ = recover() }()
	u := ParseBody(c.f.APIFamily, p)
	c.mu.Lock()
	c.bodyUse = u
	c.mu.Unlock()
}

func (c *call) Usage(p ParsedUsage) {
	u := p.usage()
	c.mu.Lock()
	c.given = &u
	c.mu.Unlock()
}

func (c *call) End(err error) Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return c.rec
	}
	c.done = true
	defer func() {
		if r := recover(); r != nil {
			c.rec = Record{Facts: c.f, Outcome: "failed", ErrorType: "usage_record_panic"}
		}
	}()
	c.rec = c.build(err)
	c.e.chargeBudgets(c.f, c.rec)
	c.e.enqueue(c.rec)
	return c.rec
}

func (c *call) build(err error) Record {
	end := time.Now()
	rec := Record{Facts: c.f, Status: c.status, Outcome: "completed", TTFB: c.ttfb, Total: end.Sub(c.start), EndedAt: end}
	switch {
	case errors.Is(err, context.Canceled):
		rec.Outcome, rec.ErrorType = "cancelled", "cancelled"
	case err != nil:
		rec.Outcome, rec.ErrorType = "failed", "upstream_error"
	case c.status >= 400:
		rec.Outcome, rec.ErrorType = "failed", "http_"+itoa(c.status)
	}
	if c.parser != nil {
		c.streamUse = c.parser.Usage()
	}
	u := c.pickUsage()
	rec.Usage = u
	rec.Cost = c.s.price(c.f, c.status, u, nil)
	c.s.bound(&rec)
	return rec
}

// pickUsage prefers usage the caller already parsed, then the stream, then
// the body, then provider headers.
func (c *call) pickUsage() Usage {
	switch {
	case c.given != nil && c.given.Has != 0:
		return *c.given
	case c.parser != nil && c.streamUse.Has != 0:
		return c.streamUse
	case c.bodyUse.Has != 0:
		return c.bodyUse
	default:
		return c.hdrUsage
	}
}

// price prices one call with the snapshot table. reported is a per-call cost
// the agent or provider reported; it is never a running total.
func (s *snapshot) price(f CallFacts, status int, u Usage, reported *float64) Cost {
	if !s.cost {
		return Resolve(s.table, nil, "", reported, s.keepRep, u.Partial)
	}
	if f.CallRole == RoleAIDefense {
		if v, ok := s.table.AIDefenseCost(); ok && status < 400 {
			return Resolve(s.table, &v, "ai_defense", reported, s.keepRep, "")
		}
		return Resolve(s.table, nil, "", reported, s.keepRep, "")
	}
	provider, model := f.SelectedProvider, f.SelectedModel
	if usd, key, ok := s.table.Compute(provider, model, u); ok {
		return Resolve(s.table, &usd, key, reported, s.keepRep, u.Partial)
	}
	if u.ResponseModel != "" && u.ResponseModel != model {
		if usd, key, ok := s.table.Compute(provider, u.ResponseModel, u); ok {
			return Resolve(s.table, &usd, key, reported, s.keepRep, u.Partial)
		}
	}
	return Resolve(s.table, nil, "", reported, s.keepRep, u.Partial)
}

// bound sets the bounded model and provider of a record and its metric
// labels. The model is the matched price entry or other, so a client-chosen
// model string cannot add series or store rows.
func (s *snapshot) bound(rec *Record) {
	rec.ModelKey = s.modelKey(rec.Facts, rec.Cost, rec.Usage)
	rec.ProviderKey = providerKey(rec.Facts.SelectedProvider)
	rec.Labels = s.metricLabels(rec.Facts, rec.ModelKey, rec.ProviderKey)
}

func (s *snapshot) modelKey(f CallFacts, cost Cost, u Usage) string {
	model := s.table.ModelKey(f.SelectedProvider, f.SelectedModel)
	if model == "other" && u.ResponseModel != "" {
		model = s.table.ModelKey(f.SelectedProvider, u.ResponseModel)
	}
	if cost.PriceEntry == "fallback" {
		model = "other"
	}
	return model
}

// providerKey bounds a provider name: a plain lower-case identifier, else other.
func providerKey(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if knownProviders[p] {
		return p
	}
	return "other"
}

// knownProviders is the closed set of provider names that become a metric
// label or a store key; any other provider is other, so a client or a custom
// provider name cannot add series.
var knownProviders = map[string]bool{
	"anthropic": true, "openai": true, "bedrock": true, "azure": true, "gemini": true, "google": true,
	"vertex": true, "ollama": true, "vllm": true, "lm_studio": true, "openrouter": true, "mistral": true,
	"cohere": true, "groq": true, "xai": true, "deepseek": true, "together": true, "fireworks": true,
	"perplexity": true, "cerebras": true, "huggingface": true, "nvidia": true, "decision_model": true, "ai_defense": true,
}

func (s *snapshot) metricLabels(f CallFacts, model, provider string) []Label {
	out := make([]Label, 0, len(s.labels))
	for _, name := range s.labels {
		var v string
		switch name {
		case "connector":
			v = f.Connector
		case "provider":
			v = provider
		case "model":
			v = model
		case "route_decision":
			v = f.Route.Decision
		case "call_role":
			v = string(f.CallRole)
		case "profile":
			v = f.ProfileName
			if v != "" && !profileLabelPattern.MatchString(v) {
				v = "other"
			}
		}
		out = append(out, Label{Key: name, Value: boundLabel(v)})
	}
	return out
}

func boundLabel(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "none"
	}
	if len(v) > maxLabelBytes {
		v = v[:maxLabelBytes]
	}
	return v
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte(0x30 + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = 0x2d
	}
	return string(b[i:])
}
