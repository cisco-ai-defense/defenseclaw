// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"context"
	"errors"
	"net/http"
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
	snap    atomic.Pointer[snapshot]
	dropped atomic.Int64

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

// PriceTable returns the current price table (never nil).
func (e *Engine) PriceTable() *PriceTable { return e.snap.Load().table }

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
	for rec := range q {
		e.mu.RLock()
		sinks := e.sinks
		e.mu.RUnlock()
		for _, s := range sinks {
			emitSafe(s, rec)
		}
	}
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
	if !s.enabled || (!s.allRoles && !s.roles[f.CallRole]) {
		return noopCall{}
	}
	if f.CallRole == "" {
		f.CallRole = RoleAgent
	}
	now := time.Now()
	if f.StartedAt.IsZero() {
		f.StartedAt = now
	}
	c := &call{e: e, s: s, f: f, start: now}
	if f.Streaming {
		c.parser = NewStreamParser(f.APIFamily)
	}
	if !s.provenance {
		c.f.Route = RouteFacts{Decision: f.Route.Decision}
		c.f.RequestedProvider, c.f.RequestedModel = "", ""
		c.f.ProfileName, c.f.ProfileDigest = "", ""
	}
	return c
}

type call struct {
	e      *Engine
	s      *snapshot
	f      CallFacts
	start  time.Time
	parser *StreamParser

	mu       sync.Mutex
	status   int
	ttfb     time.Duration
	hdrUsage Usage
	bodyUse  Usage
	given    *Usage
	done     bool
	rec      Record
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
	if c.parser != nil {
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
	u := c.pickUsage()
	rec.Usage = u
	rec.Cost = c.cost(u)
	rec.Labels = c.labels()
	return rec
}

// pickUsage prefers usage the caller already parsed, then the stream, then
// the body, then provider headers.
func (c *call) pickUsage() Usage {
	switch {
	case c.given != nil:
		return *c.given
	case c.parser != nil && c.parser.Usage().Has != 0:
		return c.parser.Usage()
	case c.bodyUse.Has != 0:
		return c.bodyUse
	default:
		return c.hdrUsage
	}
}

func (c *call) cost(u Usage) Cost {
	s := c.s
	if !s.cost {
		return Resolve(s.table, nil, "", nil, s.keepRep, u.Partial)
	}
	if c.f.CallRole == RoleAIDefense {
		if v, ok := s.table.AIDefenseCost(); ok && c.status < 400 {
			return Resolve(s.table, &v, "ai_defense", nil, s.keepRep, "")
		}
		return Resolve(s.table, nil, "", nil, s.keepRep, "")
	}
	provider, model := c.f.SelectedProvider, c.f.SelectedModel
	if usd, key, ok := s.table.Compute(provider, model, u); ok {
		return Resolve(s.table, &usd, key, nil, s.keepRep, u.Partial)
	}
	if u.ResponseModel != "" && u.ResponseModel != model {
		if usd, key, ok := s.table.Compute(provider, u.ResponseModel, u); ok {
			return Resolve(s.table, &usd, key, nil, s.keepRep, u.Partial)
		}
	}
	return Resolve(s.table, nil, "", nil, s.keepRep, u.Partial)
}

// labels builds the bounded metric labels. The model label is the matched
// price entry or other, so a client-chosen model string cannot add series.
func (c *call) labels() []Label {
	f := c.f
	model := c.s.table.ModelKey(f.SelectedProvider, f.SelectedModel)
	out := make([]Label, 0, len(c.s.labels))
	for _, name := range c.s.labels {
		var v string
		switch name {
		case "connector":
			v = f.Connector
		case "provider":
			v = f.SelectedProvider
		case "model":
			v = model
		case "route_decision":
			v = f.Route.Decision
		case "call_role":
			v = string(f.CallRole)
		case "profile":
			v = f.ProfileName
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
