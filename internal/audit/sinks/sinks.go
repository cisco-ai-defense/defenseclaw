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

// Package sinks implements the audit-event fan-out layer. Multiple
// downstream sinks (Splunk HEC, OTLP logs, generic JSONL webhooks) can be
// configured; the Manager forwards every Logger event to every enabled
// sink that matches the event's action and severity filters.
//
// This package replaces the legacy hardcoded Splunk forwarder. There is no
// backward compatibility shim — operators must migrate config.yaml from
// the old `splunk:` block to the new `audit_sinks:` list. See
// docs/OBSERVABILITY.md.
package sinks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Event is the unified audit-event payload sent to every sink. It mirrors
// audit.Event but is duplicated here to keep the audit package free of an
// import cycle (audit imports sinks; sinks must not import audit).
type Event struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Actor     string    `json:"actor"`
	Details   string    `json:"details"`
	Severity  string    `json:"severity"`
	RunID     string    `json:"run_id,omitempty"`
	TraceID   string    `json:"trace_id,omitempty"`
	// RequestID is the per-request correlation key minted at the top of
	// every proxy path (Phase 5 wiring). Empty until the gateway
	// threads it through via context; sinks must tolerate blank values.
	RequestID string `json:"request_id,omitempty"`

	// Session / agent / policy / tool correlation fields mirrored
	// from audit.Event. Every field is optional — older call sites
	// and pre-v5 audit rows leave them empty and sinks must tolerate
	// blanks without erroring. See audit.Event for the semantic
	// contract of each field.
	SessionID string `json:"session_id,omitempty"`
	TurnID    string `json:"turn_id,omitempty"`
	AgentName string `json:"agent_name,omitempty"`
	AgentID   string `json:"agent_id,omitempty"`
	// AgentInstanceID is per-session in v7 (empty when no session
	// context is anchored to the event). The process-scoped identity
	// moved to SidecarInstanceID; downstream consumers grouping
	// "sessions" must use AgentInstanceID, and those grouping "sidecar
	// processes" must use SidecarInstanceID.
	AgentInstanceID   string `json:"agent_instance_id,omitempty"`
	SidecarInstanceID string `json:"sidecar_instance_id,omitempty"`
	PolicyID          string `json:"policy_id,omitempty"`
	DestinationApp    string `json:"destination_app,omitempty"`
	ToolName          string `json:"tool_name,omitempty"`
	ToolID            string `json:"tool_id,omitempty"`

	// Connector is the hook connector that produced this event
	// (e.g. "codex", "claudecode", "antigravity") on multi-connector
	// installs. Empty for non-connector rows (admin actions, proxy
	// verdicts on single-connector installs). Sinks surface this as a
	// first-class field so SIEM consumers can filter/group by connector
	// without parsing the Structured payload. Mirrors audit.Event.Connector.
	Connector string `json:"connector,omitempty"`

	// v7 provenance fields. Logger stamps these before forwarding so
	// every sink carries the same contract fields as the SQLite
	// audit_events row.
	SchemaVersion int    `json:"schema_version,omitempty"`
	ContentHash   string `json:"content_hash,omitempty"`
	Generation    uint64 `json:"generation,omitempty"`
	BinaryVersion string `json:"binary_version,omitempty"`

	// Structured payload — when set, this is the canonical machine-readable
	// representation of the event (e.g. a guardrail verdict). Sinks should
	// prefer Structured over Details when emitting.
	Structured map[string]any `json:"structured,omitempty"`
}

// Sink is the contract every audit-event destination implements. Sinks are
// expected to be safe for concurrent use; the Manager calls Forward from a
// single goroutine but Flush/Close can race with shutdown.
type Sink interface {
	// Name returns the operator-supplied name of the sink. Used in logs
	// and health reports.
	Name() string

	// Kind returns the canonical kind tag (e.g. "splunk_hec", "otlp_logs",
	// "http_jsonl"). Used by the TUI and metrics labels.
	Kind() string

	// Forward sends a single event downstream. Implementations may buffer
	// internally and return nil immediately; surface persistent errors via
	// Flush. ctx is canceled on Manager shutdown.
	Forward(ctx context.Context, e Event) error

	// Flush blocks until any internal buffer has been drained or ctx is
	// canceled. Called periodically by the Manager and on shutdown.
	Flush(ctx context.Context) error

	// Close releases resources (HTTP transports, tickers). Manager guarantees
	// Forward is not called after Close returns.
	Close() error
}

// MinSeverityFilter and ActionFilter are wrapper helpers used by the
// Manager to enforce per-sink filtering. They are exported so adapters can
// reuse the same severity-rank rules.

const (
	severityInfo     = 1
	severityLow      = 2
	severityMedium   = 3
	severityHigh     = 4
	severityCritical = 5
)

func severityRank(s string) int {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return severityCritical
	case "HIGH":
		return severityHigh
	case "MEDIUM", "MED":
		return severityMedium
	case "LOW":
		return severityLow
	case "", "INFO", "NONE":
		return severityInfo
	}
	// Unknown severities are treated as INFO so a typo does not silently
	// suppress events.
	return severityInfo
}

// matchesFilters returns true if the event passes the sink's severity and
// action filters. Empty filters match everything.
func matchesFilters(e Event, minSev string, actions []string) bool {
	if minSev != "" && severityRank(e.Severity) < severityRank(minSev) {
		return false
	}
	if len(actions) > 0 {
		matched := false
		for _, a := range actions {
			if strings.EqualFold(strings.TrimSpace(a), e.Action) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// SinkFilter holds per-sink action/severity filtering. Embedded in concrete
// sinks via NewBaseSink.
type SinkFilter struct {
	MinSeverity string
	Actions     []string
}

// Matches is the public version of matchesFilters for use by sink impls
// that want to short-circuit before serializing.
func (f SinkFilter) Matches(e Event) bool {
	return matchesFilters(e, f.MinSeverity, f.Actions)
}

// Manager owns the configured sinks and fans out each audit event. The
// zero value is a no-op manager (Forward returns nil, Close is a no-op),
// which lets callers omit the Manager entirely when no sinks are
// configured.
type Manager struct {
	mu    sync.RWMutex
	sinks []Sink

	// connectorSinks holds per-connector audit sinks (D5b). A connector's
	// events route to ITS sinks when the connector has an override (see
	// connectorOverride below), otherwise they fall back to the global
	// sinks slice above. Keyed by normalized connector name.
	connectorSinks map[string][]Sink

	// connectorOverride records connectors with an explicit per-connector
	// audit_sinks dimension (a present list, possibly empty). A connector
	// present here with an empty connectorSinks slice SUPPRESSES global
	// routing for that connector (the tri-state's empty-list case); a
	// connector absent here INHERITS the global sinks (the safety default —
	// no silent drop). Keyed by normalized connector name.
	connectorOverride map[string]bool

	// flushImmediateActions enumerates audit actions that trigger an
	// immediate sync flush (e.g. lifecycle events the operator must see
	// without batching latency).
	flushImmediateActions map[string]struct{}

	// immediateFlushInFlight coalesces the async flush fan-out that fires
	// on every "immediate" action. Without this, a burst of guardrail
	// verdicts would spawn one goroutine per Forward call, all contending
	// for the same RLock and hammering the downstream sinks' Flush
	// implementations. The single-flight flag keeps exactly one async
	// flush in flight; subsequent immediate events within that window
	// collapse into the already-scheduled flush. The goroutine re-flushes
	// while the pending counter is non-zero, absorbing entire bursts
	// without spawning new goroutines.
	immediateFlushInFlight atomic.Bool
	immediateFlushPending  atomic.Int64

	// closed is set once Close() completes so Forward short-circuits
	// even if a concurrent caller captured an older RLock-protected
	// snapshot before we cleared m.sinks.
	closed atomic.Bool

	stderr *os.File // injected for tests; defaults to os.Stderr in production

	// deliveryHook is invoked after each sink Forward (Track 5). Nil is a no-op.
	deliveryHook func(ctx context.Context, kind, sinkName string, err error, latencyMs float64)

	cbMu       sync.Mutex
	failStreak map[string]int
	tripped    map[string]bool

	onCircuitTrip    func(kind, sinkName string)
	onCircuitRecover func(kind, sinkName string)
}

// NewManager builds an empty Manager ready to accept Register calls.
func NewManager() *Manager {
	return &Manager{
		flushImmediateActions: defaultImmediateFlushActions(),
		stderr:                os.Stderr,
	}
}

// SetDeliveryHook installs a per-sink Forward observer (metrics, SQLite
// sink_health, gateway errors). Pass nil to detach.
func (m *Manager) SetDeliveryHook(h func(ctx context.Context, kind, sinkName string, err error, latencyMs float64)) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.deliveryHook = h
	m.mu.Unlock()
}

// SetCircuitCallbacks wires circuit-breaker trip/recover notifications after
// 5 consecutive failures and the next success (soft breaker — forwards are
// still attempted every time).
func (m *Manager) SetCircuitCallbacks(onTrip, onRecover func(kind, sinkName string)) {
	if m == nil {
		return
	}
	m.cbMu.Lock()
	m.onCircuitTrip = onTrip
	m.onCircuitRecover = onRecover
	m.cbMu.Unlock()
}

// Register adds a sink to the global fan-out list. Order is preserved.
// Global sinks receive every connector's events unless that connector has a
// per-connector override (see RegisterForConnector / MarkConnectorOverride).
func (m *Manager) Register(s Sink) {
	if m == nil || s == nil {
		return
	}
	m.mu.Lock()
	m.sinks = append(m.sinks, s)
	m.mu.Unlock()
}

// normalizeConnector canonicalizes a connector name for per-connector sink
// routing: trim + lowercase, folding the known hyphen/underscore aliases onto
// their canonical registry name. Mirrors config.normalizeConnectorKey — kept
// local so the sinks package stays free of a config import (it deliberately
// sits low in the dependency graph; see the Event-duplication note above).
func normalizeConnector(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "open-hands", "open_hands":
		return "openhands"
	default:
		return n
	}
}

// RegisterForConnector registers a sink that receives ONLY events whose
// Connector matches connector. Registering a sink for a connector implicitly
// marks that connector as having a per-connector override, so its events stop
// flowing to the global sinks (override semantics). Order is preserved.
//
// The composition layer (internal/cli.buildAuditSinks) calls this for each
// sink declared under observability.connectors[<name>].audit_sinks. To express
// the tri-state's empty-list "suppress" case (an override present but with zero
// sinks), call MarkConnectorOverride instead/as well.
func (m *Manager) RegisterForConnector(connector string, s Sink) {
	if m == nil || s == nil {
		return
	}
	key := normalizeConnector(connector)
	if key == "" {
		// No connector identity — fall back to the global list rather than
		// silently dropping the sink.
		m.Register(s)
		return
	}
	m.mu.Lock()
	if m.connectorSinks == nil {
		m.connectorSinks = make(map[string][]Sink)
	}
	if m.connectorOverride == nil {
		m.connectorOverride = make(map[string]bool)
	}
	m.connectorSinks[key] = append(m.connectorSinks[key], s)
	m.connectorOverride[key] = true
	m.mu.Unlock()
}

// MarkConnectorOverride records that connector has an explicit per-connector
// audit_sinks dimension even when it resolves to zero sinks. This is the
// tri-state's empty-list case: the connector's events are SUPPRESSED (routed
// to no sinks) rather than inheriting the global list. Idempotent and safe to
// call alongside RegisterForConnector.
func (m *Manager) MarkConnectorOverride(connector string) {
	if m == nil {
		return
	}
	key := normalizeConnector(connector)
	if key == "" {
		return
	}
	m.mu.Lock()
	if m.connectorOverride == nil {
		m.connectorOverride = make(map[string]bool)
	}
	m.connectorOverride[key] = true
	m.mu.Unlock()
}

// sinksForConnector returns the sink slice an event with the given connector
// routes to, honoring the per-connector tri-state. MUST be called with at
// least an RLock held. Returns the global sinks when the connector has no
// override (inherit), or the connector's own sinks (possibly empty = suppress)
// when it does.
func (m *Manager) sinksForConnectorLocked(connector string) []Sink {
	if connector != "" && len(m.connectorOverride) > 0 {
		key := normalizeConnector(connector)
		if m.connectorOverride[key] {
			return m.connectorSinks[key]
		}
	}
	return m.sinks
}

// Sinks returns a snapshot of every registered sink — global and
// per-connector (D5b) — so health reporters, the TUI, FlushAll, and Close all
// observe the complete set. Per-connector sinks are distinct objects from the
// global ones, so the union has no duplicates.
func (m *Manager) Sinks() []Sink {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.allSinksLocked()
}

// allSinksLocked returns global + per-connector sinks. Caller holds at least
// an RLock.
func (m *Manager) allSinksLocked() []Sink {
	out := make([]Sink, 0, len(m.sinks))
	out = append(out, m.sinks...)
	for _, ss := range m.connectorSinks {
		out = append(out, ss...)
	}
	return out
}

// Len reports the number of registered sinks (global + per-connector). Used by
// the boot path to decide whether to install the manager at all, so it must
// count per-connector sinks — a global-empty install that only routes a
// connector to its own sink is still a live manager.
func (m *Manager) Len() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := len(m.sinks)
	for _, ss := range m.connectorSinks {
		n += len(ss)
	}
	return n
}

// Forward fans out the event to every registered sink. The returned map
// holds one entry per sink that returned a non-nil error (key = sink name).
func (m *Manager) Forward(ctx context.Context, e Event) map[string]error {
	if m == nil || m.closed.Load() {
		return nil
	}
	m.mu.RLock()
	// Per-connector routing (D5b): an event whose connector has an explicit
	// override fans out only to that connector's sinks (empty = suppress);
	// every other event inherits the global sinks. This keys off the
	// connector already stamped on the event by the logger/gateway, so no
	// extra threading is required at the call site.
	targets := m.sinksForConnectorLocked(e.Connector)
	snap := make([]Sink, len(targets))
	copy(snap, targets)
	immediate := m.shouldFlushImmediatelyLocked(e.Action)
	hook := m.deliveryHook
	m.mu.RUnlock()

	if len(snap) == 0 {
		return nil
	}

	perSink := make(map[string]error)
	for _, s := range snap {
		start := time.Now()
		err := m.safeForward(ctx, s, e)
		latencyMs := float64(time.Since(start).Nanoseconds()) / 1e6
		if hook != nil {
			hook(ctx, s.Kind(), s.Name(), err, latencyMs)
		}
		if err != nil {
			fmt.Fprintf(m.stderr, "warning: audit sink %q (%s): forward: %v\n",
				s.Name(), s.Kind(), err)
			perSink[s.Name()] = err
			m.recordSinkFailure(s.Kind(), s.Name())
		} else {
			m.recordSinkSuccess(s.Kind(), s.Name())
		}
	}

	if immediate {
		// Coalesce: only the first immediate-flush request within a
		// window spawns a goroutine. High-frequency actions
		// (guardrail-verdict fires on every block decision) would
		// otherwise leak goroutines and thrash the downstream
		// sinks' Flush paths. The goroutine holds the in-flight
		// flag for the entire burst: it flushes, then re-checks
		// the pending counter after a 1ms settle window to absorb
		// follow-on events before releasing the flag.
		m.immediateFlushPending.Add(1)
		if m.immediateFlushInFlight.CompareAndSwap(false, true) {
			go func() {
				defer m.immediateFlushInFlight.Store(false)
				for {
					m.immediateFlushPending.Store(0)
					_ = m.FlushAll(context.Background())
					time.Sleep(time.Millisecond)
					if m.immediateFlushPending.Load() == 0 {
						break
					}
				}
			}()
		}
	}

	if len(perSink) == 0 {
		return nil
	}
	return perSink
}

func (m *Manager) recordSinkFailure(kind, name string) {
	m.cbMu.Lock()
	defer m.cbMu.Unlock()
	if m.failStreak == nil {
		m.failStreak = make(map[string]int)
	}
	if m.tripped == nil {
		m.tripped = make(map[string]bool)
	}
	m.failStreak[name]++
	if m.failStreak[name] == 5 && !m.tripped[name] {
		m.tripped[name] = true
		if m.onCircuitTrip != nil {
			m.onCircuitTrip(kind, name)
		}
	}
}

func (m *Manager) recordSinkSuccess(kind, name string) {
	m.cbMu.Lock()
	defer m.cbMu.Unlock()
	if m.tripped != nil && m.tripped[name] {
		if m.onCircuitRecover != nil {
			m.onCircuitRecover(kind, name)
		}
	}
	if m.failStreak != nil {
		delete(m.failStreak, name)
	}
	if m.tripped != nil {
		delete(m.tripped, name)
	}
}

// safeForward wraps a single sink's Forward with recover() so a
// panic inside a third-party sink cannot unwind into the audit
// logger (and from there into the guardrail hot path). The
// recovered error is surfaced as a regular forward error so the
// caller's stderr warning path fires.
func (m *Manager) safeForward(ctx context.Context, s Sink, e Event) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("sink %q (%s): panic: %v", s.Name(), s.Kind(), r)
		}
	}()
	return s.Forward(ctx, e)
}

// FlushAll requests every sink drain its buffer. Errors are aggregated.
func (m *Manager) FlushAll(ctx context.Context) error {
	if m == nil {
		return nil
	}
	snap := m.Sinks()
	if len(snap) == 0 {
		return nil
	}
	flushCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var errs []error
	for _, s := range snap {
		if err := s.Flush(flushCtx); err != nil {
			fmt.Fprintf(m.stderr, "warning: audit sink %q (%s): flush: %v\n",
				s.Name(), s.Kind(), err)
			errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// Close flushes and closes every sink. After Close returns, Forward is a
// no-op.
func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	// Mark closed BEFORE draining so any Forward caller that races
	// with Close short-circuits via the closed.Load() check above,
	// even if they already captured an RLock-protected snapshot.
	m.closed.Store(true)
	m.mu.Lock()
	snap := m.allSinksLocked()
	m.sinks = nil
	m.connectorSinks = nil
	m.connectorOverride = nil
	m.mu.Unlock()

	var errs []error
	for _, s := range snap {
		if err := s.Flush(context.Background()); err != nil {
			errs = append(errs, fmt.Errorf("flush %s: %w", s.Name(), err))
		}
		if err := s.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close %s: %w", s.Name(), err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// SetImmediateFlushActions overrides the default set of actions that
// trigger a fast-path flush. Empty input restores defaults.
func (m *Manager) SetImmediateFlushActions(actions []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(actions) == 0 {
		m.flushImmediateActions = defaultImmediateFlushActions()
		return
	}
	set := make(map[string]struct{}, len(actions))
	for _, a := range actions {
		set[strings.TrimSpace(a)] = struct{}{}
	}
	m.flushImmediateActions = set
}

func (m *Manager) shouldFlushImmediatelyLocked(action string) bool {
	if m.flushImmediateActions == nil {
		return false
	}
	_, ok := m.flushImmediateActions[action]
	return ok
}

func defaultImmediateFlushActions() map[string]struct{} {
	// These keys mirror internal/audit Action* constants. The sinks
	// package sits below audit in the dependency graph, so importing
	// audit here would create a cycle.
	return map[string]struct{}{
		"watch-start":          {},
		"watch-stop":           {},
		"sidecar-start":        {},
		"sidecar-stop":         {},
		"sidecar-connected":    {},
		"sidecar-disconnected": {},
		"guardrail-verdict":    {},
		"gateway-verdict":      {},
		"gateway-lifecycle":    {},
		"gateway-error":        {},
	}
}
