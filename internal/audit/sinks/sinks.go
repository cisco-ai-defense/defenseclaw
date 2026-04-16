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

	// flushImmediateActions enumerates audit actions that trigger an
	// immediate sync flush (e.g. lifecycle events the operator must see
	// without batching latency).
	flushImmediateActions map[string]struct{}

	stderr *os.File // injected for tests; defaults to os.Stderr in production
}

// NewManager builds an empty Manager ready to accept Register calls.
func NewManager() *Manager {
	return &Manager{
		flushImmediateActions: defaultImmediateFlushActions(),
		stderr:                os.Stderr,
	}
}

// Register adds a sink to the fan-out list. Order is preserved.
func (m *Manager) Register(s Sink) {
	if m == nil || s == nil {
		return
	}
	m.mu.Lock()
	m.sinks = append(m.sinks, s)
	m.mu.Unlock()
}

// Sinks returns a snapshot of the registered sinks. Used by health
// reporters and the TUI.
func (m *Manager) Sinks() []Sink {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Sink, len(m.sinks))
	copy(out, m.sinks)
	return out
}

// Len reports the number of registered sinks.
func (m *Manager) Len() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sinks)
}

// Forward fans out the event to every registered sink. Errors are logged
// to stderr and returned aggregated; one failing sink does not stop
// delivery to the others.
func (m *Manager) Forward(ctx context.Context, e Event) error {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	snap := make([]Sink, len(m.sinks))
	copy(snap, m.sinks)
	immediate := m.shouldFlushImmediatelyLocked(e.Action)
	m.mu.RUnlock()

	if len(snap) == 0 {
		return nil
	}

	var errs []error
	for _, s := range snap {
		if err := s.Forward(ctx, e); err != nil {
			fmt.Fprintf(m.stderr, "warning: audit sink %q (%s): forward: %v\n",
				s.Name(), s.Kind(), err)
			errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
		}
	}

	if immediate {
		// Best effort — fire flushes asynchronously so a slow sink does not
		// stall the proxy hot-path.
		go m.FlushAll(context.Background())
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
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
	m.mu.Lock()
	snap := m.sinks
	m.sinks = nil
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
	return map[string]struct{}{
		"watch-start":          {},
		"watch-stop":           {},
		"sidecar-start":        {},
		"sidecar-stop":         {},
		"sidecar-connected":    {},
		"sidecar-disconnected": {},
		"guardrail-verdict":    {},
	}
}
