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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

const observabilityV8HealthSnapshotTimeout = 100 * time.Millisecond

type observabilityV8HealthSource interface {
	DestinationHealthSnapshot(context.Context) (observabilityruntime.DestinationHealthSnapshot, error)
}

type observabilityV8FailureObservation struct {
	generation uint64
	code       string
	occurredAt time.Time
}

type SubsystemState string

const (
	StateStarting     SubsystemState = "starting"
	StateRunning      SubsystemState = "running"
	StateReconnecting SubsystemState = "reconnecting"
	StateStopped      SubsystemState = "stopped"
	StateError        SubsystemState = "error"
	StateDisabled     SubsystemState = "disabled"
)

type SubsystemHealth struct {
	State     SubsystemState         `json:"state"`
	Since     time.Time              `json:"since"`
	LastError string                 `json:"last_error,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// ConnectorHealth reports a connector's identity, mode, and live counters.
type ConnectorHealth struct {
	Name               string                       `json:"name"`
	State              SubsystemState               `json:"state"`
	Source             string                       `json:"source,omitempty"`
	Since              time.Time                    `json:"since"`
	LastActivityAt     *time.Time                   `json:"last_activity_at,omitempty"`
	ToolInspectionMode connector.ToolInspectionMode `json:"tool_inspection_mode"`
	SubprocessPolicy   connector.SubprocessPolicy   `json:"subprocess_policy"`
	Requests           int64                        `json:"requests"`
	Errors             int64                        `json:"errors"`
	ToolInspections    int64                        `json:"tool_inspections"`
	ToolBlocks         int64                        `json:"tool_blocks"`
	SubprocessBlocks   int64                        `json:"subprocess_blocks"`
}

type HealthSnapshot struct {
	StartedAt             time.Time        `json:"started_at"`
	UptimeMs              int64            `json:"uptime_ms"`
	Gateway               SubsystemHealth  `json:"gateway"`
	Watcher               SubsystemHealth  `json:"watcher"`
	Config                SubsystemHealth  `json:"config"`
	API                   SubsystemHealth  `json:"api"`
	Guardrail             SubsystemHealth  `json:"guardrail"`
	Telemetry             SubsystemHealth  `json:"telemetry"`
	AIDiscovery           SubsystemHealth  `json:"ai_discovery"`
	ApplicationProtection SubsystemHealth  `json:"application_protection"`
	Sandbox               *SubsystemHealth `json:"sandbox,omitempty"`
	// Managed reports the local UDS gRPC server (internal/ipc) that
	// serves the DefenseClaw ↔ AVC contract. Present only when the
	// server has been started (managed_enterprise or managed.enabled).
	Managed *SubsystemHealth `json:"managed,omitempty"`
	// Connector is the primary/active connector, retained for back-compat
	// with single-connector clients. Connectors lists every active
	// connector with its own live counters (multi-connector view).
	Connector  *ConnectorHealth  `json:"connector,omitempty"`
	Connectors []ConnectorHealth `json:"connectors,omitempty"`
}

type SidecarHealth struct {
	mu                                 sync.RWMutex
	gateway                            SubsystemHealth
	watcher                            SubsystemHealth
	config                             SubsystemHealth
	api                                SubsystemHealth
	guardrail                          SubsystemHealth
	telemetry                          SubsystemHealth
	aiDiscovery                        SubsystemHealth
	applicationProtection              SubsystemHealth
	sandbox                            *SubsystemHealth
	startedAt                          time.Time
	observabilityV8Source              observabilityV8HealthSource
	observabilityV8ActiveGeneration    uint64
	observabilityV8Failures            map[string]observabilityV8FailureObservation
	observabilityV8RetentionState      string
	observabilityV8RetentionFailure    string
	observabilityV8RetentionDays       int64
	observabilityV8EventHistoryFailure string
	managed                            *SubsystemHealth

	// subscribers receive a non-blocking notification after every Set*
	// call, so long-lived consumers (like the IPC GetHealth stream)
	// can react to state changes without polling Snapshot() on a
	// ticker. The channel buffer is size 1: writes are non-blocking
	// and coalesce naturally into a single wake-up when a subscriber
	// hasn't yet drained the previous notification.
	subMu sync.Mutex
	subs  []chan struct{}

	// Per-connector health + counters. In multi-connector mode every active
	// connector gets its own ConnectorHealth so live counters are truthful
	// per connector rather than a process-global tally stapled onto one
	// arbitrary "primary". The map structure is guarded by mu; per-entry
	// counters are atomic for a lock-free increment hot path. primaryConn
	// names the connector surfaced in the back-compat singular
	// HealthSnapshot.Connector field.
	connStats   map[string]*connectorStats
	primaryConn string
}

// connectorStats holds one connector's static health plus its atomic live
// counters. Pointers are stored in SidecarHealth.connStats so the atomics are
// stable across snapshot reads.
type connectorStats struct {
	name               string
	state              SubsystemState
	source             string
	since              time.Time
	toolInspectionMode connector.ToolInspectionMode
	subprocessPolicy   connector.SubprocessPolicy

	requests         atomic.Int64
	lastActivityAt   atomic.Int64
	errors           atomic.Int64
	toolInspections  atomic.Int64
	toolBlocks       atomic.Int64
	subprocessBlocks atomic.Int64
}

func (s *connectorStats) snapshot() ConnectorHealth {
	// Load Requests before LastActivityAt. RecordConnectorRequestFor stores the
	// timestamp first, so a snapshot that observes a new request can never pair
	// that count with a missing activity timestamp.
	requests := s.requests.Load()
	var lastActivityAt *time.Time
	if unixNanos := s.lastActivityAt.Load(); unixNanos > 0 {
		activityAt := time.Unix(0, unixNanos).UTC()
		lastActivityAt = &activityAt
	}
	return ConnectorHealth{
		Name:               s.name,
		State:              s.state,
		Source:             s.source,
		Since:              s.since,
		LastActivityAt:     lastActivityAt,
		ToolInspectionMode: s.toolInspectionMode,
		SubprocessPolicy:   s.subprocessPolicy,
		Requests:           requests,
		Errors:             s.errors.Load(),
		ToolInspections:    s.toolInspections.Load(),
		ToolBlocks:         s.toolBlocks.Load(),
		SubprocessBlocks:   s.subprocessBlocks.Load(),
	}
}

func (s *connectorStats) recordActivity(at time.Time) {
	candidate := at.UnixNano()
	for {
		current := s.lastActivityAt.Load()
		if candidate <= current {
			return
		}
		if s.lastActivityAt.CompareAndSwap(current, candidate) {
			return
		}
	}
}

// connName normalizes a connector name into a stable map key.
func connName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func NewSidecarHealth() *SidecarHealth {
	now := time.Now()
	initial := SubsystemHealth{State: StateStarting, Since: now}
	disabled := SubsystemHealth{State: StateDisabled, Since: now}
	return &SidecarHealth{
		gateway:               initial,
		watcher:               initial,
		config:                initial,
		api:                   initial,
		guardrail:             disabled,
		telemetry:             disabled,
		aiDiscovery:           disabled,
		applicationProtection: disabled,
		startedAt:             now,
	}
}

func (h *SidecarHealth) SetConfig(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	h.config = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
	h.mu.Unlock()
	h.notifySubscribers()
}

func (h *SidecarHealth) SetGateway(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	h.gateway = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
	h.mu.Unlock()
	h.notifySubscribers()
}

func (h *SidecarHealth) SetWatcher(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	h.watcher = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
	h.mu.Unlock()
	h.notifySubscribers()
}

func (h *SidecarHealth) SetAPI(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	h.api = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
	h.mu.Unlock()
	h.notifySubscribers()
}

func (h *SidecarHealth) SetGuardrail(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	h.guardrail = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
	h.mu.Unlock()
	h.notifySubscribers()
}

func (h *SidecarHealth) SetTelemetry(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	h.telemetry = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
	h.mu.Unlock()
	h.notifySubscribers()
}

func (h *SidecarHealth) bindObservabilityV8HealthSource(source observabilityV8HealthSource) {
	if h == nil || source == nil {
		return
	}
	h.mu.Lock()
	h.observabilityV8Source = source
	h.telemetry = SubsystemHealth{State: StateRunning, Since: time.Now()}
	if h.observabilityV8Failures == nil {
		h.observabilityV8Failures = make(map[string]observabilityV8FailureObservation)
	}
	h.mu.Unlock()
	h.notifySubscribers()
}

func (h *SidecarHealth) clearObservabilityV8HealthSource() {
	if h == nil {
		return
	}
	changed := false
	h.mu.Lock()
	if h.observabilityV8Source != nil {
		h.observabilityV8Source = nil
		h.observabilityV8ActiveGeneration = 0
		h.observabilityV8Failures = nil
		h.telemetry = SubsystemHealth{State: StateStopped, Since: time.Now()}
		changed = true
	}
	h.mu.Unlock()
	if changed {
		h.notifySubscribers()
	}
}

func (h *SidecarHealth) observeObservabilityV8Failure(
	destination string,
	generation uint64,
	code string,
	occurredAt time.Time,
) {
	if h == nil || generation == 0 || !observability.IsStableToken(destination) ||
		len(destination) > 64 || !validObservabilityV8FailureCode(code) || occurredAt.IsZero() {
		return
	}
	h.mu.Lock()
	if h.observabilityV8ActiveGeneration != 0 && generation < h.observabilityV8ActiveGeneration {
		h.mu.Unlock()
		return
	}
	if h.observabilityV8Failures == nil {
		h.observabilityV8Failures = make(map[string]observabilityV8FailureObservation)
	}
	if len(h.observabilityV8Failures) >= configObservabilityV8MaxHealthDestinations {
		if _, exists := h.observabilityV8Failures[destination]; !exists {
			h.mu.Unlock()
			return
		}
	}
	current := h.observabilityV8Failures[destination]
	if generation < current.generation ||
		(generation == current.generation && occurredAt.Before(current.occurredAt)) {
		h.mu.Unlock()
		return
	}
	h.observabilityV8Failures[destination] = observabilityV8FailureObservation{
		generation: generation, code: code, occurredAt: occurredAt.UTC(),
	}
	h.mu.Unlock()
	h.notifySubscribers()
}

func validObservabilityV8FailureCode(code string) bool {
	switch code {
	case string(delivery.HealthReasonQueueFull), string(delivery.HealthReasonRetryable),
		string(delivery.HealthReasonPartial), string(delivery.HealthReasonDeliveryFailed),
		string(delivery.HealthReasonOriginLoop),
		"generation_mismatch", "pipeline_failed", "projection_failed",
		"route_identity_mismatch", "unsupported_shape", "payload_failed",
		"queue_rejected", "panic_isolated", "compatibility_projection_failed":
		return true
	default:
		return false
	}
}

func (h *SidecarHealth) setObservabilityV8Retention(state string, days int64, failure string) {
	if h == nil || days < 0 || !validObservabilityV8RetentionState(state) ||
		!validObservabilityV8RetentionFailure(failure) {
		return
	}
	h.mu.Lock()
	h.observabilityV8RetentionState = state
	h.observabilityV8RetentionDays = days
	h.observabilityV8RetentionFailure = failure
	h.mu.Unlock()
	h.notifySubscribers()
}

func validObservabilityV8RetentionFailure(failure string) bool {
	switch failure {
	case "", "run_failed", "scheduler_failed":
		return true
	default:
		return false
	}
}

func (h *SidecarHealth) setObservabilityV8EventHistoryFailure(code string) {
	if h == nil || !validObservabilityV8EventHistoryFailure(code) {
		return
	}
	h.mu.Lock()
	h.observabilityV8EventHistoryFailure = code
	h.mu.Unlock()
	h.notifySubscribers()
}

func validObservabilityV8EventHistoryFailure(code string) bool {
	switch code {
	case "projection_rejected", "integrity_unsigned", "integrity_signing_failed", "sqlite_write_failed":
		return true
	default:
		return false
	}
}

func validObservabilityV8RetentionState(state string) bool {
	switch state {
	case "waiting_for_readiness", "healthy", "degraded", "disabled", "stopped":
		return true
	default:
		return false
	}
}

const configObservabilityV8MaxHealthDestinations = 65

func (h *SidecarHealth) SetAIDiscovery(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	h.aiDiscovery = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
	h.mu.Unlock()
	h.notifySubscribers()
}

func (h *SidecarHealth) SetApplicationProtection(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	h.applicationProtection = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
	h.mu.Unlock()
	h.notifySubscribers()
}

func (h *SidecarHealth) SetSandbox(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	h.sandbox = &SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
	h.mu.Unlock()
	h.notifySubscribers()
}

// SetManaged records the current state of the local UDS gRPC server
// (internal/ipc) that serves the DefenseClaw ↔ AVC contract. Called
// from the IPC package as it moves through Starting → Running → Stopped
// / Error.
func (h *SidecarHealth) SetManaged(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	h.managed = &SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
	h.mu.Unlock()
	h.notifySubscribers()
}

// Subscribe returns a channel that receives a non-blocking notification
// (a single struct{} value, buffered depth 1) after every Set* call.
// Consumers coalesce multiple rapid changes naturally: the channel
// stays at depth 1, so a subscriber that hasn't drained the previous
// wake-up simply sees one more pending event when they next read.
//
// The returned cancel closes and unregisters the channel; call it
// exactly once when the subscriber exits so the internal slice does
// not grow with dead entries.
func (h *SidecarHealth) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	h.subMu.Lock()
	h.subs = append(h.subs, ch)
	h.subMu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			// Hold subMu across both the slice mutation and the
			// close so a concurrent notifySubscribers cannot pick
			// up this channel from a stale snapshot and send on
			// it after close. Allocating a fresh backing array
			// also prevents a reader that already copied the
			// slice header from seeing the removed entry mutated
			// underneath them.
			h.subMu.Lock()
			next := make([]chan struct{}, 0, len(h.subs))
			for _, existing := range h.subs {
				if existing != ch {
					next = append(next, existing)
				}
			}
			h.subs = next
			close(ch)
			h.subMu.Unlock()
		})
	}
	return ch, cancel
}

// notifySubscribers fans out a non-blocking wake-up to every current
// subscriber. Never blocks: a full 1-element buffer means the
// subscriber already has a pending notification, so we drop the
// extra. Held under subMu so a concurrent cancel cannot close a
// channel between our decision to send and the send itself.
func (h *SidecarHealth) notifySubscribers() {
	h.subMu.Lock()
	defer h.subMu.Unlock()
	for _, ch := range h.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// SetConnector registers (or updates) a connector's health entry and marks it
// as the primary connector surfaced in the singular HealthSnapshot.Connector
// field. Counters for an already-registered connector are preserved across
// re-registration (e.g. a connector hot-swap) so live totals are not reset.
func (h *SidecarHealth) SetConnector(name string, mode connector.ToolInspectionMode, policy connector.SubprocessPolicy) {
	h.registerConnector(name, mode, policy, "manual", true)
}

// RegisterConnector registers (or updates) a connector's health entry WITHOUT
// changing which connector is primary. The multi-connector boot loop calls
// this for every active connector so each appears with its own live counters.
func (h *SidecarHealth) RegisterConnector(name string, mode connector.ToolInspectionMode, policy connector.SubprocessPolicy) {
	h.registerConnector(name, mode, policy, "manual", false)
}

func (h *SidecarHealth) RegisterConnectorWithSource(name string, mode connector.ToolInspectionMode, policy connector.SubprocessPolicy, source string) {
	h.registerConnector(name, mode, policy, source, false)
}

func (h *SidecarHealth) registerConnector(name string, mode connector.ToolInspectionMode, policy connector.SubprocessPolicy, source string, primary bool) {
	key := connName(name)
	if key == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.connStats == nil {
		h.connStats = make(map[string]*connectorStats)
	}
	s := h.connStats[key]
	if s == nil {
		s = &connectorStats{name: key, since: time.Now()}
		h.connStats[key] = s
	}
	s.state = StateRunning
	if strings.TrimSpace(source) == "" {
		source = "manual"
	}
	s.source = strings.ToLower(strings.TrimSpace(source))
	s.toolInspectionMode = mode
	s.subprocessPolicy = policy
	if primary {
		h.primaryConn = key
	}
}

func (h *SidecarHealth) HasConnector(name string) bool {
	key := connName(name)
	if key == "" {
		return false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	s := h.connStats[key]
	return s != nil && s.state == StateRunning
}

func (h *SidecarHealth) HasConnectorSource(name, source string) bool {
	key := connName(name)
	wantSource := strings.ToLower(strings.TrimSpace(source))
	if key == "" || wantSource == "" {
		return false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	s := h.connStats[key]
	return s != nil && s.state == StateRunning && strings.EqualFold(strings.TrimSpace(s.source), wantSource)
}

// statsFor returns the counter bucket for a connector, lazily creating it so
// counts are never lost if a hook fires before the connector is registered.
// An empty name routes to the primary connector (back-compat).
func (h *SidecarHealth) statsFor(name string) *connectorStats {
	key := connName(name)
	h.mu.RLock()
	if key == "" {
		key = h.primaryConn
	}
	s := h.connStats[key]
	h.mu.RUnlock()
	if s != nil {
		return s
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if key == "" {
		key = h.primaryConn
	}
	if key == "" {
		key = "unknown"
	}
	if h.connStats == nil {
		h.connStats = make(map[string]*connectorStats)
	}
	if s = h.connStats[key]; s == nil {
		s = &connectorStats{name: key, state: StateRunning, since: time.Now()}
		h.connStats[key] = s
	}
	return s
}

// RecordConnectorRequestFor records one accepted hook event for a connector.
// The timestamp is stored before the count so a concurrent health snapshot
// never exposes a new request without its matching activity time.
func (h *SidecarHealth) RecordConnectorRequestFor(name string) {
	stats := h.statsFor(name)
	stats.recordActivity(time.Now())
	stats.requests.Add(1)
}

// RecordConnectorErrorFor increments the error counter for a connector.
func (h *SidecarHealth) RecordConnectorErrorFor(name string) { h.statsFor(name).errors.Add(1) }

// RecordToolInspectionFor increments the tool-inspection counter for a connector.
func (h *SidecarHealth) RecordToolInspectionFor(name string) { h.statsFor(name).toolInspections.Add(1) }

// RecordToolBlockFor increments the tool-block counter for a connector.
func (h *SidecarHealth) RecordToolBlockFor(name string) { h.statsFor(name).toolBlocks.Add(1) }

// RecordSubprocessBlockFor increments the subprocess-block counter for a connector.
func (h *SidecarHealth) RecordSubprocessBlockFor(name string) {
	h.statsFor(name).subprocessBlocks.Add(1)
}

// Back-compat no-arg variants route to the primary connector. Prefer the
// *For(name) variants from hook handlers so counters stay per-connector.
func (h *SidecarHealth) RecordConnectorRequest() { h.RecordConnectorRequestFor("") }
func (h *SidecarHealth) RecordConnectorError()   { h.RecordConnectorErrorFor("") }
func (h *SidecarHealth) RecordToolInspection()   { h.RecordToolInspectionFor("") }
func (h *SidecarHealth) RecordToolBlock()        { h.RecordToolBlockFor("") }
func (h *SidecarHealth) RecordSubprocessBlock()  { h.RecordSubprocessBlockFor("") }

func (h *SidecarHealth) Snapshot() HealthSnapshot {
	h.mu.RLock()
	snap := HealthSnapshot{
		StartedAt:             h.startedAt,
		UptimeMs:              time.Since(h.startedAt).Milliseconds(),
		Gateway:               h.gateway,
		Watcher:               h.watcher,
		Config:                h.config,
		API:                   h.api,
		Guardrail:             h.guardrail,
		Telemetry:             h.telemetry,
		AIDiscovery:           h.aiDiscovery,
		ApplicationProtection: h.applicationProtection,
		Sandbox:               h.sandbox,
		Managed:               h.managed,
	}
	source := h.observabilityV8Source
	failures := make(map[string]observabilityV8FailureObservation, len(h.observabilityV8Failures))
	for name, failure := range h.observabilityV8Failures {
		failures[name] = failure
	}
	retentionState := h.observabilityV8RetentionState
	retentionFailure := h.observabilityV8RetentionFailure
	retentionDays := h.observabilityV8RetentionDays
	eventHistoryFailure := h.observabilityV8EventHistoryFailure

	if len(h.connStats) > 0 {
		names := make([]string, 0, len(h.connStats))
		for name := range h.connStats {
			names = append(names, name)
		}
		sort.Strings(names)

		conns := make([]ConnectorHealth, 0, len(names))
		for _, name := range names {
			conns = append(conns, h.connStats[name].snapshot())
		}
		snap.Connectors = conns

		// Back-compat singular: the primary connector (or the first
		// registered when no primary was explicitly marked).
		primary := h.primaryConn
		if primary == "" {
			primary = names[0]
		}
		if s := h.connStats[primary]; s != nil {
			ch := s.snapshot()
			snap.Connector = &ch
		}
	}
	h.mu.RUnlock()

	if source != nil {
		ctx, cancel := context.WithTimeout(context.Background(), observabilityV8HealthSnapshotTimeout)
		live, ok := readObservabilityV8HealthSnapshot(ctx, source)
		cancel()
		if ok {
			failures = h.reconcileObservabilityV8Failures(live)
			snap.Telemetry = renderObservabilityV8Health(
				snap.Telemetry.Since, live, failures,
				retentionState, retentionFailure, retentionDays, eventHistoryFailure,
			)
		}
	}

	return snap
}

func (h *SidecarHealth) reconcileObservabilityV8Failures(
	snapshot observabilityruntime.DestinationHealthSnapshot,
) map[string]observabilityV8FailureObservation {
	active := make(map[string]struct{}, len(snapshot.Destinations))
	for _, destination := range snapshot.Destinations {
		active[destination.Name] = struct{}{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.observabilityV8ActiveGeneration = snapshot.Generation
	result := make(map[string]observabilityV8FailureObservation, len(h.observabilityV8Failures))
	for name, failure := range h.observabilityV8Failures {
		_, exists := active[name]
		if !exists || failure.generation != snapshot.Generation {
			delete(h.observabilityV8Failures, name)
			continue
		}
		result[name] = failure
	}
	return result
}

func readObservabilityV8HealthSnapshot(
	ctx context.Context,
	source observabilityV8HealthSource,
) (snapshot observabilityruntime.DestinationHealthSnapshot, ok bool) {
	if ctx == nil || source == nil {
		return observabilityruntime.DestinationHealthSnapshot{}, false
	}
	defer func() {
		if recover() != nil {
			snapshot = observabilityruntime.DestinationHealthSnapshot{}
			ok = false
		}
	}()
	snapshot, err := source.DestinationHealthSnapshot(ctx)
	return snapshot, err == nil
}

func renderObservabilityV8Health(
	since time.Time,
	snapshot observabilityruntime.DestinationHealthSnapshot,
	failures map[string]observabilityV8FailureObservation,
	retentionState string,
	retentionFailure string,
	retentionDays int64,
	eventHistoryFailure string,
) SubsystemHealth {
	details := make(map[string]interface{}, 6)
	details["generation"] = snapshot.Generation
	destinations := make([]map[string]interface{}, 0, len(snapshot.Destinations))
	aggregate := StateRunning
	for _, destination := range snapshot.Destinations {
		row := map[string]interface{}{
			"name": destination.Name, "kind": string(destination.Kind),
			"enabled": destination.Enabled, "generation": snapshot.Generation,
		}
		signals := make([]string, len(destination.Signals))
		for index, signal := range destination.Signals {
			signals[index] = string(signal)
		}
		row["signals"] = signals
		if destination.State != "" {
			row["state"] = string(destination.State)
		}
		if destination.Reason != "" {
			row["reason"] = destination.Reason
		}
		if destination.Queue != nil {
			row["queue"] = renderObservabilityV8Queue(*destination.Queue, destination.Counters)
		}
		row["counters"] = renderObservabilityV8Counters(destination.Counters)
		queueRows := make([]map[string]interface{}, 0, len(destination.Sources))
		signalRows := make([]map[string]interface{}, 0, len(destination.Sources))
		for _, source := range destination.Sources {
			signalRow := map[string]interface{}{
				"signal": source.Signal, "state": string(source.State),
				"counters": renderObservabilityV8Counters(source.Counters),
			}
			if source.Reason != "" {
				signalRow["reason"] = source.Reason
			}
			if !source.LastSuccess.IsZero() {
				signalRow["last_success_at"] = source.LastSuccess.UTC().Format(time.RFC3339Nano)
			}
			if !source.LastFailure.IsZero() {
				signalRow["last_failure_at"] = source.LastFailure.UTC().Format(time.RFC3339Nano)
			}
			if source.Queue != nil {
				queue := renderObservabilityV8Queue(*source.Queue, source.Counters)
				signalRow["queue"] = queue
				queueRow := renderObservabilityV8Queue(*source.Queue, source.Counters)
				queueRow["signal"] = source.Signal
				queueRow["state"] = string(source.State)
				if source.Reason != "" {
					queueRow["reason"] = source.Reason
				}
				if !source.LastSuccess.IsZero() {
					queueRow["last_success_at"] = source.LastSuccess.UTC().Format(time.RFC3339Nano)
				}
				if !source.LastFailure.IsZero() {
					queueRow["last_failure_at"] = source.LastFailure.UTC().Format(time.RFC3339Nano)
				}
				queueRows = append(queueRows, queueRow)
			}
			signalRows = append(signalRows, signalRow)
		}
		if len(signalRows) > 0 {
			row["signal_health"] = signalRows
		}
		if len(queueRows) > 0 {
			row["queues"] = queueRows
		}
		lastFailure := destination.LastFailure
		if observed, ok := failures[destination.Name]; ok &&
			observed.generation == snapshot.Generation &&
			!destination.LastSuccess.After(observed.occurredAt) {
			row["failure"] = observed.code
			if observed.occurredAt.After(lastFailure) {
				lastFailure = observed.occurredAt
			}
			aggregate = StateError
		}
		if !destination.LastSuccess.IsZero() {
			row["last_success_at"] = destination.LastSuccess.UTC().Format(time.RFC3339Nano)
		}
		if !lastFailure.IsZero() {
			row["last_failure_at"] = lastFailure.UTC().Format(time.RFC3339Nano)
		}
		if destination.Enabled && (destination.State == delivery.HealthDegraded ||
			destination.State == delivery.HealthFailing || destination.State == delivery.HealthStopped) {
			aggregate = StateError
		}
		destinations = append(destinations, row)
	}
	details["destination_count"] = len(destinations)
	details["destinations"] = destinations
	if validObservabilityV8RetentionState(retentionState) {
		details["retention_state"] = retentionState
		details["retention_days"] = retentionDays
		if retentionFailure != "" {
			details["retention_failure"] = retentionFailure
		}
		if retentionState == "degraded" {
			aggregate = StateError
		}
	}
	if eventHistoryFailure != "" {
		details["event_history_failure"] = eventHistoryFailure
		aggregate = StateError
	}
	return SubsystemHealth{State: aggregate, Since: since, Details: details}
}

func renderObservabilityV8Queue(
	queue delivery.QueueSnapshot,
	counters delivery.Counters,
) map[string]interface{} {
	return map[string]interface{}{
		"items": queue.Items, "bytes": queue.Bytes,
		"in_flight_items": queue.InFlightItems, "in_flight_bytes": queue.InFlightBytes,
		"max_items": queue.MaxItems, "max_bytes": queue.MaxBytes,
		"dropped":  counters.Dropped,
		"counters": renderObservabilityV8Counters(counters),
	}
}

func renderObservabilityV8Counters(counters delivery.Counters) map[string]interface{} {
	return map[string]interface{}{
		"accepted": counters.Accepted, "delivered": counters.Delivered,
		"retried": counters.Retried, "dropped": counters.Dropped,
		"rejected": counters.Rejected,
	}
}
