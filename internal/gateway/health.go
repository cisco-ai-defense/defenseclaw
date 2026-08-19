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

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

const (
	observabilityV8HealthSnapshotTimeout = 100 * time.Millisecond
	// ObservabilityV8HealthSnapshotUnavailable is the stable, non-sensitive
	// sentinel emitted when a bounded telemetry snapshot cannot be read.
	// Startup readiness may retry this exact condition; other consumers still
	// receive the fail-closed StateError health record.
	ObservabilityV8HealthSnapshotUnavailable = "observability_v8_health_unavailable"
)

type observabilityV8HealthSource interface {
	DestinationHealthSnapshot(context.Context) (observabilityruntime.DestinationHealthSnapshot, error)
}

type observabilityV8FailureObservation struct {
	generation uint64
	code       string
	occurredAt time.Time
}

type observabilityV8EventHistoryObservation struct {
	generation         uint64
	sequence           uint64
	active             bool
	lastFailureClass   string
	lastFailurePrimary uint8
}

type observabilityV8EventHistorySnapshot struct {
	activeCode         string
	lastFailureClass   string
	lastFailurePrimary uint8
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

// ConfigurationState is the overall daemon+guardian readiness state
// spec 003 (docs/specs/003-windows-deferred-config/) exposes on the
// health snapshot. This is distinct from the per-subsystem
// SubsystemState above: SubsystemState reports each component's own
// health, ConfigurationState reports the CROSS-subsystem "is the
// managed-enterprise Windows deployment ready to accept traffic yet"
// question that Cisco Secure Client (Workstream C) and downstream
// dashboards read.
type ConfigurationState string

const (
	// ConfigStateWaitingForConfig — the gateway daemon has not yet
	// loaded a valid config.yaml. This is the initial state on a
	// deferred-config install (`defenseclaw enterprise windows
	// install --deferred-config`) before UCB drops the config file.
	ConfigStateWaitingForConfig ConfigurationState = "waiting_for_config"
	// ConfigStateWaitingForTargets — the daemon has loaded config,
	// but the hook-guardian has not yet loaded targets.yaml.
	ConfigStateWaitingForTargets ConfigurationState = "waiting_for_targets"
	// ConfigStateReady — both daemon config and guardian targets are
	// loaded, hook enforcement is engaged.
	ConfigStateReady ConfigurationState = "ready"
)

// ConfigurationHealth is the value published under
// HealthSnapshot.Configuration. Since tracks the moment the current
// State value was entered — a bounded-wait indicator downstream
// consumers can page on without needing to inspect service uptime.
// See spec 003 REQ-19, REQ-20, REQ-21.
type ConfigurationHealth struct {
	State ConfigurationState `json:"state"`
	Since time.Time          `json:"since"`
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
	// Configuration is the overall daemon+guardian readiness state,
	// distinct from the per-subsystem Config/Gateway fields above.
	// Populated only in managed_enterprise deployments (spec 003);
	// omitted from the payload for OSS / SaaS / DP / CP hosts so
	// downstream consumers don't have to reason about the field for
	// deployments where it never has meaning.
	Configuration *ConfigurationHealth `json:"configuration,omitempty"`
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
	mu                                    sync.RWMutex
	gateway                               SubsystemHealth
	watcher                               SubsystemHealth
	config                                SubsystemHealth
	api                                   SubsystemHealth
	guardrail                             SubsystemHealth
	telemetry                             SubsystemHealth
	aiDiscovery                           SubsystemHealth
	applicationProtection                 SubsystemHealth
	sandbox                               *SubsystemHealth
	startedAt                             time.Time
	observabilityV8Source                 observabilityV8HealthSource
	observabilityV8ActiveGeneration       uint64
	observabilityV8Failures               map[string]observabilityV8FailureObservation
	observabilityV8RetentionState         string
	observabilityV8RetentionFailure       string
	observabilityV8RetentionDays          int64
	observabilityV8EventHistoryGeneration uint64
	observabilityV8EventHistory           map[string]observabilityV8EventHistoryObservation
	managed                               *SubsystemHealth

	// configuration is the collapsed daemon+guardian state (spec 003).
	// Nil until SetDaemonConfigLoaded is called at least once — a
	// nil pointer omits the top-level "configuration" block from the
	// snapshot, which is the correct behaviour for every deployment
	// mode other than managed_enterprise. The pointer becomes
	// non-nil after the first call and stays non-nil for the life of
	// the process (a managed_enterprise daemon never "un-enters"
	// deferred-config mode).
	configuration *ConfigurationHealth
	// daemonConfigLoaded is the daemon-side half of the collapsing
	// rule (spec 003 § Data flow). SetDaemonConfigLoaded flips this
	// true when v8 config parses; it never goes false again.
	daemonConfigLoaded bool
	// guardianStateReader is best-effort probe wired by the daemon
	// after it knows the state root path. Returns one of
	// guardianstate.State{WaitingForTargets,Ready,Unknown}. Nil until
	// wired; nil ⇒ collapsing rule falls to the safe default
	// (waiting_for_targets when daemon is loaded).
	guardianStateReader func() string

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

// SetDaemonConfigLoaded is the daemon-side half of the spec 003
// deferred-config collapsing rule. Call once with `false` right after
// the sidecar is constructed if the daemon is entering a
// waiting-for-config loop, then again with `true` once v8 config
// parses. Idempotent: repeated calls with the same value are no-ops,
// so a wait loop that "wakes on every fsnotify event" doesn't spam
// state transitions.
//
// The first call transitions the internal `configuration` field from
// nil to a pointer, which is what makes the top-level "configuration"
// block appear in the health snapshot JSON. Deployments that never
// call this method (OSS / SaaS / DP / CP) keep the nil pointer and
// the snapshot omits the block entirely.
func (h *SidecarHealth) SetDaemonConfigLoaded(loaded bool) {
	h.mu.Lock()
	if h.configuration == nil {
		h.configuration = &ConfigurationHealth{
			State: ConfigStateWaitingForConfig,
			Since: time.Now(),
		}
	}
	if h.daemonConfigLoaded == loaded && h.configuration.State != ConfigStateWaitingForConfig {
		// No-op: already in the right state.
		h.mu.Unlock()
		return
	}
	h.daemonConfigLoaded = loaded
	h.recomputeConfigurationLocked()
	h.mu.Unlock()
	h.notifySubscribers()
}

// SetGuardianStateReader wires the sidecar's cross-process probe for
// the hook-guardian's state file. The callback returns one of
// guardianstate.State{WaitingForTargets, Ready, Unknown}; the sidecar
// applies the safe-default collapsing rule when the probe returns
// StateUnknown (missing file, unreadable, malformed) so a
// guardian-side crash never falsely publishes "ready".
//
// Nil clears the reader (used by tests). Passing a reader triggers an
// immediate recompute so the snapshot picks up whatever the current
// guardian state file says without waiting for the next
// RefreshConfiguration tick.
func (h *SidecarHealth) SetGuardianStateReader(fn func() string) {
	h.mu.Lock()
	h.guardianStateReader = fn
	if h.configuration != nil {
		h.recomputeConfigurationLocked()
	}
	h.mu.Unlock()
	h.notifySubscribers()
}

// RefreshConfiguration re-reads the guardian state (via the wired
// reader, if any) and re-applies the collapsing rule. Meant to be
// called on a periodic ticker by the daemon so a guardian-side
// transition (waiting_for_targets → ready) is observed even when
// nothing on the daemon side has changed. If no reader is wired the
// call is a no-op.
func (h *SidecarHealth) RefreshConfiguration() {
	h.mu.Lock()
	if h.configuration == nil {
		// Deployment never entered managed-enterprise deferred-config
		// mode; nothing to refresh.
		h.mu.Unlock()
		return
	}
	prev := h.configuration.State
	h.recomputeConfigurationLocked()
	changed := h.configuration.State != prev
	h.mu.Unlock()
	if changed {
		h.notifySubscribers()
	}
}

// recomputeConfigurationLocked applies the collapsing rule; caller
// holds h.mu (write lock).
//
// Order (spec 003 § Data flow):
//   1. Daemon not loaded ⇒ waiting_for_config, regardless of guardian.
//      This lets AC-12 pass: if UCB drops targets.yaml first, the
//      daemon still says waiting_for_config until config.yaml lands.
//   2. Daemon loaded, no guardian reader wired ⇒ waiting_for_targets
//      as the safe default. Never false-positive ready.
//   3. Daemon loaded, guardian reader returns ready ⇒ ready.
//   4. Daemon loaded, guardian reader returns waiting_for_targets or
//      Unknown ⇒ waiting_for_targets.
//
// Since only advances when the collapsed state actually changes,
// so a snapshot taken 30 s into a wait returns the SAME Since as
// one taken at the wait's start (spec 003 AC-08).
func (h *SidecarHealth) recomputeConfigurationLocked() {
	if h.configuration == nil {
		return
	}
	var next ConfigurationState
	if !h.daemonConfigLoaded {
		next = ConfigStateWaitingForConfig
	} else if h.guardianStateReader == nil {
		next = ConfigStateWaitingForTargets
	} else {
		switch h.guardianStateReader() {
		case "ready":
			next = ConfigStateReady
		case "waiting_for_targets":
			next = ConfigStateWaitingForTargets
		default:
			// Unknown ⇒ safe default. Guardian may be starting up,
			// crashed mid-boot, or file may be transiently unreadable
			// during a rename; report waiting_for_targets rather than
			// stale ready.
			next = ConfigStateWaitingForTargets
		}
	}
	if h.configuration.State == next {
		return
	}
	h.configuration = &ConfigurationHealth{
		State: next,
		Since: time.Now(),
	}
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
		h.observabilityV8EventHistoryGeneration = 0
		h.observabilityV8EventHistory = nil
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

func (h *SidecarHealth) observeObservabilityV8EventHistory(
	transition audit.EventHistoryHealthTransition,
) {
	if h == nil || !validObservabilityV8EventHistoryTransition(transition) {
		return
	}
	h.mu.Lock()
	if transition.Generation < h.observabilityV8EventHistoryGeneration {
		h.mu.Unlock()
		return
	}
	if transition.Generation > h.observabilityV8EventHistoryGeneration {
		h.observabilityV8EventHistoryGeneration = transition.Generation
	}
	if h.observabilityV8EventHistory == nil {
		h.observabilityV8EventHistory = make(map[string]observabilityV8EventHistoryObservation, 4)
	}
	code := string(transition.Code)
	current := h.observabilityV8EventHistory[code]
	if transition.Generation < current.generation ||
		transition.Generation == current.generation && transition.Sequence <= current.sequence {
		h.mu.Unlock()
		return
	}
	observation := observabilityV8EventHistoryObservation{
		generation: transition.Generation, sequence: transition.Sequence,
		active:           transition.State == audit.EventHistoryHealthFailed,
		lastFailureClass: current.lastFailureClass, lastFailurePrimary: current.lastFailurePrimary,
	}
	if observation.active && transition.Code == audit.EventHistoryHealthWriteFailed {
		observation.lastFailureClass = string(transition.SQLiteClass)
		observation.lastFailurePrimary = transition.SQLitePrimaryCode
	}
	h.observabilityV8EventHistory[code] = observation
	h.mu.Unlock()
	h.notifySubscribers()
}

func (h *SidecarHealth) bindObservabilityV8EventHistoryGeneration(generation uint64) {
	if h == nil || generation == 0 {
		return
	}
	changed := false
	h.mu.Lock()
	if generation > h.observabilityV8EventHistoryGeneration {
		h.observabilityV8EventHistoryGeneration = generation
		changed = true
	}
	h.mu.Unlock()
	if changed {
		h.notifySubscribers()
	}
}

func snapshotObservabilityV8EventHistory(
	generation uint64,
	observations map[string]observabilityV8EventHistoryObservation,
) observabilityV8EventHistorySnapshot {
	result := observabilityV8EventHistorySnapshot{}
	var activeGeneration uint64
	var activeSequence uint64
	write := observations[string(audit.EventHistoryHealthWriteFailed)]
	if write.generation != 0 && write.generation <= generation {
		result.lastFailureClass = write.lastFailureClass
		result.lastFailurePrimary = write.lastFailurePrimary
	}
	for code, observation := range observations {
		if observation.generation == 0 || observation.generation > generation || !observation.active ||
			observation.generation < activeGeneration ||
			observation.generation == activeGeneration && observation.sequence < activeSequence {
			continue
		}
		activeGeneration = observation.generation
		activeSequence = observation.sequence
		result.activeCode = code
	}
	return result
}

func validObservabilityV8EventHistoryTransition(transition audit.EventHistoryHealthTransition) bool {
	return audit.ValidEventHistoryHealthTransition(transition)
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
	// Deep-copy the configuration pointer under the read lock so a
	// caller mutating the returned snapshot cannot race with a Set*
	// on the sidecar. Non-managed-enterprise deployments leave
	// h.configuration nil and this field stays omitted from the
	// snapshot JSON per its omitempty tag.
	if h.configuration != nil {
		cfg := *h.configuration
		snap.Configuration = &cfg
	}
	source := h.observabilityV8Source
	failures := make(map[string]observabilityV8FailureObservation, len(h.observabilityV8Failures))
	for name, failure := range h.observabilityV8Failures {
		failures[name] = failure
	}
	retentionState := h.observabilityV8RetentionState
	retentionFailure := h.observabilityV8RetentionFailure
	retentionDays := h.observabilityV8RetentionDays
	eventHistoryGeneration := h.observabilityV8EventHistoryGeneration
	eventHistoryObservations := make(
		map[string]observabilityV8EventHistoryObservation,
		len(h.observabilityV8EventHistory),
	)
	for code, observation := range h.observabilityV8EventHistory {
		eventHistoryObservations[code] = observation
	}

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
			eventHistory := h.reconcileObservabilityV8EventHistory(live.Generation)
			snap.Telemetry = renderObservabilityV8Health(
				snap.Telemetry.Since, live, failures,
				retentionState, retentionFailure, retentionDays, eventHistory,
			)
		} else {
			eventHistory := snapshotObservabilityV8EventHistory(
				eventHistoryGeneration, eventHistoryObservations,
			)
			snap.Telemetry = renderObservabilityV8HealthUnavailable(
				snap.Telemetry.Since,
				retentionState, retentionFailure, retentionDays, eventHistory,
			)
		}
	}

	return snap
}

func (h *SidecarHealth) reconcileObservabilityV8EventHistory(
	generation uint64,
) observabilityV8EventHistorySnapshot {
	h.bindObservabilityV8EventHistoryGeneration(generation)
	h.mu.RLock()
	defer h.mu.RUnlock()
	return snapshotObservabilityV8EventHistory(
		h.observabilityV8EventHistoryGeneration, h.observabilityV8EventHistory,
	)
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

func renderObservabilityV8HealthUnavailable(
	since time.Time,
	retentionState string,
	retentionFailure string,
	retentionDays int64,
	eventHistory observabilityV8EventHistorySnapshot,
) SubsystemHealth {
	// The source error and recovered panic value may contain destination
	// endpoints, credentials, or payload fragments. Expose only one stable
	// code plus the bounded failure fields accepted by the health setters.
	details := map[string]interface{}{"snapshot_state": "unavailable"}
	if validObservabilityV8RetentionState(retentionState) {
		details["retention_state"] = retentionState
		details["retention_days"] = retentionDays
		if retentionFailure != "" && validObservabilityV8RetentionFailure(retentionFailure) {
			details["retention_failure"] = retentionFailure
		}
	}
	appendObservabilityV8EventHistoryDetails(details, eventHistory)
	return SubsystemHealth{
		State:     StateError,
		Since:     since,
		LastError: ObservabilityV8HealthSnapshotUnavailable,
		Details:   details,
	}
}

func renderObservabilityV8Health(
	since time.Time,
	snapshot observabilityruntime.DestinationHealthSnapshot,
	failures map[string]observabilityV8FailureObservation,
	retentionState string,
	retentionFailure string,
	retentionDays int64,
	eventHistory observabilityV8EventHistorySnapshot,
) SubsystemHealth {
	details := make(map[string]interface{}, 6)
	details["generation"] = snapshot.Generation
	destinations := make([]map[string]interface{}, 0, len(snapshot.Destinations))
	aggregate := StateRunning
	for _, destination := range snapshot.Destinations {
		row := map[string]interface{}{
			"name": destination.Name, "kind": string(destination.Kind),
			"enabled": destination.Enabled, "generation": snapshot.Generation,
			"circuit_state":        string(destination.CircuitState),
			"consecutive_failures": destination.ConsecutiveFailures,
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
		if !destination.CircuitOpenUntil.IsZero() {
			row["circuit_open_until"] = destination.CircuitOpenUntil.UTC().Format(time.RFC3339Nano)
		}
		if destination.LastFailureClass != "" {
			row["last_failure_class"] = string(destination.LastFailureClass)
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
				"counters":             renderObservabilityV8Counters(source.Counters),
				"circuit_state":        string(source.CircuitState),
				"consecutive_failures": source.ConsecutiveFailures,
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
			if !source.CircuitOpenUntil.IsZero() {
				signalRow["circuit_open_until"] = source.CircuitOpenUntil.UTC().Format(time.RFC3339Nano)
			}
			if source.LastFailureClass != "" {
				signalRow["last_failure_class"] = string(source.LastFailureClass)
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
				queueRow["circuit_state"] = string(source.CircuitState)
				queueRow["consecutive_failures"] = source.ConsecutiveFailures
				if !source.CircuitOpenUntil.IsZero() {
					queueRow["circuit_open_until"] = source.CircuitOpenUntil.UTC().Format(time.RFC3339Nano)
				}
				if source.LastFailureClass != "" {
					queueRow["last_failure_class"] = string(source.LastFailureClass)
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
		if retentionFailure != "" && validObservabilityV8RetentionFailure(retentionFailure) {
			details["retention_failure"] = retentionFailure
		}
		if retentionState == "degraded" {
			aggregate = StateError
		}
	}
	if eventHistory.activeCode != "" {
		aggregate = StateError
	}
	appendObservabilityV8EventHistoryDetails(details, eventHistory)
	return SubsystemHealth{State: aggregate, Since: since, Details: details}
}

func appendObservabilityV8EventHistoryDetails(
	details map[string]interface{},
	eventHistory observabilityV8EventHistorySnapshot,
) {
	if eventHistory.activeCode != "" && validObservabilityV8EventHistoryFailure(eventHistory.activeCode) {
		details["event_history_failure"] = eventHistory.activeCode
	}
	if eventHistory.lastFailureClass != "" {
		details["event_history_last_sqlite_class"] = eventHistory.lastFailureClass
		if eventHistory.lastFailurePrimary != 0 {
			details["event_history_last_sqlite_primary_code"] = eventHistory.lastFailurePrimary
		}
	}
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
