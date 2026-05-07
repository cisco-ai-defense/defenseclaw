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
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

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

// ConnectorHealth reports the active connector's identity, mode, and counters.
type ConnectorHealth struct {
	Name               string                       `json:"name"`
	State              SubsystemState               `json:"state"`
	Since              time.Time                    `json:"since"`
	ToolInspectionMode connector.ToolInspectionMode `json:"tool_inspection_mode"`
	SubprocessPolicy   connector.SubprocessPolicy   `json:"subprocess_policy"`
	Requests           int64                        `json:"requests"`
	Errors             int64                        `json:"errors"`
	ToolInspections    int64                        `json:"tool_inspections"`
	ToolBlocks         int64                        `json:"tool_blocks"`
	SubprocessBlocks   int64                        `json:"subprocess_blocks"`
}

type HealthSnapshot struct {
	StartedAt time.Time       `json:"started_at"`
	UptimeMs  int64           `json:"uptime_ms"`
	Gateway   SubsystemHealth `json:"gateway"`
	Watcher   SubsystemHealth `json:"watcher"`
	API       SubsystemHealth `json:"api"`
	Guardrail SubsystemHealth `json:"guardrail"`
	Telemetry SubsystemHealth `json:"telemetry"`
	// Sinks reports the aggregate health of all configured audit sinks
	// (splunk_hec, otlp_logs, http_jsonl, …). Details["sinks"] holds
	// per-sink state for the TUI/CLI to render individual rows.
	Sinks     SubsystemHealth  `json:"sinks"`
	Sandbox   *SubsystemHealth `json:"sandbox,omitempty"`
	Connector *ConnectorHealth `json:"connector,omitempty"`
}

type SidecarHealth struct {
	mu        sync.RWMutex
	gateway   SubsystemHealth
	watcher   SubsystemHealth
	api       SubsystemHealth
	guardrail SubsystemHealth
	telemetry SubsystemHealth
	sinks     SubsystemHealth
	sandbox   *SubsystemHealth
	conn      *ConnectorHealth
	startedAt time.Time

	// Atomic counters for connector stats (lock-free hot path).
	connRequests         atomic.Int64
	connErrors           atomic.Int64
	connToolInspections  atomic.Int64
	connToolBlocks       atomic.Int64
	connSubprocessBlocks atomic.Int64
}

func NewSidecarHealth() *SidecarHealth {
	now := time.Now()
	initial := SubsystemHealth{State: StateStarting, Since: now}
	disabled := SubsystemHealth{State: StateDisabled, Since: now}
	return &SidecarHealth{
		gateway:   initial,
		watcher:   initial,
		api:       initial,
		guardrail: disabled,
		telemetry: disabled,
		sinks:     disabled,
		startedAt: now,
	}
}

func (h *SidecarHealth) SetGateway(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.gateway = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
}

func (h *SidecarHealth) SetWatcher(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.watcher = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
}

func (h *SidecarHealth) SetAPI(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.api = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
}

func (h *SidecarHealth) SetGuardrail(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.guardrail = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
}

func (h *SidecarHealth) SetTelemetry(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.telemetry = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
}

// SetSinks reports the aggregate audit-sink health. Details should
// include "count" (int), "kinds" ([]string), and optionally "sinks"
// ([]map) with per-sink rows for richer rendering.
func (h *SidecarHealth) SetSinks(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sinks = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
}

func (h *SidecarHealth) SetSandbox(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sandbox = &SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
}

// SetConnector initializes connector health tracking for the active connector.
func (h *SidecarHealth) SetConnector(name string, mode connector.ToolInspectionMode, policy connector.SubprocessPolicy) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.conn = &ConnectorHealth{
		Name:               name,
		State:              StateRunning,
		Since:              time.Now(),
		ToolInspectionMode: mode,
		SubprocessPolicy:   policy,
	}
}

// RecordConnectorRequest increments the connector request counter.
func (h *SidecarHealth) RecordConnectorRequest() { h.connRequests.Add(1) }

// RecordConnectorError increments the connector error counter.
func (h *SidecarHealth) RecordConnectorError() { h.connErrors.Add(1) }

// RecordToolInspection increments the tool inspection counter.
func (h *SidecarHealth) RecordToolInspection() { h.connToolInspections.Add(1) }

// RecordToolBlock increments the tool block counter.
func (h *SidecarHealth) RecordToolBlock() { h.connToolBlocks.Add(1) }

// RecordSubprocessBlock increments the subprocess block counter.
func (h *SidecarHealth) RecordSubprocessBlock() { h.connSubprocessBlocks.Add(1) }

func (h *SidecarHealth) Snapshot() HealthSnapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()

	snap := HealthSnapshot{
		StartedAt: h.startedAt,
		UptimeMs:  time.Since(h.startedAt).Milliseconds(),
		Gateway:   h.gateway,
		Watcher:   h.watcher,
		API:       h.api,
		Guardrail: h.guardrail,
		Telemetry: h.telemetry,
		Sinks:     h.sinks,
		Sandbox:   h.sandbox,
	}

	if h.conn != nil {
		ch := *h.conn
		ch.Requests = h.connRequests.Load()
		ch.Errors = h.connErrors.Load()
		ch.ToolInspections = h.connToolInspections.Load()
		ch.ToolBlocks = h.connToolBlocks.Load()
		ch.SubprocessBlocks = h.connSubprocessBlocks.Load()
		snap.Connector = &ch
	}

	return snap
}
