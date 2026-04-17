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
	"time"
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
	Sinks   SubsystemHealth  `json:"sinks"`
	Sandbox *SubsystemHealth `json:"sandbox,omitempty"`
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
	startedAt time.Time
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

func (h *SidecarHealth) Snapshot() HealthSnapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return HealthSnapshot{
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
}
