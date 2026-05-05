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
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

const maxAgentDiscoveryAgents = 32

type agentDiscoveryReport struct {
	Source     string                          `json:"source"`
	ScannedAt  string                          `json:"scanned_at"`
	CacheHit   bool                            `json:"cache_hit"`
	DurationMs int64                           `json:"duration_ms"`
	Agents     map[string]agentDiscoverySignal `json:"agents"`
}

type agentDiscoverySignal struct {
	Installed          bool   `json:"installed"`
	HasConfig          bool   `json:"has_config"`
	ConfigBasename     string `json:"config_basename,omitempty"`
	ConfigPathHash     string `json:"config_path_hash,omitempty"`
	HasBinary          bool   `json:"has_binary"`
	BinaryBasename     string `json:"binary_basename,omitempty"`
	BinaryPathHash     string `json:"binary_path_hash,omitempty"`
	Version            string `json:"version,omitempty"`
	VersionProbeStatus string `json:"version_probe_status,omitempty"`
	ErrorClass         string `json:"error_class,omitempty"`
}

type agentDiscoveryResponse struct {
	Status    string `json:"status"`
	Agents    int    `json:"agents"`
	Installed int    `json:"installed"`
}

func (a *APIServer) handleAgentDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var report agentDiscoveryReport
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&report); err != nil {
		if a.otel != nil {
			a.otel.RecordAgentDiscovery(r.Context(), "unknown", false, "malformed", 0, 0, 0)
			a.otel.EmitAgentDiscoverySummaryLog(r.Context(), "unknown", false, "malformed", 0, 0, 0)
		}
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	if err := a.validateAgentDiscoveryReport(&report); err != nil {
		if a.otel != nil {
			a.otel.RecordAgentDiscovery(r.Context(), discoverySourceOrUnknown(report.Source), report.CacheHit, "rejected", float64(report.DurationMs), len(report.Agents), 0)
			a.otel.EmitAgentDiscoverySummaryLog(r.Context(), discoverySourceOrUnknown(report.Source), report.CacheHit, "rejected", float64(report.DurationMs), len(report.Agents), 0)
		}
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	source := discoverySourceOrUnknown(report.Source)
	installed := 0
	for name, signal := range report.Agents {
		if signal.Installed {
			installed++
		}
		if a.otel != nil {
			probeStatus := normalizeDiscoveryProbeStatus(signal.VersionProbeStatus)
			a.otel.RecordAgentDiscoverySignal(r.Context(), name, signal.Installed, signal.HasConfig, signal.HasBinary, probeStatus)
			a.otel.EmitAgentDiscoverySignalLog(r.Context(), name, signal.Installed, signal.HasConfig, signal.HasBinary, probeStatus)
			if reason := normalizeDiscoveryErrorClass(signal.ErrorClass); reason != "" {
				a.otel.RecordAgentDiscoveryError(r.Context(), name, reason)
			}
		}
	}
	if a.otel != nil {
		a.otel.RecordAgentDiscovery(r.Context(), source, report.CacheHit, "ok", float64(report.DurationMs), len(report.Agents), installed)
		a.otel.EmitAgentDiscoverySummaryLog(r.Context(), source, report.CacheHit, "ok", float64(report.DurationMs), len(report.Agents), installed)
	}

	emitLifecycle(r.Context(), "agent_discovery", "completed", map[string]string{
		"source":          source,
		"cache_hit":       strconv.FormatBool(report.CacheHit),
		"agents_total":    strconv.Itoa(len(report.Agents)),
		"installed_total": strconv.Itoa(installed),
		"duration_ms":     fmt.Sprintf("%d", report.DurationMs),
	})

	a.writeJSON(w, http.StatusOK, agentDiscoveryResponse{
		Status:    "ok",
		Agents:    len(report.Agents),
		Installed: installed,
	})
}

func (a *APIServer) validateAgentDiscoveryReport(report *agentDiscoveryReport) error {
	if report == nil {
		return fmt.Errorf("missing discovery report")
	}
	if strings.TrimSpace(report.ScannedAt) == "" || len(report.ScannedAt) > 64 {
		return fmt.Errorf("scanned_at is required")
	}
	if report.DurationMs < 0 {
		return fmt.Errorf("duration_ms must be non-negative")
	}
	if len(report.Agents) == 0 {
		return fmt.Errorf("agents is required")
	}
	if len(report.Agents) > maxAgentDiscoveryAgents {
		return fmt.Errorf("too many agents")
	}

	reg := a.connectorRegistry
	if reg == nil {
		reg = connector.NewDefaultRegistry()
	}
	for name, signal := range report.Agents {
		name = strings.TrimSpace(strings.ToLower(name))
		if name == "" {
			return fmt.Errorf("connector name is required")
		}
		if _, ok := reg.Get(name); !ok {
			return fmt.Errorf("unknown connector %q", name)
		}
		if err := validateDiscoverySignal(signal); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func validateDiscoverySignal(signal agentDiscoverySignal) error {
	for _, v := range []string{signal.ConfigBasename, signal.BinaryBasename} {
		if len(v) > 128 {
			return fmt.Errorf("basename too long")
		}
		if v != "" && (filepath.Base(v) != v || strings.ContainsAny(v, `/\`)) {
			return fmt.Errorf("basename must not contain path separators")
		}
	}
	for _, v := range []string{signal.ConfigPathHash, signal.BinaryPathHash} {
		if v != "" && !validDiscoveryPathHash(v) {
			return fmt.Errorf("path hash must be sha256:<64 hex>")
		}
	}
	if len(signal.Version) > 200 {
		return fmt.Errorf("version too long")
	}
	if normalizeDiscoveryProbeStatus(signal.VersionProbeStatus) != signal.VersionProbeStatus && signal.VersionProbeStatus != "" {
		return fmt.Errorf("unsupported version_probe_status")
	}
	if normalizeDiscoveryErrorClass(signal.ErrorClass) != signal.ErrorClass && signal.ErrorClass != "" {
		return fmt.Errorf("unsupported error_class")
	}
	return nil
}

func validDiscoveryPathHash(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	for _, r := range value[len(prefix):] {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}

func discoverySourceOrUnknown(source string) string {
	source = strings.TrimSpace(strings.ToLower(source))
	switch source {
	case "cli", "tui", "api":
		return source
	default:
		return "unknown"
	}
}

func normalizeDiscoveryProbeStatus(status string) string {
	status = strings.TrimSpace(strings.ToLower(status))
	switch status {
	case "ok", "timeout", "nonzero_exit", "empty_output", "probe_failed", "not_probed", "unknown":
		return status
	case "":
		return "not_probed"
	default:
		return "other"
	}
}

func normalizeDiscoveryErrorClass(reason string) string {
	reason = strings.TrimSpace(strings.ToLower(reason))
	switch reason {
	case "timeout", "nonzero_exit", "empty_output", "probe_failed", "other":
		return reason
	case "":
		return ""
	default:
		return "other"
	}
}
