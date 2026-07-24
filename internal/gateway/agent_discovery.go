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
	"strings"
	"time"
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
		a.emitAgentDiscoverySummary(r.Context(), agentDiscoveryTelemetrySummary{
			source: "unknown", result: "malformed",
		})
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	dropped, err := a.validateAgentDiscoveryReport(&report)
	if err != nil {
		a.emitAgentDiscoverySummary(r.Context(), agentDiscoveryTelemetrySummary{
			source: discoverySourceOrUnknown(report.Source), cacheHit: report.CacheHit,
			result: "rejected", durationMs: report.DurationMs, agentsTotal: len(report.Agents),
		})
		if len(dropped) > 0 {
			_ = a.emitManagedAgentInventory(r.Context(), &report, 0, true)
		}
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// H-4: a CLI rolled out ahead of the sidecar may report a connector
	// the sidecar doesn't know about yet. The previous behaviour rejected
	// the entire report (HTTP 400), which made staged rollouts brittle —
	// every other agent in the same batch was discarded too. We now drop
	// only the unknown entries (validateAgentDiscoveryReport stripped
	// them and returned the names) and continue, while recording an OTel
	// counter so the silent drop is visible to operators triaging
	// "why isn't agent X showing up?".
	for _, name := range dropped {
		a.emitAgentDiscoveryError(r.Context(), discoverySourceOrUnknown(report.Source), name, "unknown_connector")
	}

	source := discoverySourceOrUnknown(report.Source)
	installed := 0
	for name, signal := range report.Agents {
		if signal.Installed {
			installed++
		}
		probeStatus := normalizeDiscoveryProbeStatus(signal.VersionProbeStatus)
		a.emitAgentDiscoverySignal(r.Context(), source, name, signal, probeStatus)
		if reason := normalizeDiscoveryErrorClass(signal.ErrorClass); reason != "" {
			a.emitAgentDiscoveryError(r.Context(), source, name, reason)
		}
	}
	a.emitAgentDiscoverySummary(r.Context(), agentDiscoveryTelemetrySummary{
		source: source, cacheHit: report.CacheHit, result: "ok", durationMs: report.DurationMs,
		agentsTotal: len(report.Agents), installedTotal: installed,
	})
	// Managed inventory is a separate ai.discovery snapshot. It remains
	// available when the operator disables the agent.lifecycle family and the
	// generated managed plan prevents it from reaching sibling destinations.
	_ = a.emitManagedAgentInventory(r.Context(), &report, installed, len(dropped) > 0)

	a.writeJSON(w, http.StatusOK, agentDiscoveryResponse{
		Status:    "ok",
		Agents:    len(report.Agents),
		Installed: installed,
	})
}

// validateAgentDiscoveryReport sanitizes the report in place and returns
// the names of connectors that were dropped because the sidecar's
// connector registry doesn't know them. Caller is expected to record
// the drops via OTel; the report itself only retains known, valid
// signals after this returns.
//
// Returning a (dropped, err) pair lets us preserve the existing
// "wrong shape ⇒ HTTP 400" behaviour for malformed signals while
// gracefully degrading the unknown-connector path to "drop and
// continue" — see handleAgentDiscovery's H-4 callsite for rationale.
func (a *APIServer) validateAgentDiscoveryReport(report *agentDiscoveryReport) ([]string, error) {
	if report == nil {
		return nil, fmt.Errorf("missing discovery report")
	}
	if strings.TrimSpace(report.ScannedAt) == "" || len(report.ScannedAt) > 64 {
		return nil, fmt.Errorf("scanned_at is required")
	}
	scannedAt, err := time.Parse(time.RFC3339Nano, report.ScannedAt)
	if err != nil {
		return nil, fmt.Errorf("scanned_at must be RFC3339")
	}
	report.ScannedAt = scannedAt.UTC().Format(time.RFC3339Nano)
	if report.DurationMs < 0 {
		return nil, fmt.Errorf("duration_ms must be non-negative")
	}
	if report.Agents == nil {
		return nil, fmt.Errorf("agents is required")
	}
	if len(report.Agents) > maxAgentDiscoveryAgents {
		return nil, fmt.Errorf("too many agents")
	}

	reg := a.connectorRegistry
	if reg == nil {
		// Same singleton fast-path the hook hot path uses — see
		// getFallbackConnectorRegistry. Per-request registry
		// builds otherwise multiplied connector init cost across
		// every agent-discovery POST.
		reg = getFallbackConnectorRegistry()
	}
	var dropped []string
	validatedAgents := make(map[string]agentDiscoverySignal, len(report.Agents))
	for name, signal := range report.Agents {
		normalized := strings.TrimSpace(strings.ToLower(name))
		if normalized == "" {
			return nil, fmt.Errorf("connector name is required")
		}
		if _, ok := reg.Get(normalized); !ok {
			// Forward-compat: drop unknown entries instead of rejecting
			// the whole batch. Caller surfaces this as an OTel signal
			// so the drop isn't invisible.
			dropped = append(dropped, normalized)
			continue
		}
		if err := validateDiscoverySignal(signal); err != nil {
			return nil, fmt.Errorf("%s: %w", normalized, err)
		}
		if _, duplicate := validatedAgents[normalized]; duplicate {
			return nil, fmt.Errorf("duplicate connector name")
		}
		validatedAgents[normalized] = signal
	}
	report.Agents = validatedAgents
	if len(report.Agents) == 0 && len(dropped) > 0 {
		// Every entry was unknown — preserve the historical 400 so a
		// CLI that ONLY reports unknown connectors gets a clear error
		// (otherwise the operator-side telemetry shows agent_discovery=ok
		// while installed=0, which is misleading). dropped is also
		// returned so the caller can emit the per-name drop counters.
		return dropped, fmt.Errorf("no known connectors in report")
	}
	return dropped, nil
}

func validateDiscoverySignal(signal agentDiscoverySignal) error {
	if !signal.HasConfig && (signal.ConfigBasename != "" || signal.ConfigPathHash != "") {
		return fmt.Errorf("configuration metadata requires has_config")
	}
	if !signal.HasBinary && (signal.BinaryBasename != "" || signal.BinaryPathHash != "" || signal.Version != "") {
		return fmt.Errorf("binary metadata requires has_binary")
	}
	for _, v := range []string{signal.ConfigBasename, signal.BinaryBasename} {
		if len(v) > 128 {
			return fmt.Errorf("basename too long")
		}
		if v != "" && (filepath.Base(v) != v || strings.ContainsAny(v, `/\`)) {
			return fmt.Errorf("basename must not contain path separators")
		}
		if v != "" && inventorySafeBasename(v) != v {
			return fmt.Errorf("basename contains unsafe characters")
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
	if signal.Version != "" && (inventorySafeBounded(signal.Version, 200) != signal.Version ||
		!endpointInventoryVersionPattern.MatchString(signal.Version)) {
		return fmt.Errorf("version must be a safe version label")
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
