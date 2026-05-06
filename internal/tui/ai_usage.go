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

package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AIUsageSnapshot mirrors the GET /api/v1/ai-usage response.
//
// The TUI's Overview panel uses this to render a "DISCOVERED AI
// AGENTS" box: which AI tools/CLIs/extensions the continuous
// discovery service has fingerprinted on the host, and whether
// they're newly observed since the last scan or already known.
//
// Field names and JSON tags must stay in sync with
// internal/gateway/ai_usage.go::handleAIUsage and
// internal/inventory/ai_discovery.go (AISignal/AIDiscoverySummary)
// or the TUI will silently drop signals on parse.
type AIUsageSnapshot struct {
	Enabled bool             `json:"enabled"`
	Summary AIUsageSummary   `json:"summary"`
	Signals []AIUsageSignal  `json:"signals"`
	// FetchedAt records when the TUI last refreshed this snapshot.
	// Used for the "(updated 12s ago)" hint and for tests; not part
	// of the wire format.
	FetchedAt time.Time `json:"-"`
}

// AIUsageSummary mirrors inventory.AIDiscoverySummary. Only the
// counters the Overview renders are reflected — extra fields on
// the wire are ignored, which is fine because we use json.Decoder
// without DisallowUnknownFields here (the gateway is the source
// of truth for the schema).
type AIUsageSummary struct {
	ScanID         string    `json:"scan_id"`
	ScannedAt      time.Time `json:"scanned_at"`
	PrivacyMode    string    `json:"privacy_mode"`
	Result         string    `json:"result"`
	TotalSignals   int       `json:"total_signals"`
	ActiveSignals  int       `json:"active_signals"`
	NewSignals     int       `json:"new_signals"`
	ChangedSignals int       `json:"changed_signals"`
	GoneSignals    int       `json:"gone_signals"`
	FilesScanned   int       `json:"files_scanned"`
}

// AIUsageComponent mirrors inventory.AIComponent. When the
// `package_manifest` detector resolves a matched package to a
// declared component, the resulting signal carries this. The TUI
// uses it to render specific framework labels (e.g. "OpenAI Python
// SDK 1.45.0") instead of the catch-all "AI SDKs / Multiple".
type AIUsageComponent struct {
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	Framework string `json:"framework,omitempty"`
}

// AIUsageRuntime mirrors inventory.ProcessRuntime: the live PID /
// uptime / user for `process` detector signals. Nil for any other
// detector.
type AIUsageRuntime struct {
	PID       int       `json:"pid"`
	PPID      int       `json:"ppid,omitempty"`
	StartedAt time.Time `json:"started_at,omitempty"`
	UptimeSec int64     `json:"uptime_sec,omitempty"`
	User      string    `json:"user,omitempty"`
	Comm      string    `json:"comm,omitempty"`
}

// AIUsageSignal mirrors inventory.AISignal but only the fields the
// TUI renders. Confidence is a 0..1 float (matches the inventory
// model); the renderer formats it as a percentage.
//
// Two-axis Bayesian confidence (Phase 1 of the high-fidelity
// rework) is surfaced via the optional IdentityScore / PresenceScore
// + bands. These are populated by the gateway's components endpoint;
// the bare `confidence` field stays for back-compat with v1
// renderers that pre-date the engine.
type AIUsageSignal struct {
	SignalID           string            `json:"signal_id"`
	SignatureID        string            `json:"signature_id"`
	Name               string            `json:"name"`
	Vendor             string            `json:"vendor"`
	Product            string            `json:"product"`
	Category           string            `json:"category"`
	SupportedConnector string            `json:"supported_connector,omitempty"`
	Confidence         float64           `json:"confidence"`
	IdentityScore      float64           `json:"identity_score,omitempty"`
	IdentityBand       string            `json:"identity_band,omitempty"`
	PresenceScore      float64           `json:"presence_score,omitempty"`
	PresenceBand       string            `json:"presence_band,omitempty"`
	State              string            `json:"state"`
	Detector           string            `json:"detector"`
	Source             string            `json:"source"`
	FirstSeen          time.Time         `json:"first_seen"`
	LastSeen           time.Time         `json:"last_seen"`
	LastActiveAt       *time.Time        `json:"last_active_at,omitempty"`
	Version            string            `json:"version,omitempty"`
	Component          *AIUsageComponent `json:"component,omitempty"`
	Runtime            *AIUsageRuntime   `json:"runtime,omitempty"`
	// EvidenceTypes / Detectors are flattened by the gateway for
	// quick rendering -- the TUI shows them as "via process,
	// package_manifest" without parsing the full evidence list.
	EvidenceTypes []string `json:"evidence_types,omitempty"`
}

// AIUsageComponentRollup mirrors gateway.componentRollup -- one
// deduped component row with all its installs and computed
// confidence. The TUI's "Components" tab renders one box per row,
// and the CLI's `agent components` subcommand uses the same struct.
type AIUsageComponentRollup struct {
	Ecosystem       string                       `json:"ecosystem"`
	Name            string                       `json:"name"`
	Framework       string                       `json:"framework,omitempty"`
	Vendor          string                       `json:"vendor,omitempty"`
	Versions        []string                     `json:"versions,omitempty"`
	InstallCount    int                          `json:"install_count"`
	WorkspaceCount  int                          `json:"workspace_count"`
	Detectors       []string                     `json:"detectors,omitempty"`
	IdentityScore   float64                      `json:"identity_score"`
	IdentityBand    string                       `json:"identity_band,omitempty"`
	PresenceScore   float64                      `json:"presence_score"`
	PresenceBand    string                       `json:"presence_band,omitempty"`
	IdentityFactors []AIUsageConfidenceFactor    `json:"identity_factors,omitempty"`
	PresenceFactors []AIUsageConfidenceFactor    `json:"presence_factors,omitempty"`
	Locations       []AIUsageComponentLocation   `json:"locations,omitempty"`
	LastSeen        string                       `json:"last_seen,omitempty"`
	LastActiveAt    string                       `json:"last_active_at,omitempty"`
}

// AIUsageConfidenceFactor mirrors inventory.ConfidenceFactor.
// LogitDelta is the additive shift in log-odds that this evidence
// produced; the TUI / CLI converts it to a percentage-point shift
// for human readers via PercentagePointShift on the engine side.
type AIUsageConfidenceFactor struct {
	Detector    string  `json:"detector"`
	EvidenceID  string  `json:"evidence_id,omitempty"`
	MatchKind   string  `json:"match_kind,omitempty"`
	Quality     float64 `json:"quality"`
	Specificity float64 `json:"specificity"`
	LR          float64 `json:"lr"`
	LogitDelta  float64 `json:"logit_delta"`
}

// AIUsageComponentLocation mirrors gateway.componentLocation.
// RawPath is populated only when the gateway is configured to
// disable redaction AND store raw local paths.
type AIUsageComponentLocation struct {
	Detector      string  `json:"detector"`
	State         string  `json:"state,omitempty"`
	Basename      string  `json:"basename,omitempty"`
	PathHash      string  `json:"path_hash,omitempty"`
	WorkspaceHash string  `json:"workspace_hash,omitempty"`
	Quality       float64 `json:"quality,omitempty"`
	MatchKind     string  `json:"match_kind,omitempty"`
	RawPath       string  `json:"raw_path,omitempty"`
	LastSeen      string  `json:"last_seen,omitempty"`
}

// aiUsageUpdateMsg is dispatched after pollAIUsage finishes so the
// model can hand the snapshot to the Overview panel. Mirrors
// healthUpdateMsg's shape so Update can apply both with the same
// "nil out on error, swap on success" pattern.
type aiUsageUpdateMsg struct {
	Snapshot *AIUsageSnapshot
	Err      error
}

// fetchAIUsage calls GET /api/v1/ai-usage on the local sidecar
// and parses the response into an AIUsageSnapshot. The Bearer
// token is required because tokenAuth gates everything except
// GET /health (see internal/gateway/api.go::tokenAuth). Callers
// pass an empty token when the gateway is unreachable or the
// config hasn't been loaded yet — the request will then fail
// with 401, the TUI nils the snapshot, and the Overview panel
// renders the "ai discovery offline" placeholder.
func fetchAIUsage(ctx context.Context, apiPort int, token string) (*AIUsageSnapshot, error) {
	if apiPort <= 0 {
		return nil, fmt.Errorf("tui: ai-usage: invalid api port %d", apiPort)
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/api/v1/ai-usage", apiPort)

	reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("tui: ai-usage build request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tui: ai-usage fetch: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("tui: ai-usage read: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("tui: ai-usage: 401 (configure DEFENSECLAW_GATEWAY_TOKEN)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tui: ai-usage: status %d", resp.StatusCode)
	}

	var snap AIUsageSnapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		return nil, fmt.Errorf("tui: ai-usage parse: %w", err)
	}
	snap.FetchedAt = time.Now()
	return &snap, nil
}
