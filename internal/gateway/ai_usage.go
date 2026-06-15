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
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// confidencePolicyMaxRequestBytes caps the body of
// /confidence/policy/validate to keep a hostile request from
// pinning the gateway. Matches the loader's per-file limit so the
// server-side validate behaves identically to a local file load.
const confidencePolicyMaxRequestBytes = 64 * 1024

func (a *APIServer) handleAIUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.aiDiscovery == nil {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"summary": map[string]any{
				"result": "disabled",
			},
			"signals": []any{},
		})
		return
	}
	report := a.aiDiscovery.Snapshot()
	// Stamp per-component identity / presence on each signal so
	// `defenseclaw agent usage --detail` and any other API
	// consumer can render the same confidence numbers
	// `/api/v1/ai-usage/components` returns -- without a second
	// round-trip and without re-implementing the engine.
	// Snapshot() already returns a clone, so mutating in place is
	// safe and never touches the persistent state file.
	inventory.EnrichSignalsWithComponentConfidence(report.Signals, a.aiDiscovery.ConfidenceParams())
	report = a.sanitizeAIUsageReportForResponse(report)
	a.writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true,
		"summary": report.Summary,
		"signals": report.Signals,
	})
}

func (a *APIServer) handleAIUsageScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.aiDiscovery == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ai discovery disabled"})
		return
	}
	report, err := a.aiDiscovery.ScanNow(r.Context())
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Same enrichment as the GET path (see handleAIUsage above):
	// keep the wire shape identical between cached / refresh.
	inventory.EnrichSignalsWithComponentConfidence(report.Signals, a.aiDiscovery.ConfidenceParams())
	report = a.sanitizeAIUsageReportForResponse(report)
	a.writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true,
		"summary": report.Summary,
		"signals": report.Signals,
	})
}

func (a *APIServer) sanitizeAIUsageReportForResponse(report inventory.AIDiscoveryReport) inventory.AIDiscoveryReport {
	if a == nil || a.aiDiscovery == nil {
		return report
	}
	opts := a.aiDiscovery.Options()
	inventory.SanitizeEvidenceForWire(report.Signals, opts.DisableRedaction, opts.StoreRawLocalPaths)
	return report
}

// componentRollup is one row of the deduped component view returned
// by GET /api/v1/ai-usage/components. Operators use this to answer
// "do I have openai==1.45.0 anywhere?" and "is openai actively in
// use?" without scanning the raw signals slice themselves.
type componentRollup struct {
	Ecosystem       string                       `json:"ecosystem"`
	Name            string                       `json:"name"`
	Framework       string                       `json:"framework,omitempty"`
	Vendor          string                       `json:"vendor,omitempty"`
	Versions        []string                     `json:"versions,omitempty"`       // distinct versions seen across installs
	InstallCount    int                          `json:"install_count"`            // number of underlying signals
	WorkspaceCount  int                          `json:"workspace_count"`          // distinct workspace_hash values
	Detectors       []string                     `json:"detectors,omitempty"`      // distinct detector ids contributing to this row
	Locations       []componentLocation          `json:"locations,omitempty"`      // one entry per evidence row
	IdentityScore   float64                      `json:"identity_score,omitempty"` // 0..1, two-axis Bayesian engine output
	IdentityBand    string                       `json:"identity_band,omitempty"`  // very_high|high|medium|low|very_low
	PresenceScore   float64                      `json:"presence_score,omitempty"` // 0..1
	PresenceBand    string                       `json:"presence_band,omitempty"`
	IdentityFactors []inventory.ConfidenceFactor `json:"identity_factors,omitempty"` // per-evidence breakdown for /show + explain
	PresenceFactors []inventory.ConfidenceFactor `json:"presence_factors,omitempty"`
	LastSeen        string                       `json:"last_seen,omitempty"`
	LastActiveAt    string                       `json:"last_active_at,omitempty"`
}

// componentLocation is one row in the per-component locations view.
// RawPath is populated only when the gateway is configured with
// `privacy.disable_redaction=true && ai_discovery.store_raw_local_paths=true`.
type componentLocation struct {
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

// handleAIUsageComponents returns the deduped component view of the
// most recent AI discovery snapshot. Confidence scores are computed
// inline from the in-memory snapshot using the same engine the SQL
// store uses, so the API and the persisted history agree.
func (a *APIServer) handleAIUsageComponents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.aiDiscovery == nil {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"enabled":    false,
			"components": []any{},
		})
		return
	}
	report := a.aiDiscovery.Snapshot()
	rolled := rollupComponents(report.Signals, a.aiDiscovery.ConfidenceParams(), allowRawLocations(a))
	a.writeJSON(w, http.StatusOK, map[string]any{
		"enabled":        true,
		"scan_id":        report.Summary.ScanID,
		"scanned_at":     report.Summary.ScannedAt,
		"components":     rolled,
		"policy_version": a.aiDiscovery.ConfidenceParams().Policy.Version,
	})
}

// handleAIUsageComponentLocations serves the per-component locations
// detail at GET /api/v1/ai-usage/components/{ecosystem}/{name}/locations.
// Reads from the SQLite history store so locations from previous
// scans on the same host stay queryable even after a restart.
func (a *APIServer) handleAIUsageComponentLocations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.aiDiscovery == nil || a.aiDiscovery.InventoryStore() == nil {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"enabled":   false,
			"locations": []any{},
		})
		return
	}
	ecosystem, name, ok := parseComponentPath(r.URL.EscapedPath(), "/api/v1/ai-usage/components/", "/locations")
	if !ok {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected /api/v1/ai-usage/components/{ecosystem}/{name}/locations"})
		return
	}
	includeRaw := allowRawLocations(a)
	locs, err := a.aiDiscovery.InventoryStore().ListComponentLocations(r.Context(), ecosystem, name, includeRaw)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"enabled":   true,
		"ecosystem": ecosystem,
		"name":      name,
		"locations": locs,
	})
}

// handleAIUsageComponentHistory returns up to 50 confidence
// snapshots for one component, oldest-first removed, ordered
// most-recent-first, from GET .../components/{ecosystem}/{name}/history.
func (a *APIServer) handleAIUsageComponentHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.aiDiscovery == nil || a.aiDiscovery.InventoryStore() == nil {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"history": []any{},
		})
		return
	}
	ecosystem, name, ok := parseComponentPath(r.URL.EscapedPath(), "/api/v1/ai-usage/components/", "/history")
	if !ok {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected /api/v1/ai-usage/components/{ecosystem}/{name}/history"})
		return
	}
	hist, err := a.aiDiscovery.InventoryStore().ComponentHistory(r.Context(), ecosystem, name, 50)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"enabled":   true,
		"ecosystem": ecosystem,
		"name":      name,
		"history":   hist,
	})
}

// rollupComponents groups signals carrying a `Component` block by
// (ecosystem, name) and aggregates versions, install count, workspace
// count, distinct detectors, evidence locations, and the two-axis
// Bayesian confidence scores. Signals without a Component block are
// skipped (the API caller can hit /api/v1/ai-usage for the full
// signal list including catch-all rows).
//
// `params` is passed straight to ComputeComponentConfidence; when
// the gateway has `aiDiscovery.ConfidenceParams()` it should pass
// that value so this rollup matches what the SQL history shows.
//
// `includeRawPaths` controls whether RawPath leaks into the
// componentLocation rows; the caller derives it from
// `privacy.disable_redaction && ai_discovery.store_raw_local_paths`.
func rollupComponents(signals []inventory.AISignal, params inventory.ConfidenceParams, includeRawPaths bool) []componentRollup {
	type key struct{ ecosystem, name string }
	bySigKey := map[key][]inventory.AISignal{}
	for _, sig := range signals {
		if sig.Component == nil || sig.Component.Name == "" {
			continue
		}
		if sig.State == inventory.AIStateGone {
			continue
		}
		k := key{
			ecosystem: strings.ToLower(sig.Component.Ecosystem),
			name:      strings.ToLower(sig.Component.Name),
		}
		bySigKey[k] = append(bySigKey[k], sig)
	}
	now := time.Now().UTC()
	out := make([]componentRollup, 0, len(bySigKey))
	for _, group := range bySigKey {
		entry := componentRollup{
			Ecosystem: group[0].Component.Ecosystem,
			Name:      group[0].Component.Name,
		}
		workspaces := map[string]struct{}{}
		versions := map[string]struct{}{}
		detectors := map[string]struct{}{}
		var lastSeen, lastActive time.Time
		for _, sig := range group {
			entry.InstallCount++
			// First-non-empty wins for Framework + Vendor so
			// the rollup doesn't show a blank cell when the
			// arbitrarily-ordered group[0] happens to lack
			// the field that group[1] supplies. Stable
			// across calls because we don't shadow with a
			// later non-empty value once one is set.
			if entry.Framework == "" && sig.Component != nil && sig.Component.Framework != "" {
				entry.Framework = sig.Component.Framework
			}
			if entry.Vendor == "" && sig.Vendor != "" {
				entry.Vendor = sig.Vendor
			}
			if sig.WorkspaceHash != "" {
				workspaces[sig.WorkspaceHash] = struct{}{}
			}
			v := sig.Component.Version
			if v == "" {
				v = sig.Version
			}
			if v != "" {
				versions[v] = struct{}{}
			}
			if sig.Detector != "" {
				detectors[sig.Detector] = struct{}{}
			}
			if !sig.LastSeen.IsZero() && sig.LastSeen.After(lastSeen) {
				lastSeen = sig.LastSeen
			}
			if sig.LastActiveAt != nil && sig.LastActiveAt.After(lastActive) {
				lastActive = *sig.LastActiveAt
			}
			// One location per evidence row -- the renderer
			// shows manifest evidence and process evidence as
			// separate rows so an operator can tell at a glance
			// which inputs contributed.
			for _, ev := range sig.Evidence {
				loc := componentLocation{
					Detector:      sig.Detector,
					State:         sig.State,
					Basename:      ev.Basename,
					PathHash:      ev.PathHash,
					WorkspaceHash: ev.WorkspaceHash,
					Quality:       ev.Quality,
					MatchKind:     ev.MatchKind,
				}
				// Guard zero-time so we don't emit
				// "0001-01-01T00:00:00Z" as the last_seen
				// for a freshly-discovered signal that
				// hasn't been timestamped yet. Mirrors the
				// entry-level guard below.
				if !sig.LastSeen.IsZero() {
					loc.LastSeen = sig.LastSeen.UTC().Format(time.RFC3339)
				}
				if includeRawPaths {
					loc.RawPath = ev.RawPath
				}
				entry.Locations = append(entry.Locations, loc)
			}
		}
		entry.WorkspaceCount = len(workspaces)
		vs := make([]string, 0, len(versions))
		for v := range versions {
			vs = append(vs, v)
		}
		sort.Strings(vs)
		entry.Versions = vs
		ds := make([]string, 0, len(detectors))
		for d := range detectors {
			ds = append(ds, d)
		}
		sort.Strings(ds)
		entry.Detectors = ds
		if !lastSeen.IsZero() {
			entry.LastSeen = lastSeen.UTC().Format(time.RFC3339)
		}
		if !lastActive.IsZero() {
			entry.LastActiveAt = lastActive.UTC().Format(time.RFC3339)
		}
		conf := inventory.ComputeComponentConfidence(group, now, params)
		entry.IdentityScore = conf.IdentityScore
		entry.IdentityBand = conf.IdentityBand
		entry.PresenceScore = conf.PresenceScore
		entry.PresenceBand = conf.PresenceBand
		entry.IdentityFactors = conf.IdentityFactors
		entry.PresenceFactors = conf.PresenceFactors
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// allowRawLocations evaluates the two-flag composition that controls
// whether RawPath leaks beyond the local process. We re-read both
// flags from the discovery options so a config reload is reflected
// without restarting the gateway. Defaults to false (the safest
// stance) when the discovery service is not running.
func allowRawLocations(a *APIServer) bool {
	if a == nil || a.aiDiscovery == nil {
		return false
	}
	opts := a.aiDiscovery.Options()
	return opts.DisableRedaction && opts.StoreRawLocalPaths
}

// componentPathSegmentMax bounds {ecosystem} and {name} so a hostile
// caller can't waste CPU / log-line bytes by sending megabyte-long
// segments. Real ecosystems are short ("npm", "pypi", "go", …) and
// real component names rarely exceed 100 chars; 256 leaves enough
// room for vendor-prefixed names like @org/extra-long-package while
// still capping abuse.
const componentPathSegmentMax = 256

// parseComponentPath extracts {ecosystem} and {name} from a URL of
// the form `<prefix>{ecosystem}/{name}<suffix>`. Returns ok=false
// when the path doesn't match (e.g. missing suffix, empty segments,
// or either segment longer than componentPathSegmentMax bytes).
//
// Callers must pass the *escaped* path (typically `r.URL.EscapedPath()`)
// so that percent-encoded slashes inside a segment survive the split.
// Real-world npm names use a `@scope/pkg` convention where the literal
// `/` MUST be encoded as `%2F` on the wire; using `r.URL.Path` here
// would silently drop `@anthropic-ai/sdk` requests with a 400 because
// Go's net/http decodes `%2F` to `/` before populating URL.Path.
//
// Each segment is `url.PathUnescape`d after splitting so the rest of
// the handler sees the original ecosystem/name pair. Length capping
// runs against the *encoded* form (which is always >= the decoded
// length), keeping the defense-in-depth bound effective without
// having to special-case multi-byte escapes.
//
// Defense-in-depth bound: the SQL store uses parameterized queries
// so SQLi is impossible, but unbounded segments still cost CPU on
// the LOWER() comparison and bloat log lines.
func parseComponentPath(escapedPath, prefix, suffix string) (string, string, bool) {
	if !strings.HasPrefix(escapedPath, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(escapedPath, prefix)
	if !strings.HasSuffix(rest, suffix) {
		return "", "", false
	}
	rest = strings.TrimSuffix(rest, suffix)
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	if len(parts[0]) > componentPathSegmentMax || len(parts[1]) > componentPathSegmentMax {
		return "", "", false
	}
	eco, err := url.PathUnescape(parts[0])
	if err != nil || eco == "" {
		return "", "", false
	}
	name, err := url.PathUnescape(parts[1])
	if err != nil || name == "" {
		return "", "", false
	}
	return eco, name, true
}

// handleAIUsageConfidencePolicy returns the active confidence policy.
// `?source=default` returns the embedded baseline so an operator can
// diff their override; the default `?source=merged` (or omitted)
// returns whatever the engine actually uses, which already includes
// any operator override deep-merged on top of the default.
func (a *APIServer) handleAIUsageConfidencePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	source := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("source")))
	if source == "" {
		source = "merged"
	}
	switch source {
	case "merged":
		// Even when AI discovery is disabled we can still surface
		// the embedded default — operators want to inspect the
		// shipping policy before deciding whether to enable
		// discovery at all.
		if a.aiDiscovery == nil {
			policy, err := inventory.LoadDefaultConfidencePolicy()
			if err != nil {
				a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			a.writeJSON(w, http.StatusOK, map[string]any{
				"source":  "default",
				"enabled": false,
				"policy":  policy,
			})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{
			"source":  "merged",
			"enabled": true,
			"policy":  a.aiDiscovery.ConfidenceParams().Policy,
		})
	case "default":
		policy, err := inventory.LoadDefaultConfidencePolicy()
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{
			"source":  "default",
			"enabled": a.aiDiscovery != nil,
			"policy":  policy,
		})
	default:
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "source must be one of: merged, default"})
	}
}

// handleAIUsageConfidencePolicyValidate parses a candidate policy
// out of the request body and returns whether it would deep-merge
// cleanly on top of the embedded default. Lets operators dry-run a
// policy file before writing it to the gateway host.
//
// Wire format: JSON envelope `{"yaml": "<raw policy YAML>"}` with
// Content-Type: application/json. The envelope is required because
// apiCSRFProtect (this same router stack, see api.go:apiCSRFProtect)
// rejects every non-OTLP POST that doesn't advertise
// application/json — sending the YAML as the raw body with
// Content-Type: application/x-yaml would be 415'd before we ever
// see it. Wrapping in JSON is a small ergonomic cost that keeps
// the validate endpoint inside the standard CSRF gate.
//
// Always 200 OK; the body's `valid` boolean and `error` string carry
// the result so command pipelines can `jq -e` on it.
func (a *APIServer) handleAIUsageConfidencePolicyValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, confidencePolicyMaxRequestBytes+1))
	if err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body: " + err.Error()})
		return
	}
	if int64(len(body)) > confidencePolicyMaxRequestBytes {
		a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"valid": false,
			"error": "request body exceeds policy size limit",
		})
		return
	}
	var envelope struct {
		// `yaml` is the canonical field; `policy` is accepted as
		// an alias because the obvious word for "the YAML policy
		// payload" splits between operators (some test scripts
		// use `policy`, the docs use `yaml`).
		YAML   string `json:"yaml"`
		Policy string `json:"policy"`
	}
	if len(body) == 0 {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"valid": false,
			"error": "request body must be JSON: {\"yaml\":\"<policy YAML>\"}",
		})
		return
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"valid": false,
			"error": "request body must be JSON: {\"yaml\":\"<policy YAML>\"}: " + err.Error(),
		})
		return
	}
	yamlText := envelope.YAML
	if yamlText == "" {
		yamlText = envelope.Policy
	}
	policy, err := inventory.LoadConfidencePolicyFromBytes([]byte(yamlText), "request")
	if err != nil {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"valid": false,
			"error": err.Error(),
		})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"valid":   true,
		"version": policy.Version,
		"policy":  policy,
	})
}

func (a *APIServer) handleAIUsageDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.aiDiscovery == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ai discovery disabled"})
		return
	}
	var report inventory.AIDiscoveryReport
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&report); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if err := a.aiDiscovery.IngestExternalReport(r.Context(), &report); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
