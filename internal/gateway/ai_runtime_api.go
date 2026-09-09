// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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
	"net/http"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor"
)

// aiRuntimeResponse is the wire shape of GET /api/v1/ai-usage/runtime.
//
// Coverage travels with the findings rather than in a separate call, because
// a caller that reads findings without reading coverage cannot tell a quiet
// host from a blind sensor -- and that is the one confusion this subsystem
// exists to prevent.
type aiRuntimeResponse struct {
	Enabled                 bool               `json:"enabled"`
	ScannedAt               string             `json:"scanned_at,omitempty"`
	Findings                []aiRuntimeFinding `json:"findings"`
	Planes                  []aiRuntimePlane   `json:"planes"`
	ProcessesObserved       int                `json:"processes_observed"`
	ProcessesSkipped        int                `json:"processes_skipped"`
	ConnectionsObserved     int                `json:"connections_observed"`
	ConnectionsUnattributed int                `json:"connections_unattributed"`
	Degraded                bool               `json:"degraded"`
	DegradedReasons         []string           `json:"degraded_reasons,omitempty"`
}

type aiRuntimeFinding struct {
	FindingID string              `json:"finding_id"`
	PID       int                 `json:"pid"`
	Process   string              `json:"process"`
	Cmdline   string              `json:"cmdline,omitempty"`
	User      string              `json:"user,omitempty"`
	AgentName string              `json:"agent_name,omitempty"`
	Score     int                 `json:"score"`
	Severity  string              `json:"severity"`
	Signals   []aiRuntimeSignal   `json:"signals"`
	Providers []aiRuntimeProvider `json:"providers,omitempty"`
	// Correlation is always present, including when the inventory had nothing
	// to say and why. Omitting it on "unobserved" would let a reader mistake
	// blindness for agreement.
	Correlation aiRuntimeCorrelation `json:"correlation"`
	FirstSeen   string               `json:"first_seen,omitempty"`
	LastSeen    string               `json:"last_seen,omitempty"`
}

type aiRuntimeSignal struct {
	ID     string `json:"id"`
	Title  string `json:"title,omitempty"`
	Detail string `json:"detail,omitempty"`
	Weight int    `json:"weight"`
}

type aiRuntimeProvider struct {
	Hostname          string  `json:"hostname"`
	Address           string  `json:"address,omitempty"`
	Port              int     `json:"port,omitempty"`
	Category          string  `json:"category,omitempty"`
	Confidence        float64 `json:"confidence,omitempty"`
	AttributionSource string  `json:"attribution_source,omitempty"`
}

type aiRuntimeCorrelation struct {
	Verdict          string   `json:"verdict"`
	Reason           string   `json:"reason"`
	MatchedSignalIDs []string `json:"matched_signal_ids,omitempty"`
	Categories       []string `json:"categories,omitempty"`
}

type aiRuntimePlane struct {
	Plane     string `json:"plane"`
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Running   bool   `json:"running"`
	Mechanism string `json:"mechanism,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// handleAIRuntime serves the most recent runtime-plane snapshot.
func (a *APIServer) handleAIRuntime(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	service, release := a.leaseAIRuntime()
	defer release()
	if service == nil {
		a.writeJSON(w, http.StatusOK, aiRuntimeResponse{
			Enabled: false, Findings: []aiRuntimeFinding{}, Planes: []aiRuntimePlane{},
		})
		return
	}
	a.writeJSON(w, http.StatusOK, renderAIRuntimeSnapshot(service.Snapshot()))
}

// handleAIRuntimeScan triggers an immediate poll and returns its result.
func (a *APIServer) handleAIRuntimeScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	service, release := a.leaseAIRuntime()
	defer release()
	if service == nil {
		// 503 rather than 404: the route exists, the subsystem is switched
		// off. The CLI turns this into an actionable "enable it first".
		http.Error(w, "ai_discovery.runtime is disabled in config", http.StatusServiceUnavailable)
		return
	}
	a.writeJSON(w, http.StatusOK, renderAIRuntimeSnapshot(service.Poll(r.Context())))
}

func renderAIRuntimeSnapshot(snapshot sensor.Snapshot) aiRuntimeResponse {
	response := aiRuntimeResponse{
		Enabled:                 true,
		Findings:                make([]aiRuntimeFinding, 0, len(snapshot.Findings)),
		Planes:                  make([]aiRuntimePlane, 0, len(snapshot.Planes)),
		ProcessesObserved:       snapshot.ProcessesObserved,
		ProcessesSkipped:        snapshot.ProcessesSkipped,
		ConnectionsObserved:     snapshot.ConnectionsObserved,
		ConnectionsUnattributed: snapshot.ConnectionsUnattributed,
		Degraded:                snapshot.Degraded,
	}
	if !snapshot.ScannedAt.IsZero() {
		response.ScannedAt = snapshot.ScannedAt.UTC().Format(time.RFC3339)
	}
	if snapshot.Degraded {
		response.DegradedReasons = sensor.SortedDegradedReasons(snapshot)
	}
	for _, plane := range snapshot.Planes {
		response.Planes = append(response.Planes, aiRuntimePlane{
			Plane: string(plane.Plane), Name: plane.Plane.Name(),
			Available: plane.Available, Running: plane.Running,
			Mechanism: plane.Mechanism, Reason: plane.Reason,
		})
	}
	for _, finding := range snapshot.Findings {
		rendered := aiRuntimeFinding{
			FindingID: finding.FindingID, PID: finding.PID, Process: finding.Process,
			Cmdline: finding.Cmdline, User: finding.User, AgentName: finding.AgentName,
			Score: finding.Score, Severity: string(finding.Severity),
			Signals: make([]aiRuntimeSignal, 0, len(finding.Signals)),
			Correlation: aiRuntimeCorrelation{
				Verdict:          string(finding.Correlation.Verdict),
				Reason:           finding.Correlation.Reason,
				MatchedSignalIDs: finding.Correlation.MatchedSignalIDs,
				Categories:       finding.Correlation.Categories,
			},
		}
		for _, signal := range finding.Signals {
			rendered.Signals = append(rendered.Signals, aiRuntimeSignal{
				ID: signal.ID, Title: signal.Title, Detail: signal.Detail, Weight: signal.Weight,
			})
		}
		for _, provider := range finding.Providers {
			rendered.Providers = append(rendered.Providers, aiRuntimeProvider{
				Hostname: provider.Hostname, Address: provider.Address, Port: provider.Port,
				Category: provider.Category, Confidence: provider.Confidence,
				AttributionSource: provider.AttributionSource,
			})
		}
		if !finding.FirstSeen.IsZero() {
			rendered.FirstSeen = finding.FirstSeen.UTC().Format(time.RFC3339)
		}
		if !finding.LastSeen.IsZero() {
			rendered.LastSeen = finding.LastSeen.UTC().Format(time.RFC3339)
		}
		response.Findings = append(response.Findings, rendered)
	}
	return response
}
