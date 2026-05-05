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
	"net/http"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

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
	a.writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true,
		"summary": report.Summary,
		"signals": report.Signals,
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
	if err := a.aiDiscovery.IngestExternalReport(r.Context(), report); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
