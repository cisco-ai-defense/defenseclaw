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
	"net/http"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// openClawPluginScope is the connector scope of the OpenClaw plugin
// credential: the connector-scoped hook token
// (<data_dir>/hooks/.hook-openclaw.token) that setup mints for the openclaw
// connector.
const openClawPluginScope = "openclaw"

// openClawPluginRoutes are the management routes, besides /api/v1/inspect/*
// (X-DefenseClaw-Connector: openclaw) and the listener proofs, that the
// OpenClaw plugin credential authenticates: exactly the calls the plugin
// makes. Before 1.0.10 the plugin held the master gateway token, which can
// also loosen policy and stop the gateway. The table is closed: an unlisted
// route or method takes only the master gateway token, so a leaked plugin
// credential can read the block and allow lists, write audit and scan rows
// and ask for scans and policy decisions, but never block, allow, unblock
// (those write config.yaml), switch connectors, change config or shut down.
var openClawPluginRoutes = map[string]string{
	"/status":           http.MethodGet,
	"/enforce/blocked":  http.MethodGet,
	"/enforce/allowed":  http.MethodGet,
	"/audit/event":      http.MethodPost,
	"/policy/evaluate":  http.MethodPost,
	"/scan/result":      http.MethodPost,
	"/v1/plugin/scan":   http.MethodPost,
	"/api/v1/scan/code": http.MethodPost,
	openClawRuntimePath: http.MethodGet,
}

// openClawRuntimePath answers the plugin the settings it used to read from
// config.yaml, which the plugin account cannot read in the separate-user
// layout.
const openClawRuntimePath = "/api/v1/openclaw/runtime"

// openClawPluginRoute reports whether method and path are a route the
// OpenClaw plugin credential may call.
func openClawPluginRoute(method, path string) bool {
	want, ok := openClawPluginRoutes[path]
	return ok && strings.EqualFold(method, want)
}

// openClawInspectBudget is how long the plugin waits for a verdict: the hook
// judge budget plus 2 s for the rule and AI Defense phases, or the approval
// timeout plus 5 s when human approval is on. Before 1.0.10 the plugin waited
// 2 s without approval, so a judge verdict arrived after the plugin had
// already applied its outage mode.
func openClawInspectBudget(cfg *config.Config, hilt bool, approvalTimeoutS int) time.Duration {
	budget := hookJudgeTimeout(cfg) + 2*time.Second
	if hilt {
		if approval := time.Duration(approvalTimeoutS+5) * time.Second; approval > budget {
			budget = approval
		}
	}
	return budget
}

// handleOpenClawRuntime returns the guardrail settings of the openclaw
// connector from the live config.yaml: mode, human approval and its
// timeout. It holds no secret.
func (a *APIServer) handleOpenClawRuntime(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := a.runtimeConfigSnapshot()
	if cfg == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config not loaded"})
		return
	}
	mode := "observe"
	if m := strings.ToLower(cfg.EffectiveGuardrailModeForConnector(openClawPluginScope)); m == "action" || m == "enforce" {
		mode = "action"
	}
	timeout := cfg.Gateway.ApprovalTimeout
	if timeout <= 0 {
		timeout = 30
	}
	hilt := cfg.EffectiveHILTForConnector(openClawPluginScope).Enabled
	a.writeJSON(w, http.StatusOK, map[string]interface{}{
		"mode":               mode,
		"hilt_enabled":       hilt,
		"approval_timeout_s": timeout,
		"inspect_timeout_ms": openClawInspectBudget(cfg, hilt, timeout).Milliseconds(),
		"prompt_gate":        cfg.Connectors.OpenClaw.Hooks.PromptGate,
	})
}
