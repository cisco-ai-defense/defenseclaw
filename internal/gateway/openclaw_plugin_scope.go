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
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// openClawPluginScope is the connector scope of the OpenClaw plugin
// credential: the connector-scoped hook token
// (<data_dir>/hooks/.hook-openclaw.token) that setup mints for the openclaw
// connector.
const openClawPluginScope = "openclaw"

// openClawPluginRoutes are the management routes, besides /api/v1/inspect/*
// (X-DefenseClaw-Connector: openclaw) and the listener proofs, that the
// OpenClaw plugin credential authenticates: exactly the calls the plugin
// makes, and the skill scan of its install-policy command (defenseclaw-gateway
// connector openclaw install-policy). Before 1.0.10 the plugin held the master gateway token, which can
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
	"/v1/skill/scan":    http.MethodPost,
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

// refuseOpenClawPluginPath answers 403 when the OpenClaw plugin credential
// asks to scan a path outside the OpenClaw account in the separate-user
// layout: there the credential belongs to another OS account, and a scan
// runs as the DefenseClaw account, so it must not read (or report on, or
// send to the judge) files only DefenseClaw can read. Allowed roots: the
// OpenClaw home, claw.workspace_dir and the home of plugin_account.
func (a *APIServer) refuseOpenClawPluginPath(w http.ResponseWriter, r *http.Request, target string) bool {
	if authenticatedInspectConnector(r.Context()) != openClawPluginScope {
		return false
	}
	cfg := a.runtimeConfigSnapshot()
	if cfg == nil || !cfg.OpenClawSeparateUser() {
		return false
	}
	if openClawPathUnderAny(target, openClawPluginRoots(cfg)) {
		return false
	}
	// OpenClaw stages a skill or plugin install under the temporary folder
	// of its account; a staged folder that account owns may be scanned.
	if openClawStagedByAccount(target, strings.TrimSpace(cfg.Connectors.OpenClaw.PluginAccount)) {
		return false
	}
	a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "path is outside the OpenClaw account"})
	return true
}

func openClawPluginRoots(cfg *config.Config) []string {
	roots := []string{cfg.OpenClawHome()}
	if ws := strings.TrimSpace(cfg.Claw.WorkspaceDir); ws != "" {
		roots = append(roots, ws)
	}
	if u, err := user.Lookup(strings.TrimSpace(cfg.Connectors.OpenClaw.PluginAccount)); err == nil && u.HomeDir != "" {
		roots = append(roots, u.HomeDir)
	}
	return roots
}

// openClawPathUnderAny resolves target (symlinks included) and reports
// whether it is one of roots or inside one. A path that cannot be resolved
// is refused.
func openClawPathUnderAny(target string, roots []string) bool {
	if strings.TrimSpace(target) == "" || !filepath.IsAbs(target) {
		return false
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return false
	}
	for _, root := range roots {
		rr, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		if resolved == rr || strings.HasPrefix(resolved, rr+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// openClawConnectorRegistered reports whether this gateway serves the
// openclaw connector, so a credential left from an earlier openclaw setup
// opens nothing after a switch to another connector.
func (a *APIServer) openClawConnectorRegistered() bool {
	if a.connectorRegistry == nil {
		return false
	}
	_, ok := a.connectorRegistry.Get(openClawPluginScope)
	return ok
}

// openClawPluginProofToken is the openclaw connector-scoped credential the
// plugin proves the listener with (hooks/.hook-openclaw.token), or "" when
// there is none or its teardown revoked it.
func (a *APIServer) openClawPluginProofToken() string {
	dataDir := a.configDataDir()
	if dataDir == "" || connector.HookAPITokenRevoked(dataDir, openClawPluginScope) {
		return ""
	}
	token, err := connector.LoadHookAPIToken(dataDir, openClawPluginScope)
	if err != nil {
		return ""
	}
	return token
}

// openClawPluginAccount is connectors.openclaw.plugin_account, or "".
func (a *APIServer) openClawPluginAccount() string {
	cfg := a.runtimeConfigSnapshot()
	if cfg == nil {
		return ""
	}
	return strings.TrimSpace(cfg.Connectors.OpenClaw.PluginAccount)
}
