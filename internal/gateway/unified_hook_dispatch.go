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
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// handleUnifiedConnectorHook is the single entry point that every
// connector hook route registers through. Responsibilities:
//
//  1. Emit the defenseclaw_connector_hook_unified_dispatch_total
//     metric (per-connector) so operators can confirm traffic is
//     flowing through the unified pipeline (vs. an out-of-tree
//     registration that bypasses audit/metrics emission).
//  2. Delegate to handleAgentHook(name). EVERY connector — codex,
//     claudecode, hermes, cursor, windsurf, geminicli, copilot —
//     flows through the same handler now. Connector-specific event
//     emission, dedupe, and evaluation live behind HookProfile runtime
//     callbacks; shared audit, metrics, trace propagation, W3C
//     headers, and OTel emissions stay in handleAgentHook.
//
// Why this matters: prior to this PR, codex and claudecode each
// owned a full bespoke HTTP handler that re-implemented the entire
// pipeline. Adding a cross-cutting concern (audit envelope
// refresh, dispatch metric, dedup, trace propagation) meant
// touching three handlers and risking the F2-class drift hazard
// that bit live Splunk verification when claudecode skipped the
// audit envelope refresh. The unified pipeline owns those concerns
// in exactly one place now.
func (a *APIServer) handleUnifiedConnectorHook(name string) http.HandlerFunc {
	// Resolve the unified handler once at registration time so the
	// closure does not pay the lookup cost per request.
	unified := a.handleAgentHook(name)
	return func(w http.ResponseWriter, r *http.Request) {
		if a.otel != nil {
			a.otel.RecordUnifiedHookDispatch(r.Context(), name)
		}
		unified(w, r)
	}
}

// defaultRegistryOnce + defaultRegistry cache the connector
// registry used when a.connectorRegistry is nil (typical for
// reduced-fixture tests). Constructing NewDefaultRegistry per
// request walks every package-level init() and allocates a fresh
// map; doing it once across the process keeps hookProfileForConnector
// cheap when the gateway hot-paths it.
var (
	defaultRegistryOnce sync.Once
	defaultRegistry     *connector.Registry
)

func sharedDefaultRegistry() *connector.Registry {
	defaultRegistryOnce.Do(func() {
		defaultRegistry = connector.NewDefaultRegistry()
	})
	return defaultRegistry
}

// hookProfileForConnector returns the connector-declared HookProfile
// for `name`, or a zero-value profile if the connector either does
// not exist in the registry or does not implement
// HookProfileProvider. Useful for callers that want to inspect
// profile fields (Capabilities, NativeOTLP, MapVerdict, etc.) without
// a nil-check ladder.
func (a *APIServer) hookProfileForConnector(name string) connector.HookProfile {
	reg := a.connectorRegistry
	if reg == nil {
		reg = sharedDefaultRegistry()
	}
	conn, ok := reg.Get(name)
	if !ok {
		return connector.HookProfile{Name: name}
	}
	provider, ok := conn.(connector.HookProfileProvider)
	if !ok {
		return connector.HookProfile{Name: name}
	}
	agentVersion := connector.LoadCachedAgentVersion(a.configDataDir(), name)
	lock := connector.LoadHookContractLockEntry(a.configDataDir(), name)
	contractID := lock.ContractID
	if contractID == "" {
		contractID = connector.ResolveHookContract(name, agentVersion).Contract.ContractID
	}
	return provider.HookProfile(connector.SetupOpts{
		DataDir:        a.configDataDir(),
		APIAddr:        a.apiAddrForCapabilities(),
		WorkspaceDir:   currentWorkingDir(),
		AgentVersion:   agentVersion,
		HookContractID: contractID,
	})
}
