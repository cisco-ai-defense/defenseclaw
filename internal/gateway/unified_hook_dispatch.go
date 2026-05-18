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
//  2. Delegate the actual evaluation to the connector-specific
//     handler. codex and claudecode keep dedicated handlers because
//     they shape PluginInput-v1 / Codex-notify-quirk responses that
//     the generic handler doesn't model; every other connector flows
//     through handleAgentHook(name).
//
// The shared concerns — structured audit envelope writes
// (logConnectorHookAuditEnvelope), native OTel metrics
// (RecordHookOutcome / RecordHookTokenUsage), raw-event
// deduplication, W3C trace propagation — all sit inside the
// delegated handlers; this wrapper is the "is this hook traffic?"
// gate that guarantees they ran.
func (a *APIServer) handleUnifiedConnectorHook(name string) http.HandlerFunc {
	// Resolve the bespoke handler once at registration time so the
	// closure does not pay the switch cost per request.
	bespoke := a.bespokeHookHandlerForUnifiedCollector(name)
	return func(w http.ResponseWriter, r *http.Request) {
		if a.otel != nil {
			a.otel.RecordUnifiedHookDispatch(r.Context(), name)
		}
		bespoke(w, r)
	}
}

// bespokeHookHandlerForUnifiedCollector returns the per-connector
// handler that handleUnifiedConnectorHook delegates to. codex /
// claudecode have dedicated handlers (legacy PluginInput-v1
// response shaping + Codex notify-bridge quirks); every other
// connector flows through handleAgentHook(name).
//
// Kept as a method (not a switch inside handleUnifiedConnectorHook)
// so the lookup happens once per registration instead of once per
// request.
func (a *APIServer) bespokeHookHandlerForUnifiedCollector(name string) http.HandlerFunc {
	switch name {
	case "codex":
		return a.handleCodexHook
	case "claudecode":
		return a.handleClaudeCodeHook
	default:
		return a.handleAgentHook(name)
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
	return provider.HookProfile(connector.SetupOpts{
		DataDir:      a.configDataDir(),
		APIAddr:      a.apiAddrForCapabilities(),
		WorkspaceDir: currentWorkingDir(),
	})
}
