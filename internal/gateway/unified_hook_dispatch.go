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
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// handleUnifiedConnectorHook is the single entry point that every
// connector hook route registers through. Responsibilities:
//
//  1. Emit the generated metric.connector.hook.unified_dispatch
//     family (per connector) so operators can confirm traffic is
//     flowing through the unified pipeline (vs. an out-of-tree
//     registration that bypasses audit/metrics emission).
//  2. Delegate to handleAgentHook(name). EVERY connector — codex,
//     claudecode, hermes, cursor, windsurf, geminicli, copilot —
//     flows through the same handler now. Connector-specific event
//     emission, dedupe, and evaluation live behind HookProfile runtime
//     callbacks; shared audit, generated metrics, trace propagation,
//     and W3C headers stay in handleAgentHook.
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
		a.recordUnifiedHookDispatchMetricV8(r.Context(), name)
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
	return a.hookProfileForConnectorOptions(name, connector.SetupOpts{
		DataDir:      a.configDataDir(),
		APIAddr:      a.apiAddrForCapabilities(),
		WorkspaceDir: a.connectorWorkspaceDir(),
	})
}

func (a *APIServer) hookProfileForConnectorOptions(name string, opts connector.SetupOpts) connector.HookProfile {
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
	if opts.AgentVersion == "" {
		opts.AgentVersion = connector.LoadCachedAgentVersion(a.configDataDir(), name)
	}
	if opts.HookContractID == "" {
		lock := connector.LoadHookContractLockEntry(a.configDataDir(), name)
		opts.HookContractID = lock.ContractID
		if opts.HookContractID == "" {
			opts.HookContractID = connector.ResolveHookContract(name, opts.AgentVersion).Contract.ContractID
		}
	}
	return provider.HookProfile(opts)
}

// hookProfileForRequest selects Copilot's managed v2 profile only when both
// the gateway's trusted deployment configuration and the policy-bound request
// metadata agree. No JSON field can opt a request into the privileged profile.
func (a *APIServer) hookProfileForRequest(name string, r *http.Request) (connector.HookProfile, string, error) {
	base := a.hookProfileForConnector(name)
	if !strings.EqualFold(strings.TrimSpace(name), "copilot") {
		return base, "", nil
	}
	event := strings.TrimSpace(r.Header.Get(connector.CopilotEnterpriseHookEventHeader))
	contractID := strings.TrimSpace(r.Header.Get(connector.CopilotEnterpriseHookContractHeader))
	managedHeader := strings.TrimSpace(r.Header.Get(connector.CopilotEnterpriseManagedHeader))
	if event == "" && contractID == "" && managedHeader == "" {
		return base, "", nil
	}
	if a == nil || a.scannerCfg == nil || !managed.IsManagedEnterprise(a.scannerCfg.DeploymentMode) {
		return base, "", fmt.Errorf("managed Copilot binding is not permitted outside managed enterprise deployment")
	}
	if managedHeader != "true" || contractID != connector.CopilotEnterpriseHookContractID || !connector.IsCopilotEnterpriseHookEvent(event) {
		return base, "", fmt.Errorf("managed Copilot event/contract binding is invalid")
	}
	profile := connector.NewCopilotEnterpriseConnector().HookProfile(connector.SetupOpts{
		DataDir:           a.configDataDir(),
		APIAddr:           a.apiAddrForCapabilities(),
		WorkspaceDir:      a.connectorWorkspaceDir(),
		ManagedEnterprise: true,
		// Version eligibility is authenticated during target enrollment. The
		// LocalSystem gateway intentionally has no access to the user's package
		// metadata or contract lock, so the trusted machine-policy binding selects
		// the already-reviewed v2 profile at its contract floor.
		AgentVersion:   connector.CopilotEnterpriseMinVersion,
		HookContractID: connector.CopilotEnterpriseHookContractID,
	})
	if profile.CompatibilityStatus != connector.HookCompatibilityKnown || profile.ContractID != connector.CopilotEnterpriseHookContractID {
		return base, "", fmt.Errorf("managed Copilot v2 profile is unavailable")
	}
	return profile, event, nil
}
