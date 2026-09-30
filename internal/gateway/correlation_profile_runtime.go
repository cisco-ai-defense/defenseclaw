// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// correlationSpecForConnectorV8 resolves correlation identity from the same
// authenticated runtime registry and version lock used by hook dispatch. This
// keeps native OTLP, hooks, and the durable ledger on one connector contract;
// production ingestion must not silently use an offline/default fixture
// profile when an installed agent is pinned to a different hook contract.
func (a *APIServer) correlationSpecForConnectorV8(name string) (connector.CorrelationSpec, error) {
	return a.correlationSpecForRequestV8(context.Background(), name)
}

// correlationSpecForRequestV8 is correlationSpecForConnectorV8 for one
// request. Native OTLP from a sandbox resolves identity from the binding's
// reviewed contract, exactly like its hooks (hookProfileForRequest), and
// cannot claim any other connector's profile.
func (a *APIServer) correlationSpecForRequestV8(ctx context.Context, name string) (connector.CorrelationSpec, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return connector.CorrelationSpec{}, fmt.Errorf("correlation connector is required")
	}

	registry := sharedDefaultRegistry()
	opts := connector.SetupOpts{}
	binding, sandboxed := sandboxauth.FromContext(ctx)
	if sandboxed && sandboxauth.CanonicalConnector(name) != binding.Connector {
		return connector.CorrelationSpec{}, fmt.Errorf(
			"correlation connector %q does not match the sandbox binding", name)
	}
	if a != nil && a.connectorRegistry != nil {
		registry = a.connectorRegistry
	}
	switch {
	case a != nil && sandboxed:
		opts = sandboxSetupOpts(a, binding)
	case a != nil:
		agentVersion := connector.LoadCachedAgentVersion(a.configDataDir(), name)
		lock := connector.LoadHookContractLockEntry(a.configDataDir(), name)
		contractID := lock.ContractID
		if contractID == "" {
			contractID = connector.ResolveHookContract(name, agentVersion).Contract.ContractID
		}
		opts = connector.SetupOpts{
			DataDir:        a.configDataDir(),
			APIAddr:        a.apiAddrForCapabilities(),
			WorkspaceDir:   a.connectorWorkspaceDir(),
			AgentVersion:   agentVersion,
			HookContractID: contractID,
		}
	}

	registered, ok := registry.Get(name)
	if !ok {
		spec := connector.ExplicitCanonicalCorrelationSpec(name)
		return spec, spec.Validate()
	}

	var spec connector.CorrelationSpec
	switch provider := registered.(type) {
	case connector.CorrelationSpecProvider:
		spec = provider.CorrelationSpec(opts)
	case connector.HookProfileProvider:
		spec = provider.HookProfile(opts).Correlation
	default:
		spec = connector.ExplicitCanonicalCorrelationSpec(name)
	}
	if spec.Connector == "" {
		spec = connector.ExplicitCanonicalCorrelationSpec(name)
	}
	if spec.Connector != name {
		return connector.CorrelationSpec{}, fmt.Errorf(
			"correlation profile connector %q does not match authenticated connector %q",
			spec.Connector, name,
		)
	}
	if err := spec.Validate(); err != nil {
		return connector.CorrelationSpec{}, fmt.Errorf("invalid correlation profile for %q: %w", name, err)
	}
	return spec, nil
}
