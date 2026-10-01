// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// errStandaloneAIDefenseDisabled marks a standalone deployment that did not
// opt into Cisco AI Defense. It is not an error condition: the local engine
// is the decision-maker.
var errStandaloneAIDefenseDisabled = errors.New("ai defense is not enabled for this standalone deployment")

// newStandaloneInspector builds the optional Cisco AI Defense client of a
// standalone managed deployment. The API key comes only from the protected
// credential named in enterprise.inspection.ai_defense; config api_key,
// api_key_env and the data-dir .env are never consulted, so neither a
// user nor a compromised service-writable file can substitute a key. A
// missing or untrusted credential leaves the local engine deciding alone.
//
// A built client reports every request's outcome to /health: a rejected key
// (HTTP 401/403) or an unreachable endpoint or proxy marks AI Defense
// unavailable, and the next successful inspection clears it.
func (s *Sidecar) newStandaloneInspector(ctx context.Context, cfg *config.Config) Inspector {
	c, err := newStandaloneCiscoInspectClient(cfg)
	if err != nil {
		if errors.Is(err, errStandaloneAIDefenseDisabled) {
			s.setInspectionAvailability(nil)
			return nil
		}
		s.setInspectionAvailability(err)
		EmitCiscoError(ctx, gatewaylog.ErrCodeUpstreamError,
			"standalone managed_enterprise: Cisco AI Defense disabled, local policy engine continues: "+err.Error())
		return nil
	}
	return s.adoptStandaloneInspector(c)
}

// adoptStandaloneInspector wires a built standalone AI Defense client into
// the sidecar: metrics, a fresh available state, and the observer through
// which its requests keep /health current.
func (s *Sidecar) adoptStandaloneInspector(c *CiscoInspectClient) Inspector {
	metricRuntime, _ := s.observabilityV8LifecycleRuntime().(hookLifecycleMetricV8Runtime)
	c.bindObservabilityV8(metricRuntime)
	s.setInspectionAvailability(nil)
	c.bindAvailabilityObserver(s.inspectionAvailabilityObserver())
	return c
}

func newStandaloneCiscoInspectClient(cfg *config.Config) (*CiscoInspectClient, error) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return nil, errors.New("not a standalone managed deployment")
	}
	ai := cfg.Enterprise.Inspection.AIDefense
	if !ai.Enabled {
		return nil, errStandaloneAIDefenseDisabled
	}
	secretsDir := managed.StandaloneSecretsDirForConfig(runtime.GOOS, cfg.ConfigFilePath)
	key, _, err := managed.ResolveServiceCredential(ai.Credential, secretsDir)
	if err != nil {
		return nil, fmt.Errorf("credential %q: %w", ai.Credential, err)
	}
	aid := cfg.CiscoAIDefense
	aid.APIKeyEnv = ""
	aid.APIKey = string(key)
	client := NewCiscoInspectClient(&aid, "")
	if client == nil {
		return nil, errors.New("cisco ai defense client could not be constructed")
	}
	transport, err := standaloneEgressTransport(cfg)
	if err != nil {
		return nil, err
	}
	client.client.Transport = transport
	return client, nil
}

// standaloneEgressTransport is the outbound transport of the standalone
// profile's cloud clients: it honors the administrator's egress proxy
// (enterprise.network) and, without one, keeps the environment proxy the
// default transport uses.
func standaloneEgressTransport(cfg *config.Config) (*http.Transport, error) {
	transport, err := cfg.Enterprise.EgressProxy().Transport()
	if err != nil {
		return nil, fmt.Errorf("enterprise.network: %w", err)
	}
	return transport, nil
}
