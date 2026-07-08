// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routing

import "fmt"

// RouteResult holds the resolved backend for a routed request.
type RouteResult struct {
	BackendName  string
	DecisionName string
	Model        string
	Provider     string
	BaseURL      string
	APIKey       string
}

// SemanticRouter classifies requests and routes to the optimal backend.
type SemanticRouter struct {
	cfg  RoutingConfig
	pool *ProviderPool
}

// NewSemanticRouter creates a router from the given config.
func NewSemanticRouter(cfg RoutingConfig) (*SemanticRouter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	pool := NewProviderPool(cfg.Models)
	return &SemanticRouter{cfg: cfg, pool: pool}, nil
}

// Route classifies the messages and selects the best backend.
// Returns nil when routing is disabled or no decision matches.
func (r *SemanticRouter) Route(messages []Message) (*RouteResult, error) {
	if !r.cfg.Enabled {
		return nil, nil
	}

	signals := Classify(messages, r.cfg.Signals)
	decision := Decide(signals, r.cfg.Decisions)
	if decision == nil {
		return nil, nil
	}

	if len(decision.ModelRefs) == 0 {
		return nil, fmt.Errorf("routing: decision %q has no model_refs", decision.DecisionName)
	}

	backendName := decision.ModelRefs[0]
	resolved, err := r.pool.Get(backendName)
	if err != nil {
		return nil, fmt.Errorf("routing: %w", err)
	}

	return &RouteResult{
		BackendName:  backendName,
		DecisionName: decision.DecisionName,
		Model:        resolved.Model,
		Provider:     resolved.Provider,
		BaseURL:      resolved.BaseURL,
		APIKey:       resolved.APIKey,
	}, nil
}
