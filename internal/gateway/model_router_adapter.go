// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing"
)

// semanticRouterAdapter adapts routing.SemanticRouter to ModelRouter.
type semanticRouterAdapter struct {
	sr *routing.SemanticRouter
}

func (a *semanticRouterAdapter) Route(ctx context.Context, input *ModelRouterInput) *ModelRouterDecision {
	msgs := make([]routing.Message, len(input.Messages))
	for i, m := range input.Messages {
		msgs[i] = routing.Message{Role: m.Role, Content: m.Content}
	}

	result, err := a.sr.Route(msgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] semantic router error: %v (falling back to default provider)\n", err)
		return nil
	}
	if result == nil {
		return nil
	}

	fmt.Fprintf(os.Stderr, "[guardrail] routing: decision=%q → backend=%q model=%q\n",
		result.DecisionName, result.BackendName, result.Provider+"/"+result.Model)

	return &ModelRouterDecision{
		TargetURL: result.BaseURL,
		Model:     result.Model,
		APIKey:    result.APIKey,
		Reason:    fmt.Sprintf("decision=%s backend=%s", result.DecisionName, result.BackendName),
	}
}

// NewSemanticModelRouter creates a ModelRouter from the config routing block.
// Returns nil when routing is disabled or when remote mode is configured
// (the sidecar wiring handles managed mode lifecycle separately).
func NewSemanticModelRouter(cfg config.RoutingConfig) (ModelRouter, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	// If remote endpoint is set, use that directly (external SR)
	if cfg.Remote.Endpoint != "" {
		return nil, nil
	}
	// Otherwise return nil — the sidecar wiring handles managed mode lifecycle
	return nil, nil
}

// NewRemoteModelRouter creates a ModelRouter pointing at the given SR endpoint.
func NewRemoteModelRouter(endpoint string, timeoutMs int) ModelRouter {
	return NewRemoteRouterClient(endpoint, timeoutMs)
}

func convertRoutingConfig(cfg config.RoutingConfig) routing.RoutingConfig {
	models := make([]routing.ModelBackend, len(cfg.Models))
	for i, m := range cfg.Models {
		models[i] = routing.ModelBackend{
			Name: m.Name, Provider: m.Provider, Model: m.Model,
			BaseURL: m.BaseURL, APIKeyEnv: m.APIKeyEnv,
			Weight: m.Weight, Capabilities: m.Capabilities,
		}
	}
	var keywords []routing.KeywordSignal
	for _, k := range cfg.Signals.Keywords {
		keywords = append(keywords, routing.KeywordSignal{
			Name: k.Name, Keywords: k.Keywords, Operator: k.Operator,
		})
	}
	decisions := make([]routing.DecisionRule, len(cfg.Decisions))
	for i, d := range cfg.Decisions {
		conds := make([]routing.Condition, len(d.Conditions))
		for j, c := range d.Conditions {
			conds[j] = routing.Condition{Type: c.Type, Name: c.Name}
		}
		decisions[i] = routing.DecisionRule{
			Name: d.Name, Priority: d.Priority, Conditions: conds,
			Operator: d.Operator, ModelRefs: d.ModelRefs, Algorithm: d.Algorithm,
		}
	}
	return routing.RoutingConfig{
		Enabled: cfg.Enabled, Models: models,
		Signals:   routing.SignalConfig{Keywords: keywords},
		Decisions: decisions,
	}
}
