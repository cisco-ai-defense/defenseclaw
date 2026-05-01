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
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

// GovernanceVerdict is the result of a model/provider governance check.
type GovernanceVerdict struct {
	Allowed bool
	Reason  string
	Rule    string // "provider-allow", "provider-deny", "model-allow", "model-deny"
}

// ModelGovernor evaluates model and provider names against OPA policy.
// A nil governor always allows (feature disabled).
type ModelGovernor struct {
	mode         string
	blockMessage string
	logAllowed   bool
	opa          *policy.Engine
}

// NewModelGovernor creates a governor from config. Returns nil when
// governance is disabled, so callers can nil-check for fast path.
func NewModelGovernor(cfg config.ModelGovernanceConfig, opa *policy.Engine) *ModelGovernor {
	if !cfg.Enabled {
		return nil
	}
	return &ModelGovernor{
		mode:         strings.ToLower(cfg.Mode),
		blockMessage: cfg.BlockMessage,
		logAllowed:   cfg.LogAllowed,
		opa:          opa,
	}
}

// Check evaluates the provider and model against OPA policy.
// Returns a verdict with allow/deny and reason.
func (g *ModelGovernor) Check(provider, model string) *GovernanceVerdict {
	if g == nil {
		return &GovernanceVerdict{Allowed: true}
	}

	provider = strings.ToLower(strings.TrimSpace(provider))
	model = strings.ToLower(strings.TrimSpace(model))

	if g.opa == nil {
		return &GovernanceVerdict{Allowed: true}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := g.opa.EvaluateModelGovernance(ctx, policy.ModelGovernanceInput{
		Provider: provider,
		Model:    model,
	})
	if err != nil {
		return &GovernanceVerdict{
			Allowed: true,
			Reason:  fmt.Sprintf("policy eval error (fail-open): %v", err),
		}
	}

	if out.Action == "deny" {
		return &GovernanceVerdict{
			Allowed: false,
			Reason:  out.Reason,
			Rule:    out.Rule,
		}
	}

	return &GovernanceVerdict{Allowed: true}
}

// IsMonitorOnly returns true when denials should be logged but not enforced.
func (g *ModelGovernor) IsMonitorOnly() bool {
	if g == nil {
		return false
	}
	return g.mode == "monitor"
}

// BlockMessage returns the user-facing denial message.
func (g *ModelGovernor) BlockMessage() string {
	if g == nil || g.blockMessage == "" {
		return "This model or provider is not authorized by your organization's policy."
	}
	return g.blockMessage
}

// LogAllowed returns whether allowed requests should be logged.
func (g *ModelGovernor) LogAllowed() bool {
	return g != nil && g.logAllowed
}
