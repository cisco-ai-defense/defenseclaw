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

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// A request the gateway decides (a hook or inspect call, a guardrail proxy
// request, an event the router handles) pins the generation that is live when
// it starts, and reads what decides it from that one object: the rule pack and
// its compiled rules, the local patterns, the judge, the guardrail profiles,
// and the policy digest and generation its records carry. A reload that
// publishes the next generation meanwhile leaves a request in flight alone, so
// no record carries one generation's digest for another's decision (GAP-0455,
// spec section 4). Components outside a gateway (tests, a detached router)
// pin nothing and keep the process-wide view.

type pinnedGenerationKey struct{}

// withPinnedGeneration pins g on ctx unless ctx already carries a generation,
// which then stays.
func withPinnedGeneration(ctx context.Context, g *Generation) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if g == nil || pinnedGeneration(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, pinnedGenerationKey{}, g)
}

// pinnedGeneration is the generation pinned on ctx, or nil.
func pinnedGeneration(ctx context.Context) *Generation {
	if ctx == nil {
		return nil
	}
	g, _ := ctx.Value(pinnedGenerationKey{}).(*Generation)
	return g
}

// published reports a generation the gateway published (Generation.N is set
// by publishGeneration), whose enforcement inputs are all bound.
func (g *Generation) published() bool {
	return g != nil && g.N > 0
}

// ruleGenerationOf is the compiled rule set connector is scanned with under
// g: the one g compiled for it, else one registered for it outside the
// configuration (the connector setup at boot, a sandbox harness), else g's
// active rules. Without compiled rules in g it is the process-wide set.
func ruleGenerationOf(g *Generation, connector string) *compiledRulePackCategories {
	if g == nil || g.activeRules == nil {
		return snapshotRulePackGeneration(connector)
	}
	name := canonicalConnectorRulePackKey(connector)
	if name == "" {
		return g.activeRules
	}
	if rules := g.connectorRules[name]; rules != nil {
		return rules
	}
	ruleCategoriesMu.RLock()
	registered := connectorRuleGenerations[name]
	ruleCategoriesMu.RUnlock()
	if registered != nil {
		return registered
	}
	return g.activeRules
}

// pinnedRuleGeneration is ruleGenerationOf the generation pinned on ctx.
func pinnedRuleGeneration(ctx context.Context, connector string) *compiledRulePackCategories {
	return ruleGenerationOf(pinnedGeneration(ctx), connector)
}

// localPatternsOf is g's local pattern activation; nil means the
// process-wide patterns.
func localPatternsOf(g *Generation) *localPatternsActivation {
	if g == nil {
		return nil
	}
	return g.activePatterns
}

// pinnedProfileSet is the guardrail profile set of the generation pinned on
// ctx, else the process-wide one.
func pinnedProfileSet(ctx context.Context) *guardrailProfileSet {
	if g := pinnedGeneration(ctx); g.published() {
		return g.Profiles
	}
	return liveGuardrailProfiles.Load()
}

// judgeOf is g's judge for a published g, else fallback (the component's
// own judge outside a gateway).
func judgeOf(g *Generation, fallback *LLMJudge) *LLMJudge {
	if g.published() {
		return g.judge
	}
	return fallback
}

// policyStampGeneration is the generation whose digest a record emitted
// under ctx carries: the pinned one, else the live one. nil before the first
// generation and under the Secure Client integration.
func policyStampGeneration(ctx context.Context) *Generation {
	g := pinnedGeneration(ctx)
	if g == nil {
		g = currentGeneration()
	}
	if g == nil || g.Config == nil || g.Config.SecureClientIntegration() {
		return nil
	}
	return g
}

func policyDigestV8(ctx context.Context) observability.Optional[string] {
	if g := policyStampGeneration(ctx); g != nil && g.Digest != "" {
		return observability.Present(g.Digest)
	}
	return observability.Absent[string]()
}

func policyGenerationV8(ctx context.Context) observability.Optional[int64] {
	if g := policyStampGeneration(ctx); g != nil && g.N > 0 {
		return observability.Present(int64(g.N))
	}
	return observability.Absent[int64]()
}
